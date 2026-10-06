from __future__ import annotations
import json, os, secrets, string, subprocess, sys, sysconfig
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1] / "native" / "runtimes"
WINDOWS_SLOTS = tuple(f"windows-amd64-cp3{minor}" for minor in (11, 12, 13, 14))
WINDOWS_PREFIX = "windows-amd64-cp3"
ANDROID_SLOTS = tuple(f"android-arm64-cp3{minor}" for minor in (11, 12, 13, 14))
ANDROID_PREFIX = "android-arm64-cp3"
LINUX_SLOTS = tuple(f"linux-amd64-cp3{minor}" for minor in (11, 12, 13, 14))
MACOS_SLOTS = tuple(f"macos-amd64-cp3{minor}" for minor in (11, 12, 13, 14))


def _ident(prefix="_m"):
    return prefix + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(22))


def _compile_host(output: Path):
    src = Path(__file__).resolve().parents[1] / "native" / "vm.c"
    module = _ident()
    capsule = _ident("_c")
    text = src.read_text(encoding="utf8").replace("PyInit___MODULE__", "PyInit_" + module).replace("__MODULE__", module).replace('"CAP"', '"' + capsule + '"')
    # Android runtime is compiled against the CPython stable ABI so one
    # aarch64 .so serves CPython 3.11-3.14.
    android_host = sys.platform.startswith("android") or (sys.platform.startswith("linux") and (os.environ.get("TERMUX_VERSION") or str(Path(sys.prefix)).startswith("/data/data/com.termux/") or Path("/system/bin/app_process").exists()))
    if android_host:
        text = "#define Py_LIMITED_API 0x030B0000\n" + text
    generated = output.with_suffix(".c")
    generated.write_text(text, encoding="utf8")

    if sys.platform.startswith("win"):
        ext = output.with_suffix(".pyd")
        cl = os.environ.get("CL") or "cl"
        inc = sysconfig.get_config_var("INCLUDEPY")
        libdir = sysconfig.get_config_var("LIBDIR") or ""
        library = sysconfig.get_config_var("LIBRARY") or ""
        cmd = [cl, "/nologo", "/LD", "/O2", "/GL", "/GS", "/guard:cf", "/DYNAMICBASE", "/NXCOMPAT", "/Brepro", "/Gy", "/Gw", "/EHsc", f"/I{inc}", str(generated), f"/Fe:{ext}", "/link", "/OPT:REF", "/OPT:ICF"]
        if libdir and library:
            lp = Path(libdir) / library
            if lp.exists():
                cmd.append(str(lp))
    elif sys.platform == "darwin":
        ext = output.with_suffix(".so")
        cmd = [
            os.environ.get("CC", "cc"),
            "-bundle", "-undefined", "dynamic_lookup",
            "-fPIC", "-O2", "-fno-ident", "-s",
            "-fvisibility=hidden", "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
        ]
        inc = sysconfig.get_config_var("INCLUDEPY")
        if inc:
            cmd += ["-I", inc]
        cmd += [str(generated), "-o", str(ext)]
    else:
        ext = output.with_suffix(".so")
        cmd = [os.environ.get("CC", "cc"), "-shared", "-fPIC", "-O2", "-fno-ident", "-s", "-fvisibility=hidden", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,now", "-Wl,--build-id=none"]
        inc = sysconfig.get_config_var("INCLUDEPY")
        if inc:
            cmd += ["-I", inc]
        libdir = sysconfig.get_config_var("LIBDIR") or ""
        ldlib = sysconfig.get_config_var("LDLIBRARY") or ""
        libpath = Path(libdir) / ldlib if libdir and ldlib else None
        if libpath and libpath.exists() and libpath.suffix == ".so":
            cmd += [str(libpath)]
        cmd += [str(generated), "-o", str(ext)]

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("native runtime compilation exceeded the 60-second safety limit") from exc
    return ext.read_bytes(), module, text


def _slot_from_host():
    try:
        import platform
        machine = (platform.machine() or "").lower()
    except Exception:
        machine = ""
    if not machine:
        try:
            machine = os.uname().machine.lower()
        except (AttributeError, OSError):
            pass

    if sys.platform.startswith("win"):
        win_machine = (os.environ.get("PROCESSOR_ARCHITECTURE") or machine).lower()
        if win_machine in {"amd64", "x86_64", "x64"}:
            return f"windows-amd64-cp{sys.version_info.major}{sys.version_info.minor}"
        return None

    if sys.platform.startswith("linux") or sys.platform.startswith("android"):
        prefix = os.environ.get("PREFIX", "")
        exe = str(Path(sys.executable).resolve())
        sp = str(Path(sys.prefix).resolve())
        termux_paths = (
            "/data/data/com.termux/",
            "/data/user/0/com.termux/",
            "/data/data/com.termux/files/usr",
        )
        termux = any(marker in value for value in (prefix, exe, sp) for marker in termux_paths)
        termux = termux or bool(os.environ.get("TERMUX_VERSION"))
        termux = termux or Path("/data/data/com.termux/files/usr/bin/termux-info").exists()
        android = Path("/system/bin/app_process").exists() or Path("/system/bin/linker64").exists() or Path("/system/build.prop").exists()

        if (termux or android) and machine in {"aarch64", "arm64"}:
            return f"android-arm64-cp{sys.version_info.major}{sys.version_info.minor}"
        if sys.platform.startswith("linux") and not (termux or android) and machine in {"x86_64", "amd64"}:
            return f"linux-amd64-cp{sys.version_info.major}{sys.version_info.minor}"

    if sys.platform == "darwin" and machine in {"x86_64", "amd64"}:
        return f"macos-amd64-cp{sys.version_info.major}{sys.version_info.minor}"

    return None


def _foreign_runtime(slot: str):
    d = RUNTIME_ROOT / slot
    blob_name = "runtime.pyd" if slot.startswith("windows-") else "runtime.so"
    blob = d / blob_name
    meta = d / "runtime.json"
    if not blob.exists() or not meta.exists():
        return None
    info = json.loads(meta.read_text(encoding="utf8"))
    return blob.read_bytes(), str(info["module"])


def _bundled_windows():
    out = {}
    for slot in WINDOWS_SLOTS:
        item = _foreign_runtime(slot)
        if item is None:
            raise RuntimeError(f"missing bundled Windows runtime: {slot}")
        out[slot] = item
    return out


def build_runtimes(output: Path):
    host_slot = _slot_from_host()
    if host_slot is None:
        raise RuntimeError("unsupported build host; expected Termux/Android arm64, Linux x64 or Windows x64")

    blob, module, source = _compile_host(output)
    runtimes = {host_slot: (blob, module)}

    # Android/Termux uses one stable-ABI (abi3) native runtime. The same
    # module is valid for CPython 3.11-3.14, so a runtime built on any
    # supported Android minor is copied into all Android slots.
    if host_slot in ANDROID_SLOTS:
        for slot in ANDROID_SLOTS:
            runtimes[slot] = (blob, module)

    # Always bundle every supported Windows CPython ABI. This makes the
    # generated artifact independent of a compiler being installed on Windows.
    for slot, item in _bundled_windows().items():
        if slot != host_slot:
            runtimes[slot] = item

    # Bundle all supported Linux x86_64 CPython ABIs as prebuilt runtimes.
    for slot in LINUX_SLOTS:
        item = _foreign_runtime(slot)
        if item is None:
            raise RuntimeError(f"missing bundled Linux runtime: {slot}")
        if slot != host_slot:
            runtimes[slot] = item

    # Bundle all supported macOS x86_64 CPython ABIs as prebuilt runtimes.
    for slot in MACOS_SLOTS:
        item = _foreign_runtime(slot)
        if item is None:
            raise RuntimeError(f"missing bundled macOS runtime: {slot}")
        if slot != host_slot:
            runtimes[slot] = item

    sources = {}
    if host_slot not in WINDOWS_SLOTS:
        # No Windows source compiler fallback is emitted anymore: the target
        # Windows runtime is already prebuilt and embedded.
        pass
    return runtimes, sources


def build_native(output: Path):
    runtimes, sources = build_runtimes(output)
    host = runtimes[_slot_from_host()]
    return host[0], host[1], runtimes, sources
