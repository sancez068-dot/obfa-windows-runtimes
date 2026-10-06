from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protector_core.packer.embed import _compile_host, _slot_from_host


def main() -> int:
    slot = _slot_from_host()
    if not slot:
        raise SystemExit(f"unsupported host: {sys.platform}/{platform.machine()}")
    root = ROOT / "protector_core" / "native" / "runtimes" / slot
    root.mkdir(parents=True, exist_ok=True)
    output = root / "runtime"
    blob, module, _ = _compile_host(output)
    binary = root / ("runtime.pyd" if slot.startswith("windows-") else "runtime.so")
    binary.write_bytes(blob)
    windows = slot.startswith("windows-")
    info = {
        "module": module,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "platform": slot.rsplit("-cp", 1)[0],
        "arch": platform.machine().lower(),
        "abi": f"cp{sys.version_info.major}{sys.version_info.minor}" if windows else "abi3",
        "features": ["runtime_page_mask", "lazy_authenticated_pages"],
        "compiler_hardening": ["symbols-stripped", "hidden-visibility", "stack-protector", "relro", "now" if not windows else "cfg", "aslr", "nx"],
    }
    (root / "runtime.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"slot": slot, "binary": str(binary), "bytes": len(blob), "features": info["features"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
