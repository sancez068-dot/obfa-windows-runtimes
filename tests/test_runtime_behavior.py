import glob
import importlib.util

NAME = "_mXkz2C4L16bEYJhyUXGQCOv"

def load_runtime():
    files = glob.glob(NAME + "*.so") + glob.glob(NAME + "*.pyd")
    if not files:
        raise AssertionError("Native runtime binary not found")
    spec = importlib.util.spec_from_file_location(NAME, files[0])
    if spec is None or spec.loader is None:
        raise AssertionError("Cannot load native runtime")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_malformed_containers():
    runtime = load_runtime()
    samples = [
        b"",
        b"bad",
        b"M5C2",
        b"M5C2" + bytes(8),
        b"M5C2" + bytes(32),
        b"M5C2" + bytes(100),
    ]
    for data in samples:
        try:
            runtime.run(data, {})
        except (ValueError, TypeError):
            continue
        raise AssertionError(
            f"Malformed container was not rejected: length={len(data)}"
        )
    print(f"Malformed container tests: OK ({len(samples)})")

if __name__ == "__main__":
    test_malformed_containers()
