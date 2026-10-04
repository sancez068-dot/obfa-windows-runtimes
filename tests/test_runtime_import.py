import importlib.util
import pathlib
import sysconfig

MODULE = "_mXkz2C4L16bEYJhyUXGQCOv"

def test_runtime_imports():
    root = pathlib.Path(__file__).resolve().parents[1]
    suffixes = sysconfig.get_config_var("EXT_SUFFIX")
    candidates = list(root.glob(MODULE + "*.so"))
    candidates += list(root.glob(MODULE + "*.pyd"))
    if not candidates:
        raise AssertionError(f"Native extension not found in {root}")
    path = candidates[0]
    spec = importlib.util.spec_from_file_location(MODULE, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Cannot load extension: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.run)

if __name__ == "__main__":
    test_runtime_imports()
    print("runtime import: OK")
