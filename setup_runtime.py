import sys
from setuptools import Extension, setup

name = "_mXkz2C4L16bEYJhyUXGQCOv"

if sys.platform == "win32":
    compile_args = ["/O2"]
else:
    compile_args = ["-O2", "-fvisibility=hidden"]

setup(
    name="obfa-runtime",
    version="0.1.0",
    ext_modules=[
        Extension(
            name,
            sources=["runtime.c"],
            extra_compile_args=compile_args,
        )
    ],
)
