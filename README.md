# OBFA Windows runtimes

This repository builds the Windows x64 native runtime for CPython 3.11, 3.12, 3.13 and 3.14.

No Visual Studio installation is required on the user's PC. GitHub Actions builds the `.pyd` files on a Windows runner.

Artifacts:

- `runtime-cp311-win_amd64.pyd`
- `runtime-cp312-win_amd64.pyd`
- `runtime-cp313-win_amd64.pyd`
- `runtime-cp314-win_amd64.pyd`

The source runtime is `runtime.c`.
