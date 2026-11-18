# walios runtime recipes

busybox, lua, perl and CPython (+ its stdlib C extensions) for walios, the ILP32 sysroot
(`sysroot32/`) and libffi's WALI port. Each `*/build.sh` builds from the network and the farm
toolchain (`farm/ci/toolchain.sh`); `WALI_ABI=ilp32` builds for the walios ILP32 ABI
(32-bit long), the default for WALI's own (64-bit long).

`.github/workflows/runtimes.yml` runs them on GitHub runners and publishes a
`runtimes-<abi>-<date>-<run>` release; committing `runtimes/request.json` (`{"abi": ..., "only": ...}`)
starts a run. These files are mirrored from the sandpie repository (`walios/build`), where
they are maintained.

`cpython-v11/` is the recipe the deployed `python_cxx.wasm` (sandpie `?v=11`, then `?v=12` =
the same build with the NUL-separated env reader) came from: sandpie 473f496f's
`walios/build/cpython`. `cpython/` has moved on since (libc closure exports, call
trampolines) and builds a different binary. `"cpython_dir": "runtimes/cpython-v11"` in
`request.json` picks it.
