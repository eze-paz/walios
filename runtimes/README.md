# walios runtime recipes

busybox, lua, perl and CPython (+ its stdlib C extensions) for walios, the ILP32 sysroot
(`sysroot32/`) and libffi's WALI port. Each `*/build.sh` builds from the network and the farm
toolchain (`farm/ci/toolchain.sh`); `WALI_ABI=ilp32` builds for the walios ILP32 ABI
(32-bit long), the default for WALI's own (64-bit long).

`.github/workflows/runtimes.yml` runs them on GitHub runners and publishes a
`runtimes-<abi>-<date>-<run>` release; committing `runtimes/request.json` (`{"abi": ..., "only": ...}`)
starts a run. These files are mirrored from the sandpie repository (`walios/build`), where
they are maintained.
