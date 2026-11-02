# walios ILP32 sysroot

WALI's wasm32 ABI has 32-bit pointers and `size_t` but a 64-bit `long` (clang's
`wasm32-unknown-linux-muslwali` target), so that structs match x86_64's for a runtime that hands
syscalls straight to a real kernel. No Linux ABI has that mix: code assumes `long` is as wide as a
pointer (LP64 and ILP32 both do), and on WALI it is not. Packages either fail to build (oniguruma
and jq pick a pointer-sized integer from `long`/`long long` and find neither; MPFR's precision type
overflows `size_t`) or build and misbehave (`printf("%ld", size_t)` reads 8 bytes from a 4-byte
argument: garbage, and every later argument shifted). The walios kernel is JavaScript, so it gets
nothing from the x86_64 layouts.

This sysroot is the same libc with a 32-bit `long`: ILP32, like i386 and armv7 Linux, the ABI
Alpine's 32-bit ports build and test every package against. `time_t`, `off_t`, `ino_t` stay
64-bit (musl's time64 setup).

## Build

`build.sh [workdir]` (WSL/Linux; LLVM 22.1.3 release binaries): wali-musl 243ec00 plus walios'
`musl-patches` (eze-paz/walios), with `arch/wasm32` changed as below; libc++/libc++abi/libunwind;
OpenSSL 3.0.16; compiler-rt builtins from WALI's sysroot. Output `wali32-sysroot.tar.gz` (the farm
toolchain fetches it as a toolchain release asset under `WALI_ABI=ilp32`).

Compile with `--target=wasm32-unknown-linux-musl` (long = 32, `size_t` = `unsigned long`,
defines `__wali__` and `__ILP32__`). Clang's driver has no link step for that triple, so links go
through the WALI driver: `--target=wasm32-unknown-linux-muslwali -Xclang -triple -Xclang
wasm32-unknown-linux-musl -fno-pic` does both in one call (the farm wrapper's form).

## ABI

- Syscall imports keep their wasm signatures: WALI spelled 64-bit kernel words as C `long`;
  here they are `long long`, so every `SYS_*` import has the same type as before.
- Structs the kernel reads or writes keep WALI's byte layout where musl lets the arch choose it:
  `struct kstat` (x86_64 stat, fixed-width types; fstatat copies it into `struct stat`),
  `k_sigaction`, `struct statfs` (x32's padded layout).
- Where musl's generic code decides the layout, it is the ILP32 one, and the kernel handles both
  (`Process.L`, `rLong`, `tsNs`, `msgCtl` in `walios/wali-worker.js`, and the farm's
  `host/host.js`): the `long[]` arrays musl passes for select/pselect6/ppoll timeouts, itimers and
  rusage; a `timespec`'s `tv_nsec` (32-bit, then padding); `sysinfo`, `times`; `msghdr` and
  `cmsghdr` (no padding).
- The ABI marker: a `wali.abi` custom section containing `ilp32`, assembled into the start files
  and the startup code. The kernel picks the layouts per process from it; binaries without it
  are WALI's 64-bit-long ABI, so everything already shipped keeps working.

`abiprobe.c` checks each of these from the program's side; `tests/walios/e2e-abi32.mjs` runs it
built both ways, and farm-built ILP32 packages, in both engines.

## Status

Kernel (both engines), this sysroot, libffi (`WALI_ABI=ilp32 ../libffi/build.sh`) and the farm
toolchain mode exist. Still on the 64-bit long: python_cxx, perl, lua (and therefore their C
modules: the farm skips those under ILP32), busybox, clang.wasm's own sysroot, the Rust sysroot.
