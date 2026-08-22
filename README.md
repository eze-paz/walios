# WALI wasm-OS

Run unmodified Linux userland as **native WebAssembly** in the browser (and node),
by recompiling programs against a Linux-syscall import ABI (WALI) and answering the
syscalls in JavaScript. No CPU emulation — the emulator is removed from between the
program and its syscalls, so compute runs at ~native wasm speed.

Measured on a real workload (GasN2 CSV parse+aggregate, CPython 3.14):
**~1.35s vs 103s** for the same script under an emulated riscv64 VM — **~76x**.

## Layout

- `host/` — the JS syscall layer for **node**.
  - `host.js` — full host: ~40 Linux syscalls + process model (fork/execve/wait4/
    pipes, vfork-as-macro + wasm-EH setjmp/longjmp), sockets (via `sock-bridge.js`),
    and a **WASI preview1** shim so it also runs standard `wasm32-wasi` binaries.
  - `sock-bridge.js` — worker_thread giving the synchronous guest blocking TCP/UDP
    (SAB + Atomics.wait); the node stand-in for the browser WISP relay.
  - `wali-ld` — wrapper stripping GNU-ld-only flags for `wasm-ld`.
- `browser/` — the same OS running in a **browser tab**.
  - `wali-worker.js` — Worker host: in-memory VFS (tar.gz preload) + OPFS mount,
    stdin over SAB, process model, VFS-exec, WASI shim.
  - `wali-test.html` — test page (lua, CPython, GasN2 bench, busybox, hush,
    in-browser microcc compile, real wasi binary).
  - `coi.py` — COOP/COEP static server (SharedArrayBuffer needs cross-origin isolation).
  - `microcc.c` — a tiny **real** compiler: parses integer arithmetic and emits
    genuine wasm bytecode; compiled to wasm itself, it compiles + runs in the tab.
- `farm/` — the build farm: take real Alpine **aports**, run their own `build()`
  with the WALI toolchain, smoke-test on the host, gate pass→wasm-repo / fail→VM-only.
  - `farm2.js` — dependency-ordered (topo-sort) farm over a seed set, shared overlay
    sysroot, `_start`-export exe/lib detection, `manifest.json` ledger.
  - `build-one.sh` — per-package build worker (fetch APKBUILD+patches, prepare/build/
    package, gnulib wasm overlay, smoke test).
  - `config.site` — cross-compile cache defeating gnulib "cannot run test program".
  - `build-wasm-clang.sh` — recipe to build clang+lld → wasm (the in-browser compiler).
- `ci/build-wasm-clang.yml` — GitHub Actions workflow producing `clang.wasm`/`lld.wasm`.
- `musl-patches/` — changes to `wali-musl` (setjmp→wasm-EH SJLJ, fork/vfork macros,
  execve/_Exit child-return, SSIZE_MAX fix). `wali-musl.tracked.patch` + new sources.

## Toolchain

`wasm32-unknown-linux-muslwali` is in **stock LLVM 22** — no LLVM build needed.
Get it via the WALI repo (`make compiler SLIM=1` + `make libc`), then apply
`musl-patches/`. Sysroot is ~2.8 MB.

## Status

Shipped: compute (76x), browser host, process model, sockets (real TCP), build farm
(14/22 seed aports green, dependency-ordered), in-tab compiler mechanics (microcc),
WASI execution in-tab. Pending: `clang.wasm` artifact (run `ci/build-wasm-clang.yml`
on a ≥32 GB runner — the BUILD needs the RAM; the resulting clang RUNS in a normal
browser), browser WISP sockets, openssh/openssl, farm scale-out.

Not a from-scratch build: this rides the WALI project (github.com/arjunr2/WALI) for
the toolchain/ABI. This repo is the OS layer, browser port, process model, farm, and
in-browser-compiler work built on top.
