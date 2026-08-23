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
    With `WALI_JSPI=1` (node 24 + `--experimental-wasm-jspi`) it runs the
    **concurrent scheduler**: fork+exec'd children run as concurrent
    `WebAssembly.promising(_start)` tasks, and blocking syscalls (read on an empty
    pipe, wait4, poll, nanosleep) suspend via `WebAssembly.Suspending` instead of
    stalling — so a shell can drive a *live* pipeline instead of run-at-wait4.
  - `jspi-sched.mjs` / `jspi-proto.mjs` — standalone proofs of the JSPI mechanism:
    two real WALI binaries over a bounded pipe interleave (writer suspends on a full
    pipe, reader on an empty one) to completion with no deadlock.
  - `sock-bridge.js` — worker_thread giving the synchronous guest blocking TCP/UDP
    (SAB + Atomics.wait); the node stand-in for the browser WISP relay.
  - `wali-ld` — wrapper stripping GNU-ld-only flags for `wasm-ld`.
- `browser/` — the same OS running in a **browser tab**.
  - `wali-worker.js` — Worker host: in-memory VFS (tar.gz preload) + OPFS mount,
    stdin over SAB, process model, VFS-exec, WASI shim. Passing `jspi:true` in the
    run message enables the same **concurrent scheduler** as the node host (Chrome
    has JSPI): pipeline stages run concurrently, readers suspend on empty pipes.
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

Shipped & verified:
- **Compute** ~76x faster than the emulated RISC-V VM on CPython (same script,
  byte-identical output).
- **Browser host** — CPython/busybox/lua run in a tab (in-memory VFS + OPFS +
  SAB stdin); **process model** (fork/execve/wait4/pipes) so a shell runs pipelines
  and launches other programs.
- **Sockets** — real TCP (node bridge) + **DNS via DoH** (getaddrinfo + `wget`
  a hostname work end to end).
- **Real clang IN THE BROWSER** — the prebuilt `@yowasp/clang` (LLVM 22, wasm) runs
  in a tab and compiles C; output runs in the OS. Emits both `wasm32-wasi` and, with
  the 2.8 MB wali sysroot mounted, native **WALI** binaries. (see `browser/wali-test.html`)
- **OpenSSH 9.9p1** cross-compiled to WALI (`ssh`/`sshd` wasm) and runs (`ssh -V`).
- **Build farm** — takes real Alpine aports, resolves a **transitive dependency
  closure**, topo-sorts, builds each to wasm against a shared overlay sysroot, smoke-
  tests, and gates pass→wasm / fail→vm-only (`farm/farm2.js`).
- **Searchable aports browser** — `browser/aports.html`: 1600+ Alpine packages
  searchable, the built ones runnable click-to-run in a terminal.

- **Browser TCP via WISP** — `browser/wisp-relay.js` (WebSocket↔TCP relay, DoH
  resolution, ICMP) + `browser/wisp-worker.js` (a sibling worker owning the
  WebSocket, bridged to the OS worker over a SAB). Verified: `busybox wget
  http://neverssl.com` fetches the real page **in the tab**. Synthetic DNS hands the
  hostname to the relay (avoids COEP-blocked in-browser DoH). Defaults to this
  origin's `/wisp` (same relay the riscv-vm uses); a bundled dev relay runs on :8790.
- **PTY layer** — `/dev/ptmx` + `/dev/pts/N`, termios line discipline
  (canonical/ECHO/ICRNL/ONLCR), winsize, `TIOCGPTN`/`TIOCSCTTY` etc. — in both hosts.
- **Concurrent scheduler (JSPI)** — fork+exec'd children run concurrently; blocking
  syscalls suspend and yield instead of stalling. Verified in **node 24** and in a
  real **Chrome tab**: `seq 200 | grep 1 | wc -l` and `seq 100000 | wc -l` produce
  correct output with measured pipe/wait suspends (readers genuinely suspended on
  empty pipes and were resumed by the concurrent upstream). Default stays the
  synchronous model; opt in with `WALI_JSPI=1` (node) / `jspi:true` (browser).

- **Interactive `sshd` — unmodified OpenSSH 9.9, privsep enabled.** A real
  `ssh -o ProxyCommand="sshd -i"` loopback runs entirely as WALI wasm processes: the
  ssh client, `sshd`, `sshd-session`, the privsep monitor **and** child, and the
  login shell, all under the concurrent scheduler. Verified end to end — KEX
  (post-quantum sntrup761x25519), publickey auth, privsep, PTY allocation, and a
  live interactive login shell: type `uname -a` and get `Linux wali … wasm32` back,
  with a prompt, `$SSH_TTY=/dev/pts/0`, clean teardown. See `host/ssh-loopback-demo.sh`.

  Getting there required a **general fork substrate** (no OpenSSH source edits) plus
  filling real syscall gaps, all in `host/host.js`:
  - **Real `fork()` via Asyncify.** `fork()`-without-`exec` (privsep) needs the
    monitor and child running *concurrently in a copy of the same memory* — which the
    JSPI scheduler can't do (a live wasm stack can't be cloned). So at `SYS_fork` the
    host unwinds the caller's stack into linear memory (Binaryen `--asyncify`), copies
    the whole memory into a fresh instance, and rewinds *both* to the fork point
    (parent←pid, child←0), scheduling them concurrently. Binaries are built with real
    `fork()` (`-D__WALI_ASYNCIFY_FORK`, see `musl-patches/asyncify-fork.md`) then
    `wasm-opt --asyncify --pass-arg=asyncify-imports@wali.SYS_fork`; only `SYS_fork`
    triggers asyncify, so blocking syscalls keep using JSPI. `host/asyncify-fork-proof.mjs`
    is the minimal proof; `host/asyncify-forkwali.c` a real-musl fork+wait.
  - `socketpair(AF_UNIX)` with **SCM_RIGHTS fd passing** (the privsep monitor passes
    the pty + socket fds to the child).
  - Honest `O_NONBLOCK`/`EAGAIN` on pipes & socketpairs (was a real JSPI-scheduler
    bug: reads always suspended, so poll-driven event loops deadlocked).
  - POSIX lowest-free fd allocation (sshd reopens `/dev/null` expecting fd 0).
  - PTY `ttyname` support (`/proc/self/fd/N`, `stat(/dev/pts/N)` with matching
    dev/ino) and suspend/wake on the pty line discipline.
  - **Async stdin** under JSPI (event-driven, not SAB-blocking) so the client waiting
    for a keystroke doesn't freeze the shell/server — required for live interactivity.
  - `setgroups`/`chroot` stubs; `execve` made suspend-capable (re-exec runs concurrently).

Remaining: port the fork substrate + async stdin to the browser worker; a few
per-package source walls (oniguruma `st.h`, ncurses native `tic`); farm scale-out.
The `clang.wasm` from-scratch build recipe is in `ci/` + `farm/` but is moot now that
a maintained prebuilt exists.

Not a from-scratch build: this rides the WALI project (github.com/arjunr2/WALI) for
the toolchain/ABI, and @yowasp/clang for the in-browser compiler. This repo is the
OS layer, browser port, process model, farm, DNS, and the aports browser on top.
`browser/pkgs/*.wasm` (the runnable packages) and `browser/yowasp/` (the 73 MB
clang) are produced by the farm / fetched from npm — not committed here.

## Tests

`tests/run.sh` — regression suite. Each `tests/src/*.c` is compiled with the WALI
clang (`tests/cc.sh`) and run under `host/host.js`; a test passes if it exits 0 and
its last stdout line is `PASS`. `tests/src-jspi/*.c` additionally exercise the JSPI
concurrent scheduler and Asyncify fork (needs node >= 24; fork tests are built with
`-D__WALI_ASYNCIFY_FORK` and post-processed with `wasm-opt --asyncify`).
Override `HOST=` to point the suite at any host build.
