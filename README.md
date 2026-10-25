# walios

**A Linux userland that runs as native WebAssembly in your browser tab.** busybox,
CPython 3.14 with numpy/pandas/matplotlib, clang 22, make, git, jq, lua, QuickJS and
OpenSSH are ordinary Linux builds compiled for the
[WALI](https://github.com/arjunr2/WALI) ABI (`wasm32-unknown-linux-muslwali`); a
JavaScript kernel in a Web Worker answers their Linux syscalls. There is no CPU
emulator and no server doing the work: every command is a wasm module, every
syscall a JS function.

> **Try it live:** <https://eze-paz.github.io/walios/> — a shell with a persistent
> home directory (OPFS), Python with C extensions, an in-tab C compiler. The page
> itself is static; outbound networking (`wget`, `git clone`, `ssh`) needs a
> WISP relay of your own, see [Networking](#networking-wisp).

```
walios:/root$ uname -a
Linux wali 6.1.0-wali #1 WALI-browser wasm32
walios:/root$ python3 -c "import numpy as np; print(np.__version__, np.arange(10).sum())"
2.5.2 45
walios:/root$ printf '#include <stdio.h>\nint main(){puts("hello from wasm clang");}' > h.c && cc h.c -o h && ./h
hello from wasm clang
walios:/root$ seq 1 100000 | wc -l
100000
```

Measured on the public page in Chromium, cold cache, laptop CPU: prompt in **0.7 s**,
first `python3` in 5.8 s (9 MB interpreter fetch, 0.14 s instantiate), numpy import
3.8 s (15 MB bundle mounted on the import miss), first `cc` 3.1 s (75 MB clang
fetch, 0.5 s instantiate); after that each command starts in tens of milliseconds.

---

## Why

Pyodide, v86 and CheerpX each give you one of: real packages, a real OS, or native
speed. Compiling the userland itself to wasm against a thin Linux syscall interface
gives all three: the programs are the upstream programs (no per-package porting),
the OS semantics are Linux (fork, pipes, ptys, signals, permissions), and the code
runs at wasm speed because nothing is being emulated. A measured comparison from
this project's history: the same CPython workload runs **~76x faster** here than on
the RISC-V emulator it replaced ([TabLinux](https://github.com/eze-paz/TabLinux)),
and at parity with Pyodide once warm.

## Architecture

```
 page (terminal.html)           xterm.js pty <-> postMessage
        |
        v
 wali-worker.js  -- KERNEL --  VFS, process table, ptys, signals, sockets,
        |                      dlopen loader, lazy tar mounts, OPFS bridge
        |   SharedArrayBuffer control block per process
        +-- wali-proc-worker.js   process 1 (e.g. ash)      \ one Web Worker
        +-- wali-proc-worker.js   process 2 (e.g. python3)  | per Linux process;
        +-- wali-proc-worker.js   process 3 (e.g. wasm-ld)  / blocking syscalls
                                                              park in Atomics.wait
 opfs-worker.js   /root on the Origin Private File System (persistent)
 wisp-worker.js   TCP/UDP/ICMP/DNS over one WebSocket to a WISP relay
```

- **ABI.** Guests import `wali.SYS_<name>` with x86-64 syscall numbers and struct
  layouts (`long` is 64-bit, pointers 32-bit: the `muslwali` triple). The kernel
  marshals x86-64 structs, so unmodified musl programs work.
- **Processes.** Every process has its own worker and instance. The kernel never
  blocks: a blocking syscall sets a flag in the shared control block and the
  process worker waits on it while the kernel serves everyone else. `fork()` is an
  Asyncify unwind of the caller, a copy of its linear memory into a fresh instance,
  and a rewind of both (`musl-patches/asyncify-fork.md`); `vfork`+`execve` is the
  cheap path and what busybox uses. CPython gets `ENOSYS` from `fork` on purpose.
- **Without SharedArrayBuffer** (a page that is not cross-origin isolated, e.g. an
  Android WebView) the kernel has a second engine that runs processes in-kernel and
  suspends them at blocking syscalls with JSPI. The public page instead installs a
  tiny service worker (`browser/coi-sw.js`) that adds COOP/COEP so the worker engine
  runs on GitHub Pages.
- **Python C extensions.** `python_cxx.wasm` exports a complete libc + libc++ and
  loads numpy, pandas, lxml, Pillow, matplotlib and friends as PIC wasm side modules
  through `dlopen`. Package bundles are tarballs mounted lazily on the first import
  miss (a `sitecustomize` hook asks the host over `/dev/hostcall`).
- **Toolchain in the tab.** `cc` is a driver script around one 75 MB `clang.wasm`
  (LLVM 22, dispatching on `argv[0]` for clang, wasm-ld, llvm-ar, ...) with the WALI
  musl sysroot and OpenSSL headers/libs mounted at `/sysroot`. Autotools packages
  build with a plain `./configure && make` (`/etc/config.site` presets the build
  triple); `build-pkg <aport>` fetches an Alpine APKBUILD and builds it.
- **Networking (WISP).** Sockets go to a sibling worker that multiplexes streams over
  one WebSocket to a relay. Three TLS tiers: the relay terminates TLS for busybox
  `wget` (`/bin/openssl` shim), while `curl`, `git`, `ssh` and Python link OpenSSL
  3.0 in-guest. Loopback TCP (`nc -l`, a local sshd) never touches the relay.
- **Persistence.** `/root` is the origin's OPFS; everything else is an in-memory VFS
  seeded from `rootfs.tar.gz` and the lazy bundles.

## Repository layout

| path | what |
|---|---|
| `browser/wali-worker.js` | the kernel: syscalls, VFS, process table, ptys, dlopen, mounts |
| `browser/wali-proc-worker.js` | per-process worker: instantiates the guest, proxies syscalls over the SAB |
| `browser/opfs-worker.js`, `browser/wisp-worker.js` | OPFS and network bridges |
| `browser/walios-backend.js` | boot manifest: programs, bundles, env, the guest-host call channel |
| `index.html`, `browser/terminal.html`, `browser/selftest.html` | the terminal (root page of the site), the same page served from inside `browser/`, a scripted self-test |
| `browser/bin/` | in-guest scripts: `cc`, `ld`, `ar`, `nm`, `build-pkg`, `wfetch`, `wextract`, `pkg-config`, `npm-lite` |
| `browser/src/` | `tlswrap.c`, `openssl-shim.c` (relay-terminated TLS helpers) |
| `browser/*.wasm`, `browser/*.tar.gz`, `browser/pkgcache/`, `browser/pkgs/` | prebuilt programs and bundles the page serves (see NOTICE for licenses) |
| `relay/` | the WISP relay (`node relay/wisp-standalone.mjs`) |
| `farm/` | cross-compile recipes: busybox, OpenSSL, OpenSSH, git, jq, oniguruma, tlswrap, the Alpine aports farm |
| `musl-patches/` | the Asyncify `fork`, `execve`, `_Exit` and setjmp changes against wali-musl |
| `host/` | a Node.js host for the same binaries (used by the native test suite) |
| `tests/` | C regression tests run under the Node host: fs, pipes, pty, signals, epoll, shm, creds, ... |
| `.github/workflows/build-wasm-clang.yml` | builds `clang.wasm` from LLVM source on a CI runner |

## Run it locally

```
git clone https://github.com/eze-paz/walios
cd walios/browser && python3 coi.py 8765      # static server with COOP/COEP headers
# open http://127.0.0.1:8765/terminal.html
```

Any static server works if it sends `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`; without them the page registers
`coi-sw.js` (one copy at the root for `index.html`, one in `browser/`) and reloads once.

### Networking (WISP)

The page has no network until you point it at a relay. Run one:

```
cd relay && WISP_ENABLED=1 WISP_ALLOW_HOSTS='github.com,*.githubusercontent.com,pypi.org,files.pythonhosted.org' node wisp-standalone.mjs 6970
```

then open `terminal.html?wisp=ws://127.0.0.1:6970/wisp` once (the URL is remembered
in localStorage; an empty `?wisp=` clears it). The relay is deliberately allow-listed
by host and port and can require a token (`WISP_TOKEN`); do not expose an open relay.
Public third-party WISP relays will not do: the TLS-terminating connection type and
the DNS/ICMP frames walios uses are extensions of this relay.

### Self-test

`browser/selftest.html` runs scripted assertions against a fresh kernel (VFS, OPFS
persistence across workers, permissions and symlinks as uid 1000, signals, pipes)
and reports `pass=N fail=M` in the page title, so it is drivable from any browser
automation.

## Building the binaries

Nothing under `browser/` is hand-written wasm; it is all upstream source compiled
with the WALI toolchain. `farm/` holds the recipes (`build-busybox-wali.sh`,
`build-openssl-wali.sh`, `build-git-wali.sh`, `build-jq-wali.sh`,
`build-oniguruma-wali.sh`, `build-tlswrap-wali.sh`, `farm.sh` for Alpine aports) and
`musl-patches/` the libc changes; `.github/workflows/build-wasm-clang.yml` produces
`clang.wasm` on a runner with swap because the final link needs more RAM than a
laptop has. The CPython main with libc++ and the dlopen side-module builds use a
crossenv wrapper around the same clang; the two rules that make side modules work
are in the kernel's loader comments: a `.so` may only import symbols the main
exports (loud link errors instead of silent stubs), and the main's export list is
regenerated after every relink.

Rule for package work, learned the hard way: when a package fails here, it is the
OS or toolchain breaking the Linux contract, so fix the loader, the sysroot or the
kernel, never the package source.

## Known limits

- Threads: `pthread_create` returns `EAGAIN` in the shipped Python (the worker-per-
  thread engine exists for WASI-threads binaries such as rustc but is not wired to
  WALI's thread spawn yet).
- `rustc` works but its 126 MB module is above GitHub's file cap, so it is not on
  the public page.
- Autotools builds need release tarballs with a pre-generated `configure`
  (no autoconf/automake/perl in the guest yet).
- Safari and Firefox are untested; Chrome and Edge on desktop and Android are what
  this is developed against.

## Credits

The ABI and the musl port are the [WALI project](https://github.com/arjunr2/WALI)
(Arjun Ramesh et al., CMU, MIT license); `clang.wasm` starts from the
[YoWASP](https://yowasp.org/) LLVM build. Everything on top, the browser kernel and
process model, the OPFS and WISP bridges, the dlopen loader and Python bundles, the
in-tab toolchain, the farm and the tests, is this repository, MIT licensed.
Bundled programs keep their own licenses, listed in [NOTICE](NOTICE).
