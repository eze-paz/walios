# Go for walios (GOOS=linux GOARCH=wasm)

A port of Go 1.27 to the walios kernel (WALI, the Linux syscall interface for wasm). Go
programs build with the stock linux code of `syscall`, `os`, `net`, `x/sys/unix`-style
libraries; only the bottom layer differs:

- `internal/runtime/syscall/linux.Syscall6` is a generated switch over host imports
  `wali.SYS_<name>` (tools/gen_dispatch.py from tools/wali-table.json, which comes from the
  WALI spec `spec/wali/spec/syscalls.py`: x86-64 numbers, i32 for pointers/int/size_t, i64
  for 8-byte types; checked against the signatures in walios' own binaries).
- Struct layouts are linux/amd64's (`ztypes_linux_wasm.go` = amd64), which match walios'
  64-bit-long ABI for pointer-free structs (stat is 144-byte x86-64).
- The runtime is single-threaded like wasip1 (lock_linux_wasm.go, poll(2) netpoller,
  no signals); argv/env from WALI's `__cl_*` / `__get_init_envfile0` imports.
- The linker imports `env.memory` shared (max 2 GiB) and exports `_start`, which walios'
  worker engine requires.

Status 2026-11-27 (probes/): hello, goroutines, file I/O in /tmp and the OPFS /root,
TCP + DNS (needs the walios kernel fix for write() on connected UDP), HTTPS with Go's TLS:
all pass on both walios engines (COI workers and in-process JSPI).

rclone (farm/go-walios/rclone): v1.76.0 trimmed to the dropbox, http and local backends
(cmd-walios/main.go), dependencies patched by tools/mkpatched.py from rclone/rules.txt
(x/sys gets linux/wasm = linux/amd64 tables; `mirror` makes a no-asm package's linux/wasm file
set equal its linux/amd64 one). 2026-11-27: version, lsf, copy, cat on local files and an
HTTPS http remote pass on both engines; the dropbox backend reaches the API. Needed a runtime
change: wasm has no sysmon, so findRunnable polls the network every 10 ms itself.

Not yet: os/exec (no vfork), signals, structs with pointers (iovec, msghdr: walios reads
4-byte pointers; Go writes 8), x/sys/unix for linux/wasm (rclone needs it).

Build: push this folder; .github/workflows/go-walios.yml applies go-walios.patch to
GOVERSION, builds the toolchain, std and probes, and publishes a release with a Windows
copy of the tools for local iteration.
