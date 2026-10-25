#!/usr/bin/env bash
# Build git (2.45.3) for walios: wasm32 WALI, WITH pthreads, memory IMPORTED.
#
# Why this exists: the git that shipped in pkgcache was built with NO_PTHREADS. In git,
# `start_async()` -- the sideband demultiplexer send-pack starts right before it streams
# the packfile -- is a thread when pthreads exist and a fork() WITHOUT exec otherwise.
# walios cannot fork a non-Asyncify binary for real: the vfork protocol runs the child
# branch INLINE in the parent until it execs or exits. That child blocks reading the
# server's reply, which cannot arrive until the parent sends the pack, so every `git push`
# hung until the tool's timeout (fetch survived only because its demuxer reads data the
# server is already sending). With pthreads the demuxer is a real thread on its own
# worker (see wali-worker.js threadSpawn), which needs the module to IMPORT its memory --
# hence the wasm-import-memory pass at the end.
#
# The recipe reproduces the recorded GIT-CFLAGS of the previous build (same curl/ssl/zlib
# builds under ~/curl-wali, same wali-cc wrapper) minus NO_PTHREADS. Run in WSL:
#
#   bash scripts/build-git-wali.sh
#   # -> ~/git-out/git.wasm, git-remote-https.wasm, git-remote-http.wasm (memory imported)
#   # then copy them over the box's /opt/sandpie-server/walios/pkgcache/*.wasm
set -euo pipefail
SRC="${SRC:-$HOME/git-wali/git-2.45.3}"
WCC="${WCC:-$HOME/git-wali/wali-cc}"
CURLCFG="${CURLCFG:-$HOME/git-wali/curl-config}"
OUT="${OUT:-$HOME/git-out}"
W="${W:-$HOME/wali/build}"
IMPORT_MEMORY_TOOL="${IMPORT_MEMORY_TOOL:-$(cd "$(dirname "$0")" && pwd)/wasm-import-memory.mjs}"
[ -x "$WCC" ] || { echo "!! $WCC missing"; exit 1; }
[ -d "$SRC" ] || { echo "!! $SRC missing"; exit 1; }
mkdir -p "$OUT"

cd "$SRC"
# Every make variable the recorded GIT-CFLAGS implies, except NO_PTHREADS. uname_S/M pin
# the host-detection to what the previous build used (config.mak.uname Linux defaults).
MAKEVARS=(
  CC="$WCC" AR="$W/llvm/bin/llvm-ar" RANLIB="$W/llvm/bin/llvm-ranlib"
  CURL_CONFIG="$CURLCFG" CURLDIR= NO_R_TO_GCC_LINKER=YesPlease
  uname_S=Linux uname_M=x86_64 uname_R=6.0 HOST_CPU=x86_64
  NO_OPENSSL=YesPlease NO_GETTEXT=YesPlease NO_UNIX_SOCKETS=YesPlease NO_ICONV=YesPlease
  NO_STRLCPY=YesPlease NO_REGEX=YesPlease NO_EXPAT=YesPlease NO_TCLTK=YesPlease NO_PERL=YesPlease
  NO_PYTHON=YesPlease NO_GITWEB=YesPlease NO_INSTALL_HARDLINKS=YesPlease
  HAVE_ALLOCA_H=YesPlease HAVE_SYSINFO=YesPlease NO_MMAP= NO_PTHREADS=
  ZLIB_PATH="$HOME/curl-wali/z-inst" CFLAGS="-O2 -I$HOME/curl-wali/z-inst/include"
  LDFLAGS="-L$HOME/curl-wali/z-inst/lib -Wl,--export-table"
  SHELL_PATH=/bin/sh V=1
)
echo "== cleaning objects compiled with -DNO_PTHREADS (GIT-CFLAGS changes force it anyway)"
[ -n "${CLEAN:-}" ] && make "${MAKEVARS[@]}" clean >/dev/null 2>&1 || true
echo "== building git + git-remote-http (pthreads ON)"
make -j"$(nproc)" "${MAKEVARS[@]}" git git-remote-http 2>&1 | tail -5
grep -q "NO_PTHREADS" GIT-CFLAGS && { echo "!! GIT-CFLAGS still has NO_PTHREADS"; exit 1; }
echo "== GIT-CFLAGS: $(cat GIT-CFLAGS | cut -c1-200)..."

echo "== importing memory (threads need a shared memory the kernel creates)"
for b in git git-remote-http; do
  head -c4 "$b" | od -An -tx1 | grep -qi "00 61 73 6d" || { echo "!! $b is not wasm"; exit 1; }
  node "$IMPORT_MEMORY_TOOL" "$b" "$OUT/$b.wasm"
done
cp "$OUT/git-remote-http.wasm" "$OUT/git-remote-https.wasm"   # same binary, dispatches on argv[0]
node -e '
const fs=require("fs"); for (const f of process.argv.slice(1)) WebAssembly.compile(fs.readFileSync(f)).then(m=>{const im=WebAssembly.Module.imports(m).map(i=>i.module+"."+i.name), ex=WebAssembly.Module.exports(m).map(e=>e.name);
console.log(f.split("/").pop(), "| thread_spawn:", im.includes("wali.__wasm_thread_spawn"), "| thread start export:", ex.includes("__wasm_thread_start_libc"), "| memory imported:", im.includes("env.memory"), "|", (fs.statSync(f).size/1e6).toFixed(1)+"MB");})' "$OUT/git.wasm" "$OUT/git-remote-https.wasm"
echo "== done -> $OUT"
