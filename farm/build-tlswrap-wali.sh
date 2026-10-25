#!/bin/sh
# Build walios/src/tlswrap.c for the WALI target -> walios/pkgcache/tlswrap.wasm.
#
# RUN ON WSL/Linux with the WALI toolchain at ~/wali/build (llvm + sysroot), same as
# build-busybox-wali.sh and build-oniguruma-wali.sh.
#
# Replaces a prebuilt tlswrap.wasm that had no source in any repo or on the build box and
# could not work: it hung on every proxied request. A proxy of the identical shape written
# in python, run in the same guest, worked first time -- so the fault was in that binary,
# and with no source there was nothing to fix. See walios/src/tlswrap.c for the full story.
#
# openssl-shim.c is built the same way and never had a script, so the recipe is here too --
# but only with `WITH_OPENSSL=1`, deliberately. A stray rebuild would overwrite a working
# openssl.wasm that `wget https://` depends on, and a rebuild is NOT bit-identical to the
# shipped one (95402 vs 95404 bytes), so it is not a safe no-op.
set -e

W=${WALI_BUILD:-~/wali/build}
SRC=${SRC:-$PWD/walios/src}
OUT=${OUT:-$PWD/walios/pkgcache}

[ -x "$W/llvm/bin/clang" ] || { echo "no WALI clang at $W/llvm/bin/clang"; exit 1; }
[ -d "$W/sysroot" ]        || { echo "no WALI sysroot at $W/sysroot"; exit 1; }
[ -f "$SRC/tlswrap.c" ]    || { echo "no $SRC/tlswrap.c"; exit 1; }

CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -L$W/sysroot/lib"

# The same wasm feature set the rest of the userland is built with (see
# build-busybox-wali.sh): the kernel instantiates every guest the same way, and a module
# built without these does not load.
FEATURES="-O2 -matomics -mbulk-memory -mexception-handling -fwasm-exceptions -mllvm -wasm-enable-sjlj"
LDFLAGS="-Wl,--shared-memory,--export-memory,--max-memory=268435456,-z,stack-size=1048576"

mkdir -p "$OUT"
PROGS=tlswrap
[ -n "$WITH_OPENSSL" ] && PROGS="$PROGS openssl-shim"
for prog in $PROGS; do
  [ -f "$SRC/$prog.c" ] || continue
  # openssl-shim is installed as /bin/openssl, tlswrap as /bin/tlswrap.
  case "$prog" in openssl-shim) name=openssl ;; *) name=$prog ;; esac
  $CC $FEATURES $LDFLAGS "$SRC/$prog.c" -o "$OUT/$name.wasm" \
    || { echo "FAILED to build $prog"; exit 1; }
  echo "built $OUT/$name.wasm ($(stat -c%s "$OUT/$name.wasm") bytes)"
done

echo
echo "Both are already listed in walios/pkgcache/index.json; no index change is needed."
echo "Deploy: scp the .wasm files to the server's walios/pkgcache/ (gitignored there, like"
echo "every other binary asset), and bump nothing -- the kernel fetches them by name."
