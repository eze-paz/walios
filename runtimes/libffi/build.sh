#!/usr/bin/env bash
# Build libffi for walios: libffi-wali.tar.gz = usr/include/ffi.h + ffitarget.h,
# usr/lib/libffi.a, usr/lib/pkgconfig/libffi.pc, unpacked into the farm toolchain's sysroot
# (farm/ci/toolchain.sh). libffi's own wasm32 target is Emscripten-only (its calls and
# closures are JS glue); ffi.c here is the WALI one, where the kernel does the calls
# (__wali_ffi_*: walios/wali-worker.js, wali-proc-worker.js, the farm's host/host.js).
#
#   build.sh [workdir]   -> <workdir>/libffi-wali.tar.gz
#   WALI_ABI=ilp32 build.sh [workdir]   -> <workdir>/libffi-wali32.tar.gz (walios ILP32 ABI)
#
# Toolchain: $WALI_TC (an existing farm toolchain dir, of the same ABI) or one set up in
# <workdir>/tc.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=libffi-wali$([ "${WALI_ABI:-wali}" = ilp32 ] && echo 32).tar.gz
R=$(realpath -m "${1:-$HOME/libffi-wali-build}")
mkdir -p "$R" && cd "$R"
FFI_VER=3.8.0               # Alpine edge's libffi
WALIOS_REF=main

if [ -z "${WALI_TC:-}" ]; then
  if [ ! -d walios-farm ]; then
    git clone -q --depth 1 --branch $WALIOS_REF --filter=blob:none --sparse https://github.com/eze-paz/walios.git walios-farm
    git -C walios-farm sparse-checkout set farm/ci
  fi
  bash walios-farm/farm/ci/toolchain.sh "$R/tc" >tc.log 2>&1
  WALI_TC=$R/tc
fi
source "$WALI_TC/env.sh"

[ -d libffi-$FFI_VER ] || curl -sSfL https://github.com/libffi/libffi/releases/download/v$FFI_VER/libffi-$FFI_VER.tar.gz | tar xz
rm -rf src && cp -r libffi-$FFI_VER src && cd src
cp "$HERE/ffi.c" src/wasm/ffi.c
# closures.c's mmap'd trampolines are for native code; ffi.c allocates closures (a table index
# each) itself, as Emscripten's does.
sed -i 's/^#ifndef __EMSCRIPTEN__$/#if !defined(__EMSCRIPTEN__) \&\& !defined(__wali__)/' src/closures.c
grep -q 'defined(__wali__)' src/closures.c || { echo "closures.c guard patch did not apply" >&2; exit 1; }
# --disable-multi-os-directory: configure asks $CC -print-multi-os-directory, which clang
# rejects for this target.
./configure --host=wasm32-unknown-linux-musl --build=x86_64-pc-linux-gnu --prefix=/usr \
  --disable-shared --enable-static --disable-multi-os-directory --disable-docs --disable-exec-static-tramp \
  >../cfg.log 2>&1
make -j"$(nproc)" >../build.log 2>&1
rm -rf ../stage && make install DESTDIR="$R/stage" >../install.log 2>&1
cd ../stage
for f in usr/include/ffi.h usr/include/ffitarget.h usr/lib/libffi.a usr/lib/pkgconfig/libffi.pc; do
  [ -f "$f" ] || { echo "libffi: $f missing" >&2; exit 1; }
done
tar czf "$R/$OUT" --owner=0 --group=0 usr/include/ffi.h usr/include/ffitarget.h usr/lib/libffi.a usr/lib/pkgconfig/libffi.pc
echo "built $R/$OUT"
