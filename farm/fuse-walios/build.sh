#!/bin/bash
# libfuse 3 examples (hello, hello_ll, passthrough, passthrough_ll, passthrough_fh, null) and
# pjdfstest, built for walios with the farm toolchain. Used by .github/workflows/fuse-walios.yml.
# Their purpose: test FUSE in the walios kernel (sandpie docs/plans/walios-fuse-rclone.md, phase 1).
#   build.sh <toolchain dir> <out dir>
set -uo pipefail
TC=$1; OUT=$(realpath -m "$2"); mkdir -p "$OUT"
. "$TC/env.sh"
export PATH="$TC/bin:$PATH"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FUSEVER=$(cat "$HERE/LIBFUSE_VERSION")
W=$(mktemp -d)
sum() { echo "$*" | tee -a "$OUT/summary.txt"; }

# ---- libfuse ----
( cd "$W" && curl -sSfL --retry 8 -o fuse.tgz "https://github.com/libfuse/libfuse/releases/download/fuse-$FUSEVER/fuse-$FUSEVER.tar.gz" && tar xzf fuse.tgz ) || { sum "libfuse download FAIL"; exit 1; }
cd "$W/fuse-$FUSEVER"
for p in "$HERE"/patches/libfuse-*.patch; do [ -f "$p" ] && { patch -p1 < "$p" || sum "patch $p FAIL"; }; done
meson setup --cross-file "$TC/wali.meson" --prefix=/usr --default-library=static \
  -Dexamples=true -Dutils=false -Dtests=false -Dinitscriptdir= build > "$OUT/libfuse-setup.log" 2>&1 \
  || meson setup --cross-file "$TC/wali.meson" --prefix=/usr --default-library=static \
  -Dexamples=true -Dutils=false -Dtests=false build > "$OUT/libfuse-setup.log" 2>&1 \
  || { sum "libfuse setup FAIL"; tail -60 "$OUT/libfuse-setup.log"; exit 1; }
if ninja -C build -k 0 > "$OUT/libfuse-build.log" 2>&1; then sum "libfuse build OK"; else sum "libfuse build partial"; grep -B2 -A12 "error:" "$OUT/libfuse-build.log" | head -120; fi
for x in hello hello_ll passthrough passthrough_ll passthrough_fh null ioctl poll notify_inval_entry notify_inval_inode invalidate_path; do
  if [ -f "build/example/$x" ]; then cp "build/example/$x" "$OUT/fuse-$x.wasm"; sum "example $x OK ($(stat -c %s "build/example/$x") bytes)"; else sum "example $x missing"; fi
done
# the static library + headers, for anything else that wants to link FUSE filesystems
mkdir -p "$W/fdev/usr/lib" "$W/fdev/usr/include/fuse3"
cp build/lib/libfuse3.a "$W/fdev/usr/lib/" 2>/dev/null && cp include/*.h "$W/fdev/usr/include/fuse3/" && cp build/libfuse_config.h "$W/fdev/usr/include/fuse3/" 2>/dev/null
tar czf "$OUT/libfuse3-dev.tar.gz" -C "$W/fdev" usr

# ---- pjdfstest ----
cd "$W"
if git clone -q --depth 1 https://github.com/pjd/pjdfstest.git pjd; then
  cd pjd
  for p in "$HERE"/patches/pjdfstest-*.patch; do [ -f "$p" ] && { patch -p1 < "$p" || sum "patch $p FAIL"; }; done
  ( autoreconf -ifs && ./configure --host=wasm32-unknown-linux-musl CC=wali-cc ) > "$OUT/pjdfstest-configure.log" 2>&1 || sum "pjdfstest configure FAIL"
  if make -k > "$OUT/pjdfstest-build.log" 2>&1 && [ -f pjdfstest ]; then
    cp pjdfstest "$OUT/pjdfstest.wasm"; sum "pjdfstest OK"
    tar czf "$OUT/pjdfstest-tests.tar.gz" tests
  else sum "pjdfstest build FAIL"; grep -B2 -A10 "error:" "$OUT/pjdfstest-build.log" | head -80; fi
else sum "pjdfstest clone FAIL"; fi
exit 0
