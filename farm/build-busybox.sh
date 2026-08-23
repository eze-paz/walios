#!/bin/bash
# Build busybox 1.36.1 for wasm32-wali (~/busybox-1.36.1 tree, existing .config).
# Gotchas this script encodes:
#  - busybox's partial links ($(LD) -r) break if the linker driver has -pthread:
#    clang then passes --shared-memory to wasm-ld, which rejects it with -r.
#    So LD = bare clang (no -pthread); the final link gets shared-memory via
#    CC (-pthread) + EXTRA_LDFLAGS (only used at the final trylink step).
#  - applet set is controlled by ~/busybox-1.36.1/.config; enable applets with
#    sed CONFIG_X=y + `yes "" | make oldconfig` before running this.
set -e
BB=~/busybox-1.36.1
W=~/wali/build
CCB="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 \
 -mllvm -wasm-enable-sjlj -fwasm-exceptions -pthread -matomics -mbulk-memory -mexception-handling \
 -L$W/sysroot/lib -Wno-implicit-function-declaration -Wno-int-conversion \
 -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument"
LDB="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot"
cd "$BB"
make -j"$(nproc)" CC="$CCB" LD="$LDB" HOSTCC=cc SKIP_STRIP=y \
  EXTRA_LDFLAGS="-Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608"
echo "built: $BB/busybox ($(stat -c%s "$BB/busybox") bytes)"
echo "deploy: cp $BB/busybox ~/wali-www/busybox.wasm   # browser asset"
echo "        (node host fallback reads $BB/busybox in place)"
