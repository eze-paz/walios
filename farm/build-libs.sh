#!/bin/bash
# Build the cluster libs (pcre2, oniguruma) as static WALI wasm libs into the
# overlay sysroot, from release tarballs (which ship ./configure — the aports
# use git archives needing autoreconf, which isn't installed).
set -uo pipefail
W=~/wali/build; OV=${1:-$HOME/wali-farm/overlay}
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-unused-command-line-argument"
LDF="-L$W/sysroot/lib -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608"
AR="$W/llvm/bin/llvm-ar"; RANLIB="$W/llvm/bin/llvm-ranlib"
export CONFIG_SITE="$HOME/wali-farm/config.site"
mkdir -p "$OV/usr/lib" "$OV/usr/include"
ROOT=~/wali-libs; rm -rf $ROOT; mkdir -p $ROOT; cd $ROOT

build_one() {  # name url subdir configureflags
  local name="$1" url="$2" dir="$3"; shift 3
  echo "=== $name"
  curl -sL -o "$name.tar.gz" "$url" && tar xf "$name.tar.gz" || { echo "$name: fetch FAIL"; return 1; }
  cd "$ROOT/$dir"
  CC="$CC" CFLAGS="" LDFLAGS="$LDF" AR="$AR" RANLIB="$RANLIB" cross_compiling=yes \
    ./configure --host=wasm32-unknown-linux-musl --disable-shared --enable-static --prefix="$OV/usr" "$@" >"$ROOT/$name-cfg.log" 2>&1 || { echo "$name: configure FAIL"; tail -3 "$ROOT/$name-cfg.log"; cd $ROOT; return 1; }
  make -j8 CC="$CC" AR="$AR" RANLIB="$RANLIB" >"$ROOT/$name-make.log" 2>&1
  make install >"$ROOT/$name-inst.log" 2>&1 || true
  cd $ROOT
}

build_one pcre2 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.44/pcre2-10.44.tar.gz" pcre2-10.44
build_one oniguruma "https://github.com/kkos/oniguruma/releases/download/v6.9.9/onig-6.9.9.tar.gz" onig-6.9.9

echo "=== installed libs:"
ls -la "$OV/usr/lib/"libpcre2*.a "$OV/usr/lib/"libonig*.a 2>/dev/null
for a in "$OV/usr/lib/libpcre2-8.a" "$OV/usr/lib/libonig.a"; do
  [ -f "$a" ] && echo "$(basename $a): $(du -h "$a"|cut -f1) $($AR t "$a" 2>/dev/null | head -1)"
done
