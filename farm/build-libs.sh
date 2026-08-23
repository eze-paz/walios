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
  # oniguruma: st_data_t/hash_data_type only typedef'd when SIZEOF_VOIDP==SIZEOF_LONG or
  # ==SIZEOF_LONG_LONG. On wasm32-wali voidp=4 but long=long_long=8 so NEITHER matches and
  # the type is left undefined -> force the pointer-holding typedef branch.
  for f in src/st.h src/regint.h; do [ -f "$f" ] && sed -i "s/^#if SIZEOF_VOIDP == SIZEOF_LONG\$/#if 1 \/* wasm32-wali: voidp(4)!=long(8) *\//" "$f"; done
  CC="$CC" CFLAGS="" LDFLAGS="$LDF" AR="$AR" RANLIB="$RANLIB" cross_compiling=yes \
    ./configure --host=wasm32-unknown-linux-musl --disable-shared --enable-static --prefix="$OV/usr" "$@" >"$ROOT/$name-cfg.log" 2>&1 || { echo "$name: configure FAIL"; tail -3 "$ROOT/$name-cfg.log"; cd $ROOT; return 1; }
  make -j8 CC="$CC" AR="$AR" RANLIB="$RANLIB" >"$ROOT/$name-make.log" 2>&1
  make install >"$ROOT/$name-inst.log" 2>&1 || true
  cd $ROOT
}

build_one pcre2 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.44/pcre2-10.44.tar.gz" pcre2-10.44
build_one oniguruma "https://github.com/kkos/oniguruma/releases/download/v6.9.9/onig-6.9.9.tar.gz" onig-6.9.9

# ncurses: LIBRARY-ONLY. The classic wall is that a full build runs `tic` (a native
# terminfo compiler) during `make`, which can't run when cross-compiled to wasm.
# --without-progs --disable-db-install skips building/running tic entirely; we get
# libncursesw.a + headers. (Terminal apps still need a terminfo DB at runtime —
# ship one via $TERMINFO, e.g. copy the host's /usr/share/terminfo into the VFS.)
build_ncurses() {
  echo "=== ncurses (library-only)"
  cd "$ROOT"
  curl -sL -o ncurses.tar.gz https://ftp.gnu.org/gnu/ncurses/ncurses-6.5.tar.gz && tar xf ncurses.tar.gz || { echo "ncurses: fetch FAIL"; return 1; }
  cd "$ROOT/ncurses-6.5"
  CC="$CC" CFLAGS="" LDFLAGS="$LDF" AR="$AR" RANLIB="$RANLIB" cross_compiling=yes \
    ./configure --host=wasm32-unknown-linux-musl --prefix="$OV/usr" \
      --without-shared --without-cxx --without-cxx-binding --without-ada \
      --without-manpages --without-progs --without-tests --disable-db-install \
      --without-develop --with-build-cc=cc --disable-stripping >"$ROOT/ncurses-cfg.log" 2>&1 || { echo "ncurses: configure FAIL"; tail -3 "$ROOT/ncurses-cfg.log"; return 1; }
  make -C include >"$ROOT/ncurses-inc.log" 2>&1
  make -C ncurses libs >"$ROOT/ncurses-make.log" 2>&1 || { echo "ncurses: make FAIL"; grep -iE "error:" "$ROOT/ncurses-make.log" | head -3; return 1; }
  make -C include install >/dev/null 2>&1
  cp lib/libncursesw.a "$OV/usr/lib/" && cp include/*.h "$OV/usr/include/" 2>/dev/null
  ln -sf libncursesw.a "$OV/usr/lib/libncurses.a"
  cd "$ROOT"
}
build_ncurses

echo "=== installed libs:"
ls -la "$OV/usr/lib/"libpcre2*.a "$OV/usr/lib/"libonig*.a "$OV/usr/lib/"libncurses*.a 2>/dev/null
for a in "$OV/usr/lib/libpcre2-8.a" "$OV/usr/lib/libonig.a" "$OV/usr/lib/libncursesw.a"; do
  [ -f "$a" ] && echo "$(basename $a): $(du -h "$a"|cut -f1) $($AR t "$a" 2>/dev/null | head -1)"
done
