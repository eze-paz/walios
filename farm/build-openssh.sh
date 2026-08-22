#!/bin/bash
# Build OpenSSH for WALI (wasm32-unknown-linux-muslwali) with the native WALI
# toolchain: zlib from release tarball, then openssh --without-openssl.
set -uo pipefail
W=~/wali/build
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -pthread -fdeclspec -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types -Wno-unused-command-line-argument"
LDF="-L$W/sysroot/lib -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608"
AR="$W/llvm/bin/llvm-ar"; RANLIB="$W/llvm/bin/llvm-ranlib"; LD="$HOME/walihost/wali-ld"
export CONFIG_SITE="$HOME/wali-farm/config.site"
ROOT=~/openssh-wali; rm -rf $ROOT; mkdir -p $ROOT; cd $ROOT

echo "=== [1/3] fetch sources"
curl -sL -o zlib.tgz https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && tar xf zlib.tgz
curl -sL -o openssh.tgz https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz && tar xf openssh.tgz

echo "=== [2/3] build zlib"
cd $ROOT/zlib-1.3.1
CC="$CC" CFLAGS="" LDFLAGS="$LDF" AR="$AR" RANLIB="$RANLIB" cross_compiling=yes ./configure --static --prefix=$ROOT/zlib-inst >/tmp/zlib_cfg.log 2>&1
make CC="$CC" AR="$AR" RANLIB="$RANLIB" libz.a >/tmp/zlib_make.log 2>&1 && make install >/tmp/zlib_inst.log 2>&1
echo "zlib libz.a: $(ls -la $ROOT/zlib-inst/lib/libz.a 2>/dev/null | awk '{print $5}') bytes"

echo "=== [3/3] configure + build openssh (--without-openssl)"
cd $ROOT/openssh-9.9p1
./configure --host=wasm32-unknown-linux-musl --build=x86_64-pc-linux-gnu \
  --without-openssl --with-zlib=$ROOT/zlib-inst --without-pie --disable-utmp --disable-wtmp \
  CC="$CC" CFLAGS="" LDFLAGS="$LDF" LIBS="-lpthread" AR="$AR" RANLIB="$RANLIB" LD="$LD" \
  cross_compiling=yes >/tmp/ssh_cfg.log 2>&1
echo "configure exit=$?; tail:"; tail -3 /tmp/ssh_cfg.log
make -j8 ssh sshd >/tmp/ssh_make.log 2>&1
echo "make exit=$?"
echo "=== artifacts (wasm?):"
for b in ssh sshd; do [ -f $b ] && printf "%s: %s  magic=%s\n" "$b" "$(du -h $b|cut -f1)" "$(head -c4 $b|od -An -tx1|tr -d ' \n')"; done
echo "=== last errors if any:"; grep -iE "error:|undefined symbol|cannot" /tmp/ssh_make.log | grep -viE "Wno-|warning" | tail -6
