#!/bin/bash
# Rebuild the OpenSSH `ssh` client WITH our wali libcrypto, so RSA/ECDSA keys work.
set -uo pipefail
W=~/wali/build
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -pthread -fdeclspec -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types -Wno-unused-command-line-argument"
LDF="-L$W/sysroot/lib -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608"
AR="$W/llvm/bin/llvm-ar"; RANLIB="$W/llvm/bin/llvm-ranlib"; LD="$HOME/walihost/wali-ld"
export CONFIG_SITE="$HOME/wali-farm/config.site"
OSSL=~/openssl-wali/openssl-1.1.1w; INST=~/openssl-wali/inst
ROOT=~/openssh-wali

echo "=== install libcrypto headers + lib to $INST ==="
rm -rf "$INST"; mkdir -p "$INST/include/openssl" "$INST/lib"
cp -r "$OSSL"/include/openssl/*.h "$INST/include/openssl/"
cp "$OSSL/libcrypto.a" "$INST/lib/"
echo "libcrypto.a: $(stat -c%s "$INST/lib/libcrypto.a") bytes; headers: $(ls "$INST/include/openssl" | wc -l)"

echo "=== zlib present? ==="
[ -f "$ROOT/zlib-inst/lib/libz.a" ] && echo "yes" || echo "NO zlib — run build-openssh.sh first"

echo "=== reconfigure openssh WITH openssl ==="
cd "$ROOT/openssh-9.9p1"
make clean >/dev/null 2>&1
./configure --host=wasm32-unknown-linux-musl --build=x86_64-pc-linux-gnu \
  --with-ssl-dir="$INST" --with-zlib="$ROOT/zlib-inst" --without-pie --disable-utmp --disable-wtmp \
  CC="$CC" CFLAGS="-I$INST/include" LDFLAGS="$LDF -L$INST/lib" LIBS="-lpthread" AR="$AR" RANLIB="$RANLIB" LD="$LD" \
  cross_compiling=yes >/tmp/ssh_ssl_cfg.log 2>&1
echo "configure exit=$?"
grep -iE "openssl|libcrypto|checking for RSA|error" /tmp/ssh_ssl_cfg.log | tail -8

echo "=== build ssh ==="
make -j8 ssh >/tmp/ssh_ssl_make.log 2>&1
echo "make exit=$?"
[ -f ssh ] && printf "ssh: %s  magic=%s\n" "$(du -h ssh|cut -f1)" "$(head -c4 ssh|od -An -tx1|tr -d ' \n')"
grep -iE "error:|undefined symbol|cannot find" /tmp/ssh_ssl_make.log | grep -viE "Wno-|warning" | tail -12
