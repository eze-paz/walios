#!/bin/bash
# Build OpenSSL 1.1.1 libcrypto for wasm32-unknown-linux-muslwali, so OpenSSH can do
# RSA/ECDSA (the --without-openssl build is ed25519-only). WALI = real Linux syscalls,
# so "linux-generic32 no-asm" is the right base; we drop everything that needs ucontext
# (no-async), dlopen (no-dso/no-engine), or the kernel crypto socket (no-afalgeng).
set -uo pipefail
W=~/wali/build
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -pthread -matomics -mbulk-memory -fwasm-exceptions -mllvm -wasm-enable-sjlj -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument"
AR="$W/llvm/bin/llvm-ar"; RANLIB="$W/llvm/bin/llvm-ranlib"
ROOT=~/openssl-wali; rm -rf "$ROOT"; mkdir -p "$ROOT"; cd "$ROOT"

echo "=== fetch openssl 1.1.1w ==="
curl -sL -o ossl.tgz https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz && tar xf ossl.tgz
cd openssl-1.1.1w

echo "=== configure (linux-generic32, no-asm) ==="
CC="$CC" AR="$AR" RANLIB="$RANLIB" ./Configure linux-generic32 \
  no-asm no-shared no-dso no-engine no-async no-tests no-afalgeng no-ui-console no-sse2 \
  -DOPENSSL_NO_SECURE_MEMORY \
  --prefix="$ROOT/inst" >/tmp/ossl_cfg.log 2>&1
echo "configure exit=$?; tail:"; tail -4 /tmp/ossl_cfg.log
