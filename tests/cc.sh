#!/bin/bash
# Compile one C file to wasm32-wali (same flags the farm uses, minus overlay).
# Usage: cc.sh <in.c> -o <out.wasm> [extra flags]
W=~/wali/build
exec "$W/llvm/bin/clang" --target=wasm32-unknown-linux-muslwali --sysroot="$W/sysroot" -O1 \
  -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling \
  -L"$W/sysroot/lib" -Wl,--shared-memory,--export-memory,--max-memory=2147483648,-z,stack-size=1048576 \
  "$@"
