#!/bin/bash
set -e
W=~/wali/build
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -D__WALI_ASYNCIFY_FORK -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -L$W/sysroot/lib -Wl,--shared-memory,--export-memory,--max-memory=2147483648,-z,stack-size=1048576"
$CC ~/walihost/forkwali.c -o /tmp/forkwali.wasm
echo "built: $(stat -c%s /tmp/forkwali.wasm) bytes"
echo "fork import present:"; ~/binaryen-version_132/bin/wasm-dis /tmp/forkwali.wasm 2>/dev/null | grep -oE 'SYS_fork|__wali_fork_begin' | sort -u
~/binaryen-version_132/bin/wasm-opt --asyncify --pass-arg=asyncify-imports@wali.SYS_fork /tmp/forkwali.wasm -o /tmp/forkwali.async.wasm
echo "asyncified: $(stat -c%s /tmp/forkwali.async.wasm) bytes"
~/binaryen-version_132/bin/wasm-dis /tmp/forkwali.async.wasm 2>/dev/null | grep -oE 'export "asyncify_[a-z_]+"' | sort -u | tr '\n' ' '; echo
