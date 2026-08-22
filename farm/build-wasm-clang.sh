#!/bin/bash
# Build clang + lld as WebAssembly (wasm32-wasi) so the WALI wasm-OS can run a
# real C/C++ cross-compiler IN THE BROWSER. Produces clang.wasm + lld.wasm.
#
# WHY NOT ON THE DEV BOX: needs (a) a native LLVM 22 build first for the
# tblgen tools (clang-tblgen/llvm-tblgen are build-only, not in binary
# releases), and (b) ~16-32GB RAM for the final static link of clang.wasm.
# Run this on a CI runner or a >=32GB machine. Verified prerequisites/flags
# against wasi-sdk 22.1.0 (which supplies the cross libc++/libc).
#
# Result runs on the WALI host once a WASI preview1 shim is added (clang.wasm
# is wasm32-wasi); clang stays multi-target, so it still emits our wali
# binaries via  --target=wasm32-unknown-linux-muslwali --sysroot=<wali-sysroot>.
set -euo pipefail

LLVM_VER=22.1.3
WASI_SDK=${WASI_SDK:-$HOME/wasipy/wasi-sdk-33.0-x86_64-linux}
JOBS=${JOBS:-$(nproc)}
ROOT=$HOME/wasmclang; mkdir -p "$ROOT"; cd "$ROOT"

# 0. source
[ -d llvm-project-$LLVM_VER.src ] || {
  curl -L -o src.tar.xz \
    https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VER/llvm-project-$LLVM_VER.src.tar.xz
  tar xf src.tar.xz && rm src.tar.xz
}
SRC=$ROOT/llvm-project-$LLVM_VER.src

# 1. NATIVE build — only the tblgen tools + a host clang/llvm the cross build needs.
#    (This is the step the dev box lacked: clang-tblgen is build-only.)
cmake -S "$SRC/llvm" -B build-native -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="WebAssembly" \
  -DLLVM_ENABLE_ASSERTIONS=OFF
ninja -C build-native llvm-tblgen clang-tblgen llvm-config

# 2. CROSS build to wasm32-wasi using wasi-sdk as the compiler + sysroot.
CFLAGS_W="--target=wasm32-wasi --sysroot=$WASI_SDK/share/wasi-sysroot -I$ROOT/shims -fwasm-exceptions -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID -D_WASI_EMULATED_MMAN"
cmake -S "$SRC/llvm" -B build-wasm -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$WASI_SDK/bin/clang" \
  -DCMAKE_CXX_COMPILER="$WASI_SDK/bin/clang++" \
  -DCMAKE_C_FLAGS="$CFLAGS_W" \
  -DCMAKE_CXX_FLAGS="$CFLAGS_W" \
  -DCMAKE_EXE_LINKER_FLAGS="-lwasi-emulated-signal -lwasi-emulated-process-clocks -lwasi-emulated-getpid -lwasi-emulated-mman -Wl,--max-memory=4294967296 -Wl,-z,stack-size=8388608" \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_CROSSCOMPILING=ON \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="WebAssembly" \
  -DLLVM_TABLEGEN="$ROOT/build-native/bin/llvm-tblgen" \
  -DCLANG_TABLEGEN="$ROOT/build-native/bin/clang-tblgen" \
  -DLLVM_CONFIG_PATH="$ROOT/build-native/bin/llvm-config" \
  -DLLVM_ENABLE_THREADS=OFF -DLLVM_ENABLE_PIC=OFF -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DLLVM_BUILD_LLVM_DYLIB=OFF -DLLVM_BUILD_LLVM_C_DYLIB=OFF -DCLANG_LINK_CLANG_DYLIB=OFF \
  -DLLVM_ENABLE_UNWIND_TABLES=OFF \
  -DLLVM_BUILD_TOOLS=OFF \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF -DCLANG_ENABLE_STATIC_ANALYZER=OFF \
  -DCLANG_ENABLE_ARCMT=OFF
# link-jobs=1 keeps the peak RSS survivable; the clang link is the memory spike.
ninja -C build-wasm -j"$JOBS" -l"$JOBS" clang lld || \
  ninja -C build-wasm -j1 clang lld   # retry the heavy link single-threaded

echo "artifacts:"
find build-wasm -name 'clang*.wasm' -o -name 'lld*.wasm' -o -name 'clang' -o -name 'lld' | head
echo "Wire clang.wasm into the OS manifest (basename cc/clang) + add a WASI"
echo "preview1 shim to the host. Ship the wali sysroot (2.8MB) alongside."
