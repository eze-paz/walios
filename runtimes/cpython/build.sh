#!/usr/bin/env bash
# Rebuild python_cxx.wasm (CPython 3.14.7 for walios) from nothing but this directory,
# wali-sysroot.tar.gz and the network. Linux (WSL Ubuntu 24.04 works); needs
#   build-essential cmake ninja-build pkg-config libssl-dev zlib1g-dev libbz2-dev
#   liblzma-dev libsqlite3-dev libffi-dev libreadline-dev libncurses-dev uuid-dev
# Disk: ~3GB. Time: ~15 min (most of it the host python).
#
#   build.sh <wali-sysroot.tar.gz> [workdir]     -> <workdir>/python_cxx.wasm
#
# WALI_ABI=ilp32 builds for the walios ILP32 ABI (32-bit long) from wali32-sysroot.tar.gz
# (walios/build/sysroot32), which already carries libc++ and long-double printf/scanf.
#
# The previous build tree lived only in a WSL install that was wiped, which is why this
# script exists. What it has to get right, each learned the hard way:
#  - The CURRENT wali-musl: fork() is the vfork-protocol macro, so _posixsubprocess works.
#    os.fork/os.forkpty cannot (see wali_nofork.c) and answer ENOSYS.
#  - The same exports as the old binary (main-exports.txt): the C-extension bundles
#    (zlib, _ssl, _sqlite3, numpy, docs, mpl) are side modules linked against them. Plus
#    libc++/libc++abi/libunwind and zlib linked whole into the main for the same reason.
#  - Module suffix and multiarch x86_64-linux-gnu: the bundles' .so files are named
#    *.cpython-314-x86_64-linux-gnu.so and ship _sysconfigdata__linux_x86_64-linux-gnu.py.
#  - Long double is IEEE quad on wasm32: aarch64's bits/float.h, and musl's printf/scanf/
#    strtod rebuilt with __wali_printscan_enable_long_double (the sysroot's copies abort).
#  - Reactor-style constructors (wali_start.c), or wasm-ld wraps every export in a
#    constructor re-run and `import numpy` floods stderr.
#  - musl's posix_spawn needs __clone, which walios lacks; wali_spawn.c puts posix_spawn
#    (and so system(), popen(), os.system, os.posix_spawn) on the kernel's spawn syscall.
#  - -O2 and no computed gotos (both measured faster on V8).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT_TGZ=$(realpath "$1")
R=$(realpath -m "${2:-$HOME/wali-python-build}")
mkdir -p "$R" && cd "$R"

LLVM_VER=22.1.3            # the commit python_cxx.wasm v8 was built with (e9846648)
PY_VER=3.14.7
MUSL_COMMIT=243ec00c3ffb910375db487d7eb24ea76d1e2c9f   # arjunr2/wali-musl: printscan sources
ZLIB_VER=1.3.1
TGT=wasm32-unknown-linux-muslwali
ABI=${WALI_ABI:-wali}
# ILP32: compile for wasm32-unknown-linux-musl (long = 32), link through the WALI target.
TF="--target=$TGT"; [ "$ABI" = ilp32 ] && TF="$TF -Xclang -triple -Xclang wasm32-unknown-linux-musl -fno-pic"

# ---- toolchain: only the binaries we use (the full release unpacks to ~20GB) ----
P=LLVM-$LLVM_VER-Linux-X64
if [ ! -x $P/bin/clang ] || [ ! -x $P/bin/llvm-strip ] || [ ! -x $P/bin/llvm-nm ]; then
  curl -sSLO https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VER/$P.tar.xz
  tar xf $P.tar.xz --wildcards "$P/bin/clang" "$P/bin/clang-22" "$P/bin/clang++" "$P/bin/lld" \
    "$P/bin/wasm-ld" "$P/bin/llvm-ar" "$P/bin/llvm-ranlib" "$P/bin/llvm-nm" "$P/bin/llvm-strip" "$P/bin/llvm-objcopy" "$P/lib/clang/*"
  rm -f $P.tar.xz
fi
L=$R/$P/bin
SYSROOT=$R/sysroot
WFLAGS="$TF --sysroot=$SYSROOT -nostdlibinc -isystem $SYSROOT/include -D_GNU_SOURCE -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling"

# ---- sources ----
[ -d Python-$PY_VER ] || { curl -sSL https://www.python.org/ftp/python/$PY_VER/Python-$PY_VER.tar.xz | tar xJ; }
# The call trampoline (wali_trampoline.c) in front of CPython's Emscripten-only one.
TH=Python-$PY_VER/Include/internal/pycore_emscripten_trampoline.h
cp "$HERE/wali_trampoline.h" Python-$PY_VER/Include/internal/
grep -q wali_trampoline.h $TH || sed -i 's|^#if defined(__EMSCRIPTEN__) && defined(PY_CALL_TRAMPOLINE)$|#if defined(__wali__)\n#include "wali_trampoline.h"\n#elif defined(__EMSCRIPTEN__) \&\& defined(PY_CALL_TRAMPOLINE)|' $TH
grep -q wali_trampoline.h $TH || { echo "build.sh: could not patch $TH" >&2; exit 1; }
[ -d zlib-$ZLIB_VER ] || { curl -sSL https://zlib.net/fossils/zlib-$ZLIB_VER.tar.gz | tar xz; }
if [ ! -d llvm-src ]; then
  git clone -q --depth 1 --branch llvmorg-$LLVM_VER --filter=blob:none --sparse https://github.com/llvm/llvm-project.git llvm-src
  git -C llvm-src sparse-checkout set runtimes libcxx libcxxabi libunwind libc llvm/cmake cmake third-party
fi
if [ ! -d wali-musl ]; then
  git init -q wali-musl && git -C wali-musl fetch -q --depth 1 https://github.com/arjunr2/wali-musl.git $MUSL_COMMIT
  git -C wali-musl checkout -q FETCH_HEAD
fi

# ---- sysroot, with the IEEE-quad long double description ----
rm -rf "$SYSROOT" && mkdir -p "$SYSROOT" && tar xzf "$SYSROOT_TGZ" -C "$SYSROOT"
cp wali-musl/arch/aarch64/bits/float.h "$SYSROOT/include/bits/float.h"

# ---- libc++ / libc++abi / libunwind (static, linked whole into the main) ----
if [ "$ABI" = ilp32 ]; then
  mkdir -p libcxx-prefix/lib && cp "$SYSROOT"/lib/{libc++,libc++abi,libunwind}.a libcxx-prefix/lib/
else
cmake -G Ninja -S llvm-src/runtimes -B build-libcxx \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=wasm32 -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_COMPILER=$L/clang -DCMAKE_CXX_COMPILER=$L/clang++ -DCMAKE_AR=$L/llvm-ar -DCMAKE_RANLIB=$L/llvm-ranlib \
  -DCMAKE_C_COMPILER_TARGET=$TGT -DCMAKE_CXX_COMPILER_TARGET=$TGT -DCMAKE_SYSROOT=$SYSROOT \
  -DCMAKE_C_FLAGS="$WFLAGS" -DCMAKE_CXX_FLAGS="$WFLAGS" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$R/libcxx-prefix \
  -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBUNWIND_ENABLE_SHARED=OFF \
  -DLIBCXX_HAS_MUSL_LIBC=ON -DLIBCXX_CXX_ABI=libcxxabi -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
  -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBUNWIND_INCLUDE_TESTS=OFF \
  -DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF -DLIBUNWIND_HIDE_SYMBOLS=ON -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=OFF \
  -DLLVM_INCLUDE_TESTS=OFF >cfg-libcxx.log 2>&1
ninja -C build-libcxx install >build-libcxx.log 2>&1
# The two .S files go through the HOST assembler and come out as x86 ELF; on wasm they are
# empty anyway, and wasm-ld rejects the archive with them in it.
$L/llvm-ar d libcxx-prefix/lib/libunwind.a UnwindRegistersRestore.S.o UnwindRegistersSave.S.o
fi

# ---- musl printf/scanf/strtod with long double support (link before libc) ----
# (ILP32: the sysroot's libc has them; the archive stays empty)
rm -rf ldfix && mkdir ldfix
[ "$ABI" = ilp32 ] || for s in stdio/vfprintf stdio/vfwprintf stdio/vfscanf stdlib/strtod stdlib/wcstod internal/floatscan; do
  $L/clang --target=$TGT -O2 -matomics -mbulk-memory -mexception-handling -mllvm -wasm-enable-sjlj -fwasm-exceptions \
    -std=c99 -nostdinc -ffreestanding -fno-builtin -D_XOPEN_SOURCE=700 -D__wali_printscan_enable_long_double \
    -Iwali-musl/arch/wasm32 -Iwali-musl/arch/generic -Iwali-musl/src/include -Iwali-musl/src/internal \
    -I$SYSROOT/include -Iwali-musl/include -c wali-musl/src/$s.c -o ldfix/$(basename $s).o
done
rm -f libc-ldfix.a && $L/llvm-ar rcs libc-ldfix.a $(ls ldfix/*.o 2>/dev/null)

# ---- zlib in the main (Pillow's and matplotlib's font code import inflate* from it) ----
rm -rf zobj && mkdir zobj
for f in adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr; do
  $L/clang $WFLAGS -msimd128 -DHAVE_UNISTD_H -c zlib-$ZLIB_VER/$f.c -o zobj/$f.o
done
rm -f libz-wali.a && $L/llvm-ar rcs libz-wali.a zobj/*.o

# ---- walios glue ----
for c in wali_dlfcn wali_start wali_nofork wali_spawn; do $L/clang $WFLAGS -c "$HERE/$c.c" -o $c.o; done
# (ref.test on a table entry: needs wasm GC, which every engine with JSPI has)
$L/clang $WFLAGS -mreference-types -mgc -c "$HERE/wali_trampoline.c" -o wali_trampoline.o
$L/clang $TF -matomics -mbulk-memory -mexception-handling -c "$HERE/cpp_exc.s" -o cpp_exc.o
sed 's/^/--export-if-defined=/' "$HERE/main-exports.txt" > exports.rsp
# libc: every symbol of the sysroot's libc.a that can link into a walios program
# (../libc-closure.js), pulled in with -u and exported, as lua.wasm and perl.wasm do -- a C
# extension never finds a libc function missing just because CPython did not call it.
node "$HERE/../libc-closure.js" "$L/llvm-nm" "$SYSROOT/lib/libc.a" > libc-ok.txt 2>libc-closure.log
{ sed 's/^/-u /' libc-ok.txt; sed 's/^/--export-if-defined=/' libc-ok.txt; } > libc-link.rsp

# ---- host python (a cross build needs the same version to run its build steps) ----
if [ ! -x host-prefix/bin/python3.14 ]; then
  rm -rf host-py && mkdir host-py
  (cd host-py && ../Python-$PY_VER/configure --prefix=$R/host-prefix -q && make -j"$(nproc)" && make install) >host-py.log 2>&1
fi

# ---- CPython for walios ----
rm -rf cross-py && mkdir cross-py && cd cross-py
PKG_CONFIG_LIBDIR=/nonexistent PKG_CONFIG_PATH= CONFIG_SITE="$HERE/config.site" MODULE_BUILDTYPE=static \
  CC="$L/clang $WFLAGS" CXX="$L/clang++ $WFLAGS" AR=$L/llvm-ar RANLIB=$L/llvm-ranlib READELF=true \
  CFLAGS="-msimd128 -D__wali_printscan_enable_long_double" \
  LDFLAGS="-L$SYSROOT/lib -nodefaultlibs -Wl,--shared-memory,--import-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608,--export-table,--growable-table" \
  LIBS="-lc $SYSROOT/lib/libclang_rt.builtins.a" \
  ../Python-$PY_VER/configure --host=wasm32-unknown-linux-musl --build=x86_64-pc-linux-gnu \
    --with-build-python=$R/host-prefix/bin/python3.14 --prefix=/py --disable-shared --without-ensurepip \
    --with-computed-gotos=no >../cross-cfg.log 2>&1
LF="-Wl,--export-dynamic -Wl,@$R/exports.rsp -Wl,@$R/libc-link.rsp -Wl,--export=__wali_fork_begin -Wl,--wrap=__main_void -Wl,--whole-archive $R/libcxx-prefix/lib/libc++.a $R/libcxx-prefix/lib/libc++abi.a $R/libcxx-prefix/lib/libunwind.a $R/cpp_exc.o $R/wali_dlfcn.o $R/wali_start.o $R/wali_nofork.o $R/wali_spawn.o $R/wali_trampoline.o $R/libc-ldfix.a $R/libz-wali.a -Wl,--no-whole-archive"
sed -i -e "s/^SOABI=.*/SOABI=\t\tcpython-314-x86_64-linux-gnu/" \
       -e "s/^EXT_SUFFIX=.*/EXT_SUFFIX=\t.cpython-314-x86_64-linux-gnu.so/" \
       -e "s/^MULTIARCH=.*/MULTIARCH=\tx86_64-linux-gnu/" \
       -e "s/^MULTIARCH_CPPFLAGS = .*/MULTIARCH_CPPFLAGS = -DMULTIARCH=\\\\\"x86_64-linux-gnu\\\\\"/" \
       -e "s/^OPT=.*/OPT=\t\t-DNDEBUG -g -O2 -Wall/" \
       -e "s|^LINKFORSHARED=.*|LINKFORSHARED=\t$LF|" Makefile
sed -i "1i MODULE_POSIX_CFLAGS=-D__WALI_LIBC_INTERNAL -Dfork=__wali_nofork -Dforkpty=__wali_noforkpty" Makefile
make -j"$(nproc)" python >../cross-build.log 2>&1
$L/llvm-strip --strip-debug -o ../python_cxx.wasm python
echo "built $R/python_cxx.wasm ($(stat -c %s ../python_cxx.wasm) bytes)"

# sysconfig data for the guest (ships in pylib.tar.gz as Lib/<name>.py): without it
# sysconfig.get_config_var() raises ModuleNotFoundError, which pip, setuptools and
# pandas all hit. The toolchain variables are rewritten to the in-tab cc/ar.
make pybuilddir.txt >../sysconfig.log 2>&1
SCD=_sysconfigdata__linux_x86_64-linux-gnu.py
$R/host-prefix/bin/python3.14 "$HERE/wali_sysconfig.py" "$(cat pybuilddir.txt)/$SCD" ../$SCD "$R"
