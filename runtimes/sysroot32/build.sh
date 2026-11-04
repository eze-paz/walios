#!/bin/bash
# build.sh [workdir] -- the walios ILP32 sysroot: WALI's musl (arjunr2/wali-musl 243ec00) with
# 32-bit long, built for clang's wasm32-unknown-linux-musl (long = 32, size_t = unsigned long)
# instead of wasm32-unknown-linux-muslwali (long = 64). See README.md for the ABI.
#   LLVM=<dir with bin/clang>  (default ~/wali-rebuild/LLVM-22.1.3-Linux-X64)
#   OLD_SYSROOT=<WALI sysroot> (default ~/wali-rebuild/sysroot: libclang_rt.builtins.a)
# Output: <workdir>/sysroot and <workdir>/wali32-sysroot.tar.gz
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:-$HOME/wali32}; mkdir -p "$W"; W=$(cd "$W" && pwd)
LLVM=${LLVM:-$HOME/wali-rebuild/LLVM-22.1.3-Linux-X64}; L=$LLVM/bin
OLD_SYSROOT=${OLD_SYSROOT:-$HOME/wali-rebuild/sysroot}
S=$W/sysroot M=$W/musl
TGT=wasm32-unknown-linux-musl
WFLAGS="--target=$TGT -fno-pic --sysroot=$S -nostdlibinc -isystem $S/include -D_GNU_SOURCE -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling"

# OPENSSL_ONLY=<wali32-sysroot.tar.gz>: rebuild only OpenSSL on top of that published sysroot
# (musl and libc++ stay byte-identical) -- for a change to OpenSSL's flags alone.
if [ -n "${OPENSSL_ONLY:-}" ]; then
  rm -rf "$S" && mkdir -p "$S" && tar xzf "$OPENSSL_ONLY" -C "$S"
else

# --- musl source, pinned
if [ ! -d "$M/.git" ]; then
  git clone -q https://github.com/arjunr2/wali-musl.git "$M"
fi
git -C "$M" checkout -q -f 243ec00c3ffb910375db487d7eb24ea76d1e2c9f
git -C "$M" clean -qfdx
# walios' libc changes, as WALI's sysroot has them (eze-paz/walios musl-patches): real
# setjmp/longjmp over wasm-EH (src/setjmp/wasm32/rt.c), fork()/vfork() as macros over the
# vfork protocol (__wali_fork.c), execve/_Exit returning to the fork site, SSIZE_MAX.
P=$W/walios-patches
if [ ! -d "$P/musl-patches" ]; then
  git clone -q --depth 1 --filter=blob:none --sparse https://github.com/eze-paz/walios.git "$P"
  git -C "$P" sparse-checkout set musl-patches
fi
git -C "$M" apply "$P/musl-patches/wali-musl.tracked.patch"
( cd "$P/musl-patches" && find src -type f -name '*.c' | while read -r f; do mkdir -p "$M/$(dirname "$f")"; cp "$f" "$M/$f"; done )

# --- the arch: WALI's wasm32 with long = 32
A=$M/arch/wasm32
cp "$HERE/arch/alltypes.h.in" "$A/bits/alltypes.h.in"
cp "$HERE/arch/kstat.h" "$HERE/arch/ksigaction.h" "$A/"
cp "$HERE/arch/bits/statfs.h" "$HERE/arch/bits/reg.h" "$A/bits/"
# wasm32's long double is IEEE quad (as on aarch64), not x86's 80-bit format
cp "$M/arch/aarch64/bits/float.h" "$A/bits/float.h"
# Syscall imports keep their wasm signatures: WALI spelled 64-bit kernel words as C long,
# which is now 32-bit, so every long in a prototype becomes long long (i64 stays i64).
sed -E -i 's/\blong long\b/@LL@/g; s/\blong\b/long long/g; s/@LL@/long long/g' "$A/syscall_arch.h"
# syscall() varargs read what an ILP32 caller passes: nfds_t is unsigned long (32-bit now).
sed -E -i '/CASE_SYSCALL \((poll|ppoll),/ s/va_arg\(ap, unsigned long long\)/va_arg(ap, unsigned long)/' "$A/syscall_var.h"
# syscall(n, ...) for an n this dispatcher does not map: ENOSYS, SILENTLY, as on Linux. It
# printf()'d "Invalid syscall var call -- NR <n>" to STDOUT first, so a program probing an
# optional syscall (xz and file try landlock, NR 444) wrote that line into its output --
# `x=$(file -b f)` captured it and `xz -dc` would have prefixed the decompressed data.
sed -i '/printf("Invalid syscall var call -- NR/d' "$A/syscall_var.h"
grep -q 'Invalid syscall var call' "$A/syscall_var.h" && { echo "sysroot32: the syscall_var.h printf is still there" >&2; exit 1; }
mkdir -p "$M/src/unistd/wasm32"; cp "$HERE/src/lseek.c" "$M/src/unistd/wasm32/lseek.c"
# -D__WALI_ASYNCIFY_FORK: the opt-out walios musl-patches/asyncify-fork.md describes. Such a
# program gets musl's real fork() (_Fork -> SYS_fork, returning twice once the binary is run
# through wasm-opt --asyncify), and vfork() is that fork. For programs whose child runs on
# without exec (rsync's local receiver): the default fork() macro runs the child branch inside
# the parent until execve/_exit, so such a parent never resumes.
sed -i -e 's|^#ifndef __WALI_LIBC_INTERNAL$|#if !defined(__WALI_LIBC_INTERNAL) \&\& !defined(__WALI_ASYNCIFY_FORK)|' \
  -e 's|^#endif /\* !__WALI_LIBC_INTERNAL \*/$|#elif defined(__WALI_ASYNCIFY_FORK)\n#define vfork() fork()\n#endif|' "$M/include/unistd.h"
grep -q '^#elif defined(__WALI_ASYNCIFY_FORK)$' "$M/include/unistd.h" || { echo "sysroot32: unistd.h has no __WALI_ASYNCIFY_FORK gate" >&2; exit 1; }
# _start ends in exit(), not __wali_proc_exit(<main's status>). WALI's crt1-command.c never
# called exit(), so atexit handlers never ran and stdio was never flushed: a program that
# returns from main with stdout on a pipe or a file lost everything still buffered (GNU tree:
# `tree d | wc -l` -> 1, only the line before its first fflush). __wali_cleanup is
# __wali_deinit, which the walios kernel answers with 0, so nothing else is skipped.
sed -i -e '1i #include <stdlib.h>' -e 's/^  __wali_proc_exit(r);$/  exit(r);/' "$M/crt/crt1-command.c"
grep -q '^  exit(r);$' "$M/crt/crt1-command.c" || { echo "sysroot32: crt1-command.c _start still skips exit()" >&2; exit 1; }
# The ABI marker: a `wali.abi` custom section the kernel reads to pick struct layouts. In the
# start files (clang's WALI driver links crt1-command.o) and in the startup code every program
# runs (__main_void, __libc_start_main), for programs with their own start files. Only
# assembler makes a wasm custom section (a C section attribute makes a data segment); wasm-ld
# keeps it through --strip-all and concatenates the copies ("ilp32ilp32").
for f in crt/crt1-command.c crt/crt1.c src/startup/__main_void.c src/env/__libc_start_main.c; do
  printf '\n__asm__(".section .custom_section.wali.abi,\\"\\",@\\n.ascii \\"ilp32\\"\\n.text\\n");\n' >> "$M/$f"
done

# --- build (musl's configure has no wasm32 case; WALI builds with a hand-written config.mak)
cat > "$M/config.mak" <<EOF
srcdir = .
prefix = $S
exec_prefix = \$(prefix)
bindir = \$(exec_prefix)/bin
libdir = \$(prefix)/lib
includedir = \$(prefix)/include
syslibdir = \$(prefix)/lib
ARCH = wasm32
SUBARCH =
ASMSUBARCH =
CC = $L/clang
AR = $L/llvm-ar
RANLIB = $L/llvm-ranlib
CROSS_COMPILE =
LIBCC =
SHARED_LIBS =
ALL_TOOLS =
TOOL_LIBS =
EOF
# (the patched Makefile's flags, with the ILP32 target, and printf/scanf's long double)
FLAGS="--target=wasm32-unknown-linux-musl -fno-pic -mbulk-memory -matomics -mexception-handling -mllvm -wasm-enable-sjlj -D__WALI_LIBC_INTERNAL -D__wali_printscan_enable_long_double"
make -C "$M" -j"$(nproc)" CFLAGS="$FLAGS" lib/libc.a lib/crt1.o lib/crti.o lib/crtn.o lib/Scrt1.o lib/rcrt1.o lib/libm.a lib/libpthread.a lib/librt.a lib/libdl.a >"$W/musl-build.log" 2>&1 \
  || { tail -30 "$W/musl-build.log"; exit 1; }
rm -rf "$S"; make -C "$M" CFLAGS="$FLAGS" install-headers install-libs >>"$W/musl-build.log" 2>&1
cp "$OLD_SYSROOT/lib/libclang_rt.builtins.a" "$S/lib/"
# Links go through clang's WALI driver (it has no link step for wasm32-unknown-linux-musl;
# wasm objects carry no triple), which takes start files from lib/wasm32-linux-muslwali.
mkdir -p "$S/lib/wasm32-linux-muslwali"; cp "$S"/lib/*crt*.o "$S/lib/wasm32-linux-muslwali/"

# --- check the ABI the headers now describe
cat > "$W/abicheck.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
_Static_assert(sizeof(long) == 4 && sizeof(void *) == 4 && sizeof(size_t) == 4, "ILP32");
_Static_assert(sizeof(long long) == 8 && sizeof(off_t) == 8 && sizeof(time_t) == 8, "64-bit time/off");
_Static_assert(__builtin_types_compatible_p(size_t, unsigned long), "size_t = clang's");
_Static_assert(__builtin_types_compatible_p(uintptr_t, unsigned long), "uintptr_t = clang's");
int main(void) { return 0; }
EOF
$L/clang --target=wasm32-unknown-linux-musl -fno-pic --sysroot="$S" -nostdlibinc -isystem "$S/include" -fsyntax-only "$W/abicheck.c"

# --- libc++ / libc++abi / libunwind (the CPython recipe's, for the ILP32 target)
LLVM_SRC=${LLVM_SRC:-$W/llvm-src}
if [ ! -d "$LLVM_SRC/libcxx" ]; then
  git clone -q --depth 1 --branch llvmorg-22.1.3 --filter=blob:none --sparse https://github.com/llvm/llvm-project.git "$LLVM_SRC"
  git -C "$LLVM_SRC" sparse-checkout set runtimes libcxx libcxxabi libunwind libc llvm/cmake cmake third-party
fi
rm -rf "$W/build-libcxx"
cmake -G Ninja -S "$LLVM_SRC/runtimes" -B "$W/build-libcxx" \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=wasm32 -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_COMPILER=$L/clang -DCMAKE_CXX_COMPILER=$L/clang++ -DCMAKE_AR=$L/llvm-ar -DCMAKE_RANLIB=$L/llvm-ranlib \
  -DCMAKE_C_COMPILER_TARGET=$TGT -DCMAKE_CXX_COMPILER_TARGET=$TGT -DCMAKE_SYSROOT=$S \
  -DCMAKE_C_FLAGS="$WFLAGS" -DCMAKE_CXX_FLAGS="$WFLAGS" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$S \
  -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBUNWIND_ENABLE_SHARED=OFF \
  -DLIBCXX_HAS_MUSL_LIBC=ON -DLIBCXX_CXX_ABI=libcxxabi -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
  -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBUNWIND_INCLUDE_TESTS=OFF \
  -DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF -DLIBUNWIND_HIDE_SYMBOLS=ON -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=OFF \
  -DLLVM_INCLUDE_TESTS=OFF >"$W/libcxx.log" 2>&1 && ninja -C "$W/build-libcxx" install >>"$W/libcxx.log" 2>&1 \
  || { tail -30 "$W/libcxx.log"; exit 1; }
# The two .S files go through the HOST assembler (x86 ELF); empty on wasm, and wasm-ld
# rejects the archive with them in it.
$L/llvm-ar d "$S/lib/libunwind.a" UnwindRegistersRestore.S.o UnwindRegistersSave.S.o
fi

# --- OpenSSL (the version WALI's sysroot carries); its bignum word is a long. Without
# _GNU_SOURCE (it would pick glibc's char*-returning strerror_r; musl's returns int), and
# without the secure heap (mlock + <linux/mman.h>, which this sysroot does not carry).
# Position-independent: a C module (Net::SSLeay, Crypt::OpenSSL::*, an _ssl-using Python
# extension) links it into a wasm side module, which rejects non-PIC objects; wasm-ld links
# PIC objects into a static program too.
OSSL=3.0.16
OCFLAGS=${WFLAGS/ -D_GNU_SOURCE/}; OCFLAGS=${OCFLAGS/ -fno-pic/ -fPIC}
[ -d "$W/openssl-$OSSL" ] || curl -sSfL https://github.com/openssl/openssl/releases/download/openssl-$OSSL/openssl-$OSSL.tar.gz | tar xz -C "$W"
( cd "$W/openssl-$OSSL" && { make distclean >/dev/null 2>&1 || true; } &&
  CC="$L/clang" AR="$L/llvm-ar" RANLIB="$L/llvm-ranlib" CFLAGS="$OCFLAGS" \
  ./Configure linux-generic32 no-asm no-shared no-dso no-async no-engine no-afalgeng no-tests no-ui-console no-secure-memory \
    --prefix="$S" --libdir=lib --openssldir=/etc/ssl >"$W/openssl.log" 2>&1 &&
  make -j"$(nproc)" build_libs >>"$W/openssl.log" 2>&1 && make install_dev >>"$W/openssl.log" 2>&1 ) \
  || { tail -30 "$W/openssl.log"; exit 1; }

tar czf "$W/wali32-sysroot.tar.gz" -C "$S" .
echo "sysroot: $S ($(du -sh "$S" | cut -f1)); tarball $W/wali32-sysroot.tar.gz"
