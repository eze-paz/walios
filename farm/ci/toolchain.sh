#!/bin/bash
# WALI cross toolchain for the build farm, from public parts only:
#   - upstream LLVM release binaries (clang, wasm-ld, llvm-ar...), the version walios uses
#   - the walios sysroot (wali-musl libc + openssl + compiler-rt builtins), release pkgs-*
#   - toolchain extras, release toolchain-*: libc++/libc++abi/libunwind for wasm32-wali and
#     the Linux UAPI headers (x86-64 asm layout: WALI is the x86-64 syscall ABI)
# Writes $TC/env.sh, cc/c++/ld wrappers, a meson cross file, a cmake toolchain file and the
# abuild helpers Alpine recipes call (abuild-meson). Idempotent; CI caches $TC.
#   toolchain.sh <dir> [pkgs-tag] [toolchain-tag]
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)   # before any cd: the path may be relative
TC=$(realpath -m "${1:?usage: toolchain.sh <dir> [pkgs-tag] [toolchain-tag]}")
TAG=${2:-pkgs-2026-10-31}
XTAG=${3:-toolchain-2026-10-31}
REL=https://github.com/eze-paz/walios/releases/download
LLVM_VER=22.1.3
P=LLVM-$LLVM_VER-Linux-X64
mkdir -p "$TC/bin" && cd "$TC"
if [ ! -x $P/bin/clang ]; then
  curl -sSfL https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VER/$P.tar.xz \
    | tar xJ --wildcards "$P/bin/clang" "$P/bin/clang-22" "$P/bin/clang++" "$P/bin/lld" "$P/bin/wasm-ld" \
        "$P/bin/llvm-ar" "$P/bin/llvm-ranlib" "$P/bin/llvm-nm" "$P/bin/llvm-strip" "$P/bin/llvm-objcopy" "$P/lib/clang/*"
fi
if [ ! -f sysroot/lib/libc.a ]; then
  mkdir -p sysroot
  curl -sSfL $REL/$TAG/wali-sysroot.tar.gz | tar xz -C sysroot
fi
if [ ! -f sysroot/lib/libc++.a ]; then
  curl -sSfL $REL/$XTAG/wali-libcxx.tar.gz | tar xz -C sysroot      # include/c++/v1, unwind headers, lib/*.a
  curl -sSfL $REL/$XTAG/wali-linux-headers.tar.gz | tar xz -C sysroot   # include/{linux,asm,asm-generic,...}
fi
L=$TC/$P/bin
S=$TC/sysroot
# C++ exceptions need the wasm EH tag __cpp_exception defined once per program (libc
# defines __c_longjmp, the setjmp one); python_cxx.wasm links the same 3-line object.
if [ ! -f $S/lib/libwali-cppexc.a ]; then
  printf '.globl __cpp_exception
.tagtype __cpp_exception i32
__cpp_exception:
' > $S/lib/cpp_exc.s
  $L/clang --target=wasm32-unknown-linux-muslwali -mexception-handling -c $S/lib/cpp_exc.s -o $S/lib/cpp_exc.o
  $L/llvm-ar rcs $S/lib/libwali-cppexc.a $S/lib/cpp_exc.o
fi
cat > env.sh <<EOF
export WALI_TC=$TC WALI_LLVM=$L WALI_SYSROOT=$S
export CC=$TC/bin/wali-cc CXX=$TC/bin/wali-c++ LD=$TC/bin/wali-ld
export AR=$L/llvm-ar RANLIB=$L/llvm-ranlib NM=$L/llvm-nm STRIP=$L/llvm-strip OBJCOPY=$L/llvm-objcopy
export CMAKE_TOOLCHAIN_FILE=$TC/wali.cmake
export PATH=$TC/bin:\$PATH
EOF
# One driver for compile and link. Compile flags = the ones python_cxx.wasm is built with
# (walios/build/cpython/build.sh in sandpie); a link adds the flags every walios guest
# needs: shared+imported memory (the kernel owns it), 8 MB stack (64 KB overflows into
# misleading OOB traps), exported growable table (signal handlers), and libc + builtins.
# Executables are static, so a -shared link (libtool, meson, cmake shared libs) produces a
# static archive under the .so name: wasm-ld reads it by its magic, and dependents link it
# like any -lfoo. $WALI_EXTRA_* let the farm add the overlay of already-built deps, and with
# $WALI_OVERLAY set every overlay archive joins the link as one --start-group: static
# libraries carry no record of their own dependencies (readline needs ncurses' tputs), and
# a group lets each pull exactly the members it needs.
# -flto is dropped: setjmp/longjmp lowering (-wasm-enable-sjlj) is a compile-time pass, and
# LTO objects reach the linker with it undone ("undefined symbol: longjmp").
for d in cc c++; do
  drv=clang; cxx=""; cxxlibs=""; cxxdefs=""
  [ $d = c++ ] && { drv=clang++; cxx="-isystem $S/include/c++/v1"; cxxlibs="-lc++ -lc++abi -lunwind -lwali-cppexc"
    # pre-C++17 code still uses std::unary_function/binary_function (removed in C++17).
    cxxdefs="-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION"; }
  cat > bin/wali-$d <<EOF
#!/bin/bash
link=1 shared=0 out=a.out
prev=""
for a in "\$@"; do
  case "\$a" in -c|-E|-S|-M|-MM) link=0;; -shared) shared=1;; esac
  [ "\$prev" = -o ] && out="\$a"; prev="\$a"
done
F=(--target=wasm32-unknown-linux-muslwali --sysroot=$S -nostdlibinc $cxx -isystem $S/include -D_GNU_SOURCE
   -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -pthread
   -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types
   -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument -Wno-ignored-optimization-argument
   -Wno-unknown-warning-option -Wno-long-long $cxxdefs
   \${WALI_EXTRA_CFLAGS:-})
A=()
for a in "\$@"; do case "\$a" in
  -rdynamic|-static|-s|-fPIC|-fpic|-fPIE|-fpie|-pie|-flto|-flto=*|-ffat-lto-objects|-fuse-linker-plugin) ;;
  -Wl,*)
    # ELF-linker options wasm-ld rejects, filtered token by token: one -Wl, can carry several
    # (-Wl,-Map=x.map,--cref). -z/-soname/-rpath/... take the next token as their value.
    IFS=, read -ra t <<< "\${a#-Wl,}"; k=(); skip=0
    for x in "\${t[@]}"; do
      if [ \$skip = 1 ]; then skip=0; continue; fi
      case "\$x" in
        -z|-soname|-h|-rpath|-rpath-link|--version-script|-Map) skip=1;;
        --start-group|--end-group|--as-needed|--no-as-needed|--gc-sections|--warn-common|--sort-common|-O1|-O2|--hash-style=*|-soname=*|--version-script=*|-Bsymbolic*|--cref|--no-undefined|--fatal-warnings|--enable-new-dtags|--disable-new-dtags|-rpath=*|-rpath-link=*|--build-id*|-Map=*|-E|--export-dynamic|--icf=*|-znoexecstack|-zrelro|-znow|-zdefs) ;;
        *) k+=("\$x");;
      esac
    done
    [ \${#k[@]} -gt 0 ] && A+=("-Wl,\$(IFS=,; echo "\${k[*]}")");;
  *) A+=("\$a");; esac; done
if [ \$link = 1 ] && [ \$shared = 1 ]; then
  objs=()
  for a in "\${A[@]}"; do case "\$a" in *.o|*.lo|*.obj) objs+=("\$a");; esac; done
  rm -f "\$out"; $L/llvm-ar rcs "\$out" "\${objs[@]}" || exit 1
  # -lfoo only searches lib*.a here (no dynamic linking), so give the archive that name too.
  case "\$out" in *lib*.so*) cp -f "\$out" "\${out%%.so*}.a";; esac
  exit 0
fi
if [ \$link = 1 ]; then
  exec $L/$drv "\${F[@]}" "\${A[@]}" -L$S/lib \${WALI_EXTRA_LDFLAGS:-} -nodefaultlibs \
    -Wl,--shared-memory,--import-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608,--export-table,--growable-table \
    \${WALI_EXTRA_LIBS:-} \$( [ -n "\${WALI_OVERLAY:-}" ] && { ls "\$WALI_OVERLAY"/usr/lib/*.a "\$WALI_OVERLAY"/lib/*.a 2>/dev/null | grep -q . && echo "-Wl,--start-group \$(ls "\$WALI_OVERLAY"/usr/lib/*.a "\$WALI_OVERLAY"/lib/*.a 2>/dev/null | tr '
' ' ') -Wl,--end-group"; } )     $cxxlibs -lwali-farm -lc $S/lib/libclang_rt.builtins.a
fi
exec $L/$drv "\${F[@]}" "\${A[@]}"
EOF
  chmod +x bin/wali-$d
done
printf '#!/bin/sh\nargs=""\nfor a in "$@"; do [ "$a" = "-nostdlib" ] || args="$args $a"; done\nexec %s/wasm-ld $args\n' "$L" > bin/wali-ld
chmod +x bin/wali-ld
# BSD headers musl leaves out and Alpine adds with bsd-compat-headers: sys/queue.h (the
# runner's glibc copy, BSD-licensed, self-contained) and a minimal sys/cdefs.h shim.
mkdir -p $S/include/sys
# libbsd's queue.h (full BSD set: TAILQ_FOREACH_SAFE...) when the host has libbsd-dev,
# else glibc's, which lacks the _SAFE iterators.
if [ ! -f $S/include/sys/queue.h ]; then
  if [ -f /usr/include/bsd/sys/queue.h ]; then sed 's|#include <bsd/sys/cdefs.h>|#include <sys/cdefs.h>|' /usr/include/bsd/sys/queue.h > $S/include/sys/queue.h
  else cp /usr/include/x86_64-linux-gnu/sys/queue.h $S/include/sys/queue.h; fi
fi
[ -f $S/include/sys/tree.h ] || { [ -f /usr/include/bsd/sys/tree.h ] && sed 's|#include <bsd/sys/cdefs.h>|#include <sys/cdefs.h>|' /usr/include/bsd/sys/tree.h > $S/include/sys/tree.h; } || true
[ -f $S/include/sys/cdefs.h ] || cat > $S/include/sys/cdefs.h <<'EOF'
/* walios farm: the BSD <sys/cdefs.h> macros old code expects (what Alpine's
   bsd-compat-headers provides; musl deliberately ships no cdefs.h). */
#ifndef _SYS_CDEFS_H
#define _SYS_CDEFS_H
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif
#define __THROW
#define __NTH(fct) fct
#define __P(args) args
#define __PMT(args) args
#define __CONCAT(x,y) x ## y
#define __STRING(x) #x
#define __ptr_t void *
#define __long_double_t long double
#define __attribute_malloc__ __attribute__((__malloc__))
#define __attribute_pure__ __attribute__((__pure__))
#define __attribute_const__ __attribute__((__const__))
#define __attribute_used__ __attribute__((__used__))
#define __attribute_noinline__ __attribute__((__noinline__))
#define __attribute_deprecated__ __attribute__((__deprecated__))
#define __wur __attribute__((__warn_unused_result__))
#define __nonnull(params) __attribute__((__nonnull__ params))
#define __unused __attribute__((__unused__))
#define __dead2 __attribute__((__noreturn__))
#endif
EOF
# libwali-farm.a: the glibc-isms musl leaves out (error(), closefrom()), the three-argument
# main bridge and musl's cancellation labels (see farm/ci/shim/*.c). An archive, so each
# member links only where something needs it; it goes before -lc on every link.
if [ ! -f $S/lib/libwali-farm.a ]; then
  for c in "$HERE"/shim/*.c; do
    $L/clang --target=wasm32-unknown-linux-muslwali --sysroot=$S -nostdlibinc -isystem $S/include -D_GNU_SOURCE       -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -pthread       -c "$c" -o "$S/lib/farm-$(basename "${c%.c}").o"
  done
  $L/llvm-ar rcs $S/lib/libwali-farm.a $S/lib/farm-*.o
fi
[ -f $S/include/error.h ] || cat > $S/include/error.h <<'EOF'
/* glibc <error.h>, implemented by libwali-farm.a (farm/ci/shim/error.c). */
#ifndef _ERROR_H
#define _ERROR_H
#ifdef __cplusplus
extern "C" {
#endif
void error(int status, int errnum, const char *format, ...);
void error_at_line(int status, int errnum, const char *filename, unsigned int linenum, const char *format, ...);
extern void (*error_print_progname)(void);
extern unsigned int error_message_count;
extern int error_one_per_line;
#ifdef __cplusplus
}
#endif
#endif
EOF
# OpenSSL is in the sysroot (libssl.a, libcrypto.a, include/openssl) but has no .pc files,
# so pkg-config-driven configures did not find it. Compiler default paths, so no flags.
mkdir -p $S/lib/pkgconfig
for pc in openssl:"-lssl -lcrypto" libssl:"-lssl" libcrypto:"-lcrypto"; do
  printf 'Name: %s
Description: OpenSSL (walios sysroot)
Version: 3.0.0
Libs: %s
Cflags:
' "${pc%%:*}" "${pc#*:}" > $S/lib/pkgconfig/${pc%%:*}.pc
done
# musl keeps crypt/resolv/util/... in libc; their -l names exist as empty archives (as in musl).
for l in crypt resolv util xnet; do [ -f $S/lib/lib$l.a ] || $L/llvm-ar rcs $S/lib/lib$l.a; done
# Recipes and Makefiles that call cc/gcc/c++ directly get the WALI compiler; tools built to
# run during the build use CC_FOR_BUILD/BUILD_CC/HOSTCC, which build-one.sh points at gcc.
for n in cc gcc; do ln -sf wali-cc bin/$n; done
for n in c++ g++; do ln -sf wali-c++ bin/$n; done
# Alpine helpers some recipes call: cmake3.5 (cmake with the 3.5 policy floor), and doc/ELF
# tools the farm does not need (scdoc writes man pages, scanelf audits ELF -- no-ops here).
cat > bin/cmake3.5 <<'EOF'
#!/bin/sh
case "$1" in --build|--install|-E|-P) exec cmake "$@";; esac
exec cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@"
EOF
printf '#!/bin/sh
cat >/dev/null
' > bin/scdoc
printf '#!/bin/sh
exit 0
' > bin/scanelf
chmod +x bin/cmake3.5 bin/scdoc bin/scanelf

# meson: a cross file, and abuild-meson (Alpine's wrapper around `meson setup`).
cat > wali.meson <<EOF
[binaries]
c = '$TC/bin/wali-cc'
cpp = '$TC/bin/wali-c++'
ar = '$L/llvm-ar'
strip = '$L/llvm-strip'
nm = '$L/llvm-nm'
pkg-config = 'pkg-config'
[host_machine]
system = 'linux'
cpu_family = 'wasm32'
cpu = 'wasm32'
endian = 'little'
[properties]
needs_exe_wrapper = true
EOF
cat > bin/abuild-meson <<EOF
#!/bin/bash
# The recipe's own library-type/LTO/PIE choices give way to the farm's (static, no LTO).
A=()
for a in "\$@"; do case "\$a" in -Ddefault_library=*|--default-library=*|-Db_lto=*|-Db_pie=*|-Db_staticpic=*) ;; *) A+=("\$a");; esac; done
set -- "\${A[@]}"
exec meson setup --cross-file $TC/wali.meson --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/libexec \
  --bindir=/usr/bin --sbindir=/usr/sbin --includedir=/usr/include --datadir=/usr/share --mandir=/usr/share/man \
  --sysconfdir=/etc --localstatedir=/var --buildtype=plain --default-library=static --wrap-mode=nodownload \
  -Db_lto=false -Db_pie=false -Db_staticpic=false "\$@"
EOF
chmod +x bin/abuild-meson
# cmake: CMAKE_TOOLCHAIN_FILE (env) is honoured by cmake >= 3.21.
cat > wali.cmake <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_C_COMPILER $TC/bin/wali-cc)
set(CMAKE_CXX_COMPILER $TC/bin/wali-c++)
set(CMAKE_AR $L/llvm-ar CACHE FILEPATH "")
set(CMAKE_RANLIB $L/llvm-ranlib CACHE FILEPATH "")
set(CMAKE_FIND_ROOT_PATH $S)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
# Not ELF: cmake cannot rewrite RPATHs at install time, and walios binaries are static anyway.
set(CMAKE_SKIP_RPATH ON CACHE BOOL "")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON CACHE BOOL "")
set(CMAKE_POSITION_INDEPENDENT_CODE OFF CACHE BOOL "")
EOF
echo "toolchain ready: $TC (LLVM $LLVM_VER, sysroot $TAG, extras $XTAG)"
