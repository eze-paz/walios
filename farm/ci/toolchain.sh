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
# like any -lfoo. $WALI_EXTRA_* let the farm add the overlay of already-built deps.
# -flto is dropped: setjmp/longjmp lowering (-wasm-enable-sjlj) is a compile-time pass, and
# LTO objects reach the linker with it undone ("undefined symbol: longjmp").
for d in cc c++; do
  drv=clang; cxx=""; cxxlibs=""
  [ $d = c++ ] && { drv=clang++; cxx="-isystem $S/include/c++/v1"; cxxlibs="-lc++ -lc++abi -lunwind -lwali-cppexc"; }
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
   \${WALI_EXTRA_CFLAGS:-})
A=()
for a in "\$@"; do case "\$a" in
  -Wl,--start-group|-Wl,--end-group|-Wl,--as-needed|-Wl,--no-as-needed|-Wl,--gc-sections|-Wl,--warn-common|-Wl,--sort-common|-Wl,-O1|-Wl,--hash-style=*|-Wl,-z,relro|-Wl,-z,now|-Wl,-soname*|-Wl,-soname,*|-Wl,--version-script*|-Wl,-Bsymbolic*|-rdynamic|-static|-s|-fPIC|-fpic|-fPIE|-fpie|-pie|-flto|-flto=*|-ffat-lto-objects|-fuse-linker-plugin) ;;
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
    \${WALI_EXTRA_LIBS:-} $cxxlibs -lc $S/lib/libclang_rt.builtins.a
fi
exec $L/$drv "\${F[@]}" "\${A[@]}"
EOF
  chmod +x bin/wali-$d
done
printf '#!/bin/sh\nargs=""\nfor a in "$@"; do [ "$a" = "-nostdlib" ] || args="$args $a"; done\nexec %s/wasm-ld $args\n' "$L" > bin/wali-ld
chmod +x bin/wali-ld

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
#!/bin/sh
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
set(CMAKE_POSITION_INDEPENDENT_CODE OFF CACHE BOOL "")
EOF
echo "toolchain ready: $TC (LLVM $LLVM_VER, sysroot $TAG, extras $XTAG)"
