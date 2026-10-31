#!/bin/bash
# WALI cross toolchain for the build farm, from public parts only:
#   - upstream LLVM release binaries (clang, wasm-ld, llvm-ar...), the version walios uses
#   - the walios sysroot (wali-musl libc + openssl + compiler-rt builtins), from the
#     walios package release
# Writes $TC/env.sh and cc/c++/ld wrappers in $TC/bin. Idempotent; CI caches $TC.
#   toolchain.sh <dir> [pkgs-tag]
set -euo pipefail
TC=$(realpath -m "${1:?usage: toolchain.sh <dir> [pkgs-tag]}")
TAG=${2:-pkgs-2026-10-31}
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
  curl -sSfL https://github.com/eze-paz/walios/releases/download/$TAG/wali-sysroot.tar.gz | tar xz -C sysroot
fi
L=$TC/$P/bin
S=$TC/sysroot
cat > env.sh <<EOF
export WALI_TC=$TC WALI_LLVM=$L WALI_SYSROOT=$S
export CC=$TC/bin/wali-cc CXX=$TC/bin/wali-c++ LD=$TC/bin/wali-ld
export AR=$L/llvm-ar RANLIB=$L/llvm-ranlib NM=$L/llvm-nm STRIP=$L/llvm-strip OBJCOPY=$L/llvm-objcopy
EOF
# One driver for compile and link. Compile flags = the ones python_cxx.wasm is built with
# (walios/build/cpython/build.sh in sandpie); a link adds the flags every walios guest
# needs: shared+imported memory (the kernel owns it), 8 MB stack (64 KB overflows into
# misleading OOB traps), exported growable table (signal handlers), and libc + builtins.
# $WALI_EXTRA_CFLAGS / $WALI_EXTRA_LIBS let the farm add the overlay of built deps.
for d in cc c++; do
  drv=clang; [ $d = c++ ] && drv=clang++
  cat > bin/wali-$d <<EOF
#!/bin/bash
link=1
for a in "\$@"; do case "\$a" in -c|-E|-S|-M|-MM) link=0;; esac; done
F=(--target=wasm32-unknown-linux-muslwali --sysroot=$S -nostdlibinc -isystem $S/include -D_GNU_SOURCE
   -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -pthread
   -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types
   -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument -Wno-ignored-optimization-argument
   \${WALI_EXTRA_CFLAGS:-})
A=()
for a in "\$@"; do case "\$a" in
  -Wl,--start-group|-Wl,--end-group|-Wl,--as-needed|-Wl,--no-as-needed|-Wl,--gc-sections|-Wl,--warn-common|-Wl,--sort-common|-Wl,-O1|-Wl,--hash-style=*|-Wl,-z,relro|-Wl,-z,now|-rdynamic|-static|-s) ;;
  *) A+=("\$a");; esac; done
if [ \$link = 1 ]; then
  exec $L/$drv "\${F[@]}" "\${A[@]}" -L$S/lib \${WALI_EXTRA_LDFLAGS:-} -nodefaultlibs \
    -Wl,--shared-memory,--import-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608,--export-table,--growable-table \
    \${WALI_EXTRA_LIBS:-} -lc $S/lib/libclang_rt.builtins.a
fi
exec $L/$drv "\${F[@]}" "\${A[@]}"
EOF
  chmod +x bin/wali-$d
done
printf '#!/bin/sh\nargs=""\nfor a in "$@"; do [ "$a" = "-nostdlib" ] || args="$args $a"; done\nexec %s/wasm-ld $args\n' "$L" > bin/wali-ld
chmod +x bin/wali-ld
echo "toolchain ready: $TC (LLVM $LLVM_VER, sysroot from $TAG)"
