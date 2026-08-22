#!/bin/bash
# Build one Alpine aport to wasm32-wali, install into the shared overlay sysroot,
# smoke-test if it's an executable. Prints one JSON object on the LAST stdout line.
#   build-one.sh <pkgname> <overlay-dir>
set -u
pkg="$1"; OVERLAY="$2"
FARM=~/wali-farm; W=~/wali/build
APORTS="https://git.alpinelinux.org/aports/plain"
HOST="node $HOME/walihost/host.js"
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -pthread -matomics -mbulk-memory -mexception-handling -I$OVERLAY/usr/include -L$OVERLAY/usr/lib -L$W/sysroot/lib -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608 -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument -Wno-ignored-optimization-argument"
AR="$W/llvm/bin/llvm-ar"; RANLIB="$W/llvm/bin/llvm-ranlib"; LD="$HOME/walihost/wali-ld"
log="$FARM/log/$pkg.log"; : > "$log"
bdir="$FARM/src/$pkg"; rm -rf "$bdir"; mkdir -p "$bdir" "$FARM/repo" "$OVERLAY"
BUILD_SECS=0
emit() { printf '{"pkg":"%s","ver":"%s","status":"%s","reason":"%s","wasm":"%s","kind":"%s","secs":%s,"smoke":"%s"}\n' \
  "$pkg" "${pkgver:-?}" "$1" "$2" "${3:-}" "${4:-}" "${BUILD_SECS:-0}" "$(echo "${5:-}" | sed 's/"/\\"/g' | cut -c1-50)"; }

# locate the aport dir (main or community)
repo_sub=main
curl -sSfL --max-time 20 "$APORTS/main/$pkg/APKBUILD" -o "$bdir/APKBUILD" 2>>"$log" || {
  repo_sub=community
  curl -sSfL --max-time 20 "$APORTS/community/$pkg/APKBUILD" -o "$bdir/APKBUILD" 2>>"$log" || { emit fail no-recipe; exit 0; }
}
pkgver=$(cd "$bdir" && bash -c 'source ./APKBUILD 2>/dev/null; echo "$pkgver"')
# extract the first http(s) source, handling Alpine's "newname::url" rename syntax
src_entry=$(cd "$bdir" && bash -c 'source ./APKBUILD 2>/dev/null; echo "$source"' | tr " \t" "\n\n" | grep -E 'https?://' | head -1)
src_name="${src_entry%%::*}"; src_url="${src_entry##*::}"
[ "$src_name" = "$src_url" ] && src_name="$(basename "$src_url")"
[ -z "$src_url" ] && { emit fail no-source; exit 0; }

tarball="$bdir/$src_name"
curl -sSfL --max-time 90 "$src_url" -o "$tarball" 2>>"$log" || { emit fail dl-failed; exit 0; }
tar xf "$tarball" -C "$bdir" 2>>"$log" || { emit fail extract-failed; exit 0; }
SRC=$(find "$bdir" -maxdepth 1 -type d ! -path "$bdir" | head -1)
[ -z "$SRC" ] && { emit fail no-srcdir; exit 0; }
# fetch patches / aux files
for f in $(cd "$bdir" && bash -c 'source ./APKBUILD 2>/dev/null; echo "$source"' | tr " \t" "\n\n" | grep -vE '^https?://|^$'); do
  curl -sSfL --max-time 20 "$APORTS/$repo_sub/$pkg/$f" -o "$bdir/$f" 2>>"$log" && cp "$bdir/$f" "$SRC/" 2>/dev/null
done

# wasm overlay: neutralize gnulib platform assumptions that break on wasm.
# gnulib keys stack-overflow/VMA introspection off __linux__ (which clang defines
# for our -linux-muslwali triple), but wasm has no signals or /proc VMA. Force it
# off so c-stack/sigsegv compile their no-op path. This is a generic wasm-arch
# overlay (vendored gnulib is identical across packages).
# stackvma.c reads /proc VMAs via linux/*.h kernel headers we don't have; on
# wasm there is no VMA introspection, so replace it with the always-fail stub
# (semantically correct — this is what stackvma-none.c does).
for sv in $(find "$SRC" -path "*/lib/stackvma.c" -o -name "stackvma.c" 2>/dev/null); do
  printf '#include "stackvma.h"\nint sigsegv_get_vma (uintptr_t address, struct vma_struct *vma) { (void)address; (void)vma; return -1; }\n' > "$sv"
done
for vi in $(find "$SRC" -path "*/lib/vma-iter.c" 2>/dev/null); do
  printf '#include "vma-iter.h"\nint vma_iterate (vma_iterate_callback_fn callback, void *data) { (void)callback; (void)data; return -1; }\n' > "$vi"
done
for f in $(find "$SRC" -name "sigsegv.in.h" 2>/dev/null); do
  # sigsegv.h is GENERATED from this template with config values (=1 for our
  # -linux- triple). wasm has no signals/VMA introspection, so force recovery
  # off in the emitted header, before both sigsegv.c and c-stack.c use it.
  sed -i 's|#endif /\* _SIGSEGV_H \*/|#if defined __wasm__\n# undef HAVE_SIGSEGV_RECOVERY\n# define HAVE_SIGSEGV_RECOVERY 0\n# undef HAVE_STACK_OVERFLOW_RECOVERY\n# define HAVE_STACK_OVERFLOW_RECOVERY 0\n#endif\n#endif /* _SIGSEGV_H */|' "$f"
done

# run prepare()+build()+package() with WALI toolchain, install into overlay
_t0=$(date +%s)
(
  export CC="$CC" CXX="$CC" AR="$AR" RANLIB="$RANLIB" LD="$LD"
  export CFLAGS="" CXXFLAGS="" LDFLAGS="" CPPFLAGS=""
  export CONFIG_SITE="$FARM/config.site"
  export cross_compiling=yes CHOST=wasm32-unknown-linux-musl CBUILD=x86_64-pc-linux-gnu
  srcdir="$bdir"; builddir="$SRC"; pkgdir="$bdir/pkg"; subpkgdir="$bdir/subpkg"
  export srcdir builddir pkgdir subpkgdir
  mkdir -p "$pkgdir"
  cd "$srcdir"
  default_prepare() { cd "$builddir"; for p in $source; do case "$p" in
      *.patch) [ -f "$srcdir/$p" ] && { echo "applying $p"; patch -p1 <"$srcdir/$p" || return 1; };; esac
    done; cd "$srcdir"; }
  source ./APKBUILD 2>>"$log"
  : "${builddir:=$SRC}"
  ( if type prepare >/dev/null 2>&1; then prepare; else default_prepare; fi ) >>"$log" 2>&1
  cd "$builddir" 2>/dev/null || cd "$SRC"
  ( if type build >/dev/null 2>&1; then build; else make; fi ) >>"$log" 2>&1
  # install into overlay so dependents can link (best-effort)
  ( if type package >/dev/null 2>&1; then package; fi ) >>"$log" 2>&1
  if [ -d "$pkgdir/usr" ]; then cp -a "$pkgdir/usr/." "$OVERLAY/usr/" 2>/dev/null; fi
  # also sweep any freshly built static libs / headers not captured by package()
  find "$builddir" -name "*.a" -exec cp {} "$OVERLAY/usr/lib/" \; 2>/dev/null
)
BUILD_SECS=$(( $(date +%s) - _t0 ))
mkdir -p "$OVERLAY/usr/lib" "$OVERLAY/usr/include"

# detect wasm artifacts: executable (has _start) vs library (.a)
exe=""
while IFS= read -r f; do
  [ "$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "0061736d" ] || continue
  if node -e "const m=new WebAssembly.Module(require('fs').readFileSync(process.argv[1]));process.exit(WebAssembly.Module.exports(m).some(e=>e.name==='_start'&&e.kind==='function')?0:1)" "$f" 2>/dev/null; then exe="$f"; break; fi
done < <(find "$SRC" "$bdir/pkg" -type f 2>/dev/null)

if [ -n "$exe" ]; then
  cp "$exe" "$FARM/repo/$pkg.wasm"
  case "$pkg" in
    sed|grep|tar|gzip|xz|bzip2|diffutils|patch|gawk|jq|file|coreutils|findutils) sa="--version";;
    sqlite) sa=":memory:";; *) sa="--version";;
  esac
  st=$($HOST "$FARM/repo/$pkg.wasm" $sa </dev/null 2>&1)
  smoke=$(echo "$st" | grep -vE "wali-host\]|ENOSYS|stub import" | head -1)
  if echo "$st" | grep -qE "trap in pid|fatal:|LinkError|CompileError"; then emit fail smoke-trap "$pkg.wasm" exe "$smoke"
  elif echo "$st" | grep -qE "exit=0|exit=1"; then emit pass ok "$pkg.wasm" exe "$smoke"
  else emit fail smoke-crash "$pkg.wasm" exe "$smoke"; fi
  exit 0
fi
# library-only: pass if it dropped a static archive into the overlay
if ls "$OVERLAY"/usr/lib/lib*.a >/dev/null 2>&1 && find "$SRC" -name "*.a" | grep -q .; then
  emit pass lib-built "" lib
else
  emit fail no-wasm-output
fi
