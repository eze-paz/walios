#!/bin/bash
# Build ONE Alpine aport to wasm32-wali with the farm toolchain (toolchain.sh), the CI
# edition of farm/build-one.sh: no shared state, everything goes to <out>.
#   build-one.sh <pkg> <overlay> <out>
# <overlay>  usr/{include,lib} of already-built deps (read-only input)
# <out>/<pkg>.json            result row (also the last stdout line)
# <out>/<pkg>.wasm            the main executable, if any (smoke-tested on host/host.js)
# <out>/<pkg>.overlay.tar.gz  what package() installed under usr/ (libs + headers for dependents)
# <out>/<pkg>.log             full build log
set -u
pkg="$1"; OVERLAY=$(realpath -m "$2"); OUT=$(realpath -m "$3")
HERE=$(cd "$(dirname "$0")" && pwd)
: "${WALI_TC:?source the toolchain env.sh first}"
APORTS="https://git.alpinelinux.org/aports/plain"
HOST="node $HERE/../../host/host.js"
mkdir -p "$OUT" "$OVERLAY/usr/include" "$OVERLAY/usr/lib"
log="$OUT/$pkg.log"; : > "$log"
bdir=$(mktemp -d); trap 'rm -rf "$bdir"' EXIT
pkgver="?"; BUILD_SECS=0
emit() {  # status reason kind smoke
  local row
  row=$(printf '{"pkg":"%s","ver":"%s","status":"%s","reason":"%s","kind":"%s","secs":%s,"smoke":"%s"}' \
    "$pkg" "$pkgver" "$1" "$2" "${3:-}" "$BUILD_SECS" "$(printf '%s' "${4:-}" | tr -d '\000-\037"\\' | cut -c1-80)")
  echo "$row" > "$OUT/$pkg.json"; echo "$row"; exit 0
}

# The recipe dir: from $APORTS_DIR (an aports checkout, what CI ships) or git.alpinelinux.org.
repo_sub=""
if [ -n "${APORTS_DIR:-}" ]; then
  for s in main community; do [ -f "$APORTS_DIR/$s/$pkg/APKBUILD" ] && { repo_sub=$s; cp -r "$APORTS_DIR/$s/$pkg/." "$bdir/"; break; }; done
  [ -z "$repo_sub" ] && emit fail no-recipe
else
  repo_sub=main
  curl -sSfL --retry 3 --max-time 30 "$APORTS/main/$pkg/APKBUILD" -o "$bdir/APKBUILD" 2>>"$log" || {
    repo_sub=community
    curl -sSfL --retry 3 --max-time 30 "$APORTS/community/$pkg/APKBUILD" -o "$bdir/APKBUILD" 2>>"$log" || emit fail no-recipe; }
fi
apk() { (cd "$bdir" && bash -c "source ./APKBUILD >/dev/null 2>&1; echo \"\$$1\""); }
pkgver=$(apk pkgver)
src_entry=$(apk source | tr ' \t' '\n\n' | grep -E 'https?://' | head -1)
src_name="${src_entry%%::*}"; src_url="${src_entry##*::}"
[ "$src_name" = "$src_url" ] && src_name="$(basename "$src_url")"
[ -z "$src_url" ] && emit fail no-source
curl -sSfL --retry 3 --max-time 300 "$src_url" -o "$bdir/$src_name" 2>>"$log" || emit fail dl-failed
tar xf "$bdir/$src_name" -C "$bdir" 2>>"$log" || emit fail extract-failed
SRC=$(find "$bdir" -mindepth 1 -maxdepth 1 -type d | head -1)
[ -z "$SRC" ] && emit fail no-srcdir
for f in $(apk source | tr ' \t' '\n\n' | grep -vE 'https?://|^$'); do
  [ -f "$bdir/$f" ] || curl -sSfL --retry 3 --max-time 30 "$APORTS/$repo_sub/$pkg/$f" -o "$bdir/$f" 2>>"$log"
  [ -f "$bdir/$f" ] && cp "$bdir/$f" "$SRC/" 2>/dev/null
done

# gnulib on wasm: no signals, no /proc VMA introspection. Its __linux__ checks fire for our
# -linux-muslwali triple, so give c-stack/sigsegv their no-op paths (what stackvma-none.c is).
for sv in $(find "$SRC" -name stackvma.c 2>/dev/null); do
  printf '#include "stackvma.h"\nint sigsegv_get_vma (uintptr_t address, struct vma_struct *vma) { (void)address; (void)vma; return -1; }\n' > "$sv"; done
for vi in $(find "$SRC" -path "*/lib/vma-iter.c" 2>/dev/null); do
  printf '#include "vma-iter.h"\nint vma_iterate (vma_iterate_callback_fn callback, void *data) { (void)callback; (void)data; return -1; }\n' > "$vi"; done
for f in $(find "$SRC" -name sigsegv.in.h 2>/dev/null); do
  sed -i 's|#endif /\* _SIGSEGV_H \*/|#if defined __wasm__\n# undef HAVE_SIGSEGV_RECOVERY\n# define HAVE_SIGSEGV_RECOVERY 0\n# undef HAVE_STACK_OVERFLOW_RECOVERY\n# define HAVE_STACK_OVERFLOW_RECOVERY 0\n#endif\n#endif /* _SIGSEGV_H */|' "$f"; done

# The aport's own prepare()/build()/package(), unmodified, with our toolchain in the env.
_t0=$(date +%s)
pkgdir="$bdir/pkg"; mkdir -p "$pkgdir"
(
  export WALI_EXTRA_CFLAGS="-I$OVERLAY/usr/include" WALI_EXTRA_LDFLAGS="-L$OVERLAY/usr/lib"
  export CFLAGS="" CXXFLAGS="" LDFLAGS="" CPPFLAGS="" CONFIG_SITE="$HERE/../config.site"
  export PKG_CONFIG_PATH="$OVERLAY/usr/lib/pkgconfig" PKG_CONFIG_SYSROOT_DIR="$OVERLAY"
  export cross_compiling=yes CHOST=wasm32-unknown-linux-musl CBUILD=x86_64-pc-linux-gnu CTARGET=wasm32-unknown-linux-musl
  export srcdir="$bdir" builddir="$SRC" pkgdir subpkgdir="$bdir/subpkg" startdir="$bdir"
  cd "$bdir"
  default_prepare() { cd "$builddir"; for p in $source; do case "${p%%::*}" in
      *.patch) [ -f "$srcdir/${p%%::*}" ] && { echo "applying $p"; patch -p1 <"$srcdir/${p%%::*}" || return 1; };; esac; done; }
  source ./APKBUILD
  : "${builddir:=$SRC}"
  ( if type prepare >/dev/null 2>&1; then prepare; else default_prepare; fi )
  cd "$builddir" 2>/dev/null || cd "$SRC"
  ( if type build >/dev/null 2>&1; then build; else make; fi )
  cd "$builddir" 2>/dev/null || cd "$SRC"
  ( if type package >/dev/null 2>&1; then package; fi )
) >>"$log" 2>&1
BUILD_SECS=$(( $(date +%s) - _t0 ))

if [ -d "$pkgdir/usr" ]; then tar czf "$OUT/$pkg.overlay.tar.gz" -C "$pkgdir" usr; fi

# The main executable: prefer usr/bin/<pkg>, then anything in the package's bin dirs, then
# any wasm with a _start export in the tree.
is_exe() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "0061736d" ] &&
  node -e "const m=new WebAssembly.Module(require('fs').readFileSync(process.argv[1]));process.exit(WebAssembly.Module.exports(m).some(e=>e.name==='_start')?0:1)" "$1" 2>/dev/null; }
exe=""
for f in "$pkgdir/usr/bin/$pkg" "$pkgdir/bin/$pkg" $(find "$pkgdir" -path '*bin/*' -type f 2>/dev/null) $(find "$SRC" -type f -size +8k 2>/dev/null); do
  [ -f "$f" ] && is_exe "$f" && { exe="$f"; break; }
done
if [ -n "$exe" ]; then
  cp "$exe" "$OUT/$pkg.wasm"
  st=$(cd /tmp && timeout 60 $HOST "$OUT/$pkg.wasm" --version </dev/null 2>&1)
  smoke=$(printf '%s\n' "$st" | grep -vE 'wali-host\]|ENOSYS|stub' | head -1)
  if printf '%s' "$st" | grep -qE 'trap in pid|LinkError|CompileError|RuntimeError'; then rm -f "$OUT/$pkg.wasm"; emit fail smoke-trap exe "$smoke"
  elif printf '%s' "$st" | grep -qE 'exit=[0-9]+ procs'; then emit pass ok exe "$smoke"
  else rm -f "$OUT/$pkg.wasm"; emit fail smoke-crash exe "$smoke"; fi
fi
if [ -f "$OUT/$pkg.overlay.tar.gz" ] && tar tzf "$OUT/$pkg.overlay.tar.gz" | grep -qE '\.a$'; then emit pass lib-built lib; fi
emit fail "no-wasm-output:$(grep -m1 -iE 'error' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
