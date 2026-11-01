#!/bin/bash
# Build ONE Alpine aport to wasm32-wali with the farm toolchain (toolchain.sh), the CI
# edition of farm/build-one.sh: no shared state, everything goes to <out>.
#   build-one.sh <pkg> <overlay> <out>
# <overlay>  usr/{include,lib} of already-built deps (read-only input)
# <out>/<pkg>.json            result row (also the last stdout line); status pass|fail|skip
# <out>/<pkg>.wasm            the package's program, if it installs one (smoke-tested)
# <out>/<pkg>.overlay.tar.gz  what package() installed under usr/ (libs + headers for dependents)
# <out>/<pkg>.log             full build log
set -u
pkg="$1"; OVERLAY=$(realpath -m "$2"); OUT=$(realpath -m "$3")
HERE=$(cd "$(dirname "$0")" && pwd)
: "${WALI_TC:?source the toolchain env.sh first}"
APORTS="https://git.alpinelinux.org/aports/plain"
HOST="node $HERE/../../host/host.js"
mkdir -p "$OUT" "$OVERLAY/usr/include" "$OVERLAY/usr/lib" "$OVERLAY/lib"
# A static-inline <error.h> some package installs would clash with every gnulib error.c;
# libwali-farm.a provides the real error()/error_at_line().
rm -f "$OVERLAY/usr/include/error.h"
log="$OUT/$pkg.log"; : > "$log"
bdir=$(mktemp -d); trap 'rm -rf "$bdir"' EXIT
pkgver="?"; BUILD_SECS=0; DEPS=""
emit() {  # status reason kind smoke
  local row deps
  # Runtime depends, as plain package names (the index lets `apk add` pull a module's deps).
  deps=$(for d in $DEPS; do d=${d%%[<>=~]*}; case "$d" in ''|*:*|!*) ;; *) printf '"%s",' "$d";; esac; done)
  row=$(printf '{"pkg":"%s","ver":"%s","status":"%s","reason":"%s","kind":"%s","secs":%s,"smoke":"%s","deps":[%s]}' \
    "$pkg" "$pkgver" "$1" "$2" "${3:-}" "$BUILD_SECS" "$(printf '%s' "${4:-}" | tr -d '\000-\037"\\' | cut -c1-80)" "${deps%,}")
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
apk() { (cd "$bdir" && bash -c "CARCH=wasm32; source ./APKBUILD >/dev/null 2>&1; echo \"\$$1\""); }
pkgver=$(apk pkgver)
DEPS=$(apk depends)
# Not wasm targets: architecture-independent packages (pure perl/python/lua, data, fonts)
# run on a walios interpreter as they are -- but they are still built and packaged, because
# header/data ones (xorgproto, xcb-proto, util-macros) are what C dependents need in the
# overlay. Rust and Go need their own toolchains.
NOARCH=""; [ "$(apk arch)" = noarch ] && NOARCH=1
case " $(apk makedepends) " in *" cargo "*|*" rust "*|*" cargo-auditable "*) emit skip needs-rust;; *" go "*) emit skip needs-go;; esac
# Python packages built with gpep517 (C extensions) need a walios Python build environment.
grep -q gpep517 "$bdir/APKBUILD" && emit skip needs-python

src_entry=$(apk source | tr ' \t' '\n\n' | grep -E 'https?://' | head -1)
src_name="${src_entry%%::*}"; src_url="${src_entry##*::}"
[ "$src_name" = "$src_url" ] && src_name="$(basename "$src_url")"
if [ -n "$src_url" ]; then
  # Upstream first (with a normal user agent: gitlab.alpinelinux.org answers bots 418), then
  # Alpine's own mirror of every recipe's sources, keyed by the same file name.
  # A 200 can still be a bot-check page (gitlab.freedesktop.org serves the runners HTML),
  # which only failed later at extraction: an HTML body counts as a failed download.
  dl() { curl -sSfL --retry 2 --connect-timeout 30 --max-time 300 -A "Mozilla/5.0 (walios farm)" "$1" -o "$bdir/$src_name" 2>>"$log" &&
         ! head -c 512 "$bdir/$src_name" | grep -qiE '<!doctype html|<html'; }
  dl "$src_url" || dl "https://distfiles.alpinelinux.org/distfiles/edge/$src_name"     || dl "https://distfiles.alpinelinux.org/distfiles/v3.22/$src_name" || emit fail dl-failed
  # tar first; bsdtar for what GNU tar cannot open (.zip, .tar.lz, .7z...)
  case "$src_name" in *.tar*|*.tgz|*.tbz*|*.txz|*.zip|*.7z|*.lz|*.zst)
    tar xf "$bdir/$src_name" -C "$bdir" 2>>"$log" || bsdtar xf "$bdir/$src_name" -C "$bdir" 2>>"$log" || emit fail extract-failed;;
  esac
  SRC=$(find "$bdir" -mindepth 1 -maxdepth 1 -type d ! -name pkg | head -1)
  # a single-file source (a .c, a script) or a tarball without a top dir
  [ -z "$SRC" ] && { SRC="$bdir/$pkg-$pkgver"; mkdir -p "$SRC"; }
else
  # only local files (alpine-keys, bsd-compat-headers...): the recipe builds from $srcdir
  SRC="$bdir/$pkg-$pkgver"; mkdir -p "$SRC"
fi
for f in $(apk source | tr ' \t' '\n\n' | grep -vE 'https?://|^$'); do
  [ -f "$bdir/$f" ] || curl -sSfL --retry 3 --max-time 30 "$APORTS/$repo_sub/$pkg/$f" -o "$bdir/$f" 2>>"$log"
  [ -f "$bdir/$f" ] && cp "$bdir/$f" "$SRC/" 2>/dev/null
done

# Old config.sub/config.guess reject wasm32; abuild's update_config_sub does this per recipe.
for f in $(find "$SRC" -name config.sub 2>/dev/null); do chmod u+w "$f"; cp /usr/share/misc/config.sub "$f"; done
for f in $(find "$SRC" -name config.guess 2>/dev/null); do chmod u+w "$f"; cp /usr/share/misc/config.guess "$f"; done
# gnulib on wasm: no signals, no /proc VMA introspection. Its __linux__ checks fire for our
# -linux-muslwali triple, so give c-stack/sigsegv their no-op paths (what stackvma-none.c is).
for sv in $(find "$SRC" -name stackvma.c 2>/dev/null); do
  printf '#include "stackvma.h"\nint sigsegv_get_vma (uintptr_t address, struct vma_struct *vma) { (void)address; (void)vma; return -1; }\n' > "$sv"; done
for vi in $(find "$SRC" -path "*/lib/vma-iter.c" 2>/dev/null); do
  printf '#include "vma-iter.h"\nint vma_iterate (vma_iterate_callback_fn callback, void *data) { (void)callback; (void)data; return -1; }\n' > "$vi"; done
for f in $(find "$SRC" -name sigsegv.in.h 2>/dev/null); do
  sed -i 's|#endif /\* _SIGSEGV_H \*/|#if defined __wasm__\n# undef HAVE_SIGSEGV_RECOVERY\n# define HAVE_SIGSEGV_RECOVERY 0\n# undef HAVE_STACK_OVERFLOW_RECOVERY\n# define HAVE_STACK_OVERFLOW_RECOVERY 0\n#endif\n#endif /* _SIGSEGV_H */|' "$f"; done

# The aport's own prepare()/build()/package(), unmodified, with our toolchain and the abuild
# environment it expects (CARCH, CHOST, the helper functions), under fakeroot so package()
# may chown/install -o root. Not under `set -u`: recipes read optional variables freely.
pkgdir="$bdir/pkg"; mkdir -p "$pkgdir"
cat > "$bdir/.farm-build.sh" <<'EOS'
set +u
export WALI_EXTRA_CFLAGS="-I$OVERLAY/usr/include" WALI_EXTRA_LDFLAGS="-L$OVERLAY/usr/lib -L$OVERLAY/lib" WALI_OVERLAY="$OVERLAY"
# Deps' *-config scripts (gpgrt-config, pcre2-config, xml2-config...) are shell scripts the
# recipes look up on PATH -- last, so host tools still win over the overlay's wasm binaries.
# (No CMAKE_PREFIX_PATH: cmake searches PREFIX/bin for programs and took the overlay's wasm ninja.)
export PATH="$PATH:$OVERLAY/usr/bin"
export CFLAGS="" CXXFLAGS="" LDFLAGS="" CPPFLAGS="" CONFIG_SITE="$HERE/config.site" FARM_CI_DIR="$HERE"
# LIBDIR, not PATH: the build host's own .pc files (the runner's libyaml, zlib...) must not
# be found, or a recipe enables a feature whose wasm library does not exist.
export PKG_CONFIG_LIBDIR="$OVERLAY/usr/lib/pkgconfig:$OVERLAY/usr/share/pkgconfig:$OVERLAY/lib/pkgconfig:$WALI_SYSROOT/lib/pkgconfig" PKG_CONFIG_PATH="" PKG_CONFIG_SYSROOT_DIR="$OVERLAY"
export CARCH=wasm32 CLIBC=musl CBUILD=x86_64-pc-linux-gnu CHOST=wasm32-unknown-linux-musl CTARGET=wasm32-unknown-linux-musl
export CTARGET_ARCH=wasm32 CBUILD_ARCH=x86_64 cross_compiling=yes JOBS=$(nproc) MAKEFLAGS="-j$(nproc)"
export CC_FOR_BUILD=/usr/bin/gcc CXX_FOR_BUILD=/usr/bin/g++ BUILD_CC=/usr/bin/gcc BUILD_CXX=/usr/bin/g++ HOSTCC=/usr/bin/gcc HOSTCXX=/usr/bin/g++
export srcdir="$BDIR" builddir="$SRC" pkgdir="$PKGDIR" subpkgdir="$BDIR/subpkg" startdir="$BDIR"
msg() { echo ">>> $*"; }; msg2() { echo "  > $*"; }; warning() { echo "WARNING: $*"; }; warning2() { warning "$@"; }
error() { echo "ERROR: $*"; }; die() { error "$@"; exit 1; }
update_config_sub() { find "${1:-.}" -name config.sub -exec chmod u+w {} \; -exec cp /usr/share/misc/config.sub {} \; ; }
update_config_guess() { find "${1:-.}" -name config.guess -exec chmod u+w {} \; -exec cp /usr/share/misc/config.guess {} \; ; }
want_check() { return 1; }; amove() { :; }; default_check() { :; }; default_doc() { :; }; default_dev() { :; }; default_libs() { :; }
default_prepare() { cd "$builddir"; for p in $source; do case "${p%%::*}" in
    *.patch) [ -f "$srcdir/${p%%::*}" ] && { msg "applying $p"; patch -p1 <"$srcdir/${p%%::*}" || return 1; };; esac; done; }
cd "$BDIR"
source ./APKBUILD
: "${builddir:=$SRC}"
( if type prepare >/dev/null 2>&1; then prepare; else default_prepare; fi )
cd "$builddir" 2>/dev/null || cd "$SRC"
( if type build >/dev/null 2>&1; then build; else make; fi )
cd "$builddir" 2>/dev/null || cd "$SRC"
( if type package >/dev/null 2>&1; then package; fi )
EOS
# Link against this package's deps' archives only (plan.js deps.json + the wave job's
# per-package archive lists); without both, the wrapper falls back to every overlay archive.
if [ -n "${WALI_OVERLAY_IDX:-}" ] && [ -f "${APORTS_DIR:-}/deps.json" ]; then
  WALI_OVERLAY_LIBS=$(for d in $(node -e 'const j=require(process.argv[1]);console.log((j[process.argv[2]]||[]).join(" "))' "$APORTS_DIR/deps.json" "$pkg"); do
    [ -f "$WALI_OVERLAY_IDX/$d.list" ] && sed "s|^|$OVERLAY/|" "$WALI_OVERLAY_IDX/$d.list"; done | tr '\n' ' ')
  export WALI_OVERLAY_LIBS
  echo "farm: linking against deps' archives: $WALI_OVERLAY_LIBS" >> "$log"
fi
_t0=$(date +%s)
# stdin is /dev/null and the perl/test knobs say "no questions": a Makefile.PL prompt used to
# hang a job until its timeout.
OVERLAY="$OVERLAY" HERE="$HERE" BDIR="$bdir" SRC="$SRC" PKGDIR="$pkgdir"   PERL_MM_USE_DEFAULT=1 AUTOMATED_TESTING=1 NONINTERACTIVE_TESTING=1 DEBIAN_FRONTEND=noninteractive   fakeroot -- bash "$bdir/.farm-build.sh" >>"$log" 2>&1 </dev/null
BUILD_SECS=$(( $(date +%s) - _t0 ))

# Only wasm archives may reach the overlay: every later link pulls all overlay archives into
# one group, and a native one (a recipe that built a helper library with the host gcc) made
# wasm-ld fail every link -- configure's "C compiler cannot create executables".
for a in $(find "$pkgdir" -name '*.a' 2>/dev/null); do
  m=$($AR t "$a" 2>/dev/null | grep -v '^/' | head -1)
  { [ -n "$m" ] && [ "$($AR p "$a" "$m" 2>/dev/null | head -c4 | od -An -tx1 | tr -d ' \n')" = "0061736d" ]; } || { echo "farm: dropping non-wasm archive $a" >> "$log"; rm -f "$a"; }
done
# A recipe that installs only lib*.so* (our -shared output is an ar archive under that name)
# leaves dependents' -lfoo unresolved: wasm-ld's -l searches lib*.a only. Add the .a beside it.
for f in $(find "$pkgdir" -name 'lib*.so*' \( -type f -o -type l \) 2>/dev/null); do
  a="${f%%.so*}.a"
  [ -e "$a" ] || { [ "$(head -c7 "$f" 2>/dev/null)" = '!<arch>' ] && cp -L "$f" "$a"; }
done
# libtool .la files name /usr/lib/... paths, which then break every dependent's libtool link
# ("'/usr/lib/libXdmcp.la' is not a valid libtool archive"); Alpine deletes them too.
find "$pkgdir" -name '*.la' -delete 2>/dev/null
# Some recipes install libraries under /lib (zlib, ncurses' terminfo libs), not /usr/lib.
ovdirs=$(cd "$pkgdir" && ls -d usr lib 2>/dev/null)
[ -n "$ovdirs" ] && tar czf "$OUT/$pkg.overlay.tar.gz" -C "$pkgdir" $ovdirs
# A pure-Perl or pure-Lua module (noarch, installs into Alpine's module paths) is a package in
# its own right on walios: those files, as a tarball `apk add` mounts at /.
if [ -n "$NOARCH" ]; then
  mdirs=$(cd "$pkgdir" && ls -d usr/share/perl5 usr/lib/perl5 usr/share/lua 2>/dev/null)
  if [ -n "$mdirs" ] && (cd "$pkgdir" && find $mdirs -type f \( -name '*.pm' -o -name '*.pl' -o -name '*.lua' \)) | grep -q .; then
    tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" $mdirs; emit pass module mod
  fi
  emit skip noarch
fi

# The package's program: what it INSTALLS -- usr/bin/<pkg> first, then its other bin dirs.
# A wasm left in the source tree (an example, a test helper) is not the package.
is_exe() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "0061736d" ] &&
  node -e "const m=new WebAssembly.Module(require('fs').readFileSync(process.argv[1]));process.exit(WebAssembly.Module.exports(m).some(e=>e.name==='_start')?0:1)" "$1" 2>/dev/null; }
exe=""
for f in "$pkgdir/usr/bin/$pkg" "$pkgdir/bin/$pkg" "$pkgdir/usr/sbin/$pkg" "$pkgdir/sbin/$pkg" \
         $(find "$pkgdir/usr/bin" "$pkgdir/bin" "$pkgdir/usr/sbin" "$pkgdir/sbin" -type f 2>/dev/null | sort); do
  [ -f "$f" ] && is_exe "$f" && { exe="$f"; break; }
done
if [ -n "$exe" ]; then
  cp "$exe" "$OUT/$pkg.wasm"
  st=$(cd /tmp && timeout 60 $HOST "$OUT/$pkg.wasm" --version </dev/null 2>&1)
  smoke="$(basename "$exe"): $(printf '%s\n' "$st" | grep -vE 'wali-host\]|ENOSYS|stub' | head -1)"
  if printf '%s' "$st" | grep -qE 'trap in pid|LinkError|CompileError|RuntimeError'; then rm -f "$OUT/$pkg.wasm"; emit fail smoke-trap exe "$smoke"
  elif printf '%s' "$st" | grep -qE 'exit=[0-9]+ procs'; then emit pass ok exe "$smoke"
  else rm -f "$OUT/$pkg.wasm"; emit fail smoke-crash exe "$smoke"; fi
fi
if [ -f "$OUT/$pkg.overlay.tar.gz" ] && tar tzf "$OUT/$pkg.overlay.tar.gz" | grep -qE '\.(a|so)$'; then emit pass lib-built lib; fi
emit fail "no-wasm-output:$(grep -m1 -E 'error|Error|ERROR' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
