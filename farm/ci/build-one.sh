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
# pkg-config's python3 / python-3.X (-embed), for recipes that build Python bindings or embed
# Python (libxml2 asks for the build host's version): walios Python's headers, i.e. the
# runner's 3.14 include dir once the workflow put walios' pyconfig.h in it. No Libs: an
# extension takes the interpreter's symbols from python_cxx.wasm.
if command -v python3.14 >/dev/null; then
  pinc=$(python3.14 -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
  if grep -q 'define SIZEOF_VOID_P 4' "$pinc/pyconfig.h" 2>/dev/null; then
    if [ ! -f "$OVERLAY/usr/lib/pkgconfig/python3.pc" ]; then
      mkdir -p "$OVERLAY/usr/include/python3.14" "$OVERLAY/usr/lib/pkgconfig" && cp -r "$pinc/." "$OVERLAY/usr/include/python3.14/"
      for n in python3 python-3.14 python-3.13 python-3.12 python-3.11; do for e in "" -embed; do
        printf 'prefix=/usr
includedir=${prefix}/include/python3.14
Name: Python
Description: walios Python
Version: 3.14
Libs:
Cflags: -I${includedir}
' > "$OVERLAY/usr/lib/pkgconfig/$n$e.pc"
      done; done
    fi
    # meson's python module reads the interpreter's own python-3.14.pc (its LIBPC dir), whose
    # includedir is the runner's path -- which PKG_CONFIG_SYSROOT_DIR then puts under the
    # overlay ("Cannot compile `Python.h`", numpy). The same headers, at that path.
    [ -e "$OVERLAY$pinc" ] || { mkdir -p "$(dirname "$OVERLAY$pinc")" && ln -s "$pinc" "$OVERLAY$pinc"; }
  fi
fi
log="$OUT/$pkg.log"; : > "$log"
bdir=$(mktemp -d); trap 'rm -rf "$bdir"' EXIT
pkgver="?"; BUILD_SECS=0; DEPS=""
emit() {  # status reason kind smoke
  local row deps
  # Runtime depends, as plain package names (the index lets `apk add` pull a module's deps).
  deps=$(for d in $DEPS; do d=${d%%[<>=~]*}; case "$d" in ''|*:*|!*) ;; *) printf '"%s",' "$d";; esac; done)
  # abiwarn: format calls whose argument width differs from what the format reads (abiwarn.js);
  # they compile and run, printing garbage, so a built package carries the count.
  row=$(printf '{"pkg":"%s","ver":"%s","status":"%s","reason":"%s","kind":"%s","secs":%s,"smoke":"%s","abiwarn":%s,"deps":[%s]}' \
    "$pkg" "$pkgver" "$1" "$2" "${3:-}" "$BUILD_SECS" "$(printf '%s' "${4:-}" | tr -d '\000-\037"\\' | cut -c1-80)" \
    "$(node "$HERE/abiwarn.js" "$log" 2>/dev/null || echo 0)" "${deps%,}")
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
# Already part of the walios sysroot (libssl/libcrypto, musl, libffi with its WALI port --
# toolchain.sh): dependents
# link those; Alpine's openssl recipe has no wasm32 target ("Unable to determine architecture").
case "$pkg" in openssl|musl|libffi) emit skip in-sysroot;; esac
case " $(apk makedepends) " in *" cargo "*|*" rust "*|*" cargo-auditable "*) emit skip needs-rust;; *" go "*) emit skip needs-go;; esac
# A C module must match its interpreter's ABI: under WALI_ABI=ilp32 it links against the
# exports of walios' ILP32 python/perl/lua (the *-exports32.txt lists).
X=""; [ "${WALI_ABI:-ilp32}" = ilp32 ] && X=32
# Python packages (gpep517 + installer) are built as Alpine builds them, on the runner's
# Python 3.14 -- the version walios runs, and the same extension suffix
# (.cpython-314-x86_64-linux-gnu.so) -- whose pyconfig.h the workflow swapped for walios
# Python's (the toolchain's ABI). Its compiler is `gcc`, i.e. the wasm wrapper, so
# with WALI_SIDE a C extension links as a wasm side module importing only python_cxx.wasm's
# exports (python-exports.txt = sandpie walios/build/cpython/main-exports.txt).
PYPKG=""; grep -qE 'gpep517|python3 -m (build|installer)|python3 setup\.py' "$bdir/APKBUILD" && { PYPKG=1; export WALI_SIDE="$HERE/python-exports$X.txt"
  # (setuptools/meson take these over the compiler recorded in the host Python's sysconfig)
  export LDSHARED="$CC -shared" LDCXXSHARED="$CXX -shared"
  # (meson-python runs $MESON, not the first meson on PATH: the runner's pip one, a native build)
  export MESON="$WALI_TC/bin/meson"
  # (a release tarball has no git metadata for setuptools-scm; Alpine's builds set the same)
  export SETUPTOOLS_SCM_PRETEND_VERSION="$pkgver"; }
# Its build-time Python deps (makedepends py3-foo, mostly PyPI's foo: build backends,
# expandvars, cython...) run on the HOST Python: installed from PyPI, wheels only -- an sdist
# would compile with `gcc`, which here is the wasm compiler.
if [ -n "$PYPKG" ]; then
  # (PyPI names: numpy-dev is numpy, py3-pybind11-dev pybind11, py3-python-versioneer versioneer)
  for d in $(apk makedepends); do case "$d" in py3-*|numpy-dev)
    n=${d#py3-}; n=${n%-dev}
    python3 -m pip install -q --only-binary=:all: "$n" >>"$log" 2>&1 || python3 -m pip install -q --only-binary=:all: "${n#python-}" >>"$log" 2>&1 ||
      echo "farm: no host wheel for $n" >>"$log";; esac; done
  # Extensions built against numpy (pandas, contourpy, matplotlib) take its headers from the
  # host numpy (numpy.get_include()); they must be walios numpy's, whose config headers record
  # this ABI (NPY_SIZEOF_LONG...) -- like pyconfig.h, swapped in.
  hn=$(python3 -c 'import numpy, os; print(os.path.dirname(numpy.get_include()))' 2>/dev/null)
  wn=$(ls -d "$OVERLAY"/usr/lib/python3*/site-packages/numpy/_core 2>/dev/null | head -1)
  if [ -n "$hn" ] && [ -n "$wn" ] && [ -d "$wn/include" ]; then
    rm -rf "$hn/include" && cp -r "$wn/include" "$hn/include"
    [ -d "$wn/lib" ] && cp -r "$wn/lib/." "$hn/lib/" 2>/dev/null
    echo "farm: host numpy headers <- walios numpy" >>"$log"
  fi
fi
# Lua C modules (recipes looping over $_luaversions): built for Lua 5.4 only, what walios'
# lua.wasm is, as wasm side modules it dlopen()s -- PIC, importing only lua.wasm's exports
# (lua-exports.txt, from walios/build/lua in sandpie). Alpine installs them from the
# lua5.X-<name> subpackage functions, so the farm runs the 5.4 one into $pkgdir.
LUAMOD=""
if [ -z "$NOARCH" ] && grep -q '^_luaversions=' "$bdir/APKBUILD"; then
  LUAMOD=1; export WALI_SIDE="$HERE/lua-exports$X.txt"
  sed -i 's/^_luaversions=.*/_luaversions="5.4"/' "$bdir/APKBUILD"
fi
# Perl XS modules (perl-*, not noarch): side modules perl.wasm's DynaLoader dlopen()s,
# importing only its exports (perl-exports.txt, from walios/build/perl in sandpie). The
# recipe's `perl Makefile.PL` runs on the runner's perl and writes the host's Config into
# the Makefile; MakeMaker ignores PERL_INC/CCFLAGS arguments, so make's own command-line
# overrides (through MAKEFLAGS, which every make in the recipe sees) point it at walios
# perl's headers (the toolchain's perl-core), the wasm compiler, no host ccflags, no host
# header deps (PERL_HDRS names 5.38's), and walios' vendor dirs. No value may contain a
# space; perl's -fwrapv -fno-strict-aliasing ride in WALI_EXTRA_CFLAGS instead.
PERLXS="" PERLXS_MAKE=""
if [ -z "$NOARCH" ] && case "$pkg" in perl-*) true;; *) false;; esac; then
  PERLXS=1; export WALI_SIDE="$HERE/perl-exports$X.txt" PERL_MM_OPT="CC=$CC LD=$CC"
  # Makefile.PL's compiler probes (ExtUtils::CBuilder, Config::AutoConf) link with $LD, which
  # the toolchain sets to the bare wasm-ld wrapper; and they `use` build-time modules the
  # farm built as pure-Perl packages (Canary::Stability...), in the overlay's noarch dir.
  export LD="$CC" PERL5LIB="$OVERLAY/usr/share/perl5/vendor_perl:$OVERLAY/usr/share/perl5${PERL5LIB:+:$PERL5LIB}"
  pc=$WALI_TC/perl-core/5.44.0/wasm32-linux/CORE
  PERLXS_MAKE="PERL_HDRS= PERL_INC=$pc PERL_INCDEP=$pc CC=$CC LD=$CC CCFLAGS=-D_GNU_SOURCE OPTIMIZE=-O2 CCCDLFLAGS=-fPIC LDDLFLAGS=-shared LDFLAGS= INSTALLVENDORARCH=/usr/lib/perl5/vendor_perl INSTALLVENDORLIB=/usr/share/perl5/vendor_perl"
fi

# Every remote source, like abuild (freetype's second tarball is ft2demos); the first one's
# top directory is $SRC.
srcs=$(apk source | tr ' \t' '\n\n' | grep -E 'https?://')
if [ -n "$srcs" ]; then
  # Upstream first (with a normal user agent: gitlab.alpinelinux.org answers bots 418), then
  # Alpine's own mirror of every recipe's sources, keyed by the same file name.
  # A 200 can still be a bot-check page (gitlab.freedesktop.org serves the runners HTML),
  # which only failed later at extraction: an HTML body counts as a failed download.
  dl() { curl -sSfL --retry 2 --connect-timeout 30 --max-time 300 -A "Mozilla/5.0 (walios farm)" "$1" -o "$bdir/$src_name" 2>>"$log" &&
         ! head -c 512 "$bdir/$src_name" | grep -qiE '<!doctype html|<html'; }
  SRC=""
  for src_entry in $srcs; do
    src_name="${src_entry%%::*}"; src_url="${src_entry##*::}"
    [ "$src_name" = "$src_url" ] && src_name="$(basename "$src_url")"
    dl "$src_url" || dl "https://distfiles.alpinelinux.org/distfiles/edge/$src_name"     || dl "https://distfiles.alpinelinux.org/distfiles/v3.22/$src_name" || emit fail dl-failed
    # tar first; bsdtar for what GNU tar cannot open (.zip, .tar.lz, .7z...)
    before=$(ls "$bdir")
    case "$src_name" in *.tar*|*.tgz|*.tbz*|*.txz|*.zip|*.7z|*.lz|*.zst)
      tar xf "$bdir/$src_name" -C "$bdir" 2>>"$log" || bsdtar xf "$bdir/$src_name" -C "$bdir" 2>>"$log" || emit fail extract-failed;;
    esac
    [ -z "$SRC" ] && SRC=$(comm -13 <(printf '%s\n' "$before" | sort) <(ls "$bdir" | sort) | while read -r d; do [ -d "$bdir/$d" ] && [ "$d" != pkg ] && echo "$bdir/$d"; done | head -1)
  done
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
# gnulib on wasm: no signals, no /proc VMA introspection. (config.h first, like every gnulib
# source: gnulib's own stdint.h/sys/types.h replacements insist on it.) Its __linux__ checks fire for our
# -linux-muslwali triple, so give c-stack/sigsegv their no-op paths (what stackvma-none.c is).
for sv in $(find "$SRC" -name stackvma.c 2>/dev/null); do
  printf '#include <config.h>\n#include "stackvma.h"\nint sigsegv_get_vma (uintptr_t address, struct vma_struct *vma) { (void)address; (void)vma; return -1; }\n' > "$sv"; done
for vi in $(find "$SRC" -path "*/lib/vma-iter.c" 2>/dev/null); do
  printf '#include <config.h>\n#include "vma-iter.h"\nint vma_iterate (vma_iterate_callback_fn callback, void *data) { (void)callback; (void)data; return -1; }\n' > "$vi"; done
for f in $(find "$SRC" -name sigsegv.in.h 2>/dev/null); do
  sed -i 's|#endif /\* _SIGSEGV_H \*/|#if defined __wasm__\n# undef HAVE_SIGSEGV_RECOVERY\n# define HAVE_SIGSEGV_RECOVERY 0\n# undef HAVE_STACK_OVERFLOW_RECOVERY\n# define HAVE_STACK_OVERFLOW_RECOVERY 0\n#endif\n#endif /* _SIGSEGV_H */|' "$f"; done

# The aport's own prepare()/build()/package(), unmodified, with our toolchain and the abuild
# environment it expects (CARCH, CHOST, the helper functions), under fakeroot so package()
# may chown/install -o root. Not under `set -u`: recipes read optional variables freely.
pkgdir="$bdir/pkg"; mkdir -p "$pkgdir"
cat > "$bdir/.farm-build.sh" <<'EOS'
set +u
# (Lua modules: 5.4's headers before /usr/include, which holds lua5.1's lua.h.)
export WALI_EXTRA_CFLAGS="${LUAMOD:+-I$OVERLAY/usr/include/lua5.4 }-I$OVERLAY/usr/include${PERLXS:+ -fwrapv -fno-strict-aliasing}${ABIFLAGS:+ $ABIFLAGS}" WALI_EXTRA_LDFLAGS="-L$OVERLAY/usr/lib -L$OVERLAY/lib" WALI_OVERLAY="$OVERLAY"
# Deps' *-config scripts (gpgrt-config, pcre2-config, xml2-config...) are shell scripts the
# recipes look up on PATH -- last, so host tools still win over the overlay's wasm binaries.
# (No CMAKE_PREFIX_PATH: cmake searches PREFIX/bin for programs and took the overlay's wasm ninja.)
export PATH="$PATH:$OVERLAY/usr/bin"
export CFLAGS="" CXXFLAGS="" LDFLAGS="" CPPFLAGS="" CONFIG_SITE="$HERE/config.site" FARM_CI_DIR="$HERE"
# LIBDIR, not PATH: the build host's own .pc files (the runner's libyaml, zlib...) must not
# be found, or a recipe enables a feature whose wasm library does not exist.
export PKG_CONFIG_LIBDIR="$OVERLAY/usr/lib/pkgconfig:$OVERLAY/usr/share/pkgconfig:$OVERLAY/lib/pkgconfig:$WALI_SYSROOT/lib/pkgconfig" PKG_CONFIG_PATH="" PKG_CONFIG_SYSROOT_DIR="$OVERLAY"
export CARCH=wasm32 CLIBC=musl CBUILD=x86_64-pc-linux-gnu CHOST=wasm32-unknown-linux-musl CTARGET=wasm32-unknown-linux-musl
export CTARGET_ARCH=wasm32 CBUILD_ARCH=x86_64 cross_compiling=yes JOBS=$(nproc) MAKEFLAGS="-j$(nproc)${PERLXS_MAKE:+ -- $PERLXS_MAKE}"
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
if [ -n "$LUAMOD" ]; then for sp in $subpackages; do case "$sp" in
  lua5.4-*:*) ( subpkgname=${sp%%:*}; subpkgdir="$PKGDIR"; cd "$builddir" 2>/dev/null || cd "$SRC"; "${sp##*:}" );; esac; done; fi
EOS
# Link against this package's deps' archives only (plan.js deps.json + the wave job's
# per-package archive lists); without both, the wrapper falls back to every overlay archive.
if [ -n "${WALI_OVERLAY_IDX:-}" ] && [ -f "${APORTS_DIR:-}/deps.json" ]; then
  WALI_OVERLAY_LIBS=$(for d in $(node -e 'const j=require(process.argv[1]);console.log((j[process.argv[2]]||[]).join(" "))' "$APORTS_DIR/deps.json" "$pkg"); do
    [ -f "$WALI_OVERLAY_IDX/$d.list" ] && sed "s|^|$OVERLAY/|" "$WALI_OVERLAY_IDX/$d.list"; done | tr '\n' ' ')
  export WALI_OVERLAY_LIBS
  echo "farm: linking against deps' archives: $WALI_OVERLAY_LIBS" >> "$log"
fi
# WALI ABI (32-bit pointers, 64-bit long) flags for this package, from abi-flags.txt; the
# ILP32 ABI needs none.
ABIFLAGS=""
[ "${WALI_ABI:-ilp32}" = wali ] && ABIFLAGS=$(awk -v p="$pkg" '$1 == p { $1 = ""; print substr($0, 2) }' "$HERE/abi-flags.txt")
[ -n "$ABIFLAGS" ] && echo "farm: ABI flags: $ABIFLAGS" >> "$log"
# Real fork (farm/ci/asyncify-fork.txt): the define rides in ABIFLAGS into every compile.
ASYNCFORK=""
if grep -qx "$pkg" "$HERE/asyncify-fork.txt" 2>/dev/null; then
  ASYNCFORK=1; ABIFLAGS="${ABIFLAGS:+$ABIFLAGS }-D__WALI_ASYNCIFY_FORK"; echo "farm: real fork() (asyncify)" >> "$log"
fi
_t0=$(date +%s)
# stdin is /dev/null and the perl/test knobs say "no questions": a Makefile.PL prompt used to
# hang a job until its timeout.
ABIFLAGS="$ABIFLAGS" LUAMOD="$LUAMOD" PERLXS="$PERLXS" PERLXS_MAKE="$PERLXS_MAKE" OVERLAY="$OVERLAY" HERE="$HERE" BDIR="$bdir" SRC="$SRC" PKGDIR="$pkgdir"   PERL_MM_USE_DEFAULT=1 AUTOMATED_TESTING=1 NONINTERACTIVE_TESTING=1 DEBIAN_FRONTEND=noninteractive   fakeroot -- bash "$bdir/.farm-build.sh" >>"$log" 2>&1 </dev/null
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
# Perl modules installed by the runner's (Debian's) perl land in its arch dirs; walios perl
# reads Alpine's (PERL5LIB in sandpie's walios-backend.js), so they move there.
for d in "$pkgdir"/usr/lib/x86_64-linux-gnu/perl5/5.* "$pkgdir"/usr/lib/x86_64-linux-gnu/perl/5.* "$pkgdir"/usr/local/lib/x86_64-linux-gnu/perl/5.*; do
  [ -d "$d" ] || continue
  mkdir -p "$pkgdir/usr/lib/perl5/vendor_perl" && cp -a "$d/." "$pkgdir/usr/lib/perl5/vendor_perl/" && rm -rf "$d"
done
rmdir -p "$pkgdir/usr/lib/x86_64-linux-gnu/perl5" "$pkgdir/usr/lib/x86_64-linux-gnu/perl" 2>/dev/null
# Some recipes install libraries under /lib (zlib, ncurses' terminfo libs), not /usr/lib.
ovdirs=$(cd "$pkgdir" && ls -d usr lib 2>/dev/null)
# Wherever the build host's Python installed it: Debian's is usr/local/lib/python3.X/
# dist-packages, a venv's is under the venv path, Alpine's is usr/lib/python3.X/site-packages.
pyd=$(cd "$pkgdir" && find . -type d \( -name site-packages -o -name dist-packages \) 2>/dev/null | head -1 | sed 's|^\./||')
# A Python package reaches later waves too, at Alpine's path: a package built against numpy
# takes walios numpy's C headers from there (the runner's Python prefix is no overlay dir,
# so pandas compiled against x86-64 numpy's, where npy_int64 is a long -- 4 bytes here).
pyov=; [ -n "$pyd" ] && [ -n "$PYPKG" ] && case "$pyd" in usr/*) ;; *) pyov=$pyd;; esac
[ -n "$ovdirs$pyov" ] && tar czf "$OUT/$pkg.overlay.tar.gz" -C "$pkgdir" ${pyov:+--transform "s|^$pyov|usr/lib/python3/site-packages|"} $ovdirs $pyov
# Scripts the build host's pip/setuptools installed start with ITS interpreter
# (#!/opt/hostedtoolcache/Python/3.14.9/x64/bin/python3.14): Alpine's say /usr/bin/python3.
fix_shebangs() {
  for f in $(cd "$pkgdir" && find usr/bin bin usr/sbin sbin -type f 2>/dev/null); do
    head -c2 "$pkgdir/$f" 2>/dev/null | grep -q '#!' || continue
    sed -i -E '1s|^#![^ ]*/python[0-9.]*( .*)?$|#!/usr/bin/python3\1|' "$pkgdir/$f"
  done
}
# noarch_files <reason>: the whole of what package() installed, docs aside, as a mod.
noarch_files() {
  local top; top=$(cd "$pkgdir" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | sort)
  [ -n "$top" ] || return 0
  (cd "$pkgdir" && find $top -type f ! -path 'usr/share/man/*' ! -path 'usr/share/doc/*' ! -path 'usr/share/info/*' | grep -q .) || return 0
  fix_shebangs
  tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" --exclude=usr/share/man --exclude=usr/share/doc --exclude=usr/share/info --exclude=__pycache__ $top
  emit pass "$1" mod "$(cd "$pkgdir" && find usr/bin bin usr/sbin sbin -maxdepth 1 -type f 2>/dev/null | head -3 | tr '\n' ' ')"
}
# A pure-Perl or pure-Lua module (noarch, installs into Alpine's module paths) is a package in
# its own right on walios: those files, as a tarball `apk add` mounts at /.
# Python: site-packages built with the runner's Python goes to walios Python's /site-packages
# (on its PYTHONPATH), C extensions included when every one is a wasm side module.
if [ -n "$pyd" ] && { [ -n "$PYPKG" ] || [ -n "$NOARCH" ]; }; then   # not a C library's bindings
  for so in $(cd "$pkgdir/$pyd" && find . -name '*.so' -o -name '*.pyd'); do
    node -e "process.exit(WebAssembly.Module.customSections(new WebAssembly.Module(require('fs').readFileSync(process.argv[1])),'dylink.0').length?0:1)" "$pkgdir/$pyd/$so" 2>/dev/null ||
      emit fail "python-c-extension:$(basename "$so") is not a wasm side module"
  done
  if (cd "$pkgdir/$pyd" && find . -name '*.py' | grep -q .); then
    # (no __pycache__: compiled for the build host's Python, not walios'), with the package's
    # commands (meson, scons, cython... are Python programs as much as modules)
    fix_shebangs
    bins=$(cd "$pkgdir" && ls -d usr/bin bin usr/sbin sbin 2>/dev/null)
    tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" --exclude=__pycache__ --transform "s|^$pyd|site-packages|" "$pyd" $bins; emit pass module mod
  fi
fi
if [ -n "$LUAMOD" ]; then
  # Only real side modules (a dylink.0 section) count: lua.wasm cannot load anything else.
  sm=$(cd "$pkgdir" && find usr/lib/lua/5.4 -name '*.so' 2>/dev/null | while read -r f; do
    node -e "process.exit(WebAssembly.Module.customSections(new WebAssembly.Module(require('fs').readFileSync(process.argv[1])),'dylink.0').length?0:1)" "$f" 2>/dev/null && echo "$f"; done)
  if [ -n "$sm" ]; then
    tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" $(cd "$pkgdir" && ls -d usr/lib/lua/5.4 usr/share/lua/5.4 usr/share/lua/common 2>/dev/null); emit pass module mod
  fi
  emit fail "lua-no-module:$(grep -m1 -E 'error|Error|ERROR' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
fi
if [ -n "$PERLXS" ]; then
  # auto/**/*.so side modules + the .pm files that bootstrap them, under walios' vendor dirs.
  sm=$(cd "$pkgdir" && find usr/lib/perl5 -name '*.so' 2>/dev/null | while read -r f; do
    node -e "process.exit(WebAssembly.Module.customSections(new WebAssembly.Module(require('fs').readFileSync(process.argv[1])),'dylink.0').length?0:1)" "$f" 2>/dev/null && echo "$f"; done)
  # (an arch=all recipe with no .xs at all is pure Perl after all)
  if [ -n "$sm" ] || { ! find "$SRC" -name '*.xs' | grep -q . && (cd "$pkgdir" && find usr -name '*.pm' 2>/dev/null) | grep -q .; }; then
    tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" $(cd "$pkgdir" && ls -d usr/lib/perl5 usr/share/perl5 2>/dev/null); emit pass module mod
  fi
  emit fail "perl-no-xs-module:$(grep -m1 -E 'error|Error|ERROR' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
fi
[ -n "$PYPKG" ] && emit fail "python-no-output:$(grep -m1 -E 'ERROR|Error|error' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
if [ -n "$NOARCH" ]; then
  mdirs=$(cd "$pkgdir" && ls -d usr/share/perl5 usr/lib/perl5 usr/share/lua 2>/dev/null)
  if [ -n "$mdirs" ] && (cd "$pkgdir" && find $mdirs -type f \( -name '*.pm' -o -name '*.pl' -o -name '*.lua' \)) | grep -q .; then
    tar czf "$OUT/$pkg.mod.tar.gz" -C "$pkgdir" $mdirs; emit pass module mod
  fi
  # Anything else architecture-independent (scripts, data, fonts, web apps) is the same files on
  # walios as on any Linux: what package() installed, as a tarball `apk add` mounts at /. The
  # docs stay out (Alpine splits them into -doc subpackages).
  noarch_files files
  emit skip noarch-empty
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
  if [ -n "$ASYNCFORK" ]; then
    "${TC:?}/binaryen/bin/wasm-opt" --asyncify --pass-arg=asyncify-imports@wali.SYS_fork -O2 \
      "$OUT/$pkg.wasm" -o "$OUT/$pkg.async.wasm" >> "$log" 2>&1 && mv "$OUT/$pkg.async.wasm" "$OUT/$pkg.wasm" \
      || { rm -f "$OUT/$pkg.wasm" "$OUT/$pkg.async.wasm"; emit fail asyncify-failed exe ""; }
  fi
  st=$(cd /tmp && timeout 60 $HOST "$OUT/$pkg.wasm" --version </dev/null 2>&1)
  smoke="$(basename "$exe"): $(printf '%s\n' "$st" | grep -vE 'wali-host\]|ENOSYS|stub' | head -1)"
  if printf '%s' "$st" | grep -qE 'trap in pid|LinkError|CompileError|RuntimeError'; then rm -f "$OUT/$pkg.wasm"; emit fail smoke-trap exe "$smoke"
  elif printf '%s' "$st" | grep -qE 'exit=[0-9]+ procs'; then emit pass ok exe "$smoke"
  else rm -f "$OUT/$pkg.wasm"; emit fail smoke-crash exe "$smoke"; fi
fi
# A NON-EMPTY archive or shared object: a failed compile still leaves `ar` an empty libfoo.a
# (8 bytes, xxhash), which used to count as built and broke every dependent's configure.
if [ -f "$OUT/$pkg.overlay.tar.gz" ] && tar tzvf "$OUT/$pkg.overlay.tar.gz" | awk '$1 ~ /^-/ && $3 > 8 && $6 ~ /\.(a|so)$/' | grep -q .; then emit pass lib-built lib; fi
emit fail "no-wasm-output:$(grep -m1 -E 'error|Error|ERROR' "$log" | tr -d '\000-\037"\\' | cut -c1-60)"
