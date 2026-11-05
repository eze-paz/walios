#!/usr/bin/env bash
# PDF tools for walios, from upstream sources with their own build systems (no source edits):
#   poppler   pdftoppm pdfimages pdftotext pdfinfo pdffonts pdfseparate pdfunite pdftohtml
#             pdfattach pdfdetach -- the Splash backend (no cairo/glib/qt), FreeType, libjpeg,
#             OpenJPEG, lcms2, libpng; base-14 fonts = URW base35 at the gsfonts names
#             poppler's generic font configuration looks for (/usr/share/fonts/type1/gsfonts)
#   mupdf     mutool (draw, extract, convert, info, clean, merge, ...) with its bundled libs;
#             the base-14 fonts are compiled in
#   qpdf      qpdf, zlib-flate, fix-qdf (native crypto, no openssl/gnutls)
# Each lands as <workdir>/pkg/<name>.pkg.tar.gz: usr/bin/<program> (wasm) + usr/share data,
# mounted at / by `apk add` (kind 'pkg' in the farm index; the kernel execs a wasm file from
# the filesystem).
#
#   build.sh <workdir> <poppler|mupdf|qpdf|deps>
#
# Toolchain: $WALI_TC = a farm toolchain (eze-paz/walios farm/ci/toolchain.sh): wali-cc /
# wali-c++ wrappers, the ILP32 sysroot with libc++, a cmake toolchain file. Runs on GitHub
# Actions (eze-paz/walios .github/workflows/pdftools.yml), Ubuntu 24.04.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(realpath -m "${1:?usage: build.sh <workdir> <component>}")
WHAT=${2:?component: poppler mupdf qpdf deps}
mkdir -p "$R/src" "$R/pkg" && cd "$R"
: "${WALI_TC:?set WALI_TC to a farm toolchain}"
source "$WALI_TC/env.sh"
L=$WALI_LLVM
J=$(nproc)

ZLIB_VER=1.3.1
PNG_VER=1.6.44
JPEG_VER=3.0.4
FT_VER=2.13.3
OPJ_VER=2.5.2
LCMS_VER=2.16
POPPLER_VER=24.08.0
MUPDF_VER=1.24.10
QPDF_VER=11.9.1

# Libraries install under $OV/usr (DESTDIR): the toolchain's cmake file adds $WALI_OVERLAY to
# CMAKE_FIND_ROOT_PATH, and with it set every program link also gets the overlay's archives
# (static libraries carry no record of their own deps: freetype needs libpng and zlib).
OV=$R/overlay
export WALI_OVERLAY=$OV
export PKG_CONFIG_LIBDIR=$OV/usr/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=$OV PKG_CONFIG_PATH=
export CPPFLAGS="-I$OV/usr/include" LDFLAGS="-L$OV/usr/lib"
CM=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_PREFIX_PATH=/usr -DCMAKE_POLICY_VERSION_MINIMUM=3.5)

fetch() {   # fetch <url> -> unpacked under src/ (once)
  local u=$1 f=src/$(basename "$1")
  [ -f "$f" ] || curl -sSfL --retry 8 --retry-all-errors --retry-delay 10 -o "$f" "$u"
  tar xf "$f" -C src
}
log() { echo "== $*"; }
run() { local n=$1; shift; log "$n"; if ! "$@" >"$R/$n.log" 2>&1; then echo "FAILED: $n (tail of $R/$n.log)"; tail -n 80 "$R/$n.log"; exit 1; fi; }

deps() {
  [ -f "$OV/.done" ] && return 0
  rm -rf "$OV"; mkdir -p "$OV/usr"
  fetch https://github.com/madler/zlib/releases/download/v$ZLIB_VER/zlib-$ZLIB_VER.tar.gz
  run zlib bash -c "cd src/zlib-$ZLIB_VER && ./configure --static --prefix=/usr && make -j$J libz.a && make install DESTDIR=$OV"
  fetch https://github.com/pnggroup/libpng/archive/refs/tags/v$PNG_VER.tar.gz
  run libpng bash -c "cmake -S src/libpng-$PNG_VER -B b-png ${CM[*]} -DPNG_SHARED=OFF -DPNG_STATIC=ON -DPNG_TESTS=OFF -DPNG_TOOLS=OFF -DPNG_EXECUTABLES=OFF -DPNG_HARDWARE_OPTIMIZATIONS=OFF && cmake --build b-png -j$J && DESTDIR=$OV cmake --install b-png"
  fetch https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/$JPEG_VER/libjpeg-turbo-$JPEG_VER.tar.gz
  run libjpeg bash -c "cmake -S src/libjpeg-turbo-$JPEG_VER -B b-jpeg ${CM[*]} -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DWITH_SIMD=OFF -DWITH_TURBOJPEG=OFF && cmake --build b-jpeg -j$J && DESTDIR=$OV cmake --install b-jpeg"
  fetch https://download.savannah.gnu.org/releases/freetype/freetype-$FT_VER.tar.xz
  run freetype bash -c "cmake -S src/freetype-$FT_VER -B b-ft ${CM[*]} -DFT_DISABLE_HARFBUZZ=ON -DFT_DISABLE_BROTLI=ON -DFT_DISABLE_BZIP2=ON -DFT_REQUIRE_ZLIB=ON -DFT_REQUIRE_PNG=ON && cmake --build b-ft -j$J && DESTDIR=$OV cmake --install b-ft"
  fetch https://github.com/uclouvain/openjpeg/archive/refs/tags/v$OPJ_VER.tar.gz
  run openjpeg bash -c "cmake -S src/openjpeg-$OPJ_VER -B b-opj ${CM[*]} -DBUILD_CODEC=OFF -DBUILD_TESTING=OFF && cmake --build b-opj -j$J && DESTDIR=$OV cmake --install b-opj"
  fetch https://github.com/mm2/Little-CMS/releases/download/lcms$LCMS_VER/lcms2-$LCMS_VER.tar.gz
  [ -f /usr/share/misc/config.sub ] && cp -f /usr/share/misc/config.sub /usr/share/misc/config.guess src/lcms2-$LCMS_VER/ 2>/dev/null || true
  run lcms2 bash -c "cd src/lcms2-$LCMS_VER && ./configure --host=wasm32-unknown-linux-musl --build=x86_64-pc-linux-gnu --prefix=/usr --disable-shared --enable-static --without-jpeg --without-tiff && make -j$J && make install DESTDIR=$OV"
  ls -la "$OV/usr/lib"
  touch "$OV/.done"
}

# strip debug info only: the name section stays (readable traps), and so does the wali.abi
# custom section the kernel reads the ABI from.
inst() { mkdir -p "$(dirname "$2")"; "$L/llvm-strip" --strip-debug -o "$2" "$1"; }
pack() { (cd "$R/pkg/$1" && tar czf "$R/pkg/$1.pkg.tar.gz" usr); ls -la "$R/pkg/$1.pkg.tar.gz"; find "$R/pkg/$1" -type f | sort | sed "s|$R/pkg/$1||"; }

poppler() {
  deps
  fetch https://poppler.freedesktop.org/poppler-$POPPLER_VER.tar.xz
  local off=()
  for p in Cairo GLIB GTK TIFF NSS3 Gpgmepp Boost Qt5Core Qt6Core CURL GObjectIntrospection Fontconfig; do off+=(-DCMAKE_DISABLE_FIND_PACKAGE_$p=ON); done
  run poppler-cmake cmake -S src/poppler-$POPPLER_VER -B b-poppler "${CM[@]}" "${off[@]}" \
    -DENABLE_UTILS=ON -DENABLE_CPP=OFF -DENABLE_GLIB=OFF -DENABLE_GOBJECT_INTROSPECTION=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF \
    -DENABLE_BOOST=OFF -DENABLE_LIBCURL=OFF -DENABLE_NSS3=OFF -DENABLE_GPGME=OFF -DENABLE_LIBTIFF=OFF -DENABLE_LCMS=ON \
    -DENABLE_DCTDECODER=libjpeg -DENABLE_LIBOPENJPEG=openjpeg2 -DENABLE_ZLIB=ON -DFONT_CONFIGURATION=generic \
    -DBUILD_GTK_TESTS=OFF -DBUILD_QT5_TESTS=OFF -DBUILD_QT6_TESTS=OFF -DBUILD_CPP_TESTS=OFF -DBUILD_MANUAL_TESTS=OFF \
    -DENABLE_GTK_DOC=OFF -DRUN_GPERF_IF_PRESENT=OFF -DTESTDATADIR=/nonexistent
  grep -E 'Building|Use|with ' "$R/poppler-cmake.log" | tail -n 40 || true
  run poppler-build cmake --build b-poppler -j$J
  local d=$R/pkg/poppler-utils
  rm -rf "$d"
  for t in pdftoppm pdfimages pdftotext pdfinfo pdffonts pdfseparate pdfunite pdftohtml pdfattach pdfdetach; do
    [ -f b-poppler/utils/$t ] && inst b-poppler/utils/$t "$d/usr/bin/$t" || echo "poppler: no $t"
  done
  [ -f "$d/usr/bin/pdftoppm" ] || { echo "poppler: pdftoppm missing"; exit 1; }
  # base-14 fonts for documents that do not embed them (ReportLab's Helvetica): URW base35,
  # at the gsfonts file names poppler's generic configuration searches for.
  ( cd "$R/src" && apt-get download fonts-urw-base35 >/dev/null 2>&1 && dpkg-deb -x fonts-urw-base35_*.deb urw )
  local u=$R/src/urw/usr/share/fonts/type1/urw-base35 g=$d/usr/share/fonts/type1/gsfonts
  mkdir -p "$g"
  while read -r old new; do
    [ -f "$u/$new.t1" ] || { echo "font missing: $new"; exit 1; }
    cp -L "$u/$new.t1" "$g/$old.pfb"
  done <<'EOF'
n022003l NimbusMonoPS-Regular
n022004l NimbusMonoPS-Bold
n022024l NimbusMonoPS-BoldItalic
n022023l NimbusMonoPS-Italic
n019003l NimbusSans-Regular
n019004l NimbusSans-Bold
n019024l NimbusSans-BoldItalic
n019023l NimbusSans-Italic
s050000l StandardSymbolsPS
n021004l NimbusRoman-Bold
n021024l NimbusRoman-BoldItalic
n021023l NimbusRoman-Italic
n021003l NimbusRoman-Regular
d050000l D050000L
EOF
  pack poppler-utils
}

mupdf() {
  fetch https://mupdf.com/downloads/archive/mupdf-$MUPDF_VER-source.tar.gz
  # Upstream's own switches: no X11/GL viewers, no curl, fonts embedded as generated C (not
  # objcopy'd ELF), the CJK fallback fonts left out (TOFU_CJK: 20 MB of the binary).
  run mupdf make -C src/mupdf-$MUPDF_VER -j$J build=release OS=Linux shared=no verbose=yes \
    HAVE_X11=no HAVE_GLUT=no HAVE_CURL=no HAVE_OBJCOPY=no HAVE_LEPTONICA=no HAVE_TESSERACT=no \
    CC="$CC" CXX="$CXX" AR="$AR" XCFLAGS="-DTOFU_CJK" tools
  local d=$R/pkg/mupdf-tools
  rm -rf "$d"
  inst src/mupdf-$MUPDF_VER/build/release/mutool "$d/usr/bin/mutool"
  [ -f src/mupdf-$MUPDF_VER/build/release/muraster ] && inst src/mupdf-$MUPDF_VER/build/release/muraster "$d/usr/bin/muraster"
  pack mupdf-tools
}

qpdf() {
  deps
  fetch https://github.com/qpdf/qpdf/releases/download/v$QPDF_VER/qpdf-$QPDF_VER.tar.gz
  run qpdf-cmake cmake -S src/qpdf-$QPDF_VER -B b-qpdf "${CM[@]}" -DBUILD_STATIC_LIBS=ON -DREQUIRE_CRYPTO_NATIVE=ON \
    -DUSE_IMPLICIT_CRYPTO=OFF -DBUILD_DOC=OFF -DINSTALL_MANUAL=OFF -DINSTALL_EXAMPLES=OFF -DMAINTAINER_MODE=OFF
  run qpdf-build cmake --build b-qpdf -j$J --target qpdf zlib-flate fix-qdf
  local d=$R/pkg/qpdf
  rm -rf "$d"
  inst b-qpdf/qpdf/qpdf "$d/usr/bin/qpdf"
  inst b-qpdf/zlib-flate/zlib-flate "$d/usr/bin/zlib-flate"
  [ -f b-qpdf/qpdf/fix-qdf ] && inst b-qpdf/qpdf/fix-qdf "$d/usr/bin/fix-qdf"
  pack qpdf
}

case "$WHAT" in
  deps) deps;;
  poppler) poppler;;
  mupdf) mupdf;;
  qpdf) qpdf;;
  *) echo "unknown component $WHAT" >&2; exit 2;;
esac
