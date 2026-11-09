#!/usr/bin/env bash
# OCR for walios, from upstream sources with their own build systems (no source edits):
#   leptonica   image library tesseract reads with (PNG, JPEG, TIFF, zlib; no GIF/WebP/JP2; TIFF
#               is also how leptonica stores its built-in bitmap font: without it every run
#               printed pixReadMemTiff errors),
#               linked statically into tesseract (no separate package: nothing else uses it)
#   tesseract   tesseract 5 CLI, LSTM engine only (the legacy engine is off: the fast models
#               below are LSTM-only), no OpenMP, no curl/libarchive, no training tools
#   tessdata    the tessdata_fast models for spa, cat, eng (+ osd for --psm 0) under
#               /usr/share/tessdata, tesseract's compiled-in default
# Each lands as <workdir>/pkg/<name>.pkg.tar.gz: usr/bin/<program> (wasm) and/or usr/share data,
# mounted at / by `apk add` (kind 'pkg' in the farm index).
#
#   build.sh <workdir> <tesseract|tessdata|deps>
#
# Toolchain: $WALI_TC = a farm toolchain (eze-paz/walios farm/ci/toolchain.sh), as for
# walios/build/pdftools. Runs on GitHub Actions (eze-paz/walios .github/workflows/ocrtools.yml).
set -euo pipefail
R=$(realpath -m "${1:?usage: build.sh <workdir> <component>}")
WHAT=${2:?component: tesseract tessdata deps}
mkdir -p "$R/src" "$R/pkg" && cd "$R"

ZLIB_VER=1.3.1
PNG_VER=1.6.44
JPEG_VER=3.0.4
TIFF_VER=4.7.0
LEPT_VER=1.85.0
TESS_VER=5.5.0
TESSDATA_FAST_REF=4.1.0
LANGS="spa cat eng osd"

fetch() {   # fetch <url> [name] -> unpacked under src/ (once)
  local u=$1 f=src/${2:-$(basename "$1")}
  [ -f "$f" ] || curl -sSfL --retry 8 --retry-all-errors --retry-delay 10 -o "$f" "$u"
  case "$f" in *.tar.*|*.tgz) tar xf "$f" -C src;; esac
}
log() { echo "== $*"; }
run() { local n=$1; shift; log "$n"; if ! "$@" >"$R/$n.log" 2>&1; then echo "FAILED: $n (tail of $R/$n.log)"; tail -n 80 "$R/$n.log"; exit 1; fi; }
pack() { (cd "$R/pkg/$1" && tar czf "$R/pkg/$1.pkg.tar.gz" usr); ls -la "$R/pkg/$1.pkg.tar.gz"; find "$R/pkg/$1" -type f | sort | sed "s|$R/pkg/$1||"; }

tessdata() {   # data only: no toolchain needed
  local d=$R/pkg/tesseract-data
  rm -rf "$d"; mkdir -p "$d/usr/share/tessdata"
  for l in $LANGS; do
    curl -sSfL --retry 8 --retry-all-errors --retry-delay 10 -o "$d/usr/share/tessdata/$l.traineddata" \
      "https://github.com/tesseract-ocr/tessdata_fast/raw/$TESSDATA_FAST_REF/$l.traineddata"
  done
  pack tesseract-data
}

if [ "$WHAT" = tessdata ]; then tessdata; exit 0; fi

: "${WALI_TC:?set WALI_TC to a farm toolchain}"
source "$WALI_TC/env.sh"
L=$WALI_LLVM
J=$(nproc)
OV=$R/overlay
export WALI_OVERLAY=$OV
export PKG_CONFIG_LIBDIR=$OV/usr/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=$OV PKG_CONFIG_PATH=
export CPPFLAGS="-I$OV/usr/include" LDFLAGS="-L$OV/usr/lib"
CM=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_PREFIX_PATH=/usr -DCMAKE_POLICY_VERSION_MINIMUM=3.5)

deps() {
  [ -f "$OV/.done" ] && return 0
  rm -rf "$OV"; mkdir -p "$OV/usr"
  fetch https://github.com/madler/zlib/releases/download/v$ZLIB_VER/zlib-$ZLIB_VER.tar.gz
  run zlib bash -c "cd src/zlib-$ZLIB_VER && ./configure --static --prefix=/usr && make -j$J libz.a && make install DESTDIR=$OV"
  fetch https://github.com/pnggroup/libpng/archive/refs/tags/v$PNG_VER.tar.gz
  run libpng bash -c "cmake -S src/libpng-$PNG_VER -B b-png ${CM[*]} -DPNG_SHARED=OFF -DPNG_STATIC=ON -DPNG_TESTS=OFF -DPNG_TOOLS=OFF -DPNG_EXECUTABLES=OFF -DPNG_HARDWARE_OPTIMIZATIONS=OFF && cmake --build b-png -j$J && DESTDIR=$OV cmake --install b-png"
  fetch https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/$JPEG_VER/libjpeg-turbo-$JPEG_VER.tar.gz
  run libjpeg bash -c "cmake -S src/libjpeg-turbo-$JPEG_VER -B b-jpeg ${CM[*]} -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DWITH_SIMD=OFF -DWITH_TURBOJPEG=OFF && cmake --build b-jpeg -j$J && DESTDIR=$OV cmake --install b-jpeg"
  fetch https://download.osgeo.org/libtiff/tiff-$TIFF_VER.tar.gz
  run libtiff bash -c "cmake -S src/tiff-$TIFF_VER -B b-tiff ${CM[*]} -Dtiff-tools=OFF -Dtiff-tests=OFF -Dtiff-contrib=OFF -Dtiff-docs=OFF -Dcxx=OFF \
    -Dzlib=ON -Djpeg=ON -Dlzma=OFF -Dzstd=OFF -Dwebp=OFF -Djbig=OFF -Dlerc=OFF -Dlibdeflate=OFF -Dpixarlog=ON \
    && cmake --build b-tiff -j$J && DESTDIR=$OV cmake --install b-tiff"
  # libtiff's CMake package names a CMath::CMath target that only its own build defines;
  # leptonica's find_package(TIFF) took that package and failed to generate. Without it,
  # CMake's FindTIFF module finds libtiff.a (its deps come in through the overlay's archives).
  rm -rf "$OV/usr/lib/cmake/tiff"
  # leptonica: the codecs tesseract's inputs need (mutool/pdftoppm render to PNG; scans come as TIFF).
  fetch https://github.com/DanBloomberg/leptonica/releases/download/$LEPT_VER/leptonica-$LEPT_VER.tar.gz
  run leptonica bash -c "cmake -S src/leptonica-$LEPT_VER -B b-lept ${CM[*]} -DSW_BUILD=OFF -DBUILD_PROG=OFF \
    -DENABLE_ZLIB=ON -DENABLE_PNG=ON -DENABLE_JPEG=ON -DENABLE_GIF=OFF -DENABLE_TIFF=ON -DENABLE_WEBP=OFF -DENABLE_OPENJPEG=OFF \
    && cmake --build b-lept -j$J && DESTDIR=$OV cmake --install b-lept"
  ls -la "$OV/usr/lib" "$OV/usr/lib/cmake" || true
  touch "$OV/.done"
}

# strip debug info only: the name section stays (readable traps), and so does the wali.abi
# custom section the kernel reads the ABI from.
inst() { mkdir -p "$(dirname "$2")"; "$L/llvm-strip" --strip-debug -o "$2" "$1"; }

tesseract() {
  deps
  fetch https://github.com/tesseract-ocr/tesseract/archive/refs/tags/$TESS_VER.tar.gz tesseract-$TESS_VER.tar.gz
  # TESSDATA_PREFIX: the CMake build compiles no data directory in (only autotools does), so
  # without it tesseract looked for its models in ./ (ccutil.cpp: <prefix>/tessdata/).
  # 5.5.0 pastes it as a string literal (datadir = TESSDATA_PREFIX "/tessdata/"), so it must be
  # a quoted string; a CMake include sets it (CMake does the quoting, not the shell).
  echo 'add_compile_definitions(TESSDATA_PREFIX="/usr/share")' > "$R/tessdata-prefix.cmake"
  local ld; ld=$(dirname "$(find "$OV/usr/lib" -name 'LeptonicaConfig.cmake' -o -name 'leptonica-config.cmake' | head -n1)")
  run tesseract-cmake cmake -S src/tesseract-$TESS_VER -B b-tess "${CM[@]}" -DLeptonica_DIR="$ld" \
    -DSW_BUILD=OFF -DOPENMP_BUILD=OFF -DGRAPHICS_DISABLED=ON -DDISABLED_LEGACY_ENGINE=ON \
    -DBUILD_TRAINING_TOOLS=OFF -DBUILD_TESTS=OFF -DENABLE_LTO=OFF -DENABLE_NATIVE=OFF \
    -DDISABLE_ARCHIVE=ON -DDISABLE_CURL=ON -DINSTALL_CONFIGS=ON \
    -DCMAKE_PROJECT_INCLUDE="$R/tessdata-prefix.cmake"
  grep -iE 'leptonica|simd|openmp|legacy|curl|archive' "$R/tesseract-cmake.log" | tail -n 30 || true
  run tesseract-build cmake --build b-tess -j$J --target tesseract
  local d=$R/pkg/tesseract
  rm -rf "$d"
  inst b-tess/bin/tesseract "$d/usr/bin/tesseract" 2>/dev/null || inst "$(find b-tess -maxdepth 2 -type f -name tesseract | head -n1)" "$d/usr/bin/tesseract"
  # The config files (-c presets like "tsv", "hocr", "txt") tesseract looks up under tessdata/configs.
  mkdir -p "$d/usr/share/tessdata"
  cp -r src/tesseract-$TESS_VER/tessdata/configs src/tesseract-$TESS_VER/tessdata/tessconfigs "$d/usr/share/tessdata/" 2>/dev/null || true
  pack tesseract
}

case "$WHAT" in
  deps) deps;;
  tesseract) tesseract;;
  *) echo "unknown component $WHAT" >&2; exit 2;;
esac
