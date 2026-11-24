#!/bin/bash
# Minimal experiment: pdfTeX only, not the complete Alpine texlive distribution.
# Engine output, not a supported package release: no texmf/font bundle is shipped.
set -euo pipefail
HERE=$PWD
. "$TC/env.sh"
export CONFIG_SITE="$HERE/farm/ci/config.site"
export FARM_CI_DIR="$HERE/farm/ci"
export CFLAGS=-O2 CXXFLAGS=-O2 LDFLAGS= CPPFLAGS=
export BUILDCC=/usr/bin/gcc CC_FOR_BUILD=/usr/bin/gcc
export BUILDCPPFLAGS= BUILDLDFLAGS=
COMMIT=562901fe3302de1432fb98adcfd4d10a5e140760
mkdir -p artifacts
if [ ! -f texlive.tar.gz ]; then
  curl -fsSL --retry 5 --retry-delay 10 \
    "https://github.com/TeX-Live/texlive-source/archive/$COMMIT.tar.gz" \
    -o texlive.tar.gz
fi
echo "Downloaded source: $(stat -c '%s bytes' texlive.tar.gz)"
if [ ! -d "texlive-source-$COMMIT" ]; then tar xzf texlive.tar.gz; fi
ln -sfn "texlive-source-$COMMIT" texlive-src
mkdir -p texlive-src/build
cd texlive-src/build
../configure \
  --build=x86_64-pc-linux-gnu \
  --host=wasm32-unknown-linux-musl \
  --prefix=/usr \
  --disable-native-texlive-build \
  --without-x \
  --disable-shared \
  --disable-all-pkgs \
  --enable-pdftex \
  --enable-missing \
  --disable-synctex \
  --disable-xetex \
  --disable-luatex \
  --disable-luajittex \
  --disable-luahbtex
make -j"$(nproc)"
cd ../..
ENGINE=texlive-src/build/texk/web2c/pdftex
[ -f "$ENGINE" ]
cp "$ENGINE" artifacts/pdftex.wasm
node -e 'const b=require("fs").readFileSync(process.argv[1]);const m=new WebAssembly.Module(b);if(b.subarray(0,4).toString("hex")!=="0061736d"||!WebAssembly.Module.exports(m).some(x=>x.name==="_start"))throw Error("not an executable Wasm");console.log({bytes:b.length,start:true});' artifacts/pdftex.wasm
cd /tmp
timeout 120 node "$HERE/host/host.js" "$HERE/artifacts/pdftex.wasm" --version | tee "$HERE/artifacts/smoke.txt"
grep -q pdfTeX "$HERE/artifacts/smoke.txt"
printf 'Built and ran pdfTeX under walios host/host.js; no TeX resource bundle included.\n' > "$HERE/artifacts/STATUS.txt"