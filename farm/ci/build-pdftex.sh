#!/bin/bash
# Minimal experiment: pdfTeX only, not the complete Alpine texlive distribution.
# Engine output, not a supported package release: no texmf/font bundle is shipped.
set -euo pipefail
HERE=$PWD
# CI runner logs are not downloadable through the API token used to drive this
# experiment; make failures surface as check-run annotations instead.
mkdir -p "$HERE/artifacts"
exec > >(tee "$HERE/artifacts/build.log") 2>&1
emit_fail() {
  rc=$1
  grep -iaE "error|fatal|cannot find|undefined reference|not found" "$HERE/artifacts/build.log" | grep -viaE "strerror" | tail -n 4 |
    while IFS= read -r l; do printf '::error::build: %s\n' "$l"; done
  for f in $(find "$HERE/texlive-src/build" -name config.log -type f 2>/dev/null | head -2); do
    grep -iaE "error|cannot" "$f" | tail -n 2 |
      while IFS= read -r l; do printf '::error::%s: %s\n' "$f" "$l"; done
  done
  printf '::error::build failed rc=%s (full log in build.log artifact)\n' "$rc"
}
trap 'emit_fail $?' ERR
. "$TC/env.sh"
export CONFIG_SITE="$HERE/farm/ci/config.site"
export FARM_CI_DIR="$HERE/farm/ci"
export CFLAGS=-O2 CXXFLAGS=-O2 LDFLAGS= CPPFLAGS=
export BUILDCC=/usr/bin/gcc CC_FOR_BUILD=/usr/bin/gcc
export BUILDCPPFLAGS= BUILDLDFLAGS=
# TeX's native helper inherits WALI's Wasm linker and otherwise passes
# `-m elf_x86_64` to it. Dispatch only that native target to the system linker;
# every Wasm link still goes through WALI's linker.
mkdir -p "$HERE/bin"
cat > "$HERE/bin/ld-dispatch" <<'EOF'
#!/bin/sh
case "$*" in
  *"-m elf_x86_64"*) exec /usr/bin/ld "$@" ;;
esac
exec "$TC/bin/wali-ld" "$@"
EOF
chmod +x "$HERE/bin/ld-dispatch"
export LD="$HERE/bin/ld-dispatch"
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
  --enable-web2c \
  --enable-pdftex \
  --disable-lua53 \
  --disable-luajit \
  --enable-missing \
  --disable-synctex \
  --disable-xetex \
  --disable-luatex \
  --disable-luajittex \
  --disable-luahbtex
if ! make -j"$(nproc)"; then
  echo '=== Nested native configure logs (failure diagnostics) ==='
  for f in $(find . -path '*/native/config.log' -type f); do
    echo "--- $f ---"
    tail -n 110 "$f"
  done
  exit 1
fi
cd ../..
ENGINE=texlive-src/build/texk/web2c/pdftex
[ -f "$ENGINE" ] || { echo "FATAL: pdftex engine binary missing at $ENGINE"; exit 1; }
cp "$ENGINE" artifacts/pdftex.wasm
node -e 'const b=require("fs").readFileSync(process.argv[1]);const m=new WebAssembly.Module(b);if(b.subarray(0,4).toString("hex")!=="0061736d"||!WebAssembly.Module.exports(m).some(x=>x.name==="_start"))throw Error("not an executable Wasm");console.log({bytes:b.length,start:true});' artifacts/pdftex.wasm
cd /tmp
timeout 120 node "$HERE/host/host.js" "$HERE/artifacts/pdftex.wasm" --version | tee "$HERE/artifacts/smoke.txt"
grep -q pdfTeX "$HERE/artifacts/smoke.txt"
printf 'Built and ran pdfTeX under walios host/host.js; no TeX resource bundle included.\n' > "$HERE/artifacts/STATUS.txt"