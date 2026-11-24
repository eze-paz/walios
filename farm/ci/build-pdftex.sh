#!/bin/bash
# pdfTeX for walios: engine build + a minimal, self-contained LaTeX bundle.
# The wasm engine itself builds latex.fmt and compiles a real hello.tex, so the
# artifact is typesetting-capable, not just a --version smoke.
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
  for f in "$HERE"/artifacts/hello/*.log; do
    [ -f "$f" ] && tail -n 25 "$f" | while IFS= read -r l; do printf '::error::latex: %s\n' "$l"; done
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
  --disable-luajithbtex \
  --disable-tex4htk \
  --disable-hitex \
  --disable-mflua \
  --disable-mfluajit \
  --disable-synctex \
  --disable-xetex \
  --disable-luatex \
  --disable-luajittex \
  --disable-luahbtex
make_rc=0
make -j"$(nproc)" || make_rc=$?
if [ "$make_rc" -ne 0 ]; then
  # An unrelated engine or utility may have failed; pdftex itself may be fine.
  echo "make failed rc=$make_rc; continuing if the pdftex engine binary exists"
fi
cd ../..
ENGINE=texlive-src/build/texk/web2c/pdftex
[ -f "$ENGINE" ] || { echo "FATAL: pdftex engine binary missing at $ENGINE"; exit 1; }
cp "$ENGINE" artifacts/pdftex.wasm
node -e 'const b=require("fs").readFileSync(process.argv[1]);const m=new WebAssembly.Module(b);if(b.subarray(0,4).toString("hex")!=="0061736d"||!WebAssembly.Module.exports(m).some(x=>x.name==="_start"))throw Error("not an executable Wasm");console.log({bytes:b.length,start:true});' artifacts/pdftex.wasm
cd /tmp
timeout 120 node "$HERE/host/host.js" "$HERE/artifacts/pdftex.wasm" --version | tee "$HERE/artifacts/smoke.txt"
grep -q pdfTeX "$HERE/artifacts/smoke.txt"
printf 'Engine built and ran under walios host/host.js.\n' > "$HERE/artifacts/STATUS.txt"

# ---------- Stage 2: a typesetting-capable LaTeX bundle ----------
# The runner's apt texlive (texlive-latex-base + texlive-fonts-recommended)
# provides the texmf tree; the wasm engine builds latex.fmt from it and
# compiles a real document. Bundle: pruned texmf + texmf.cnf + latex.fmt.
TEXMF_SRC=/usr/share/texlive/texmf-dist
[ -d "$TEXMF_SRC/tex/latex/base" ] || { printf '::error::no texmf tree at %s (workflow must apt-install texlive-latex-base)\n' "$TEXMF_SRC"; exit 1; }
echo "=== building latex.fmt with the wasm engine ==="
cd "$HERE/artifacts"
rm -f latex.fmt latex.log
cp pdftex.wasm pdftex   # kpathsea resolves the engine name in cwd
# host.js does not forward the shell environment, so TEXMFCNF=... never
# reaches kpathsea; a ./texmf.cnf is found automatically (cwd is searched
# first) and points the engine at the runner's apt texlive tree.
cat > texmf.cnf <<'CNF'
TEXMF = /usr/share/texlive/texmf-dist
TEXFORMATS = .;$TEXMF/web2c//
TEXINPUTS = .;$TEXMF/tex/{latex,generic,plain}//
TEXINPUTS.latex = .;$TEXMF/tex/{latex,generic,plain}//
TEXINPUTS.pdflatex = .;$TEXMF/tex/{latex,generic,plain}//
TFMFONTS = .;$TEXMF/fonts/tfm//
T1FONTS = .;$TEXMF/fonts/type1//
TEXFONTMAPS = .;$TEXMF/fonts/map//
main_memory = 12000000
font_mem_size = 15000000
pool_size = 12500000
max_strings = 550000
hash_extra = 1000000
buf_size = 200000
save_size = 80000
param_size = 10000
expand_depth = 10000
CNF
env TEXMFCNF="$TEXMF_SRC/web2c" TEXMF="$TEXMF_SRC" \
  timeout 1200 node "$HERE/host/host.js" ./pdftex \
  -ini -etex -progname=latex -jobname=latex '*latex.ini' < /dev/null || true
[ -f latex.fmt ] || { printf '::error::latex.fmt was not dumped (see latex.log)\n'; tail -n 40 latex.log; exit 1; }
ls -la latex.fmt
echo "=== compiling hello.tex with the wasm engine ==="
rm -rf hello; mkdir hello; cd hello
cp ../pdftex ../texmf.cnf .   # engine + cnf must resolve in THIS cwd
cat > hello.tex <<'EOF'
\documentclass{article}
\begin{document}
Hello from pdfTeX compiled to WebAssembly, running inside walios.
Einstein: $E = mc^2$, a square root: $\sqrt{2} \approx 1.41$.
\end{document}
EOF
env TEXMFCNF="$TEXMF_SRC/web2c" TEXMF="$TEXMF_SRC" \
  timeout 1200 node "$HERE/host/host.js" ./pdftex \
  -progname=latex -fmt="$HERE/artifacts/latex.fmt" -output-format=pdf -interaction=nonstopmode hello.tex < /dev/null || true
[ -f hello.pdf ] || { printf '::error::hello.pdf was not produced (hello.log)\n'; tail -n 40 hello.log; exit 1; }
head -c 5 hello.pdf | grep -q '%PDF'
echo "hello.pdf: $(stat -c '%s bytes') — wasm LaTeX typesetting works"
printf 'Engine + latex.fmt + hello.tex all OK under walios host.js.\n' > "$HERE/artifacts/STATUS.txt"

echo "=== pruning and packing the bundle ==="
cd "$HERE/artifacts"
rm -rf bundle; mkdir -p bundle
cp -a "$TEXMF_SRC/tex"  bundle/tex
mkdir -p bundle/fonts bundle/bibtex bundle/web2c
cp -a "$TEXMF_SRC/fonts/tfm"   bundle/fonts/tfm
cp -a "$TEXMF_SRC/fonts/type1" bundle/fonts/type1
cp -a "$TEXMF_SRC/fonts/map"   bundle/fonts/map
cp -a "$TEXMF_SRC/fonts/enc"   bundle/fonts/enc
cp -a "$TEXMF_SRC/fonts/vf"    bundle/fonts/vf
cp -a "$TEXMF_SRC/bibtex"      bundle/bibtex
cp latex.fmt bundle/web2c/latex.fmt
# The generated pdftex font map lives in the runner's TEXMFVAR after apt
# triggers ran updmap-sys; without it pdftex would try mktexpk and fail.
MAPSRC=$(find /var/lib/texmf /etc/texmf "$TEXMF_SRC" -name pdftex.map -type f 2>/dev/null | head -1)
[ -n "$MAPSRC" ] && { mkdir -p bundle/fonts/map/pdftex/updmap; cp "$MAPSRC" bundle/fonts/map/pdftex/updmap/pdftex.map; } || echo "NOTE: no pdftex.map found"
cat > bundle/web2c/texmf.cnf <<'EOF'
% Minimal self-contained walios texmf tree (installed under /usr/share/texmf).
TEXMF = /usr/share/texmf
TEXMFCNF = /usr/share/texmf/web2c
TEXFORMATS = .;$TEXMF/web2c//
TEXINPUTS.tex = .;$TEXMF/tex/{generic,plain}//
TEXINPUTS.latex = .;$TEXMF/tex/{latex,generic,plain}//
TEXINPUTS.pdflatex = .;$TEXMF/tex/{latex,generic,plain}//
TEXINPUTS = .;$TEXMF/tex/{latex,generic,plain}//
TEXFONTS = .;$TEXMF/fonts/tfm//
TFMFONTS = .;$TEXMF/fonts/tfm//
T1FONTS = .;$TEXMF/fonts/type1//
TTFONTS = .;$TEXMF/fonts/truetype//
VFFONTS = .;$TEXMF/fonts/vf//
ENCFONTS = .;$TEXMF/fonts/enc//
TEXFONTMAPS = .;$TEXMF/fonts/map/{pdftex,dvips,}//
TEXPSHEADERS = .;$TEXMF/fonts/{type1,truetype}//
TEXPOOL = .;$TEXMF/web2c
MFBASES = .;$TEXMF/web2c
MPPOOL = .;$TEXMF/web2c
SYSTEXMF = $TEXMF
OSFONTDIR =
main_memory = 12000000
extra_mem_top = 10000000
extra_mem_bot = 40000000
font_mem_size = 15000000
pool_size = 12500000
string_vacancies = 180000
max_strings = 550000
hash_extra = 1000000
buf_size = 200000
save_size = 80000
param_size = 10000
expand_depth = 10000
EOF
mkdir -p bundle/bin
cat > bundle/bin/latex <<'EOF'
#!/bin/sh
export TEXMFCNF=/usr/share/texmf/web2c
exec /bin/pdftex -progname=latex -fmt=latex -output-format=pdf "$@"
EOF
cat > bundle/bin/pdflatex <<'EOF'
#!/bin/sh
export TEXMFCNF=/usr/share/texmf/web2c
exec /bin/pdftex -progname=pdflatex -fmt=latex "$@"
EOF
chmod +x bundle/bin/latex bundle/bin/pdflatex
cat > bundle/install-tex.sh <<'EOF'
#!/bin/sh
# install-tex.sh — run INSIDE walios with the bundle tar.gz path as $1.
# Installs /usr/share/texmf (tree + fmt + texmf.cnf), /bin/pdftex (wasm engine)
# and the latex/pdflatex wrappers, then smoke-compiles a document.
set -e
SRC=${1:?usage: install-tex.sh <texlive-minimal.tar.gz>}
tar -xzf "$SRC" -C /usr/share
cp /usr/share/texmf/engine/pdftex.wasm /bin/pdftex
cp /usr/share/texmf/bin/latex /usr/bin/latex
cp /usr/share/texmf/bin/pdflatex /usr/bin/pdflatex
cd "$TMPDIR"
printf '\\documentclass{article}\\begin{document}walios LaTeX OK.\\end{document}\n' > smoke.tex
/usr/bin/latex -interaction=nonstopmode smoke.tex < /dev/null > smoke.out 2>&1 || { tail -n 20 smoke.log; exit 1; }
grep -q '%PDF' smoke.pdf && echo "pdftex+latex installed and verified in walios"
EOF
chmod +x bundle/install-tex.sh
mkdir -p bundle/engine; cp pdftex.wasm bundle/engine/pdftex.wasm
tar czf texlive-minimal.tar.gz -C bundle .
echo "bundle: $(du -sh bundle | cut -f1), tar.gz $(stat -c '%s' texlive-minimal.tar.gz) bytes"
printf 'Bundle stage complete (see artifacts/texlive-minimal.tar.gz).\n' >> "$HERE/artifacts/STATUS.txt"
