#!/bin/sh
# Build jq for the WALI target -> walios/pkgcache/jq.wasm, with regex support.
#
# RUN ON WSL/Linux with the WALI toolchain at ~/wali/build, same as the other build-*-wali
# scripts. Needs liboniguruma for the regex builtins: build-oniguruma-wali.sh produces it,
# and this script will run that first if the library is not already staged.
#
# WHY SHIP IT. jq builds in-browser now (that was the point of the toolchain work: config.site,
# the binutils wrappers, cc -include, the executable-bit fix, oniguruma's ABI). But an
# in-browser build of jq takes ~15 minutes of somebody's session, and the run_walios tool
# description still tells the model "ABSENT: jq ... do jq work in run_python". Shipping the
# binary makes `jq` just work, and the description can stop sending people elsewhere.
#
# The in-browser build stays the interesting capability; this is the convenience, exactly as
# curl and openssl are already shipped rather than built per session.
set -e

W=${WALI_BUILD:-~/wali/build}
JQ_VER=${JQ_VER:-1.7.1}
OUT=${OUT:-$PWD/walios/pkgcache}
WORK=${WORK:-~/jqbuild}
ONIG_STAGE=${ONIG_STAGE:-~/onigbuild/stage/opt/wali}

[ -x "$W/llvm/bin/clang" ] || { echo "no WALI clang at $W/llvm/bin/clang"; exit 1; }

if [ ! -f "$ONIG_STAGE/lib/libonig.a" ]; then
  echo "liboniguruma not staged at $ONIG_STAGE -- run scripts/build-oniguruma-wali.sh first"
  exit 1
fi

CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -L$W/sysroot/lib"
# The same wasm feature set every other guest is built with; a module without these does not
# load in the kernel.
FEAT="-O2 -matomics -mbulk-memory -mexception-handling -fwasm-exceptions -mllvm -wasm-enable-sjlj"
LDF="-Wl,--shared-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608"

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"
curl -sL "https://github.com/jqlang/jq/releases/download/jq-$JQ_VER/jq-$JQ_VER.tar.gz" -o jq.tar.gz
tar xzf jq.tar.gz
cd "jq-$JQ_VER"

# --disable-shared is not cosmetic here. libtool builds its symbol pipe by probing nm, and
# this toolchain has NO llvm-nm at all (9 binaries: clang, clang++, clang-22, ld.lld, lld,
# llvm-ar, llvm-config, llvm-ranlib, wasm-ld). The probe fails, the pipe comes out EMPTY,
# and libtool then evals a pipeline with a hole in it -- "syntax error near unexpected
# token |" -- which is the same failure the in-browser build hit for its own reason (walios
# had no working nm either until bin/nm was wrapped). With shared libraries disabled libtool
# never needs the symbol pipe. Worth the irony: jq builds IN THE BROWSER, where nm works,
# and not on the build box, where nm does not exist at all.
#
# --host, not --build: this IS a cross build (x86 host, wasm target), unlike the in-browser
# one where host==build and configure can run its own test programs.
./configure --host=wasm32-unknown-linux-muslwali \
  CC="$CC $FEAT" \
  AR="$W/llvm/bin/llvm-ar" RANLIB="$W/llvm/bin/llvm-ranlib" \
  CPPFLAGS="-I$ONIG_STAGE/include" \
  LDFLAGS="$LDF -L$ONIG_STAGE/lib" \
  LIBS="-lonig -lclang_rt.builtins" \
  --with-oniguruma="$ONIG_STAGE" \
  --disable-shared --enable-static \
  --disable-maintainer-mode --disable-docs --disable-valgrind \
  >"$WORK/conf.log" 2>&1 || { echo "configure FAILED"; tail -25 "$WORK/conf.log"; exit 1; }

grep -m1 "checking for oniguruma.h" "$WORK/conf.log" || true
grep -m1 "checking for onig_version" "$WORK/conf.log" || true

make -j"$(nproc)" >"$WORK/make.log" 2>&1 || { echo "make FAILED"; grep -iE "error" "$WORK/make.log" | head -20; exit 1; }

BIN=$(find . -name jq -type f -perm -u+x | head -1)
[ -n "$BIN" ] || { echo "no jq binary produced"; exit 1; }
mkdir -p "$OUT"
cp "$BIN" "$OUT/jq.wasm"
echo "wrote $OUT/jq.wasm ($(stat -c%s "$OUT/jq.wasm") bytes)"
echo
echo "Add \"jq\" to walios/pkgcache/index.json packages[] if it is not there, and scp"
echo "jq.wasm to the server's walios/pkgcache/ (gitignored, like every other binary asset)."
