#!/bin/sh
# Build liboniguruma for the WALI target and package it as walios/onig-wali.tar.gz.
#
# RUN ON WSL/Linux with the WALI toolchain at ~/wali/build (llvm + sysroot), same as
# build-busybox-wali.sh. Produces opt/wali/{lib/libonig.a,include/oniguruma.h,
# include/onigposix.h}, which walios-backend.js mounts at "/" for clang. `cc` already
# carries -I/opt/wali/include -L/opt/wali/lib, so `-lonig` works with no driver change.
#
# WHY THE OS SHIPS THIS AT ALL
# ----------------------------
# oniguruma cannot select its own integer types on WALI. Both st.h and regint.h do:
#
#     #if   SIZEOF_VOIDP == SIZEOF_LONG
#     typedef unsigned long      st_data_t;     /* and hash_data_type, in regint.h */
#     #elif SIZEOF_VOIDP == SIZEOF_LONG_LONG
#     typedef unsigned long long st_data_t;
#     #endif                                    <- NOTE: no #else, and no error
#
# i.e. "the pointer-sized integer is long, or else long long". WALI is neither: it is
# 32-bit pointers with a 64-bit long (measured: SIZEOF_VOIDP 4, SIZEOF_LONG 8,
# SIZEOF_LONG_LONG 8), because WALI mirrors the x86-64 Linux syscall ABI -- struct stat is
# 144 bytes here, and time_t/off_t are 8. Only the exact triple
# wasm32-unknown-linux-muslwali does this; every other wasm32 triple gives long=4.
#
# So NEITHER branch fires, nothing is typedef'd, and because there is no #else it fails
# far away with a wall of "unknown type name 'st_data_t'" / "'hash_data_type'". jq's
# vendored copy died exactly there, which is what made jq look unbuildable in the browser.
#
# NO SOURCE PATCH IS NEEDED. The type these headers are reaching for is simply uintptr_t,
# and since neither branch fires there is no typedef to collide with -- so supplying it as
# a macro is enough, and it is correct by construction rather than by luck:
#
#     CPPFLAGS="-include stdint.h -Dst_data_t=uintptr_t -Dhash_data_type=uintptr_t"
#
# Upstream master has since fixed this properly (its first branch is
# SIZEOF_VOIDP == SIZEOF_INTPTR_T -> typedef intptr_t st_data_t), but it is NOT in any
# release: v6.9.8, v6.9.9 and v6.9.10 all still lack it. Building master instead would
# need autoreconf, which the WALI box does not have. When a release carries the fix, drop
# the two -D flags and this becomes a stock build.
#
# The -Wno flags are the same set build-busybox-wali.sh needs: clang 22 promotes several
# long-standing C constructs (implicit int conversions, incompatible pointer types) from
# warnings to errors, and oniguruma predates that.
#
# VERIFIED (browser, via walios' own cc + the mounted tarball): a program linking -lonig
# compiles, links and RUNS, with correct captures --
#     a(.*)c   on xxabbbcyy -> match_at=2 group1=[3,6)   ("bbb")
#     (foo|bar)+ on zzbarfoo -> match_at=2 group1=[5,8)   ("foo")
#     ^[0-9]+$ on 12345     -> match_at=0
#     no_match_here on abc  -> -1
# That run matters: -Dst_data_t=uintptr_t changes the width of the hash-table key type
# (4 bytes here, 8 on a normal LP64 build), so it had to be exercised, not assumed.
set -e

W=${WALI_BUILD:-~/wali/build}
VER=${ONIG_VERSION:-6.9.10}
OUT=${OUT:-$PWD/walios/onig-wali.tar.gz}
WORK=${WORK:-~/onigbuild}

[ -x "$W/llvm/bin/clang" ] || { echo "no WALI clang at $W/llvm/bin/clang"; exit 1; }
[ -d "$W/sysroot" ]        || { echo "no WALI sysroot at $W/sysroot"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"
curl -sL "https://github.com/kkos/oniguruma/releases/download/v$VER/onig-$VER.tar.gz" -o o.tgz
tar xzf o.tgz
cd "onig-$VER"

CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -L$W/sysroot/lib"

# LIBS uses the -l form on purpose. Handing libtool a bare path to libclang_rt.builtins.a
# makes it treat the archive as a CONVENIENCE library and absorb its members into
# libonig.a -- the result carried a non-wasm member and wasm-ld warned on every link.
./configure --host=wasm32-unknown-linux-muslwali \
  CC="$CC" AR="$W/llvm/bin/llvm-ar" RANLIB="$W/llvm/bin/llvm-ranlib" \
  CFLAGS="-O2 -Wno-incompatible-pointer-types -Wno-int-conversion -Wno-implicit-function-declaration" \
  CPPFLAGS="-include stdint.h -Dst_data_t=uintptr_t -Dhash_data_type=uintptr_t" \
  LIBS="-lclang_rt.builtins" \
  --disable-shared --enable-static --prefix=/opt/wali >"$WORK/conf.log" 2>&1 \
  || { echo "configure FAILED"; tail -20 "$WORK/conf.log"; exit 1; }

echo "sizes configure measured (the whole reason this script exists):"
grep -E "^#define SIZEOF_(VOIDP|LONG|LONG_LONG|INT) " src/config.h | sed 's/^/  /'

make -j"$(nproc)" >"$WORK/make.log" 2>&1 \
  || { echo "make FAILED"; grep -i error "$WORK/make.log" | head -20; exit 1; }

# The archive must contain ONLY wasm objects.
if "$W/llvm/bin/llvm-ar" t src/.libs/libonig.a | grep -q builtins; then
  echo "REFUSING: libclang_rt.builtins.a was absorbed into libonig.a"; exit 1
fi

# Prove it links before shipping it. There is no llvm-nm in this toolchain (9 tools only),
# so a link against the real API is the check that actually discriminates.
cat > "$WORK/ot.c" <<'CEOF'
#include <oniguruma.h>
int main(void){
  regex_t *reg; OnigErrorInfo e; OnigRegion *r; UChar *p=(UChar*)"a(.*)c";
  if (onig_new(&reg,p,p+6,ONIG_OPTION_DEFAULT,ONIG_ENCODING_UTF8,ONIG_SYNTAX_DEFAULT,&e)) return 1;
  r = onig_region_new(); onig_region_free(r,1); onig_free(reg); onig_end();
  return 0;
}
CEOF
$CC -I src "$WORK/ot.c" src/.libs/libonig.a -lclang_rt.builtins -o "$WORK/ot.wasm" \
  || { echo "link test FAILED"; exit 1; }

rm -rf "$WORK/stage"
mkdir -p "$WORK/stage/opt/wali/lib" "$WORK/stage/opt/wali/include"
cp src/.libs/libonig.a "$WORK/stage/opt/wali/lib/"
cp src/oniguruma.h src/onigposix.h "$WORK/stage/opt/wali/include/"
mkdir -p "$(dirname "$OUT")"
( cd "$WORK/stage" && tar czf "$OUT" opt )

echo "wrote $OUT ($(stat -c%s "$OUT") bytes)"
echo "  libonig.a $(stat -c%s src/.libs/libonig.a) bytes, $("$W/llvm/bin/llvm-ar" t src/.libs/libonig.a | wc -l) members"
echo "Deploy: scp it to the server's walios/ (gitignored there, like every other binary asset)."
