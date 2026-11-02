#!/usr/bin/env bash
# Build lua.wasm (Lua 5.4 for walios) that loads C modules: `require "cjson"` dlopen()s
# /usr/lib/lua/5.4/cjson.so, a PIC wasm side module linked against lua.wasm's exports
# (lua-exports.txt, written here). Linux (WSL Ubuntu 24.04 works); needs curl git nodejs.
#
#   build.sh [workdir]   -> <workdir>/lua.wasm, <workdir>/lua-exports.txt, <workdir>/cjson.so
#
# Toolchain: $WALI_TC (an existing farm toolchain dir) or one set up in <workdir>/tc by
# farm/ci/toolchain.sh from github.com/eze-paz/walios (LLVM 22.1.3 + the walios sysroot).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(realpath -m "${1:-$HOME/lua-wali-build}")
mkdir -p "$R" && cd "$R"

LUA_VER=5.4.8
CJSON_VER=2.1.0.14         # openresty/lua-cjson: Alpine's lua-cjson
WALIOS_REF=main

# ---- toolchain ----
if [ -z "${WALI_TC:-}" ]; then
  if [ ! -d walios-farm ]; then
    git clone -q --depth 1 --branch $WALIOS_REF --filter=blob:none --sparse https://github.com/eze-paz/walios.git walios-farm
    git -C walios-farm sparse-checkout set farm/ci
  fi
  bash walios-farm/farm/ci/toolchain.sh "$R/tc" >tc.log 2>&1
  WALI_TC=$R/tc
fi
source "$WALI_TC/env.sh"
L=$WALI_LLVM

# ---- sources ----
[ -d lua-$LUA_VER ] || curl -sSfL https://www.lua.org/ftp/lua-$LUA_VER.tar.gz | tar xz
[ -d lua-cjson-$CJSON_VER ] || curl -sSfL https://github.com/openresty/lua-cjson/archive/refs/tags/$CJSON_VER.tar.gz | tar xz

# ---- lua.wasm ----
# Modules live where Alpine puts them (/usr/share/lua/5.4, /usr/lib/lua/5.4), not /usr/local.
rm -rf src && cp -r lua-$LUA_VER/src src && cd src
sed -i 's|^#define LUA_ROOT\t"/usr/local/"|#define LUA_ROOT\t"/usr/"|' luaconf.h
grep -q '^#define LUA_ROOT.*"/usr/"' luaconf.h || { echo "luaconf.h LUA_ROOT patch did not apply" >&2; exit 1; }
# dlopen/dlsym: the sysroot's musl has only stubs; the kernel's loader is reached through
# wali_dlfcn.c (the one CPython links).
"$CC" -O2 -c "$HERE/../cpython/wali_dlfcn.c" -o wali_dlfcn.o
# What a C module may import from lua.wasm:
#  - the Lua API: compiled -fvisibility=default (wasm clang hides everything by default) and
#    exported by --export-dynamic, passed through WALI_EXTRA_LDFLAGS because the toolchain
#    wrapper drops it from the command line;
#  - libc: the sysroot's libc.a is hidden-visibility, so every symbol that can link into a
#    walios program (libc-closure.js) is pulled in with -u and exported by name. A module
#    then never finds a libc function missing just because lua itself did not call it.
node "$HERE/../libc-closure.js" "$NM" "$WALI_SYSROOT/lib/libc.a" > libc-ok.txt 2>../libc-closure.log
{ sed 's/^/-u /' libc-ok.txt; sed 's/^/--export-if-defined=/' libc-ok.txt; printf -- '--export=%s\n' dlopen dlsym dlerror dlclose; } > libc-link.rsp
WALI_EXTRA_LDFLAGS="-Wl,--export-dynamic -Wl,@$PWD/libc-link.rsp" make -j"$(nproc)" CC="$CC" AR="$AR rcu" RANLIB="$RANLIB" \
  MYCFLAGS="-fvisibility=default -DLUA_USE_LINUX -DLUA_COMPAT_5_3" MYLIBS="wali_dlfcn.o" \
  lua >../build.log 2>&1
"$L/llvm-strip" --strip-debug -o ../lua.wasm lua
cd ..
# What a side module may import: lua.wasm's exports (functions + data addresses).
node -e 'const m=new WebAssembly.Module(require("fs").readFileSync(process.argv[1]));
  for (const e of WebAssembly.Module.exports(m)) console.log(e.name)' lua.wasm | sort > lua-exports.txt
for s in lua_pushinteger luaL_checklstring luaL_setfuncs strtod snprintf malloc; do
  grep -qx $s lua-exports.txt || { echo "lua.wasm does not export $s" >&2; exit 1; }
done

# ---- cjson.so: a PIC side module ----
# (\$WALI_TARGET: the toolchain's target flags, for the walios ILP32 ABI too; $WALI_SIDE_OBJ
#  carries that ABI's marker, so the kernel refuses a module built for the other one.)
SIDE=(${WALI_TARGET:---target=wasm32-unknown-linux-muslwali} --sysroot="$WALI_SYSROOT" -nostdlibinc -isystem "$WALI_SYSROOT/include"
      -D_GNU_SOURCE -O2 -fPIC -fvisibility=default -matomics -mbulk-memory -mllvm -wasm-enable-sjlj -fwasm-exceptions -mexception-handling)
rm -rf cjson-obj && mkdir cjson-obj
for f in lua_cjson strbuf fpconv; do   # (dtoa.c/g_fmt.c: the USE_INTERNAL_FPCONV alternative)
  "$L/clang" "${SIDE[@]}" -Isrc -c lua-cjson-$CJSON_VER/$f.c -o cjson-obj/$f.o
done
"$L/clang" "${SIDE[@]}" -shared -nostdlib -Wl,--no-entry -Wl,--experimental-pic -Wl,--shared-memory \
  -Wl,--allow-undefined-file=lua-exports.txt -o cjson.so cjson-obj/*.o ${WALI_SIDE_OBJ:-}
ls -la lua.wasm cjson.so
