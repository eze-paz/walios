#!/usr/bin/env bash
# Build the stdlib C extensions python_cxx.wasm loads as side modules (walios-extras.tar.gz):
# zlib, _bz2, _sqlite3, _ssl. Each is a PIC wasm side module with its library linked in
# (zlib, bzip2, SQLite, OpenSSL compiled -fPIC here), importing only python_cxx.wasm's exports.
#
#   ext.sh <build.sh workdir>      -> <workdir>/ext/*.cpython-314-x86_64-linux-gnu.so
#
# Run after build.sh on the same workdir (its LLVM, sysroot, CPython sources, pyconfig.h and
# python_cxx.wasm), with the same WALI_ABI.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(realpath "${1:?usage: ext.sh <build.sh workdir>}")
cd "$R"

PY_VER=3.14.7
ZLIB_VER=1.3.1
BZIP2_VER=1.0.8
SQLITE_YEAR=2025 SQLITE_VER=3500400   # 3.50.4 amalgamation
OPENSSL_VER=3.0.16
L=$R/LLVM-22.1.3-Linux-X64/bin
SYSROOT=$R/sysroot
TGT=wasm32-unknown-linux-muslwali
TF="--target=$TGT"; [ "${WALI_ABI:-wali}" = ilp32 ] && TF="$TF -Xclang -triple -Xclang wasm32-unknown-linux-musl"
SFLAGS="$TF --sysroot=$SYSROOT -nostdlibinc -isystem $SYSROOT/include -D_GNU_SOURCE -O2 -fPIC -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling"
PYINC="-I$R/cross-py -I$R/Python-$PY_VER/Include -I$R/Python-$PY_VER/Include/internal -DPy_BUILD_CORE_MODULE"
mkdir -p ext ext-obj

# What a module may import: python_cxx.wasm's exports. Under WALI_ABI=ilp32 the module also
# carries the wali.abi marker, so the kernel refuses it in a process of the other ABI.
node -e 'const m=new WebAssembly.Module(require("fs").readFileSync(process.argv[1]));
  for (const e of WebAssembly.Module.exports(m)) console.log(e.name)' python_cxx.wasm | sort > ext-obj/python-exports.txt
MARK=""
if [ "${WALI_ABI:-wali}" = ilp32 ]; then
  printf '.section .custom_section.wali.abi,"",@\n.ascii "ilp32"\n' > ext-obj/abi.s
  $L/clang $TF -c ext-obj/abi.s -o ext-obj/abi.o; MARK=ext-obj/abi.o
fi
side() {   # side <name> <objs...>
  local n=$1; shift
  $L/clang $SFLAGS -shared -nostdlib -Wl,--no-entry -Wl,--experimental-pic -Wl,--shared-memory \
    -Wl,--allow-undefined-file=ext-obj/python-exports.txt -o ext/$n.cpython-314-x86_64-linux-gnu.so "$@" $MARK
}
cc() { local o=ext-obj/$1; shift; mkdir -p "$(dirname "$o")"; $L/clang $SFLAGS "$@" -c -o "$o"; }

# ---- sources ----
[ -d zlib-$ZLIB_VER ] || curl -sSfL https://zlib.net/fossils/zlib-$ZLIB_VER.tar.gz | tar xz
[ -d bzip2-$BZIP2_VER ] || curl -sSfL https://sourceware.org/pub/bzip2/bzip2-$BZIP2_VER.tar.gz | tar xz
[ -d sqlite-amalgamation-$SQLITE_VER ] || { curl -sSfLO https://www.sqlite.org/$SQLITE_YEAR/sqlite-amalgamation-$SQLITE_VER.zip && unzip -q sqlite-amalgamation-$SQLITE_VER.zip && rm sqlite-amalgamation-$SQLITE_VER.zip; }
[ -d openssl-$OPENSSL_VER ] || curl -sSfL https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz | tar xz
M=Python-$PY_VER/Modules

# ---- zlib ----
for f in adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr; do
  cc zlib/$f.o -DHAVE_UNISTD_H zlib-$ZLIB_VER/$f.c
done
cc zlib/zlibmodule.o $PYINC -Izlib-$ZLIB_VER $M/zlibmodule.c
side zlib ext-obj/zlib/*.o

# ---- _bz2 ----
for f in blocksort huffman crctable randtable compress decompress bzlib; do
  cc bz2/$f.o -D_FILE_OFFSET_BITS=64 bzip2-$BZIP2_VER/$f.c
done
cc bz2/_bz2module.o $PYINC -Ibzip2-$BZIP2_VER $M/_bz2module.c
side _bz2 ext-obj/bz2/*.o

# ---- _sqlite3 ----
# (no extension loading: a walios process dlopen()s only side modules built for python_cxx)
SQDEF="-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_MATH_FUNCTIONS -DSQLITE_ENABLE_DESERIALIZE"
cc sqlite/sqlite3.o $SQDEF sqlite-amalgamation-$SQLITE_VER/sqlite3.c
for f in blob connection cursor microprotocols module prepare_protocol row statement util; do
  cc sqlite/m_$f.o $PYINC -Isqlite-amalgamation-$SQLITE_VER -I$M/_sqlite -DPY_SQLITE_HAVE_SERIALIZE=1 $M/_sqlite/$f.c
done
side _sqlite3 ext-obj/sqlite/*.o

# ---- _ssl (OpenSSL linked in, PIC) ----
if [ ! -f ossl-pic/libssl.a ]; then
  rm -rf ossl-pic && cp -r openssl-$OPENSSL_VER ossl-pic
  # OpenSSL's Configure takes CC as one word; the flags go in CFLAGS. Same configuration as the
  # sysroot's copy (walios/build/sysroot32/build.sh), plus -fPIC.
  (cd ossl-pic && CC=$L/clang AR=$L/llvm-ar RANLIB=$L/llvm-ranlib CFLAGS="$SFLAGS -U_GNU_SOURCE" ./Configure linux-generic32 \
    no-asm no-shared no-dso no-async no-engine no-afalgeng no-tests no-ui-console no-secure-memory \
    --prefix=/usr --openssldir=/etc/ssl && make -j"$(nproc)" build_libs) >ossl-pic.log 2>&1
fi
cc ssl/_ssl.o $PYINC -Iossl-pic/include -I$M $M/_ssl.c
side _ssl ext-obj/ssl/_ssl.o ossl-pic/libssl.a ossl-pic/libcrypto.a

ls -la ext/
