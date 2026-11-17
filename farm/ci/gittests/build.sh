#!/bin/bash
# git's own test suite for walios: git 2.45.3 (the git walios ships) built with the farm's
# WALI toolchain, only for its test helpers (t/helper/test-tool, test-fake-ssh) and
# GIT-BUILD-OPTIONS. The suite then runs INSIDE walios against walios's own git
# (GIT_TEST_INSTALLED), as a measure of how well the kernel serves git (sandpie
# tests/walios/e2e-git-testsuite.mjs).
#   build.sh <toolchain-dir> <out-dir>
set -euo pipefail
TC=$(realpath -m "$1"); OUT=$(realpath -m "$2")
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$OUT" work && cd work
bash "$HERE/../toolchain.sh" "$TC"
# shellcheck disable=SC1091
source "$TC/env.sh"
GITV=2.45.3 ZV=1.3.1
fetch() { curl -sSfL --retry 8 --retry-all-errors --retry-delay 10 -o "$2" "$1"; }

# zlib (static, into a private prefix)
fetch https://zlib.net/fossils/zlib-$ZV.tar.gz z.tgz && tar xzf z.tgz
( cd zlib-$ZV && CHOST=wasm32 CC="$CC" AR="$AR" RANLIB="$RANLIB" ./configure --static --prefix="$PWD/../zinst" >/dev/null \
  && make -j"$(nproc)" libz.a >/dev/null && make install >/dev/null )

fetch https://mirrors.edge.kernel.org/pub/software/scm/git/git-$GITV.tar.gz g.tgz && tar xzf g.tgz
cd git-$GITV
MAKEVARS=(
  CC="$CC" AR="$AR" RANLIB="$RANLIB"
  uname_S=Linux uname_M=x86_64 uname_R=6.0 HOST_CPU=x86_64
  NO_CURL=YesPlease NO_OPENSSL=YesPlease NO_GETTEXT=YesPlease NO_ICONV=YesPlease NO_EXPAT=YesPlease
  NO_TCLTK=YesPlease NO_PERL=YesPlease NO_PYTHON=YesPlease NO_GITWEB=YesPlease NO_REGEX=YesPlease
  NO_UNIX_SOCKETS=YesPlease NO_INSTALL_HARDLINKS=YesPlease HAVE_ALLOCA_H=YesPlease
  NO_MMAP= NO_PTHREADS=
  ZLIB_PATH="$PWD/../zinst" CFLAGS="-O2 -I$PWD/../zinst/include" LDFLAGS="-L$PWD/../zinst/lib"
  SHELL_PATH=/bin/sh TAR=tar
)
make -j"$(nproc)" "${MAKEVARS[@]}" t/helper/test-tool t/helper/test-fake-ssh GIT-BUILD-OPTIONS
for b in t/helper/test-tool t/helper/test-fake-ssh; do
  head -c4 "$b" | od -An -tx1 | grep -qi "00 61 73 6d" || { echo "!! $b is not wasm"; exit 1; }
done
ls -la t/helper/test-tool t/helper/test-fake-ssh
# The package: t/ (minus perf), the helpers in place, GIT-BUILD-OPTIONS, templates dir for
# GIT_TEST_TEMPLATE_DIR. Paths stay relative to the git tree (test-lib.sh expects ../ layout).
tar czf "$OUT/git-tests-$GITV.tar.gz" --exclude='t/perf' t GIT-BUILD-OPTIONS templates
ls -la "$OUT"
