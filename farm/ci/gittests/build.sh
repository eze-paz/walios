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
# libc: the walios env reader (musl-patches/src/env/initenv.c: a NUL-separated environment from
# __get_init_envfile0, so values may contain newlines) swapped into this job's libc.a BEFORE
# anything links -- the sysroot release predates it. Every wasm built below (the test helpers,
# git-sh-i18n--envsubst, iconv, git) imports __get_init_envfile0.
bash "$HERE/../libc-envpatch.sh" "$TC"
GITV=2.45.3 ZV=1.3.1
fetch() { curl -sSfL --retry 8 --retry-all-errors --retry-delay 10 -o "$2" "$1"; }

# zlib (static, into a private prefix)
# (GitHub release first: zlib.net once answered a non-gzip page and the build died in tar)
{ fetch https://github.com/madler/zlib/releases/download/v$ZV/zlib-$ZV.tar.gz z.tgz && gzip -t z.tgz; } \
  || { fetch https://zlib.net/fossils/zlib-$ZV.tar.gz z.tgz && gzip -t z.tgz; }
tar xzf z.tgz
( cd zlib-$ZV && CHOST=wasm32 CC="$CC" AR="$AR" RANLIB="$RANLIB" ./configure --static --prefix="$PWD/../zinst" >/dev/null \
  && make -j"$(nproc)" libz.a >/dev/null && make install >/dev/null )

fetch https://mirrors.edge.kernel.org/pub/software/scm/git/git-$GITV.tar.gz g.tgz && tar xzf g.tgz
cd git-$GITV
MAKEVARS=(
  CC="$CC" AR="$AR" RANLIB="$RANLIB"
  uname_S=Linux uname_M=x86_64 uname_R=6.0 HOST_CPU=x86_64
  NO_CURL=YesPlease NO_OPENSSL=YesPlease NO_GETTEXT=YesPlease NO_EXPAT=YesPlease
  # musl's iconv writes UTF-16/UTF-32 big-endian WITHOUT a byte-order mark (glibc writes one);
  # git adds the BOM itself for working-tree-encoding=UTF-16 files when told (t0028, t2082)
  ICONV_OMITS_BOM=YesPlease
  NO_TCLTK=YesPlease NO_PERL=YesPlease NO_PYTHON=YesPlease NO_GITWEB=YesPlease NO_REGEX=YesPlease
  NO_UNIX_SOCKETS=YesPlease NO_INSTALL_HARDLINKS=YesPlease HAVE_ALLOCA_H=YesPlease
  NO_MMAP= NO_PTHREADS=
  # --export=__stack_pointer / __tls_base: a forked child rewinds on a fresh instance and the
  # kernel hands it the parent's values through these (runtimes/busybox/build.sh, same reason).
  # Without them the child ran on the MAIN thread's TLS: a fork from a thread (git's filters
  # and async helpers run on a pthread) saw pthread_self() as the wrong thread and musl's
  # fork() looped forever walking the thread list.
  ZLIB_PATH="$PWD/../zinst" CFLAGS="-O2 -I$PWD/../zinst/include" LDFLAGS="-L$PWD/../zinst/lib -Wl,--export=__stack_pointer -Wl,--export-if-defined=__tls_base"
  SHELL_PATH=/bin/sh TAR=tar
)
# t/unit-tests/bin/t-basic: t0080 checks the unit-test framework's TAP output against it
make -j"$(nproc)" "${MAKEVARS[@]}" t/helper/test-tool t/helper/test-fake-ssh t/unit-tests/bin/t-basic GIT-BUILD-OPTIONS
# templates/blt: test-lib.sh points GIT_TEMPLATE_DIR there (and bails out without it)
make "${MAKEVARS[@]}" -C templates SHELL_PATH=/bin/sh PERL_PATH=/usr/bin/perl
test -d templates/blt || { echo "!! templates/blt missing"; exit 1; }
for b in t/helper/test-tool t/helper/test-fake-ssh t/unit-tests/bin/t-basic; do
  head -c4 "$b" | od -An -tx1 | grep -qi "00 61 73 6d" || { echo "!! $b is not wasm"; exit 1; }
done
ls -la t/helper/test-tool t/helper/test-fake-ssh t/unit-tests/bin/t-basic
# The package: t/ (minus perf), the helpers in place, GIT-BUILD-OPTIONS, templates dir for
# GIT_TEST_TEMPLATE_DIR. Paths stay relative to the git tree (test-lib.sh expects ../ layout).
# contrib: tests call contrib/workdir/git-new-workdir etc.; Makefile and COPYING: tests use them as
# sample data (t4023's COPYING_test_data cats ../Makefile); mergetools: t7609 sources $GIT_BUILD_DIR/mergetools/vimdiff;
# po/is.po: t0200 checks its xgettext-extracted TRANSLATORS comments ($GIT_PO_PATH = $GIT_BUILD_DIR/po)
tar czf "$OUT/git-tests-$GITV.tar.gz" --exclude='t/perf' t GIT-BUILD-OPTIONS templates contrib Makefile COPYING mergetools po/is.po
# git's scripted commands (git submodule, git-sh-setup, mergetool, ...) for walios's exec path:
# walios shipped only the git binary, so `git submodule` was "not a git command". Installed at
# /usr/libexec/git-core (GIT_EXEC_PATH) by sandpie's walios-backend.js.
SCRIPTS="git-submodule git-sh-setup git-sh-i18n git-mergetool--lib git-merge-octopus git-merge-one-file git-merge-resolve git-mergetool git-quiltimport git-request-pull git-web--browse git-difftool--helper git-filter-branch"
make "${MAKEVARS[@]}" $SCRIPTS git-sh-i18n--envsubst
mkdir -p ../gc/usr/libexec/git-core && cp $SCRIPTS git-sh-i18n--envsubst ../gc/usr/libexec/git-core/ && cp -r mergetools ../gc/usr/libexec/git-core/
# walios's git.wasm was built with prefix=$HOME on the build box: its compiled-in exec-path is
# /home/aezequiel/libexec/git-core. Point that at the real one, so git finds its scripts even
# when GIT_EXEC_PATH is unset (git's own test-lib unsets it; so does env -i).
mkdir -p ../gc/home/aezequiel/libexec && ln -s /usr/libexec/git-core ../gc/home/aezequiel/libexec/git-core
chmod 755 ../gc/usr/libexec/git-core/git-*
head -1 ../gc/usr/libexec/git-core/git-submodule

# Candidate git.wasm with REAL fork() (Asyncify, as farm/ci/asyncify-fork.txt programs): the
# shipped git uses the vfork protocol, whose child branch runs inside the parent until it
# execs -- and git's child sets its die/warn routines before exec, which then stuck in the
# parent ("warn() should not be called in child", t3600). Same tree, rebuilt with the define,
# then wasm-opt --asyncify on SYS_fork. Published as git-asyncfork.wasm for sandpie to A/B.
cd "$OLDPWD" 2>/dev/null || true
cd "$(dirname "$OUT")/work/git-$GITV"
# (libc.a already carries the walios env reader: see the top)
make "${MAKEVARS[@]}" prefix=/usr CFLAGS="-O2 -I$PWD/../zinst/include -D__WALI_ASYNCIFY_FORK" clean-obj >/dev/null 2>&1 || make "${MAKEVARS[@]}" clean >/dev/null 2>&1 || true
# prefix=/usr: its exec-path is /usr/libexec/git-core (where walios installs git-core.tar.gz)
make -j"$(nproc)" "${MAKEVARS[@]}" prefix=/usr CFLAGS="-O2 -I$PWD/../zinst/include -D__WALI_ASYNCIFY_FORK" git
"$TC/binaryen/bin/wasm-opt" --asyncify --pass-arg=asyncify-imports@wali.SYS_fork -O2 git -o "$OUT/git-asyncfork.wasm"
node -e 'const m=new WebAssembly.Module(require("fs").readFileSync(process.argv[1])); const i=WebAssembly.Module.imports(m).map(x=>x.name); console.log("env import:", i.filter(n=>/init_envfile/.test(n)).join(","))' "$OUT/git-asyncfork.wasm"
ls -la "$OUT/git-asyncfork.wasm"
# git's other programs, where a Linux install puts them (git 2.45 `make install`, prefix=/usr):
# scalar and git-shell in /usr/bin (git-shell also in the exec-path), git-http-backend and
# git-daemon in /usr/libexec/git-core. Same tree and flags as git; each forks, so each gets
# the Asyncify pass too. Their own git-extras.tar.gz (~3 MB): sandpie mounts it when git first
# runs, so the boot-time git-core.tar.gz (scripts, iconv) stays small.
EXTRA="scalar git-shell git-http-backend git-daemon"
make -j"$(nproc)" "${MAKEVARS[@]}" prefix=/usr CFLAGS="-O2 -I$PWD/../zinst/include -D__WALI_ASYNCIFY_FORK" $EXTRA
mkdir -p ../gx/usr/bin ../gx/usr/libexec/git-core
for b in $EXTRA; do
  case $b in scalar|git-shell) dst=../gx/usr/bin/$b ;; *) dst=../gx/usr/libexec/git-core/$b ;; esac
  "$TC/binaryen/bin/wasm-opt" --asyncify --pass-arg=asyncify-imports@wali.SYS_fork -O2 "$b" -o "$dst"
  chmod 755 "$dst"; ls -la "$dst"
done
cp ../gx/usr/bin/git-shell ../gx/usr/libexec/git-core/git-shell
tar czf "$OUT/git-extras-$GITV.tar.gz" -C ../gx usr
# iconv(1) (iconv.c, on musl's iconv(3)): Linux has the command, busybox has no applet, and
# git's tests pipe through it (t7102). Ships in git-core.tar.gz at /usr/bin/iconv. Built here,
# after the libc env patch, so it reads the NUL-separated environment like the git above.
mkdir -p ../gc/usr/bin
"$CC" -O2 "$HERE/iconv.c" -o ../gc/usr/bin/iconv
head -c4 ../gc/usr/bin/iconv | od -An -tx1 | grep -qi "00 61 73 6d" || { echo "!! iconv is not wasm"; exit 1; }
chmod 755 ../gc/usr/bin/iconv
tar czf "$OUT/git-core-$GITV.tar.gz" -C ../gc usr home
ls -la "$OUT"
