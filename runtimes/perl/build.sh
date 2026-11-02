#!/usr/bin/env bash
# Build perl.wasm (Perl 5.44.0 for walios) + perllib.tar.gz from nothing but this directory,
# the network and the walios farm toolchain. Linux (WSL Ubuntu 24.04 works); needs
#   build-essential curl git nodejs
#
#   build.sh [workdir]      -> <workdir>/perl.wasm, <workdir>/perllib.tar.gz
#
# Toolchain: $WALI_TC (an existing farm toolchain dir) or one set up in <workdir>/tc by
# farm/ci/toolchain.sh from github.com/eze-paz/walios (LLVM 22.1.3 + the walios sysroot).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(realpath -m "${1:-$HOME/perl-wali-build}")
mkdir -p "$R" && cd "$R"

PERL_VER=5.44.0            # Alpine edge's perl: the catalog's XS modules are written against it
CROSS_VER=1.6.5            # arsv/perl-cross release that knows $PERL_VER
WALIOS_REF=main            # eze-paz/walios: farm/ci/toolchain.sh

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

# ---- sources ----
[ -d perl-$PERL_VER ] || curl -sSfL https://www.cpan.org/src/5.0/perl-$PERL_VER.tar.gz | tar xz
[ -d perl-cross-$CROSS_VER ] || curl -sSfL https://github.com/arsv/perl-cross/releases/download/$CROSS_VER/perl-cross-$CROSS_VER.tar.gz | tar xz
rm -rf src && cp -r perl-$PERL_VER src && cp -rf perl-cross-$CROSS_VER/* src/
cd src
# perl-cross builds each static XS extension with `make static`, which in this MakeMaker no
# longer depends on pm_to_blib, then touches pm_to_blib as its stamp: List::Util, POSIX,
# File::Spec, Cwd, IO... compiled into perl but their .pm files never reached lib/.
sed -i 's/^\t$(MAKE) -C $(dir $@) PERL_CORE=1 LIBPERL=$(LIBPERL) LINKTYPE=static static$/& pm_to_blib/' Makefile
grep -q 'LINKTYPE=static static pm_to_blib$' Makefile || { echo "perl-cross Makefile patch did not apply" >&2; exit 1; }

# ---- fork: the vfork protocol ----
# The sysroot's fork() is a MACRO (unistd.h): the child branch runs in the parent, against a
# copy of the fd table, until it calls execve/_exit, which longjmp back to the fork site; the
# kernel then starts the child on its own. That is right for system(), qx// and pipe opens:
# each forks and execs inside ONE C function. So:
#  - PerlProc_fork() must expand to fork() at the call site, not call my_fork(): a fork site
#    in a function that returns is a longjmp into a dead frame.
#  - Perl's own fork, and the implicit fork of open($fh, "-|") with no command, return into
#    Perl code with the child still running in the parent: ENOSYS, as python's os.fork.
#  (The same sources build the host miniperl, hence __wali__.)
sed -i '/#  define PerlProc_fork()       my_fork()/a #  ifdef __wali__  /* walios: fork() is a vfork-protocol macro, see walios/build/perl/build.sh */\n#    undef PerlProc_fork\n#    define PerlProc_fork() fork()\n#    define PerlProc_fork_noexec() (errno = ENOSYS, -1)\n#  else\n#    define PerlProc_fork_noexec() PerlProc_fork()\n#  endif' iperlsys.h
sed -i '/^PP_wrapped(pp_fork,/,/^}/ s/childpid = PerlProc_fork();/childpid = PerlProc_fork_noexec();/' pp_sys.c
sed -i '/^Perl_my_popen(pTHX_/,/^}/ s/(pid = PerlProc_fork())/(pid = doexec ? PerlProc_fork() : PerlProc_fork_noexec())/' util.c
sed -i '/^Perl_my_fork(void)/,/^}/ s/^    pid = fork();/#ifdef __wali__\n    errno = ENOSYS; pid = -1;\n#else\n    pid = fork();\n#endif/' util.c
[ "$(grep -c '__wali__' iperlsys.h)" = 1 ] && [ "$(grep -c 'PerlProc_fork_noexec()' pp_sys.c util.c | paste -sd' ')" = "pp_sys.c:2 util.c:1" ] &&
  [ "$(grep -c '__wali__' util.c)" = 2 ] || { echo "fork patches did not apply" >&2; exit 1; }

# ---- dynamic loading: XS modules as wasm side modules ----
# The core extensions stay compiled in (--all-static); -Dusedl adds DynaLoader with
# dl_dlopen.xs, whose dlopen/dlsym reach the kernel's loader through wali_dlfcn.c (the one
# CPython links). An XS module (auto/Foo/Foo.so, PIC, linked against perl-exports.txt)
# imports from perl.wasm:
#  - the perl API and PL_ globals: compiled -fvisibility=default (wasm clang hides
#    everything by default) and exported by --export-dynamic;
#  - libc: every symbol of the sysroot's libc.a that can link into a walios program
#    (../libc-closure.js), pulled in with -u and exported by name, so a module never finds
#    a libc function missing just because perl itself did not call it.
"$WALI_LLVM/clang" ${WALI_TARGET:---target=wasm32-unknown-linux-muslwali} --sysroot="$WALI_SYSROOT" -O2 -matomics -mbulk-memory \
  -c "$HERE/../cpython/wali_dlfcn.c" -o "$R/wali_dlfcn.o"
node "$HERE/../libc-closure.js" "$NM" "$WALI_SYSROOT/lib/libc.a" > "$R/libc-ok.txt" 2>"$R/libc-closure.log"
{ sed 's/^/-u /' "$R/libc-ok.txt"; sed 's/^/--export-if-defined=/' "$R/libc-ok.txt"; printf -- '--export=%s\n' dlopen dlsym dlerror dlclose; } > "$R/libc-link.rsp"
# (through the wrapper's WALI_EXTRA_LDFLAGS: it drops --export-dynamic from command lines)
export WALI_EXTRA_LDFLAGS="-Wl,--export-dynamic -Wl,@$R/libc-link.rsp $R/wali_dlfcn.o"

# ---- configure ----
NOLRINT="-fno-builtin-lrint -fno-builtin-lrintf -fno-builtin-lrintl -fno-builtin-lround -fno-builtin-lroundf -fno-builtin-lroundl"
INT64=""
# The walios ILP32 ABI (WALI_ABI=ilp32: 32-bit long) needs no lrint workaround, and keeps
# Perl's integers 64-bit the way 32-bit Debian does (IV = long long).
[ "${WALI_ABI:-wali}" = ilp32 ] && { NOLRINT=""; INT64=-Duse64bitint; }
# The farm toolchain links `gcc`/`cc` to the wasm compiler, so the host (miniperl) side gets
# the real ones by full path.
./configure --target=wasm32-unknown-linux-musl --target-tools-prefix=wasm32- \
  --with-cc=wali-cc --with-ranlib="$RANLIB" --with-readelf="$HERE/wasm-readelf" --with-objdump=true \
  --host-cc=/usr/bin/gcc --host-cpp="/usr/bin/gcc -E" --host-ranlib=/usr/bin/ranlib \
  --prefix=/usr --all-static -Dusedl $INT64 -Uusethreads -Dinc_version_list=none -Dbyteorder=1234 \
  -Dman1dir=none -Dman3dir=none -Dldflags="-Wl,--allow-multiple-definition --no-wasm-opt" \
  -Accflags="-fwrapv -fno-strict-aliasing -fvisibility=default $NOLRINT" \
  -Dd_perl_lc_all_uses_name_value_pairs=undef -Dd_perl_lc_all_separator=define -Dperl_lc_all_separator='";"' \
  -Dd_perl_lc_all_category_positions_init=define -Dperl_lc_all_category_positions_init='{ 0, 1, 2, 3, 4, 5 }' \
  >../cfg.log 2>&1
# The LC_ALL answers are what Configure measures on musl (Alpine's config.sh): a mixed
#  locale reads "C.UTF-8;C;C;C;C;C", positional in category order. perl-cross cannot run the
#  probe and assumes glibc's name=value form -> "panic: ... needs an '=' to split" at startup.
# -fwrapv -fno-strict-aliasing: what perl's own Configure always adds; perl-cross does only
#  for a compiler it recognises as gcc. Without them clang -O2 breaks the stash backrefs:
#  deleting a sub from any package -> "panic: del_backref", so `use warnings` died.
# -fno-builtin-l{rint,round}* (WALI's ABI only): LLVM's wasm32 backend lowers them to
#  libcalls returning i32, but long is 64-bit on muslwali; libc's lrint returns i64 and the module fails to compile
#  (XS_POSIX_fpclassify, the POSIX::lrint/lround xsub).
# --allow-multiple-definition: a static re.a defines 7 regcomp helpers libperl.a has too
#  (re_top.h renames the rest); libperl's copies come first on the link line and win.
# --no-wasm-opt: clang otherwise runs whatever wasm-opt is on PATH after the link (Ubuntu's
#  binaryen 108 here, nothing on the farm runners); the output must not depend on that.

# ---- build ----
make -j"$(nproc)" >../build.log 2>&1
"$WALI_LLVM/llvm-strip" --strip-debug -o ../perl.wasm perl
# What an XS module may import: perl.wasm's exports (functions + data addresses).
node -e 'const m=new WebAssembly.Module(require("fs").readFileSync(process.argv[1]));
  for (const e of WebAssembly.Module.exports(m)) console.log(e.name)' ../perl.wasm | sort > ../perl-exports.txt
for s in Perl_newXS_deffile Perl_croak PL_sv_immortals boot_DynaLoader dlopen strtod snprintf malloc; do
  grep -qx $s ../perl-exports.txt || { echo "perl.wasm does not export $s" >&2; exit 1; }
done

# ---- library: perllib.tar.gz, unpacked at /usr/lib/perl5 (privlib = /usr/lib/perl5/5.44.0) ----
# Documentation (.pod, but perldiag.pod: `use diagnostics` reads it), the static XS archives
# (already inside perl.wasm) and the C headers (CORE/, only a cross build of an XS module
# needs them) stay out.
rm -rf ../stage && make install DESTDIR="$R/stage" >../install.log 2>&1
cd ../stage/usr/lib/perl5
find . \( \( -name '*.pod' ! -name perldiag.pod \) -o -name '*.a' -o -name '.packlist' \) -delete
# The headers (and Config) a cross build of an XS module compiles against: perl-core.tar.gz.
tar czf "$R/perl-core.tar.gz" --owner=0 --group=0 $PERL_VER/wasm32-linux/CORE $PERL_VER/wasm32-linux/Config.pm $PERL_VER/wasm32-linux/Config_heavy.pl
rm -rf $PERL_VER/wasm32-linux/CORE
for m in strict.pm wasm32-linux/DynaLoader.pm File/Basename.pm wasm32-linux/File/Spec.pm wasm32-linux/List/Util.pm wasm32-linux/POSIX.pm wasm32-linux/Config.pm unicore/Name.pm; do
  [ -f $PERL_VER/$m ] || { echo "perllib: $m missing" >&2; exit 1; }
done
tar czf "$R/perllib.tar.gz" --owner=0 --group=0 $PERL_VER
echo "built $R/perl.wasm ($(stat -c %s "$R/perl.wasm") bytes), $R/perllib.tar.gz ($(stat -c %s "$R/perllib.tar.gz") bytes)"
