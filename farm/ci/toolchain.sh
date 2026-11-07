#!/bin/bash
# WALI cross toolchain for the build farm, from public parts only:
#   - upstream LLVM release binaries (clang, wasm-ld, llvm-ar...), the version walios uses
#   - the walios sysroot (wali-musl libc + openssl + compiler-rt builtins), release pkgs-*
#   - toolchain extras, release toolchain-*: libc++/libc++abi/libunwind for wasm32-wali and
#     the Linux UAPI headers (x86-64 asm layout: WALI is the x86-64 syscall ABI)
# Writes $TC/env.sh, cc/c++/ld wrappers, a meson cross file, a cmake toolchain file and the
# abuild helpers Alpine recipes call (abuild-meson). Idempotent; CI caches $TC.
#   toolchain.sh <dir> [pkgs-tag] [toolchain-tag]
# The default ABI is the walios ILP32 one (runtimes/sysroot32: 32-bit long like every other
# 32-bit Linux, where WALI's wasm32 has a 64-bit one): its sysroot carries libc++ and openssl,
# and clang compiles for wasm32-unknown-linux-musl (long = 32) while still driving the link
# through the WALI target, which has a link step. WALI_ABI=wali builds for WALI's own.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)   # before any cd: the path may be relative
TC=$(realpath -m "${1:?usage: toolchain.sh <dir> [pkgs-tag] [toolchain-tag]}")
TAG=${2:-pkgs-2026-10-31}
XTAG=${3:-toolchain-2026-10-31}
# the ILP32 sysroot (sandpie walios/build/sysroot32, built by the claude/sysroot32-quiet
# workflow): runtimes-ilp32-2026-11-03-9's, position-independent OpenSSL included, plus
#  - _start ends in exit(): stdio is flushed when main returns (piped output was lost)
#  - syscall() answers ENOSYS without printing "Invalid syscall var call" to stdout
#  - -D__WALI_ASYNCIFY_FORK gives musl's real fork() (farm/ci/asyncify-fork.txt)
S32TAG=${WALI_SYSROOT32_TAG:-toolchain-2026-11-04-s}
ABI=${WALI_ABI:-ilp32}
TGT=--target=wasm32-unknown-linux-muslwali
[ "$ABI" = ilp32 ] && TGT="$TGT -Xclang -triple -Xclang wasm32-unknown-linux-musl -fno-pic"
REL=https://github.com/eze-paz/walios/releases/download
LLVM_VER=22.1.3
P=LLVM-$LLVM_VER-Linux-X64
mkdir -p "$TC/bin" && cd "$TC"
# Downloads go to a file with retries, then extract: a reset mid-stream (seen on a runner
# after the cache was evicted) used to kill the job.
# GitHub's release CDN can answer 504 for minutes (R41 lost a job to 6 tries in 30 s).
fetch() { curl -sSfL --retry 12 --retry-all-errors --retry-delay 20 -o "$2" "$1"; }
if [ ! -x $P/bin/clang ]; then
  fetch https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VER/$P.tar.xz llvm.tar.xz
  tar xJf llvm.tar.xz --wildcards "$P/bin/clang" "$P/bin/clang-22" "$P/bin/clang++" "$P/bin/lld" "$P/bin/wasm-ld" \
      "$P/bin/llvm-ar" "$P/bin/llvm-ranlib" "$P/bin/llvm-nm" "$P/bin/llvm-strip" "$P/bin/llvm-objcopy" "$P/lib/clang/*"
  rm -f llvm.tar.xz
fi
# clang's resource dir carries the ARM intrinsic headers for every target; on wasm they only
# #error. Code that probes __has_include(<arm_neon.h>) then takes a NEON path (xxhash 0.8.3 does
# whenever __wasm_simd128__ is set, expecting Emscripten's SIMDe shim). A Linux x86 toolchain has
# no arm_*.h, so neither does this one.
rm -f $P/lib/clang/*/include/arm_*.h
# binaryen: wasm-opt --asyncify for the farm/ci/asyncify-fork.txt programs (132 understands
# wasm exceptions, as runtimes/busybox needs too).
BINARYEN_VER=132
if [ ! -x binaryen/bin/wasm-opt ]; then
  fetch https://github.com/WebAssembly/binaryen/releases/download/version_$BINARYEN_VER/binaryen-version_$BINARYEN_VER-x86_64-linux.tar.gz bn.tgz
  mkdir -p binaryen && tar xzf bn.tgz -C binaryen --strip-components=1 && rm bn.tgz
fi
if [ ! -f sysroot/lib/libc.a ]; then
  mkdir -p sysroot
  if [ "$ABI" = ilp32 ]; then fetch $REL/$S32TAG/wali32-sysroot.tar.gz sr.tgz   # musl, libc++, openssl, builtins
  else fetch $REL/$TAG/wali-sysroot.tar.gz sr.tgz; fi
  tar xzf sr.tgz -C sysroot && rm sr.tgz
fi
if [ ! -f sysroot/lib/libc++.a ]; then
  fetch $REL/$XTAG/wali-libcxx.tar.gz x1.tgz && tar xzf x1.tgz -C sysroot && rm x1.tgz          # include/c++/v1, unwind headers, lib/*.a
fi
if [ ! -f sysroot/include/linux/version.h ]; then
  fetch $REL/$XTAG/wali-linux-headers.tar.gz x2.tgz && tar xzf x2.tgz -C sysroot && rm x2.tgz    # include/{linux,asm,asm-generic,...}
fi
# walios perl.wasm's C headers and Config (sandpie walios/build/perl): what an XS module
# compiles against (build-one.sh points MakeMaker's PERL_INC here).
if [ ! -f perl-core/5.44.0/wasm32-linux/CORE/perl.h ]; then
  mkdir -p perl-core && fetch $REL/$XTAG/perl-core$([ "$ABI" = ilp32 ] && echo 32).tar.gz pc.tgz && tar xzf pc.tgz -C perl-core && rm pc.tgz
fi
# walios python_cxx.wasm's pyconfig.h (CPython 3.14 configured for wasm32-wali): the farm
# workflow puts it into the runner's Python 3.14 so C extensions compile for walios.
[ -f python/pyconfig.h ] || { mkdir -p python && fetch $REL/$XTAG/python-pyconfig$([ "$ABI" = ilp32 ] && echo 32).h python/pyconfig.h; }
# libffi with the WALI port (sandpie walios/build/libffi: calls and closures through the
# kernel): part of the sysroot, like openssl -- Alpine's libffi has an Emscripten-only wasm32.
if [ ! -f sysroot/lib/libffi.a ]; then
  fetch $REL/$XTAG/libffi-wali$([ "$ABI" = ilp32 ] && echo 32).tar.gz ffi.tgz && tar xzf ffi.tgz -C sysroot --strip-components=1 && rm ffi.tgz
fi
L=$TC/$P/bin
S=$TC/sysroot
# C++ exceptions need the wasm EH tag __cpp_exception defined once per program (libc
# defines __c_longjmp, the setjmp one); python_cxx.wasm links the same 3-line object.
if [ ! -f $S/lib/libwali-cppexc.a ]; then
  printf '.globl __cpp_exception
.tagtype __cpp_exception i32
__cpp_exception:
' > $S/lib/cpp_exc.s
  $L/clang $TGT -mexception-handling -c $S/lib/cpp_exc.s -o $S/lib/cpp_exc.o
  $L/llvm-ar rcs $S/lib/libwali-cppexc.a $S/lib/cpp_exc.o
fi
# ILP32: a side module (C module a runtime dlopen()s) carries the same wali.abi marker as a
# program, so the kernel refuses to load it into a process of the other ABI.
SIDEOBJ=""
if [ "$ABI" = ilp32 ]; then
  SIDEOBJ=$S/lib/wali-abi-side.o
  [ -f $SIDEOBJ ] || { printf '.section .custom_section.wali.abi,"",@
.ascii "ilp32"
' > $S/lib/wali-abi-side.s
    $L/clang $TGT -c $S/lib/wali-abi-side.s -o $SIDEOBJ; }
fi
cat > env.sh <<EOF
export WALI_TC=$TC WALI_LLVM=$L WALI_SYSROOT=$S WALI_ABI=$ABI WALI_TARGET="$TGT" WALI_SIDE_OBJ="$SIDEOBJ"
export CC=$TC/bin/wali-cc CXX=$TC/bin/wali-c++ LD=$TC/bin/wali-ld
export AR=$L/llvm-ar RANLIB=$L/llvm-ranlib NM=$L/llvm-nm STRIP=$TC/bin/wali-strip OBJCOPY=$L/llvm-objcopy
export CMAKE_TOOLCHAIN_FILE=$TC/wali.cmake
export PATH=$TC/bin:\$PATH
EOF
# One driver for compile and link. Compile flags = the ones python_cxx.wasm is built with
# (walios/build/cpython/build.sh in sandpie); a link adds the flags every walios guest
# needs: shared+imported memory (the kernel owns it), 8 MB stack (64 KB overflows into
# misleading OOB traps), exported growable table (signal handlers), and libc + builtins.
# Executables are static, so a -shared link (libtool, meson, cmake shared libs) produces a
# static archive under the .so name: wasm-ld reads it by its magic, and dependents link it
# like any -lfoo. $WALI_EXTRA_* let the farm add the overlay of already-built deps, and with
# $WALI_OVERLAY set every overlay archive joins the link: static
# libraries carry no record of their own dependencies (readline needs ncurses' tputs), and
# wasm-ld pulls from each archive exactly the members something needs.
# -fno-builtin-lrint/lround: LLVM's wasm32 backend lowers them as returning i32, but long is
# 64-bit on WALI, so calls disagree with libm's definitions ("function signature mismatch:
# lround") and the module fails to load (found building Perl: walios/build/perl in sandpie).
# PGO flags are dropped: there is no profile runtime (libclang_rt.profile.a) for wasm, so
# Alpine's profile-guided builds (zstd) failed to link and installed half a package. Without
# them the build is the same program, unprofiled.
# -flto is dropped: setjmp/longjmp lowering (-wasm-enable-sjlj) is a compile-time pass, and
# LTO objects reach the linker with it undone ("undefined symbol: longjmp").
# Both that and _MPFR_PREC_FORMAT (below) exist only because of WALI's 64-bit long; the
# ILP32 ABI needs neither.
ABIDEFS="-D_MPFR_PREC_FORMAT=2 -fno-builtin-lrint -fno-builtin-lrintf -fno-builtin-lround -fno-builtin-lroundf -fno-builtin-lrintl -fno-builtin-lroundl"
[ "$ABI" = ilp32 ] && ABIDEFS=""
for d in cc c++; do
  # The C++ runtime archives go on C links too (after everything else): a C program can link a
  # C++ static library, and archives only contribute members something references.
  drv=clang; cxx=""; cxxlibs="-lc++ -lc++abi -lunwind -lwali-cppexc"; cxxdefs=""
  [ $d = c++ ] && { drv=clang++; cxx="-isystem $S/include/c++/v1"; cxxlibs="-lc++ -lc++abi -lunwind -lwali-cppexc"
    # pre-C++17 code still uses std::unary_function/binary_function (removed in C++17).
    # -Wno-c++11-narrowing: GCC only warns on a non-constant narrowing in braces, clang errors,
    # and with 32-bit long more of them narrow (matplotlib: unsigned int -> long).
    cxxdefs="-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION -Wno-c++11-narrowing"; }
  cat > bin/wali-$d <<EOF
#!/bin/bash
link=1 shared=0 out=a.out OPT=-O2
prev=""
for a in "\$@"; do
  case "\$a" in -c|-E|-S|-M|-MM) link=0;; -shared) shared=1;; -O|-O[0-9sgz]*|-Ofast) OPT=;; esac
  [ "\$prev" = -o ] && out="\$a"; prev="\$a"
done
# __STDC_ISO_10646__: gcc on musl/glibc pre-includes stdc-predef.h, which defines it (wchar_t
# holds Unicode code points); clang for wasm does not, and libedit refuses to build without
# it. (Not the whole header: it redefines two clang builtins, a warning under -Werror.)
# _MPFR_PREC_FORMAT=2: MPFR's precision type follows GMP's mp_size_t (long), but a precision
# in bytes must fit size_t, which is 32-bit here (MPFR's own static assertion); int is the
# setting MPFR provides for that. Global, so every program including mpfr.h sees the same ABI.
# -O2 unless the command line has its own -O (CFLAGS carry -O2 as abuild's do, so a recipe that
# rewrites or drops it -- libgcrypt's jitter RNG must be -O0 -- is obeyed).
# -msimd128: the baseline vector unit, as SSE2 is on x86-64 (every engine with JSPI or COI has it).
# XSIMD_WITH_EMULATED=1: xsimd only takes its wasm backend under Emscripten, and with no
# architecture it declares no API at all (pandas' scalar kernels use it); this is its own
# switch for the portable one.
F=($TGT --sysroot=$S -nostdlibinc $cxx -isystem $S/include -D_GNU_SOURCE -DXSIMD_WITH_EMULATED=1
   -D__STDC_ISO_10646__=201206L \$OPT -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -msimd128 -pthread
   -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types
   -Wno-incompatible-function-pointer-types -Wno-unused-command-line-argument -Wno-ignored-optimization-argument
   -Wno-unknown-warning-option -Wno-long-long -Wno-macro-redefined $cxxdefs $ABIDEFS
   \${WALI_EXTRA_CFLAGS:-})
# \$WALI_LATE_CFLAGS go after the package's own flags: the overlay's include dir must not shadow
# a package's bundled headers of the same name (git's, util-linux's, cmake's own copies).
LATE=(\${WALI_LATE_CFLAGS:-})
# \$WALI_SIDE = a runtime's export list (lua-exports.txt, perl-exports.txt): the package is a
# C module that runtime dlopen()s, so objects are PIC with visible symbols and -shared links
# a wasm side module that may import only what the runtime exports.
# Everything else is PIC too: a library's archive may end up inside a side module (lxml links
# libxml2/libxslt, Pillow libjpeg/libtiff), and wasm-ld links PIC objects into a static
# program as well (GOT entries become internal globals).
F+=(-fPIC); [ -n "\${WALI_SIDE:-}" ] && F+=(-fvisibility=default)
A=(); skip=0
for a in "\$@"; do case "\$a" in
  -rdynamic|-static|-s|-fPIC|-fpic|-fPIE|-fpie|-pie|-flto|-flto=*|-fprofile-generate|-fprofile-generate=*|-fprofile-use|-fprofile-use=*|-fprofile-instr-generate*|-fprofile-instr-use*|-ffat-lto-objects|-fuse-linker-plugin|-fstack-protector*|-fstack-clash-protection|-fcommon) ;;   # -fcommon: wasm objects have no common symbols;   # (host perl Config ldflags in Makefile.PL probes)
  # the build host's headers and libraries (Pillow's setup.py adds /usr/include and /usr/lib):
  # a subdirectory means the overlay's copy (lpeg's -I/usr/include/lua5.4), the rest is dropped
  -I/usr/include/*|-I/usr/local/include/*|-L/usr/lib/*|-L/usr/local/lib/*)
    p=\${a:2}; [ -n "\${WALI_OVERLAY:-}" ] && [ -d "\$WALI_OVERLAY\$p" ] && A+=("\${a:0:2}\$WALI_OVERLAY\$p");;
  -I/usr/include|-I/usr/local/include|-L/usr/lib|-L/usr/local/lib|-L/lib|-L/lib/*|-L/lib64) ;;
  # the build host perl's C headers (ExtUtils::CBuilder and Module::Build read the host Config:
  # Params::Util's "can I use the Perl API" probe, Params::Validate, YAML::Syck): walios perl's
  -I/usr/lib/*/perl/*/CORE|-I/usr/lib/perl5/*/CORE|-I/usr/lib/*/perl5/*/CORE|-I/usr/local/lib/*/perl/*/CORE)
    A+=(-I$TC/perl-core/5.44.0/wasm32-linux/CORE);;
  -Wl,*)
    # ELF-linker options wasm-ld rejects, filtered token by token: one -Wl, can carry several
    # (-Wl,-Map=x.map,--cref). -z/-soname/-rpath/... take the next token as their value.
    # The value may come in the next -Wl, argument (-Wl,-z -Wl,relro), so skip carries over.
    IFS=, read -ra t <<< "\${a#-Wl,}"; k=()
    for x in "\${t[@]}"; do
      if [ \$skip = 1 ]; then skip=0; continue; fi
      case "\$x" in
        -z|-soname|-h|-rpath|-rpath-link|--version-script|-Map) skip=1;;
        --start-group|--end-group|--as-needed|--no-as-needed|--gc-sections|--warn-common|--sort-common|-O1|-O2|--hash-style=*|-soname=*|--version-script=*|-Bsymbolic*|--cref|--no-undefined|--fatal-warnings|--enable-new-dtags|--disable-new-dtags|-rpath=*|-rpath-link=*|--build-id*|-Map=*|-E|--export-dynamic|--icf=*|-znoexecstack|-zrelro|-znow|-zdefs|-warn-common|-stats|--stats|--no-copy-dt-needed-entries) ;;
        *) k+=("\$x");;
      esac
    done
    [ \${#k[@]} -gt 0 ] && A+=("-Wl,\$(IFS=,; echo "\${k[*]}")");;
  *) A+=("\$a");; esac; done
if [ \$link = 1 ] && [ \$shared = 1 ] && [ -n "\${WALI_SIDE:-}" ]; then
  # libc, libm and the runtime's own library come from the runtime (its exports), not a copy.
  S2=(); for a in "\${A[@]}"; do case "\$a" in -lc|-lm|-ldl|-lpthread|-lrt|-llua*|-lperl) ;; *) S2+=("\$a");; esac; done
  D2=(); for a in \${WALI_OVERLAY_LIBS:-}; do case "\$a" in */liblua*.a|*/libperl.a|*/libpython*.a) ;; *) D2+=("\$a");; esac; done
  # the library search path a program link gets (sysroot: openssl; the overlay: deps' libz,
  # libbz2...), so a module's own -lssl / -lz resolves (Net::SSLeay, Compress::Raw::Zlib)
  LP=(-L$S/lib); for a in \${WALI_EXTRA_LDFLAGS:-}; do case "\$a" in -L*) LP+=("\$a");; esac; done
  # then the deps' archives: a static library carries no record of its own deps (Pillow's
  # -lwebp needs libsharpyuv, -lfreetype libpng; only members something needs are pulled),
  # never an interpreter library the runtime exports. A module with thread-locals gets its own
  # __tls_base, 0 until the loader runs __wasm_init_tls on a block (wasm-ld makes it hidden).
  # Last, compiler-rt's builtins, as a program link has them: the long-double (IEEE quad)
  # helpers clang calls (__trunctfdf2, __multf3... FCGI) are not among the runtimes' exports.
  exec $L/clang "\${F[@]}" "\${LP[@]}" "\${S2[@]}" "\${LATE[@]}" "\${D2[@]}" $S/lib/libwali-sideunwind.a $S/lib/libclang_rt.builtins.a -nostdlib -Wl,--no-entry,--experimental-pic,--shared-memory,--allow-undefined-file=\$WALI_SIDE,--export-if-defined=__wasm_init_tls,--export-if-defined=__tls_size,--export-if-defined=__tls_align $SIDEOBJ
fi
if [ \$link = 1 ] && [ \$shared = 1 ]; then
  # The objects, and the members of the build's OWN static libraries on the line: a shared
  # library contains those (meson's link_whole: glib's libcharset.a and gnulib's printf, which
  # libglib-2.0's dependents then lacked -- _g_locale_get_charset_aliases undefined). A
  # dependency's archive by absolute path (overlay, sysroot) stays out: it is linked on its own.
  objs=(); ars=()
  for a in "\${A[@]}"; do
    case "\$a" in
      *.o|*.lo|*.obj) objs+=("\$a");;
      /*.a) ;;
      *.a) [ -f "\$a" ] && ars+=("\$a");;
      @*) [ -f "\${a#@}" ] && for x in \$(cat "\${a#@}"); do case "\$x" in *.o|*.lo|*.obj) objs+=("\$x");; /*.a) ;; *.a) [ -f "\$x" ] && ars+=("\$x");; esac; done;;   # cmake/ninja response files
    esac
  done
  rm -f "\$out"; $L/llvm-ar rcs "\$out" "\${objs[@]}" || exit 1
  for x in "\${ars[@]}"; do $L/llvm-ar qL "\$out" "\$x" || exit 1; done
  [ \${#ars[@]} -gt 0 ] && $L/llvm-ranlib "\$out"
  # -lfoo only searches lib*.a here (no dynamic linking), so give the archive that name too.
  case "\$out" in *lib*.so*) cp -f "\$out" "\${out%%.so*}.a";; esac
  exit 0
fi
if [ \$link = 1 ]; then
  # --allow-multiple-definition: a program may define a libc function itself (linux-pam's
  # tests replace getpwnam_r). Against a shared libc on Linux the program's copy wins; in this
  # static link both would collide -- first definition wins, and the program's objects come
  # before every library.
  LINK=(-L$S/lib \${WALI_EXTRA_LDFLAGS:-} -nodefaultlibs
    -Wl,--shared-memory,--import-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608,--export-table,--growable-table,--allow-multiple-definition)
  TAIL=($cxxlibs -lwali-farm -lc $S/lib/libclang_rt.builtins.a)
  G=()
  if [ -n "\${WALI_OVERLAY_LIBS+set}" ]; then
    # the package's own deps' archives (build-one.sh, from the plan's dependency closure)
    ov=(\${WALI_OVERLAY_LIBS})
    [ \${#ov[@]} -gt 0 ] && G=("\${ov[@]}")
  elif [ -n "\${WALI_OVERLAY:-}" ]; then
    ov=(\$(ls "\$WALI_OVERLAY"/usr/lib/*.a "\$WALI_OVERLAY"/lib/*.a 2>/dev/null))
    # No --start-group: wasm-ld rejects it, and like lld it resolves archives in any order.
    [ \${#ov[@]} -gt 0 ] && G=("\${ov[@]}")
  fi
  if [ \${#G[@]} -gt 0 ]; then
    # With the overlay group first; if anything in it breaks the link, the same link without
    # it (and that attempt's own errors are what the caller sees).
    $L/$drv "\${F[@]}" "\${A[@]}" "\${LATE[@]}" "\${LINK[@]}" \${WALI_EXTRA_LIBS:-} "\${G[@]}" "\${TAIL[@]}" 2>/dev/null && exit 0
  fi
  exec $L/$drv "\${F[@]}" "\${A[@]}" "\${LATE[@]}" "\${LINK[@]}" \${WALI_EXTRA_LIBS:-} "\${TAIL[@]}"
fi
# A compile that fails in ELF-only inline assembly gets one retry without it (wali-noelfasm).
e=\$(mktemp); $L/$drv "\${F[@]}" "\${A[@]}" "\${LATE[@]}" 2>"\$e"; rc=\$?
if [ \$rc != 0 ] && grep -q '<inline asm>' "\$e" && $TC/bin/wali-noelfasm $L/$drv "\${F[@]}" "\${A[@]}" "\${LATE[@]}"; then rm -f "\$e"; exit 0; fi
cat "\$e" >&2; rm -f "\$e"; exit \$rc
EOF
  chmod +x bin/wali-$d
done
# ELF-only assembler directives in C sources: symbol versions (.symver, attr's compat
# symbols) and glibc-style link warnings (.gnu.warning.* sections, alsa-lib). wasm objects
# have neither and clang's wasm assembler rejects them. wali-noelfasm <compiler command>:
# preprocess the one source, drop exactly those statements/attributes, compile the result.
cat > bin/wali-noelfasm <<'EOF'
#!/bin/bash
cc=$1; shift
src="" out="" P=() C=() skip=""
for a in "$@"; do
  if [ -n "$skip" ]; then skip=""; P+=("$a"); continue; fi
  case "$a" in
    *.c|*.cc|*.cpp|*.cxx|*.C) [ -f "$a" ] && { [ -n "$src" ] && exit 1; src=$a; continue; } ;;
  esac
  P+=("$a")
  case "$a" in -MF|-MT|-MQ) skip=1;; esac
done
[ -n "$src" ] || exit 1
case "$src" in *.c) ext=i;; *) ext=ii;; esac
t=$(mktemp -d)
# 1. preprocess with the same flags (-c becomes -E; -o names the .i; dependency flags stay
#    here, so make's .d files still name the real headers)
E=(); n=0; for a in "${P[@]}"; do case "$a" in -c) E+=(-E);; *) E+=("$a");; esac; done
oi=0; for i in "${!E[@]}"; do [ "${E[$i]}" = -o ] && { out=${E[$((i+1))]}; E[$((i+1))]=$t/s.$ext; oi=1; }; done
[ $oi = 1 ] || { rm -rf "$t"; exit 1; }
"$cc" "${E[@]}" "$src" 2>/dev/null || { rm -rf "$t"; exit 1; }
# 2. drop the ELF-only pieces
perl -0pi -e '
  s/\b(?:__asm__|__asm|asm)\s*(?:__volatile__\s*)?\(\s*"\s*\.(?:symver|section[\s"]+\.gnu\.warning|stabs)[^;]*;//g;
  s/__attribute__\s*\(\(\s*(?:__)?section(?:__)?\s*\(\s*"\.gnu\.warning\.[^)]*\)\s*\)\)//g;
' "$t/s.$ext"
# 3. compile the result, without the dependency/preprocessor-only flags
K=(); skip=""
for a in "${P[@]}"; do
  if [ -n "$skip" ]; then skip=""; continue; fi
  case "$a" in -MF|-MT|-MQ) skip=1;; -MD|-MMD|-MP) ;; *) K+=("$a");; esac
done
"$cc" "${K[@]}" -Wno-unused-command-line-argument "$t/s.$ext"; rc=$?
rm -rf "$t"; exit $rc
EOF
chmod +x bin/wali-noelfasm
printf '#!/bin/sh\nargs=""\nfor a in "$@"; do [ "$a" = "-nostdlib" ] || args="$args $a"; done\nexec %s/wasm-ld $args\n' "$L" > bin/wali-ld
chmod +x bin/wali-ld
# BSD headers musl leaves out and Alpine adds with bsd-compat-headers: sys/queue.h (the
# runner's glibc copy, BSD-licensed, self-contained) and a minimal sys/cdefs.h shim.
mkdir -p $S/include/sys
# libbsd's queue.h (full BSD set: TAILQ_FOREACH_SAFE...) when the host has libbsd-dev,
# else glibc's, which lacks the _SAFE iterators.
if [ ! -f $S/include/sys/queue.h ]; then
  if [ -f /usr/include/bsd/sys/queue.h ]; then sed 's|#include <bsd/sys/cdefs.h>|#include <sys/cdefs.h>|' /usr/include/bsd/sys/queue.h > $S/include/sys/queue.h
  else cp /usr/include/x86_64-linux-gnu/sys/queue.h $S/include/sys/queue.h; fi
fi
[ -f $S/include/sys/tree.h ] || { [ -f /usr/include/bsd/sys/tree.h ] && sed 's|#include <bsd/sys/cdefs.h>|#include <sys/cdefs.h>|' /usr/include/bsd/sys/tree.h > $S/include/sys/tree.h; } || true
[ -f $S/include/sys/cdefs.h ] || cat > $S/include/sys/cdefs.h <<'EOF'
/* walios farm: the BSD <sys/cdefs.h> macros old code expects (what Alpine's
   bsd-compat-headers provides; musl deliberately ships no cdefs.h). */
#ifndef _SYS_CDEFS_H
#define _SYS_CDEFS_H
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif
#define __THROW
#define __NTH(fct) fct
#define __P(args) args
#define __PMT(args) args
#define __CONCAT(x,y) x ## y
#define __STRING(x) #x
#define __ptr_t void *
#define __long_double_t long double
#define __attribute_malloc__ __attribute__((__malloc__))
#define __attribute_pure__ __attribute__((__pure__))
#define __attribute_const__ __attribute__((__const__))
#define __attribute_used__ __attribute__((__used__))
#define __attribute_noinline__ __attribute__((__noinline__))
#define __attribute_deprecated__ __attribute__((__deprecated__))
#define __wur __attribute__((__warn_unused_result__))
#define __nonnull(params) __attribute__((__nonnull__ params))
#define __unused __attribute__((__unused__))
#define __dead2 __attribute__((__noreturn__))
#define __dead __attribute__((__noreturn__))
#define __packed __attribute__((__packed__))
#define __aligned(x) __attribute__((__aligned__(x)))
#define __predict_true(e) __builtin_expect(!!(e), 1)
#define __predict_false(e) __builtin_expect(!!(e), 0)
#define __offsetof(type, field) __builtin_offsetof(type, field)
#define __containerof(x, s, m) ((s *)((char *)(x) - __offsetof(s, m)))
#define __DEQUALIFY(type, var) ((type)(__UINTPTR_TYPE__)(const volatile void *)(var))
#define __DECONST(type, var) ((type)(__UINTPTR_TYPE__)(const void *)(var))
#endif
EOF
# libwali-farm.a: the glibc-isms musl leaves out (error(), closefrom()), the three-argument
# main bridge and musl's cancellation labels (see farm/ci/shim/*.c). An archive, so each
# member links only where something needs it; it goes before -lc on every link.
if [ ! -f $S/lib/libwali-farm.a ]; then
  for c in "$HERE"/shim/*.c; do
    $L/clang $TGT --sysroot=$S -nostdlibinc -isystem $S/include -D_GNU_SOURCE       -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -pthread       -c "$c" -o "$S/lib/farm-$(basename "${c%.c}").o"
  done
  $L/llvm-ar rcs $S/lib/libwali-farm.a $S/lib/farm-*.o
fi
# libwali-sideunwind.a: a side module's own landing-pad context (farm/ci/shim-side/unwind-side.c),
# for C++ exceptions caught inside a C module; PIC like every side-module object.
if [ ! -f $S/lib/libwali-sideunwind.a ]; then
  $L/clang $TGT --sysroot=$S -nostdlibinc -isystem $S/include -O2 -fPIC -fwasm-exceptions -matomics -mbulk-memory -mexception-handling -pthread \
    -c "$HERE"/shim-side/unwind-side.c -o $S/lib/unwind-side.o
  $L/llvm-ar rcs $S/lib/libwali-sideunwind.a $S/lib/unwind-side.o
fi
# closefrom(), glibc 2.34+'s declaration (libwali-farm.a defines it): xapian-core calls it once
# configure's link test finds it.
grep -q closefrom $S/include/unistd.h || printf '\n#ifndef _WALI_CLOSEFROM\n#define _WALI_CLOSEFROM\n#ifdef __cplusplus\nextern "C"\n#endif\nvoid closefrom(int);\n#endif\n' >> $S/include/unistd.h
[ -f $S/include/error.h ] || cat > $S/include/error.h <<'EOF'
/* glibc <error.h>, implemented by libwali-farm.a (farm/ci/shim/error.c). */
#ifndef _ERROR_H
#define _ERROR_H
#ifdef __cplusplus
extern "C" {
#endif
void error(int status, int errnum, const char *format, ...);
void error_at_line(int status, int errnum, const char *filename, unsigned int linenum, const char *format, ...);
extern void (*error_print_progname)(void);
extern unsigned int error_message_count;
extern int error_one_per_line;
#ifdef __cplusplus
}
#endif
#endif
EOF
# OpenSSL is in the sysroot (libssl.a, libcrypto.a, include/openssl) but has no .pc files,
# so pkg-config-driven configures did not find it. Compiler default paths, so no flags.
mkdir -p $S/lib/pkgconfig
for pc in openssl:"-lssl -lcrypto" libssl:"-lssl" libcrypto:"-lcrypto"; do
  printf 'Name: %s
Description: OpenSSL (walios sysroot)
Version: 3.0.0
Libs: %s
Cflags:
' "${pc%%:*}" "${pc#*:}" > $S/lib/pkgconfig/${pc%%:*}.pc
done
# musl keeps crypt/resolv/util/... in libc; their -l names exist as empty archives (as in musl).
for l in crypt resolv util xnet; do [ -f $S/lib/lib$l.a ] || $L/llvm-ar rcs $S/lib/lib$l.a; done
# Recipes and Makefiles that call cc/gcc/c++ directly get the WALI compiler; tools built to
# run during the build use CC_FOR_BUILD/BUILD_CC/HOSTCC, which build-one.sh points at gcc.
for n in cc gcc; do ln -sf wali-cc bin/$n; done
for n in c++ g++; do ln -sf wali-c++ bin/$n; done
# Alpine helpers some recipes call: cmake3.5 (cmake with the 3.5 policy floor), and doc/ELF
# tools the farm does not need (scdoc writes man pages, scanelf audits ELF -- no-ops here).
cat > bin/cmake3.5 <<'EOF'
#!/bin/sh
case "$1" in --build|--install|-E|-P) exec cmake "$@";; esac
exec cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@"
EOF
printf '#!/bin/sh
cat >/dev/null
' > bin/scdoc
printf '#!/bin/sh
exit 0
' > bin/scanelf
# strip / install -s: a no-op that still honours -o. llvm-strip drops custom sections, the
# wali.abi marker among them, and the kernel then runs an ILP32 program as the other ABI.
cat > bin/wali-strip <<'EOF'
#!/bin/sh
o=""; f=""
while [ $# -gt 0 ]; do case "$1" in -o) o=$2; shift;; -o*) o=${1#-o};; -*) ;; *) f=$1;; esac; shift; done
[ -n "$o" ] && [ -n "$f" ] && [ "$o" != "$f" ] && cp -f "$f" "$o"
exit 0
EOF
ln -sf wali-strip bin/strip
chmod +x bin/cmake3.5 bin/scdoc bin/scanelf bin/wali-strip

# meson: a cross file, and abuild-meson (Alpine's wrapper around `meson setup`).
cat > wali.meson <<EOF
[binaries]
c = '$TC/bin/wali-cc'
cpp = '$TC/bin/wali-c++'
ar = '$L/llvm-ar'
strip = '$TC/bin/wali-strip'
nm = '$L/llvm-nm'
pkg-config = 'pkg-config'
# (cc.run() checks, and the sanity check, run the wasm program on the build machine: farm-wave.yml)
exe_wrapper = '/usr/local/bin/wali-run'
[host_machine]
system = 'linux'
cpu_family = 'wasm32'
cpu = 'wasm32'
endian = 'little'
[properties]
needs_exe_wrapper = true
# (numpy: clang's wasm32 long double is IEEE binary128)
longdouble_format = 'IEEE_QUAD_LE'
EOF
cat > bin/abuild-meson <<EOF
#!/bin/bash
# The recipe's own library-type/LTO/PIE choices give way to the farm's (static, no LTO).
A=()
# GObject introspection data is made by running g-ir-scanner against the just-built (wasm)
# libraries, and nothing on walios reads it: a recipe's introspection=enabled/true is turned off.
for a in "\$@"; do case "\$a" in -Ddefault_library=*|--default-library=*|-Db_lto=*|-Db_pie=*|-Db_staticpic=*) ;;
  -Dintrospection=enabled) A+=(-Dintrospection=disabled);; -Dintrospection=true) A+=(-Dintrospection=false);;
  *) A+=("\$a");; esac; done
set -- "\${A[@]}"
exec meson setup --cross-file $TC/wali.meson --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/libexec \
  --bindir=/usr/bin --sbindir=/usr/sbin --includedir=/usr/include --datadir=/usr/share --mandir=/usr/share/man \
  --sysconfdir=/etc --localstatedir=/var --buildtype=plain --default-library=static --wrap-mode=nodownload \
  -Db_lto=false -Db_pie=false -Db_staticpic=true "\$@"
# (b_staticpic=true: with it false meson refuses a recipe's explicit shared_library() over a
#  static helper -- linux-pam; the wrapper drops -fPIC anyway, outside WALI_SIDE builds.)
EOF
chmod +x bin/abuild-meson
# A recipe calling `meson setup` directly (glib) would get a NATIVE build, whose sanity check
# runs a compiled wasm test program and stops ("Executables created by c compiler ... are
# not runnable"). This meson, first on PATH, adds the cross file when the call has none.
cat > bin/meson <<EOF
#!/bin/bash
real=""; IFS=:
for d in \$PATH; do [ "\$d" = "$TC/bin" ] && continue; [ -x "\$d/meson" ] && { real="\$d/meson"; break; }; done
unset IFS
# a package that brings its own meson (numpy's vendored-meson, with its "features" module)
# keeps it: meson-python passes the source dir to setup and runs later steps in a build dir
# inside it
for d in "\$@" "\$PWD" "\$(dirname "\$PWD")"; do
  [ -f "\$d/vendored-meson/meson/meson.py" ] && { real="python3 \$d/vendored-meson/meson/meson.py"; break; }; done
[ -n "\$real" ] || { echo "meson: not installed" >&2; exit 127; }
if [ "\$1" = setup ]; then
  # Alpine builds offline (abuild-meson: --wrap-mode=nodownload): a dependency the recipe does not
  # list is disabled, not fetched and built as a subproject (glib's bootstrap fetched sysprof).
  W=--wrap-mode=nodownload; case " \$* " in *" --wrap-mode"*) W=;; esac
  case " \$* " in *" --cross-file"*) shift; exec \$real setup \$W "\$@";; *) shift; exec \$real setup --cross-file $TC/wali.meson \$W "\$@";; esac
fi
exec \$real "\$@"
EOF
chmod +x bin/meson
# cmake: CMAKE_TOOLCHAIN_FILE (env) is honoured by cmake >= 3.21.
cat > wali.cmake <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
# try_run() and check_c_source_runs() run the wasm program on the build machine (farm-wave.yml's
# wali-run), instead of failing as an unanswered cross-compile run.
set(CMAKE_CROSSCOMPILING_EMULATOR /usr/local/bin/wali-run)
set(CMAKE_C_COMPILER $TC/bin/wali-cc)
set(CMAKE_CXX_COMPILER $TC/bin/wali-c++)
set(CMAKE_AR $L/llvm-ar CACHE FILEPATH "")
set(CMAKE_RANLIB $L/llvm-ranlib CACHE FILEPATH "")
# The farm's overlay of already-built deps (build-one.sh exports WALI_OVERLAY), so
# find_package/find_library see them as well as the sysroot.
set(CMAKE_FIND_ROOT_PATH $S \$ENV{WALI_OVERLAY} \$ENV{WALI_OVERLAY}/usr)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
# Not ELF: cmake cannot rewrite RPATHs at install time, and walios binaries are static anyway.
set(CMAKE_SKIP_RPATH ON CACHE BOOL "")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON CACHE BOOL "")
set(CMAKE_POSITION_INDEPENDENT_CODE OFF CACHE BOOL "")
EOF
echo "toolchain ready: $TC (LLVM $LLVM_VER, sysroot $TAG, extras $XTAG)"
