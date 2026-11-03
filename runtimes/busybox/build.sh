#!/usr/bin/env bash
# Build busybox.wasm (busybox 1.36.1 for walios): ash with line editing, the applets in
# applets.txt, `ls` colours and the checksum/base64 applets, Asyncify'd so fork() works.
# Linux (WSL Ubuntu 24.04 works); needs curl git nodejs.
#
#   build.sh [workdir]     -> <workdir>/busybox.wasm, <workdir>/busybox.links
#   # then bump WB.BUSYBOX ('busybox.wasm?v=...') in sandpie/modules/walios-backend.js
#
# Toolchain: $WALI_TC (an existing farm toolchain dir) or one set up in <workdir>/tc by
# farm/ci/toolchain.sh from github.com/eze-paz/walios (LLVM 22.1.3 + the walios sysroot);
# WALI_ABI=ilp32 there gives the walios ILP32 ABI (32-bit long).
#
# fork: busybox forks and keeps running Perl-free C in both processes (subshells, pipelines
# of builtins), so it cannot use the sysroot's vfork-protocol fork() macro. It is compiled
# with __WALI_LIBC_INTERNAL, which leaves fork() the plain libc function (_Fork -> the
# SYS_fork import), and Asyncify'd on that import: the kernel unwinds the parent and rewinds
# a copy as the child (reference: walios-farm host/asyncify-fork-proof).
#
# applets.txt is the applet set the box served before this recipe existed (the old .config
# was lost with the machine it lived on); allnoconfig + those applets + the features below
# reproduce it. A new applet goes into applets.txt.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(realpath -m "${1:-$HOME/busybox-wali-build}")
mkdir -p "$R" && cd "$R"

BB_VER=1.36.1
BINARYEN_VER=132           # Asyncify that understands wasm exceptions (Ubuntu's 108 does not)
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
if [ ! -x binaryen-version_$BINARYEN_VER/bin/wasm-opt ]; then
  curl -sSfL https://github.com/WebAssembly/binaryen/releases/download/version_$BINARYEN_VER/binaryen-version_$BINARYEN_VER-x86_64-linux.tar.gz | tar xz
fi
WO=$R/binaryen-version_$BINARYEN_VER/bin/wasm-opt

# ---- sources ----
[ -d busybox-$BB_VER ] || curl -sSfL https://busybox.net/downloads/busybox-$BB_VER.tar.bz2 | tar xj

# bb-cc: clang for walios. A link gets libc and compiler-rt's builtins by path (the release
# LLVM has no wasm builtins in its resource dir) and loses busybox's -Wl,--start-group /
# --end-group (wasm-ld rejects them and, like lld, resolves archives in any order) and the
# ELF-only --warn-common/--sort-* trylink adds. --no-wasm-opt: clang otherwise runs whatever
# wasm-opt is on PATH after the link; the output must not depend on that.
cat > "$R/bb-cc" <<EOF
#!/bin/bash
A=(); link=1
for a in "\$@"; do case "\$a" in -Wl,--start-group|-Wl,--end-group|-Wl,--warn-common|-Wl,--sort-common|-Wl,--sort-section=*) ;; -c|-E|-S|-M|-MM) link=0; A+=("\$a");; *) A+=("\$a");; esac; done
[ \$link = 1 ] && A+=(--no-wasm-opt -nodefaultlibs -lc "$WALI_SYSROOT/lib/libclang_rt.builtins.a")
exec "$WALI_LLVM/clang" ${WALI_TARGET:---target=wasm32-unknown-linux-muslwali} --sysroot="$WALI_SYSROOT" "\${A[@]}"
EOF
chmod +x "$R/bb-cc"
CCBASE="$R/bb-cc -L$WALI_SYSROOT/lib -Wno-unused-command-line-argument -Wno-ignored-optimization-argument"
CC="$CCBASE -O2 -D__WALI_LIBC_INTERNAL -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types -Wl,--shared-memory -Wl,--import-memory -Wl,--export-memory -Wl,--max-memory=${BB_MAX_MEMORY:-2147483648} -Wl,-z,stack-size=${BB_STACK_SIZE:-8388608} -Wl,--export-table -Wl,--table-base=16 -Wl,--export=__stack_pointer -Wl,--export-if-defined=__tls_base"
# --export=__stack_pointer: a forked child rewinds on a fresh instance whose stack pointer
# global is the initial (empty-stack) value; the worker copies the parent's value in or the
# child's next calls overwrite the frames it inherited (timeout kill(parent) saw parent=0).
# --export-table + --table-base=16: lets the host invoke ash's signal handlers
# (job control, ^C to the foreground group). Without it, delivered signals fall
# back to the default action and interactive Ctrl-C in the shell degrades.
# BB_MAX_MEMORY / BB_STACK_SIZE are overridable so the per-instance memory cost can be
# re-measured, but the DEFAULTS are deliberately unchanged. Both were tried against the
# process-spawn ceiling (a long pipeline-heavy run dies with "Cannot allocate Wasm memory
# for new instance" after a few hundred forks): 2GB->256MB moved the first failure not at
# all (248 -> 248) and an 8MB->1MB stack made it WORSE (248 -> 202). Neither is the driver,
# so neither default is changed on a guess.
LD="$WALI_LLVM/clang ${WALI_TARGET:---target=wasm32-unknown-linux-muslwali} --sysroot=$WALI_SYSROOT -nostdlib"   # -r applet-combine: no memory flags (they conflict with -r)
cd busybox-$BB_VER

set_y() { local k="$1"; sed -i "s|^# ${k} is not set|${k}=y|; s|^${k}=.*|${k}=y|" .config; grep -q "^${k}=y" .config || echo "${k}=y" >> .config; }
set_n() { local k="$1"; sed -i "s|^${k}=.*|# ${k} is not set|" .config; grep -qE "^(# )?${k}( is not set|=)" .config || echo "# ${k} is not set" >> .config; }
set_v() { local k="$1" v="$2"; sed -i "s|^# ${k} is not set|${k}=${v}|; s|^${k}=.*|${k}=${v}|" .config; grep -q "^${k}=" .config || echo "${k}=${v}" >> .config; }

# (the farm toolchain's PATH makes `cc`/`gcc` the wasm compiler: kconfig gets the real one)
export HOSTCC=/usr/bin/gcc
# Start from upstream's DEFAULT config, then switch off every applet not in applets.txt.
# This used to start from allnoconfig, which also turned off every applet's optional
# features -- and the .config the box's binary was really built from (edited in place in a
# WSL tree, never committed) had them on. A rebuild from allnoconfig silently lost, among
# others, nearly all of find (-type -exec -mtime -size -newer -maxdepth -delete -regex ...),
# sort -t/-k (FEATURE_SORT_BIG) and hush's loops/trap/wait. Each applet's config symbol is
# read from its //applet:IF_<SYM>(APPLET...(name ...)) line, so a symbol stays on only if one
# of its applets is wanted.
make HOSTCC=$HOSTCC defconfig >"$R/defconfig.log" 2>&1
grep -rhoE '^//applet:IF_[A-Z0-9_]+\( *APPLET[A-Z_]*\( *[^, ]+' --include=*.c . \
  | sed -E 's|^//applet:IF_([A-Z0-9_]+)\( *APPLET[A-Z_]*\( *|\1 |' > "$R/applet-syms.txt"
awk 'NR==FNR { want[$1] = 1; next } { sym[$1] = sym[$1] || ($2 in want) } END { for (s in sym) if (!sym[s]) print s }' \
  "$HERE/applets.txt" "$R/applet-syms.txt" | while read -r s; do set_n "CONFIG_$s"; done
while read -r a; do set_y "CONFIG_$(echo "$a" | tr 'a-z-' 'A-Z_')"; done < "$HERE/applets.txt"
set_n CONFIG_NOMMU                 # we have real fork() now (Asyncify substrate)
set_y CONFIG_LFS                   # off_t is 64-bit on every walios ABI (allnoconfig turns it off)
set_y CONFIG_ASH; set_y CONFIG_SHELL_ASH
set_y CONFIG_ASH_INTERNAL_GLOB; set_y CONFIG_ASH_BASH_COMPAT; set_y CONFIG_ASH_JOB_CONTROL
set_y CONFIG_ASH_ALIAS; set_y CONFIG_ASH_EXPAND_PRMT; set_y CONFIG_ASH_ECHO; set_y CONFIG_ASH_PRINTF
set_y CONFIG_ASH_TEST; set_y CONFIG_ASH_GETOPTS; set_y CONFIG_ASH_CMDCMD; set_y CONFIG_ASH_RANDOM_SUPPORT
set_y CONFIG_SH_IS_ASH; set_n CONFIG_SH_IS_HUSH; set_n CONFIG_SH_IS_NONE
set_y CONFIG_FEATURE_SH_MATH; set_y CONFIG_FEATURE_SH_MATH_64; set_y CONFIG_FEATURE_SH_STANDALONE
set_y CONFIG_FEATURE_EDITING; set_v CONFIG_FEATURE_EDITING_MAX_LEN 1024; set_v CONFIG_FEATURE_EDITING_HISTORY 500
set_y CONFIG_FEATURE_TAB_COMPLETION; set_y CONFIG_FEATURE_USERNAME_COMPLETION
set_n CONFIG_FEATURE_EDITING_FANCY_PROMPT   # crashes on wasm (indirect call in prompt %-expansion)
set_n CONFIG_FEATURE_EDITING_ASK_TERMINAL; set_n CONFIG_FEATURE_EDITING_VI
# -NUM shorthand (`tail -5`, `head -20`): busybox only parses the legacy leading-number
# form under FANCY_TAIL/FANCY_HEAD (which also add -c/-q/-v). Without them the GNU idiom
# every tool and script reaches for first dies with "tail: unrecognized option: 5".
set_y CONFIG_FEATURE_FANCY_TAIL; set_y CONFIG_FEATURE_FANCY_HEAD
# ls colours (the standard scheme, on by default when stdout is a tty, off when piped --
# so the walios() tool's output stays plain), plus the applets the model kept routing
# around in Python: base64, md5sum/sha1sum/sha256sum, stat -c.
set_y CONFIG_LONG_OPTS             # FEATURE_LS_COLOR depends on it; also gives --help, --list, ls --color=...
set_y CONFIG_FEATURE_LS_COLOR; set_y CONFIG_FEATURE_LS_COLOR_IS_DEFAULT
set_y CONFIG_BASE64; set_y CONFIG_MD5SUM; set_y CONFIG_SHA1SUM; set_y CONFIG_SHA256SUM
set_y CONFIG_FEATURE_STAT_FORMAT
# Archives. The farm's GNU tar package shipped as `rmt` (wrong executable picked) and the
# GNU grep/diffutils/findutils packages as gnulib test helpers, so the catalog's tar was
# never usable and the others merely shadowed working busybox applets. busybox provides
# them all: tar with create/extract, GNU long options and seamless -z/-j via the gzip and
# bzip2 applets, plus unzip (zip extraction was missing entirely), diff/cmp, find/xargs.
set_y CONFIG_TAR; set_y CONFIG_FEATURE_TAR_CREATE; set_y CONFIG_FEATURE_TAR_AUTODETECT; set_y CONFIG_FEATURE_TAR_FROM
set_y CONFIG_FEATURE_TAR_GNU_EXTENSIONS; set_y CONFIG_FEATURE_TAR_LONG_OPTIONS; set_y CONFIG_FEATURE_TAR_NOPRESERVE_TIME
set_y CONFIG_FEATURE_SEAMLESS_GZ; set_y CONFIG_FEATURE_SEAMLESS_BZ2; set_y CONFIG_FEATURE_SEAMLESS_XZ
set_y CONFIG_GZIP; set_y CONFIG_GUNZIP; set_y CONFIG_ZCAT; set_y CONFIG_FEATURE_GZIP_LONG_OPTIONS
set_y CONFIG_BZIP2; set_y CONFIG_BUNZIP2; set_y CONFIG_BZCAT; set_y CONFIG_UNXZ; set_y CONFIG_XZCAT
set_y CONFIG_UNZIP; set_y CONFIG_FEATURE_UNZIP_CDF; set_y CONFIG_FEATURE_UNZIP_BZIP2; set_y CONFIG_FEATURE_UNZIP_XZ
set_y CONFIG_DIFF; set_y CONFIG_FEATURE_DIFF_LONG_OPTIONS; set_y CONFIG_FEATURE_DIFF_DIR; set_y CONFIG_CMP
# Accept the tar formats a real tar accepts. Both of these are `default y` upstream and
# were lost only because this .config started minimal and the list above never asserted
# them -- so busybox REJECTED valid archives that GNU tar reads without complaint:
#   OLDGNU: header magic of five NULs (v7 / pre-POSIX format). jq-1.8.2.tar.gz is exactly
#     this, so `build-pkg jq` died with "invalid tar magic" on the FIRST header even
#     though the download and gunzip were perfect (8755200 bytes, byte 0 = 'jq-1.8.2/').
#     get_header_tar.c: `"ustar" is for the proper tar, five NULs are for the old tar`.
#   OLDSUN: checksums old Sun tar computed with signed arithmetic.
# Neither loosens anything a real tar would refuse; both only stop us rejecting good input.
set_y CONFIG_FEATURE_TAR_OLDGNU_COMPATIBILITY; set_y CONFIG_FEATURE_TAR_OLDSUN_COMPATIBILITY
# Same story for ls and grep: every one of these is `default y` upstream and every one was
# off, so the applet silently lacked a standard flag and scripts died on it.
#   ls -t  (SORTFILES+TIMESTAMPS): automake's `checking whether build environment is sane`
#          runs `ls -t` and aborts the whole configure with "ls -t appears to fail. Make
#          sure there is not a broken alias in your environment".
#   grep -A/-B/-C (CONTEXT): used by configure and by anyone reading logs; without it
#          `grep -B5` is "unrecognized option: B".
# -R/-W/-p/-L/username are the rest of the standard ls surface, same default, same reason.
set_y CONFIG_FEATURE_LS_SORTFILES; set_y CONFIG_FEATURE_LS_TIMESTAMPS; set_y CONFIG_FEATURE_LS_FILETYPES
set_y CONFIG_FEATURE_LS_RECURSIVE; set_y CONFIG_FEATURE_LS_WIDTH; set_y CONFIG_FEATURE_LS_USERNAME
set_y CONFIG_FEATURE_LS_FOLLOWLINKS; set_y CONFIG_FEATURE_GREP_CONTEXT
# CONFIG_DESKTOP is the same story one level up: `default y` upstream, off here, and it
# gates "applet options and features which are not essential" ACROSS applets -- for 8kB.
# Building oniguruma (jq's regex engine) died on `od: unrecognized option: A`, which is one
# of them. Rather than chase these one flag at a time, take upstream's default.
set_y CONFIG_DESKTOP
for a in CONFIG_REV CONFIG_TR CONFIG_ID CONFIG_LESS CONFIG_VI CONFIG_CLEAR CONFIG_ENV CONFIG_SEQ \
         CONFIG_SORT CONFIG_UNIQ CONFIG_HEAD CONFIG_TAIL CONFIG_CUT CONFIG_XARGS CONFIG_DATE \
         CONFIG_DIRNAME CONFIG_BASENAME CONFIG_STAT CONFIG_DU CONFIG_WC CONFIG_WHICH CONFIG_FIND \
         CONFIG_GREP CONFIG_SED CONFIG_AWK CONFIG_TEST CONFIG_HOSTNAME CONFIG_UNAME CONFIG_CLEAR \
         CONFIG_NC CONFIG_WGET CONFIG_TELNET CONFIG_PING CONFIG_PING6 CONFIG_NSLOOKUP \
         CONFIG_NC_110_COMPAT CONFIG_NC_SERVER CONFIG_NC_EXTRA \
         CONFIG_FEATURE_HUMAN_READABLE \
         CONFIG_FEATURE_WGET_STATUSBAR CONFIG_FEATURE_WGET_LONG_OPTIONS CONFIG_FEATURE_FANCY_PING; do set_y "$a"; done
# HTTPS for wget. Without this busybox does not even know the scheme: parse_url compares
# against P_HTTPS only under SSL_SUPPORTED, so every `wget https://...` died with
# "not an http or ftp url" -- which is what silently broke build-pkg (its wfetch is wget,
# so EVERY APKBUILD fetch failed and was misreported as "no APKBUILD for <pkg>").
# OPENSSL, not HTTPS/TLS: FEATURE_WGET_OPENSSL makes wget fork+socketpair+execlp an
# `openssl s_client -quiet -connect H:P -servername N` helper, and walios ships one
# (/bin/openssl -> the relay's TLS termination: TLS 1.3 + system-CA validation).
# CONFIG_TLS/FEATURE_WGET_HTTPS stay OFF on purpose: busybox's internal tls.c is TLS 1.2
# only and verifies NO certificate, so enabling it would add a silent unverified-TLS
# fallback whenever the helper is missing. Off = loud failure.
set_y CONFIG_FEATURE_WGET_OPENSSL
set_n CONFIG_FEATURE_WGET_HTTPS; set_n CONFIG_TLS; set_n CONFIG_SSL_CLIENT

{ yes "" || true; } | make HOSTCC=$HOSTCC oldconfig >"$R/oldcfg.log" 2>&1
for k in ASH SH_IS_ASH FEATURE_EDITING FEATURE_LS_COLOR BASE64; do grep -q "^CONFIG_$k=y" .config || { echo "busybox .config: CONFIG_$k is off" >&2; exit 1; }; done
! grep -q '^CONFIG_NOMMU=y' .config || { echo "busybox .config: CONFIG_NOMMU is on" >&2; exit 1; }
make HOSTCC=$HOSTCC clean >/dev/null 2>&1   # a new libc.a must reach every object: no stale .o from the old link
make CC="$CC" LD="$LD" HOSTCC=$HOSTCC LDFLAGS="" SKIP_STRIP=y -j"$(nproc)" busybox >"$R/make.log" 2>&1 ||
  { grep -iE "error:|undefined symbol" "$R/make.log" | tail -6 >&2; exit 1; }
"$WO" --asyncify --pass-arg=asyncify-imports@wali.SYS_fork busybox -o "$R/busybox.wasm"

# The applet LINK LIST. Real busybox is installed with `busybox --install -s`, which drops a
# symlink per applet into /bin and /usr/bin. walios never did that, so /bin/sed and friends
# did not EXIST as files -- exec still worked (the kernel falls back to busybox by name) but
# `test -f` / `test -x` did not, and that is exactly how autoconf hunts for tools:
#   configure: error: no acceptable sed could be found in $PATH
# walios-backend.js seeds one empty file per line of this list so the probes tell the truth.
make HOSTCC=$HOSTCC busybox.links >/dev/null 2>&1
cp busybox.links "$R/busybox.links"
# Every applet asked for, and nothing else (a dependency of one turning on another counts).
diff <(sed 's|.*/||' busybox.links | sort) <(sort "$HERE/applets.txt") >"$R/applets.diff" ||
  { echo "busybox: applet set differs from applets.txt (< built, > asked):" >&2; cat "$R/applets.diff" >&2; exit 1; }
echo "built $R/busybox.wasm ($(stat -c %s "$R/busybox.wasm") bytes), $(wc -l < "$R/busybox.links") applets"