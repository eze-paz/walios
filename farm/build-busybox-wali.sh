#!/bin/bash
# Build busybox (1.36.1) for walios: wasm32-wali with ash, line editing, a broad applet
# set, `ls` colours and the checksum/base64 applets, Asyncify'd so fork() works.
#
# RUN ON WSL/Linux with the WALI toolchain at ~/wali/build (llvm + sysroot) and binaryen.
# Source tree: ~/busybox-1.36.1 (untouched upstream + .config). This is the recipe that
# used to live only in ~/build-busybox.sh on one machine; it is in the repo so the binary
# the box serves can be reproduced.
#
#   bash scripts/build-busybox-wali.sh            # -> ~/busybox-1.36.1/busybox (wasm)
#   cp ~/busybox-1.36.1/busybox walios/busybox.wasm
#   # then bump WB.BUSYBOX ('busybox.wasm?v=netN') in sandpie/modules/walios-backend.js
#
# IMPORTANT: the libc this links must be built against the CURRENT wali-musl headers.
# The Sep-2026 libc.a had frexpl/strtod compiled for an 80-bit long double layout while
# the compiler uses 128-bit, so every float printf recursed to death (seq, printf %f,
# awk floats all broken). `make -C ~/wali/wali-musl install` first if in doubt.
set -uo pipefail
W=~/wali/build; WO=~/binaryen-version_132/bin/wasm-opt
CCBASE="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -L$W/sysroot/lib -Wno-unused-command-line-argument -Wno-ignored-optimization-argument"
CC="$CCBASE -O2 -D__WALI_ASYNCIFY_FORK -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types -Wl,--shared-memory -Wl,--import-memory -Wl,--export-memory -Wl,--max-memory=${BB_MAX_MEMORY:-2147483648} -Wl,-z,stack-size=${BB_STACK_SIZE:-8388608} -Wl,--export-table -Wl,--table-base=16 -Wl,--export=__stack_pointer -Wl,--export-if-defined=__tls_base"
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
LD="$CCBASE -nostdlib"   # -r applet-combine: no memory flags (they conflict with -r)
cd ~/busybox-1.36.1

set_y() { local k="$1"; sed -i "s|^# ${k} is not set|${k}=y|; s|^${k}=.*|${k}=y|" .config; grep -q "^${k}=y" .config || echo "${k}=y" >> .config; }
set_n() { local k="$1"; sed -i "s|^${k}=.*|# ${k} is not set|" .config; grep -qE "^(# )?${k}( is not set|=)" .config || echo "# ${k} is not set" >> .config; }
set_v() { local k="$1" v="$2"; sed -i "s|^# ${k} is not set|${k}=${v}|; s|^${k}=.*|${k}=${v}|" .config; grep -q "^${k}=" .config || echo "${k}=${v}" >> .config; }

set_n CONFIG_NOMMU                 # we have real fork() now (Asyncify substrate)
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

yes "" | make oldconfig >/tmp/bb-oldcfg.log 2>&1
echo "ash=$(grep -c '^CONFIG_ASH=y' .config) sh_is_ash=$(grep -c '^CONFIG_FEATURE_SH_IS_ASH=y' .config) editing=$(grep -c '^CONFIG_FEATURE_EDITING=y' .config) nommu=$(grep -c '^CONFIG_NOMMU=y' .config) ls_color=$(grep -c '^CONFIG_FEATURE_LS_COLOR=y' .config) base64=$(grep -c '^CONFIG_BASE64=y' .config)"
make clean >/dev/null 2>&1   # a new libc.a must reach every object: no stale .o from the old link
make CC="$CC" LD="$LD" HOSTCC=cc LDFLAGS="" SKIP_STRIP=y -j"$(nproc)" busybox >/tmp/bb-make.log 2>&1; echo "make=$?"
grep -iE "error:|undefined symbol" /tmp/bb-make.log | grep -viE "warning|Wno-" | tail -6
[ -f busybox ] || { echo "NOT BUILT"; exit 1; }
cp busybox busybox_unstripped
echo "raw: $(du -h busybox|cut -f1); fork import: $(~/binaryen-version_132/bin/wasm-dis busybox 2>/dev/null | grep -oE 'SYS_fork|__wali_fork_begin' | sort -u | tr '\n' ' ')"
$WO --asyncify --pass-arg=asyncify-imports@wali.SYS_fork busybox -o busybox.async && mv busybox.async busybox
echo "asyncified: $(du -h busybox|cut -f1)  -> ~/busybox-1.36.1/busybox"

# The applet LINK LIST. Real busybox is installed with `busybox --install -s`, which drops a
# symlink per applet into /bin and /usr/bin. walios never did that, so /bin/sed and friends
# did not EXIST as files -- exec still worked (the kernel falls back to busybox by name) but
# `test -f` / `test -x` did not, and that is exactly how autoconf hunts for tools:
#   configure: error: no acceptable sed could be found in $PATH
# walios-backend.js seeds one empty file per line of this list so the probes tell the truth.
make busybox.links >/dev/null 2>&1
echo "applet links: $(wc -l < busybox.links) -> copy busybox.links next to busybox.wasm"