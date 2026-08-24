#!/bin/bash
# Rebuild busybox for WALI with ash (needs !NOMMU) + line editing + tab completion +
# a broad applet set. !NOMMU means real fork() -> we build with -D__WALI_ASYNCIFY_FORK
# and post-process with wasm-opt --asyncify so fork() works via the host's fork substrate.
set -uo pipefail
W=~/wali/build; WO=~/binaryen-version_132/bin/wasm-opt
CCBASE="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -L$W/sysroot/lib -Wno-unused-command-line-argument -Wno-ignored-optimization-argument"
CC="$CCBASE -O2 -D__WALI_ASYNCIFY_FORK -pthread -fwasm-exceptions -mllvm -wasm-enable-sjlj -matomics -mbulk-memory -mexception-handling -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608 -Wl,--export-table -Wl,--table-base=16"
# --export-table + --table-base=16: lets the host invoke ash's signal handlers
# (job control, ^C to the foreground group). Without it, delivered signals fall
# back to the default action and interactive Ctrl-C in the shell degrades.
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
for a in CONFIG_REV CONFIG_TR CONFIG_ID CONFIG_LESS CONFIG_VI CONFIG_CLEAR CONFIG_ENV CONFIG_SEQ \
         CONFIG_SORT CONFIG_UNIQ CONFIG_HEAD CONFIG_TAIL CONFIG_CUT CONFIG_XARGS CONFIG_DATE \
         CONFIG_DIRNAME CONFIG_BASENAME CONFIG_STAT CONFIG_DU CONFIG_WC CONFIG_WHICH CONFIG_FIND \
         CONFIG_GREP CONFIG_SED CONFIG_AWK CONFIG_TEST CONFIG_HOSTNAME CONFIG_UNAME CONFIG_CLEAR \
         CONFIG_NC CONFIG_WGET CONFIG_TELNET CONFIG_PING CONFIG_PING6 CONFIG_NSLOOKUP \
         CONFIG_NC_110_COMPAT CONFIG_NC_SERVER CONFIG_NC_EXTRA \
         CONFIG_FEATURE_HUMAN_READABLE \
         CONFIG_FEATURE_WGET_STATUSBAR CONFIG_FEATURE_WGET_LONG_OPTIONS CONFIG_FEATURE_FANCY_PING; do set_y "$a"; done

yes "" | make oldconfig >/tmp/bb-oldcfg.log 2>&1
echo "ash=$(grep -c '^CONFIG_ASH=y' .config) sh_is_ash=$(grep -c '^CONFIG_FEATURE_SH_IS_ASH=y' .config) editing=$(grep -c '^CONFIG_FEATURE_EDITING=y' .config) nommu=$(grep -c '^CONFIG_NOMMU=y' .config)"
make CC="$CC" LD="$LD" HOSTCC=cc LDFLAGS="" SKIP_STRIP=y -j8 busybox >/tmp/bb-make.log 2>&1; echo "make=$?"
grep -iE "error:|undefined symbol" /tmp/bb-make.log | grep -viE "warning|Wno-" | tail -6
[ -f busybox ] || { echo "NOT BUILT"; exit 1; }
echo "raw: $(du -h busybox|cut -f1); fork import: $(~/binaryen-version_132/bin/wasm-dis busybox 2>/dev/null | grep -oE 'SYS_fork|__wali_fork_begin' | sort -u | tr '\n' ' ')"
$WO --asyncify --pass-arg=asyncify-imports@wali.SYS_fork busybox -o busybox.async && mv busybox.async busybox
echo "asyncified: $(du -h busybox|cut -f1)"
