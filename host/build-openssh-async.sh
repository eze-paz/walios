#!/bin/bash
# Rebuild sshd + sshd-session with REAL fork() (-D__WALI_ASYNCIFY_FORK) and Asyncify
# them (asyncify-imports@wali.SYS_fork) so privsep fork-without-exec runs concurrently.
set -uo pipefail
cd ~/openssh-wali/openssh-9.9p1
export CONFIG_SITE="$HOME/wali-farm/config.site"
WO=~/binaryen-version_132/bin/wasm-opt

# add the real-fork define to CFLAGS (idempotent)
grep -q "__WALI_ASYNCIFY_FORK" Makefile || sed -i 's/^CFLAGS= /CFLAGS= -D__WALI_ASYNCIFY_FORK /' Makefile

echo "=== clean + rebuild objects with real fork ==="
make clean >/dev/null 2>&1
make ssh sshd sshd-session >/tmp/ssh_async_make.log 2>&1
echo "make exit=$?"
grep -iE "error:|undefined symbol" /tmp/ssh_async_make.log | grep -viE "Wno-|warning|construct_utmp" | tail -8

# sshd-session needs the construct_utmp stub (as before)
if [ ! -f sshd-session ]; then
  echo "=== relink sshd-session with loginstub ==="
  cat > /tmp/loginstub.c <<'EOF'
void construct_utmp(void){}
void construct_utmpx(void){}
EOF
  ~/wali/build/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$HOME/wali/build/sysroot -O2 -matomics -mbulk-memory -c /tmp/loginstub.c -o loginstub.o
  CMD=$(make -n sshd-session 2>/dev/null | tail -1)
  eval "${CMD/-o sshd-session /-o sshd-session loginstub.o }" 2>&1 | grep -viE "warning: unknown -z|signature mismatch|>>>" | tail -5
fi

echo "=== fork imports (should be SYS_fork, not __wali_fork_begin) ==="
for b in sshd sshd-session; do
  [ -f $b ] && echo "$b: $($WO --version >/dev/null; ~/binaryen-version_132/bin/wasm-dis $b 2>/dev/null | grep -oE 'SYS_fork|__wali_fork_begin' | sort -u | tr '\n' ' ')"
done

echo "=== asyncify sshd + sshd-session ==="
for b in sshd sshd-session; do
  [ -f $b ] || { echo "$b MISSING"; continue; }
  $WO --asyncify --pass-arg=asyncify-imports@wali.SYS_fork $b -o ~/sshdemo/$b.wasm 2>&1 | head -3
  echo "$b.wasm: $(stat -c%s ~/sshdemo/$b.wasm 2>/dev/null) bytes"
done
