#!/bin/bash
# Interactive OpenSSH over WALI — end to end, unmodified sshd (privsep enabled),
# real fork() via the Asyncify substrate. Runs `ssh -o ProxyCommand="sshd -i"` so
# the ssh client, sshd, sshd-session, the privsep monitor+child, and the login shell
# are ALL WALI wasm processes under the concurrent scheduler; the only external I/O
# is the client's stdin/stdout.
#
# Prereqs (built elsewhere in this tree):
#   - sshd.wasm / sshd-session.wasm : OpenSSH 9.9, built -D__WALI_ASYNCIFY_FORK
#       (real fork -> SYS_fork) then `wasm-opt --asyncify --pass-arg=asyncify-imports@wali.SYS_fork`
#       (see build-openssh-async.sh). sshd-session needs a construct_utmp link stub.
#   - ssh.wasm : the stock WALI ssh client (no asyncify needed; it only fork+execs).
#   - a WALI busybox for the login shell (/bin/sh).
# Run with node 24: node --experimental-wasm-jspi host.js ...   (WALI_JSPI=1)
set -euo pipefail
D=${1:-~/sshdemo}; D=$(eval echo "$D")
NODE=${NODE:-~/node-v24.5.0-linux-x64/bin/node}
HOST=${HOST:-~/walihost/host.js}
MAP="/usr/local/libexec/sshd-session=$D/sshd-session.wasm,/usr/sbin/sshd=$D/sshd.wasm"

# --- one-time environment: host key, client key, virtual user DB, config ---
if [ ! -f "$D/ssh_host_ed25519_key" ]; then
  mkdir -p "$D/etc" "$D/home/me/.ssh" "$D/var/empty"
  ssh-keygen -t ed25519 -f "$D/ssh_host_ed25519_key" -N "" -q
  ssh-keygen -t ed25519 -f "$D/id_client" -N "" -q
  cp "$D/id_client.pub" "$D/authorized_keys"; cp "$D/authorized_keys" "$D/home/me/.ssh/"
  printf 'root:x:0:0:root:/root:/bin/sh\nme:x:1000:1000:me:%s/home/me:/bin/sh\nsshd:x:74:74:sshd:/var/empty:/sbin/nologin\n' "$D" > "$D/etc/passwd"
  printf 'root:x:0:\nme:x:1000:\nsshd:x:74:\n' > "$D/etc/group"
  printf 'root:*:19000:0:99999:7:::\nme:*:19000:0:99999:7:::\nsshd:!:19000:0:99999:7:::\n' > "$D/etc/shadow"
  cat > "$D/sshd_config" <<EOF
HostKey $D/ssh_host_ed25519_key
AuthorizedKeysFile $D/authorized_keys
StrictModes no
PidFile none
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin yes
EOF
  cat > "$D/ssh_config" <<EOF
Host localhost
  User me
  IdentityFile $D/id_client
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ProxyCommand /usr/sbin/sshd -i -f $D/sshd_config
  LogLevel ERROR
EOF
fi

# --- run: interactive login shell over SSH (feed commands on stdin) ---
( printf 'echo INTERACTIVE_SESSION_WORKS\n'; sleep 2; printf 'uname -a\n'; sleep 2; printf 'exit\n'; sleep 1 ) | \
  WALI_JSPI=1 WALI_ETC="$D/etc" WALI_MAP="$MAP" \
  "$NODE" --experimental-wasm-jspi "$HOST" "$D/ssh.wasm" -tt -F "$D/ssh_config" me@localhost
