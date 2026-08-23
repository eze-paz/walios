#!/bin/bash
set -e
S=/tmp/sshvfs; D=~/sshdemo
rm -rf "$S"; mkdir -p "$S/etc/ssh" "$S/home/me/.ssh" "$S/root" "$S/var/empty" "$S/bin" "$S/sbin" "$S/usr/local/libexec" "$S/usr/sbin"
cp "$D/ssh_host_ed25519_key" "$S/etc/ssh/"; cp "$D/ssh_host_ed25519_key.pub" "$S/etc/ssh/"
cp "$D/id_client" "$S/root/id_client"; cp "$D/authorized_keys" "$S/home/me/.ssh/authorized_keys"
cat > "$S/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
me:x:1000:1000:me:/home/me:/bin/sh
sshd:x:74:74:sshd:/var/empty:/sbin/nologin
EOF
cat > "$S/etc/group" <<EOF
root:x:0:
me:x:1000:
sshd:x:74:
EOF
cat > "$S/etc/shadow" <<EOF
root:*:19000:0:99999:7:::
me:*:19000:0:99999:7:::
sshd:!:19000:0:99999:7:::
EOF
cat > "$S/etc/ssh/sshd_config" <<EOF
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /home/me/.ssh/authorized_keys
StrictModes no
PidFile none
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin yes
EOF
cat > "$S/etc/ssh/ssh_config" <<EOF
Host localhost
  User me
  IdentityFile /root/id_client
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ProxyCommand /usr/sbin/sshd -i -f /etc/ssh/sshd_config
  LogLevel ERROR
EOF
touch "$S/var/empty/.keep"
# executable placeholders (execve resolves via manifest; sshd stat-checks these)
for f in usr/local/libexec/sshd-session usr/sbin/sshd bin/sh bin/hush bin/busybox sbin/nologin; do
  printf '\0asm placeholder' > "$S/$f"; chmod 755 "$S/$f"
done
cd "$S" && tar czf ~/wali-www/sshvfs.tar.gz . && echo "rebuilt quiet $(stat -c%s ~/wali-www/sshvfs.tar.gz)b"
