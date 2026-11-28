#!/bin/bash
set -e
S=/tmp/walios-rootfs; rm -rf "$S"; mkdir -p "$S"/{root,home,tmp,bin,usr/bin,etc,var/log,dev}
cat > "$S/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
EOF
# groups: root, and nogroup for nobody (65534) -- as Debian; `id -g nobody`, pjdfstest
cat > "$S/etc/group" <<EOF
root:x:0:
nogroup:x:65534:
EOF
echo walios > "$S/etc/hostname"
cat > "$S/etc/motd" <<'EOF'

  walios — a real Linux userland as native WebAssembly.
  busybox applets work as normal commands: ls, cat, grep, seq, wc, find, sort, sed,
  awk, tar, wget, vi, du, ps ... try `busybox --list` to see them all.

EOF
cat > "$S/etc/profile" <<'EOF'
export PS1='walios:\w\$ '
cat /etc/motd 2>/dev/null
EOF
# NB: no files under /root — it's a persistent OPFS mount (see terminal.html), so the
# in-memory tar must not shadow it. Welcome lives in /etc/motd (cat it any time).
cd "$S" && tar czf ~/wali-www/rootfs.tar.gz . && echo "rootfs: $(stat -c%s ~/wali-www/rootfs.tar.gz) bytes"
