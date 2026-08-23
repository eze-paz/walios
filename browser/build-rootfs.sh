#!/bin/bash
set -e
S=/tmp/walios-rootfs; rm -rf "$S"; mkdir -p "$S"/{root,home,tmp,bin,usr/bin,etc,var/log,dev}
cat > "$S/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
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
