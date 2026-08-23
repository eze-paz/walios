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
cat > "$S/root/.profile" <<'EOF'
cat /etc/motd 2>/dev/null
EOF
cat > "$S/root/readme.txt" <<'EOF'
Welcome to walios. This whole shell — and every command you run — is native
WebAssembly executing in your browser tab, answered by a JavaScript syscall host.
No CPU emulation. Try: ls, cat readme.txt, seq 5 | wc -l, find / -maxdepth 2.
EOF
printf 'hello from a file inside the wasm OS\n' > "$S/root/hello.txt"
cd "$S" && tar czf ~/wali-www/rootfs.tar.gz . && echo "rootfs: $(stat -c%s ~/wali-www/rootfs.tar.gz) bytes"
