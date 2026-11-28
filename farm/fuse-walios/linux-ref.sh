#!/bin/bash
# pjdfstest on real Linux, as a reference for walios (sandpie docs/plans/walios-fuse-rclone.md):
# the same test scripts walios runs (release fuse-walios-N's pjdfstest-tests.tar.gz), the
# pjdfstest program and libfuse's passthrough example built natively, run as root on tmpfs
# (walios' RAM filesystem's counterpart) and through passthrough over that tmpfs
# (-o default_permissions,allow_other, as walios' tests mount it). Output, per place:
#   F <file> <ok> <not ok> <secs> <exit> <plan line>
#   N <file> <not ok line>
#   linux-ref.sh <tests release tag> <out dir>
set -u
TAG=$1; OUT=$(realpath -m "$2"); mkdir -p "$OUT"; W0=$(mktemp -d)
cd "$W0"
sum() { echo "$*" | tee -a "$OUT/summary.txt"; }
sum "kernel: $(uname -r)"
# libfuse (its passthrough example), the version walios' release has
LV=$(cat "$GITHUB_WORKSPACE/farm/fuse-walios/LIBFUSE_VERSION")
git clone -q --depth 1 -b "fuse-$LV" https://github.com/libfuse/libfuse.git libfuse || { sum "libfuse clone FAIL"; exit 1; }
( cd libfuse && meson setup build -Dexamples=true -Dutils=false -Dtests=false >/dev/null && ninja -C build >/dev/null ) || { sum "libfuse build FAIL"; exit 1; }
PT="$W0/libfuse/build/example/passthrough"; export LD_LIBRARY_PATH="$W0/libfuse/build/lib"
[ -x "$PT" ] && sum "libfuse $LV passthrough OK"
# pjdfstest, the program; the tests: walios' release copy (the same scripts byte for byte)
git clone -q --depth 1 https://github.com/pjd/pjdfstest.git pjd || { sum "pjdfstest clone FAIL"; exit 1; }
( cd pjd && sum "pjdfstest $(git rev-parse --short HEAD)" && autoreconf -ifs >/dev/null 2>&1 && ./configure >/dev/null && make >/dev/null ) || { sum "pjdfstest build FAIL"; exit 1; }
curl -fsSL -o tests.tar.gz "https://github.com/eze-paz/walios/releases/download/$TAG/pjdfstest-tests.tar.gz" || { sum "tests download FAIL"; exit 1; }
mkdir -p /opt/pjd && tar xzf tests.tar.gz -C /opt/pjd && cp pjd/pjdfstest /opt/pjd/pjdfstest/pjdfstest
cd /opt/pjd/pjdfstest
FILES=$(ls -d */*.t | sort)
mkdir -p /mnt/t /mnt/p && mount -t tmpfs tmpfs /mnt/t
run() {   # run <place> <workdir>
  local place=$1 W=$2 f s rc
  : > "$OUT/linux-$place.txt"
  for f in $FILES; do
    rm -rf /mnt/t/w; mkdir -p /mnt/t/w
    s=$(date +%s)
    ( cd "$W" && timeout 900 sh "/opt/pjd/pjdfstest/$f" > /tmp/pjout 2>&1 ); rc=$?
    echo "F $f $(grep -c '^ok' /tmp/pjout) $(grep -c '^not ok' /tmp/pjout) $(( $(date +%s) - s )) $rc $(head -1 /tmp/pjout)" >> "$OUT/linux-$place.txt"
    grep '^not ok' /tmp/pjout | sed "s|^|N $f |" >> "$OUT/linux-$place.txt"
  done
  sum "$place: $(awk '$1=="F"{o+=$3; n+=$4} END{print o" ok, "n" not ok"}' "$OUT/linux-$place.txt") (not ok incl. TODO: $(grep -c '# TODO' "$OUT/linux-$place.txt"))"
}
run ram /mnt/t/w
"$PT" -f -s -o default_permissions,allow_other /mnt/p > "$OUT/passthrough.log" 2>&1 &
for i in $(seq 50); do grep -q ' /mnt/p fuse' /proc/mounts && break; sleep 0.2; done
run fuse /mnt/p/mnt/t/w
umount /mnt/p; umount /mnt/t
exit 0
