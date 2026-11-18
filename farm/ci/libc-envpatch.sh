#!/bin/bash
# libc-envpatch.sh <toolchain-dir> [sysroot-tarball]
#
# Swap walios' environment reader (musl-patches/src/env/initenv.c: a NUL-separated
# environment from __get_init_envfile0, so values may contain newlines) into the libc.a of a
# farm toolchain (farm/ci/toolchain.sh, either ABI) and, if given, into a sysroot tarball too
# (the CPython recipe takes one). For builds whose sysroot release predates the reader; a
# sysroot built from musl-patches has it already. Programs linked afterwards import
# __get_init_envfile0, which only kernels that serve it can run.
set -euo pipefail
TC=$(realpath -m "${1:?usage: libc-envpatch.sh <toolchain-dir> [sysroot-tarball]}")
TARBALL=${2:-}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck disable=SC1091
source "$TC/env.sh"
W=$(mktemp -d)
curl -sSfL --retry 6 -o "$W/init_env.h" \
  https://raw.githubusercontent.com/arjunr2/wali-musl/243ec00c3ffb910375db487d7eb24ea76d1e2c9f/arch/wasm32/init_env.h
patch_libc() {
  local libc=$1 mem
  mem=$("$WALI_LLVM/llvm-ar" t "$libc" | grep -E '^initenv\.l?o$' | head -1)
  [ -n "$mem" ] || { echo "libc-envpatch: no initenv member in $libc" >&2; exit 1; }
  "$CC" -c -O2 -I"$W" "$REPO/musl-patches/src/env/initenv.c" -o "$W/$mem"
  ( cd "$W" && "$WALI_LLVM/llvm-ar" r "$libc" "$mem" )
  echo "libc-envpatch: $libc <- $mem (ABI ${WALI_ABI:-?})"
}
patch_libc "$WALI_SYSROOT/lib/libc.a"
if [ -n "$TARBALL" ]; then
  mkdir -p "$W/s" && tar xzf "$TARBALL" -C "$W/s"
  L=$(find "$W/s" -name libc.a -path '*/lib/*' | head -1)
  [ -n "$L" ] || { echo "libc-envpatch: no lib/libc.a in $TARBALL" >&2; exit 1; }
  patch_libc "$L"
  tar czf "$TARBALL" -C "$W/s" .
fi
