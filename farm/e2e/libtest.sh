#!/bin/bash
# Library cases for the farm e2e: a program that links ALL of a library, run later in the real
# walios kernel (run.mjs, both engines).
#
#   source $TC/env.sh; farm/e2e/libtest.sh <index.json> <overlays.tar.gz> <catalog.txt> <out dir>
#
# For every catalog package the farm built as a library (index kind 'lib'), its own archives (from
# its overlay in the release's overlays.tar.gz) give the symbols it defines; the test program asks
# the linker for each of them (--undefined=<sym>), so every object of the library is linked in and
# each of its references must resolve -- against walios' libc, libc++ and the archives of every
# other package the farm built (the merged overlays, as a dependent's link would see them). The
# program prints __libok. Out: <out>/<lib>.libtest.wasm and <out>/libtest.json
# ({lib: {ok, syms, archives, reason}}); a library that does not link is not ok, with the
# linker's first error as the reason.
set -uo pipefail
IDX=$(realpath -m "$1"); OVT=$(realpath -m "$2"); CAT=$(realpath -m "$3"); OUT=$(realpath -m "$4")
: "${WALI_TC:?source the toolchain env.sh first}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT" "$W/ov" "$W/all" "$W/l"
tar xzf "$OVT" -C "$W/ov"
for t in "$W"/ov/*.overlay.tar.gz; do tar xzf "$t" -C "$W/all" 2>/dev/null || true; done
# every built package's archives; a library's own come first on the command line
mapfile -t ALL < <(ls "$W"/all/usr/lib/*.a "$W"/all/lib/*.a 2>/dev/null)
echo "libtest: ${#ALL[@]} archives in the merged overlays"
LIBS=$(node -e '
  const fs = require("fs"), [idx, cat] = process.argv.slice(1);
  const P = JSON.parse(fs.readFileSync(idx, "utf8")).packages, C = new Set(fs.readFileSync(cat, "utf8").split(/\s+/));
  console.log(Object.keys(P).filter((k) => P[k].kind === "lib" && C.has(k)).sort().join(" "));' "$IDX" "$CAT")
printf 'int puts(const char *);\nint main(void) { puts("__libok"); return 0; }\n' > "$W/t.c"
"$CC" -c "$W/t.c" -o "$W/t.o" || { echo "libtest: cannot compile the test main"; exit 1; }
: > "$W/rows.tsv"
for lib in $LIBS; do
  d="$W/l/$lib"; mkdir -p "$d"; reason=""; n=0; na=0
  if [ -f "$W/ov/$lib.overlay.tar.gz" ]; then tar xzf "$W/ov/$lib.overlay.tar.gz" -C "$d" 2>/dev/null; else reason="no overlay"; fi
  mapfile -t A < <(find "$d" -name '*.a' -type f 2>/dev/null | sort)
  na=${#A[@]}
  [ -z "$reason" ] && [ "$na" = 0 ] && reason="no archive"
  if [ -z "$reason" ]; then
    # global definitions (functions and data); linker-made and entry symbols excluded
    "$NM" -g --defined-only -j "${A[@]}" 2>/dev/null | grep -v -E '^$|:$|^(main|_start|__main_argc_argv|__main_void|__dso_handle|__data_end|__heap_base|__heap_end|__stack_pointer|__stack_low|__stack_high|__memory_base|__table_base|__indirect_function_table|__tls_base|__tls_size|__tls_align|__wasm_.*)$' |
      sort -u > "$d/syms"
    n=$(wc -l < "$d/syms")
    if [ "$n" = 0 ]; then reason="no symbols"
    else
      sed 's/^/-Wl,--undefined=/' "$d/syms" > "$d/und.rsp"
      # WALI_OVERLAY_LIBS set and empty: the wrapper adds no archives of its own (the ones named
      # here are the whole set), and its error output is this link's.
      if WALI_OVERLAY_LIBS= "$CXX" "$W/t.o" "@$d/und.rsp" "${A[@]}" "${ALL[@]}" -o "$OUT/$lib.libtest.wasm" 2> "$d/err"; then :
      else
        reason="link: $(grep -m1 -E 'error|undefined' "$d/err" | sed -E 's#/tmp/[^ :]*/##g' | tr -d '\000-\037"\\' | cut -c1-200)"
        [ "$reason" = "link: " ] && reason="link: $(head -c 200 "$d/err" | tr -d '\000-\037"\\')"
        rm -f "$OUT/$lib.libtest.wasm"
      fi
    fi
  fi
  printf '%s\t%s\t%s\t%s\n' "$lib" "$n" "$na" "$reason" >> "$W/rows.tsv"
  echo "libtest $lib: syms=$n archives=$na ${reason:-ok}"
done
node -e '
  const fs = require("fs"), [rows, out] = process.argv.slice(1), j = {};
  for (const l of fs.readFileSync(rows, "utf8").split("\n").filter(Boolean)) {
    const [lib, syms, archives, reason] = l.split("\t");
    j[lib] = { ok: !reason, syms: +syms, archives: +archives, ...(reason ? { reason } : {}) };
  }
  fs.writeFileSync(out, JSON.stringify(j, null, 1));
  const v = Object.values(j); console.log(`libtest: ${v.filter((x) => x.ok).length}/${v.length} libraries link`);' "$W/rows.tsv" "$OUT/libtest.json"
