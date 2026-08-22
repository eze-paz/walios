#!/bin/bash
# WALI wasm-OS build farm — takes Alpine aport recipes, cross-compiles to
# wasm32-wali, smoke-tests each on the JS host, and gates: pass -> wasm repo
# (runnable in the OS), fail -> stays VM-only. Emits repo/manifest.json.
#
# Usage: farm.sh pkg1 pkg2 ...      (aport names, real APKBUILDs from Alpine)
set -u
FARM=~/wali-farm
W=~/wali/build
CC="$W/llvm/bin/clang --target=wasm32-unknown-linux-muslwali --sysroot=$W/sysroot -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -pthread -matomics -mbulk-memory -mexception-handling -L$W/sysroot/lib -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types -Wl,--shared-memory -Wl,--export-memory -Wl,--max-memory=2147483648 -Wl,-z,stack-size=8388608 -Wno-unused-command-line-argument -Wno-ignored-optimization-argument"
export CC W
export AR="$W/llvm/bin/llvm-ar" RANLIB="$W/llvm/bin/llvm-ranlib" LD="$HOME/walihost/wali-ld"
APORTS="https://git.alpinelinux.org/aports/plain/main"
HOST="node $HOME/walihost/host.js"

mkdir -p "$FARM/src" "$FARM/repo" "$FARM/log"
MANIFEST="$FARM/repo/manifest.json"
echo '{' > "$MANIFEST"
first=1

strip_gnu_ld() { sed -e 's/-Wl,--start-group//g;s/-Wl,--end-group//g;s/-Wl,--warn-common//g;s/-Wl,--sort-common//g;s/-Wl,--gc-sections//g;s/-Wl,--as-needed//g'; }

for pkg in "$@"; do
  echo "======================================================================"
  echo "FARM: $pkg"
  log="$FARM/log/$pkg.log"
  status="fail"; reason=""; wasmout=""; smoke=""
  bdir="$FARM/src/$pkg"; rm -rf "$bdir"; mkdir -p "$bdir"

  # 1. fetch recipe
  if ! curl -sSL --max-time 20 "$APORTS/$pkg/APKBUILD" -o "$bdir/APKBUILD" 2>>"$log"; then
    reason="no-recipe"; echo "  [$pkg] FAIL: $reason"; emit=1
  else
  # 2. parse recipe (source it in a subshell, read the fields we need)
  eval "$(cd "$bdir" && sed -n 's/^\(pkgname\|pkgver\|_pkgver\|builddir\)=/&/p' APKBUILD | grep -E '^(pkgname|pkgver)=')" 2>/dev/null
  src_url=$(cd "$bdir" && bash -c 'source ./APKBUILD 2>/dev/null; echo "$source"' | tr " \t" "\n\n" | grep -E '^https?://' | head -1)
  echo "  ver=$pkgver  src=$src_url" | tee -a "$log"

  # 3. download + extract main tarball; fetch all local patch/aux files too
  if [ -n "$src_url" ]; then
    tarball="$bdir/$(basename "$src_url")"
    curl -sSL --max-time 60 "$src_url" -o "$tarball" 2>>"$log"
    tar xf "$tarball" -C "$bdir" 2>>"$log"
    srcdir=$(find "$bdir" -maxdepth 1 -type d ! -path "$bdir" | head -1)
    # fetch every non-URL source entry (patches, .in files) from the aport dir
    for f in $(cd "$bdir" && bash -c 'source ./APKBUILD 2>/dev/null; echo "$source"' | tr " \t" "\n\n" | grep -vE '^https?://|^$'); do
      curl -sSL --max-time 20 "$APORTS/$pkg/$f" -o "$bdir/$f" 2>>"$log"
      [ -n "${srcdir:-}" ] && cp "$bdir/$f" "$srcdir/" 2>/dev/null
    done
  else
    srcdir=""; reason="no-source"
  fi

  if [ -n "${srcdir:-}" ] && [ -d "$srcdir" ]; then
    # 4. run the aport's OWN build() with the WALI toolchain injected.
    #    This is the faithful test: unmodified recipe, our CC/flags in env.
    (
      export CC="$CC" CXX="$CC" AR="$AR" RANLIB="$RANLIB" LD="$LD"
      export CFLAGS="" CXXFLAGS="" LDFLAGS="" CPPFLAGS=""
      export cross_compiling=yes CHOST=wasm32-unknown-linux-musl CBUILD=x86_64-pc-linux-gnu
      SRC="$srcdir"
      srcdir="$bdir" builddir="$SRC" pkgdir="$bdir/pkg" subpkgdir="$bdir/subpkg"
      export srcdir builddir pkgdir
      cd "$srcdir"
      # abuild's default_prepare: apply every *.patch listed in $source, -p1
      default_prepare() {
        cd "$builddir"
        for p in $source; do case "$p" in
          *.patch) [ -f "$srcdir/$p" ] && { echo "  applying $p"; patch -p1 < "$srcdir/$p" || return 1; };;
        esac; done
        cd "$srcdir"
      }
      source ./APKBUILD 2>>"$log"
      : "${builddir:=$SRC}"
      # run prepare() (or default) then build()
      if type prepare >/dev/null 2>&1; then prepare; else default_prepare; fi
      cd "$builddir" 2>/dev/null || cd "$SRC"
      if type build >/dev/null 2>&1; then build; else make; fi
    ) >>"$log" 2>&1
    # 5. find a produced wasm binary (reliable magic check: 00 61 73 6d)
    cand=$(find "$srcdir" -type f 2>/dev/null | while read f; do
             m=$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n');
             [ "$m" = "0061736d" ] && { echo "$f"; break; }; done | head -1)
    if [ -n "$cand" ]; then
      cp "$cand" "$FARM/repo/$pkg.wasm"; wasmout="$pkg.wasm"
      # 6. smoke test on the JS host (per-pkg args; stdin from /dev/null)
      case "$pkg" in
        tree) sa="--version";; gzip) sa="-h";; bzip2) sa="--help";;
        jq) sa="--version";; sed) sa="--version";; grep) sa="--version";;
        less) sa="--version";; lua*) sa="-v";; *) sa="--version";;
      esac
      st=$($HOST "$FARM/repo/$pkg.wasm" $sa </dev/null 2>&1)
      sc=$?
      smoke=$(echo "$st" | grep -v "wali-host\]\|ENOSYS" | head -1 | cut -c1-60)
      if echo "$st" | grep -q "exit=0\|exit=1"; then
        if echo "$st" | grep -q "trap in pid\|fatal:"; then status="fail"; reason="smoke-trap";
        else status="pass"; reason="ok"; fi
      else status="fail"; reason="smoke-crash"; fi
    else status="fail"; reason="${reason:-no-wasm-output}"; fi
  fi
  emit=1
  fi

  # 7. emit manifest row (the validated compatibility ledger)
  [ $first -eq 0 ] && echo ',' >> "$MANIFEST"; first=0
  printf '  "%s": {"ver":"%s","status":"%s","reason":"%s","wasm":"%s","tier":"%s","smoke":"%s"}' \
    "$pkg" "${pkgver:-?}" "$status" "$reason" "$wasmout" \
    "$([ "$status" = pass ] && echo wasm || echo vm-only)" "$(echo "$smoke" | sed 's/"/\\"/g')" >> "$MANIFEST"
  echo "  [$pkg] => $status ($reason) tier=$([ "$status" = pass ] && echo wasm || echo vm-only)"
  unset pkgver
done
echo '' >> "$MANIFEST"; echo '}' >> "$MANIFEST"
echo "======================================================================"
echo "MANIFEST: $MANIFEST"
cat "$MANIFEST"
