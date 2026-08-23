#!/bin/bash
# walios regression suite. Run from anywhere: tests/run.sh [name-filter]
# Sync-model tests (src/) run under plain node; JSPI tests (src-jspi/) need
# node >= 24 (--experimental-wasm-jspi) and wasm-opt --asyncify for fork.
cd "$(dirname "$0")"
HOST=${HOST:-../host/host.js}
NODE=${NODE:-node}
NODE24=${NODE24:-$HOME/node-v24.5.0-linux-x64/bin/node}
WASM_OPT=${WASM_OPT:-$HOME/binaryen-version_132/bin/wasm-opt}
FILTER=${1:-}
mkdir -p build
pass=0; fail=0; skip=0

build() { # build <src.c> <out.wasm> [extra cflags...]
  local src="$1" out="$2"; shift 2
  [ "$out" -nt "$src" ] 2>/dev/null && return 0
  ./cc.sh "$@" "$src" -o "$out" 2> "build/$(basename "$out").ccerr" || { cat "build/$(basename "$out").ccerr"; return 1; }
}

run_one() { # run_one <name> <wasm> <node> <extra argv...>
  local name="$1" wasm="$2" nodebin="$3"; shift 3
  local out; out=$(timeout 60 "$nodebin" ${NODEFLAGS:-} "$HOST" "$wasm" "$@" 2> "build/$name.err"); local rc=$?
  if [ $rc -eq 0 ] && [ "$(echo "$out" | tail -1)" = "PASS" ]; then
    echo "ok   $name"; pass=$((pass+1))
  else
    echo "FAIL $name (rc=$rc)"; echo "$out" | sed "s/^/     | /"; tail -3 "build/$name.err" | sed "s/^/     ! /"; fail=$((fail+1))
  fi
}

for src in src/*.c; do
  name=$(basename "$src" .c)
  [ -n "$FILTER" ] && [[ "$name" != *$FILTER* ]] && continue
  wasm="$PWD/build/$name.wasm"   # absolute: execve(argv[0]) must resolve from any guest cwd
  build "$src" "$wasm" || { echo "FAIL $name (compile)"; fail=$((fail+1)); continue; }
  case "$name" in
    00-hello) run_one "$name" "$wasm" "$NODE" world ;;
    *)        run_one "$name" "$wasm" "$NODE" ;;
  esac
done

if [ -x "$NODE24" ]; then
  for src in src-jspi/*.c; do
    name=$(basename "$src" .c)
    [ -n "$FILTER" ] && [[ "$name" != *$FILTER* ]] && continue
    wasm="$PWD/build/$name.wasm"
    cflags=(); [[ "$name" == *fork* ]] && cflags=(-D__WALI_ASYNCIFY_FORK)  # real fork() path in musl, not the vfork macro
    build "$src" "$wasm" "${cflags[@]}" || { echo "FAIL $name (compile)"; fail=$((fail+1)); continue; }
    if [[ "$name" == *fork* ]]; then
      awasm="$PWD/build/$name.async.wasm"
      if [ ! -f "$awasm" ] || [ "$wasm" -nt "$awasm" ]; then
        "$WASM_OPT" --asyncify --pass-arg=asyncify-imports@wali.SYS_fork "$wasm" -o "$awasm" || { echo "FAIL $name (asyncify)"; fail=$((fail+1)); continue; }
      fi
      wasm="$awasm"
    fi
    WALI_JSPI=1 NODEFLAGS=--experimental-wasm-jspi run_one "$name" "$wasm" "$NODE24"
  done
else
  echo "skip src-jspi/* (no node24 at $NODE24)"; skip=$((skip+1))
fi

echo "---"
echo "pass=$pass fail=$fail skip=$skip"
[ $fail -eq 0 ]
