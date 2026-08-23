#!/bin/bash
# Make a WALI binary fully preemptible: wasm-opt --log-execution inserts a
# host hook at every basic-block entry, so even syscall-free compute loops
# deliver signals, honor SIGSTOP, and yield their scheduler quantum.
# Cost: one (fuel-amortized) import call per basic block — measured ~8x on
# call-dense pure recursion (fib), less on loopy code. IMPORTANT: link the
# binary WITHOUT --shared-memory (else the instrumented __wasm_init_memory
# start function calls the Suspending hook during instantiation and traps).
# Use for untrusted/CPU-bound programs; IO-bound ones already preempt at syscalls.
#   instrument-preempt.sh in.wasm out.wasm
set -e
WASM_OPT=${WASM_OPT:-$HOME/binaryen-version_132/bin/wasm-opt}
"$WASM_OPT" --log-execution "$1" -o "$2"
echo "instrumented: $2 ($(stat -c%s "$2") bytes)"
