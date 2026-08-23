# CPython-on-wasm performance notes (measured, i5-1235U, V8/node)

## What works: switch dispatch + --export-table
The deployed build uses the DEFAULT switch-based opcode dispatch and links with
`-Wl,--export-table -Wl,--table-base=16` (the table export is required for
signal-handler dispatch, not for speed). Warm steady-state fib(30) ~185 ms.

## Computed gotos: HARMFUL on wasm (do NOT enable)
`USE_COMPUTED_GOTOS` is a large win on native CPUs (per-opcode indirect branch =
better branch prediction) but a PESSIMIZATION on wasm: clang lowers
label-as-values to many per-handler indirect branches, which V8's wasm compiler
handles far worse than a switch's single central `br_table`. Measured warm ABBA:
switch ~185 ms vs computed-gotos ~570 ms, degrading to ~1000 ms over iterations.
(An earlier "3.1x speedup" claim was cross-run measurement noise — cold
per-process runs cross V8 Liftoff->TurboFan tiering unpredictably. Only warm,
in-process, interleaved measurements are valid here.)

## LTO (-flto -O3): HARMFUL (do NOT enable)
Whole-program LTO + -O3 bloats the giant `_PyEval_EvalFrameDefault` (register
pressure, i-cache). Measured warm ~800 ms vs ~185 ms. `--with-lto` not worth it.

## PGO: not available without building compiler-rt for wasm
`--enable-optimizations` needs an instrumented run: no wasm build of
`libclang_rt.profile.a` ships (only x86_64), and no `llvm-profdata` in the WALI
toolchain. Would require building the profile runtime for wasm32-wali plus a
profraw-write path (could run the instrumented binary ON walios itself) — a
large detour, deferred.

## vs Pyodide (warm steady-state fib(30), same box)
walios ~185 ms vs Pyodide ~245 ms — parity, walios marginally ahead. Both are
CPython->wasm; V8 generates similar code. walios also cold-starts ~9x faster and
runs a real process model (fork/exec/shell/subprocess) Pyodide cannot.

## Measurement discipline
Per-process `node host.js python -c ...` timings vary 3-5x from V8 wasm tiering
and are NOT comparable. Measure warm: loop the kernel >= 8x inside one process
and read the stable tail; compare interleaved (ABBA) within one session.
