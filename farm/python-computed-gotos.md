# CPython build: force computed gotos (cross-compile fix)

The WALI CPython build (~/wali-py) had `USE_COMPUTED_GOTOS` **undef** because
configure runs a test *binary* to detect label-as-values support, and that
binary cannot run under cross-compilation — so it silently assumed "no". The
WALI clang fully supports computed gotos; missing them made the interpreter
dispatch ~3x slower on branchy Python (fib) and ~1.7x on loops.

Fix (already applied to ~/wali-py/pyconfig.h):
    #define HAVE_COMPUTED_GOTOS 1
    #define USE_COMPUTED_GOTOS 1
then rebuild the interpreter loop and relink:
    rm -f Python/ceval.o && make Python/ceval.o
    # relink with the same flags as the main link, adding:
    #   -Wl,--export-table -Wl,--table-base=16   (signal handler dispatch)

Result on i5-1235U: fib(30) 0.536s -> 0.172s; 2M-loop 1.061s -> 0.624s —
at parity with Pyodide, which enables computed gotos by default.
Next lever if needed: --enable-optimizations (PGO) — Pyodide uses it.
