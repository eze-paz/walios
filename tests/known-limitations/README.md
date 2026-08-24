# Known limitations (repros kept here, NOT in the auto-run suite)

## sighandler-io.c — a signal handler that makes a syscall traps under JSPI

**Symptom.** `ping` prints `PING host (ip): 56 data bytes` then exits/hangs with no
replies. Console shows:

    [host] signal handler trap pid N sig 14: SuspendError: trying to suspend without WebAssembly.promising

Sig 14 = SIGALRM. busybox `ping` arms a repeating SIGALRM whose handler sends the
next echo (a `sendto` syscall). Delivering that handler traps, so ping dies.

**Root cause (confirmed, not a guess).** Under the JSPI concurrent scheduler every
syscall import is a `WebAssembly.Suspending` function. A signal is delivered by
re-entering wasm from a JS callback (`table.get(handlerPtr)(sig)`), which runs the
handler on a fresh JS→wasm stack that is **not** inside a `WebAssembly.promising`
execution. A `Suspending` import **throws `SuspendError` the moment it is called
from non-promising wasm — even when the host returns a plain value and never
actually suspends.** Verified with an `inSigHandler` guard that made the handler's
syscalls fully synchronous: the guard was hit (`GUARD-HIT write inSig=1`) and it
STILL trapped. So the trap is intrinsic to calling a Suspending import from the
re-entered handler, independent of whether it would block.

**What was tried and did NOT work:**
- `inSigHandler` flag + running the handler's syscalls synchronously (`S.sys`) and
  skipping the quantum yield — still traps (Suspending import rejects the call
  itself, before the return value matters).
- Making the syscall wrapper a non-async fn that returns a plain value in a handler
  (so the promise-return wouldn't force a suspend) — still traps, same reason.
- `await WebAssembly.promising(table.get(ptr))(sig)` to run the handler in its own
  promising context — also trapped (nested promising from a suspended context did
  not establish a working suspender; needs its own investigation).

**Scope.** Only affects programs whose signal handlers make syscalls (ping's
SIGALRM→sendto; possibly SIGINT/SIGCHLD handlers that do I/O). Handlers that only
set a flag (the common case) are unaffected — the whole signals/timers/job-control
suite (24 tests) passes. The sync (non-JSPI) model is also unaffected.

**Candidate real fixes (future work):**
1. Signal trampolining: instead of re-entering wasm from JS, arrange for the handler
   to run as part of `_start`'s own promising execution on the next resume (how a
   real kernel sets up a signal frame). Correct but invasive.
2. Verify whether nested `WebAssembly.promising` can be made to work (minimal
   isolated repro of a Suspending call inside a promising call inside a Suspending
   callback) — if it can, delivery via promising is the clean fix.
3. For the browser only: route blocking syscalls through `Atomics.wait` on the
   bridge SABs instead of JSPI Suspending, so there are no Suspending imports to
   trip over — but this reintroduces worker-thread blocking and would need care to
   preserve the concurrent scheduler.

Build/run this repro with `-D__WALI_ASYNCIFY_FORK` + `wasm-opt --asyncify` and
`WALI_JSPI=1` on node 24, same as the other src-jspi tests.
