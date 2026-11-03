/* A side module's own copy of libunwind's wasm landing-pad glue (Unwind-wasm.c).
 *
 * A catch in C++ compiled with -fwasm-exceptions stores the landing pad's index and LSDA in
 * the thread-local __wasm_lpad_context and calls _Unwind_CallPersonality, which runs the
 * personality on it. In a PIC side module that TLS variable cannot be the program's
 * (wasm-ld: R_WASM_MEMORY_ADDR_TLS_SLEB against an undefined symbol), so each side module
 * defines its own, together with the one function that reads it; the personality and the
 * _Unwind_Get*/Set* it calls take the context by pointer and stay the program's. Linked into
 * side modules (wali-cc with $WALI_SIDE) only when something references them. */
#include <stdint.h>
#include <unwind.h>

struct _Unwind_LandingPadContext {
  uintptr_t lpad_index;   /* set by the compiler-generated landing pad */
  uintptr_t lsda;         /* likewise */
  uintptr_t selector;     /* set by the personality */
};

__attribute__((visibility("hidden"))) _Thread_local struct _Unwind_LandingPadContext __wasm_lpad_context;

_Unwind_Reason_Code __gxx_personality_wasm0(int, _Unwind_Action, uint64_t, struct _Unwind_Exception *,
                                            struct _Unwind_Context *);

__attribute__((visibility("hidden"))) _Unwind_Reason_Code _Unwind_CallPersonality(void *exception_ptr) {
  struct _Unwind_Exception *exception_object = (struct _Unwind_Exception *)exception_ptr;
  __wasm_lpad_context.selector = 0;
  /* wasm has no two-phase unwinding: the search phase is the only one */
  return __gxx_personality_wasm0(1, _UA_SEARCH_PHASE, exception_object->exception_class, exception_object,
                                 (struct _Unwind_Context *)&__wasm_lpad_context);
}
