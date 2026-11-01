/* musl's pthread_cancel.c compares the interrupted PC against the bounds of its
   cancellation-point syscall asm (extern const char __cp_begin[1], __cp_end[1], __cp_cancel[1]), which the
   WALI port does not assemble. Asynchronous cancellation cannot interrupt wasm anyway, so
   give the labels addresses that never match. */
const char __cp_begin[1], __cp_end[1], __cp_cancel[1];

