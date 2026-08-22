// wasm-EH setjmp/longjmp runtime (LLVM -wasm-enable-sjlj contract, emscripten ABI)
struct args { void* env; int val; };
typedef struct { void* func_invocation_id; unsigned label; struct args arg; } jb_impl;

void __wasm_setjmp(void* env, unsigned label, void* func_invocation_id) {
  jb_impl* jb = (jb_impl*)env;
  jb->func_invocation_id = func_invocation_id;
  jb->label = label;
}
unsigned __wasm_setjmp_test(void* env, void* func_invocation_id) {
  jb_impl* jb = (jb_impl*)env;
  return (jb->func_invocation_id == func_invocation_id) ? jb->label : 0;
}
__attribute__((noreturn)) void __wasm_longjmp(void* env, int val) {
  jb_impl* jb = (jb_impl*)env;
  if (val == 0) val = 1;
  jb->arg.env = env;
  jb->arg.val = val;
  __builtin_wasm_throw(1, &jb->arg);
}

__asm__(".globl __c_longjmp\n.tagtype __c_longjmp i32\n__c_longjmp:\n");
