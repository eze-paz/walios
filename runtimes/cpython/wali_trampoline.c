/* CPython's call trampoline for walios (Include/internal/pycore_emscripten_trampoline.h,
 * patched by build.sh to use it on non-Emscripten wasm).
 *
 * C extensions routinely register a METH_NOARGS method as `f(PyObject *self)` or a getter
 * as `get(PyObject *self)` and let CPython call it with one more argument. Every native
 * ABI ignores the extra argument; wasm's call_indirect traps on the signature mismatch
 * ("function signature mismatch", kiwisolver's Variable.value() is the first one met).
 * CPython has the fix only for Emscripten, where it goes through JS. Here it stays in wasm
 * (a JS frame would break JSPI suspension in the callee): clang's
 * __builtin_wasm_test_function_pointer_signature is a ref.test on the table entry, so the
 * call is made with exactly as many arguments as the function takes.
 *
 * Python.h is not available when build.sh compiles this, so the types are spelled out:
 * every argument and the result are pointers or int, all i32 here. */

typedef void *(*wali_f3)(void *, void *, void *);
typedef void *(*wali_f2)(void *, void *);
typedef void *(*wali_f1)(void *);
typedef void *(*wali_f0)(void);

extern void *PyExc_SystemError;
void PyErr_SetString(void *exception, const char *message);

void *_PyWali_TrampolineCall(wali_f3 func, void *a, void *b, void *c)
{
	if (__builtin_wasm_test_function_pointer_signature(func)) return func(a, b, c);
	if (__builtin_wasm_test_function_pointer_signature((wali_f2)func)) return ((wali_f2)func)(a, b);
	if (__builtin_wasm_test_function_pointer_signature((wali_f1)func)) return ((wali_f1)func)(a);
	if (__builtin_wasm_test_function_pointer_signature((wali_f0)func)) return ((wali_f0)func)();
	PyErr_SetString(PyExc_SystemError, "Handler takes too many arguments");
	return 0;
}
