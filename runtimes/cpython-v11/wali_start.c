/* Reactor-style constructors for a main that C extensions call into.
 * crt1.o never calls __wasm_call_ctors, so wasm-ld treated the link as a WASI command
 * and wrapped EVERY exported function to re-run the constructors on each call from a
 * side module (mimalloc re-printed its options to stderr each time: GBs of newlines on
 * `import numpy`). Referencing __wasm_call_ctors here turns that off; the constructors
 * run once, before main, via --wrap=__main_void. */
extern void __wasm_call_ctors(void);
extern int __real___main_void(void);

__attribute__((export_name("_initialize")))
void _initialize(void)
{
	static int done;
	if (done) return;
	done = 1;
	__wasm_call_ctors();
}

int __wrap___main_void(void)
{
	_initialize();
	return __real___main_void();
}
