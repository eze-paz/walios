#include <features.h>

/* rt_sigaction's record, byte for byte what WALI's wasm32 passes (handler@0, 64-bit flags@4,
 * restorer@12, mask@16, packed), so the kernel reads both ABIs the same way. */
struct __attribute__((packed)) k_sigaction {
	void (*handler)(int);
	unsigned long flags;
	unsigned long __flags_hi;
	void (*restorer)(void);
	unsigned mask[2];
};

hidden void __restore() __attribute((
  __import_module__("wali"),
  __import_name__("__restore")
));

hidden void __restore_rt() __attribute((
  __import_module__("wali"),
  __import_name__("__restore_rt")
));
