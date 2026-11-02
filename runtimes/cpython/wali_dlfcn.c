/* dlopen/dlsym for walios: the kernel loads a PIC wasm side module into this process
 * (shared memory + table) and hands back an index; dlsym answers a table index, i.e. a
 * function pointer. musl static libc only has stubs ("Dynamic loading not supported").
 * Handles are kernel index + 1 so that a valid handle is never NULL. The kernel answers -2
 * for a side module built for the other walios ABI (wali.abi marker: 32- vs 64-bit long). */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

__attribute__((import_module("env"), import_name("__wali_dlopen")))
int __wali_dlopen(const char *path, int flags);
__attribute__((import_module("env"), import_name("__wali_dlsym")))
int __wali_dlsym(int handle, const char *sym);

static char errbuf[512];
static int have_err;

void *dlopen(const char *path, int flags)
{
	if (!path) { snprintf(errbuf, sizeof errbuf, "dlopen(NULL): no handle for the main program"); have_err = 1; return 0; }
	int h = __wali_dlopen(path, flags);
	if (h == -2) { snprintf(errbuf, sizeof errbuf, "%s: built for the other walios ABI (this program's long is %d-bit)", path, (int)(8 * sizeof(long))); have_err = 1; return 0; }
	if (h < 0) { snprintf(errbuf, sizeof errbuf, "%s: cannot load shared object", path); have_err = 1; return 0; }
	return (void *)(intptr_t)(h + 1);
}

void *dlsym(void *restrict handle, const char *restrict sym)
{
	int h = (int)(intptr_t)handle - 1;
	int f = h < 0 ? -1 : __wali_dlsym(h, sym);
	if (f < 0) { snprintf(errbuf, sizeof errbuf, "%s: undefined symbol", sym); have_err = 1; return 0; }
	return (void *)(intptr_t)f;
}

char *dlerror(void)
{
	if (!have_err) return 0;
	have_err = 0;
	return errbuf;
}

int dlclose(void *handle) { (void)handle; return 0; }
