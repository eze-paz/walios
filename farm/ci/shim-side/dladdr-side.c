/* dladdr for a side module whose runtime does not export it (lua.wasm, perl.wasm, python):
 * returns 0 ("address not found"), which callers treat as no symbol information (cqueues and
 * luaossl use it only to name the module's own file). Linked (wali-cc, $WALI_SIDE without
 * dladdr) only when something references it. */
#define _GNU_SOURCE
#include <dlfcn.h>

__attribute__((visibility("hidden")))
int dladdr(const void *addr, Dl_info *info) {
  (void)addr; (void)info;
  return 0;
}
