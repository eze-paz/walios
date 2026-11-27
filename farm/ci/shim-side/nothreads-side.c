/* pthread_create for a side module whose runtime cannot start threads (lua.wasm, perl.wasm
 * export the pthread mutex/key/once calls but no pthread_create). A dependency's archive that
 * can spawn a helper thread (c-ares' event thread, SQLite's sorter workers) left the module
 * unlinkable ("undefined symbol: pthread_create"); with this the call fails with EAGAIN, the
 * documented "no resources for another thread" result those libraries already handle.
 * Linked (wali-cc, $WALI_SIDE without pthread_create) only when something references it. */
#include <errno.h>
#include <pthread.h>

__attribute__((visibility("hidden")))
int pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) {
  (void)t; (void)a; (void)fn; (void)arg;
  return EAGAIN;
}
