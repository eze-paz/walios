/* closefrom(): glibc 2.34+/BSD, not in this musl. Weak: a package that brings its own (doas,
   OpenBSD's int-returning one) links that instead of clashing with this signature. */
#include <unistd.h>
__attribute__((weak)) void closefrom(int lowfd) { for (int fd = lowfd < 0 ? 0 : lowfd; fd < 1024; fd++) close(fd); }
