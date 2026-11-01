/* closefrom(): glibc 2.34+/BSD, not in this musl. */
#include <unistd.h>
void closefrom(int lowfd) { for (int fd = lowfd < 0 ? 0 : lowfd; fd < 1024; fd++) close(fd); }
