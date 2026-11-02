#include <unistd.h>
#include "syscall.h"

/* The SYS_lseek import returns the 64-bit offset (i64); musl's generic lseek passes it
 * through __syscall_ret(unsigned long), which keeps 32 bits once long is 32-bit. */
off_t __lseek(int fd, off_t offset, int whence)
{
	long long r = __syscall_SYS_lseek(fd, offset, whence);
	if (r < 0 && r > -4096) {
		errno = -r;
		return -1;
	}
	return r;
}

weak_alias(__lseek, lseek);
