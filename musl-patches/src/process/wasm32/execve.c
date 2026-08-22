#include <unistd.h>
#include "syscall.h"

_Noreturn void __wali_child_return(void);

int execve(const char *path, char *const argv[], char *const envp[])
{
	long r = __syscall_SYS_execve((char*)path, (void*)argv, (void*)envp);
	if (r == 0x7e57) __wali_child_return();
	return __syscall_ret(r);
}
