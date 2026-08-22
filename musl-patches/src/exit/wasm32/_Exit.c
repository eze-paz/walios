#include <stdlib.h>
#include "syscall.h"

_Noreturn void __wali_child_return(void);

_Noreturn void _Exit(int ec)
{
	long r = __syscall_SYS_exit_group(ec);
	if (r == 0x7e57) __wali_child_return();
	__syscall_SYS_exit(ec);
	for (;;);
}
