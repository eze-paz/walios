/* wasm32-wali vfork machinery: the child branch runs in-place in the parent
 * instance (host tracks an fd overlay); execve/_Exit in child mode make the
 * host return 0x7e57, and libc longjmps back to the fork point, which lives
 * in the CALLER frame (fork/vfork are statement-expression macros). */
#include <setjmp.h>
#include <errno.h>
#include "syscall.h"

#define MAXD 16
static jmp_buf jbs[MAXD];
static long pids[MAXD];
static int depth;

long __wali_fork_begin(void)
{
	long pid = __syscall_SYS_fork();
	if (pid < 0) {
		errno = -pid;
		return -1;
	}
	if (depth >= MAXD) {
		errno = EAGAIN;
		return -1;
	}
	pids[depth++] = pid;
	return pid;
}

void *__wali_fork_jbuf(void)
{
	return &jbs[depth-1];
}

long __wali_fork_finish(void)
{
	return pids[--depth];
}

_Noreturn void __wali_child_return(void)
{
	longjmp(jbs[depth-1], 1);
}
