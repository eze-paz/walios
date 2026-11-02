/* posixmodule.c is compiled with -D__WALI_LIBC_INTERNAL -Dfork=__wali_nofork
 * -Dforkpty=__wali_noforkpty. walios forks with the vfork protocol (the fork() macro in
 * unistd.h): the child branch runs in the parent until it execs or exits, which only
 * works when that happens before the forking C function returns -- _posixsubprocess
 * does exactly that. os.fork()/os.forkpty() return into Python with the child still
 * running in the parent, so they must say ENOSYS instead (the libc fork() function
 * would be answered with a pid by the kernel and the child would never run). */
#include <errno.h>
#include <sys/types.h>
struct termios; struct winsize;
pid_t __wali_nofork(void) { errno = ENOSYS; return -1; }
pid_t __wali_noforkpty(int *m, char *n, const struct termios *t, const struct winsize *w)
{ (void)m; (void)n; (void)t; (void)w; errno = ENOSYS; return -1; }
