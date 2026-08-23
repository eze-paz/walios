#define _GNU_SOURCE
/* Credentials: root by default, POSIX setuid drop is one-way, ids survive
 * exec (child re-checks after the parent dropped privileges). */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "child")) { /* exec'd AFTER the drop */
    if (getuid() != 1000 || geteuid() != 1000) { printf("FAIL child uid=%d euid=%d\n", (int)getuid(), (int)geteuid()); return 1; }
    return 7;
  }
  CK(getuid() == 0 && geteuid() == 0);          /* boots as root */
  CK(setgid(100) == 0);                          /* root may set any gid */
  CK(getgid() == 100 && getegid() == 100);
  CK(setuid(1000) == 0);                         /* drop */
  CK(getuid() == 1000 && geteuid() == 1000);
  errno = 0; CK(setuid(0) == -1 && errno == EPERM);   /* one-way */
  errno = 0; CK(setgid(0) == -1 && errno == EPERM);
  CK(setuid(1000) == 0);                         /* no-op re-set allowed */
  uid_t r, e, s2; CK(getresuid(&r, &e, &s2) == 0); CK(r == 1000 && e == 1000 && s2 == 1000);
  pid_t pid = vfork();
  if (pid == 0) { char *cargv[] = { argv[0], "child", NULL }; execve("/proc/self/exe", cargv, NULL); _exit(9); }
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 7);     /* child saw the dropped ids */
  printf("PASS\n"); return 0;
}
