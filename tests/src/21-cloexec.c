/* FD_CLOEXEC must be tracked (open O_CLOEXEC, pipe2, fcntl F_SETFD, F_DUPFD_CLOEXEC,
 * dup clearing it) and HONORED at execve: marked fds vanish from the exec'd image.
 * ash keeps its job-control ttyfd on a high CLOEXEC fd — leaking it into every
 * child is the classic source of "Bad file descriptor" job-control corruption. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
  if (argc > 3 && !strcmp(argv[1], "probe")) {          /* exec'd image: check inherited fds */
    int keep = atoi(argv[2]), gone = atoi(argv[3]);
    if (write(keep, "X", 1) != 1) return 3;             /* non-cloexec pipe end survives */
    errno = 0;
    if (write(gone, "Y", 1) != -1 || errno != EBADF) return 4; /* cloexec end must be GONE */
    return 0;
  }
  /* flag bookkeeping */
  int p[2]; CK(pipe2(p, O_CLOEXEC) == 0);
  CK(fcntl(p[0], F_GETFD) == FD_CLOEXEC);
  int d = dup(p[0]); CK(d >= 0);
  CK(fcntl(d, F_GETFD) == 0);                           /* dup clears FD_CLOEXEC */
  int dc = fcntl(p[0], F_DUPFD_CLOEXEC, 20); CK(dc >= 20);
  CK(fcntl(dc, F_GETFD) == FD_CLOEXEC);
  CK(fcntl(d, F_SETFD, FD_CLOEXEC) == 0);
  CK(fcntl(d, F_GETFD) == FD_CLOEXEC);
  close(d); close(dc); close(p[0]); close(p[1]);
  /* exec honoring: keep = plain pipe write end; gone = O_CLOEXEC-marked write end */
  int keep[2], gone[2];
  CK(pipe(keep) == 0);
  CK(pipe(gone) == 0);
  CK(fcntl(gone[1], F_SETFD, FD_CLOEXEC) == 0);
  pid_t pid = vfork();
  if (pid == 0) {
    char k[16], g[16];
    snprintf(k, sizeof k, "%d", keep[1]); snprintf(g, sizeof g, "%d", gone[1]);
    char *cargv[] = { argv[0], "probe", k, g, NULL };
    execve("/proc/self/exe", cargv, NULL);
    _exit(9);
  }
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  char b = 0; CK(read(keep[0], &b, 1) == 1 && b == 'X');
  /* the probe's cloexec end was dropped at exec, so with ours closed too the
   * reader must see EOF (refcount released, not leaked) */
  close(gone[1]);
  CK(read(gone[0], &b, 1) == 0);
  printf("PASS\n"); return 0;
}
