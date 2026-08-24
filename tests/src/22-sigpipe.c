/* Writing to a pipe with no readers must raise SIGPIPE (default action kills the
 * writer with 128+13) — not just return EPIPE. Without it, `yes | head -1`-class
 * pipelines spin forever when the writer doesn't check write() errors.
 * With SIGPIPE ignored, the write still fails EPIPE (12-epipe covers that). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
  if (argc > 2 && !strcmp(argv[1], "victim")) {         /* fresh image: SIGPIPE is SIG_DFL */
    int wfd = atoi(argv[2]);
    write(wfd, "x", 1);                                 /* no readers -> SIGPIPE */
    getpid();                                           /* a syscall boundary so delivery lands */
    return 0;                                           /* reaching here = signal NOT delivered */
  }
  int p[2]; CK(pipe(p) == 0);
  CK(close(p[0]) == 0);                                 /* read end gone before the fork */
  pid_t pid = vfork();
  if (pid == 0) {
    char w[16]; snprintf(w, sizeof w, "%d", p[1]);
    char *cargv[] = { argv[0], "victim", w, NULL };
    execve("/proc/self/exe", cargv, NULL);
    _exit(9);
  }
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  /* the host encodes signal-death as exit(128+sig) */
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 128 + SIGPIPE);
  printf("PASS\n"); return 0;
}
