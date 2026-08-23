/* Parent and exec-child alternate over a pipe: requires the concurrent
 * scheduler (a blocking read in one process must suspend, not deadlock). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "child")) {
    char b[8] = {0};
    if (read(0, b, 4) != 4 || memcmp(b, "ping", 4)) _exit(3);
    if (write(1, "pong", 4) != 4) _exit(4);
    _exit(7);
  }
  int up[2], down[2];
  if (pipe(up) || pipe(down)) { printf("FAIL pipe\n"); return 1; }
  pid_t pid = vfork();
  if (pid == 0) {
    dup2(up[0], 0); dup2(down[1], 1);
    close(up[0]); close(up[1]); close(down[0]); close(down[1]);
    char *cargv[] = { argv[0], "child", NULL };
    execve("/proc/self/exe", cargv, NULL);
    _exit(9);
  }
  close(up[0]); close(down[1]);
  if (write(up[1], "ping", 4) != 4) { printf("FAIL write\n"); return 1; }
  char b[8] = {0};
  if (read(down[0], b, 4) != 4 || memcmp(b, "pong", 4)) { printf("FAIL read\n"); return 1; }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 7) { printf("FAIL wait\n"); return 1; }
  printf("PASS\n"); return 0;
}
