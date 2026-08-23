#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "child")) { printf("child %s\n", getenv("WT") ? getenv("WT") : "?"); return 7; }
  pid_t pid = vfork();
  if (pid == 0) {
    char *cargv[] = { argv[0], "child", NULL };
    char *cenvp[] = { "WT=inherited", NULL };
    execve("/proc/self/exe", cargv, cenvp);
    _exit(9);
  }
  if (pid < 0) { printf("FAIL vfork\n"); return 1; }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid) { printf("FAIL waitpid\n"); return 1; }
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) { printf("FAIL status=%d\n", st); return 1; }
  printf("PASS\n"); return 0;
}
