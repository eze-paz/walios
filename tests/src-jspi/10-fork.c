/* Real fork() (Asyncify): returns twice, child is a memory copy. JSPI-only. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {
  int before = 1234;
  pid_t pid = fork();
  if (pid == 0) {
    if (before != 1234) { printf("FAIL child memory\n"); _exit(2); }
    before = 9999; /* must NOT be visible to parent */
    printf("child pid=%d\n", (int)getpid());
    _exit(7);
  }
  if (pid < 0) { printf("FAIL fork\n"); return 1; }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid) { printf("FAIL waitpid\n"); return 1; }
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) { printf("FAIL status=%d\n", st); return 1; }
  if (before != 1234) { printf("FAIL isolation before=%d\n", before); return 1; }
  printf("PASS\n"); return 0;
}
