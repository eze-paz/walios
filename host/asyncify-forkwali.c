// Real fork() (SYS_fork) on full musl, to test the host's Asyncify fork substrate.
// Build with -D__WALI_ASYNCIFY_FORK so fork() is the real function, not the vfork macro.
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
int main(void) {
  printf("before fork (pid=%d)\n", getpid()); fflush(stdout);
  pid_t p = fork();
  if (p == 0) {
    for (int i = 0; i < 3; i++) { printf("  child  i=%d\n", i); fflush(stdout); }
    _exit(7);
  } else {
    for (int i = 0; i < 3; i++) { printf("parent i=%d (child=%d)\n", i, p); fflush(stdout); }
    int st = 0; pid_t w = wait(&st);
    printf("reaped %d status=%d\n", w, WEXITSTATUS(st)); fflush(stdout);
  }
  return 0;
}
