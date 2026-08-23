/* Preemption (JSPI): a syscalling busy-loop child must NOT starve the parent —
 * the parent's timed sleep completes while the child spins, and kill() then
 * terminates the spinner. Requires the quantum yield in the syscall gate. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static long ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
int main(void) {
  pid_t pid = fork();
  if (pid == 0) {                      /* spinner: hot loop of cheap syscalls */
    for (;;) (void)getpid();
    _exit(0);
  }
  CK(pid > 0);
  long t0 = ms();
  struct timespec nap = { 0, 150 * 1000000L };
  CK(nanosleep(&nap, NULL) == 0);      /* must complete while the child spins */
  long el = ms() - t0;
  CK(el >= 100 && el < 2000);          /* not starved until child end (child never ends) */
  CK(kill(pid, SIGTERM) == 0);         /* and we can kill the spinner */
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 128 + SIGTERM);
  printf("PASS\n"); return 0;
}
