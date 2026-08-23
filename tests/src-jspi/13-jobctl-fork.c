/* Job control (JSPI): SIGSTOP parks a spinning child (it stops making
 * progress), wait4 WUNTRACED reports it, SIGCONT resumes it, TERM ends it. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static void napms(long ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&t, NULL); }
int main(void) {
  pid_t pid = fork();
  if (pid == 0) { for (;;) (void)getpid(); _exit(0); }   /* spinner */
  CK(pid > 0);
  napms(50);
  CK(kill(pid, SIGSTOP) == 0);
  napms(100);                                            /* let the stop land at a syscall boundary */
  int st = 0;
  pid_t r = waitpid(pid, &st, WUNTRACED | WNOHANG);
  CK(r == pid);                                          /* reported as stopped */
  CK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
  r = waitpid(pid, &st, WUNTRACED | WNOHANG);            /* reported only once */
  CK(r == 0);
  CK(kill(pid, SIGCONT) == 0);
  napms(50);
  CK(kill(pid, SIGTERM) == 0);                           /* only lands if it resumed */
  CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 128 + SIGTERM);
  printf("PASS\n"); return 0;
}
