/* Two JSPI-path behaviors:
 * 1. sa_mask: signals named in a handler's mask stay BLOCKED while it runs
 *    (rt_sigaction never captured sa_mask before — handlers could re-enter).
 * 2. getppid(): a real (asyncify) forked child sees its parent's pid, and the
 *    value survives the child's execve (was a hardcoded 1). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static volatile int seq = 0, in1_at = 0, in2_at = 0;
static void on_usr2(int sig) { (void)sig; in2_at = ++seq; }
static void on_usr1(int sig) { (void)sig;
  kill(getpid(), SIGUSR2);      /* must stay pending: sa_mask blocks USR2 here */
  getpid(); getpid();           /* syscall boundaries — delivery chances */
  in1_at = ++seq;               /* if USR2 ran first, its seq is lower */
}
int main(int argc, char **argv) {
  if (argc > 2 && !strcmp(argv[1], "ppid")) return getppid() == atoi(argv[2]) ? 0 : 3;
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr2; CK(sigaction(SIGUSR2, &sa, NULL) == 0);
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigemptyset(&sa.sa_mask); sigaddset(&sa.sa_mask, SIGUSR2);
  CK(sigaction(SIGUSR1, &sa, NULL) == 0);
  kill(getpid(), SIGUSR1);
  getpid();                     /* boundary: USR1 delivers (USR2 after it returns) */
  getpid();
  CK(in1_at > 0 && in2_at > 0);
  CK(in1_at < in2_at);          /* USR2 ran only AFTER the USR1 handler finished */
  /* ppid across fork and exec */
  pid_t me = getpid();
  pid_t pid = fork();
  CK(pid >= 0);
  if (pid == 0) {
    if (getppid() != me) _exit(4);
    char pp[16]; snprintf(pp, sizeof pp, "%d", (int)me);
    char *cargv[] = { argv[0], "ppid", pp, NULL };
    execve("/proc/self/exe", cargv, NULL);
    _exit(9);
  }
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  printf("PASS\n"); return 0;
}
