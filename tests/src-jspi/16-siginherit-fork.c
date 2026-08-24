/* fork() must inherit signal dispositions and the blocked mask (POSIX). Before
 * the fix, an asyncify-forked child got an EMPTY handler table, so a signal the
 * parent had a handler for killed the child via the default action. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static volatile int got = 0;
static void on_usr1(int sig) { (void)sig; got = 1; }
int main(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1; sa.sa_flags = SA_RESTART;
  CK(sigaction(SIGUSR1, &sa, NULL) == 0);
  /* block USR2 pre-fork: the mask must survive into the child too */
  sigset_t bl; sigemptyset(&bl); sigaddset(&bl, SIGUSR2);
  CK(sigprocmask(SIG_BLOCK, &bl, NULL) == 0);
  pid_t pid = fork();
  CK(pid >= 0);
  if (pid == 0) {                       /* child: inherited handler must run */
    kill(getpid(), SIGUSR1);
    getpid();                           /* a syscall boundary so delivery lands */
    if (!got) _exit(3);                 /* handler lost -> would have died 138 anyway */
    sigset_t cur; sigemptyset(&cur);
    sigprocmask(SIG_BLOCK, NULL, &cur);
    if (!sigismember(&cur, SIGUSR2)) _exit(4);  /* blocked mask lost */
    _exit(0);
  }
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  printf("PASS\n"); return 0;
}
