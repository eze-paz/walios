/* Signals as walios models them today: handlers/masks are accepted (stubs),
 * kill(pid,0) is a liveness probe, and a fatal signal terminates the process
 * with exit code 128+sig (the host reports it as an exit, not WIFSIGNALED). */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "die")) { raise(SIGTERM); return 1; /* unreachable */ }
  CK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = SIG_IGN;
  CK(sigaction(SIGUSR1, &sa, NULL) == 0);
  sigset_t set; sigemptyset(&set); sigaddset(&set, SIGUSR2);
  CK(sigprocmask(SIG_BLOCK, &set, NULL) == 0);
  CK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0);
  CK(kill(getpid(), 0) == 0);            /* probe must NOT kill us */
  pid_t pid = vfork();
  if (pid == 0) {
    char *cargv[] = { argv[0], "die", NULL };
    execve("/proc/self/exe", cargv, NULL);
    _exit(9);
  }
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 128 + SIGTERM);
  printf("PASS\n"); return 0;
}
