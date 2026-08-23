/* Live shared memory across fork: child increments a counter and a flag in a
 * SysV shm segment; parent polls the SAME segment and sees the update (proving
 * cross-process coherence at syscall boundaries, not just attach/detach). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static void napms(long ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&t, NULL); }
int main(void) {
  int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600); CK(id >= 0);
  volatile int *p = shmat(id, NULL, 0); CK(p != (void *)-1);
  p[0] = 0; p[1] = 0;                 /* [0]=counter [1]=done flag */
  pid_t pid = fork();
  if (pid == 0) {
    volatile int *c = shmat(id, NULL, 0); if (c == (void *)-1) _exit(2);
    for (int i = 1; i <= 5; i++) { c[0] = i; napms(20); }
    c[1] = 1;                          /* signal done */
    shmdt((void *)c);
    _exit(0);
  }
  CK(pid > 0);
  int last = 0, saw = 0;
  for (int spins = 0; spins < 500 && !p[1]; spins++) { if (p[0] != last) { last = p[0]; saw++; } napms(10); }
  CK(p[1] == 1);                       /* saw the done flag the child set */
  CK(p[0] == 5);                       /* final counter value visible */
  CK(saw >= 2);                        /* observed intermediate updates, i.e. LIVE */
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  shmdt((void *)p);
  shmctl(id, IPC_RMID, NULL);
  printf("PASS\n"); return 0;
}
