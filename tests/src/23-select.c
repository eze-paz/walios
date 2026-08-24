/* select() must report real readiness and write the fd_sets back (it was a
 * return-1 stub that never touched the sets — busybox applets and python's
 * select module got garbage). Timeout must actually elapse and report 0. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
int main(void) {
  int full[2], empty[2];
  CK(pipe(full) == 0); CK(pipe(empty) == 0);
  CK(write(full[1], "z", 1) == 1);
  fd_set rf; FD_ZERO(&rf); FD_SET(full[0], &rf); FD_SET(empty[0], &rf);
  struct timeval tv = { 1, 0 };
  int n = select((full[0] > empty[0] ? full[0] : empty[0]) + 1, &rf, NULL, NULL, &tv);
  CK(n == 1);
  CK(FD_ISSET(full[0], &rf));                  /* has data */
  CK(!FD_ISSET(empty[0], &rf));                /* empty pipe must NOT be ready */
  /* write side is always ready */
  fd_set wf; FD_ZERO(&wf); FD_SET(empty[1], &wf);
  struct timeval tv2 = { 1, 0 };
  CK(select(empty[1] + 1, NULL, &wf, NULL, &tv2) == 1);
  CK(FD_ISSET(empty[1], &wf));
  /* timeout on a never-ready fd really elapses and reports 0 */
  fd_set rf2; FD_ZERO(&rf2); FD_SET(empty[0], &rf2);
  struct timeval tv3 = { 0, 120000 };          /* 120 ms */
  long t0 = now_ms();
  n = select(empty[0] + 1, &rf2, NULL, NULL, &tv3);
  long dt = now_ms() - t0;
  CK(n == 0);
  CK(!FD_ISSET(empty[0], &rf2));
  CK(dt >= 100);
  printf("PASS\n"); return 0;
}
