/* epoll (level-triggered): create/ctl/wait with real readiness and the packed
 * x86_64 epoll_event layout. CPython's asyncio uses EpollSelector — ENOSYS
 * killed `import asyncio` workloads outright. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/epoll.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
int main(void) {
  int ep = epoll_create1(0); CK(ep >= 0);
  int p[2]; CK(pipe(p) == 0);
  struct epoll_event ev; memset(&ev, 0, sizeof ev);
  ev.events = EPOLLIN; ev.data.u64 = 0xabcdef0011223344ULL;
  CK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == 0);
  errno = 0; CK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == -1 && errno == EEXIST);
  /* empty pipe: timeout must elapse and report 0 */
  struct epoll_event out[4];
  long t0 = now_ms();
  CK(epoll_wait(ep, out, 4, 120) == 0);
  CK(now_ms() - t0 >= 100);
  /* data arrives -> one event, with our data payload */
  CK(write(p[1], "x", 1) == 1);
  int n = epoll_wait(ep, out, 4, 1000);
  CK(n == 1);
  CK(out[0].events & EPOLLIN);
  CK(out[0].data.u64 == 0xabcdef0011223344ULL);
  /* MOD to EPOLLOUT interest on the write end: always ready */
  struct epoll_event ev2; memset(&ev2, 0, sizeof ev2);
  ev2.events = EPOLLOUT; ev2.data.u64 = 7;
  CK(epoll_ctl(ep, EPOLL_CTL_ADD, p[1], &ev2) == 0);
  char b; CK(read(p[0], &b, 1) == 1);                 /* drain so only OUT fires */
  n = epoll_wait(ep, out, 4, 1000);
  CK(n == 1 && (out[0].events & EPOLLOUT) && out[0].data.u64 == 7);
  /* DEL semantics */
  CK(epoll_ctl(ep, EPOLL_CTL_DEL, p[1], NULL) == 0);
  errno = 0; CK(epoll_ctl(ep, EPOLL_CTL_DEL, p[1], NULL) == -1 && errno == ENOENT);
  close(ep); close(p[0]); close(p[1]);
  printf("PASS\n"); return 0;
}
