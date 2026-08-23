/* Timers as first-class OS behavior: SIGALRM handler invocation (needs the
 * binary linked with --export-table), EINTR on interrupted sleep, interval
 * itimers, getitimer remaining-time, timerfd blocking reads, absolute sleeps. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static volatile int alarms = 0;
static void on_alrm(int sig) { if (sig == SIGALRM) alarms++; }
static long ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
int main(void) {
  CK(signal(SIGALRM, on_alrm) != SIG_ERR);

  /* one-shot alarm interrupts a long sleep: handler runs, sleep returns early */
  struct itimerval one = { { 0, 0 }, { 0, 80000 } }; /* 80ms */
  CK(setitimer(ITIMER_REAL, &one, NULL) == 0);
  struct itimerval rem; CK(getitimer(ITIMER_REAL, &rem) == 0);
  CK(rem.it_value.tv_sec == 0 && rem.it_value.tv_usec > 0 && rem.it_value.tv_usec <= 80000);
  long t0 = ms();
  struct timespec nap = { 5, 0 };
  errno = 0; int r = nanosleep(&nap, NULL);
  CK(r == -1 && errno == EINTR);      /* interrupted, NOT a 5s wait */
  CK(alarms == 1);
  CK(ms() - t0 < 3000);

  /* interval timer: ticks repeatedly until disarmed */
  struct itimerval iv = { { 0, 30000 }, { 0, 30000 } }; /* every 30ms */
  CK(setitimer(ITIMER_REAL, &iv, NULL) == 0);
  int base = alarms;
  while (alarms < base + 3) { struct timespec n2 = { 1, 0 }; nanosleep(&n2, NULL); }
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  CK(setitimer(ITIMER_REAL, &off, NULL) == 0);

  /* pause(): returns EINTR after a delivered signal */
  struct itimerval p1 = { { 0, 0 }, { 0, 50000 } };
  CK(setitimer(ITIMER_REAL, &p1, NULL) == 0);
  errno = 0; CK(pause() == -1 && errno == EINTR);

  /* timerfd: blocking read returns the expiration count */
  int tfd = timerfd_create(CLOCK_MONOTONIC, 0); CK(tfd >= 0);
  struct itimerspec its = { { 0, 0 }, { 0, 60000000 } }; /* 60ms one-shot */
  CK(timerfd_settime(tfd, 0, &its, NULL) == 0);
  unsigned long long cnt = 0; t0 = ms();
  CK(read(tfd, &cnt, sizeof cnt) == 8);
  CK(cnt >= 1); CK(ms() - t0 >= 40);
  CK(close(tfd) == 0);

  /* clock_nanosleep TIMER_ABSTIME: sleep to a monotonic deadline */
  struct timespec now; CK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  struct timespec until = { now.tv_sec, now.tv_nsec + 60000000L };
  if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
  t0 = ms();
  CK(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL) == 0);
  long el = ms() - t0; CK(el >= 40 && el < 5000);

  struct timespec res; CK(clock_getres(CLOCK_MONOTONIC, &res) == 0); CK(res.tv_nsec > 0);
  printf("PASS\n"); return 0;
}
