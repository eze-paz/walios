#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static long ms(struct timespec t) { return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
int main(void) {
  struct timespec a, b;
  CK(clock_gettime(CLOCK_MONOTONIC, &a) == 0);
  struct timespec nap = { 0, 50 * 1000000L };
  CK(nanosleep(&nap, NULL) == 0);
  CK(clock_gettime(CLOCK_MONOTONIC, &b) == 0);
  long el = ms(b) - ms(a);
  CK(el >= 40); CK(el < 5000);
  struct timeval tv; CK(gettimeofday(&tv, NULL) == 0);
  CK(tv.tv_sec > 1600000000L); /* wall clock is after 2020 */
  time_t t = time(NULL); CK(t > 1600000000L);
  printf("PASS\n"); return 0;
}
