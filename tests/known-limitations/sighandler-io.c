/* A signal handler that makes syscalls (I/O) must run without trapping under
 * JSPI. Before the inSigHandler fix, a handler that called any syscall hit
 * "trying to suspend without WebAssembly.promising" (this is what killed
 * busybox ping, whose SIGALRM handler sends the next echo). setitimer drives
 * a repeating SIGALRM; the handler writes to a pipe each time. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
static int wfd;
static volatile int ticks = 0;
static void on_alrm(int sig) {
  (void)sig;
  const char b = 'a';
  write(wfd, &b, 1);   /* a syscall INSIDE the handler — must not trap */
  ticks++;
}
int main(void) {
  int p[2];
  CK(pipe(p) == 0);
  wfd = p[1];
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_alrm; sa.sa_flags = SA_RESTART;
  CK(sigaction(SIGALRM, &sa, NULL) == 0);
  struct itimerval iv = { { 0, 40000 }, { 0, 40000 } };   /* 40 ms repeating */
  CK(setitimer(ITIMER_REAL, &iv, NULL) == 0);
  /* wait for 3 handler runs; each handler write() makes the read side readable */
  char buf[8];
  for (int got = 0; got < 3; ) {
    ssize_t n = read(p[0], buf, sizeof buf);   /* interruptible; handler feeds it */
    if (n > 0) got += n;
  }
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  setitimer(ITIMER_REAL, &off, NULL);
  CK(ticks >= 3);   /* handler actually ran, repeatedly, doing I/O */
  printf("PASS\n"); return 0;
}
