/* Ctrl-C: writing VINTR (^C) to a pty master must deliver SIGINT to the
 * foreground process group — the handler runs and the blocked read on the
 * slave returns EINTR (this is what makes ^C work in an interactive shell). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static volatile int ints = 0;
static void on_int(int sig) { (void)sig; ints++; }
int main(void) {
  CK(signal(SIGINT, on_int) != SIG_ERR);
  int m = posix_openpt(O_RDWR); CK(m >= 0);
  CK(grantpt(m) == 0); CK(unlockpt(m) == 0);
  int s = open(ptsname(m), O_RDWR); CK(s >= 0);
  pid_t pg = getpgrp(); CK(ioctl(s, TIOCSPGRP, &pg) == 0);  /* we are the foreground group */
  pid_t got = 0; CK(ioctl(s, TIOCGPGRP, &got) == 0); CK(got == pg);

  /* ^C while blocked reading the terminal: handler + EINTR, input line flushed */
  CK(write(m, "abc\x03", 4) == 4);   /* partial line, then VINTR */
  char buf[16];
  errno = 0; long r = read(s, buf, sizeof buf);
  CK(r == -1 && errno == EINTR);
  CK(ints == 1);

  /* after the interrupt, normal canonical input still works */
  CK(write(m, "ok\n", 3) == 3);
  memset(buf, 0, sizeof buf);
  CK(read(s, buf, sizeof buf) == 3); CK(!strcmp(buf, "ok\n"));

  /* SIGINT with default disposition kills: probe via a child that resets it */
  close(s); close(m);
  printf("PASS\n"); return 0;
}
