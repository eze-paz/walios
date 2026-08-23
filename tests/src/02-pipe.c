#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  int p[2]; CK(pipe(p) == 0);
  CK(write(p[1], "ping", 4) == 4);
  char buf[8] = {0}; CK(read(p[0], buf, 4) == 4); CK(!strcmp(buf, "ping"));
  /* O_NONBLOCK on empty pipe must be EAGAIN, not a hang */
  CK(fcntl(p[0], F_SETFL, O_NONBLOCK) == 0);
  errno = 0; CK(read(p[0], buf, 4) == -1); CK(errno == EAGAIN);
  /* dup2 the write end onto a new fd and write through it */
  int d = dup(p[1]); CK(d >= 0);
  CK(write(d, "pong", 4) == 4);
  CK(read(p[0], buf, 4) == 4); CK(!memcmp(buf, "pong", 4));
  /* EOF after both write ends close */
  CK(close(p[1]) == 0); CK(close(d) == 0);
  CK(fcntl(p[0], F_SETFL, 0) == 0);
  CK(read(p[0], buf, 4) == 0);
  CK(close(p[0]) == 0);
  printf("PASS\n"); return 0;
}
