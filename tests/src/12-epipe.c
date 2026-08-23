/* Writing to a pipe/socketpair whose read side is gone must fail with EPIPE
 * (the host models SIGPIPE-by-default as the error return; handlers are stubs). */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  signal(SIGPIPE, SIG_IGN);
  int p[2]; CK(pipe(p) == 0);
  CK(close(p[0]) == 0);                       /* read end gone */
  errno = 0; CK(write(p[1], "x", 1) == -1); CK(errno == EPIPE);
  CK(close(p[1]) == 0);
  int sv[2]; CK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  CK(close(sv[1]) == 0);                      /* peer gone */
  errno = 0; CK(write(sv[0], "x", 1) == -1); CK(errno == EPIPE);
  CK(close(sv[0]) == 0);
  printf("PASS\n"); return 0;
}
