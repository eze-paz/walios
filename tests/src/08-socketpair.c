/* AF_UNIX socketpair (the sshd privsep transport): full-duplex, EOF on close. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  int sv[2];
  CK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  CK(write(sv[0], "abcd", 4) == 4);
  char b[8] = {0}; CK(read(sv[1], b, 4) == 4); CK(!memcmp(b, "abcd", 4));
  CK(write(sv[1], "efgh", 4) == 4);        /* reverse direction */
  CK(read(sv[0], b, 4) == 4); CK(!memcmp(b, "efgh", 4));
  int one = 1;
  CK(setsockopt(sv[0], SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) == 0);
  CK(close(sv[0]) == 0);
  CK(read(sv[1], b, 4) == 0);              /* peer closed -> EOF, not hang */
  CK(close(sv[1]) == 0);
  printf("PASS\n"); return 0;
}
