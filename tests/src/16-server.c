/* Inbound networking: socket/bind/listen/getsockname/accept on a real TCP
 * port, self-connect over loopback, byte exchange both directions. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  int ls = socket(AF_INET, SOCK_STREAM, 0); CK(ls >= 0);
  struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0; /* ephemeral */
  CK(bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0);
  CK(listen(ls, 4) == 0);
  struct sockaddr_in bound; socklen_t bl = sizeof bound;
  CK(getsockname(ls, (struct sockaddr *)&bound, &bl) == 0);
  CK(ntohs(bound.sin_port) > 0);

  int c = socket(AF_INET, SOCK_STREAM, 0); CK(c >= 0);
  struct sockaddr_in dst; memset(&dst, 0, sizeof dst);
  dst.sin_family = AF_INET; dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK); dst.sin_port = bound.sin_port;
  CK(connect(c, (struct sockaddr *)&dst, sizeof dst) == 0);

  struct sockaddr_in peer; socklen_t pl = sizeof peer;
  int s = accept(ls, (struct sockaddr *)&peer, &pl); CK(s >= 0);

  CK(write(c, "ping", 4) == 4);
  char b[8] = {0}; CK(read(s, b, 4) == 4); CK(!memcmp(b, "ping", 4));
  CK(write(s, "pong", 4) == 4);
  memset(b, 0, sizeof b); CK(read(c, b, 4) == 4); CK(!memcmp(b, "pong", 4));

  CK(close(c) == 0); CK(close(s) == 0); CK(close(ls) == 0);
  printf("PASS\n"); return 0;
}
