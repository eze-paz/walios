/* Canonical-mode VEOF (^D) on a pty: mid-line it flushes the pending line to the
 * slave (no newline); on an empty line it queues EOF — the next slave read()
 * returns 0 exactly once. Without this, `cat` on the terminal can never end.
 * Also: FIONREAD reports the buffered byte count. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  int m = posix_openpt(O_RDWR); CK(m >= 0);
  CK(grantpt(m) == 0); CK(unlockpt(m) == 0);
  char *sn = ptsname(m); CK(sn != NULL);
  int s = open(sn, O_RDWR); CK(s >= 0);
  struct termios tio; CK(tcgetattr(s, &tio) == 0);
  tio.c_lflag &= ~(ECHO); CK(tcsetattr(s, TCSANOW, &tio) == 0);
  char eof = tio.c_cc[VEOF]; CK(eof == 4);     /* ^D */
  char buf[32];
  /* mid-line ^D flushes the partial line without a newline */
  CK(write(m, "ab", 2) == 2);
  CK(write(m, &eof, 1) == 1);
  int avail = -1; CK(ioctl(s, FIONREAD, &avail) == 0); CK(avail == 2);
  memset(buf, 0, sizeof buf); CK(read(s, buf, sizeof buf) == 2); CK(!memcmp(buf, "ab", 2));
  /* ^D on an empty line = EOF: read returns 0, once */
  CK(write(m, &eof, 1) == 1);
  CK(read(s, buf, sizeof buf) == 0);
  /* the pty keeps working after the EOF */
  CK(write(m, "hi\n", 3) == 3);
  memset(buf, 0, sizeof buf); CK(read(s, buf, sizeof buf) == 3); CK(!strcmp(buf, "hi\n"));
  close(s); close(m);
  printf("PASS\n"); return 0;
}
