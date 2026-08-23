#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  int m = posix_openpt(O_RDWR); CK(m >= 0);
  CK(grantpt(m) == 0); CK(unlockpt(m) == 0);
  char *sn = ptsname(m); CK(sn != NULL); CK(!strncmp(sn, "/dev/pts/", 9));
  int s = open(sn, O_RDWR); CK(s >= 0);
  CK(isatty(s) == 1); CK(isatty(m) == 1);
  struct termios tio; CK(tcgetattr(s, &tio) == 0);
  tio.c_lflag &= ~(ECHO); CK(tcsetattr(s, TCSANOW, &tio) == 0);
  CK(write(m, "hi\n", 3) == 3);           /* canonical mode: delivered at newline */
  char buf[16] = {0}; CK(read(s, buf, sizeof buf) == 3); CK(!strcmp(buf, "hi\n"));
  CK(write(s, "yo", 2) == 2);             /* slave->master with ONLCR untouched */
  char b2[16] = {0}; CK(read(m, b2, sizeof b2) == 2); CK(!memcmp(b2, "yo", 2));
  close(s); close(m);
  printf("PASS\n"); return 0;
}
