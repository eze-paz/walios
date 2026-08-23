/* /proc/self/fd/N readlink — what musl ttyname_r walks (sshd pty allocation),
 * and the dev/ino identity contract between fstat(fd) and stat(ttyname). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  int m = posix_openpt(O_RDWR); CK(m >= 0);
  CK(grantpt(m) == 0); CK(unlockpt(m) == 0);
  char *sn = ptsname(m); CK(sn != NULL);
  int s = open(sn, O_RDWR); CK(s >= 0);
  char link[64]; snprintf(link, sizeof link, "/proc/self/fd/%d", s);
  char tgt[256]; ssize_t n = readlink(link, tgt, sizeof tgt - 1); CK(n > 0); tgt[n] = 0;
  CK(!strcmp(tgt, sn));                       /* fd resolves back to the pts path */
  char *tn = ttyname(s); CK(tn != NULL);      /* the real consumer of the above */
  CK(!strcmp(tn, sn));
  struct stat a, b; CK(fstat(s, &a) == 0); CK(stat(sn, &b) == 0);
  CK(a.st_dev == b.st_dev && a.st_ino == b.st_ino); /* identity musl requires */
  close(s); close(m);
  printf("PASS\n"); return 0;
}
