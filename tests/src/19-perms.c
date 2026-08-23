/* Permission enforcement: umask shapes create modes, chmod'ing away write
 * access makes open/access fail with EACCES for a non-root process, chown
 * is root-only. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  const char *f = "/tmp/wali-perm-test.txt";
  unlink(f);
  mode_t old = umask(027);
  int fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0666); CK(fd >= 0);
  CK(write(fd, "x", 1) == 1); CK(close(fd) == 0);
  struct stat st; CK(stat(f, &st) == 0);
  CK((st.st_mode & 0777) == 0640);              /* 0666 & ~027 */
  umask(old);

  CK(setuid(1000) == 0);                        /* drop privileges */
  CK(chmod(f, 0400) == 0);                      /* still the owner */
  errno = 0; CK(open(f, O_WRONLY) == -1 && errno == EACCES);
  errno = 0; CK(access(f, W_OK) == -1 && errno == EACCES);
  CK(access(f, R_OK) == 0);
  fd = open(f, O_RDONLY); CK(fd >= 0); CK(close(fd) == 0);
  CK(chmod(f, 0600) == 0);
  fd = open(f, O_WRONLY); CK(fd >= 0);
  CK(fchmod(fd, 0644) == 0);
  CK(close(fd) == 0);
  errno = 0; CK(chown(f, 0, 0) == -1 && errno == EPERM);  /* non-root chown */
  CK(unlink(f) == 0);
  printf("PASS\n"); return 0;
}
