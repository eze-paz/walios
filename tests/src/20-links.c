/* Links + fs stragglers: symlink resolution (stat follows, lstat doesn't,
 * readlink returns the target, IO through the link reaches the target),
 * hard links share content, ftruncate, fsync, statfs. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(void) {
  const char *t = "/tmp/wali-lnk-target.txt", *l = "/tmp/wali-lnk-sym.txt", *h = "/tmp/wali-lnk-hard.txt";
  unlink(t); unlink(l); unlink(h);
  int fd = open(t, O_CREAT | O_WRONLY | O_TRUNC, 0644); CK(fd >= 0);
  CK(write(fd, "via-target", 10) == 10); CK(close(fd) == 0);

  CK(symlink(t, l) == 0);
  struct stat st;
  CK(lstat(l, &st) == 0); CK(S_ISLNK(st.st_mode));
  CK(stat(l, &st) == 0); CK(S_ISREG(st.st_mode) && st.st_size == 10);
  char buf[64] = {0}; ssize_t n = readlink(l, buf, sizeof buf - 1);
  CK(n == (ssize_t)strlen(t)); buf[n] = 0; CK(!strcmp(buf, t));
  fd = open(l, O_RDONLY); CK(fd >= 0);          /* open through the link */
  memset(buf, 0, sizeof buf); CK(read(fd, buf, 10) == 10); CK(!strcmp(buf, "via-target"));
  CK(close(fd) == 0);

  CK(link(t, h) == 0);                          /* hard link shares content */
  fd = open(h, O_WRONLY); CK(fd >= 0);
  CK(write(fd, "VIA-HARDLK", 10) == 10); CK(close(fd) == 0);
  fd = open(t, O_RDONLY); CK(fd >= 0);
  memset(buf, 0, sizeof buf); CK(read(fd, buf, 10) == 10); CK(!strcmp(buf, "VIA-HARDLK"));
  CK(close(fd) == 0);

  fd = open(t, O_RDWR); CK(fd >= 0);
  CK(ftruncate(fd, 3) == 0);
  CK(fsync(fd) == 0);
  CK(fstat(fd, &st) == 0); CK(st.st_size == 3);
  CK(close(fd) == 0);
  CK(truncate(t, 1) == 0);
  CK(stat(t, &st) == 0); CK(st.st_size == 1);

  struct statfs sf; CK(statfs("/tmp", &sf) == 0); CK(sf.f_bsize > 0);
  CK(unlink(l) == 0); CK(unlink(h) == 0); CK(unlink(t) == 0);
  printf("PASS\n"); return 0;
}
