#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  const char *d = "/tmp/walitest";
  mkdir(d, 0755); /* may already exist */
  char f[64]; snprintf(f, sizeof f, "%s/a.txt", d);
  int fd = open(f, O_CREAT | O_TRUNC | O_WRONLY, 0644); CK(fd >= 0);
  CK(write(fd, "abcdef", 6) == 6);
  CK(close(fd) == 0);
  struct stat st; CK(stat(f, &st) == 0); CK(st.st_size == 6);
  fd = open(f, O_RDONLY); CK(fd >= 0);
  CK(lseek(fd, 2, SEEK_SET) == 2);
  char buf[8] = {0}; CK(read(fd, buf, 4) == 4); CK(!strcmp(buf, "cdef"));
  CK(close(fd) == 0);
  char f2[64]; snprintf(f2, sizeof f2, "%s/b.txt", d);
  CK(rename(f, f2) == 0); CK(stat(f, &st) != 0); CK(stat(f2, &st) == 0);
  CK(unlink(f2) == 0);
  char cwd[256]; CK(getcwd(cwd, sizeof cwd) != NULL);
  CK(chdir(d) == 0);
  char cwd2[256]; CK(getcwd(cwd2, sizeof cwd2) != NULL); CK(!strcmp(cwd2, d));
  CK(chdir(cwd) == 0);
  CK(rmdir(d) == 0);
  printf("PASS\n"); return 0;
}
