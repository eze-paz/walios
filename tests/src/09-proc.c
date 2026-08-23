/* /proc/self/exe + system identity: what re-exec and uname consumers rely on. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  char p[512]; ssize_t n = readlink("/proc/self/exe", p, sizeof p - 1);
  CK(n > 0); p[n] = 0;
  CK(p[0] == '/'); CK(strstr(p, ".wasm") != NULL);
  struct stat st; CK(stat("/proc/self/exe", &st) == 0); CK(S_ISREG(st.st_mode));
  CK(access("/proc/self/exe", R_OK) == 0);
  int fd = open("/proc/self/exe", O_RDONLY); CK(fd >= 0);
  unsigned char m[4] = {0}; CK(read(fd, m, 4) == 4);
  CK(m[0] == 0 && m[1] == 'a' && m[2] == 's' && m[3] == 'm');
  CK(close(fd) == 0);
  struct utsname u; CK(uname(&u) == 0);
  CK(!strcmp(u.sysname, "Linux")); CK(!strcmp(u.machine, "wasm32"));
  CK(getpid() > 0); CK(getppid() >= 1);
  printf("PASS\n"); return 0;
}
