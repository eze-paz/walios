/* execve of a "#!" script must run its interpreter with the script path appended
 * (./configure, libtool, every build-system wrapper). An executable file with no
 * shebang runs as a shell script (the kernel-ENOEXEC fallback). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
static int run_script(const char *path, const char *body, const char *expect) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (fd < 0) { printf("FAIL open %s errno=%d\n", path, errno); return 1; }
  write(fd, body, strlen(body)); close(fd);
  int p[2]; if (pipe(p)) { printf("FAIL pipe\n"); return 1; }
  pid_t pid = vfork();
  if (pid == 0) {
    dup2(p[1], 1); close(p[0]); close(p[1]);
    char *cargv[] = { (char *)path, "argone", NULL };
    execve(path, cargv, NULL);
    _exit(9);
  }
  close(p[1]);
  int st = 0; waitpid(pid, &st, 0);
  char buf[128]; memset(buf, 0, sizeof buf);
  int n = read(p[0], buf, sizeof buf - 1); (void)n;
  close(p[0]);
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { printf("FAIL %s status=%d out=%s\n", path, st, buf); return 1; }
  if (!strstr(buf, expect)) { printf("FAIL %s out=%s (want %s)\n", path, buf, expect); return 1; }
  return 0;
}
int main(void) {
  /* shebang: interpreter + script arg propagation ($1 must arrive) */
  if (run_script("/tmp/wt-shebang.sh", "#!/bin/sh\necho shebang-ok-$1\n", "shebang-ok-argone")) return 1;
  /* no shebang, executable: runs as a shell script */
  if (run_script("/tmp/wt-plain.sh", "echo plain-ok\n", "plain-ok")) return 1;
  unlink("/tmp/wt-shebang.sh"); unlink("/tmp/wt-plain.sh");
  printf("PASS\n"); return 0;
}
