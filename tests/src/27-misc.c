/* Small correctness batch: getppid() in a child reports the real parent (was a
 * hardcoded 1), read() on a directory fd is EISDIR (was EBADF), and a shared
 * (dup'd) fd closing on one side must not tear down the other side's stream. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
  (void)argc; (void)argv;
  /* read() on a directory */
  int d = open("/tmp", O_RDONLY); CK(d >= 0);
  char b[8]; errno = 0; CK(read(d, b, 8) == -1 && errno == EISDIR);
  close(d);
  /* getppid inside a (vfork) child branch = the forking process's pid */
  pid_t me = getpid();
  pid_t pid = vfork();
  if (pid == 0) _exit(getppid() == me ? 0 : 4);
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  printf("PASS\n"); return 0;
}
