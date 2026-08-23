/* Shared memory subset: MAP_SHARED file mapping writes back on msync/munmap;
 * SysV shm segments round-trip content across attach/detach in one process
 * tree (exec child re-attaches and reads what the parent wrote). */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define CK(x) do { if (!(x)) { printf("FAIL %s (line %d) errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
#define KEY 0x5150
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "child")) {  /* exec'd: segment must persist */
    int id = shmget(KEY, 4096, 0); if (id < 0) { printf("FAIL child shmget\n"); return 1; }
    char *p = shmat(id, NULL, 0); if (p == (void *)-1) return 1;
    if (strcmp(p, "from-parent")) { printf("FAIL child sees [%s]\n", p); return 1; }
    strcpy(p, "from-child");
    shmdt(p);
    return 7;
  }
  /* MAP_SHARED file mapping: stores land in the file after munmap */
  const char *f = "/tmp/wali-shm-test.bin";
  int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644); CK(fd >= 0);
  CK(write(fd, "0123456789abcdef", 16) == 16);
  char *m = mmap(NULL, 16, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  CK(m != MAP_FAILED);
  CK(!memcmp(m, "0123456789abcdef", 16));
  memcpy(m, "WALI", 4);
  CK(msync(m, 16, MS_SYNC) == 0);
  char back[17] = {0};
  CK(pread(fd, back, 16, 0) == 16);
  CK(!memcmp(back, "WALI456789abcdef", 16));   /* store reached the file */
  CK(munmap(m, 16) == 0);
  CK(close(fd) == 0); CK(unlink(f) == 0);

  /* SysV shm: parent writes, exec child re-attaches, reads, replies */
  int id = shmget(KEY, 4096, IPC_CREAT | 0600); CK(id >= 0);
  char *p = shmat(id, NULL, 0); CK(p != (void *)-1);
  strcpy(p, "from-parent");
  CK(shmdt(p) == 0);                            /* detach flushes to the segment */
  pid_t pid = vfork();
  if (pid == 0) { char *cargv[] = { argv[0], "child", NULL }; execve("/proc/self/exe", cargv, NULL); _exit(9); }
  CK(pid > 0);
  int st = 0; CK(waitpid(pid, &st, 0) == pid);
  CK(WIFEXITED(st) && WEXITSTATUS(st) == 7);
  p = shmat(id, NULL, 0); CK(p != (void *)-1);  /* re-attach: see the child's write */
  CK(!strcmp(p, "from-child"));
  CK(shmdt(p) == 0);
  CK(shmctl(id, IPC_RMID, NULL) == 0);
  printf("PASS\n"); return 0;
}
