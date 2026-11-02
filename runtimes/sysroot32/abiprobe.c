/* abiprobe: every syscall whose argument layout depends on the width of long, checked from
 * the program's side. Built against both sysroots (WALI's 64-bit long and walios ILP32) and run
 * in both engines by tests/walios/e2e-abi32.mjs. Prints "abiprobe <abi>: N/N ok". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int pass, total;
#define CHECK(name, cond) do { total++; if (cond) pass++; else printf("FAIL %s (errno %d)\n", name, errno); } while (0)

static volatile sig_atomic_t got;
static void on_usr1(int s) { got = s; }

int main(void)
{
  char buf[256];
  /* printf of the platform's own types */
  size_t z = 5; long l = -7;
  snprintf(buf, sizeof buf, "%zu %ld %s", z, l, "tail");
  CHECK("printf zu/ld", strcmp(buf, "5 -7 tail") == 0);
  if (sizeof(long) == 4) {  /* WALI's prebuilt libc aborts on %L ("long double disabled") */
    long double ld = 1.5L; snprintf(buf, sizeof buf, "%Lg %s", ld, "tail");
    CHECK("printf Lg", strcmp(buf, "1.5 tail") == 0);
  }
  snprintf(buf, sizeof buf, "%lu %s", (unsigned long)sizeof(long), "tail");
  CHECK("printf lu of sizeof(long)", strcmp(buf, sizeof(long) == 4 ? "4 tail" : "8 tail") == 0);

  /* file: stat, lseek past 4 GiB, utimensat nanoseconds, statfs, fcntl locks */
  const char *f = "/tmp/abiprobe.dat";
  int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
  CHECK("open", fd >= 0);
  CHECK("write", write(fd, "hello", 5) == 5);
  struct stat st; CHECK("fstat", fstat(fd, &st) == 0 && st.st_size == 5 && S_ISREG(st.st_mode));
  CHECK("stat", stat(f, &st) == 0 && st.st_size == 5);
  off_t big = (off_t)5 << 30;
  CHECK("lseek 5 GiB", lseek(fd, big, SEEK_SET) == big && lseek(fd, 0, SEEK_CUR) == big);
  lseek(fd, 0, SEEK_SET);
  struct timespec ts[2]; memset(ts, 0xff, sizeof ts);   /* garbage in any padding */
  ts[0].tv_sec = 1000000000; ts[0].tv_nsec = 123456789; ts[1] = ts[0];
  CHECK("utimensat", utimensat(AT_FDCWD, f, ts, 0) == 0);
  CHECK("mtime round trip", stat(f, &st) == 0 && st.st_mtim.tv_sec == 1000000000);
  struct statfs sfs; CHECK("statfs", statfs("/tmp", &sfs) == 0 && sfs.f_bsize == 4096 && sfs.f_namelen == 255);
  struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };
  CHECK("fcntl F_GETLK", fcntl(fd, F_GETLK, &fl) == 0);
  close(fd); unlink(f);

  /* time */
  struct timespec t0, t1; CHECK("clock_gettime", clock_gettime(CLOCK_MONOTONIC, &t0) == 0 && t0.tv_nsec >= 0 && t0.tv_nsec < 1000000000);
  struct timespec req; memset(&req, 0xff, sizeof req); req.tv_sec = 0; req.tv_nsec = 20000000;
  CHECK("nanosleep 20ms", nanosleep(&req, NULL) == 0);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  long ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
  CHECK("nanosleep slept", ms >= 15 && ms < 2000);
  struct timeval tv; CHECK("gettimeofday", gettimeofday(&tv, NULL) == 0 && tv.tv_sec > 1600000000 && tv.tv_usec >= 0 && tv.tv_usec < 1000000);
  struct timeval sel = { 0, 30000 };
  clock_gettime(CLOCK_MONOTONIC, &t0);
  CHECK("select timeout", select(0, NULL, NULL, NULL, &sel) == 0);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
  CHECK("select waited", ms >= 20 && ms < 2000);
  struct timespec pts = { 0, 30000000 };
  clock_gettime(CLOCK_MONOTONIC, &t0);
  CHECK("ppoll timeout", ppoll(NULL, 0, &pts, NULL) == 0);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
  CHECK("ppoll waited", ms >= 20 && ms < 2000);
  struct itimerval it = { { 0, 0 }, { 100, 250000 } }, old;
  CHECK("setitimer", setitimer(ITIMER_REAL, &it, NULL) == 0);
  CHECK("getitimer", getitimer(ITIMER_REAL, &old) == 0 && old.it_value.tv_sec >= 99 && old.it_value.tv_sec <= 100 && old.it_value.tv_usec >= 0 && old.it_value.tv_usec < 1000000);
  memset(&it, 0, sizeof it); setitimer(ITIMER_REAL, &it, NULL);

  /* resources and system info */
  struct rusage ru; memset(&ru, 0x5a, sizeof ru);
  CHECK("getrusage", getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_utime.tv_usec >= 0 && ru.ru_utime.tv_usec < 1000000 && ru.ru_maxrss >= 0 && ru.ru_nivcsw >= 0);
  struct tms tm; CHECK("times", times(&tm) != (clock_t)-1);
  struct sysinfo si; memset(&si, 0, sizeof si);
  CHECK("sysinfo", sysinfo(&si) == 0 && si.uptime > 0 && si.totalram > 0 && si.mem_unit > 0
        && (unsigned long long)si.totalram * si.mem_unit >= (64ull << 20));
  struct rlimit rl; CHECK("getrlimit", getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur == 1024);

  /* signals */
  struct sigaction sa = { 0 }, osa; sa.sa_handler = on_usr1; sigemptyset(&sa.sa_mask); sigaddset(&sa.sa_mask, SIGUSR2);
  CHECK("sigaction", sigaction(SIGUSR1, &sa, NULL) == 0);
  CHECK("sigaction readback", sigaction(SIGUSR1, NULL, &osa) == 0 && osa.sa_handler == on_usr1 && sigismember(&osa.sa_mask, SIGUSR2));
  /* (walios delivers at the next syscall boundary, not inside raise itself) */
  raise(SIGUSR1); for (int i = 0; i < 5 && !got; i++) usleep(1000);
  CHECK("handler ran", got == SIGUSR1);

  /* sockets: SCM_RIGHTS through sendmsg/recvmsg */
  int sv[2]; CHECK("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  int pfd[2]; pipe(pfd);
  { char c = 'x'; struct iovec io = { &c, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u; memset(&u, 0, sizeof u);
    struct msghdr m = { 0 }; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = u.b; m.msg_controllen = sizeof u.b;
    struct cmsghdr *c1 = CMSG_FIRSTHDR(&m); c1->cmsg_level = SOL_SOCKET; c1->cmsg_type = SCM_RIGHTS; c1->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c1), &pfd[1], sizeof(int));
    CHECK("sendmsg SCM_RIGHTS", sendmsg(sv[0], &m, 0) == 1); }
  { char c = 0; struct iovec io = { &c, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u; memset(&u, 0, sizeof u);
    struct msghdr m = { 0 }; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = u.b; m.msg_controllen = sizeof u.b;
    int n = recvmsg(sv[1], &m, 0); struct cmsghdr *c1 = CMSG_FIRSTHDR(&m); int got_fd = -1;
    if (c1 && c1->cmsg_level == SOL_SOCKET && c1->cmsg_type == SCM_RIGHTS) memcpy(&got_fd, CMSG_DATA(c1), sizeof(int));
    CHECK("recvmsg byte", n == 1 && c == 'x');
    CHECK("recvmsg SCM_RIGHTS fd", got_fd >= 0 && write(got_fd, "z", 1) == 1);
    char r = 0; CHECK("passed fd is the pipe", read(pfd[0], &r, 1) == 1 && r == 'z'); }

  /* wait4 with an rusage and no children */
  int status = 0;
  CHECK("wait4 ECHILD", wait4(-1, &status, WNOHANG, &ru) == -1 && errno == ECHILD);

  printf("abiprobe %s: %d/%d ok\n", sizeof(long) == 4 ? "ilp32" : "long64", pass, total);
  return pass == total ? 0 : 1;
}
