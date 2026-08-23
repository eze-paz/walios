#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <stdlib.h>
static double ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}
int main(int c, char **v){
  if (c > 1 && !strcmp(v[1], "x")) return 0;   /* exec target */
  double t = ms(); long N = 500000;
  for (long i = 0; i < N; i++) getpid();
  double sc = ms() - t;
  printf("syscall:   %.2f M getpid/sec\n", N / (sc * 1000.0));
  t = ms(); int K = 200;
  for (int i = 0; i < K; i++) {
    pid_t p = vfork();
    if (p == 0) { char *a[] = { v[0], "x", 0 }; execve("/proc/self/exe", a, 0); _exit(9); }
    int st; waitpid(p, &st, 0);
  }
  double fk = ms() - t;
  printf("fork+exec: %.2f ms/spawn (%d procs, %.0f ms)\n", fk / K, K, fk);
  return 0;
}
