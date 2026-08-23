#include <stdio.h>
#include <setjmp.h>
static jmp_buf jb;
static int steps = 0;
static void hop(int depth) { steps++; if (depth == 0) longjmp(jb, 42); hop(depth - 1); }
int main(void) {
  int r = setjmp(jb);
  if (r == 0) { hop(5); printf("FAIL longjmp did not jump\n"); return 1; }
  if (r != 42 || steps != 6) { printf("FAIL r=%d steps=%d\n", r, steps); return 1; }
  printf("PASS\n"); return 0;
}
