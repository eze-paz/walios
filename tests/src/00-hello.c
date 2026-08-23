#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "world")) { printf("FAIL argv argc=%d\n", argc); return 1; }
  printf("hello %s\n", argv[1]);
  printf("PASS\n");
  return 0;
}
