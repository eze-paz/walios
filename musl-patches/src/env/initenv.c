/* walios: the process environment arrives as a NUL-separated file (like Linux's
 * /proc/self/environ), from the kernel import __get_init_envfile0.
 *
 * WALI's reader took a NEWLINE-separated file from __get_init_envfile, so a value containing a
 * newline could not be represented: the kernel had to drop it (git's test suite sets a
 * multi-line GIT_EDITOR; autoconf exports as_nl='<newline>'). The import has a new name so the
 * two formats never meet: binaries built before this keep importing __get_init_envfile and get
 * the old file; binaries built with this get NUL-separated entries, newlines and all.
 *
 * Also unlike the old reader, an entry putenv() refuses is skipped instead of aborting the
 * process before main (WALI_ENV_READ_FAIL killed every program a malformed variable reached). */
#include "init_env.h"
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

#define FSIZE 1000

int get_init_envfile0(char *filebuf, int fsize) __attribute__((
  __import_module__("wali"),
  __import_name__("__get_init_envfile0")
));

static int read_envfile0(const char *filename) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) return 0;                      /* no file: an empty environment */
  struct stat st;
  if (fstat(fd, &st) < 0) { close(fd); return WALI_ENV_READ_FAIL; }
  size_t size = (size_t)st.st_size;
  if (size == 0) { close(fd); return 0; }
  char *buf = malloc(size + 1);
  if (!buf) { close(fd); return WALI_ENV_MALLOC_FAIL; }
  size_t got = 0;
  while (got < size) {
    ssize_t n = read(fd, buf + got, size - got);
    if (n <= 0) break;
    got += (size_t)n;
  }
  close(fd);
  buf[got] = '\0';
  /* Each entry is NUL-terminated; putenv keeps the pointer, so entries stay in buf (never
   * freed: it IS the environment storage). */
  for (char *p = buf, *end = buf + got; p < end; ) {
    size_t len = strlen(p);
    if (len && strchr(p, '=')) (void)putenv(p);
    p += len + 1;
  }
  return 0;
}

int init_env() {
  char filename[FSIZE];
  int found = get_init_envfile0(filename, FSIZE);
  if (found > 0) return read_envfile0(filename);
  return 0;
}
