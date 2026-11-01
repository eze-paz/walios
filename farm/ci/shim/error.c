/* glibc's error()/error_at_line(), which musl leaves out (gnulib and many GNU tools call
   them, and their configure checks assume a glibc-like libc when cross-compiling). */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char *program_invocation_name;
unsigned int error_message_count;
int error_one_per_line;
void (*error_print_progname)(void);
static void verr(int status, int errnum, const char *file, unsigned line, const char *fmt, va_list ap) {
  fflush(stdout);
  if (error_print_progname) error_print_progname();
  else if (program_invocation_name) fprintf(stderr, "%s:", program_invocation_name);
  if (file) fprintf(stderr, "%s:%u:", file, line);
  fputc(' ', stderr); vfprintf(stderr, fmt, ap);
  if (errnum) fprintf(stderr, ": %s", strerror(errnum));
  fputc('\n', stderr); error_message_count++;
  if (status) exit(status);
}
void error(int status, int errnum, const char *fmt, ...) { va_list ap; va_start(ap, fmt); verr(status, errnum, 0, 0, fmt, ap); va_end(ap); }
void error_at_line(int status, int errnum, const char *file, unsigned int line, const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); verr(status, errnum, file, line, fmt, ap); va_end(ap); }
