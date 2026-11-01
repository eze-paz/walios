/* BSD getprogname()/setprogname() (gnulib's error.c and many BSD-origin tools call them);
   musl has program_invocation_short_name, which is the same thing. */
extern char *program_invocation_short_name;
const char *getprogname(void) { return program_invocation_short_name ? program_invocation_short_name : ""; }
void setprogname(const char *name) { (void)name; }
