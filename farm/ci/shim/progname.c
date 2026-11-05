/* BSD getprogname()/setprogname() (gnulib's error.c and many BSD-origin tools call them);
   musl has program_invocation_short_name, which is the same thing. Weak, like closefrom.c: a
   package's own definition wins. */
extern char *program_invocation_short_name;
__attribute__((weak)) const char *getprogname(void) { return program_invocation_short_name ? program_invocation_short_name : ""; }
__attribute__((weak)) void setprogname(const char *name) { (void)name; }
