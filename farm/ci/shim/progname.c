/* BSD getprogname() (gnulib's error.c and many BSD-origin tools call it); musl has
   program_invocation_short_name, which is the same thing. Weak, like closefrom.c: a package's
   own definition wins.
   No setprogname: musl has none, and no header here declares one, so a package's configure
   found it ("Checking for setprogname ... yes"), skipped its own compat copy and called it
   undeclared -- int setprogname() against this void one: wasm-ld's signature_mismatch stub,
   a trap at startup (doas, R78). Without it the package brings its own, as on Alpine.
   (getprogname undeclared is int() against const char *(): the same i32 on ILP32.) */
extern char *program_invocation_short_name;
__attribute__((weak)) const char *getprogname(void) { return program_invocation_short_name ? program_invocation_short_name : ""; }
