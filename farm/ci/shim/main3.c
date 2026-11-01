/* main(argc, argv, envp): clang names a two-argument main __main_argc_argv, which is what
   the WALI crt1 calls; a three-argument main stays plain `main` and nothing would call it.
   This member is only pulled from the archive when __main_argc_argv is undefined, i.e.
   when the program's main takes envp. */
extern char **environ;
int main(int, char **, char **);
int __main_argc_argv(int argc, char **argv) { return main(argc, argv, environ); }
