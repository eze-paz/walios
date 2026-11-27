/* getprogname for a side module whose runtime does not export it (perl.wasm, lua.wasm,
 * python): fontconfig's fcdefault.c asks for the program name to match <match target="...">
 * rules (perl-gd -> libgd -> fontconfig, R85); an empty name matches no program-specific rule.
 * Linked (wali-cc, $WALI_SIDE without getprogname) only when something references it. */
__attribute__((visibility("hidden")))
const char *getprogname(void) {
  return "";
}
