/* mpfrtest: MPFR (farm-built gmp + mpfr4, ILP32) computes pi and sqrt(2) to 50 digits, the
 * case that needed _MPFR_PREC_FORMAT=2 under WALI's 64-bit long. Run by e2e-abi32.mjs. */
#include <stdio.h>
#include <string.h>
#include <mpfr.h>

int main(void)
{
  char pi[80], r2[80];
  mpfr_t x, y;
  mpfr_inits2(200, x, y, (mpfr_ptr)0);
  mpfr_const_pi(x, MPFR_RNDN);
  mpfr_set_ui(y, 2, MPFR_RNDN);
  mpfr_sqrt(y, y, MPFR_RNDN);
  mpfr_snprintf(pi, sizeof pi, "%.50Rf", x);
  mpfr_snprintf(r2, sizeof r2, "%.50Rf", y);
  int ok = strcmp(pi, "3.14159265358979323846264338327950288419716939937511") == 0
        && strcmp(r2, "1.41421356237309504880168872420969807856967187537695") == 0
        && sizeof(mpfr_prec_t) == sizeof(long);
  printf("mpfrtest: pi=%s sqrt2=%s prec_t=%zu: %s\n", pi, r2, sizeof(mpfr_prec_t), ok ? "ok" : "FAIL");
  mpfr_clears(x, y, (mpfr_ptr)0);
  return ok ? 0 : 1;
}
