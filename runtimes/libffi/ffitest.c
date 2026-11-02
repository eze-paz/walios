/* libffi on walios: calls of every ABI shape and closures, each checked against a direct
 * C call. Prints "ffitest: N/N ok" (and every failure). Built and run by
 * tests/walios/e2e-ffi.mjs (both engines) and on the farm's node host. */
#include <ffi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int pass, total;
#define CHECK(name, cond) do { total++; if (cond) pass++; else printf("FAIL %s\n", name); } while (0)

static int add2(int a, int b) { return a + b; }
static double mix(int8_t a, double b, int64_t c, float d, uint16_t e) { return a + b + (double)c + d + e; }
static int64_t big(int64_t a, int32_t b) { return a * b; }
static int8_t neg8(int8_t a) { return (int8_t)-a; }
static uint8_t byte_ret(void) { return 200; }
typedef struct { int x, y; } P;
typedef struct { double d; } D1;
typedef struct { char c; short s; int i; double d; } Big;
static P padd(P a, P b) { P r = { a.x + b.x, a.y + b.y }; return r; }
static D1 dscale(D1 a, float k) { D1 r = { a.d * k }; return r; }
static double bigsum(Big b, int k) { return b.c + b.s + b.i + b.d + k; }
static long double ldadd(long double a, long double b) { return a + b; }

/* closure: int cmp(const void *, const void *) for qsort */
static void cmp_fn(ffi_cif *cif, void *ret, void **args, void *ud)
{
  (void)cif; (*(int *)ud)++;
  int a = **(int **)args[0], b = **(int **)args[1];
  *(ffi_arg *)ret = (ffi_sarg)(a > b) - (a < b);
}
/* closure: double f(double, P) re-entering ffi_call */
static ffi_cif add_cif;
static void reent_fn(ffi_cif *cif, void *ret, void **args, void *ud)
{
  (void)cif; (void)ud;
  int a = 20, b = 22; void *av[] = { &a, &b }; ffi_arg r;
  ffi_call(&add_cif, FFI_FN(add2), &r, av);
  P p = *(P *)args[1];
  *(double *)ret = *(double *)args[0] + (int)r + p.x * p.y;
}

static void sleepy_fn(ffi_cif *cif, void *ret, void **args, void *ud)
{
  (void)cif; (void)args; (void)ud;
  usleep(2000);
  *(ffi_arg *)ret = 7;
}

int main(void)
{
  ffi_cif cif; ffi_arg r;
  /* int(int, int) */
  ffi_type *t2[] = { &ffi_type_sint, &ffi_type_sint };
  ffi_prep_cif(&add_cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint, t2);
  { int a = 40, b = 2; void *av[] = { &a, &b }; ffi_call(&add_cif, FFI_FN(add2), &r, av); CHECK("int add", (int)r == 42); }
  /* mixed scalars */
  { ffi_type *t[] = { &ffi_type_sint8, &ffi_type_double, &ffi_type_sint64, &ffi_type_float, &ffi_type_uint16 };
    ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 5, &ffi_type_double, t);
    int8_t a = -3; double b = 0.5; int64_t c = 10000000000LL; float d = 0.25f; uint16_t e = 60000; double out;
    void *av[] = { &a, &b, &c, &d, &e }; ffi_call(&cif, FFI_FN(mix), &out, av);
    CHECK("mixed scalars", out == mix(a, b, c, d, e)); }
  { ffi_type *t[] = { &ffi_type_sint64, &ffi_type_sint32 }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint64, t);
    int64_t a = -123456789012LL; int32_t b = 3; int64_t out; void *av[] = { &a, &b };
    ffi_call(&cif, FFI_FN(big), &out, av); CHECK("int64", out == big(a, b)); }
  { ffi_type *t[] = { &ffi_type_sint8 }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &ffi_type_sint8, t);
    int8_t a = 5; void *av[] = { &a }; ffi_call(&cif, FFI_FN(neg8), &r, av); CHECK("int8 widened to ffi_arg", (ffi_sarg)r == -5); }
  { ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 0, &ffi_type_uint8, NULL); ffi_call(&cif, FFI_FN(byte_ret), &r, NULL); CHECK("uint8 ret", r == 200); }
  /* structs */
  ffi_type *pel[] = { &ffi_type_sint, &ffi_type_sint, NULL }; ffi_type pt = { 0, 0, FFI_TYPE_STRUCT, pel };
  { ffi_type *t[] = { &pt, &pt }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &pt, t);
    P a = { 1, 2 }, b = { 30, 40 }, out; void *av[] = { &a, &b }; ffi_call(&cif, FFI_FN(padd), &out, av);
    CHECK("struct by value + sret", out.x == 31 && out.y == 42); }
  ffi_type *d1el[] = { &ffi_type_double, NULL }; ffi_type d1t = { 0, 0, FFI_TYPE_STRUCT, d1el };
  { ffi_type *t[] = { &d1t, &ffi_type_float }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &d1t, t);
    D1 a = { 1.5 }, out; float k = 4; void *av[] = { &a, &k }; ffi_call(&cif, FFI_FN(dscale), &out, av);
    CHECK("1-scalar struct", out.d == 6.0); }
  ffi_type *bel[] = { &ffi_type_schar, &ffi_type_sshort, &ffi_type_sint, &ffi_type_double, NULL }; ffi_type bt = { 0, 0, FFI_TYPE_STRUCT, bel };
  { ffi_type *t[] = { &bt, &ffi_type_sint }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_double, t);
    Big b = { 1, 2, 3, 0.5 }; int k = 4; double out; void *av[] = { &b, &k }; ffi_call(&cif, FFI_FN(bigsum), &out, av);
    CHECK("padded struct", out == bigsum(b, k)); }
  { ffi_type *t[] = { &ffi_type_longdouble, &ffi_type_longdouble }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_longdouble, t);
    long double a = 1.25L, b = 2.5L, out; void *av[] = { &a, &b }; ffi_call(&cif, FFI_FN(ldadd), &out, av);
    CHECK("long double", out == 3.75L); }
  /* varargs: snprintf(buf, n, fmt, int, double, char *, long long) */
  { /* (size_t is 32-bit on WALI, long 64-bit) */
    ffi_type *t[] = { &ffi_type_pointer, &ffi_type_uint32, &ffi_type_pointer, &ffi_type_sint, &ffi_type_double, &ffi_type_pointer, &ffi_type_sint64 };
    ffi_prep_cif_var(&cif, FFI_DEFAULT_ABI, 3, 7, &ffi_type_sint, t);
    char buf[64]; char *bp = buf; size_t n = sizeof buf; const char *fmt = "%d %.2f %s %lld", *s = "xyz";
    int i = 7; double d = 3.14159; int64_t ll = -9000000000LL;
    void *av[] = { &bp, &n, &fmt, &i, &d, &s, &ll }; ffi_call(&cif, FFI_FN(snprintf), &r, av);
    CHECK("varargs snprintf", strcmp(buf, "7 3.14 xyz -9000000000") == 0 && (int)r == (int)strlen(buf)); }
  /* closures */
  { ffi_type *t[] = { &ffi_type_pointer, &ffi_type_pointer }; ffi_cif ccif;
    ffi_prep_cif(&ccif, FFI_DEFAULT_ABI, 2, &ffi_type_sint, t);
    void *code; ffi_closure *c = ffi_closure_alloc(sizeof(ffi_closure), &code); int calls = 0;
    CHECK("closure prep", c && ffi_prep_closure_loc(c, &ccif, cmp_fn, &calls, code) == FFI_OK);
    int v[] = { 5, 3, 9, 1, 7, 2 };
    qsort(v, 6, sizeof(int), (int (*)(const void *, const void *))code);
    CHECK("closure as qsort comparator", v[0] == 1 && v[1] == 2 && v[2] == 3 && v[5] == 9 && calls > 0);
    ffi_closure_free(c); }
  { ffi_type *t[] = { &ffi_type_double, &pt }; ffi_cif ccif; ffi_prep_cif(&ccif, FFI_DEFAULT_ABI, 2, &ffi_type_double, t);
    void *code; ffi_closure *c = ffi_closure_alloc(sizeof(ffi_closure), &code);
    ffi_prep_closure_loc(c, &ccif, reent_fn, NULL, code);
    P p = { 3, 4 }; double out = ((double (*)(double, P))code)(0.5, p);
    CHECK("closure with struct arg, re-entering ffi_call", out == 0.5 + 42 + 12);
    /* and the closure called through ffi_call itself */
    double x = 1.0; void *av[] = { &x, &p }; double out2; ffi_call(&ccif, FFI_FN(code), &out2, av);
    CHECK("closure through ffi_call", out2 == 1.0 + 42 + 12);
    ffi_closure_free(c); }
  /* callees that make syscalls which may block or suspend (in-process engine: JSPI) */
  { ffi_type *t[] = { &ffi_type_uint32 }; ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &ffi_type_sint, t);
    uint32_t us = 2000; void *av[] = { &us }; ffi_call(&cif, FFI_FN(usleep), &r, av);
    CHECK("ffi_call of usleep", (int)r == 0); }
  { ffi_cif ccif; ffi_prep_cif(&ccif, FFI_DEFAULT_ABI, 0, &ffi_type_sint, NULL);
    void *code; ffi_closure *c = ffi_closure_alloc(sizeof(ffi_closure), &code);
    ffi_prep_closure_loc(c, &ccif, sleepy_fn, NULL, code);
    CHECK("closure that sleeps", ((int (*)(void))code)() == 7);
    ffi_call(&ccif, FFI_FN(code), &r, NULL);
    CHECK("closure that sleeps, through ffi_call", (int)r == 7);
    ffi_closure_free(c); }
  printf("ffitest: %d/%d ok\n", pass, total);
  return pass == total ? 0 : 1;
}
