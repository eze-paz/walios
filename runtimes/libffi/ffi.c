/* libffi for walios (wasm32-unknown-linux-muslwali): calls and closures through the kernel.
 *
 * wasm code cannot call a function pointer with a signature only known at run time, and
 * cannot create functions. So this port reduces every call to its wasm-level signature
 * ("i" i32, "j" i64, "f" f32, "d" f64; first char = the result, "v" = none) plus one 8-byte
 * slot per wasm parameter, and the kernel does the rest (walios/wali-worker.js,
 * wali-proc-worker.js and the farm's host/host.js, `__wali_ffi_*`):
 *   __wali_ffi_call(fn, sig, slots, ret)   calls table[fn] with the slot values
 *   __wali_ffi_table_alloc()               reserves a function-table index (a closure's code)
 *   __wali_ffi_closure(idx, sig, closure, buf, enter)
 *                                          puts at table[idx] a wasm function of that
 *                                          signature that stores its arguments in slots and
 *                                          calls enter(closure, slots)
 *   __wali_ffi_closure_free(idx)
 *
 * The lowering follows clang's wasm32 C ABI (WebAssemblyABIInfo):
 *  - integers up to 32 bits and pointers are i32; 64-bit integers are i64 (long, and so
 *    ffi_arg, is 64-bit on WALI's wasm32 and 32-bit on walios ILP32: the lowering goes by
 *    size, so one ffi.c serves both); float f32; double f64; long double (IEEE quad) two i64;
 *  - a struct whose only non-empty member is (recursively) one scalar of the struct's size
 *    is passed and returned as that scalar; any other struct is passed as a pointer to a copy
 *    and returned through a pointer the caller passes first (sret);
 *  - variadic arguments go in a buffer, each aligned to max(4, its alignment) and padded to
 *    4 bytes, and the buffer's address is one more i32 after the fixed parameters; structs
 *    there are pointers to copies too. */
#include <ffi.h>
#include <ffi_common.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

__attribute__((import_module("env"), import_name("__wali_ffi_call")))
void __wali_ffi_call(void (*fn)(void), const char *sig, uint64_t *slots, uint64_t *ret);
__attribute__((import_module("env"), import_name("__wali_ffi_table_alloc")))
int __wali_ffi_table_alloc(void);
__attribute__((import_module("env"), import_name("__wali_ffi_closure")))
int __wali_ffi_closure(int idx, const char *sig, void *closure, void *(*buf)(void *, unsigned),
                       void (*enter)(ffi_closure *, uint64_t *));
__attribute__((import_module("env"), import_name("__wali_ffi_closure_free")))
void __wali_ffi_closure_free(int idx);

#define VARARGS_FLAG 1
#define MAX_ARGS 1000

ffi_status FFI_HIDDEN
ffi_prep_cif_machdep(ffi_cif *cif)
{
  if (cif->abi != FFI_WASM32 && cif->abi != FFI_WASM32_EMSCRIPTEN)
    return FFI_BAD_ABI;
  /* (called after ffi_prep_cif_machdep_var for a variadic cif) */
  if (!(cif->flags & VARARGS_FLAG))
    cif->nfixedargs = cif->nargs;
  if (cif->nargs > MAX_ARGS || cif->rtype->type == FFI_TYPE_COMPLEX)
    return FFI_BAD_TYPEDEF;
  for (unsigned i = 0; i < cif->nargs; i++)
    if (cif->arg_types[i]->type == FFI_TYPE_COMPLEX)
      return FFI_BAD_TYPEDEF;
  return FFI_OK;
}

ffi_status FFI_HIDDEN
ffi_prep_cif_machdep_var(ffi_cif *cif, unsigned nfixedargs, unsigned ntotalargs)
{
  (void)ntotalargs;
  cif->flags |= VARARGS_FLAG;
  cif->nfixedargs = nfixedargs;
  return cif->nfixedargs + 1 > MAX_ARGS ? FFI_BAD_TYPEDEF : FFI_OK;
}

/* The one scalar a struct is passed as, or NULL if it is passed indirectly. */
static ffi_type *
single_scalar(ffi_type *t)
{
  if (t->type != FFI_TYPE_STRUCT)
    return t;
  ffi_type *found = NULL;
  for (ffi_type **e = t->elements; e && *e; e++) {
    if ((*e)->size == 0)
      continue;
    if (found)
      return NULL;
    if (!(found = single_scalar(*e)))
      return NULL;
  }
  return found && found->size == t->size && found->type != FFI_TYPE_LONGDOUBLE ? found : NULL;
}

/* wasm value class of a scalar (not a struct, not long double) */
static char
wclass(ffi_type *t)
{
  switch (t->type) {
  case FFI_TYPE_FLOAT: return 'f';
  case FFI_TYPE_DOUBLE: return 'd';
  case FFI_TYPE_UINT64: case FFI_TYPE_SINT64: return 'j';
  default: return 'i';
  }
}

/* An integer argument, sign/zero-extended to the i32 it travels as. */
static uint64_t
load_scalar(ffi_type *t, const void *p)
{
  switch (t->type) {
  case FFI_TYPE_UINT8: return *(const uint8_t *)p;
  case FFI_TYPE_SINT8: return (uint32_t)(int32_t)*(const int8_t *)p;
  case FFI_TYPE_UINT16: return *(const uint16_t *)p;
  case FFI_TYPE_SINT16: return (uint32_t)(int32_t)*(const int16_t *)p;
  case FFI_TYPE_UINT64: case FFI_TYPE_SINT64: case FFI_TYPE_DOUBLE: return *(const uint64_t *)p;
  case FFI_TYPE_FLOAT: return *(const uint32_t *)p;
  default: return *(const uint32_t *)p;        /* INT, (U|S)INT32, POINTER */
  }
}

/* A result into libffi's rvalue: integers narrower than ffi_arg are widened to it. */
static void
store_ret(ffi_type *t, uint64_t r, void *rvalue)
{
  switch (t->type) {
  case FFI_TYPE_UINT8: *(ffi_arg *)rvalue = (uint8_t)r; break;
  case FFI_TYPE_SINT8: *(ffi_sarg *)rvalue = (int8_t)r; break;
  case FFI_TYPE_UINT16: *(ffi_arg *)rvalue = (uint16_t)r; break;
  case FFI_TYPE_SINT16: *(ffi_sarg *)rvalue = (int16_t)r; break;
  case FFI_TYPE_INT: case FFI_TYPE_SINT32: *(ffi_sarg *)rvalue = (int32_t)r; break;
  case FFI_TYPE_UINT32: case FFI_TYPE_POINTER: *(ffi_arg *)rvalue = (uint32_t)r; break;
  default: memcpy(rvalue, &r, t->size); break;  /* 64-bit, float, double, 1-scalar struct */
  }
}

static unsigned
align_up(unsigned n, unsigned a)
{
  return (n + a - 1) & ~(a - 1);
}

/* The wasm signature of a cif: sig[0] = result class, then one char per wasm parameter.
 * Returns the parameter count; *sret = result goes through a hidden first pointer. */
static unsigned
make_sig(ffi_cif *cif, char *sig, int *sret)
{
  ffi_type *rt = cif->rtype, *s;
  unsigned p = 0;
  *sret = 0;
  if (rt->type == FFI_TYPE_VOID)
    sig[0] = 'v';
  else if (rt->type == FFI_TYPE_LONGDOUBLE || !(s = single_scalar(rt))) {
    *sret = 1; sig[0] = 'v'; sig[1 + p++] = 'i';
  } else
    sig[0] = wclass(s);
  for (unsigned i = 0; i < cif->nfixedargs; i++) {
    ffi_type *t = cif->arg_types[i];
    if (t->type == FFI_TYPE_LONGDOUBLE) { sig[1 + p++] = 'j'; sig[1 + p++] = 'j'; }
    else if (t->type == FFI_TYPE_STRUCT && t->size == 0) ;     /* empty struct: no parameter */
    else if ((s = single_scalar(t))) sig[1 + p++] = wclass(s);
    else sig[1 + p++] = 'i';
  }
  if (cif->flags & VARARGS_FLAG)
    sig[1 + p++] = 'i';
  sig[1 + p] = 0;
  return p;
}

/* Where variadic argument i sits in the buffer, and how big the buffer is. */
static unsigned
va_layout(ffi_cif *cif, unsigned *offs)
{
  unsigned off = 0;
  for (unsigned i = cif->nfixedargs; i < cif->nargs; i++) {
    ffi_type *t = cif->arg_types[i];
    unsigned size = 4, align = 4;
    if (t->type != FFI_TYPE_STRUCT || single_scalar(t)) {
      size = t->size; align = t->alignment > 4 ? t->alignment : 4;
    }
    off = align_up(off, align);
    offs[i - cif->nfixedargs] = off;
    off += align_up(size, 4);
  }
  return off;
}

void
ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue)
{
  char *sig = alloca(2 * cif->nargs + 4);
  uint64_t *slots = alloca(8 * (2 * cif->nargs + 2));
  int sret;
  unsigned np = make_sig(cif, sig, &sret), p = 0;
  ffi_type *rt = cif->rtype, *s;
  if (sret) {
    void *dst = rvalue ? rvalue : alloca(rt->size);
    slots[p++] = (uint32_t)(uintptr_t)dst;
  }
  for (unsigned i = 0; i < cif->nfixedargs; i++) {
    ffi_type *t = cif->arg_types[i];
    if (t->type == FFI_TYPE_LONGDOUBLE) {
      memcpy(&slots[p], avalue[i], 16); p += 2;
    } else if (t->type == FFI_TYPE_STRUCT && t->size == 0) {
    } else if ((s = single_scalar(t))) {
      slots[p++] = load_scalar(s, avalue[i]);
    } else {                                   /* by value = a pointer to the caller's copy */
      void *copy = alloca(t->size);
      memcpy(copy, avalue[i], t->size);
      slots[p++] = (uint32_t)(uintptr_t)copy;
    }
  }
  if (cif->flags & VARARGS_FLAG) {
    unsigned nva = cif->nargs - cif->nfixedargs;
    unsigned *offs = alloca(sizeof(unsigned) * (nva + 1));
    unsigned size = va_layout(cif, offs);
    char *buf = alloca(size ? size : 4);
    buf = (char *)(((uintptr_t)buf + 15) & ~(uintptr_t)15);
    for (unsigned k = 0; k < nva; k++) {
      ffi_type *t = cif->arg_types[cif->nfixedargs + k];
      void *v = avalue[cif->nfixedargs + k];
      if (t->type != FFI_TYPE_STRUCT || single_scalar(t))
        memcpy(buf + offs[k], v, t->size);
      else {
        void *copy = alloca(t->size);
        memcpy(copy, v, t->size);
        *(uint32_t *)(buf + offs[k]) = (uint32_t)(uintptr_t)copy;
      }
    }
    slots[p++] = (uint32_t)(uintptr_t)buf;
  }
  (void)np;
  uint64_t r = 0;
  __wali_ffi_call(fn, sig, slots, &r);
  if (!sret && rvalue && rt->type != FFI_TYPE_VOID)
    store_ret(rt, r, rvalue);                  /* (a 1-scalar struct: its bytes, as is) */
}

/* ---- closures ---- */

/* The kernel's trampoline gets its argument slots here (and frees them after reading the
 * result from slot 0): enter() may call back into ffi, so the slots cannot be static. */
static void *
closure_buf(void *p, unsigned n)
{
  if (p) { free(p); return NULL; }
  return calloc(n, 1);
}

/* slots[0] = result, slots[1..] = the wasm parameters, as the trampoline received them. */
static void
closure_enter(ffi_closure *c, uint64_t *slots)
{
  ffi_cif *cif = c->cif;
  ffi_type *s;
  void **avalue = alloca(sizeof(void *) * (cif->nargs + 1));
  uint64_t *arg = slots + 1;
  void *ret = &slots[0];
  if (cif->rtype->type != FFI_TYPE_VOID && (cif->rtype->type == FFI_TYPE_LONGDOUBLE || !single_scalar(cif->rtype)))
    ret = (void *)(uintptr_t)(uint32_t)*arg++;
  for (unsigned i = 0; i < cif->nfixedargs; i++) {
    ffi_type *t = cif->arg_types[i];
    if (t->type == FFI_TYPE_LONGDOUBLE) { avalue[i] = arg; arg += 2; }
    else if (t->type == FFI_TYPE_STRUCT && t->size == 0) avalue[i] = arg;
    else if ((s = single_scalar(t))) avalue[i] = arg++;          /* little-endian: low bytes */
    else avalue[i] = (void *)(uintptr_t)(uint32_t)*arg++;
  }
  if (cif->flags & VARARGS_FLAG) {
    unsigned nva = cif->nargs - cif->nfixedargs;
    unsigned *offs = alloca(sizeof(unsigned) * (nva + 1));
    va_layout(cif, offs);
    char *buf = (char *)(uintptr_t)(uint32_t)*arg;
    for (unsigned k = 0; k < nva; k++) {
      ffi_type *t = cif->arg_types[cif->nfixedargs + k];
      avalue[cif->nfixedargs + k] = (t->type != FFI_TYPE_STRUCT || single_scalar(t))
        ? (void *)(buf + offs[k]) : (void *)(uintptr_t)*(uint32_t *)(buf + offs[k]);
    }
  }
  c->fun(cif, ret, avalue, c->user_data);
}

void *
ffi_closure_alloc(size_t size, void **code)
{
  ffi_closure *c = calloc(1, size < sizeof(ffi_closure) ? sizeof(ffi_closure) : size);
  if (!c)
    return NULL;
  int idx = __wali_ffi_table_alloc();
  if (idx <= 0) { free(c); return NULL; }
  *(int *)c->tramp = idx;
  *code = (void *)(uintptr_t)idx;     /* a function pointer is a table index */
  return c;
}

void
ffi_closure_free(void *ptr)
{
  ffi_closure *c = ptr;
  if (!c)
    return;
  __wali_ffi_closure_free(*(int *)c->tramp);
  free(c);
}

ffi_status
ffi_prep_closure_loc(ffi_closure *closure, ffi_cif *cif,
                     void (*fun)(ffi_cif *, void *, void **, void *),
                     void *user_data, void *codeloc)
{
  if (cif->abi != FFI_WASM32 && cif->abi != FFI_WASM32_EMSCRIPTEN)
    return FFI_BAD_ABI;
  char *sig = alloca(2 * cif->nargs + 4);
  int sret;
  make_sig(cif, sig, &sret);
  closure->cif = cif;
  closure->fun = fun;
  closure->user_data = user_data;
  return __wali_ffi_closure((int)(uintptr_t)codeloc, sig, closure, closure_buf, closure_enter) == 0
    ? FFI_OK : FFI_BAD_TYPEDEF;
}
