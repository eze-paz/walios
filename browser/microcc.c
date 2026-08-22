/* microcc — a tiny REAL compiler that emits WebAssembly.
 * Language: one integer arithmetic expression (+ - * / and parens).
 * It does genuine recursive-descent parsing and genuine codegen (emits
 * i32.const / i32.add / ... — the arithmetic runs at RUNTIME in the produced
 * module, it is NOT constant-folded here), then writes a valid .wasm whose
 * _start computes the expression and returns it as the process exit code.
 *
 * The point: microcc itself is compiled to wasm32-wali and runs inside the
 * browser OS; the .wasm it emits is then executed by the same OS. Compiler in
 * the browser, end to end, no native toolchain.
 *
 *   microcc <input-expr-file> <output.wasm>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- code buffer + LEB128 ---- */
static unsigned char code[4096]; static int clen = 0;
static void b(unsigned char x){ code[clen++] = x; }
static void uleb(unsigned v){ do{ unsigned char x=v&0x7f; v>>=7; if(v)x|=0x80; b(x);}while(v); }
static void sleb(int v){ int more=1; while(more){ unsigned char x=v&0x7f; v>>=7;
  if((v==0 && !(x&0x40)) || (v==-1 && (x&0x40))) more=0; else x|=0x80; b(x);} }

/* ---- parser (recursive descent) ---- */
static const char *p;
static void skip(){ while(*p==' '||*p=='\t'||*p=='\n') p++; }
static void expr(void);
static void primary(void){
  skip();
  if(*p=='('){ p++; expr(); skip(); if(*p==')') p++; return; }
  int v=0, any=0; while(*p>='0'&&*p<='9'){ v=v*10+(*p-'0'); p++; any=1; }
  if(!any){ fprintf(stderr,"microcc: parse error at '%s'\n", p); exit(2); }
  b(0x41); sleb(v);                 /* i32.const v */
}
static void term(void){
  primary();
  for(;;){ skip();
    if(*p=='*'){ p++; primary(); b(0x6c); }      /* i32.mul */
    else if(*p=='/'){ p++; primary(); b(0x6d); } /* i32.div_s */
    else break; }
}
static void expr(void){
  term();
  for(;;){ skip();
    if(*p=='+'){ p++; term(); b(0x6a); }         /* i32.add */
    else if(*p=='-'){ p++; term(); b(0x6b); }    /* i32.sub */
    else break; }
}

/* ---- wasm module assembly ---- */
static unsigned char out[8192]; static int olen=0;
static void o(unsigned char x){ out[olen++]=x; }
static void obytes(const void*d,int n){ memcpy(out+olen,d,n); olen+=n; }
static void osleb_len(int v){ /* uleb into out */ do{unsigned char x=v&0x7f; v>>=7; if(v)x|=0x80; o(x);}while(v); }
/* emit a section: id, then size-prefixed payload */
static void section(int id, const unsigned char*payload, int n){
  o(id); osleb_len(n); obytes(payload,n);
}

int main(int argc, char**argv){
  if(argc<3){ fprintf(stderr,"usage: microcc <in> <out.wasm>\n"); return 2; }
  /* read source */
  FILE*f=fopen(argv[1],"rb"); if(!f){ perror("open input"); return 1; }
  char src[1024]; int n=fread(src,1,sizeof src-1,f); src[n]=0; fclose(f);
  p=src; expr(); skip();
  b(0x10); uleb(0);   /* call SYS_exit_group (func 0) */
  b(0x1a);            /* drop its i64 result */
  b(0x0b);            /* end */

  /* ---- assemble the module ---- */
  o(0x00);o(0x61);o(0x73);o(0x6d); o(1);o(0);o(0);o(0);   /* \0asm, version 1 */

  /* Type section: type0 (i32)->i64 ; type1 ()->() */
  { unsigned char s[32]; int i=0;
    s[i++]=2;                                 /* count */
    s[i++]=0x60; s[i++]=1; s[i++]=0x7f; s[i++]=1; s[i++]=0x7e; /* (i32)->i64 */
    s[i++]=0x60; s[i++]=0; s[i++]=0;          /* ()->() */
    section(1,s,i); }
  /* Import section: wali.SYS_exit_group : type0 */
  { unsigned char s[64]; int i=0;
    s[i++]=1;                                 /* count */
    s[i++]=4; memcpy(s+i,"wali",4); i+=4;
    s[i++]=14; memcpy(s+i,"SYS_exit_group",14); i+=14;
    s[i++]=0x00; s[i++]=0;                     /* func, typeidx 0 */
    section(2,s,i); }
  /* Function section: _start : type1 */
  { unsigned char s[4]; int i=0; s[i++]=1; s[i++]=1; section(3,s,i); }
  /* Memory section: 1 page min */
  { unsigned char s[4]; int i=0; s[i++]=1; s[i++]=0x00; s[i++]=1; section(5,s,i); }
  /* Export section: _start (func 1), memory (mem 0) */
  { unsigned char s[48]; int i=0;
    s[i++]=2;
    s[i++]=6; memcpy(s+i,"_start",6); i+=6; s[i++]=0x00; s[i++]=1;
    s[i++]=6; memcpy(s+i,"memory",6); i+=6; s[i++]=0x02; s[i++]=0;
    section(7,s,i); }
  /* Code section: one body (locals=0, then our code) */
  { unsigned char s[4200]; int i=0;
    s[i++]=1;                                 /* count */
    /* body = uleb(bodysize){ locals=0; code } */
    int bodysize = 1 + clen;                  /* 1 for local-decl-count(0) */
    /* write bodysize as uleb */
    { int v=bodysize; do{ unsigned char x=v&0x7f; v>>=7; if(v)x|=0x80; s[i++]=x; }while(v); }
    s[i++]=0;                                 /* local decl count = 0 */
    memcpy(s+i,code,clen); i+=clen;
    section(10,s,i); }

  FILE*g=fopen(argv[2],"wb"); if(!g){ perror("open output"); return 1; }
  fwrite(out,1,olen,g); fclose(g);
  fprintf(stderr,"microcc: emitted %d-byte wasm (%d code bytes) -> %s\n", olen, clen, argv[2]);
  return 0;
}
