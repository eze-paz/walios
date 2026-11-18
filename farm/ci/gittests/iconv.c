/* iconv(1) for walios: the command Linux has (glibc's, or Alpine's musl-utils), on musl's
 * iconv(3). busybox has no iconv applet, and git's test suite pipes through it (t7102:
 * `printf ... | iconv -f utf-8 -t ISO8859-1`).
 *   iconv [-c] [-s] [-f FROM] [-t TO] [FILE...]      (FROM/TO default to UTF-8; - is stdin)
 *   iconv -l                                         (the charsets musl knows, roughly)
 * -c drops characters that cannot be converted; without it the first one is an error (exit 1). */
#include <errno.h>
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static iconv_t cd;
static int skip_bad, quiet, status;

static void out(const char *p, size_t n) {
  while (n) {
    ssize_t w = write(1, p, n);
    if (w < 0) { if (errno == EINTR) continue; perror("iconv: write"); exit(1); }
    p += w; n -= (size_t)w;
  }
}

/* Convert one input stream; returns 0, or 1 on an unconvertible/invalid sequence without -c. */
static int convert(int fd, const char *name) {
  static char in[65536], obuf[65536 * 4];
  size_t have = 0;
  for (;;) {
    ssize_t r = read(fd, in + have, sizeof in - have);
    if (r < 0) { if (errno == EINTR) continue; fprintf(stderr, "iconv: %s: %s\n", name, strerror(errno)); return 1; }
    int eof = r == 0;
    have += (size_t)r;
    char *ip = in; size_t il = have;
    while (il) {
      char *op = obuf; size_t ol = sizeof obuf;
      size_t k = iconv(cd, &ip, &il, &op, &ol);
      out(obuf, (size_t)(op - obuf));
      if (k != (size_t)-1) break;
      if (errno == E2BIG) continue;
      if (errno == EINVAL && !eof) break;          /* a sequence cut at the buffer end: read more */
      if (skip_bad) { ip++; il--; continue; }
      if (!quiet) fprintf(stderr, errno == EINVAL ? "iconv: %s: incomplete character or shift sequence at end of buffer\n"
                                                  : "iconv: %s: cannot convert\n", name);
      return 1;
    }
    memmove(in, ip, il); have = il;
    if (eof) break;
  }
  char *op = obuf; size_t ol = sizeof obuf;   /* flush any shift state */
  iconv(cd, NULL, NULL, &op, &ol);
  out(obuf, (size_t)(op - obuf));
  return 0;
}

int main(int argc, char **argv) {
  const char *from = "UTF-8", *to = "UTF-8";
  int c;
  while ((c = getopt(argc, argv, "f:t:csl")) != -1) {
    switch (c) {
    case 'f': from = optarg; break;
    case 't': to = optarg; break;
    case 'c': skip_bad = 1; break;
    case 's': quiet = 1; break;
    case 'l':
      puts("UTF-8 UTF8 UTF-16 UTF-16LE UTF-16BE UTF-32 UTF-32LE UTF-32BE UCS-2 UCS-2LE UCS-2BE UCS-4 WCHAR_T\n"
           "ASCII US-ASCII ISO-8859-1 LATIN1 ISO-8859-2..ISO-8859-16 CP1250..CP1258 KOI8-R KOI8-U CP437 CP850 CP866\n"
           "SHIFT_JIS SJIS EUC-JP ISO-2022-JP GB18030 GBK GB2312 BIG5 BIG5-HKSCS EUC-KR");
      return 0;
    default:
      fprintf(stderr, "usage: iconv [-c] [-s] [-f FROM] [-t TO] [FILE...]\n       iconv -l\n");
      return 1;
    }
  }
  /* glibc accepts "//TRANSLIT" / "//IGNORE" suffixes; musl does not know them. */
  char tobuf[128];
  const char *sl = strstr(to, "//");
  if (sl) {
    if (strstr(sl, "IGNORE")) skip_bad = 1;
    snprintf(tobuf, sizeof tobuf, "%.*s", (int)(sl - to), to); to = tobuf;
  }
  cd = iconv_open(to, from);
  if (cd == (iconv_t)-1) { fprintf(stderr, "iconv: conversion from '%s' to '%s' is not supported\n", from, to); return 1; }
  if (optind >= argc) return convert(0, "(stdin)");
  for (int i = optind; i < argc; i++) {
    if (!strcmp(argv[i], "-")) { status |= convert(0, "(stdin)"); continue; }
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) { fprintf(stderr, "iconv: %s: %s\n", argv[i], strerror(errno)); status = 1; continue; }
    status |= convert(fd, argv[i]);
    close(fd);
  }
  return status;
}
