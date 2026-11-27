# Evaluate Go build constraints for a (goos, goarch) on files in given dirs.
import os, re, sys
KNOWN_OS = "aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos".split()
KNOWN_ARCH = "386 amd64 arm arm64 loong64 mips mipsle mips64 mips64le ppc64 ppc64le riscv64 s390x sparc64 wasm".split()
UNIX = "aix android darwin dragonfly freebsd hurd illumos ios linux netbsd openbsd solaris".split()
def tags_for(goos, goarch):
    t = {goos, goarch, "gc", "go1.27"}
    t |= {f"go1.{i}" for i in range(1, 28)}
    if goos in UNIX: t.add("unix")
    if goos == "android": t.add("linux")
    if goos in ("illumos",): t.add("solaris")
    if goos == "ios": t.add("darwin")
    return t
def name_ok(fn, goos, goarch):
    base = fn.rsplit(".", 1)[0]
    if base.endswith("_test"): return False
    parts = base.split("_")
    if len(parts) >= 3 and parts[-2] in KNOWN_OS and parts[-1] in KNOWN_ARCH:
        return parts[-2] == goos and parts[-1] == goarch
    if len(parts) >= 2 and parts[-1] in KNOWN_OS: return parts[-1] == goos
    if len(parts) >= 2 and parts[-1] in KNOWN_ARCH: return parts[-1] == goarch
    return True
def expr_ok(expr, tags):
    e = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    e = re.sub(r"[A-Za-z0-9_.]+", lambda m: str(m.group(0) in tags) if m.group(0) not in ("and","or","not") else m.group(0), e)
    return eval(e)
def build_line(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s.startswith("//go:build "): return s[len("//go:build "):]
            if s.startswith("package ") : return None
    return None
def files(d, goos, goarch):
    out = []
    for fn in sorted(os.listdir(d)):
        if not (fn.endswith(".go") or fn.endswith(".s")): continue
        if not name_ok(fn, goos, goarch): continue
        bl = build_line(os.path.join(d, fn))
        if bl and not expr_ok(bl, tags_for(goos, goarch)): continue
        out.append(fn)
    return out
if __name__ == "__main__":
    d = sys.argv[1]
    a = set(files(d, "wasip1", "wasm")); b = set(files(d, "linux", "wasm")); c = set(files(d, "linux", "amd64"))
    print("only wasip1/wasm:", " ".join(sorted(a - b)))
    print("only linux/wasm (new):", " ".join(sorted(b - a)))

def arch_gap(d):
    la = files(d, "linux", "amd64"); lw = set(files(d, "linux", "wasm"))
    return [f for f in la if ("amd64" in f) and f not in lw]
