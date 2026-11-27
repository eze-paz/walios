# mkpatched.py RULES MODDIR GOMODCACHE GOMOD
# Copies each module named in RULES from the module cache to MODDIR, applies the rules there,
# and adds `replace <module> => <copy>` to GOMOD. Rules (one per line, '#' comments):
#   copy <module@ver>[/<dir>] <file_amd64.go>      add a linux/wasm twin (amd64 -> wasm in name and //go:build)
#   tag  <module@ver>[/<dir>] <file.go> <suffix>   append <suffix> to the file's //go:build expression
#   add  <module@ver>[/<dir>] <file.go>            add files/<file.go> (next to RULES) to the package
#   mirror <module@ver>[/<dir>]                    make the package's linux/wasm file set equal its linux/amd64 one
import os, re, shutil, stat, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import tags
rules, moddir, mc, gomod = sys.argv[1:5]
done = {}
def modcopy(modver):
    if modver in done: return done[modver]
    src = os.path.join(mc, modver); dst = os.path.join(moddir, modver.replace('/', '_'))
    if os.path.exists(dst):
        shutil.rmtree(dst, onerror=lambda f, p, e: (os.chmod(p, stat.S_IWRITE), f(p)))
    shutil.copytree(src, dst)
    for r, ds, fs in os.walk(dst):
        for f in fs: os.chmod(os.path.join(r, f), stat.S_IWRITE | stat.S_IREAD)
    done[modver] = dst; return dst
def split(d):  # module@ver/dir -> (module@ver, dir)
    i = d.index('@'); j = d.find('/', i)
    return (d, '') if j < 0 else (d[:j], d[j + 1:])
for ln in open(rules, encoding='utf-8'):
    ln = ln.split('#', 1)[0].strip()
    if not ln: continue
    parts = ln.split(None, 3); kind, d = parts[0], parts[1]; f = parts[2] if len(parts) > 2 else ''
    modver, sub = split(d); root = modcopy(modver); p = os.path.join(root, sub, f)
    if kind == 'mirror':
        # make the package's linux/wasm file set equal its linux/amd64 one (no-asm packages only)
        pd = os.path.join(root, sub)
        a = set(tags.files(pd, 'linux', 'amd64')); w = set(tags.files(pd, 'linux', 'wasm'))
        if any(x.endswith('.s') for x in a): sys.exit('mirror: %s has amd64 assembly' % d)
        for x in sorted(a - w):
            xs = open(os.path.join(pd, x), encoding='utf-8', newline='').read()
            if 'amd64' in x:
                xs = re.sub(r'^//go:build (.*)$', lambda m: '//go:build ' + re.sub(r'amd64', 'wasm', m.group(1)), xs, count=1, flags=re.M)
                open(os.path.join(pd, x.replace('amd64', 'wasm')), 'w', encoding='utf-8', newline='').write(xs)
            else:
                xs = re.sub(r'^//go:build (.*)$', lambda m: '//go:build (' + m.group(1) + ') || (linux && wasm)', xs, count=1, flags=re.M)
                open(os.path.join(pd, x), 'w', encoding='utf-8', newline='').write(xs)
        for x in sorted(w - a):
            xs = open(os.path.join(pd, x), encoding='utf-8', newline='').read()
            if re.search(r'^//go:build ', xs, re.M):
                xs = re.sub(r'^//go:build (.*)$', lambda m: '//go:build (' + m.group(1) + ') && !(linux && wasm)', xs, count=1, flags=re.M)
            else:
                i = xs.index(chr(10) + 'package '); xs = xs[:i] + chr(10) + '//go:build !(linux && wasm)' + chr(10) + xs[i:]
            open(os.path.join(pd, x), 'w', encoding='utf-8', newline='').write(xs)
        continue
    if kind == 'add':
        shutil.copyfile(os.path.join(os.path.dirname(os.path.abspath(rules)), 'files', f), p)
        continue
    s = open(p, encoding='utf-8', newline='').read()
    if kind == 'copy':
        s = re.sub(r'^//go:build (.*)$', lambda m: '//go:build ' + re.sub(r'\bamd64\b', 'wasm', m.group(1)), s, count=1, flags=re.M)
        open(os.path.join(root, sub, f.replace('amd64', 'wasm')), 'w', encoding='utf-8', newline='').write(s)
    elif kind == 'tag':
        s = re.sub(r'^//go:build (.*)$', lambda m: '//go:build (' + m.group(1) + ') ' + parts[3], s, count=1, flags=re.M)
        open(p, 'w', encoding='utf-8', newline='').write(s)
    else: sys.exit('bad rule: ' + ln)
g = open(gomod, encoding='utf-8', newline='').read()
g = re.sub(r'\n// walios-replace-begin.*?// walios-replace-end\n', '\n', g, flags=re.S)
g += '\n// walios-replace-begin\n' + ''.join('replace %s => %s\n' % (m.split('@')[0], d.replace(chr(92), '/')) for m, d in done.items()) + '// walios-replace-end\n'
open(gomod, 'w', encoding='utf-8', newline='').write(g)
print(len(done), 'patched modules')
