import os, sys; sys.path.insert(0, 'C:/gw/tools'); import tags
for root, dirs, fs in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ('testdata', 'cmd') and not d.startswith('.')]
    if not any(f.endswith('.go') for f in fs): continue
    a = set(tags.files(root, 'linux', 'amd64')); w = set(tags.files(root, 'linux', 'wasm'))
    # amd64-only files whose function has no wasm counterpart: list file names only
    g = sorted(f for f in a - w)
    wonly = sorted(w - a)
    if g: print(root.replace(chr(92), '/'), '| amd64-only:', ' '.join(g), '| wasm-only:', ' '.join(wonly))
