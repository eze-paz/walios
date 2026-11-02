// Which libc symbols a language runtime (lua.wasm, perl.wasm) can link in and export for its
// C modules: every global the sysroot's libc.a defines, minus the members that cannot link
// into a walios program (musl's TLS setup, fork, thread creation: __init_tls.o wants
// mmap2) and every member that needs one of them, transitively.
//
//   node libc-closure.js <llvm-nm> <libc.a>  -> stdout: the symbol names, one per line
const { execFileSync } = require('child_process');
const [nm, lib] = process.argv.slice(2);
const run = (args) => execFileSync(nm, [...args, lib], { maxBuffer: 1 << 28 }).toString();
const ROOTS = /^(__init_tls|_Fork|pthread_create|dl[a-z]*)\.o$/;   // dl*: wali_dlfcn.c replaces them

const defs = new Map(), needs = new Map(), defBy = new Map();      // member -> [sym], member -> [sym], sym -> member
const line = /^[^:]*\.a:([^:]+): +(?:[0-9a-f]+ )?([A-Za-z]) (\S+)$/;
for (const l of run(['-A', '-g', '--defined-only']).split('\n')) {
  const m = line.exec(l); if (!m) continue;
  const [, mem, t, s] = m;
  if (!defs.has(mem)) defs.set(mem, []);
  defs.get(mem).push({ s, strong: t !== 'W' && t !== 'V' });
  if (t !== 'W' && t !== 'V' || !defBy.has(s)) defBy.set(s, mem);
}
for (const l of run(['-A', '-u']).split('\n')) {
  const m = line.exec(l); if (!m) continue;
  if (!needs.has(m[1])) needs.set(m[1], []);
  needs.get(m[1]).push(m[3]);
}
const bad = new Set([...defs.keys()].filter((m) => ROOTS.test(m)));
for (let grew = true; grew;) {
  grew = false;
  for (const [mem, syms] of needs) {
    if (bad.has(mem)) continue;
    if (syms.some((s) => bad.has(defBy.get(s)))) { bad.add(mem); grew = true; }
  }
}
const out = new Set();
// Each name as the linker would resolve it (a strong definition over a weak one, e.g. malloc).
for (const [s, mem] of defBy) if (!bad.has(mem)) out.add(s);
process.stderr.write(`libc: ${defs.size} members, ${bad.size} left out (${[...bad].sort().join(' ')})\n`);
process.stdout.write([...out].sort().join('\n') + '\n');
