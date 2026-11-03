// The busybox functions that are reached through a FUNCTION POINTER and can fork(), i.e. the
// function-table entries from which the fork import is reachable by direct calls. One name
// per line, sorted.
//
//   wasm-dis busybox -o busybox.wat && node fork-entries.mjs busybox.wat [import]   (default wali.SYS_fork)
//
// build.sh compares this against fork-entries.txt. Asyncify runs with ignore-indirect, so every
// place that CALLS one of these through a pointer has to be named in its addlist (the applet
// table, ash's evaltree/evalbltin, hush's builtin dispatch, find's action walker, tar's data
// handler). If a config or version change adds an entry, the build stops here instead of
// shipping a fork path Asyncify cannot unwind.
import fs from 'node:fs';
const [, , file, imp = 'wali.SYS_fork'] = process.argv;
if (!file) { console.error('usage: node fork-entries.mjs <busybox.wat> [import]'); process.exit(2); }
const calls = new Map(), importOf = new Map(), tableFns = new Set();
let cur = null;
for (const l of fs.readFileSync(file, 'utf8').split('\n')) {
  let m = /^ \(import "([^"]+)" "([^"]+)" \(func \$([^\s()]+)/.exec(l);
  if (m) { importOf.set(m[3], m[1] + '.' + m[2]); continue; }
  m = /^ \(func \$([^\s()]+)/.exec(l);
  if (m) { cur = m[1]; calls.set(cur, new Set()); continue; }
  if (/^ \(elem /.test(l)) { for (const x of l.matchAll(/\$([^\s()]+)/g)) tableFns.add(x[1]); continue; }
  if (/^ \(/.test(l)) { cur = null; continue; }
  // A call's operands go on the following lines, so the name often ends the line.
  if (cur) for (const c of l.matchAll(/\((?:return_)?call \$([^\s()]+)/g)) calls.get(cur).add(c[1]);
}
const callers = new Map();
for (const [f, cs] of calls) for (const c of cs) { if (!callers.has(c)) callers.set(c, new Set()); callers.get(c).add(f); }
const reach = new Set(), work = [];
for (const [n, i] of importOf) if (i === imp) { reach.add(n); work.push(n); }
if (!reach.size) { console.error('fork-entries: ' + imp + ' is not imported'); process.exit(1); }
while (work.length) { const n = work.pop(); for (const c of callers.get(n) || []) if (!reach.has(c)) { reach.add(c); work.push(c); } }
process.stdout.write([...reach].filter((n) => tableFns.has(n)).sort().join('\n') + '\n');
