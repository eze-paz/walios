#!/usr/bin/env node
// Fold a farm run's result rows into the package index published with the release.
//   make-index.js <results-dir> <tag> > index.json      (a markdown summary goes to stderr)
// index.json: {tag, built, toolchain, packages:{name:{ver,kind,file,size,sha256,smoke,secs}},
//              failed:{name:{ver,reason,secs}}}
// A walios host turns file into https://<cdn>/<tag>/<file> (walios/cdn in sandpie).
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [dir, tag] = process.argv.slice(2);
const rows = fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
const index = { tag, built: new Date().toISOString(), toolchain: 'LLVM 22.1.3 + wali-sysroot (pkgs-2026-10-31)', packages: {}, failed: {} };
for (const r of rows.sort((a, b) => a.pkg.localeCompare(b.pkg))) {
  if (r.status === 'pass' && r.kind === 'exe') {
    const file = `${r.pkg}.wasm`, buf = fs.readFileSync(path.join(dir, file));
    index.packages[r.pkg] = { ver: r.ver, kind: 'exe', file, size: buf.length, sha256: crypto.createHash('sha256').update(buf).digest('hex'), smoke: r.smoke, secs: r.secs };
  } else if (r.status === 'pass') index.packages[r.pkg] = { ver: r.ver, kind: r.kind, secs: r.secs };
  else if (r.status === 'skip') (index.skipped = index.skipped || {})[r.pkg] = { ver: r.ver, reason: r.reason };
  else index.failed[r.pkg] = { ver: r.ver, reason: r.reason, secs: r.secs };
}
process.stdout.write(JSON.stringify(index, null, 1) + '\n');
const exe = Object.values(index.packages).filter(p => p.kind === 'exe').length;
const lib = Object.keys(index.packages).length - exe, nf = Object.keys(index.failed).length;
const reasons = {}; for (const f of Object.values(index.failed)) { const k = String(f.reason).split(':')[0]; reasons[k] = (reasons[k] || 0) + 1; }
const secs = rows.map(r => r.secs || 0).sort((a, b) => a - b);
const med = secs.length ? secs[secs.length >> 1] : 0, tot = secs.reduce((a, b) => a + b, 0);
const ns = Object.keys(index.skipped || {}).length;
process.stderr.write(`## walios farm ${tag}\n\n${rows.length} packages: **${exe} runnable**, ${lib} libraries, ${nf} failed, ${ns} skipped (noarch / needs rust or go).\n\n` +
  `Build time: median ${med}s, total ${Math.round(tot / 60)} min of job time.\n\nFailures: ` +
  Object.entries(reasons).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ') + '\n');
