// merge.mjs <shard results dir> <index.json> <catalog.txt> <out e2e.json>: one result file for a
// farm release, and the counts against the catalog: built (the farm's pass) and works (passed in
// every engine the e2e ran). Libraries have no case of their own and are counted apart.
import fs from 'node:fs';
import path from 'node:path';
const [dir, indexFile, catalogFile, out] = process.argv.slice(2);
const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
const catalog = fs.readFileSync(catalogFile, 'utf8').split(/\s+/).filter(Boolean);
const results = {}; let engines = [];
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.json'))) {
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  engines = j.engines; Object.assign(results, j.results);
}
const inCat = (k) => catalog.includes(k);
const built = catalog.filter((k) => index.packages[k]);
const works = built.filter((k) => results[k] && engines.every((e) => results[k][e] && results[k][e][0] === 'pass'));
const libs = built.filter((k) => index.packages[k].kind === 'lib');
const outcome = {};
for (const k of built) if (results[k]) for (const e of engines) { const s = results[k][e] ? results[k][e][0] : 'none'; (outcome[e] = outcome[e] || {})[s] = (outcome[e][s] || 0) + 1; }
const shadowed = Object.entries(results).filter(([k, r]) => inCat(k) && r.shadowed).map(([k, r]) => `${k}:${r.shadowed}`);
const summary = { tag: index.tag, catalog: catalog.length, built: built.length, works: works.length, libs_not_run: libs.length, engines, outcome, shadowed };
fs.writeFileSync(out, JSON.stringify({ summary, results }, null, 1));
console.log(`works ${works.length}/${catalog.length} (built ${built.length}/${catalog.length}; ${libs.length} of those are libraries, not run alone)`);
console.log(JSON.stringify(outcome), 'shadowed by a busybox applet:', shadowed.length);
const bad = Object.entries(results).filter(([k, r]) => inCat(k) && engines.some((e) => r[e] && !['pass', 'skip'].includes(r[e][0])));
for (const [k, r] of bad.slice(0, 400)) console.log(`  ${k}: ` + engines.map((e) => `${e}=${r[e] ? r[e][0] + ' ' + String(r[e][1] || '').slice(0, 140) : '-'}`).join('  '));
