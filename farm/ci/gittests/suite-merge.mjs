// Merge suite.mjs shard results into one results.json + a markdown summary.
//   node farm/ci/gittests/suite-merge.mjs <dir with gittests-*.json> <out-dir>
import fs from 'node:fs';
import path from 'node:path';

const [dir, out] = process.argv.slice(2);
fs.mkdirSync(out, { recursive: true });
const results = {};
for (const f of fs.readdirSync(dir, { recursive: true })) {
  if (!/gittests-\d+\.json$/.test(f)) continue;
  Object.assign(results, JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')).results);
}
const names = Object.keys(results).sort();
const tot = { pass: 0, fail: 0, skip: 0, known: 0 }, by = {};
for (const n of names) { const r = results[n]; for (const k of Object.keys(tot)) tot[k] += r[k] || 0; by[r.status] = (by[r.status] || 0) + 1; }
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ scripts: names.length, by, tot, results }, null, 1));

const bad = names.filter((n) => results[n].status !== 'ok');
let md = `# git 2.45.3 test suite in walios\n\n`
  + `**${names.length} scripts**: ${Object.entries(by).map(([k, v]) => `${v} ${k}`).join(', ')}  \n`
  + `**tests**: ${tot.pass} passed, ${tot.fail} failed, ${tot.skip} skipped, ${tot.known} known breakages (# TODO)\n\n`;
if (bad.length) {
  md += `| script | status | pass | fail | skip | first failures |\n|---|---|---|---|---|---|\n`;
  for (const n of bad) {
    const r = results[n];
    md += `| ${n} | ${r.status} | ${r.pass} | ${r.fail} | ${r.skip} | ${(r.failures || []).slice(0, 3).join('; ').replace(/\|/g, '\\|').slice(0, 200)} |\n`;
  }
}
fs.writeFileSync(path.join(out, 'summary.md'), md);
// The failing scripts' logs, one file (the release asset to read failures from)
let logs = '';
for (const n of bad) {
  const r = results[n];
  logs += `\n\n======== ${n}: ${r.status} (pass ${r.pass} fail ${r.fail})\n` + (r.failures || []).join('\n')
    + (r.host && r.host.length ? '\n-- host:\n' + r.host.join('\n') : '') + '\n-- tap tail:\n' + (r.tail || '') + '\n-- log tail:\n' + (r.log || '') + (r.stats ? '\n-- kernel at timeout:\n' + r.stats : '');
}
fs.writeFileSync(path.join(out, 'failures.log'), logs);
console.log(md);
