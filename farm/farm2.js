#!/usr/bin/env node
// WALI build farm at scale, dependency-ordered.
// Fetches real Alpine APKBUILDs, builds a dep graph among the seed set,
// topo-sorts (libs before dependents), builds each into a shared overlay
// sysroot, smoke-tests executables, writes repo/manifest.json.
'use strict';
const { execSync, execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const HOME = os.homedir();
const FARM = path.join(HOME, 'wali-farm');
const OVERLAY = path.join(FARM, 'overlay');
const APORTS = 'https://git.alpinelinux.org/aports/plain';

// pre-flight gate: a broken host silently poisons every smoke test in the run,
// so refuse to farm until the regression suite is green against the SAME host
// build-one.sh uses. FARM_NO_GATE=1 skips (e.g. mid-bringup of a new syscall).
if (!process.env.FARM_NO_GATE) {
  const runsh = [path.join(HOME, 'wali-os', 'tests', 'run.sh'), path.join(__dirname, '..', 'tests', 'run.sh')]
    .find(p => fs.existsSync(p));
  if (runsh) {
    console.log('[farm] pre-flight: regression suite vs ' + path.join(HOME, 'walihost', 'host.js'));
    try {
      execFileSync('bash', [runsh], { stdio: 'inherit', timeout: 300000,
        env: { ...process.env, HOST: path.join(HOME, 'walihost', 'host.js') } });
    } catch {
      console.error('[farm] pre-flight FAILED — host regressions would poison every smoke test. Fix the host or set FARM_NO_GATE=1.');
      process.exit(1);
    }
  } else console.log('[farm] pre-flight: tests/run.sh not found, skipping gate');
}

// Seed = DEPENDENTS ONLY. The closure crawler discovers and orders their
// libraries automatically (grep→pcre2, jq→oniguruma, less→ncurses, file→zlib...).
const SEED = ['grep', 'jq', 'file', 'less', 'tar', 'sed', 'bc'];

fs.mkdirSync(path.join(FARM, 'log'), { recursive: true });
fs.mkdirSync(path.join(OVERLAY, 'usr', 'lib'), { recursive: true });
fs.mkdirSync(path.join(OVERLAY, 'usr', 'include'), { recursive: true });

function sh(cmd) { return execSync(cmd, { encoding: 'utf8', timeout: 60000 }); }

// host-provided build tools / virtuals / non-buildable deps — pruned from the
// closure (we don't cross-compile these; the CI host supplies them).
const DENY = new Set(['autoconf', 'automake', 'libtool', 'pkgconf', 'pkgconfig', 'make', 'cmake',
  'meson', 'ninja', 'samurai', 'bison', 'flex', 'gettext', 'gettext-tiny', 'gettext-dev', 'texinfo',
  'perl', 'python3', 'py3-setuptools', 'linux-headers', 'musl-dev', 'gcc', 'g++', 'clang', 'llvm',
  'bsd-compat-headers', 'utmps', 'byacc', 'gperf', 'help2man', 'doxygen', 'groff', 'scdoc', 'asciidoc',
  'coreutils', 'grep', 'sed', 'gzip', 'xz', 'zstd', 'brotli', 'go', 'rust', 'cargo', 'ca-certificates',
  'openrc', 'lang', 'bash', 'sh']);
const MAXPKGS = 50; // bound the closure so it doesn't drag in half of Alpine
const clean = (d) => d.replace(/[<>=].*$/, '').replace(/-dev$/, '');
const skip = (d) => !d || d.includes(':') || d.startsWith('!') || d.startsWith('$') || DENY.has(d) ||
  /-doc$|-lang$|-openrc$|-static$|-bash-completion$/.test(d);

// ---- transitive dependency closure (BFS over real APKBUILDs) ----
console.log(`[farm] resolving dependency closure from ${SEED.length} seeds (cap ${MAXPKGS})...`);
const meta = {};
const worklist = [...SEED]; const seen = new Set(SEED);
while (worklist.length && Object.keys(meta).length < MAXPKGS) {
  const pkg = worklist.shift();
  let txt = null;
  for (const sub of ['main', 'community']) {
    try { txt = sh(`curl -sSfL --max-time 20 "${APORTS}/${sub}/${pkg}/APKBUILD"`); break; } catch {}
  }
  if (!txt) { meta[pkg] = { missing: true, deps: [] }; console.log(`  ${pkg}: NO RECIPE`); continue; }
  const tmp = path.join(FARM, 'log', `_apk_${pkg}`); fs.writeFileSync(tmp, txt);
  let deps = '';
  try { deps = sh(`bash -c 'source "${tmp}" 2>/dev/null; echo "$depends $makedepends"'`); } catch {}
  const ver = (txt.match(/^pkgver=(\S+)/m) || [])[1] || '?';
  const names = [...new Set(deps.split(/\s+/).map(clean).filter(d => !skip(d)))];
  meta[pkg] = { ver, deps: names };
  const fresh = names.filter(d => !seen.has(d));
  fresh.forEach(d => { seen.add(d); if (Object.keys(meta).length + worklist.length < MAXPKGS) worklist.push(d); });
  console.log(`  ${pkg} ${ver}: deps=[${names.join(', ') || '-'}]${fresh.length ? ` (+pulled: ${fresh.join(', ')})` : ''}`);
}
console.log(`[farm] closure = ${Object.keys(meta).length} packages (from ${SEED.length} seeds)`);

// ---- build dependency graph over the whole closure, topo-sort (Kahn) ----
const inset = new Set(Object.keys(meta).filter(p => !meta[p].missing));
const edges = {}, indeg = {};
for (const p of inset) { edges[p] = []; indeg[p] = 0; }
for (const p of inset) for (const d of meta[p].deps) {
  if (inset.has(d) && d !== p && !edges[d].includes(p)) { edges[d].push(p); indeg[p]++; }
}
const order = [], q = [...inset].filter(p => indeg[p] === 0).sort();
while (q.length) {
  const n = q.shift(); order.push(n);
  for (const m of edges[n]) if (--indeg[m] === 0) q.push(m);
}
for (const p of inset) if (!order.includes(p)) order.push(p); // cycle guard
console.log(`\n[farm] build order (deps first):\n  ${order.join(' -> ')}\n`);

// ---- build each in order ----
const results = {};
let pass = 0, i = 0;
for (const pkg of order) {
  i++;
  process.stdout.write(`[${i}/${order.length}] ${pkg} ... `);
  let row;
  try {
    const out = execFileSync('bash', [path.join(FARM, 'build-one.sh'), pkg, OVERLAY], { encoding: 'utf8', timeout: 240000 });
    const last = out.trim().split('\n').filter(l => l.startsWith('{')).pop();
    row = JSON.parse(last);
  } catch (e) {
    row = { pkg, ver: meta[pkg].ver, status: 'fail', reason: e.killed ? 'timeout' : 'builder-error', wasm: '', kind: '', smoke: '' };
  }
  row.tier = row.status === 'pass' ? 'wasm' : 'vm-only';
  results[pkg] = row;
  if (row.status === 'pass') pass++;
  console.log(`${row.status} (${row.reason})${row.kind === 'lib' ? ' [lib]' : ''} ${row.secs != null ? row.secs + 's' : ''}${row.smoke ? ' :: ' + row.smoke : ''}`);
  fs.writeFileSync(path.join(FARM, 'repo', 'manifest.json'), JSON.stringify(results, null, 2)); // incremental
}

console.log(`\n[farm] DONE: ${pass}/${order.length} passed -> wasm tier`);
console.log(`[farm] manifest: ${path.join(FARM, 'repo', 'manifest.json')}`);
const libs = order.filter(p => results[p].kind === 'lib' && results[p].status === 'pass');
const exes = order.filter(p => results[p].kind === 'exe' && results[p].status === 'pass');
console.log(`[farm] libraries: ${libs.join(', ') || '(none)'}`);
console.log(`[farm] executables: ${exes.join(', ') || '(none)'}`);
// timing summary (build-to-wasm wall per package)
const timed = order.map(p => [p, results[p].secs || 0, results[p].status]).filter(x => x[1] > 0);
timed.sort((a, b) => b[1] - a[1]);
const green = timed.filter(x => x[2] === 'pass');
const sum = green.reduce((a, x) => a + x[1], 0);
console.log(`\n[farm] BUILD TIMES (wall, compile+link to wasm):`);
for (const [p, s, st] of timed) console.log(`  ${String(s).padStart(4)}s  ${p} (${st})`);
if (green.length) console.log(`[farm] green avg ${(sum / green.length).toFixed(1)}s, median ${green.map(x=>x[1]).sort((a,b)=>a-b)[Math.floor(green.length/2)]}s, total ${sum}s for ${green.length} pkgs`);
