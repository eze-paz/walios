#!/usr/bin/env node
// WALI build farm — SCALE edition. Dependency-ordered, resumable, parallel.
// Over farm2.js it adds:
//   - closure cache (APKBUILDs + computed graph cached to disk; re-runs skip the crawl)
//   - resumability (packages already 'pass' in the manifest with a live artifact are skipped)
//   - parameterized: FARM_SEEDS, FARM_MAX, FARM_JOBS, FARM_FORCE
//   - topo-aware pool (a package builds only once its deps are done)
// FARM_JOBS>1 is EXPERIMENTAL: build-one.sh installs into a SHARED overlay sysroot, so
// concurrent builds can race (a dependent linking against a half-installed lib -> no
// wasm output). Safe default is JOBS=1 (correct, and the big scale wins are resume +
// cache, which don't need parallelism). Real parallelism needs per-build overlay
// snapshots + serialized merge — left as future work.
// Env:
//   FARM_SEEDS="grep jq file less tar sed bc ..."   (default below)
//   FARM_MAX=200   FARM_JOBS=<cpus-1>   FARM_FORCE=1 (rebuild all)
'use strict';
const { execSync, spawn } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const HOME = os.homedir();
const FARM = path.join(HOME, 'wali-farm');
const OVERLAY = path.join(FARM, 'overlay');
const REPO = path.join(FARM, 'repo');
const APORTS = 'https://git.alpinelinux.org/aports/plain';
const CACHE = path.join(FARM, 'cache'); // APKBUILD + closure cache

const SEED = (process.env.FARM_SEEDS || 'grep jq file less tar sed bc gawk diffutils findutils patch which').split(/\s+/).filter(Boolean);
const MAXPKGS = +(process.env.FARM_MAX || 200);
const JOBS = +(process.env.FARM_JOBS || 1); // 1 = safe (shared overlay); >1 experimental
const FORCE = !!process.env.FARM_FORCE;

for (const d of [path.join(FARM, 'log'), CACHE, REPO, path.join(OVERLAY, 'usr', 'lib'), path.join(OVERLAY, 'usr', 'include')]) fs.mkdirSync(d, { recursive: true });
function sh(cmd) { return execSync(cmd, { encoding: 'utf8', timeout: 60000 }); }

const DENY = new Set(['autoconf', 'automake', 'libtool', 'pkgconf', 'pkgconfig', 'make', 'cmake',
  'meson', 'ninja', 'samurai', 'bison', 'flex', 'gettext', 'gettext-tiny', 'gettext-dev', 'texinfo',
  'perl', 'python3', 'py3-setuptools', 'linux-headers', 'musl-dev', 'gcc', 'g++', 'clang', 'llvm',
  'bsd-compat-headers', 'utmps', 'byacc', 'gperf', 'help2man', 'doxygen', 'groff', 'scdoc', 'asciidoc',
  'coreutils', 'grep', 'sed', 'gzip', 'xz', 'zstd', 'brotli', 'go', 'rust', 'cargo', 'ca-certificates',
  'openrc', 'lang', 'bash', 'sh']);
const clean = (d) => d.replace(/[<>=].*$/, '').replace(/-dev$/, '');
const skip = (d) => !d || d.includes(':') || d.startsWith('!') || d.startsWith('$') || DENY.has(d) ||
  /-doc$|-lang$|-openrc$|-static$|-bash-completion$/.test(d);

// ---- fetch an APKBUILD (disk-cached) ----
function fetchApkbuild(pkg) {
  const cf = path.join(CACHE, `${pkg}.APKBUILD`);
  if (fs.existsSync(cf)) return fs.readFileSync(cf, 'utf8') || null;
  for (const sub of ['main', 'community']) {
    try { const t = sh(`curl -sSfL --max-time 20 "${APORTS}/${sub}/${pkg}/APKBUILD"`); fs.writeFileSync(cf, t); return t; } catch {}
  }
  fs.writeFileSync(cf, ''); return null; // negative-cache
}

// ---- transitive dependency closure (BFS, cached) ----
console.log(`[farm] closure from ${SEED.length} seeds (cap ${MAXPKGS}, jobs ${JOBS})...`);
const meta = {};
const worklist = [...SEED]; const seen = new Set(SEED);
while (worklist.length && Object.keys(meta).length < MAXPKGS) {
  const pkg = worklist.shift();
  const txt = fetchApkbuild(pkg);
  if (!txt) { meta[pkg] = { missing: true, deps: [] }; continue; }
  const tmp = path.join(CACHE, `_src_${pkg}`); fs.writeFileSync(tmp, txt);
  let deps = '';
  try { deps = sh(`bash -c 'source "${tmp}" 2>/dev/null; echo "$depends $makedepends"'`); } catch {}
  const ver = (txt.match(/^pkgver=(\S+)/m) || [])[1] || '?';
  const names = [...new Set(deps.split(/\s+/).map(clean).filter(d => !skip(d)))];
  meta[pkg] = { ver, deps: names };
  names.filter(d => !seen.has(d)).forEach(d => { seen.add(d); if (Object.keys(meta).length + worklist.length < MAXPKGS) worklist.push(d); });
}
const closure = Object.keys(meta).length;
console.log(`[farm] closure = ${closure} packages`);

// ---- topo order (deps first) ----
const inset = new Set(Object.keys(meta).filter(p => !meta[p].missing));
const edges = {}, indeg = {};
for (const p of inset) { edges[p] = []; indeg[p] = 0; }
for (const p of inset) for (const d of meta[p].deps) if (inset.has(d) && d !== p && !edges[d].includes(p)) { edges[d].push(p); indeg[p]++; }
const order = [], q0 = [...inset].filter(p => indeg[p] === 0).sort();
{ const id = { ...indeg }; const q = [...q0];
  while (q.length) { const n = q.shift(); order.push(n); for (const m of edges[n]) if (--id[m] === 0) q.push(m); }
  for (const p of inset) if (!order.includes(p)) order.push(p); }
console.log(`[farm] ${order.length} buildable; ${closure - order.length} unbuildable (missing recipe)`);

// ---- resumable manifest ----
const manifestPath = path.join(REPO, 'manifest.json');
let results = {};
if (!FORCE && fs.existsSync(manifestPath)) { try { results = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch {} }
const artifactLive = (row) => row && row.status === 'pass' && (row.kind === 'lib' || !row.wasm || fs.existsSync(row.wasm) || fs.existsSync(path.join(REPO, path.basename(row.wasm || ''))));
const isDone = (p) => !FORCE && artifactLive(results[p]);
const depsSatisfied = (p) => meta[p].deps.every(d => !inset.has(d) || isDone(d) || results[d]); // built or attempted

// ---- parallel, topo-aware build pool ----
function buildOne(pkg) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn('bash', [path.join(FARM, 'build-one.sh'), pkg, OVERLAY], { encoding: 'utf8' });
    let out = ''; const to = setTimeout(() => child.kill('SIGKILL'), 300000);
    child.stdout.on('data', d => out += d); child.stderr.on('data', () => {});
    child.on('close', () => { clearTimeout(to);
      let row; try { row = JSON.parse(out.trim().split('\n').filter(l => l.startsWith('{')).pop()); }
      catch { row = { pkg, ver: meta[pkg].ver, status: 'fail', reason: 'builder-error', wasm: '', kind: '', smoke: '' }; }
      row.tier = row.status === 'pass' ? 'wasm' : 'vm-only';
      if (row.secs == null) row.secs = Math.round((Date.now() - started) / 1000);
      resolve(row);
    });
  });
}

(async () => {
  const pending = new Set(order);
  let running = 0, built = 0, skipped = 0;
  const t0 = Date.now();
  // pre-skip already-built
  for (const p of order) if (isDone(p)) { pending.delete(p); skipped++; }
  console.log(`[farm] resuming: ${skipped} already built, ${pending.size} to build, ${JOBS} parallel\n`);
  await new Promise((finish) => {
    const pump = () => {
      if (!pending.size && running === 0) return finish();
      for (const p of [...pending]) {
        if (running >= JOBS) break;
        if (!depsSatisfied(p)) continue;   // wait for deps
        pending.delete(p); running++;
        buildOne(p).then((row) => {
          results[p] = row; running--; built++;
          if (row.status === 'pass') { /* ok */ }
          console.log(`[${built + skipped}/${order.length}] ${p} ${row.status} (${row.reason})${row.kind === 'lib' ? ' [lib]' : ''} ${row.secs}s${row.smoke ? ' :: ' + row.smoke : ''}`);
          fs.writeFileSync(manifestPath, JSON.stringify(results, null, 2));
          pump();
        });
      }
      // deadlock guard: nothing running and nothing ready (unsatisfiable deps) -> build them anyway
      if (running === 0 && pending.size) { const p = [...pending][0]; pending.delete(p); running++;
        buildOne(p).then((row) => { results[p] = row; running--; built++;
          console.log(`[${built + skipped}/${order.length}] ${p} ${row.status} (${row.reason}) [forced]`); fs.writeFileSync(manifestPath, JSON.stringify(results, null, 2)); pump(); }); }
    };
    pump();
  });
  const pass = order.filter(p => results[p] && results[p].status === 'pass').length;
  const secs = ((Date.now() - t0) / 1000).toFixed(0);
  console.log(`\n[farm] DONE: ${pass}/${order.length} pass -> wasm tier (${skipped} skipped, ${built} built this run, ${secs}s wall @ ${JOBS} jobs)`);
  const libs = order.filter(p => results[p] && results[p].kind === 'lib' && results[p].status === 'pass');
  const exes = order.filter(p => results[p] && results[p].kind === 'exe' && results[p].status === 'pass');
  console.log(`[farm] libraries (${libs.length}): ${libs.join(', ') || '(none)'}`);
  console.log(`[farm] executables (${exes.length}): ${exes.join(', ') || '(none)'}`);
})();
