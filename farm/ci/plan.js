#!/usr/bin/env node
// Plan a farm run: package set -> dependency waves -> GitHub Actions matrix chunks.
//   PKGS="a b c"   explicit seeds, or
//   SAMPLE=50      a deterministic sample of farm/ci/catalog.txt (SEED=1), or
//   ALL=1          the whole catalog
//   MAX=400        cap on seeds + dependency closure
//   WAVES=8        dependency waves (deeper chains collapse into the last one)
//   CHUNK=8        packages per matrix job (one wave stays <= 256 jobs: GitHub's cap)
// Deps = APKBUILD depends + makedepends(+_host/_build) + depends_dev, minus build tools (DENY).
// Prints {waves:[[chunk,...],...], count}; with GITHUB_OUTPUT set, writes w0..wN + count.
'use strict';
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const APORTS = 'https://git.alpinelinux.org/aports/plain';
const DENY = new Set(['autoconf', 'automake', 'libtool', 'pkgconf', 'pkgconfig', 'make', 'cmake',
  'meson', 'ninja', 'samurai', 'bison', 'gettext', 'gettext-tiny', 'gettext-dev', 'texinfo',
  'perl', 'python3', 'py3-setuptools', 'linux-headers', 'musl-dev', 'gcc', 'g++', 'clang', 'llvm',
  'bsd-compat-headers', 'byacc', 'gperf', 'help2man', 'doxygen', 'groff', 'scdoc', 'asciidoc',
  'coreutils', 'grep', 'sed', 'gzip', 'xz', 'zstd', 'brotli', 'go', 'rust', 'cargo', 'ca-certificates',
  'openrc', 'lang', 'bash', 'sh']);
const clean = (d) => d.replace(/[<>=~].*$/, '').replace(/-dev$/, '');
const skip = (d) => !d || d.includes(':') || d.startsWith('!') || d.startsWith('$') || DENY.has(d) ||
  /-doc$|-lang$|-openrc$|-static$|-bash-completion$/.test(d);

const catalog = fs.readFileSync(path.join(__dirname, 'catalog.txt'), 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
const MAX = +(process.env.MAX || 400), NW = +(process.env.WAVES || 8), CHUNK = +(process.env.CHUNK || 8);
let seeds;
if (process.env.PKGS) seeds = process.env.PKGS.split(/[\s,]+/).filter(Boolean);
else if (process.env.ALL) seeds = catalog.slice();
else {  // deterministic sample: mulberry32
  let a = +(process.env.SEED || 1) >>> 0;
  const rnd = () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const pool = catalog.slice(); for (let i = pool.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [pool[i], pool[j]] = [pool[j], pool[i]]; }
  seeds = pool.slice(0, +(process.env.SAMPLE || 50));
}

// APORTS_DIR = a checkout of alpinelinux/aports (CI clones the GitHub mirror, depth 1);
// without one, each recipe is fetched from git.alpinelinux.org (slow: minutes per 100).
const ADIR = process.env.APORTS_DIR, where = {};
function apkbuild(pkg) {
  for (const sub of ['main', 'community']) {
    if (ADIR) { const f = path.join(ADIR, sub, pkg, 'APKBUILD'); if (fs.existsSync(f)) { where[pkg] = `${sub}/${pkg}`; return fs.readFileSync(f, 'utf8'); } continue; }
    try { const t = execFileSync('curl', ['-sSfL', '--retry', '3', '--max-time', '30', `${APORTS}/${sub}/${pkg}/APKBUILD`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); where[pkg] = `${sub}/${pkg}`; return t; } catch {}
  }
  return null;
}
function depsOf(txt) {
  const f = path.join(require('os').tmpdir(), `apk-${process.pid}`); fs.writeFileSync(f, txt);
  let d = '';
  try { d = execFileSync('bash', ['-c', `source "${f}" >/dev/null 2>&1; echo "$depends $makedepends $makedepends_host $makedepends_build $depends_dev"`], { encoding: 'utf8' }); } catch {}
  return [...new Set(d.split(/\s+/).map(clean).filter(x => !skip(x)))];
}

// Subpackages (musl-utils, lua5.4-posix, mariadb-client) have no aport dir of their own: map
// each to the aport that builds it, from every APKBUILD's subpackages= line (textually --
// sourcing ~10k recipes would take minutes). Only with a local aports checkout.
const origin = {};
if (ADIR) for (const sub of ['main', 'community']) {
  for (const dir of fs.readdirSync(path.join(ADIR, sub))) {
    let t; try { t = fs.readFileSync(path.join(ADIR, sub, dir, 'APKBUILD'), 'utf8'); } catch { continue; }
    const name = (t.match(/^pkgname=["']?([^"'\s]+)/m) || [])[1] || dir;
    const m = t.match(/^subpackages="([^"]*)"/m);
    if (!m) continue;
    for (let s of m[1].split(/\s+/)) {
      s = s.split(':')[0].replace(/\$\{?pkgname\}?/g, name);
      if (s && !/[$`{}]/.test(s) && !fs.existsSync(path.join(ADIR, 'main', s)) && !fs.existsSync(path.join(ADIR, 'community', s))) origin[s] = origin[s] || dir;
    }
  }
}
// Lua module subpackages are generated in a loop (lua5.4-posix from aport lua-posix).
const hasDir = (p) => ADIR && (fs.existsSync(path.join(ADIR, 'main', p)) || fs.existsSync(path.join(ADIR, 'community', p)));
const canon = (p) => {
  if (origin[p]) return origin[p];
  const m = p.match(/^lua5\.\d-(.+)$/);
  if (m && !hasDir(p)) for (const o of ['lua-' + m[1], m[1]]) if (hasDir(o)) return (origin[p] = o);
  return p;
};
const aliases = {};
for (const s of seeds) if (canon(s) !== s) aliases[s] = canon(s);
seeds = [...new Set(seeds.map(canon))];

const meta = {}, queue = [...seeds], seen = new Set(seeds);
while (queue.length && Object.keys(meta).length < MAX) {
  const p = queue.shift(), txt = apkbuild(p);
  if (!txt) { meta[p] = { missing: true, deps: [] }; continue; }
  meta[p] = { deps: [...new Set(depsOf(txt).map(canon))].filter(d => d !== p) };
  for (const d of meta[p].deps) if (!seen.has(d)) { seen.add(d); queue.push(d); }
}
if (process.env.ALIASES_OUT) fs.writeFileSync(process.env.ALIASES_OUT, JSON.stringify(aliases));
const set = new Set(Object.keys(meta).filter(p => !meta[p].missing));
const wave = {};
const level = (p, stack = new Set()) => {
  if (wave[p] !== undefined) return wave[p];
  if (stack.has(p)) return 0;                        // cycle: break it
  stack.add(p);
  let w = 0; for (const d of meta[p].deps) if (set.has(d) && d !== p) w = Math.max(w, level(d, stack) + 1);
  stack.delete(p);
  return (wave[p] = Math.min(w, NW - 1));
};
const waves = Array.from({ length: NW }, () => []);
for (const p of [...set].sort()) waves[level(p)].push(p);
// GitHub caps a matrix at 256 jobs: a big wave gets bigger chunks rather than being cut.
const chunked = waves.map(w => { const n = Math.max(CHUNK, Math.ceil(w.length / 250)), c = [];
  for (let i = 0; i < w.length; i += n) c.push(w.slice(i, i + n).join(' ')); return c; });
const missing = Object.keys(meta).filter(p => meta[p].missing);
const out = { count: set.size, seeds: seeds.length, missing, waves: chunked };
console.log(JSON.stringify({ count: out.count, seeds: out.seeds, missing: missing.length, waves: waves.map(w => w.length) }));
// Each package's transitive build deps (within the set): a build links only those packages'
// archives from the overlay, not every library built so far (unrelated archives clashed).
if (process.env.DEPS_OUT) {
  const closure = {};
  const walk = (p, acc) => { for (const d of meta[p].deps) if (set.has(d) && !acc.has(d)) { acc.add(d); walk(d, acc); } return acc; };
  for (const p of set) closure[p] = [...walk(p, new Set())].filter(d => d !== p).sort();
  fs.writeFileSync(process.env.DEPS_OUT, JSON.stringify(closure));
}
// The recipe dirs the build jobs need (CI ships them as one artifact).
if (process.env.APORTS_LIST) fs.writeFileSync(process.env.APORTS_LIST, [...set].map(p => where[p]).filter(Boolean).join('\n') + '\n');
if (process.env.GITHUB_OUTPUT) {
  const lines = [`count=${set.size}`, `missing=${JSON.stringify(missing)}`];
  chunked.forEach((c, i) => lines.push(`w${i}=${JSON.stringify(c)}`));
  fs.appendFileSync(process.env.GITHUB_OUTPUT, lines.join('\n') + '\n');
} else console.log(JSON.stringify(out, null, 1));
