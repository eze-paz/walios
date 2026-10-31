#!/usr/bin/env node
// Plan a farm run: package set -> dependency waves -> GitHub Actions matrix chunks.
//   PKGS="a b c"   explicit seeds, or
//   SAMPLE=50      a deterministic sample of farm/ci/catalog.txt (SEED=1), or
//   ALL=1          the whole catalog
//   MAX=400        cap on seeds + dependency closure
//   WAVES=4        dependency waves (deeper chains collapse into the last one)
//   CHUNK=8        packages per matrix job (one wave stays <= 256 jobs: GitHub's cap)
// Deps = APKBUILD depends + makedepends, minus build tools (DENY), as farm/farm3.js did.
// Prints {waves:[[chunk,...],...], count}; with GITHUB_OUTPUT set, writes w0..wN + count.
'use strict';
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const APORTS = 'https://git.alpinelinux.org/aports/plain';
const DENY = new Set(['autoconf', 'automake', 'libtool', 'pkgconf', 'pkgconfig', 'make', 'cmake',
  'meson', 'ninja', 'samurai', 'bison', 'flex', 'gettext', 'gettext-tiny', 'gettext-dev', 'texinfo',
  'perl', 'python3', 'py3-setuptools', 'linux-headers', 'musl-dev', 'gcc', 'g++', 'clang', 'llvm',
  'bsd-compat-headers', 'utmps', 'byacc', 'gperf', 'help2man', 'doxygen', 'groff', 'scdoc', 'asciidoc',
  'coreutils', 'grep', 'sed', 'gzip', 'xz', 'zstd', 'brotli', 'go', 'rust', 'cargo', 'ca-certificates',
  'openrc', 'lang', 'bash', 'sh']);
const clean = (d) => d.replace(/[<>=~].*$/, '').replace(/-dev$/, '');
const skip = (d) => !d || d.includes(':') || d.startsWith('!') || d.startsWith('$') || DENY.has(d) ||
  /-doc$|-lang$|-openrc$|-static$|-bash-completion$/.test(d);

const catalog = fs.readFileSync(path.join(__dirname, 'catalog.txt'), 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
const MAX = +(process.env.MAX || 400), NW = +(process.env.WAVES || 4), CHUNK = +(process.env.CHUNK || 8);
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
  try { d = execFileSync('bash', ['-c', `source "${f}" >/dev/null 2>&1; echo "$depends $makedepends"`], { encoding: 'utf8' }); } catch {}
  return [...new Set(d.split(/\s+/).map(clean).filter(x => !skip(x)))];
}

const meta = {}, queue = [...seeds], seen = new Set(seeds);
while (queue.length && Object.keys(meta).length < MAX) {
  const p = queue.shift(), txt = apkbuild(p);
  if (!txt) { meta[p] = { missing: true, deps: [] }; continue; }
  meta[p] = { deps: depsOf(txt) };
  for (const d of meta[p].deps) if (!seen.has(d)) { seen.add(d); queue.push(d); }
}
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
const chunked = waves.map(w => { const c = []; for (let i = 0; i < w.length; i += CHUNK) c.push(w.slice(i, i + CHUNK).join(' ')); return c; });
const missing = Object.keys(meta).filter(p => meta[p].missing);
const out = { count: set.size, seeds: seeds.length, missing, waves: chunked };
console.log(JSON.stringify({ count: out.count, seeds: out.seeds, missing: missing.length, waves: waves.map(w => w.length) }));
// The recipe dirs the build jobs need (CI ships them as one artifact).
if (process.env.APORTS_LIST) fs.writeFileSync(process.env.APORTS_LIST, [...set].map(p => where[p]).filter(Boolean).join('\n') + '\n');
if (process.env.GITHUB_OUTPUT) {
  const lines = [`count=${set.size}`, `missing=${JSON.stringify(missing)}`];
  chunked.forEach((c, i) => lines.push(`w${i}=${JSON.stringify(c)}`));
  fs.appendFileSync(process.env.GITHUB_OUTPUT, lines.join('\n') + '\n');
} else console.log(JSON.stringify(out, null, 1));
