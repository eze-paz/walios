// Farm e2e: every package a farm run built, run in the REAL walios kernel (wali-worker.js in
// headless Chromium), in both engines -- the farm's own check is one `--version` on the Node
// host, which says a program starts, not that walios runs it.
//
//   node farm/e2e/run.mjs --farm <dir: index.json + its files> --rt <dir: runtimes> \
//        --kernel <dir: wali-worker.js wali-proc-worker.js opfs-worker.js> \
//        [--shard i/n] [--engines coi,nocoi] [--only a,b] [--catalog farm/ci/catalog.txt] [--out res.json]
//
// --rt holds busybox.wasm python_cxx.wasm python-ext.tar.gz pylib.tar.gz perl.wasm perllib.tar.gz
// lua.wasm rootfs.tar.gz. A case per package:
//   exe  <prog> --version, prog named by the farm's smoke line ("prog: output"); pass = the same
//        output the Node host printed, "differs" = it ran but printed something else
//   mod  py3-*: import each top-level module; perl-*: require the module the package is named
//        after; lua-*: require it. The package's mod deps are mounted with it.
//   lib  no case: a library is exercised by the programs and modules built on it.
// Outcomes: pass, differs, fail (non-zero / import error), trap, timeout.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const FARM = path.resolve(arg('farm')), RT = path.resolve(arg('rt')), KERNEL = path.resolve(arg('kernel'));
const [SHARD, NSHARD] = (arg('shard', '0/1')).split('/').map(Number);
const ENGINES = arg('engines', 'coi,nocoi').split(',');
const ONLY = arg('only') ? new Set(arg('only').split(',')) : null;
const CATALOG = arg('catalog') ? new Set(fs.readFileSync(arg('catalog'), 'utf8').split(/\s+/).filter(Boolean)) : null;
const OUT = arg('out', 'e2e-results.json');
// busybox.links in --rt (the runtime release ships it): applet names a bare command resolves to
const APPLETS = new Set(fs.existsSync(path.join(RT, 'busybox.links')) ? fs.readFileSync(path.join(RT, 'busybox.links'), 'utf8').split(/\s+/).filter(Boolean).map((l) => path.posix.basename(l)) : []);
const index = JSON.parse(fs.readFileSync(path.join(FARM, 'index.json'), 'utf8'));
const P = index.packages;

// ---- tar listing (ustar + GNU long names) of a .tar.gz ----
function tarNames(file) {
  const b = zlib.gunzipSync(fs.readFileSync(file)); const names = []; let p = 0, longName = null;
  while (p + 512 <= b.length) {
    const h = b.subarray(p, p + 512); if (h[0] === 0) break;
    const str = (o, n) => { const s = h.subarray(o, o + n); const z = s.indexOf(0); return s.subarray(0, z < 0 ? n : z).toString('utf8'); };
    const size = parseInt(str(124, 12).trim() || '0', 8), type = String.fromCharCode(h[156] || 48);
    let name = str(0, 100); const prefix = str(345, 155); if (prefix) name = prefix + '/' + name;
    if (type === 'L') longName = b.subarray(p + 512, p + 512 + size).toString('utf8').replace(/\0.*$/s, '');
    else { if (longName) { name = longName; longName = null; } if (type === '0' || type === '\0' || type === '5') names.push(name.replace(/^\.\//, '')); }
    p += 512 + Math.ceil(size / 512) * 512;
  }
  return names;
}

const norm = (s) => String(s || '').replace(/\s+/g, ' ').trim();
const modDeps = (pkg, seen = new Set()) => {
  for (const d of (P[pkg] && P[pkg].deps) || []) if (P[d] && P[d].kind === 'mod' && !seen.has(d)) { seen.add(d); modDeps(d, seen); }
  return seen;
};

function buildCase(pkg) {
  const r = P[pkg];
  if (r.kind === 'exe') {
    const m = /^([^:\s]+): ?([\s\S]*)$/.exec(r.smoke || '');
    const prog = m ? m[1] : pkg, expect = m ? m[2] : '';
    // By path: a bare name that is also a busybox applet runs the applet (hush prefers its
    // own), which is reported separately as `shadowed`, not as the package failing.
    return { pkg, kind: 'exe', manifest: { [prog]: '/f/' + r.file }, tars: [], expect, prog,
      cmd: `/bin/${prog} --version >/tmp/o 2>&1 </dev/null; echo "__rc=$?"; head -c 600 /tmp/o` };
  }
  if (r.kind !== 'mod') return null;
  const tars = [pkg, ...modDeps(pkg)].filter((d) => P[d].file).map((d) => ['/f/' + P[d].file, '/']);
  const names = tarNames(path.join(FARM, r.file));
  if (pkg.startsWith('py3-')) {
    const tops = new Set();
    for (const n of names) {
      const m = /^site-packages\/([A-Za-z_][\w]*)(\/__init__\.py|\.py|\.[^/]*\.so|\.so)$/.exec(n);
      if (m && !/^(_|tests?$|test_|conftest)/.test(m[1])) tops.add(m[1]);
    }
    if (!tops.size) return { pkg, kind: 'mod', skip: 'no importable top-level module' };
    const list = JSON.stringify([...tops]);
    return { pkg, kind: 'py', tars, tops: [...tops],
      cmd: `python3 -c 'import importlib, json\nok = []\nfor n in ${list}:\n    try:\n        importlib.import_module(n); ok.append(n)\n    except BaseException as e:\n        print("IMPORT-FAIL", n, type(e).__name__, str(e)[:300])\nprint("__imported", len(ok), "of", len(${list}))'` };
  }
  if (pkg.startsWith('perl-')) {
    const pms = names.map((n) => /(?:^|\/)perl5\/(?:vendor_perl\/|site_perl\/)?(?:[\d.]+\/)?(.+)\.pm$/.exec(n)).filter(Boolean).map((m) => m[1].replace(/^(?:x86_64[^/]*|wasm32[^/]*)\//, ''));
    if (!pms.length) return { pkg, kind: 'mod', skip: 'no .pm' };
    const want = pkg.slice(5).toLowerCase().replace(/-/g, '/');
    const main = pms.find((p) => p.toLowerCase() === want) || pms.sort((a, b) => a.split('/').length - b.split('/').length || a.length - b.length)[0];
    const mod = main.replace(/\//g, '::');
    return { pkg, kind: 'perl', tars, mod, cmd: `perl -e 'require ${mod}; print "__ok ${mod}\\n"' 2>&1` };
  }
  if (pkg.startsWith('lua-')) {
    const mods = names.map((n) => /^usr\/(?:share|lib)\/lua\/(?:5\.4|common)\/(.+?)(?:\/init)?\.(?:lua|so)$/.exec(n)).filter(Boolean).map((m) => m[1].replace(/\//g, '.'));
    if (!mods.length) return { pkg, kind: 'mod', skip: 'no lua module' };
    const want = pkg.slice(4).toLowerCase();
    const main = mods.find((m) => m.toLowerCase() === want) || mods.sort((a, b) => a.length - b.length)[0];
    return { pkg, kind: 'lua', tars, mod: main, cmd: `lua -e 'require("${main}") print("__ok ${main}")' 2>&1` };
  }
  return { pkg, kind: 'mod', skip: 'module of an unknown language' };
}

function judge(c, r) {
  const out = r.out || '';
  if (r.timeout) return ['timeout', out.slice(-400)];
  if (/\[host\] trap|RuntimeError|unreachable|memory access out of bounds/.test(out)) return ['trap', (out.match(/\[host\] trap[^\n]*/) || [out.slice(0, 300)])[0]];
  if (c.kind === 'exe') {
    const body = out.replace(/^[\s\S]*?__rc=\d+\n?/, '').replace(/\[host\][^\n]*\n?/g, '');
    // The program's own name is not the output: the Node host ran it as argv0 = the package
    // name ("expat using expat_2.9.0"), walios as the real binary ("xmlwf using ..."). Drop the
    // first word and every word naming the program, then compare what follows.
    const words = (s) => norm(s).split(' ').filter((w, i) => { const b = w.replace(/[:,.'"]+$/, '').replace(/^['"]/, '');
      return i > 0 && !b.includes('/bin/') && b !== c.pkg && b !== c.prog; }).join(' ');
    const want = words(c.expect).slice(0, 60);
    if (!c.expect || (want ? words(body).includes(want) : norm(body).includes(norm(c.expect)))) return ['pass', ''];
    return ['differs', norm(body).slice(0, 200) + '  [node host: ' + norm(c.expect).slice(0, 120) + ']'];
  }
  if (c.kind === 'py') {
    const m = /__imported (\d+) of (\d+)/.exec(out);
    if (m && m[1] === m[2]) return ['pass', ''];
    return ['fail', (out.match(/IMPORT-FAIL[^\n]*/g) || [out.slice(0, 300)]).slice(0, 3).join(' | ')];
  }
  return /__ok /.test(out) ? ['pass', ''] : ['fail', norm(out.replace(/\[host\][^\n]*\n?/g, '')).slice(0, 300)];
}

// ---- server: harness + kernel at /, runtimes at /rt/, farm files at /f/ ----
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.gz': 'application/gzip', '.json': 'application/json' };
const serve = (coi) => http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  let file = u === '/' || u === '/harness.html' ? path.join(HERE, 'harness.html')
    : u.startsWith('/rt/') ? path.join(RT, u.slice(4)) : u.startsWith('/f/') ? path.join(FARM, u.slice(3)) : path.join(KERNEL, u.slice(1));
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end('nf'); return; }
  const h = { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'max-age=3600' };
  if (coi) Object.assign(h, { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Resource-Policy': 'same-origin' });
  res.writeHead(200, h); fs.createReadStream(file).pipe(res);
});

const ENV = { HOME: '/root', PATH: '/bin:/usr/bin', TERM: 'dumb', LC_ALL: 'C.UTF-8', NO_COLOR: '1',
  PYTHONHOME: '/py', PYTHONPATH: '/py/Lib:/ext:/site-packages', PYTHONDONTWRITEBYTECODE: '1', MPLBACKEND: 'Agg',
  PERL5LIB: '/usr/share/perl5/vendor_perl:/usr/share/perl5:/usr/lib/perl5/vendor_perl',
  LUA_PATH: '/usr/share/lua/5.4/?.lua;/usr/share/lua/5.4/?/init.lua;/usr/share/lua/common/?.lua;/usr/share/lua/common/?/init.lua;;' };
const runMsg = (c) => ({
  t: 'run', wasm: '/rt/busybox.wasm',
  manifest: Object.assign({ busybox: '/rt/busybox.wasm', sh: '/rt/busybox.wasm', hush: '/rt/busybox.wasm',
    python3: '/rt/python_cxx.wasm', python: '/rt/python_cxx.wasm', perl: '/rt/perl.wasm', lua: '/rt/lua.wasm' }, c.manifest || {}),
  tars: [['/rt/rootfs.tar.gz', '/'], ...c.tars],
  lazyTars: { '/rt/python_cxx.wasm': [['/rt/pylib.tar.gz', '/py'], ['/rt/python-ext.tar.gz', '/ext']],
              '/rt/perl.wasm': [['/rt/perllib.tar.gz', '/usr/lib/perl5']] },
  env: ENV, cwd: '/', argv: ['busybox', 'hush', '-c', c.cmd],
  // the ILP32 python's sysconfig data ships beside it, not in pylib (sysconfig/hypothesis need it)
  ...(fs.existsSync(path.join(RT, SYSCFG)) ? { blobUrls: { ['/py/Lib/' + SYSCFG]: '/rt/' + SYSCFG } } : {}),
});
const SYSCFG = '_sysconfigdata__linux_x86_64-linux-gnu.py';

let pkgs = Object.keys(P).filter((k) => ['exe', 'mod'].includes(P[k].kind) && (!CATALOG || CATALOG.has(k)) && (!ONLY || ONLY.has(k))).sort();
pkgs = pkgs.filter((_, i) => i % NSHARD === SHARD);
// --fetch <base url>: download only this shard's files (and its modules' deps) from the
// release's public download URLs -- the Releases API rate-limits a dozen shards pulling ~700 assets.
const FETCH = arg('fetch');
if (FETCH) {
  const need = new Set();
  for (const k of pkgs) for (const d of [k, ...(P[k].kind === 'mod' ? modDeps(k) : [])]) if (P[d].file) need.add(P[d].file);
  const todo = [...need].filter((f) => !fs.existsSync(path.join(FARM, f)));
  let n = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (todo.length) {
      const f = todo.pop();
      for (let t = 0; t < 5; t++) {
        try { const r = await fetch(FETCH.replace(/\/?$/, '/') + f); if (!r.ok) throw new Error('HTTP ' + r.status);
          fs.writeFileSync(path.join(FARM, f), Buffer.from(await r.arrayBuffer())); n++; break; }
        catch (e) { if (t === 4) console.log('fetch failed', f, e.message); else await new Promise((r) => setTimeout(r, 3000 * (t + 1))); }
      }
    }
  }));
  console.log(`fetched ${n}/${need.size} files for ${pkgs.length} packages`);
}
const cases = pkgs.map(buildCase).filter(Boolean);
const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(path.join(execSync('npm root -g').toString().trim(), 'playwright'))); }

const results = {};
for (const eng of ENGINES) {
  const server = serve(eng === 'coi'); await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/harness.html`);
  const got = await page.evaluate(() => window.walEngine);
  if (got !== eng) throw new Error(`harness came up as ${got}, wanted ${eng}`);
  const t0 = Date.now();
  for (const c of cases) {
    const row = (results[c.pkg] = results[c.pkg] || { kind: P[c.pkg].kind });
    if (c.prog && APPLETS.has(c.prog)) row.shadowed = c.prog;
    if (c.skip) { row[eng] = ['skip', c.skip]; continue; }
    const t = Date.now();
    const r = await page.evaluate(([m]) => window.walRun(m, 45000), [runMsg(c)]);
    row[eng] = [...judge(c, r), Date.now() - t];
    if (process.env.E2E_VERBOSE) console.log(eng, c.pkg, row[eng][0], row[eng][1] || '');
  }
  console.log(`${eng}: ${cases.length} cases in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
  await browser.close(); server.close();
}
fs.writeFileSync(OUT, JSON.stringify({ tag: index.tag, shard: `${SHARD}/${NSHARD}`, engines: ENGINES, results }, null, 1));
const both = Object.entries(results).filter(([, r]) => ENGINES.every((e) => r[e] && r[e][0] === 'pass'));
const tally = {}; for (const r of Object.values(results)) for (const e of ENGINES) { const s = r[e] ? r[e][0] : 'none'; tally[e + ':' + s] = (tally[e + ':' + s] || 0) + 1; }
const shadowed = Object.values(results).filter((r) => r.shadowed).length;
console.log(`works in ${ENGINES.join('+')}: ${both.length}/${cases.length}`, JSON.stringify(tally), `shadowed by a busybox applet: ${shadowed}`);
