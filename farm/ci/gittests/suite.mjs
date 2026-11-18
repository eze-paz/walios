// git's own test suite (all of t/t[0-9]*.sh, git 2.45.3) in the real walios kernel: headless
// Chromium, the per-process engine (cross-origin isolated, like sandpie), one fresh kernel per
// script through farm/e2e/harness.html. The run message mirrors what sandpie's walios-backend.js
// builds: rootfs + git-core.tar.gz at /, git on PATH (/bin/git), perl, GIT_EXEC_PATH, $HOME
// /root on OPFS -- where the trash directories go, as in sandpie (/root is the workspace).
//
//   node farm/ci/gittests/suite.mjs --rt <dir> --kernel <dir> [--shard i/n] [--only t0000-basic,...]
//        [--timeout 1800] [--out res.json]
//
// --rt: busybox.wasm busybox.links perl.wasm perllib.tar.gz rootfs.tar.gz git.wasm
//       git-core.tar.gz git-tests.tar.gz (gittests-* release: git-asyncfork.wasm,
//       git-core-2.45.3.tar.gz, git-tests-2.45.3.tar.gz under those names)
// Per script: TAP counts, failing test names, a known-breakage count ("# TODO"), and for a script
// with failures the tail of its --verbose-log -x log (what each failing test ran and printed).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HARNESS = path.join(HERE, '../../e2e/harness.html');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const RT = path.resolve(arg('rt')), KERNEL = path.resolve(arg('kernel'));
const [SHARD, NSHARD] = arg('shard', '0/1').split('/').map(Number);
const ONLY = arg('only') ? arg('only').split(',').filter(Boolean) : null;
const TIMEOUT_S = +arg('timeout', 1800);
const OUT = arg('out', 'gittests-results.json');
const LOG_TAIL = 24000;

// ---- the script list, from the tarball (t/tNNNN-*.sh) ----
function tarNames(file) {
  const b = zlib.gunzipSync(fs.readFileSync(file)); const names = []; let p = 0, longName = null;
  while (p + 512 <= b.length) {
    const h = b.subarray(p, p + 512); if (h[0] === 0) break;
    const str = (o, n) => { const s = h.subarray(o, o + n); const z = s.indexOf(0); return s.subarray(0, z < 0 ? n : z).toString('utf8'); };
    const size = parseInt(str(124, 12).trim() || '0', 8), type = String.fromCharCode(h[156] || 48);
    let name = str(0, 100); const prefix = str(345, 155); if (prefix) name = prefix + '/' + name;
    if (type === 'L') longName = b.subarray(p + 512, p + 512 + size).toString('utf8').replace(/\0.*$/s, '');
    else { if (longName) { name = longName; longName = null; } names.push(name.replace(/^\.\//, '')); }
    p += 512 + Math.ceil(size / 512) * 512;
  }
  return names;
}
const all = tarNames(path.join(RT, 'git-tests.tar.gz')).map((n) => /^t\/(t\d{4}-[^/]+)\.sh$/.exec(n)).filter(Boolean).map((m) => m[1]).sort();
let scripts = ONLY || all;
scripts = scripts.filter((_, i) => i % NSHARD === SHARD);
console.log(`${all.length} scripts in the suite; shard ${SHARD}/${NSHARD}: ${scripts.length}`);

// ---- server: harness + kernel at /, runtimes at /rt/ (COOP/COEP: the per-process engine) ----
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.gz': 'application/gzip' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  const file = u === '/' || u === '/harness.html' ? HARNESS : u.startsWith('/rt/') ? path.join(RT, u.slice(4)) : path.join(KERNEL, u.slice(1));
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end('nf'); return; }
  res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'max-age=3600',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Resource-Policy': 'same-origin' });
  fs.createReadStream(file).pipe(res);
});

const LINKS = fs.readFileSync(path.join(RT, 'busybox.links'), 'utf8').split(/\s+/).filter((l) => l.startsWith('/'));
const ENV = { HOME: '/root', TERM: 'dumb', PATH: '/usr/local/bin:/bin:/usr/bin', HOSTNAME: 'walios', LC_ALL: 'C.UTF-8', NO_COLOR: '1',
  GIT_EXEC_PATH: '/usr/libexec/git-core',
  PERL5LIB: '/usr/share/perl5/vendor_perl:/usr/share/perl5:/usr/lib/perl5/vendor_perl' };
// --env K=V,K2=V2: extra variables for the suite (e.g. GIT_TEST_GIT_DAEMON=1, the opt-in for
// the tests that serve on a real TCP port)
for (const kv of (arg('env') || '').split(',').filter(Boolean)) { const i = kv.indexOf('='); ENV[kv.slice(0, i)] = kv.slice(i + 1); }
const cmdFor = (name) => [
  'cd /tmp/gt/t || exit 9',
  'chmod +x helper/test-tool helper/test-fake-ssh *.sh 2>/dev/null',
  'rm -rf /root/gt-trash; mkdir -p /root/gt-trash',
  `GIT_TEST_INSTALLED=/bin GIT_TEST_DEFAULT_HASH=sha1 GIT_TEST_CHAIN_LINT=0 GIT_TEST_CLONE_2GB= TEST_NO_MALLOC_CHECK=1 sh ${name}.sh --root=/root/gt-trash --verbose-log -x`,
  'echo "__rc=$?"',
  `if grep -q "^not ok" test-results/${name}.out 2>/dev/null; then echo __LOG__; tail -c ${LOG_TAIL} test-results/${name}.out; fi`,
].join('\n');
// The files sandpie's walios-backend.js seeds for git (tlsBlobs): the dashed transport helpers
// git runs by name through PATH (a local fetch/push: sh -c "git-upload-pack '<dir>'"), its
// gitconfig (test-lib sets GIT_CONFIG_NOSYSTEM, so the suite ignores that one) and templates.
const BLOB_TEXT = {
  '/bin/git-upload-pack': '#!/bin/sh\nexec git upload-pack "$@"\n',
  '/bin/git-receive-pack': '#!/bin/sh\nexec git receive-pack "$@"\n',
  '/bin/git-upload-archive': '#!/bin/sh\nexec git upload-archive "$@"\n',
  '/etc/gitconfig': '[safe]\n\tdirectory = *\n[core]\n\tpager = cat\n\teditor = true\n[user]\n\tname = walios\n\temail = walios@sandpie.invalid\n'
    + '[init]\n\tdefaultBranch = main\n\ttemplateDir = /usr/share/git-core/templates\n[advice]\n\tdetachedHead = false\n',
  '/usr/share/git-core/templates/.keep': '',
};
const runMsg = (name) => ({
  t: 'run', wasm: '/rt/busybox.wasm',
  manifest: { busybox: '/rt/busybox.wasm', sh: '/rt/busybox.wasm', hush: '/rt/busybox.wasm', perl: '/rt/perl.wasm', git: '/rt/git.wasm' },
  tars: [['/rt/rootfs.tar.gz', '/'], ['/rt/git-core.tar.gz', '/'], ['/rt/git-tests.tar.gz', '/tmp/gt']],
  lazyTars: { '/rt/perl.wasm': [['/rt/perllib.tar.gz', '/usr/lib/perl5']] },
  blobText: BLOB_TEXT, opfs: '/root', env: ENV, cwd: '/root', argv: ['busybox', 'sh', '-c', cmdFor(name)], appletLinks: LINKS,
});

function judge(name, r) {
  const out = r.out || '';
  const [tap, log] = out.split('\n__LOG__\n');
  const lines = tap.split('\n');
  const ok = lines.filter((l) => /^ok \d+/.test(l)), skipped = ok.filter((l) => /^ok \d+ # skip/i.test(l));
  const notOk = lines.filter((l) => /^not ok \d+/.test(l));
  const known = notOk.filter((l) => /# TODO/.test(l)), failed = notOk.filter((l) => !/# TODO/.test(l));
  const done = /^# (passed all|failed \d+ among|still have)/m.test(tap) || /^1\.\.\d+/m.test(tap);
  const rc = Number((/__rc=(\d+)/.exec(tap) || [])[1]);
  const status = r.timeout ? 'timeout' : !done ? 'broken' : failed.length ? 'fail' : 'ok';
  const host = (out.match(/\[host\][^\n]*/g) || []).filter((l) => !/OPFS lazily mounted|engine:/.test(l)).slice(0, 8);
  return { status, pass: ok.length - skipped.length, fail: failed.length, skip: skipped.length, known: known.length, rc,
    failures: failed.map((l) => l.replace(/^not ok /, '')).slice(0, 40), host,
    ...(status !== 'ok' ? { log: (log || '').slice(-LOG_TAIL), tail: status === 'ok' ? '' : tap.slice(-3000) } : {}) };
}

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(path.join(execSync('npm root -g').toString().trim(), 'playwright'))); }
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/harness.html`;
// A NEW BROWSER per script, with its own profile. Every kernel and process is a dedicated worker
// in the page's renderer, each reserving a large shared wasm memory that a dead worker gives
// back only lazily; scripts sharing one page ran out of reservations ("WebAssembly.Memory():
// could not allocate memory") and later scripts sat silent until their timeout. A persistent
// profile, not an incognito one: incognito OPFS has a ~1 GiB quota.
let ctx = null, page = null, prof = null;
const fresh = async () => {
  if (ctx) await ctx.close().catch(() => {});
  if (prof) fs.rmSync(prof, { recursive: true, force: true });
  prof = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || '/tmp', 'gitsuite-prof-'));
  ctx = await chromium.launchPersistentContext(prof, { headless: true });
  page = ctx.pages()[0] || await ctx.newPage();
  await page.goto(url);
  const eng = await page.evaluate(() => window.walEngine);
  if (eng !== 'coi') throw new Error('harness came up as ' + eng + ', wanted coi');
};
const results = {}, t0 = Date.now();
// --deadline <minutes>: start no script after this (the job's own timeout would kill the shard
// and its results with it). The results file is rewritten after every script either way.
const DEADLINE = arg('deadline') ? t0 + +arg('deadline') * 60000 : Infinity;
const save = () => fs.writeFileSync(OUT, JSON.stringify({ shard: `${SHARD}/${NSHARD}`, secs: Math.round((Date.now() - t0) / 1000), results }, null, 1));
for (const name of scripts) {
  if (Date.now() + Math.min(TIMEOUT_S, 600) * 1000 > DEADLINE) { results[name] = { status: 'not-run', pass: 0, fail: 0, skip: 0, known: 0, failures: [], host: [], secs: 0 }; continue; }
  const t = Date.now();
  let r;
  try {
    await fresh();
    r = await page.evaluate(([m, ms]) => {
      m.blobs = {}; for (const [p, t] of Object.entries(m.blobText)) m.blobs[p] = new TextEncoder().encode(t).buffer; delete m.blobText;
      return window.walRun(m, ms);
    }, [runMsg(name), TIMEOUT_S * 1000]);
  } catch (e) {   // the page itself died (OOM, crash): recorded as broken
    r = { out: '[suite] page error: ' + (e && e.message || e), code: -3 };
  }
  const row = results[name] = { ...judge(name, r), secs: Math.round((Date.now() - t) / 1000) };
  console.log(`${row.status.padEnd(7)} ${name.padEnd(44)} pass ${String(row.pass).padStart(4)} fail ${String(row.fail).padStart(3)} skip ${String(row.skip).padStart(3)}${row.known ? ' todo ' + row.known : ''} ${row.secs}s`
    + (row.failures.length ? '\n          ' + row.failures.slice(0, 5).join('\n          ') : ''));
  save();
}
if (ctx) await ctx.close().catch(() => {});
if (prof) fs.rmSync(prof, { recursive: true, force: true });
server.close();
save();
const tot = { pass: 0, fail: 0, skip: 0, known: 0 }, by = {};
for (const r of Object.values(results)) { for (const k of Object.keys(tot)) tot[k] += r[k]; by[r.status] = (by[r.status] || 0) + 1; }
console.log(`shard ${SHARD}/${NSHARD}: ${scripts.length} scripts`, JSON.stringify(by), JSON.stringify(tot));
