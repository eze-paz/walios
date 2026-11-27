// X11 P0 spike: does an X server run on walios? Boots the REAL kernel (wali-worker.js) in
// headless Chromium through harness.html, starts Xvfb, runs X clients against it over TCP
// 127.0.0.1:6000, dumps the root window with xwd and writes it out as a PNG.
//
//   node farm/e2e/x11-spike.mjs --index <farm index.json URL> --base <full farm index.json URL> \
//        --kernel <dir: wali-worker.js wali-proc-worker.js opfs-worker.js> --rt <dir: busybox.wasm rootfs.tar.gz> \
//        [--cache dir] [--out root.png] [--engine coi|nocoi] [--cmd 'extra shell'] [--display walios-x11.js]
//
// --display <sandpie modules/walios-x11.js>: the P1 display test. The page opens the X server
// itself (kernel 'tcp-open': a MessagePort into 127.0.0.1:6000), draws it on a canvas with that
// client, moves the pointer (xeyes must follow), types and clicks into x11-keyprobe.py's
// window (it logs what arrives), and the canvas is compared with xwd's dump of the same screen.
//
// Programs come from --index (the canary) first, then --base; data packages (xkeyboard-config,
// fonts) are mounted as tars like `apk add` does.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const KERNEL = path.resolve(arg('kernel')), RT = path.resolve(arg('rt'));
const CACHE = path.resolve(arg('cache', path.join(HERE, '.x11cache'))); fs.mkdirSync(CACHE, { recursive: true });
const OUT = path.resolve(arg('out', 'x11-root.png')), ENGINE = arg('engine', 'coi');

const getJson = async (u) => { const r = await fetch(u); if (!r.ok) throw new Error(u + ' HTTP ' + r.status); return r.json(); };
const idxs = [];
for (const u of [arg('index'), arg('base')].filter(Boolean)) idxs.push({ url: u, idx: await getJson(u) });
// pkg -> { url of its file, kind, smoke }
const find = (pkg) => { for (const { url, idx } of idxs) { const r = idx.packages[pkg]; if (r && r.file && r.status !== 'fail') return { ...r, href: new URL(r.file, url).href }; } return null; };
const loc = (href) => path.join(CACHE, href.replace(/^https?:\/\//, '').replace(/[\/\\:?]/g, '__'));
async function fetchTo(href) {
  const f = loc(href); if (fs.existsSync(f)) return f;
  for (let t = 0; t < 4; t++) {
    try { const r = await fetch(href); if (!r.ok) throw new Error('HTTP ' + r.status); fs.writeFileSync(f, Buffer.from(await r.arrayBuffer())); return f; }
    catch (e) { if (t === 3) throw new Error(href + ': ' + e.message); await new Promise((r) => setTimeout(r, 2000)); }
  }
}

// Programs: name on PATH -> package. Data: tars mounted at /.
const PROGS = { Xvfb: 'xorg-server', xkbcomp: 'xkbcomp', xdpyinfo: 'xdpyinfo', xwd: 'xwd', xeyes: 'xeyes', xclock: 'xclock', xterm: 'xterm', xauth: 'xauth' };
const DATA = ['xkeyboard-config', 'font-misc-misc', 'font-cursor-misc'];
const manifest = {}, tars = [], files = {};
// --local Xvfb=/path/xorg-server.wasm,xwd=/path/xwd.wasm: a build artifact instead of an index's file
const LOCAL = Object.fromEntries((arg('local', '') || '').split(',').filter(Boolean).map((kv) => kv.split('=')));
for (const [prog, f] of Object.entries(LOCAL)) { const name = '/f/local-' + prog + '.wasm'; files[name] = path.resolve(f); manifest[prog] = name; console.log(`program ${prog} <- local ${f}`); }
for (const [prog, pkg] of Object.entries(PROGS)) {
  if (LOCAL[prog]) continue;
  const r = find(pkg); if (!r) { console.log(`missing program ${prog} (${pkg})`); continue; }
  if (r.kind !== 'exe') { console.log(`${pkg} is kind ${r.kind}, not exe`); continue; }
  const f = await fetchTo(r.href); const name = '/f/' + path.basename(f); files[name] = f; manifest[prog] = name;
  console.log(`program ${prog} <- ${pkg} ${r.ver} (${(fs.statSync(f).size / 1e6).toFixed(1)} MB) smoke: ${(r.smoke || '').slice(0, 60)}`);
}
for (const pkg of DATA) {
  const r = find(pkg); if (!r) { console.log(`missing data ${pkg}`); continue; }
  const f = await fetchTo(r.href); const name = '/f/' + path.basename(f); files[name] = f; tars.push([name, '/']);
  console.log(`data ${pkg} ${r.ver} (${r.kind})`);
}

files['/f/x11-probe.py'] = path.join(HERE, 'x11-probe.py');
const DISPLAY_JS = arg('display');
if (DISPLAY_JS) { files['/f/walios-x11.js'] = path.resolve(DISPLAY_JS); files['/f/x11-keyprobe.py'] = path.join(HERE, 'x11-keyprobe.py'); }
const DISPLAY_CMD = `xeyes -geometry 300x200+20+20 >/tmp/xeyes.log 2>&1 &
xclock -geometry 200x200+360+20 >/tmp/xclock.log 2>&1 &
python3 /tmp/x11-keyprobe.py /tmp/keys.log >/tmp/keyprobe.log 2>&1 &
i=0; until grep -q __KEYPROBE /tmp/keys.log 2>/dev/null || [ $i -ge 60 ]; do sleep 1; i=$((i+1)); done
sleep 3; echo __READY
i=0; until grep -q __KEYDONE /tmp/keys.log 2>/dev/null || [ $i -ge 120 ]; do sleep 1; i=$((i+1)); done
echo __KEYS; cat /tmp/keys.log; cat /tmp/keyprobe.log
sleep 2`;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.gz': 'application/gzip', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  const file = u === '/' || u === '/harness.html' ? path.join(HERE, 'harness.html')
    : u.startsWith('/rt/') ? path.join(RT, u.slice(4)) : files[u] || path.join(KERNEL, u.slice(1));
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end('nf'); return; }
  const h = { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' };
  if (ENGINE === 'coi') Object.assign(h, { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Resource-Policy': 'same-origin' });
  res.writeHead(200, h); fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));

const LINKS = fs.existsSync(path.join(RT, 'busybox.links')) ? fs.readFileSync(path.join(RT, 'busybox.links'), 'utf8').split(/\s+/).filter((l) => l.startsWith('/')) : [];
const SCRIPT = `
for p in xkbcomp Xvfb; do [ -e /usr/bin/$p ] || ln -s /bin/$p /usr/bin/$p 2>/dev/null; done
ls /usr/share/X11/xkb 2>&1 | head -3; ls /usr/share/fonts/misc 2>&1 | head -3
echo __START $(date +%s)
Xvfb :0 -screen 0 640x480x24 -nolisten unix -listen tcp -ac -nolock >/tmp/xvfb.log 2>&1 &
XP=$!
export DISPLAY=127.0.0.1:0
echo __PROBE; python3 /tmp/x11-probe.py 0 2>&1; echo __probe_rc=$?
if command -v xdpyinfo >/dev/null; then xdpyinfo >/tmp/dpy 2>&1; echo __xdpyinfo_rc=$?; head -40 /tmp/dpy; fi
${arg('cmd', DISPLAY_JS ? DISPLAY_CMD : `xeyes -geometry 300x200+20+20 >/tmp/xeyes.log 2>&1 &
xclock -geometry 200x200+360+20 -update 1 >/tmp/xclock.log 2>&1 &
xterm -geometry 60x10+20+260 -e sh -c 'echo hello from walios; sleep 30' >/tmp/xterm.log 2>&1 &
sleep 8`)}
xwd -root -silent -out /tmp/root.xwd; echo __xwd_rc=$?
echo __XWD; base64 /tmp/root.xwd | tr -d '\\n'; echo; echo __END
for f in /tmp/xvfb.log /tmp/xeyes.log /tmp/xclock.log /tmp/xterm.log; do echo "== $f"; head -c 1500 $f; done
kill $XP 2>/dev/null; echo __DONE`;
const msg = {
  t: 'run', wasm: '/rt/busybox.wasm',
  manifest: Object.assign({ busybox: '/rt/busybox.wasm', sh: '/rt/busybox.wasm', hush: '/rt/busybox.wasm',
    python3: '/rt/python_cxx.wasm' }, manifest),
  tars: [['/rt/rootfs.tar.gz', '/'], ...tars],
  lazyTars: { '/rt/python_cxx.wasm': [['/rt/pylib.tar.gz', '/py']] },
  blobUrls: Object.assign({ '/tmp/x11-probe.py': '/f/x11-probe.py' }, DISPLAY_JS ? { '/tmp/x11-keyprobe.py': '/f/x11-keyprobe.py' } : {}),
  env: { HOME: '/root', PATH: '/bin:/usr/bin', TERM: 'dumb', LC_ALL: 'C.UTF-8', PYTHONHOME: '/py', PYTHONPATH: '/py/Lib', PYTHONDONTWRITEBYTECODE: '1' }, cwd: '/',
  argv: ['busybox', 'sh', '-c', SCRIPT], appletLinks: LINKS,
};

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(path.join(execSync('npm root -g').toString().trim(), 'playwright'))); }
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
page.on('console', (m) => { if (process.env.X11_VERBOSE) console.log('[page]', m.text()); });
await page.goto(`http://127.0.0.1:${server.address().port}/harness.html`);
console.log('engine', await page.evaluate(() => window.walEngine));
const t0 = Date.now();
const runP = page.evaluate(([m]) => window.walRun(m, 240000), [msg]);
const disp = DISPLAY_JS ? await page.evaluate(displayTest).catch((e) => ({ error: String(e) })) : null;
const r = await runP;
await browser.close(); server.close();
console.log(`run: code ${r.code}${r.timeout ? ' TIMEOUT' : ''} in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
const out = r.out || '';
const m = /__XWD\n([A-Za-z0-9+/=]*)\n__END/.exec(out);
console.log(out.replace(/__XWD\n[A-Za-z0-9+/=]*\n__END/, `__XWD <${m ? m[1].length : 0} base64 chars>`).slice(0, 12000));
if (disp) {
  console.log('--- display test (page side) ---\n' + (disp.log || []).join('\n') + (disp.error ? '\nERROR ' + disp.error : ''));
  if (disp.png) fs.writeFileSync(OUT.replace(/.png$/, '') + '-canvas.png', Buffer.from(disp.png.split(',')[1], 'base64'));
  const keys = (/__KEYS\n([\s\S]*?)(?:\n== |$)/.exec(out) || [])[1] || '';
  const ok = [];
  ok.push(['canvas painted by DAMAGE + GetImage', disp.frames > 0]);
  ok.push(['xeyes followed the injected pointer', disp.eyesDiff > 50]);
  const kc = disp.expect || {};
  ok.push(['key a arrived', new RegExp('__KEY ' + kc.a + ' 0\\b').test(keys)]);
  ok.push(['key A arrived as Shift + a', new RegExp('__KEY ' + kc.a + ' 1\\b').test(keys)]);
  ok.push(['Return arrived', new RegExp('__KEY ' + kc.Return + ' ').test(keys)]);
  ok.push(['left click arrived at (100,70) in the window', /__BTN 1 100 70/.test(keys)]);
  if (m && m[1].length && disp.rgba) {
    const x = xwdPixels(Buffer.from(m[1], 'base64')), c = Buffer.from(disp.rgba, 'base64');
    let same = 0; for (let i = 0, n = x.w * x.h; i < n; i++) if (c[i * 4] === x.px[i * 3] && c[i * 4 + 1] === x.px[i * 3 + 1] && c[i * 4 + 2] === x.px[i * 3 + 2]) same++;
    const frac = same / (x.w * x.h);
    ok.push([`canvas matches xwd's dump (${(frac * 100).toFixed(2)}% of pixels identical)`, frac > 0.99]);
  }
  for (const [what, pass] of ok) console.log((pass ? 'PASS ' : 'FAIL ') + what);
  console.log(ok.every((x) => x[1]) ? '__DISPLAY_OK' : '__DISPLAY_FAIL');
}
if (m && m[1].length) { fs.writeFileSync(OUT.replace(/.png$/, '') + '.xwd', Buffer.from(m[1], 'base64')); const png = xwdToPng(Buffer.from(m[1], 'base64')); fs.writeFileSync(OUT, png); console.log('wrote', OUT, png.length, 'bytes'); }

// ---- the display test, run in the page (needs harness.html's walWorker / walOutText) ----
async function displayTest() {
  const log = [], L = (s) => log.push(s), sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  await new Promise((res, rej) => { const s = document.createElement('script'); s.src = '/f/walios-x11.js'; s.onload = res; s.onerror = rej; document.head.appendChild(s); });
  const t0 = performance.now();
  while (!(window.walOutText || '').includes('__READY')) { if (performance.now() - t0 > 180000) return { log, error: 'the X clients never came up' }; await sleep(300); }
  const w = window.walWorker;
  const ports = await new Promise((res) => { const id = Math.random(); const h = (e) => { if (e.data && e.data.t === 'listening' && e.data.id === id) { w.removeEventListener('message', h); res(e.data.ports); } }; w.addEventListener('message', h); w.postMessage({ t: 'listening', id }); });
  L('kernel loopback listeners: ' + ports.join(' '));
  const ch = new MessageChannel();
  w.postMessage({ t: 'tcp-open', dport: 6000, mp: ch.port2 }, [ch.port2]);
  const canvas = document.createElement('canvas'); document.body.appendChild(canvas);
  const sess = SandpieX11.attach(ch.port1, canvas, { raf: false, log: L });
  const tc = performance.now();
  const info = await sess.ready;
  L('connected in ' + Math.round(performance.now() - tc) + ' ms: ' + JSON.stringify(info));
  await sleep(2000);
  L('first picture: ' + JSON.stringify(sess.stats));
  const ctx = canvas.getContext('2d'), snap = () => ctx.getImageData(20, 20, 300, 200).data;
  sess.fake(6, 0, 2, 120); await sleep(1500); const a = snap();
  sess.fake(6, 0, 638, 120); await sleep(1500); const b = snap();
  let eyesDiff = 0; for (let i = 0; i < a.length; i += 4) if (a[i] !== b[i] || a[i + 1] !== b[i + 1] || a[i + 2] !== b[i + 2]) eyesDiff++;
  L('xeyes pixels changed by the pointer moving left -> right: ' + eyesDiff);
  // real DOM events on the canvas, through the same handlers a user's mouse and keyboard hit
  const r = canvas.getBoundingClientRect(), at = (x, y) => ({ clientX: r.left + x * r.width / canvas.width, clientY: r.top + y * r.height / canvas.height });
  canvas.dispatchEvent(new MouseEvent('mousemove', { ...at(460, 330), bubbles: true })); await sleep(300);
  canvas.focus();
  const key = (k, code, shiftKey) => { canvas.dispatchEvent(new KeyboardEvent('keydown', { key: k, code, shiftKey, bubbles: true, cancelable: true })); canvas.dispatchEvent(new KeyboardEvent('keyup', { key: k, code, shiftKey, bubbles: true, cancelable: true })); };
  key('a', 'KeyA'); key('A', 'KeyA', true); key('Enter', 'Enter');
  canvas.dispatchEvent(new MouseEvent('mousedown', { ...at(460, 330), button: 0, bubbles: true, cancelable: true }));
  canvas.dispatchEvent(new MouseEvent('mouseup', { ...at(460, 330), button: 0, bubbles: true, cancelable: true }));
  const expect = { a: (sess.keysym(0x61) || {}).code, A: sess.keysym(0x41), Return: (sess.keysym(0xff0d) || {}).code };
  L('keymap: a -> ' + expect.a + ', A -> ' + JSON.stringify(expect.A) + ', Return -> ' + expect.Return);
  await sleep(1500);
  canvas.dispatchEvent(new MouseEvent('mousedown', { ...at(460, 330), button: 2, bubbles: true, cancelable: true }));
  canvas.dispatchEvent(new MouseEvent('mouseup', { ...at(460, 330), button: 2, bubbles: true, cancelable: true }));
  await sleep(1500);
  L('stats: ' + JSON.stringify(sess.stats));
  const all = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  let s = ''; for (let i = 0; i < all.length; i += 32768) s += String.fromCharCode.apply(null, all.subarray(i, i + 32768));
  const png = canvas.toDataURL('image/png');
  sess.close();
  return { log, frames: sess.stats.frames, eyesDiff, expect, rgba: btoa(s), png };
}
function xwdPixels(b) {   // -> { w, h, px: RGB bytes }
  const u = (i) => b.readUInt32BE(i * 4);
  const hsize = u(0), w = u(4), h = u(5), byteOrder = u(7), bpp = u(11), bpl = u(12), ncolors = u(19), rm = u(14), gm = u(15), bm = u(16);
  const sh = (mask) => { let s = 0; while (mask && !(mask & 1)) { mask >>>= 1; s++; } return s; };
  const px = Buffer.alloc(w * h * 3), data = hsize + ncolors * 12;
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const o = data + y * bpl + x * (bpp / 8), p = bpp === 32 ? (byteOrder ? b.readUInt32BE(o) : b.readUInt32LE(o)) : b[o], d = (y * w + x) * 3;
    px[d] = (p & rm) >>> sh(rm); px[d + 1] = (p & gm) >>> sh(gm); px[d + 2] = (p & bm) >>> sh(bm);
  }
  return { w, h, px };
}

// ---- XWD (X11 window dump, version 7, ZPixmap TrueColor) -> PNG ----
function xwdToPng(b) {
  const u = (i) => b.readUInt32BE(i * 4);
  const hsize = u(0), w = u(4), h = u(5), byteOrder = u(7), bpp = u(11), bpl = u(12), ncolors = u(19);
  const rm = u(14), gm = u(15), bm = u(16);   // header: ... bits_per_pixel 11, bytes_per_line 12, visual_class 13, masks 14-16
  const data = hsize + ncolors * 12;
  const sh = (mask) => { let s = 0; while (mask && !(mask & 1)) { mask >>>= 1; s++; } return s; };
  const rs = sh(rm), gs = sh(gm), bs = sh(bm);
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 3 + 1)] = 0;
    for (let x = 0; x < w; x++) {
      const o = data + y * bpl + x * (bpp / 8);
      let px = bpp === 32 ? (byteOrder ? b.readUInt32BE(o) : b.readUInt32LE(o)) : bpp === 16 ? (byteOrder ? b.readUInt16BE(o) : b.readUInt16LE(o)) : b[o];
      const d = y * (w * 3 + 1) + 1 + x * 3;
      raw[d] = (px & rm) >>> rs; raw[d + 1] = (px & gm) >>> gs; raw[d + 2] = (px & bm) >>> bs;
    }
  }
  const crcT = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcT[n] = c >>> 0; }
  const crc = (buf) => { let c = 0xffffffff; for (const x of buf) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (t, d) => { const l = Buffer.alloc(4); l.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t), d]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([l, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
