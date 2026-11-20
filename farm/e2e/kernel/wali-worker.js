// WALI browser syscall host v2 — process model edition.
// vfork/execve/wait4/pipes on top of the in-memory VFS + OPFS mount.
// Child branch runs in-place under an fd overlay (vfork semantics, guest
// longjmps back via wasm-EH SJLJ); wait4 runs parked children synchronously.
'use strict';

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
try { self.addEventListener('unhandledrejection', (e) => { try { self.postMessage({ t: 'out', fd: 2, s: '[host] UNHANDLED: ' + ((e.reason && e.reason.stack) || e.reason) + '\n' }); } catch {} }); } catch {}
// (NXIO: open("/dev/tty") with no controlling terminal -- it was missing, so err(undefined)
// trapped every program that probes /dev/tty first: bash in the in-process engine.)
const E = { PERM:1, NOENT:2, SRCH:3, INTR:4, IO:5, NXIO:6, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, EXIST:17, XDEV:18, NOTDIR:20, ISDIR:21, INVAL:22, NOTTY:25, SPIPE:29, PIPE:32, NOSPC:28, NOSYS:38, NOTEMPTY:39,
            ADDRINUSE:98, ADDRNOTAVAIL:99, CONNREFUSED:111, TIMEDOUT:110 };

// LOOPBACK TCP, entirely inside this kernel.
//
// listen() used to hand the port to the WISP relay (OP.LISTEN). But WISP is an OUTBOUND
// transport -- a browser cannot accept inbound TCP -- so the relay refused, and since it
// refused with -98 the guest saw "Address in use" on EVERY port. Measured on unused ports
// in a fresh kernel, three independent stacks agreeing:
//     nc -l -p 9001        -> nc: listen: Address in use
//     python bind(9002)    -> [Errno 98] Address in use
//     tlswrap -L 9443 ...  -> listen: Address in use
// which made the tlswrap -L LOCALPORT HOST 443 workflow the tool documents impossible,
// and a local server unbuildable.
//
// A 127.0.0.1 listener never needed the relay: both ends are in here. Connections are
// ordinary socketpairs, so read/write/poll/close all work through the existing spair paths
// with no new plumbing -- and accept blocks the way the relay one does, by returning
// EAGAIN for sysAsync to retry.
//
// 0.0.0.0 is treated as local too. A guest binding "any" in a browser has no "any" to bind:
// there is no route by which an outside connection could arrive, so local is the only
// meaning it can have -- and it is what makes a plain `nc -l -p N` work.
const localListeners = new Map();          // port -> { port, backlog: [] }
const isLocalBindIp = (ip) => !ip || ip === '0.0.0.0' || ip === '::' || ip === '127.0.0.1'
  || (typeof ip === 'string' && (ip.startsWith('127.') || ip === '::1'));
const err = (e) => BigInt(-e);
const td = new TextDecoder(), te = new TextEncoder();
// argv and environment strings are BYTES on Linux, not UTF-8: `git commit -m "$(printf
// 'a\370b')"` must store byte 0xF8 (git's t4201 does exactly that). The kernel keeps them as
// JS strings, so bytes that are not valid UTF-8 travel as lone surrogates U+DC80..U+DCFF
// (Python's "surrogateescape"), which valid UTF-8 can never produce: bdec/benc round-trip
// any byte string. td/te would turn each such byte into U+FFFD for good.
const tdStrict = new TextDecoder('utf-8', { fatal: true });
function bdec(u8) {
  try { return tdStrict.decode(u8); } catch (_) {}
  let s = '', i = 0;
  while (i < u8.length) {
    const b = u8[i];
    let n = b < 0x80 ? 1 : b >= 0xc2 && b <= 0xdf ? 2 : b >= 0xe0 && b <= 0xef ? 3 : b >= 0xf0 && b <= 0xf4 ? 4 : 0;
    if (n > 1) {   // a well-formed sequence (no overlongs, no surrogates, <= U+10FFFF), else escape the lead byte
      const c1 = u8[i + 1];
      const lo = b === 0xe0 ? 0xa0 : b === 0xf0 ? 0x90 : 0x80, hi = b === 0xed ? 0x9f : b === 0xf4 ? 0x8f : 0xbf;
      if (!(c1 >= lo && c1 <= hi)) n = 0;
      for (let k = 2; n && k < n; k++) if (!(u8[i + k] >= 0x80 && u8[i + k] <= 0xbf)) n = 0;
    }
    if (n === 0) { s += String.fromCharCode(0xdc00 + b); i++; continue; }
    s += td.decode(u8.subarray(i, i + n)); i += n;
  }
  return s;
}
const ESC_RE = /[\udc80-\udcff]/u;   // u flag: a lone low surrogate, never half of a valid pair
function benc(s) {
  if (!ESC_RE.test(s)) return te.encode(s);
  const out = [];
  for (const ch of s) {   // by code point
    const c = ch.charCodeAt(0);
    if (ch.length === 1 && c >= 0xdc80 && c <= 0xdcff) out.push(c - 0xdc00);
    else for (const x of te.encode(ch)) out.push(x);
  }
  return Uint8Array.from(out);
}

// ================= VFS (global, shared by all processes) =================
const files = new Map(), dirs = new Map([['/', new Set()]]);
// libffi for walios guests (walios/build/libffi/ffi.c): calls by a signature only known at
// run time, and closures, through the guest's own function table. exp() = the instance's
// exports (memory, __indirect_function_table). jspi: the guest runs on a JSPI stack, so a
// call or closure goes through WebAssembly.promising and may suspend inside (a syscall).
// Signatures: sig[0] = result ('v' none, 'i' i32, 'j' i64, 'f' f32, 'd' f64), then the
// parameters; values travel in 8-byte slots.
function waliFfiImports(exp, jspi) {
  const VT = { i: 0x7f, j: 0x7e, f: 0x7d, d: 0x7c };
  const freeIdx = [];
  const dv = () => new DataView(exp().memory.buffer);
  const tbl = () => exp().__indirect_function_table;
  const sigOf = (p) => { const u = new Uint8Array(exp().memory.buffer); let s = ''; while (u[p]) s += String.fromCharCode(u[p++]); return s; };
  const rd = (d, c, o) => (c === 'i' ? d.getInt32(o, true) : c === 'j' ? d.getBigInt64(o, true) : c === 'f' ? d.getFloat32(o, true) : d.getFloat64(o, true));
  const wr = (d, c, o, v) => { if (c === 'i') d.setInt32(o, v, true); else if (c === 'j') d.setBigInt64(o, BigInt(v), true); else if (c === 'f') d.setFloat32(o, v, true); else if (c === 'd') d.setFloat64(o, v, true); };
  const args = (sig, slots) => { const d = dv(), a = []; for (let i = 1; i < sig.length; i++) a.push(rd(d, sig[i], slots + 8 * (i - 1))); return a; };
  // A wasm function of signature sig that calls f: the only way to put a JS function in a
  // wasm table is to import it into a module of its own and take the export.
  const leb = (n) => { const b = []; do { let x = n & 0x7f; n >>>= 7; if (n) x |= 0x80; b.push(x); } while (n); return b; };
  const sec = (id, body) => [id, ...leb(body.length), ...body];
  const wasmFn = (sig, f) => {
    const ps = [...sig.slice(1)].map((c) => VT[c]), rs = sig[0] === 'v' ? [] : [VT[sig[0]]];
    const bytes = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
      ...sec(1, [1, 0x60, ...leb(ps.length), ...ps, ...leb(rs.length), ...rs]),
      ...sec(2, [1, 1, 0x65, 1, 0x66, 0, 0]),            // import e.f : type 0
      ...sec(7, [1, 1, 0x66, 0, 0])]);                    // export f = function 0
    return new WebAssembly.Instance(new WebAssembly.Module(bytes), { e: { f } }).exports.f;
  };
  const call = jspi
    ? new WebAssembly.Suspending(async (fn, sigP, slots, ret) => {
      const sig = sigOf(sigP), r = await WebAssembly.promising(tbl().get(fn))(...args(sig, slots));
      if (sig[0] !== 'v') wr(dv(), sig[0], ret, r);
    })
    : (fn, sigP, slots, ret) => {
      const sig = sigOf(sigP), r = tbl().get(fn)(...args(sig, slots));
      if (sig[0] !== 'v') wr(dv(), sig[0], ret, r);
    };
  const closure = (idx, sigP, clo, bufFn, enterFn) => {
    const sig = sigOf(sigP), n = sig.length - 1, T = tbl();
    // slots come from the guest's malloc (bufFn), so a closure may re-enter itself
    const fill = (a) => { const b = T.get(bufFn)(0, 8 * (n + 1)), d = dv(); a.forEach((v, i) => wr(d, sig[i + 1], b + 8 * (i + 1), v)); return b; };
    const done = (b) => { const r = sig[0] === 'v' ? undefined : rd(dv(), sig[0], b); T.get(bufFn)(b, 0); return r; };
    const h = jspi
      ? new WebAssembly.Suspending(async (...a) => { const b = fill(a); await WebAssembly.promising(T.get(enterFn))(clo, b); return done(b); })
      : (...a) => { const b = fill(a); T.get(enterFn)(clo, b); return done(b); };
    T.set(idx, wasmFn(sig, h));
    return 0;
  };
  return {
    __wali_ffi_call: call,
    __wali_ffi_table_alloc: () => (freeIdx.length ? freeIdx.pop() : tbl().grow(1)),
    __wali_ffi_closure: closure,
    __wali_ffi_closure_free: (idx) => { tbl().set(idx, null); freeIdx.push(idx); },
  };
}

function norm(p, cwd) {
  if (!p.startsWith('/')) p = cwd.replace(/\/$/, '') + '/' + p;
  const out = [];
  for (const part of p.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') out.pop(); else out.push(part);
  }
  return '/' + out.join('/');
}
function mkdirp(p) {
  if (dirs.has(p)) return;
  const parent = p.slice(0, p.lastIndexOf('/')) || '/';
  mkdirp(parent);
  dirs.set(p, new Set());
  dirs.get(parent).add(p.slice(p.lastIndexOf('/') + 1));
  dirTouch(p); dirTouch(parent);
}
// Stable, unique inodes. Every regular file used to report ino 1: LLVM's FileManager keys
// its cache by (dev, ino), so <stddef.h> was "the same file" as the source that included
// it -- "#include nested too deeply" -- and Python's os.path.samefile() / git's index have
// the same need. Files carry theirs on the entry; directories are keyed by path.
let inoSeq = 1000; const dirInos = new Map();
// Files and directories on the OPFS mount get an inode HASHED from their path: the same in
// every kernel, tab and boot. A per-kernel counter gave the same file 1024 in one tab and 1010
// in another, and git's index (which stores st_ino) then saw every file as changed in each
// fresh kernel and re-read them all. 52 bits from two FNV-1a passes, offset past the counter.
// (Deviation: a rename changes the number; Linux keeps it. Cross-kernel stability won.)
function pathIno(s) {
  let h1 = 0x811c9dc5, h2 = 0x01000193 ^ 0x5bd1e995;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 16777619); h2 = Math.imul(h2 ^ c, 0x01000193) ^ (h2 >>> 13); }
  return 2 ** 40 + (h1 >>> 0) * 2 ** 12 + ((h2 >>> 0) & 0xfff);
}
function inoOf(x) {
  if (typeof x === 'string') {
    if (inOpfs(x)) return pathIno('d:' + opfsRel(x));
    let n = dirInos.get(x); if (!n) dirInos.set(x, n = ++inoSeq); return n;
  }
  if (x.linkIno) return x.linkIno;   // a link() copy on the mount reports its source's inode (OP.LINK)
  if (x.br !== undefined) return pathIno('f:' + x.br);
  if (!x.ino) x.ino = ++inoSeq; return x.ino;
}
// Directory mtimes: stable per kernel (first seen / last changed here), never "now" on every
// stat -- statPath used to fall back to Date.now() for directories and symlinks.
const dirMtimes = new Map();
// Strictly increasing per directory (10 us steps past the last stamp): Date.now() is whole
// milliseconds, so two entries added within one ms left the mtime unchanged -- and git's
// untracked cache, which trusts a directory whose mtime did not move, listed stale results
// (t7063, intermittently). Linux stamps in nanoseconds; collisions there do not happen.
const dirTouch = (p) => { const last = dirMtimes.get(p) || 0, now = Date.now(); dirMtimes.set(p, now > last ? now : last + 0.01); };
// Directory owners. stat reported every directory as uid/gid 1000 (putStat's fallback) while
// files and processes are uid 0: git's safe.directory check (owner of the repo dir == euid)
// then refused every repository whose config did not list it -- "detected dubious ownership",
// and git ignored the repo. Directories default to root like files; mkdir/chown record.
const dirOwners = new Map();          // path -> { uid, gid }
// Directory permission bits: stat said 0755 for every directory and chmod on one was a no-op,
// so umask, `git init --shared` (setgid + group bits) and restricted dirs were invisible. On
// the OPFS mount they persist through the bridge's mode sidecar like a file's.
const dirModes = new Map();           // path -> permission bits (0o7777)
function dirSetMode(p, bits) {
  dirModes.set(p, bits & 0o7777);
  if (inOpfs(p) && p !== opfsMount) { const br = initOpfs(); if (br) { try { const pb = te.encode(opfsRel(p)); br.call(OFS.SETMODE, pb.length, bits & 0o7777, 0, pb); } catch (_) {} } }
}
function addFile(p, data, mode = 0o100644) {
  const parent = p.slice(0, p.lastIndexOf('/')) || '/';
  mkdirp(parent);
  dirs.get(parent).add(p.slice(p.lastIndexOf('/') + 1));
  files.set(p, { data, size: data.length, mode, mtimeMs: Date.now() });
  dirTouch(parent);
}
function rmEntry(p) {
  const parent = p.slice(0, p.lastIndexOf('/')) || '/';
  files.delete(p); dirs.delete(p); dirMtimes.delete(p); dirOwners.delete(p); dirModes.delete(p);
  const d = dirs.get(parent); if (d) { d.delete(p.slice(p.lastIndexOf('/') + 1)); dirTouch(parent); }
}
// Package CDN fallback (walios-backend.js PKG_BASE). The run message maps each CDN url to
// this server's own copy; a CDN error, non-2xx or no response headers within 8s fetches the
// copy instead, and after one failure the CDN is skipped for the rest of this kernel's
// life. Module keys stay the CDN urls either way. Hosts without the map (the public
// site) fetch the url as-is.
let artFallback = {};
let artCdnDown = false;
// Versioned assets (a url with ?v=, which the server marks immutable) are kept in Cache
// Storage, not only the browser's HTTP cache. The Android app's WebView did not keep them:
// one user's phone downloaded pylib.tar.gz (8.9MB) 47 times in a day (2026-11-07), every
// Python start, over mobile data. Cache Storage is the page's own store (the LibreOffice
// engine already lives there), so a bundle is downloaded once per version. Older versions of
// the same file are dropped when a new one is stored. Unversioned urls, blob: urls and
// errors go to the network as before.
const ASSET_CACHE = 'walios-assets-v1';
async function fetchArt(url) {
  let c = null, abs = null;
  try {
    if (typeof caches !== 'undefined' && /[?&]v=/.test(url) && !/^blob:/.test(url)) {
      abs = new URL(url, self.location.href).href;
      c = await caches.open(ASSET_CACHE);
      const hit = await c.match(abs);
      if (hit) return hit;
    }
  } catch (_) { c = null; }
  const resp = await fetchArtNet(url);
  if (c && resp && resp.status === 200) {
    try {
      const copy = resp.clone();
      c.put(abs, copy).then(async () => {
        const base = abs.replace(/\?.*$/, '');
        for (const req of await c.keys()) if (req.url !== abs && req.url.replace(/\?.*$/, '') === base) c.delete(req);
      }).catch(() => {});
    } catch (_) {}
  }
  return resp;
}
async function fetchArtNet(url) {
  const alt = artFallback[url];
  if (!alt) return fetch(url);
  if (!artCdnDown) {
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), 8000);
    try {
      const r = await fetch(url, { signal: ac.signal });
      clearTimeout(t);
      if (r.ok) return r;
      post(`[host] package CDN: HTTP ${r.status} for ${url}; using this server's copy\n`, 2);
    } catch (e) { clearTimeout(t); post(`[host] package CDN unreachable (${e.name === 'AbortError' ? 'timeout' : e.message || e}); using this server's copies\n`, 2); }
    artCdnDown = true;
  }
  return fetch(alt);
}
async function loadTar(url, prefix, onPath) {
  const resp = await fetchArt(url);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
  const ds = new DecompressionStream('gzip');
  installTar(new Uint8Array(await new Response(resp.body.pipeThrough(ds)).arrayBuffer()), prefix, onPath);
  mountedTars.set(url, prefix);
}
// Split out of loadTar so a bundle that arrived by another route can be installed too. (The
// guest is parked in Atomics.wait ON THIS THREAD, so this thread can no longer run its own
// message handler and the fetch half can never happen here -- the host does fetch+gunzip on
// its thread and hands the plain tar bytes over a SAB; the guest parses them with this,
// rather than a second copy of the parser.
function installTar(buf, prefix, onPath) {
  let off = 0;
  while (off + 512 <= buf.length) {
    const hdr = buf.subarray(off, off + 512);
    if (hdr.every(b => b === 0)) break;
    let name = td.decode(hdr.subarray(0, 100)).replace(/\0.*$/, '');
    const pfx = td.decode(hdr.subarray(345, 500)).replace(/\0.*$/, '');
    if (pfx) name = pfx + '/' + name;
    const size = parseInt(td.decode(hdr.subarray(124, 136)).trim(), 8) || 0;
    const tmode = parseInt(td.decode(hdr.subarray(100, 108)).trim(), 8) || 0o644; // preserve perms (sshd checks host-key 0600)
    const type = String.fromCharCode(hdr[156] || 48);
    off += 512;
    if (type === '0' || type === '\0') { const fp = norm(prefix + '/' + name, '/'); addFile(fp, buf.slice(off, off + size), 0o100000 | (tmode & 0o7777)); if (onPath) onPath(fp); }
    else if (type === '5') mkdirp(norm(prefix + '/' + name, '/'));
    else if (type === '2') {
      const lp = norm(prefix + '/' + name, '/');
      if (!files.has(lp) && !dirs.has(lp)) { addFile(lp, new Uint8Array(0), 0o120777); files.get(lp).sym = td.decode(hdr.subarray(157, 257)).replace(/\0.*$/, ''); }
    }
    off += Math.ceil(size / 512) * 512;
  }
}
// ---- per-conversation VM state (host: sandpie-worker.js _waliosVm*) ----
// A conversation's kernel is dropped after its idle timeout, and everything it held in RAM
// went with it: /tmp, a `make install` into /usr/local, /opt, packages added with `apk add`.
// The host asks for this snapshot after runs, stores it locally (IndexedDB, never synced) and
// hands it back as an extra boot tar of the conversation's NEXT kernel, so the VM carries on.
// Only RAM files: OPFS-backed ones (f.br) are the workspace and already persist. Regular
// files, symlinks and directories; anything else (fifos, sockets, devices) is skipped.
function vmSnapshot(roots, max) {
  const parts = []; let bytes = 0, nfiles = 0, skipped = 0, tooBig = false;
  const oct = (n, w) => n.toString(8).padStart(w - 1, '0') + '\0';
  const header = (name, size, mode, type, link, mtime) => {
    let nm = name, pfx = '';
    if (te.encode(nm).length > 100) {             // ustar: split into prefix (155) + name (100) at a '/'
      let cut = -1;
      for (let i = nm.indexOf('/'); i > 0; i = nm.indexOf('/', i + 1)) { if (i <= 155 && te.encode(nm.slice(i + 1)).length <= 100) { cut = i; break; } }
      if (cut < 0) return null;
      pfx = nm.slice(0, cut); nm = nm.slice(cut + 1);
    }
    const h = new Uint8Array(512);
    const put = (str, off, len) => { const b = te.encode(str); h.set(b.subarray(0, len), off); };
    put(nm, 0, 100); put(oct(mode & 0o7777, 8), 100, 8); put(oct(0, 8), 108, 8); put(oct(0, 8), 116, 8);
    put(oct(size, 12), 124, 12); put(oct(Math.floor((mtime || Date.now()) / 1000), 12), 136, 12);
    h.fill(32, 148, 156); h[156] = type.charCodeAt(0); if (link) put(link, 157, 100);
    put('ustar\0', 257, 6); put('00', 263, 2); if (pfx) put(pfx, 345, 155);
    let sum = 0; for (let i = 0; i < 512; i++) sum += h[i];
    put(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    return h;
  };
  const add = (h, data) => {
    if (!h) { skipped++; return; }
    parts.push(h); bytes += 512;
    if (data && data.length) { parts.push(data); const pad = (512 - (data.length % 512)) % 512; if (pad) parts.push(new Uint8Array(pad)); bytes += data.length + pad; }
  };
  const walk = (dir) => {
    if (tooBig) return;
    const kids = dirs.get(dir); if (!kids) return;
    if (dir !== '/') add(header(dir.slice(1) + '/', 0, 0o755, '5', '', Date.now()));
    for (const n of [...kids].sort()) {
      if (tooBig) return;
      const p = dir === '/' ? '/' + n : dir + '/' + n;
      if (dirs.has(p)) { walk(p); continue; }
      const f0 = files.get(p);
      if (!f0 || f0.br !== undefined || f0.brId) continue;      // OPFS-backed: the workspace, already persistent
      const type = f0.mode & 0o170000;
      if (type === 0o120000) { add(header(p.slice(1), 0, 0o777, '2', String(f0.sym || ''), f0.mtimeMs)); nfiles++; }
      else if (type === 0o100000 && f0.data) {
        const data = f0.data.subarray(0, f0.size);
        if (bytes + data.length > max) { tooBig = true; return; }
        add(header(p.slice(1), data.length, f0.mode, '0', '', f0.mtimeMs), data); nfiles++;
      } else skipped++;
    }
  };
  for (const r of roots) { const rp = norm(r, '/'); if (dirs.has(rp)) walk(rp); }
  if (tooBig) return { tooBig: true, bytes };
  parts.push(new Uint8Array(1024)); bytes += 1024;
  const buf = new Uint8Array(bytes); let o = 0; for (const x of parts) { buf.set(x, o); o += x.length; }
  return { buf, files: nfiles, skipped, bytes };
}
// ---- lazy OPFS mount (the riscv-vm ?p9lazy model): a sibling opfs-worker
// (spawned by the page, SAB set via the 'opfs-sab' message) owns every OPFS
// handle. We fault a directory's LISTING in on first touch of any path under
// it, and open a per-file handle only when the file is actually read/written —
// so mount cost is O(1) and untouched files hold no exclusive locks. ----
let opfsSab = null, opfsMount = null, opfsBr = null, opfsDead = false;   // opfsDead: the bridge never answered; every op is EIO
const opfsListWarned = new Set();   // directories whose failed listing was already reported (a failure is retried, the warning is not)
// dir -> when its OPFS listing was last merged into the VFS. A listing used to be taken
// ONCE per kernel lifetime, and a kernel lives across runs (the tool reuses it) or for a
// whole terminal session -- so a file another kernel created (the terminal vs the tool vs
// another conversation) or the Dropbox sync pulled was invisible here until this kernel
// died, and a size it changed was read back stale. Listings now expire; opfsLoadDir
// reconciles the cached entries against the fresh listing (see there).
const opfsLoaded = new Map();
const OPFS_LIST_TTL = 1500;

// The app's OWN workspace, inside the OPFS root the guest mounts at /root:
// sandpie/{config,conversations,memory,scripts,secrets,skills,...}. It is the
// application's data, not the shell's, and deleting it costs the user their
// conversations, memory and secrets -- and it propagates to Dropbox as well. A
// model asked to "clone the sandpie repo" ran `rm -rf /root/sandpie` and wiped
// exactly that (admin transcript t946ympe-2026-09-08T23-10-34); the warning in the
// tool description did not stop it, so this is a real gate.
//
// Deletion only. Reading and writing there stay allowed, and an INTERNAL rename
// inside sandpie/ is a legitimate edit -- what is refused is removing the data:
// unlink, rmdir, and a rename that moves a protected path OUT of the workspace
// (which sync would then see as a deletion). Escape hatch for a deliberate wipe:
// touch /root/.allow-sandpie-delete first (a sentinel FILE, not an env var --
// busybox runs `rm` as an in-process applet, so a `VAR=1 rm` prefix reaches no new
// process env and an env-based override does not work).
const APP_DIR = 'sandpie';
function isAppPath(p) {
  if (!inOpfs(p)) return false;
  const rel = opfsRel(p);
  return rel === APP_DIR || rel.startsWith(APP_DIR + '/');
}
let protectedWarned = false;
function protectedDelete(S, p) {
  if (!isAppPath(p)) return false;
  if (files.has(opfsMount + '/.allow-sandpie-delete')) return false;   // sentinel override
  if (!protectedWarned) {
    protectedWarned = true;
    post('walios: refusing to delete /' + opfsRel(p) + " - that is the app's own workspace"
         + ' (conversations, memory, secrets, skills), not scratch space. If you really'
         + ' mean it: touch /root/.allow-sandpie-delete first.\n', 2);
  }
  return true;
}
const OFS = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11, SETMODE: 12, FSYNC: 13, SYMLINK: 14, RENAMEDIR: 15, STAT: 16, LOCK: 17, UNLOCK: 18, SETMTIME: 19, LINK: 20 };
// ---- bridges without SharedArrayBuffer (in-process engine) ----
// The OPFS and WISP workers answer over a MessagePort here (sandpie-worker.js wires
// one when the page has no SAB; the 'opfs-port' / 'wisp-port' messages). The VFS and
// socket code that calls br.call() is synchronous and cannot wait for a message, so a
// call whose answer is not in hand throws NeedAsync carrying the request's promise. The
// Suspending import that is running the syscall (see _makeInProcImports) awaits it --
// the answer lands in bridgeCache -- and re-runs the syscall from the top: the same
// call then finds its answer and consumes it. That makes every handler's bridge call
// a resumption point, which is why the handlers must not change kernel state before
// the call they depend on (opfsLoadDir marks its directory loaded only once listed).
// Ops whose result the kernel never needs (writes, closes, path changes it already
// applied to its own tree) are posted and answered at once; the worker still performs
// them in order, before any later read.
// 64-bit offsets/sizes over the bridges' Int32 slots (see opfs-worker finishNow): hi32 of an
// argument rides alongside it, a size answer's high word comes back as auxh.
const hi32 = (v) => (typeof v === 'number' && v >= 2147483648) ? Math.floor(v / 4294967296) : 0;
const auxBig = (r) => r.auxh ? (r.aux >>> 0) + r.auxh * 4294967296 : r.aux;
class NeedAsync extends Error { constructor(promise) { super('need-async'); this.promise = promise; } }
const bridgeCache = new Map();          // key -> { res, aux, data }, consumed by the retry that finds it
let bridgeSeq = 0;
const EMPTY_U8 = new Uint8Array(0);
let opfsPort = null, wispPort = null;
function bridgeKey(name, op, a0, a1, a2, bytes) {
  let b = '';
  if (bytes) {
    if (bytes.length <= 512) { for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]); }
    else { let h = 2166136261; for (let i = 0; i < bytes.length; i++) h = Math.imul(h ^ bytes[i], 16777619); b = 'h' + bytes.length + ':' + (h >>> 0); }
  }
  return name + '|' + op + '|' + a0 + '|' + a1 + '|' + a2 + '|' + b;
}
// fireAndForget: op -> the result to answer at once (a value, or a function of the args).
// probes: op -> the "not yet" answer. A readiness probe (socket POLL, PINGPOLL) is asked
// in a loop that sleeps between asks and keeps its own deadline, so it must not restart
// the syscall: the first ask sends the request and answers "not yet", later asks answer
// the latest reply and send a fresh request once it is older than a tick. A data op on
// the same socket (RECV, ACCEPT) consumes what the probe saw, so its answer is dropped.
function portBridge(port, name, fireAndForget, probes) {
  const pending = new Map();
  const ffErr = new Map();    // opfs handle id -> errno of a fire-and-forget op that failed (see call)
  const probed = new Map();   // key -> { res, aux, data, at, inflight }
  const PROBE_FRESH_MS = 10;
  port.onmessage = (ev) => { const m = ev.data; if (!m || m.t !== 'reply') return; const p = pending.get(m.id); if (!p) return; pending.delete(m.id); p(m); };
  const send = (op, a0, a1, a2, bytes) => new Promise((res) => {
    const id = ++bridgeSeq; pending.set(id, res);
    const copy = bytes ? bytes.slice() : null;
    port.postMessage({ t: 'call', id, op, a0: a0 | 0, a1: a1 | 0, a1h: hi32(a1), a2: a2 | 0, bytes: copy ? copy.buffer : null }, copy ? [copy.buffer] : []);
  });
  const unpack = (m) => ({ res: m.res | 0, aux: m.aux | 0, auxh: m.auxh | 0, data: m.data ? new Uint8Array(m.data) : EMPTY_U8 });
  const call = (op, a0, a1, a2, bytes) => {
    const ff = fireAndForget[op];
    if (ff !== undefined) {
      // Answered at once (the syscall cannot wait here), so a failure only shows up when the
      // reply arrives. It used to be dropped, and a write that failed (quota, a lock, a stalled
      // bridge) read as success: the data was silently lost (confirmed 2026-11-07, Android).
      // Now a failed reply is remembered per open file: the next write/truncate/close on that
      // file returns the error (close() reporting a deferred write error is what Linux does on
      // network filesystems), and the guest's stderr gets one loud line at once.
      const handleOp = name === 'opfs' && (op === OFS.WRITE || op === OFS.TRUNC || op === OFS.CLOSE);
      if (handleOp && ffErr.has(a0)) { const e = ffErr.get(a0); ffErr.delete(a0); return { res: e, aux: 0, data: EMPTY_U8 }; }
      send(op, a0, a1, a2, bytes).then((m) => {
        const r = m.res | 0;
        if (r >= 0 || name !== 'opfs') return;
        if (handleOp && op !== OFS.CLOSE) ffErr.set(a0, r);
        ffFailed(op, a0, r);
      });
      if (handleOp && op === OFS.CLOSE) ffErr.delete(a0);
      return { res: typeof ff === 'function' ? ff(a0, a1, a2, bytes) : ff, aux: 0, data: EMPTY_U8 };
    }
    const key = bridgeKey(name, op, a0, a1, a2, bytes);
    if (probes && probes[op] !== undefined) {
      let e = probed.get(key);
      if (!e) { e = { res: probes[op], aux: 0, data: EMPTY_U8, at: 0, inflight: false }; probed.set(key, e); }
      if (!e.inflight && Date.now() - e.at >= PROBE_FRESH_MS) {
        e.inflight = true;
        send(op, a0, a1, a2, bytes).then((m) => { Object.assign(e, unpack(m)); e.at = Date.now(); e.inflight = false; });
      }
      return e;
    }
    const hit = bridgeCache.get(key);
    if (hit) {
      bridgeCache.delete(key);
      if (probes) for (const pk of probed.keys()) if (pk.startsWith(name + '|') && pk.split('|')[2] === String(a0 | 0)) probed.delete(pk);
      return hit;
    }
    throw new NeedAsync(send(op, a0, a1, a2, bytes).then((m) => { bridgeCache.set(key, unpack(m)); }));
  };
  // No SAB window: a read asks for the whole range in one call (a retry must find the
  // one answer it is waiting for, not the first of several chunks). `port` tells the
  // socket code the same about a multi-buffer receive.
  // takeErr: the deferred error of a fire-and-forget op on this handle, consumed (fsync
  // reports it: an fsync that said 0 after a lost write would be a false "durable").
  const takeErr = (id) => { const e = ffErr.get(id); if (e === undefined) return 0; ffErr.delete(id); return e; };
  return { call, max: 1 << 30, port: true, takeErr };
}
const ERRNO_NAME = { [-1]: 'EPERM', [-2]: 'ENOENT', [-5]: 'EIO', [-9]: 'EBADF', [-13]: 'EACCES', [-16]: 'EBUSY', [-17]: 'EEXIST', [-22]: 'EINVAL', [-28]: 'ENOSPC', [-39]: 'ENOTEMPTY' };
const ffWarned = new Set();
function ffFailed(op, a0, r) {
  let where = '';
  if (op === OFS.WRITE || op === OFS.TRUNC || op === OFS.CLOSE) { for (const [p, fo] of files) if (fo && fo.brId === a0) { where = p; break; } }
  const what = op === OFS.WRITE ? 'a write to' : op === OFS.TRUNC ? 'truncating' : op === OFS.CLOSE ? 'closing' : 'a change in';
  const key = op + '|' + (where || a0) + '|' + r;
  if (ffWarned.has(key)) return; ffWarned.add(key);
  post('[host] ' + what + ' ' + (where || 'the workspace') + ' FAILED (' + (ERRNO_NAME[r] || ('errno ' + (-r))) + '): the data was NOT saved\n', 2);
}
const OPFS_FF = { [OFS.WRITE]: (a0, a1, a2) => a2, [OFS.TRUNC]: 0, [OFS.CLOSE]: 0, [OFS.UNLINK]: 0, [OFS.MKDIR]: 0,
                  [OFS.RMDIR]: 0, [OFS.RENAME]: 0, [OFS.RELEASE]: 0, [OFS.SETMODE]: 0, [OFS.UNLOCK]: 0 };
// ---- modes for OPFS-backed files ------------------------------------------
// OPFS has no modes. The bridge (opfs-worker.js) keeps a sidecar of the ones the
// guest set explicitly and hands them back with each listing; anything without a
// record gets a guess here. chmod used to change RAM only, so `chmod 600 ~/.ssh/id_ed25519`
// was undone by the next boot and ssh refused the key again.
const OPFS_DEFAULT_MODE = 0o100644;
function opfsGuessMode(rel) {
  if (/(^|\/)\.ssh\//.test(rel)) return 0o100600;     // ssh refuses a world-readable key; sshd wants 0600 host keys
  if (/\.sh$/.test(rel)) return 0o100755;             // a script by name should be runnable by name
  return OPFS_DEFAULT_MODE;
}
// Persist f.mode for an OPFS-backed file. Called only where the guest ASKED for a
// mode (chmod/fchmod, O_CREAT with a non-default mode, rename keeping attrs), so the
// store holds exceptions, not every file. Best-effort: RAM already has the mode.
function opfsSaveMode(f) {
  if (!f || f.br === undefined || f.br === '') return;
  const br = initOpfs(); if (!br) return;
  try { const pb = te.encode(f.br); br.call(OFS.SETMODE, pb.length, f.sym !== undefined ? 0o120777 : (f.mode & 0o7777), 0, pb); } catch (_) {}
}
// A symlink on the OPFS mount: OPFS has no symlinks, so the bridge stores a small file holding
// the target and marks it S_IFLNK in its mode sidecar (it lists back with `l` = target). It
// used to live in RAM only: gone on the next boot and invisible to other tabs, so a git
// checkout with symlinks lost them. -> errno (0 = ok). The RAM entry is made by the caller.
function opfsSymlink(lp, tgt) {
  opfsFault(lp.slice(0, lp.lastIndexOf('/')) || '/');
  const br = initOpfs(); if (!br) return E.IO;
  const pb = te.encode(opfsRel(lp) + '\0' + tgt);
  const r = br.call(OFS.SYMLINK, pb.length, 0, 0, pb);
  return r.res < 0 ? ioErrno(r.res) : 0;
}
function initOpfs() {
  if (opfsBr) return opfsBr;
  if (opfsPort) { opfsBr = portBridge(opfsPort, 'opfs', OPFS_FF); return opfsBr; }
  if (!opfsSab) return null;
  const ctl = new Int32Array(opfsSab, 0, 8), bdata = new Uint8Array(opfsSab, 32);
  const call = (op, a0, a1, a2, bytes) => {
    if (bytes) bdata.set(bytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0; ctl[7] = hi32(a1);
    if (opfsDead) return { res: -E.IO, aux: 0, data: bdata };
    const prev = Atomics.load(ctl, 1);
    Atomics.add(ctl, 0, 1); Atomics.notify(ctl, 0);
    // Bounded, not forever -- but two different bounds. A bridge that never PICKS UP the
    // request (no OPFS in this browser, a worker that failed to start) used to park the
    // kernel and every guest for good: after 20s with no pickup the store is declared dead
    // and every op fails with EIO. A bridge that picked the request up and is merely slow
    // (opening a cloud-only file downloads it from Dropbox first; a large file on a slow
    // link takes longer than 20s) stamps SLOW_MARK into ctl[5]: then the kernel keeps
    // waiting, up to 10 minutes, and a timeout fails only THAT operation. The first
    // version treated both alike and one slow download disabled /root for the session.
    const SLOW_MARK = 0x7ea7, start = Date.now(); let warned = false;
    while (Atomics.load(ctl, 1) === prev) {
      const waited = Date.now() - start, pickedUp = Atomics.load(ctl, 5) === SLOW_MARK;
      if (!pickedUp && waited >= 20000) {
        opfsDead = true; post('[host] the OPFS bridge did not answer in 20s; /' + (opfsMount || 'root').replace(/^\//, '') + ' is unavailable (EIO) from now on\n', 2);
        // Tell the host: opfsDead is permanent for this kernel, and a warm kernel (the Python
        // REPL, the walios() tool's) used to stay EIO on every /root access until it was reaped.
        // The host retires it like a bridge that reported 'stuck' (sandpie-worker.js k.sick).
        try { self.postMessage({ t: 'bridge-dead', bridge: 'opfs', ms: waited }); } catch {}
        return { res: -E.IO, aux: 0, data: bdata };
      }
      if (pickedUp && waited >= 600000) { post('[host] an OPFS operation did not finish in 10 minutes (a cloud-only file that would not download?); EIO for this file only\n', 2); return { res: -E.IO, aux: 0, data: bdata }; }
      if (pickedUp && !warned && waited >= 20000) { warned = true; post('[host] still waiting on the OPFS bridge (downloading a cloud-only file from Dropbox?)\n', 2); }
      Atomics.wait(ctl, 1, prev, 1000);
    }
    return { res: ctl[6], aux: ctl[7], auxh: ctl[2], data: bdata };
  };
  opfsBr = { call, max: bdata.length };
  return opfsBr;
}
const inOpfs = (p) => opfsMount && (p === opfsMount || p.startsWith(opfsMount + '/'));
const opfsRel = (p) => p === opfsMount ? '' : p.slice(opfsMount.length + 1);
function opfsPathOp(op, rel, rel2) {
  const br = initOpfs(); if (!br) return -E.NOSYS;
  const pb = te.encode(rel2 !== undefined ? rel + '\0' + rel2 : rel);
  return br.call(op, pb.length, 0, 0, pb).res;
}
// A listing taken before the current run started (opfsEpoch) is always refreshed, so a
// warm kernel still sees what other kernels, the host app and the sync changed between
// runs. Within a run, refresh=false keeps a listing that still answers the lookup.
let opfsEpoch = 0;
// Drop a directory that is gone from OPFS from the VFS, with everything under it. The prune
// below used to drop a vanished directory only when it was EMPTY here, so a directory the
// host, the sync or another kernel deleted stayed listed -- children, files and all -- for
// the life of this kernel (`find` kept printing dc/a/b/c/f after `rm -rf dc/a/b` elsewhere,
// and opening it failed). Kept, as for single files: a file a process still has open (its
// handle keeps the bytes, as on Linux) and RAM-only entries; a directory stays while
// anything under it is kept. Returns true when something was kept.
// May the VFS drop an OPFS file the store no longer lists? Yes, unless a process has it open AND
// the bridge never opened it: a file created here and not written yet is not in the store until
// its first write. One the bridge HAS opened was there, so another kernel (or tab, or the sync)
// deleted or renamed it: the PATH goes, as on Linux -- open fds keep their file object, and its
// bridge id follows a rename / answers an error after a delete. Keeping the path used to leave a
// moved file listed under its old name, and re-opening that name reused the id of the moved file.
const opfsGone = (f) => f.br !== undefined && !f.pendingFrom && (!!f.brId || !opfsFileInUse(f));
// ---- link() on the mount, made cheap -------------------------------------------------------
// OPFS has no hard links, so a link is a COPY (opfs-worker OP.LINK). But git links EVERY object
// it writes (tmp_obj -> objects/xx/..., then unlinks the tmp): a copy each time made `git add`
// and commits ~30% slower than the rename git fell back to while link() was EPERM. So link()
// only records the new name as a pending alias of the source (files entry with pendingFrom),
// and the copy is made later -- unless the SOURCE is unlinked first, git's case: then the
// store file is simply renamed to the new name. Anything else that touches either name (open,
// rename, chmod, utime, truncate), a 100 ms timer, or the end of the run makes the copy.
const pendingLinks = new Map();       // new path -> { src: source file object, timer }
function linkMaterialize(pb) {        // make the pending alias pb a real store file (copy of its source)
  const pl = pendingLinks.get(pb); if (!pl) return;
  const fa = files.get(pb);
  if (!fa || fa.pendingFrom !== pl.src) { clearTimeout(pl.timer); pendingLinks.delete(pb); return; }
  const br = initOpfs();
  let ok = false;
  if (br) {
    const pbb = te.encode(pl.src.br + '\0' + opfsRel(pb));
    const r = br.call(OFS.LINK, pbb.length, 0, 0, pbb);   // may throw NeedAsync: the entry stays for the replay
    ok = r.res >= 0 || r.res === -E.EXIST;
    if (!ok) post(`[host] link: could not copy ${pb} (errno ${-r.res}); the new name is dropped\n`, 2);
    // The copy carries the mtime OPFS has for the source -- its flush time, which can be a
    // second past the write time this kernel reports for it. A hard link is one inode, so pin
    // the copy to the source's time as this kernel knows it (t7701: objects loosened from a
    // pack got the pack's time, and its link reported a second later).
    if (r.res >= 0 && fa.mtimeMs !== undefined) {
      const ms = Math.max(0, Math.round(fa.mtimeMs)), nb = te.encode(opfsRel(pb));
      try { const r2 = br.call(OFS.SETMTIME, nb.length, Math.floor(ms / 1000) | 0, ms % 1000, nb); if (r2.res >= 0) fa.opfsM = ms; } catch (_) {}
    }
  }
  clearTimeout(pl.timer); pendingLinks.delete(pb); delete fa.pendingFrom;
  if (!ok) rmEntry(pb);
}
function linkFlushFrom(f) { if (f && pendingLinks.size) for (const [pb, pl] of [...pendingLinks]) if (pl.src === f) linkMaterialize(pb); }
function linkFlushPath(p) {           // before anything changes p: settle the links it is part of
  if (!pendingLinks.size) return;
  const f = files.get(p); if (!f) return;
  if (f.pendingFrom) linkMaterialize(p);
  linkFlushFrom(f);
}
function linkTimer(pb) {
  return setTimeout(function tick() {
    try { linkMaterialize(pb); }
    catch (e) { if (e instanceof NeedAsync) e.promise.then(() => { try { linkMaterialize(pb); } catch (_) {} }); }
  }, 100);
}
function opfsDropTree(c) {
  let kept = false;
  const kids = dirs.get(c);
  if (kids) for (const n of [...kids]) {
    const cc = c + '/' + n, f = files.get(cc);
    if (f) { if (opfsGone(f)) { files.delete(cc); kids.delete(n); } else kept = true; }
    else if (dirs.has(cc)) { if (opfsDropTree(cc)) kept = true; else kids.delete(n); }
    else kids.delete(n);
  }
  if (!kept) { dirs.delete(c); opfsLoaded.delete(c); }
  return kept;
}
// force: re-read even a fresh listing, AS a refresh (getdents at the start of every
// enumeration). It used to clear the listing's stamp instead, which made the re-read look
// like a first listing -- and a first listing prunes nothing, so a file deleted mid-run
// kept showing in `ls` and still passed `[ -e ]`.
function opfsLoadDir(p, refresh = true, force = false) {   // merge one directory's OPFS listing
  const now = Date.now(), at = opfsLoaded.get(p);
  if (!force && at !== undefined && at >= opfsEpoch && (!refresh || now - at < OPFS_LIST_TTL)) return; opfsLoaded.set(p, now);
  const br = initOpfs(); if (!br) return;
  const pb = te.encode(opfsRel(p));
  let r;
  try { r = br.call(OFS.READDIR, pb.length, 0, 0, pb); }
  catch (e) { if (e instanceof NeedAsync) opfsLoaded.delete(p); throw e; }   // not listed yet: the retry must get here again
  // A failed listing used to return silently, and the directory then looked EMPTY --
  // indistinguishable from one that really has no files, which is exactly how a sync
  // problem gets misread as missing data. The realistic cause is the bridge's fixed
  // buffer: opfs-worker answers EINVAL when the JSON listing does not fit (~1MB, so
  // roughly 20k entries), and any OPFS error lands here too. Say so.
  if (r.res === -E.NOENT && p !== opfsMount) {
    // The directory is gone (not local, not in the cloud index). It used to stay in the
    // VFS as it was last seen, with a "will look empty but may not be" warning -- and
    // everything under it kept listing. Drop it like the prune does.
    if (!opfsDropTree(p)) { const parent = p.slice(0, p.lastIndexOf('/')) || '/'; const pd = dirs.get(parent); if (pd) pd.delete(p.slice(p.lastIndexOf('/') + 1)); }
    else opfsLoaded.delete(p);
    return;
  }
  if (r.res < 0) {
    // Deliberately NOT prefixed '[host]': the terminal routes those to console.debug,
    // which Chrome hides unless Verbose is enabled, so the one message that explains an
    // empty-looking directory was invisible exactly when it mattered. Without the prefix
    // it lands on the terminal itself, next to the `ls` that produced nothing.
    if (!opfsListWarned.has(p)) { opfsListWarned.add(p);
      post('walios: OPFS listing of /' + opfsRel(p) + ' failed (errno ' + (-r.res)
           + ') - this directory will look empty but may not be\n', 2); }
    opfsLoaded.delete(p);            // do not cache a failure as if it were an answer
    return;
  }
  // aux = how many of these entries exist ONLY in Dropbox and cannot be fetched
  // right now (no usable token in this tab). They ARE listed -- an empty-looking
  // directory is the worse lie -- but say once, per directory, why opening one
  // will fail, instead of leaving the guest to hit EIO file by file.
  if (r.aux > 0 && !opfsCloudWarned.has(p)) {
    opfsCloudWarned.add(p);
    post('walios: ' + r.aux + ' file(s) in /' + opfsRel(p) + ' live only in Dropbox and this tab has no'
         + ' valid token - they are listed but cannot be read; open sandpie in this browser to reconnect'
         + String.fromCharCode(10), 2);
  }
  mkdirp(p);
  const seen = new Set();
  for (const e of JSON.parse(td.decode(r.data.slice(0, r.res)))) { // slice: TextDecoder rejects SAB views
    const child = p + '/' + e.n; seen.add(e.n);
    // The entry changed KIND since we last looked (rm -rf x && echo > x elsewhere, or the
    // reverse): drop the stale one first, or the VFS held both and the directory won --
    // `cat x` said "Is a directory" about a file. Anything still open stays (see opfsDropTree).
    if (e.d) {
      if (e.p !== undefined) dirModes.set(child, e.p & 0o7777);
      const f = files.get(child);
      if (f && opfsGone(f)) files.delete(child);
      if (!files.has(child)) mkdirp(child);
    } else if (!files.has(child) && dirs.has(child) && opfsDropTree(child)) {
      continue;                        // a process still uses something under the old directory
    }
    if (e.d) continue;
    { const f = files.get(child);
      if (!f) {
        dirs.get(p).add(e.n);
        if (e.l !== undefined && e.p !== undefined && (e.p & 0o170000) === 0o120000) {   // a symlink (see opfsSymlink)
          files.set(child, { br: opfsRel(child), size: te.encode(e.l).length, mtimeMs: e.m, data: null, mode: 0o120777, sym: e.l });
          continue;
        }
        files.set(child, { br: opfsRel(child), size: e.s, mtimeMs: e.m, opfsM: e.m, data: null,
                           mode: e.p !== undefined ? (0o100000 | (e.p & 0o7777)) : opfsGuessMode(opfsRel(child)) });
      } else if (f.br !== undefined && !f.brId && e.s !== undefined) {
        // A file's stat must not change without a write: git's rm/checkout compare stat data
        // without re-reading content. So this kernel's own write keeps the mtime it gave the file
        // (the next listing only RECORDS the lastModified that write produced); a lastModified
        // other than the recorded one means another kernel, the app or the sync rewrote it.
        // (It used to adopt lastModified on every re-listing: `git add f && git rm --cached f`
        // failed 'staged content different' when a listing fell in between.)
        if (f.ownWrite) { f.opfsM = e.m; f.ownWrite = false; if (e.s !== f.size) f.size = e.s; }
        else if (e.m !== f.opfsM || e.s !== f.size) { f.size = e.s; f.mtimeMs = e.m; f.opfsM = e.m; }   // rewritten elsewhere
      }
    }
  }
  // A refresh (not the first listing): entries that are gone from OPFS -- deleted by another
  // kernel or by the sync -- leave the VFS too, unless a process still has the file open
  // (its handle keeps the bytes valid, as on Linux) or it is a RAM-only entry seeded here.
  if (at !== undefined) for (const n of [...dirs.get(p)]) {
    if (seen.has(n)) continue;
    const c = p + '/' + n, f = files.get(c);
    if (f) { if (opfsGone(f)) { files.delete(c); dirs.get(p).delete(n); } }
    else if (dirs.has(c)) { if (!opfsDropTree(c)) dirs.get(p).delete(n); }
  }
}
// Fault in listings along p (and p itself if it is a dir). A listing older than
// OPFS_LIST_TTL used to be re-read on EVERY lookup through it, so a walk that outlived
// the TTL re-listed the same directories once per entry (four `find`s over 6000 files:
// 11.8s, 7.6s after this; profiled, the kernel sat 45% inside bridge calls). Now a directory is re-listed when the
// next step of the path is not in it (something created elsewhere shows up), when it was
// never listed or was listed before this run (opfsEpoch). getdents re-reads the
// directory it enumerates regardless, so ls/find still see every change.
function opfsFault(p) {
  if (!inOpfs(p)) return;
  const segs = p === opfsMount ? [] : opfsRel(p).split('/');
  let cur = opfsMount;
  for (let i = 0; ; i++) {
    const next = i < segs.length ? cur + '/' + segs[i] : null;
    opfsLoadDir(cur, next !== null && !files.has(next) && !dirs.has(next));
    if (next === null || !(dirs.has(next) && !files.has(next))) break;
    cur = next;
  }
}
const opfsOpenFailed = new Set();
// Set by fileRead/fileWrite when the OPFS handle could not be opened (typically a
// file that is still only in Dropbox and could not be fetched). Read and cleared
// by the read/write syscalls, which turn it into EIO -- a short read of zero bytes
// is indistinguishable from an empty file, and that is exactly how "my data is
// gone" gets reported when the data is merely unreachable.
//
// It carries the bridge's real errno (0 = no error), not just "failed": everything used to
// reach the guest as EIO, so a file another worker had locked (EBUSY), one that vanished
// (ENOENT) and a full disk (ENOSPC) all read "OSError: [Errno 5] Input/output error" in
// Python, and the model retried the same call instead of acting on the cause.
let fileIoError = 0;
const ioFailed = () => { const v = fileIoError; fileIoError = 0; return v; };
// A bridge answer as the errno the guest sees. EBADF from the bridge means ITS id is gone
// (the file was unlinked/renamed under an open fd); the guest's fd is still valid, so EIO.
const ioErrno = (res) => (res < 0 && res !== -E.BADF) ? -res : E.IO;
const opfsCloudWarned = new Set();   // dirs we have already reported as holding unreachable cloud files
let opfsOpenErr = 0;                 // errno of the last failed opfsHandle (see fileIoError)
let opfsQuotaWarned = 0;             // when the download-budget note (EDQUOT) was last printed
function opfsHandle(f, create, excl) { // lazily open the per-file bridge handle
  if (f.brId) return f.brId;
  const br = initOpfs(); if (!br) { opfsOpenErr = E.IO; return 0; }
  const pb = te.encode(f.br);
  const r = br.call(OFS.OPEN, pb.length, (create ? 1 : 0) | (excl ? 2 : 0), 0, pb);
  if (r.res <= 0) {
    opfsOpenErr = ioErrno(r.res);
    // EEXIST on an exclusive create is an ANSWER, not a failure: someone holds the lock
    // (git's index.lock in another tab). The caller returns EEXIST and git says so itself.
    if (excl && r.res === -E.EXIST) return 0;
    // A failed open used to read back as ZERO BYTES -- `cat` printed nothing and
    // looked like an empty file. The realistic cause is a file that is still only
    // in the user's Dropbox (listed from the cloud index) whose download failed:
    // no token in this tab, an expired one, or no network. Say which file.
    // EDQUOT: the host's per-command download budget (>>> lean, shellfs) is spent -- grep -r or
    // find -exec over a Dropbox tree opens every file, and each cloud-only one is a download.
    // Said once per command (not once per file), naming the way that downloads nothing.
    if (r.res === -122) {
      if (Date.now() - opfsQuotaWarned > 10000) post('walios: stopped downloading Dropbox files for this command (it opened too many cloud-only files: grep -r / find over Dropbox downloads every file it reads). Use dbxsearch WORDS [FOLDER] to search names and contents without downloading, then open just the files you need.\n', 2);
      opfsQuotaWarned = Date.now();
      return 0;
    }
    if (!opfsOpenFailed.has(f.br)) {
      opfsOpenFailed.add(f.br);
      // EBUSY: the file is LOCAL and intact but a handle outside this tab's bridge holds it
      // (another tab, the app's own writer) and it is too big to work on a private copy of.
      // That used to print the cloud message below, and a whole git repo "became not a
      // repository" over it.
      if (r.res === -16) post('walios: /' + f.br + ' is locked (open in another tab or by the app) - EBUSY; retry once it is closed there\n', 2);
      else post('walios: /' + f.br + ' is in Dropbox but could not be downloaded (errno '
           + (-r.res) + ') - it is NOT empty; open sandpie in this browser to refresh the connection\n', 2);
    }
    return 0;
  }
  f.brId = r.res;
  if (f.brRel) { clearTimeout(f.brRel); f.brRel = 0; }   // reopened inside the release grace: keep the handle
  // The bridge reports the file's CURRENT size with the handle. Another kernel (the
  // terminal, the REPL, another conversation's walios()) may have rewritten the file since
  // this one listed the directory, and a read is bounded by the cached size.
  { const sz = auxBig(r); if (sz >= 0 && sz !== f.size) f.size = sz; if (sz >= 0) f.sizeAt = Date.now(); }
  return f.brId;
}
// Drop the bridge handle -- the EXCLUSIVE OPFS lock -- once no fd in any process refers to
// the file. Handles used to live until RELEASE at the end of the run (for the terminal:
// until the tab closed), so a file the shell had merely `cat`ed once stayed locked against
// the walios() tool, the Python REPL and every other conversation's kernel: EBUSY on open,
// which git reports as "not a git repository" or "unable to read <object>". A short grace
// keeps git's open/close/open churn on one object from paying a createSyncAccessHandle per
// touch, and a file reopened inside it keeps its handle (see opfsHandle).

// ---- advisory locks: fcntl record locks (POSIX + OFD) and flock ----------------
// fcntl F_SETLK/F_SETLKW/F_GETLK used to fall through to "return 0": every lock was granted,
// so nothing that relied on them (sqlite, pip/filelock, make -j jobservers, lockf in
// scripts) was ever mutually exclusive -- worse than an error. Now:
//   POSIX record locks: byte ranges, owned by the PROCESS, released when it closes ANY fd of
//     the file or exits (Linux semantics, gotchas included).
//   OFD locks (F_OFD_*) and flock(): owned by the open file description (h.off, shared by
//     dup and fork), released by LOCK_UN / F_UNLCK or when the last fd of it closes.
//   flock and fcntl locks are independent, as on Linux.
// Exact within this kernel (all its processes). Across tabs, each kernel's aggregate lock on
// an OPFS file is a Web Lock in the bridge (OFS.LOCK): whole-file, so conservative.
// Blocking variants (F_SETLKW, flock without LOCK_NB) wait in sysAsync, interruptible.
const lockTab = new Map();          // file object -> [{ kind: 'posix'|'ofd'|'flock', owner, w, start, end }]
const lockWaiters = new Set();      // resolvers woken on any unlock in this kernel
function lockWake() { const w = [...lockWaiters]; lockWaiters.clear(); for (const f of w) f('wake'); }
const lkOverlap = (a, s, e) => a.start < e && s < a.end;
// The conflicting lock for a request, or null. Same owner never conflicts; flock and fcntl
// never conflict with each other.
function lockConflict(f, kind, owner, w, s, e) {
  const L = lockTab.get(f); if (!L) return null;
  const fam = kind === 'flock' ? 'flock' : 'rec';
  for (const l of L) {
    if ((l.kind === 'flock' ? 'flock' : 'rec') !== fam) continue;
    if (l.owner === owner && l.kind === kind) continue;
    if (!(w || l.w)) continue;
    if (fam === 'flock' || lkOverlap(l, s, e)) return l;
  }
  return null;
}
// The kernel's aggregate lock on f: 2 any write lock, 1 only read locks, 0 none.
const lockAgg = (f) => { const L = lockTab.get(f); if (!L || !L.length) return 0; return L.some((l) => l.w) ? 2 : 1; };
// Tell the bridge when the aggregate changes (OPFS files only). -> errno (0 = ok)
function lockSync(f, before, after) {
  if (before === after || f.br === undefined) return 0;
  const br = initOpfs(); if (!br) return 0;
  const pb = te.encode(f.br);
  if (!after) { br.call(OFS.UNLOCK, pb.length, 0, 0, pb); return 0; }
  const r = br.call(OFS.LOCK, pb.length, after, 0, pb);
  return r.res < 0 ? -r.res : 0;
}
// Apply a lock/unlock for an owner over [s, e). Returns errno (0 = ok, EAGAIN = busy).
function lockSet(f, kind, owner, type, s, e, pid) {
  const w = type === 1, un = type === 2;
  if (!un && lockConflict(f, kind, owner, w, s, e)) return E.AGAIN;
  const L = lockTab.get(f) || [];
  // Remove this owner's locks of this kind over [s, e), splitting partial overlaps.
  const next = [];
  for (const l of L) {
    if (l.owner !== owner || l.kind !== kind || (kind !== 'flock' && !lkOverlap(l, s, e))) { next.push(l); continue; }
    if (kind === 'flock') continue;
    if (l.start < s) next.push({ ...l, end: s });
    if (l.end > e) next.push({ ...l, start: e });
  }
  if (!un) next.push({ kind, owner, w, start: s, end: e, pid });
  const before = lockAgg(f);
  const after = next.length ? (next.some((l) => l.w) ? 2 : 1) : 0;
  const err2 = lockSync(f, before, after);
  if (err2) return err2 === E.AGAIN || err2 === 11 ? E.AGAIN : err2;
  if (next.length) lockTab.set(f, next); else lockTab.delete(f);
  if (un || L.length !== next.length - (un ? 0 : 1)) lockWake();
  return 0;
}
// Drop locks matching pred (close / exit). Never fails (the bridge unlock is fire-and-forget).
function lockDrop(pred) {
  let woke = false;
  for (const [f, L] of [...lockTab]) {
    const keep = L.filter((l) => !pred(f, l));
    if (keep.length === L.length) continue;
    const before = lockAgg(f);
    if (keep.length) lockTab.set(f, keep); else lockTab.delete(f);
    lockSync(f, before, lockAgg(f));
    woke = true;
  }
  if (woke) lockWake();
}
// Is this open file description still referenced by an fd of any process?
function ofdLive(ofd) { for (const p of procs.values()) for (const h of p.fds.values()) if (h && h.off === ofd) return true; return false; }
// struct flock (musl, 64-bit off_t): short l_type @0, short l_whence @2, off_t l_start @8,
// off_t l_len @16, pid_t l_pid @24. -> { type, s, e } in absolute bytes, or null (EINVAL).
function readFlock(S, ptr, h) {
  S.refresh();
  const type = S.dv.getInt16(ptr, true), whence = S.dv.getInt16(ptr + 2, true);
  const start = Number(S.dv.getBigInt64(ptr + 8, true)), len = Number(S.dv.getBigInt64(ptr + 16, true));
  if (type < 0 || type > 2) return null;
  const base = whence === 0 ? 0 : whence === 1 ? ((h.off && h.off.v) || 0) : whence === 2 ? (h.file ? h.file.size : 0) : NaN;
  if (Number.isNaN(base)) return null;
  let s = base + start, e = len === 0 ? Infinity : s + len;
  if (len < 0) { e = s; s = s + len; }
  if (s < 0) return null;
  return { type, s, e };
}
function writeFlock(S, ptr, l) {
  S.refresh();
  if (!l) { S.dv.setInt16(ptr, 2, true); return; }                   // F_UNLCK: nothing in the way
  S.dv.setInt16(ptr, l.w ? 1 : 0, true); S.dv.setInt16(ptr + 2, 0, true);
  S.dv.setBigInt64(ptr + 8, BigInt(l.start), true);
  S.dv.setBigInt64(ptr + 16, l.end === Infinity ? 0n : BigInt(l.end - l.start), true);
  S.dv.setInt32(ptr + 24, l.kind === 'posix' ? l.pid : -1, true);
}
// One non-blocking attempt of a lock syscall. -> BigInt result (err on failure).
function lockTry(S, name, a) {
  const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
  if (!h.file) return err(E.INVAL);
  const f = h.file;
  if (name === 'flock') {
    const op = a[1] | 0, nb = op & 4, base = op & ~4;
    if (base !== 1 && base !== 2 && base !== 8) return err(E.INVAL);
    const ofd = (h.off ??= { v: 0 });
    const r = lockSet(f, 'flock', ofd, base === 8 ? 2 : base === 2 ? 1 : 0, 0, Infinity, S.selfPid);
    return r ? err(r) : 0n;
  }
  const cmd = a[1] | 0, ofdCmd = cmd >= 36 && cmd <= 38;
  const rq = readFlock(S, Number(a[2]), h); if (!rq) return err(E.INVAL);
  const kind = ofdCmd ? 'ofd' : 'posix', owner = ofdCmd ? (h.off ??= { v: 0 }) : S.selfPid;
  if (cmd === 5 || cmd === 36) {                                     // F_GETLK / F_OFD_GETLK
    writeFlock(S, Number(a[2]), rq.type === 2 ? null : lockConflict(f, kind, owner, rq.type === 1, rq.s, rq.e));
    return 0n;
  }
  const r = lockSet(f, kind, owner, rq.type, rq.s, rq.e, S.selfPid);
  return r ? err(r) : 0n;
}
// An OPFS-backed file this kernel wrote reports a kernel-clock mtime until it is settled from
// OPFS's own lastModified -- the value every other kernel lists. Done on the first stat once no
// fd holds the file: through the open bridge id (STAT, settle: the bridge closes its writer so
// lastModified is final), or, after the id was released, by re-listing the parent.
function opfsSettleMtime(f, path) {
  if (!f || !f.mtimeDirty || f.br === undefined || f.sym !== undefined || f.brId || opfsFileInUse(f)) return;
  // Still held by the bridge (inside the release grace): keep the kernel's time for now. Settling
  // through the open id (closing the writer to read a final lastModified) made every write+stat
  // pair reopen a sync handle: git status/commit ran 50-80% slower (perf-git-ab).
  if (f.brId) return;
  const parent = path.slice(0, path.lastIndexOf('/')) || '/';
  if (inOpfs(parent)) opfsLoadDir(parent, true, true);
}
function opfsFileInUse(f) { for (const p of procs.values()) for (const h of p.fds.values()) if (h && h.file === f) return true; return false; }
function opfsMaybeRelease(f) {
  if (!f || !f.brId || f.brRel) return;
  f.brRel = setTimeout(() => {
    f.brRel = 0;
    if (!f.brId || opfsFileInUse(f)) return;
    const br = initOpfs(); if (br) { try { br.call(OFS.CLOSE, f.brId, 0, 0, null); } catch {} }
    f.brId = 0;
  }, 250);
}
function fileRead(f, pos, n) {
  if (f.br !== undefined) {
    fileIoError = 0;   // only THIS call's failure: a caller that never checks (exec, mmap) must not leak one into the next read()
    const br = initOpfs(), id = opfsHandle(f); if (!id) { fileIoError = opfsOpenErr || E.IO; return new Uint8Array(0); }
    // Ask for what the caller wants, not just up to the size THIS kernel last saw: other kernels
    // (and tabs) can write a file this one holds open, so that size goes stale -- a re-read
    // after the shell rewrote a file Python had open came back cut to the old length. The
    // bridge answers each READ with the file's real size (aux = size + 1; 0 = unknown), which
    // becomes f.size once the read is done (not before: in the in-process engine a bridge call
    // can restart this syscall, and the state it computed `lim` from must not have moved).
    // `want` starts at what this kernel believes is left and follows the size the bridge
    // reports; at the believed EOF one small probe asks whether the file grew. Nothing is
    // allocated beyond what actually comes back (a 1MB-per-read buffer made 600 small reads
    // churn 1.2GB and slowed down run after run).
    let want = Math.min(n, Math.max(0, f.size - pos)), got = 0, size = -1, out = null;
    for (;;) {
      const ask = Math.min(want > got ? want - got : Math.min(n - got, 65536), br.max);
      if (ask <= 0) break;
      const r = br.call(OFS.READ, id, pos + got, ask, null);
      // A failed READ used to end the loop like EOF: the guest got a short or EMPTY read and
      // no error. Nothing read yet -> the error; something read -> that much (POSIX short read).
      if (r.res < 0) { if (!got) fileIoError = ioErrno(r.res); break; }
      { const ab = auxBig(r); if (ab > 0) { size = ab - 1; want = Math.min(n, Math.max(0, size - pos)); f.sizeAt = Date.now(); } }
      if (r.res === 0) break;
      // (a short read is not EOF: stopping there handed dlopen a truncated .so, which
      // lost its wali.abi marker at the end and was refused as the other ABI)
      if (!out) out = new Uint8Array(Math.max(want, r.res));
      else if (got + r.res > out.length) { const nb = new Uint8Array(Math.max(got + r.res, want)); nb.set(out.subarray(0, got)); out = nb; }
      out.set(r.data.subarray(0, r.res), got); got += r.res;
      if (got >= want && size >= 0) break;   // the bridge's size says there is no more
    }
    if (size >= 0) f.size = size;
    return out ? out.subarray(0, got) : new Uint8Array(0);
  }
  return f.data.subarray(pos, Math.min(pos + n, f.size));
}
function fileWrite(f, pos, bytes) {
  if (f.br !== undefined) {
    fileIoError = 0;
    const br = initOpfs(), id = opfsHandle(f, true); if (!id) { fileIoError = opfsOpenErr || E.IO; return 0; }
    let done = 0;
    while (done < bytes.length) {
      const chunk = Math.min(bytes.length - done, br.max);
      const r = br.call(OFS.WRITE, id, pos + done, chunk, bytes.subarray(done, done + chunk));
      if (r.res < 0) { if (!done) fileIoError = ioErrno(r.res); break; }   // was: a silent 0-byte write
      if (r.res === 0) break;
      done += r.res;
    }
    // (No 'settle to OPFS lastModified' afterwards: a stat that changes with no write in between
    // breaks git -- rm/checkout compare stat data WITHOUT re-reading content, so `git add f &&
    // git rm --cached f` failed 'staged content different' once the mtime moved. A file keeps
    // the mtime this kernel gave it; another tab may see OPFS's and re-read it: slower, correct.)
    f.size = Math.max(f.size, pos + done); f.mtimeMs = Date.now(); f.ownWrite = true;
    return done;
  }
  if (pos + bytes.length > f.data.length) {
    const nd = new Uint8Array(Math.max(pos + bytes.length, f.data.length * 2, 4096));
    nd.set(f.data.subarray(0, f.size)); f.data = nd;
  }
  f.data.set(bytes, pos); f.size = Math.max(f.size, pos + bytes.length); f.mtimeMs = Date.now();
  return bytes.length;
}

// ================= global kernel state =================
let nextPid = 100, syscallTotal = 0, procCount = 0;
// ---- walios monitor (stats every second while a run is live; the page draws it) ----
// CPU: every process worker keeps its own guest-running time in its control block (see
// CPU_ACC in wali-proc-worker.js); cpuLive holds the blocks being served right now, and a
// finished one is folded into P.cpuMs. kBusyMs: time this kernel thread spent inside
// syscall handlers -- one thread serves every process, so when it saturates they all slow.
const cpuLive = new Set();
let kBusyMs = 0, vfsBytesCache = 0, vfsBytesAt = 0;
const KCPU_ACC = 32, KCPU_SINCE = 33;   // f64 slots of the control block (bytes 256/264)
const nowEpoch = () => performance.timeOrigin + performance.now();
function cpuOfRec(r) { const since = r.f64[KCPU_SINCE]; return r.f64[KCPU_ACC] + (since > 0 ? Math.max(0, nowEpoch() - since) : 0); }
function vfsBytes() {
  if (Date.now() - vfsBytesAt < 5000) return vfsBytesCache;
  let n = 0; for (const f of files.values()) { const d = f.data; if (d && d.byteLength) n += d.byteLength; }
  vfsBytesAt = Date.now(); return (vfsBytesCache = n);
}
function statsSnapshot(t0) {
  const per = new Map();   // P -> { cpu, running }
  for (const r of cpuLive) {
    const e = per.get(r.P) || { cpu: 0, running: 0 };
    e.cpu += cpuOfRec(r); if (r.f64[KCPU_SINCE] > 0) e.running++;
    per.set(r.P, e);
  }
  const seen = new Set(); let mem = 0, running = 0, threads = 0;
  const list = [];
  for (const P of procs.values()) {
    const e = per.get(P) || { cpu: 0, running: 0 };
    const pm = procMemBytes(P);
    try { if (P.memory && !seen.has(P.memory)) { seen.add(P.memory); mem += pm; } } catch (_) {}
    running += e.running; threads += 1 + ((P._threads && P._threads.length) || 0);
    list.push({ pid: P.pid, comm: procComm(P), mem: pm, cpu: Math.round((P.cpuMs || 0) + e.cpu), run: e.running,
                 ...(P._threads && P._threads.length ? { thr: P._threads.map((w) => w._ph || '?').join(',') } : {}) });
  }
  let cpuLiveMs = 0; for (const r of cpuLive) cpuLiveMs += cpuOfRec(r);
  return { t: 'stats', mem, procs: procs.size, syscalls: syscallTotal, ms: performance.now() - t0,
           engine: INPROC ? 'inproc' : 'workers', cores: (self.navigator && navigator.hardwareConcurrency) || 0,
           cpuMs: cpuDoneMs + cpuLiveMs, kBusyMs, running, threads, vfs: vfsBytes(), list };
}
let cpuDoneMs = 0;
let STRACE = false;
// strace lines are BATCHED (flushed every 50ms and before the exit message): posting one
// message per syscall slowed the kernel enough to hide timing-dependent bugs -- a clone
// that failed every time ran clean under --strace. A hang still shows within 50ms.
let straceBuf = [], straceTimer = null;
function straceFlush() { if (straceTimer) { clearTimeout(straceTimer); straceTimer = null; } if (straceBuf.length) { const b = straceBuf; straceBuf = []; post(b.join(''), 2); } }
function stracePost(s) { straceBuf.push(s); if (!straceTimer) straceTimer = setTimeout(straceFlush, 50); }                  // run message `strace: true` -> every served import is logged to stderr (test harness --strace)
// A WALI syscall argument is a 64-bit `long`. An int passed through varargs (fcntl's
// FD_CLOEXEC, ioctl requests) arrives with GARBAGE in the high 32 bits; Number() of such
// a value rounds (53-bit mantissa) and `& 1` on it read FD_CLOEXEC as 0 -- git's notify
// pipe stayed open in the exec'd pack-objects and every `git push` hung after the ref
// negotiation. Anything outside the safe-integer range cannot be a pointer, size or
// offset here (memory is < 4GB), so take it as the int it is: the low 32 bits, signed.
function i64arg(x) { const n = Number(x); return Number.isSafeInteger(n) ? n : Number(BigInt.asIntN(32, x)); }
const unknownSyscalls = new Set();
const __waliWarned = new Set();
function WARN(m) { if (__waliWarned.has(m)) return; __waliWarned.add(m); post('[host] ' + m + '\n', 2); }
const modCache = new Map();   // key -> WebAssembly.Module
// WARM SPARES per module. Measured (2026-11-03): starting a process costs 8-13ms, and
// nearly all of it is the WORKER starting -- instantiating busybox inside it is 0.1-0.2ms.
// A spare is a worker already past `init`: created, module instantiated, sitting on its
// 'ready'. Taking one turns process start into a postMessage.
//
// A module that IMPORTS its memory (busybox, python and the other WALI binaries linked
// with --import-memory -- nearly every process) gets a fresh shared memory with its spare,
// made exactly as getSharedMemory() makes one, and the process adopts it (runInWorker).
// These spares used to be for modules that DEFINE their memory only, which since the
// --import-memory relinks was none of them: every process started cold.
// Fork children take spares too: the parent's memory is copied over the child's before it
// rewinds, and a spare's instance has never run, so it is the same as a cold one.
// Up to two per module, because a fork+exec takes two in a row, faster than one warms.
// A module with a big initial memory (clang) gets none: an idle spare would pin it.
const SPARE_POOL = (lim) => (!lim || lim.initial <= 160 ? 2 : 1);   // 160 pages = 10MB
const SPARE_MAX_PAGES = 512;
const spares = new Map();          // modKey -> [{ w, ctl, bulk, memory, ready, settle }]
function takeSpare(modKey) {
  const list = spares.get(modKey);
  return list && list.length ? list.shift() : null;
}
function prepareSpare(modKey, plan) {
  if (!plan || NODE_STUB_RE.test(modKey)) return;
  const mod = modCache.get(modKey);
  if (!mod) return;
  const lim = plan.memory ? (modSharedMem.get(modKey) || { initial: 256, maximum: 16384 }) : null;
  if (lim && lim.initial > SPARE_MAX_PAGES) return;
  const list = spares.get(modKey) || [];
  spares.set(modKey, list);
  while (list.length < SPARE_POOL(lim)) {
    try {
      const memory = lim ? new WebAssembly.Memory({ initial: lim.initial, maximum: lim.maximum, shared: true }) : null;
      let bulk;
      try { bulk = new SharedArrayBuffer(1 << 20, { maxByteLength: 64 << 20 }); }
      catch (_) { bulk = new SharedArrayBuffer(32 << 20); }
      const ctl = new SharedArrayBuffer(KCTL.BYTES);
      const w = new Worker('wali-proc-worker.js?v=tfork5');
      let settle;
      const ready = new Promise((res) => { settle = res; });
      const sp = { w, ctl, bulk, memory, ready, settle: (m) => settle(m) };
      // The worker is silent after 'ready' until it is told to run, so buffering one message is enough.
      w.onmessage = (ev) => { if (ev.data && ev.data.t === 'ready') settle(ev.data); };
      w.onerror = () => { settle({ ok: false, error: 'spare worker failed' }); const i = list.indexOf(sp); if (i >= 0) list.splice(i, 1); };
      w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk, memory });
      list.push(sp);
    } catch (_) { return; }
  }
}
const modSharedMem = new Map(); // key -> {initial, maximum} for a shared env.memory import (wasi-threads)
// walios-node: a process whose USERSPACE is JavaScript on the page's own V8 rather
// than a wasm guest. Everything else is identical -- same control block, same
// syscalls, same pid, same fd table -- so only the worker script differs.
// node-stub.wasm is a real WALI module declaring the syscall imports and a shared
// env.memory, purely so _workerPlan() can derive names/sigs/memory the way it does
// for any guest; the node worker never instantiates it. See walios-node-poc/.
const NODE_STUB_RE = /node-stub\.wasm/;
const NODE_WORKER_URL = '/walios-node-poc/node-proc-worker.js';
const modSigs = new Map();      // key -> Map('module.name' -> {params, results, retI64}) for the process-worker proxy

// A wasm binary's ABI from its `wali.abi` custom section ("ilp32": walios ILP32, 32-bit long;
// none: WALI's 64-bit long), read by walking the section headers -- no compile needed.
function wasmIsIlp32(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes); let p = 8;
  const uleb = () => { let r = 0, s = 0, x; do { x = b[p++]; r += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80); return r; };
  // (not TextDecoder: a big file's bytes can be a view of shared memory, which it refuses --
  // the throw used to make every large .so, numpy's _multiarray_umath, "the other ABI")
  const str = (s, e) => String.fromCharCode(...b.subarray(s, e));
  while (p < b.length) {
    const id = b[p++], len = uleb(), end = p + len;
    if (id === 0) { const n = uleb(); if (n === 8 && str(p, p + 8) === 'wali.abi') return str(p + 8, end).includes('ilp32'); }
    p = end;
  }
  return false;
}
// A side module must be built for its process's ABI: a struct or a `long` would mean two things.
function abiMismatch(proc, bytes, path) {
  const so = wasmIsIlp32(bytes);
  return so === !!proc.ilp32 ? '' : `${path} is built for ${so ? 'the walios ILP32 ABI (32-bit long)' : "WALI's 64-bit-long ABI"}, this program for ${proc.ilp32 ? 'ILP32' : 'the 64-bit-long one'}`;
}

// Parse a wasm side module's "dylink.0" custom section (MEM_INFO subsection id 1):
// how much linear memory + how many table slots it needs, so the dlopen loader can size them.
function parseDylink(mod) {
  const secs = WebAssembly.Module.customSections(mod, 'dylink.0');
  const info = { memsize: 0, memalign: 0, tablesize: 0, tablealign: 0 };
  if (!secs.length) return info;
  const b = new Uint8Array(secs[0]); let p = 0;
  const uleb = () => { let r = 0, s = 0, x; do { x = b[p++]; r |= (x & 0x7f) << s; s += 7; } while (x & 0x80); return r >>> 0; };
  while (p < b.length) { const id = b[p++], len = uleb(), end = p + len;
    if (id === 1) { info.memsize = uleb(); info.memalign = uleb(); info.tablesize = uleb(); info.tablealign = uleb(); }
    p = end; }
  return info;
}

// Parse a wasm module's import section for a SHARED memory import (wasm32-wasip1-threads
// binaries import env.memory as shared). Returns {initial, maximum} in pages, or null.
// Every imported function's signature, straight out of the binary.
//
// The process-worker proxy needs one fact per import: does it return an i64? A JS
// function imported into wasm must hand back a BigInt for an i64 result and a Number for
// an i32 one, and getting it wrong traps at the boundary. WALI is not uniform -- SYS_*
// return i64, but __cl_get_argc, __init and __cl_copy_argv return i32 and __proc_exit
// returns nothing -- and WebAssembly.Module.imports() does not report types in this
// browser, so read the type section ourselves. Verified against busybox (110 imports)
// and python_cxx (195): every imported function covered.
function parseImportSigs(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let p = 8;                                            // magic + version
  const uleb = () => { let r = 0, sh = 0, x; do { x = b[p++]; r |= (x & 0x7f) << sh; sh += 7; } while (x & 0x80); return r >>> 0; };
  const nm = () => { const n = uleb(); const t = td.decode(b.subarray(p, p + n)); p += n; return t; };
  const types = [], out = new Map();
  try {
    while (p < b.length) {
      const id = b[p++], size = uleb(), end = p + size;
      if (id === 1) {                                   // Type
        const n = uleb();
        for (let i = 0; i < n; i++) {
          if (b[p++] !== 0x60) { p = end; break; }
          const np = uleb(), params = []; for (let k = 0; k < np; k++) params.push(b[p++]);
          const nr = uleb(), results = []; for (let k = 0; k < nr; k++) results.push(b[p++]);
          types.push({ params, results });
        }
      } else if (id === 2) {                            // Import
        const n = uleb();
        for (let i = 0; i < n; i++) {
          const mod = nm(), name = nm(), kind = b[p++];
          if (kind === 0) { const t = types[uleb()] || { params: [], results: [] };
            out.set(mod + '.' + name, { params: t.params, results: t.results,
                                        retI64: t.results.length === 1 && t.results[0] === 0x7e }); }
          else if (kind === 1) { p++; const fl = b[p++]; uleb(); if (fl & 1) uleb(); }
          else if (kind === 2) { const fl = b[p++]; uleb(); if (fl & 1) uleb(); }
          else if (kind === 3) { p++; p++; }
        }
        return out;                                     // imports precede everything else
      }
      p = end;
    }
  } catch (e) { post('[host] parseImportSigs failed: ' + (e.message || e) + '\n', 2); }
  return out;
}

function parseSharedMemImport(bytes) {
  try {
    let p = 8; // magic + version
    const u = () => { let x = 0, s = 0, b; do { b = bytes[p++]; x |= (b & 0x7f) << s; s += 7; } while (b & 0x80); return x >>> 0; };
    while (p < bytes.length) {
      const id = bytes[p++]; const size = u(); const end = p + size;
      if (id === 2) {
        const n = u();
        for (let i = 0; i < n; i++) {
          const ml = u(); p += ml; const nl = u(); p += nl; const kind = bytes[p++];
          if (kind === 0) { u(); }                                   // func: typeidx
          else if (kind === 1) { p++; const f = bytes[p++]; u(); if (f & 1) u(); } // table
          else if (kind === 2) { const f = bytes[p++]; const min = u(); let max = null; if (f & 1) max = u();
            if (f & 2) return { initial: min, maximum: max ?? min }; } // shared memory
          else if (kind === 3) { p++; }                              // global
        }
      }
      p = end;
    }
  } catch {}
  return null;
}

// ---- load-time fixes: link options the kernel needs, applied to the binary itself ----
// Two link options decide whether walios can give a guest Linux behaviour, and a binary
// built without them used to get a warning and a DIFFERENT behaviour instead:
//  - --export-table: a signal handler is a function-table index, and the kernel can only
//    call it through an exported __indirect_function_table. Without the export every
//    handler fell back to the default action (alarm+pause killed instead of woken).
//  - --import-memory: a thread is a second instance of the module on the SAME memory, so
//    a module that defines its own memory could never have threads (pthread_create EAGAIN).
// Both are pure container edits -- an extra export entry; a memory moved from the memory
// section to an env.memory import (one memory: index 0 either way, so no instruction or
// data segment changes) -- so do them here rather than ask every binary to be relinked.
// Only where they change behaviour: the table for a WALI guest that defines one and does
// not export it, the memory for a guest that defines one AND imports a thread spawn.
function walifyModule(bytes) {
  try {
    const rd = (b, q) => { let r = 0, s = 0, c; do { c = b[q++]; r |= (c & 0x7f) << s; s += 7; } while (c & 0x80); return [r >>> 0, q]; };
    const leb = (v) => { const o = []; do { let c = v & 0x7f; v >>>= 7; if (v) c |= 0x80; o.push(c); } while (v); return o; };
    const str = (s) => { const b = new TextEncoder().encode(s); return [...leb(b.length), ...b]; };
    const secs = []; let p = 8;
    while (p < bytes.length) { const id = bytes[p]; const [size, q] = rd(bytes, p + 1); secs.push({ id, body: bytes.subarray(q, q + size) }); p = q + size; }
    // imports: which modules, a thread spawn, an imported table/memory
    let wali = false, spawn = false, tableImported = false;
    const imp = secs.find((s) => s.id === 2);
    if (imp) {
      const b = imp.body; let [n, q] = rd(b, 0);
      for (let i = 0; i < n; i++) {
        let l; [l, q] = rd(b, q); const mod = new TextDecoder().decode(b.subarray(q, q + l)); q += l;
        [l, q] = rd(b, q); const nm = new TextDecoder().decode(b.subarray(q, q + l)); q += l;
        const kind = b[q++];
        if (mod === 'wali') wali = true;
        if (nm === '__wasm_thread_spawn' || nm === 'thread-spawn') spawn = true;
        if (kind === 0) [, q] = rd(b, q);
        else if (kind === 1) { tableImported = true; q++; const f = b[q++]; [, q] = rd(b, q); if (f & 1) [, q] = rd(b, q); }
        else if (kind === 2) { const f = b[q++]; [, q] = rd(b, q); if (f & 1) [, q] = rd(b, q); }
        else if (kind === 3) q += 2;
        else if (kind === 4) { q++; [, q] = rd(b, q); }
        else return bytes;                                       // unknown import kind: leave it alone
      }
    }
    const tab = secs.find((s) => s.id === 4), memSec = secs.find((s) => s.id === 5);
    let exp = secs.find((s) => s.id === 7);
    const exportNames = new Set();
    if (exp) { const b = exp.body; let [n, q] = rd(b, 0);
      for (let i = 0; i < n; i++) { let l; [l, q] = rd(b, q); exportNames.add(new TextDecoder().decode(b.subarray(q, q + l))); q += l; q++; [, q] = rd(b, q); } }
    const wantTable = wali && !tableImported && tab && rd(tab.body, 0)[0] >= 1 && !exportNames.has('__indirect_function_table');
    const wantMem = spawn && memSec && rd(memSec.body, 0)[0] === 1;
    if (!wantTable && !wantMem) return bytes;
    if (wantTable) {                                             // export table 0
      const entry = [...str('__indirect_function_table'), 0x01, 0x00];
      if (exp) { const [n, q] = rd(exp.body, 0); exp.body = new Uint8Array([...leb(n + 1), ...exp.body.subarray(q), ...entry]); }
      else { exp = { id: 7, body: new Uint8Array([...leb(1), ...entry]) };
        const at = secs.findIndex((s) => s.id >= 8 && s.id <= 12);   // start/elem/datacount/code/data follow export; tag (13) precedes it
        secs.splice(at < 0 ? secs.length : at, 0, exp); }
    }
    if (wantMem) {                                               // defined memory -> shared env.memory import
      const lim = memSec.body.subarray(rd(memSec.body, 0)[1]);
      let f = lim[0]; let [min, q] = rd(lim, 1); let max = (f & 1) ? rd(lim, q)[0] : null;
      if (!(f & 2)) { if (max === null || max > 32768) max = Math.max(min, 32768); f = 3; }   // a shared memory needs a maximum
      const entry = [...str('env'), ...str('memory'), 0x02, f, ...leb(min), ...(f & 1 ? leb(max) : [])];
      if (imp) { const [n, q2] = rd(imp.body, 0); imp.body = new Uint8Array([...leb(n + 1), ...imp.body.subarray(q2), ...entry]); }
      else { const at = secs.findIndex((s) => s.id > 2 && s.id !== 0); secs.splice(at < 0 ? secs.length : at, 0, { id: 2, body: new Uint8Array([...leb(1), ...entry]) }); }
      secs.splice(secs.indexOf(memSec), 1);
    }
    const parts = [bytes.subarray(0, 8)];
    for (const s of secs) parts.push(new Uint8Array([s.id, ...leb(s.body.length)]), s.body);
    const out = new Uint8Array(parts.reduce((a, x) => a + x.length, 0)); let o = 0;
    for (const x of parts) { out.set(x, o); o += x.length; }
    return WebAssembly.validate(out) ? out : bytes;             // never hand the guest a broken module
  } catch (_) { return bytes; }
}
// Compile a guest module and record what the process workers need from its bytes.
function compileGuest(key, bytes) {
  const b = walifyModule(bytes);
  modCache.set(key, new WebAssembly.Module(b));
  modSigs.set(key, parseImportSigs(b));
  const sm = parseSharedMemImport(b); if (sm) modSharedMem.set(key, sm);
}

// ---- process model ----
// Every process runs on its OWN worker (wali-proc-worker.js) and proxies each host
// import to this kernel over a SharedArrayBuffer; this thread is a never-blocked
// syscall server, so a parked guest blocks nothing else and pipelines run in parallel.
// Names in BLOCKING may park the caller: they run through the async implementations in
// sysAsync while the kernel keeps serving everyone else. (This used to be one of three
// engines; the other two -- and the SAB bridges that existed only to feed a parked
// kernel -- are gone.)
const KSPIN_MS = 0.02;   // _serve: poll this long for a process's next request before waitAsync (see there)
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'select', 'pselect6', 'epoll_wait', 'epoll_pwait', 'nanosleep', 'clock_nanosleep', 'execve', 'recvmsg', 'recvfrom', 'pause', 'sigsuspend', 'rt_sigsuspend', 'accept', 'accept4', 'futex']);
// fcntl/flock park only when they wait for a lock (F_SETLKW / F_OFD_SETLKW, flock without
// LOCK_NB). Routing EVERY fcntl through sysAsync cost git ~10% (it calls F_GETFD/F_SETFD on
// nearly every open): measured with tests/walios/perf-git-ab.mjs.
const argI32 = (x) => Number(typeof x === 'bigint' ? BigInt.asIntN(32, x) : x) | 0;
const lockWaits = (name, a) => name === 'fcntl' ? (argI32(a[1]) === 7 || argI32(a[1]) === 38)
  : name === 'flock' ? ((argI32(a[1]) & 4) === 0 && (argI32(a[1]) & ~4) !== 8) : false;
const isBlocking = (name, a) => BLOCKING.has(name) || ((name === 'fcntl' || name === 'flock') && lockWaits(name, a));
// Binaries linked against the OLDER wali-musl, whose fork() is plain musl _Fork(): it
// expects the syscall itself to return twice, which only Asyncify can do here. Without
// it the vfork protocol below would hand such a binary a pid it never treats as "run
// the child branch now", and it would then block forever on its own pipes -- so answer
// ENOSYS instead (python raises OSError at once). Everything built with the current
// toolchain carries the fork() macro and never hits this. A CPython rebuilt against the
// current wali-musl exports __wali_fork_begin and is let through (Process.forkMacro).
const PLAIN_MUSL_FORK = /python/i;
const inflight = new Set();   // live child task promises
// Process-worker control block. Mirrored in wali-proc-worker.js -- change both.
// i32[4]/i32[5] carry a handler address + signal number for KCTL.SIGNAL. 16 argument
// slots (i64 each) at ARGS: WASI path_open takes 9 and the block used to hold 8, so the
// 9th -- the OUT pointer for the opened fd -- was dropped and the fd landed at address 0.
const KCTL = { BYTES: 512, ARGS: 64, RET: 192, MAXARGS: 16, IDLE: 0, REQ: 1, REPLY: 2, DONE: 3, DIE: 4, FORKED: 5,
               SIGNAL: 6, SIGDONE: 7 };
// ---- engine selection ----
// Per-process workers need SharedArrayBuffer, i.e. a cross-origin isolated page. Without
// it (the Android system WebView never grants isolation, whatever headers it gets) every
// process runs on this thread instead, with JSPI suspending the guest at blocking
// syscalls: Process.runInProc. The run message's `engine: 'inproc'` forces that engine on
// an isolated page too (how the tests exercise it).
const INPROC_AVAILABLE = typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function';
let INPROC = typeof SharedArrayBuffer !== 'function';
const QUANTUM_MS = 10;          // in-process engine: longest run between event-loop yields
const INPROC_ASYNC_PAGES = 16;  // 1MB Asyncify unwind buffer, as in wali-proc-worker.js
// stdin: the page posts {t:'stdin'} chunks; a blocked read waits in sysAsync
let stdinChunks = [], stdinEOF = false, stdinWaiters = [];
let winRows = 24, winCols = 80; // terminal size (set by the page's {t:'winsize'} message)
function pushStdin(u8) { stdinChunks.push(u8); const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); }
function concatU8(arr) { let n = 0; for (const a of arr) n += a.length; const o = new Uint8Array(n); let k = 0; for (const a of arr) { o.set(a, k); k += a.length; } return o; }
function drainStdinAsync(max) { if (stdinChunks.length) { let b = concatU8(stdinChunks); const take = b.subarray(0, max); const rest = b.subarray(take.length); stdinChunks = rest.length ? [rest.slice()] : []; return take.slice(); } if (stdinEOF) return new Uint8Array(0); return null; }
let manifest = {};            // basename -> module key (url)
const pkgAdded = new Set();
const pkgAddedMsgs = new Map();   // name -> the add-pkg message, so a VM snapshot can bring the package back (vm-snapshot)   // names `apk add` registered mid-session: they outrank a busybox applet (see resolveExec)
function resolveModuleKey(p, selfKey) {
  if (p === '/proc/self/exe') return selfKey;
  const base = p.slice(p.lastIndexOf('/') + 1);
  for (const k of Object.keys(manifest)) {
    if (base === k || (k.endsWith('*') && base.startsWith(k.slice(0, -1)))) return manifest[k];
  }
  return null;
}
// ---- pseudo-terminals (module-level; master in parent, slave in child) ----
const ptys = new Map(); let nextPtyId = 0;
const ICANON = 0x2, ECHO = 0x8, ISIG = 0x1, ICRNL = 0x100, OPOST = 0x1, ONLCR = 0x4;
function defaultTermios() { const t = new Uint8Array(60); const dv = new DataView(t.buffer);
  dv.setUint32(0, ICRNL | 0x400, true); dv.setUint32(4, OPOST | ONLCR, true);
  dv.setUint32(8, 0xbf, true); dv.setUint32(12, ISIG | ICANON | ECHO | 0x10, true);
  // c_cc @17: VINTR=^C, VQUIT=^\, VERASE=DEL, VKILL=^U, VEOF=^D, VMIN=1, VSUSP=^Z
  t[17] = 3; t[18] = 28; t[19] = 127; t[20] = 21; t[21] = 4; t[23] = 1; t[27] = 26; return t; }
function newPty() { const id = nextPtyId++; ptys.set(id, { toSlave: [], toMaster: [], line: [], termios: defaultTermios(), rows: winRows, cols: winCols, pgrp: 0, slaveWaiters: [], masterWaiters: [] }); return id; }
function wakePty(list) { if (list && list.length) { const w = list.splice(0); for (const f of w) f(); } }
function ptyStatObj(id, master) { return { size: 0, mode: 0o020620, nlink: 1, uid: 1000, gid: 5, dev: 6, ino: master ? 2 : 1000 + id, rdev: master ? ((5 << 8) | 2) : ((136 << 8) | id) }; }
const tflag = (p, off) => new DataView(p.termios.buffer).getUint32(off, true);
let termPty = null; // pty-terminal mode: the root shell runs on this pty; master <-> page
function pumpTerm(p) { // flush a terminal pty's master-side bytes to the page (screen)
  if (termPty === null || ptys.get(termPty) !== p || !p.toMaster.length) return;
  self.postMessage({ t: 'out', fd: 1, s: td.decode(Uint8Array.from(p.toMaster)) }); p.toMaster.length = 0;
}
function ptyMasterWrite(p, bytes) { const lf = tflag(p, 12), canon = lf & ICANON, echo = lf & ECHO, icrnl = tflag(p, 0) & ICRNL;
  const isig = lf & ISIG;
  for (let c of bytes) {
    if (isig && c && (c === p.termios[17] || c === p.termios[18] || c === p.termios[27])) { // VINTR (^C) / VQUIT (^\) / VSUSP (^Z)
      const sig = c === p.termios[17] ? SIG.INT : c === p.termios[18] ? SIG.QUIT : SIG.TSTP;
      p.line = [];
      if (echo) p.toMaster.push(94, 64 + (c & 31)); // echo ^C / ^\ / ^Z
      if (p.pgrp) signalPgrp(p.pgrp, sig);
      else if (p.fg) postSignal(p.fg, sig);
      continue;
    }
    if (canon) {
      if (c && c === p.termios[21]) { // VEOF (^D): flush the pending line; on an empty line, queue EOF (read returns 0)
        if (p.line.length) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
        else p.slaveEof = (p.slaveEof || 0) + 1;
        wakePty(p.slaveWaiters); continue;
      }
      if (c === 0x7f || c === 0x08) { if (p.line.length) { p.line.pop(); if (echo) p.toMaster.push(8, 32, 8); } continue; }
      if (c === 0x0d && icrnl) c = 0x0a; p.line.push(c);
      // Echo is OUTPUT: it goes through OPOST/ONLCR. Pushing the raw byte sent a bare
      // LF for Enter, so the cursor dropped a row and kept its column -- every line a
      // program read in canonical mode (git's "Username for ...:" prompt) came back
      // indented by the length of the prompt.
      if (echo) { if (c === 0x0a && (tflag(p, 4) & OPOST) && (tflag(p, 4) & ONLCR)) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); }
      if (c === 0x0a) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
    } else { p.toSlave.push(c); if (echo) p.toMaster.push(c); } }
  if (p.toSlave.length) wakePty(p.slaveWaiters); if (p.toMaster.length) wakePty(p.masterWaiters); pumpTerm(p); }
function ptySlaveWrite(p, bytes) { const of = tflag(p, 4), onlcr = (of & OPOST) && (of & ONLCR);
  for (const c of bytes) { if (onlcr && c === 0x0a) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); }
  if (p.toMaster.length) wakePty(p.masterWaiters); pumpTerm(p); }

// writers/readers are refcounts (bumped on fork/dup of an end, dropped on close);
// a reader on an empty pipe waits (in sysAsync) until a write wakes it or the
// last writer closes (writers==0 => EOF). readWaiters holds suspend resolvers.
function mkPipe() { return { chunks: [], writers: 1, readers: 1, readWaiters: [] }; }
// Named pipes (mkfifo / mknod S_IFIFO). The node is a VFS file with f.fnode; every open of it
// shares ONE pipe (fnode.pipe) until all its ends are closed, then the next open starts a
// fresh one (unread data is dropped, as on Linux). Linux blocks open() until the other side
// arrives; here open() returns at once and the same thing is seen at the next step instead:
// a reader WAITS (not EOF) until a writer has connected, and a writer's data is kept until a
// reader comes (no EPIPE before any reader ever opened). git's test-lib (git daemon output)
// and every shell script that mkfifo's a pipe between two jobs depend on that.
const fifoEOF = (f) => f.writers <= 0 && !(f.named && !f.hadWriter);       // read() would see end-of-file
const fifoNoReader = (f) => f.readers <= 0 && !(f.named && !f.hadReader);  // write() would see EPIPE
function fifoDrop(h) {                     // one end of h's pipe closed
  const f = h.fifo;
  if (h.end === 'w') { if (--f.writers <= 0) wakePipe(f); } else if (h.end === 'r') f.readers--;
  // All ends closed: the next open starts afresh -- unless a writer left data no reader has
  // seen yet (on Linux that writer would still sit in open() until a reader came).
  if (f.named && f.readers <= 0 && f.writers <= 0 && f.node && f.node.pipe === f && !(f.chunks.length && !f.hadReader)) f.node.pipe = null;
}
function fifoOpen(f, acc) {                // an open() of a named pipe node: the handle's fifo/end
  const node = f.fnode;
  if (!node.pipe) { node.pipe = { chunks: [], writers: 0, readers: 0, readWaiters: [], named: true, hadWriter: false, hadReader: false, node }; }
  const pp = node.pipe;
  if (acc === 1) { pp.writers++; pp.hadWriter = true; wakePipe(pp); return { fifo: pp, end: 'w' }; }
  pp.readers++; pp.hadReader = true;
  if (acc === 2) { pp.writers++; pp.hadWriter = true; return { fifo: pp, end: 'r', alsoW: true }; }   // O_RDWR: both ends (Linux allows it on a FIFO)
  return { fifo: pp, end: 'r' };
}
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
// Free every loopback listener (localListeners) that no live process holds a socket of any
// more. close() freed the port only for an UNSHARED fd, and a process killed or exiting with
// its listener open never freed it: git daemon (its socket shared with each forked child)
// was stopped and could not listen again -- "Address in use" (git's t5570 restarts it).
// Deferred a turn, so the exiting process has left `procs` by then.
let listenerSweepQueued = false;
function listenerSweepSoon() {
  if (listenerSweepQueued || !localListeners.size) return;
  listenerSweepQueued = true;
  setTimeout(() => {
    listenerSweepQueued = false;
    const held = new Set();
    for (const P of procs.values()) {
      if (P._dead !== undefined) continue;
      try { for (const h of P.fds.values()) if (h && h.sock && h.sock.local) held.add(h.sock.local); } catch (_) {}
    }
    for (const [port, L] of [...localListeners]) if (!held.has(L)) localListeners.delete(port);
  }, 0);
}
function releaseFds(fdMap) { for (const h of fdMap.values()) {
  if (h && h.sock && h.sock.listener) listenerSweepSoon();
  if (h && h.fifo) { fifoDrop(h); if (h.alsoW) fifoDrop({ fifo: h.fifo, end: 'w' }); }
  else if (h && h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; }
  else if (h && h.file && h.file.brId) opfsMaybeRelease(h.file); } }   // a process that exits with files open
function wakeWaiters(S) { if (S.waitWaiters.length) { const w = S.waitWaiters; S.waitWaiters = []; for (const f of w) f(); } }
// execve: drop close-on-exec fds from the image's table (POSIX). Pipe ends must
// release their refcount or the reader never sees EOF (writers stays high).
function execDropCloexec(fdMap) {
  for (const [fd, h] of [...fdMap]) if (h && h.cloexec) {
    if (h.sock && h.sock.listener) listenerSweepSoon();
    if (h.fifo) { fifoDrop(h); if (h.alsoW) fifoDrop({ fifo: h.fifo, end: 'w' }); }
    else if (h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; }
    fdMap.delete(fd);
  }
  return fdMap;
}

// ---- signals (mirror of the node host): per-process handlers/mask/pending;
// delivery at syscall boundaries; handlers invoked via the exported function
// table (--export-table --table-base=16), else default action. ----
const SIG = { HUP:1, INT:2, QUIT:3, ILL:4, ABRT:6, KILL:9, USR1:10, SEGV:11, USR2:12, PIPE:13, ALRM:14, TERM:15, CHLD:17, CONT:18, STOP:19, TSTP:20, TTIN:21, TTOU:22, URG:23, WINCH:28 };
const SIG_DFL_IGNORE = new Set([SIG.CHLD, SIG.CONT, SIG.URG, SIG.WINCH]);
// SIGNAL DISPOSITION SENTINELS. In THIS ABI a handler is a FUNCTION-TABLE INDEX, so the
// only non-handler values are SIG_DFL (0) and SIG_IGN (-2, i.e. 0xFFFFFFFE unsigned).
// Measured in-guest: a real handler printed as pointer 1, SIG_IGN as 4294967294, SIG_DFL 0.
//
// The old code also treated ptr === 1 as SIG_IGN, "classic ABI". That is WRONG here: index
// 1 is the FIRST function in the table, which is exactly where a small program's handler
// lands -- so its signals were silently dropped. It cost nothing visible in the shell
// (busybox's handlers sit at high indices) and everything in configure, whose test
// programs are one function long: OpenSSH's `SA_RESTARTed signals interrupt select()`
// check parks in select(NULL) waiting for an alarm that the kernel discarded, so every
// OpenSSH build hung there forever rather than being slow.
const isSigIgn = (ptr) => ptr === -2 || ptr === 0xFFFFFFFE;
const isSigHandler = (ptr) => !!ptr && !isSigIgn(ptr);          // 0 = SIG_DFL
const SIG_STOPPERS = new Set([SIG.STOP, SIG.TSTP, SIG.TTIN, SIG.TTOU]);
// SysV shared memory: host-side buffers, snapshot in/out at attach/detach (see node host)
const shmSegs = new Map(), shmById = new Map(); let nextShmId = 1;
const procs = new Map();             // live pid -> Process (kill routing)
// ZOMBIES: an exited child its parent has not wait()ed for yet. Linux keeps such a pid
// (in its process group) until it is reaped; here the Process left procs the moment it
// exited, so getpgid(pid), kill(pid, 0) and kill(-pgid, ...) on a finished-but-unreaped
// child said ESRCH -- os.getpgid() after a quick posix_spawn raised ProcessLookupError.
// pid -> { ppid, pgid }; cleared by wait4 and, like init reaping orphans, when the parent
// itself exits. A parent ignoring SIGCHLD gets none (Linux auto-reaps those).
const zombies = new Map();
// ---- /proc ------------------------------------------------------------------------
// A read-only view of THIS kernel's process table, generated at open/stat time; nothing
// is stored in the VFS. There was no /proc at all, so busybox ps/pgrep/pkill/top had
// nothing to read and printed empty tables. What it holds, per process: stat, status,
// cmdline, comm, environ, statm, cwd/exe links and fd/; plus the global uptime, loadavg,
// meminfo (the same numbers sysinfo reports), cpuinfo, stat, version, mounts.
// Honest gaps: CPU times are 0 (a guest runs on its own worker; the kernel cannot measure
// its CPU), every process but the caller reads as sleeping, zombies are not listed.
const KSTART = Date.now();                    // kernel boot (uptime, process start times)
const isProcPath = (p) => p === '/proc' || p.startsWith('/proc/');
const PROC_PID_FILES = ['cmdline', 'comm', 'environ', 'stat', 'statm', 'status'];
const PROC_FILES = ['cpuinfo', 'loadavg', 'meminfo', 'mounts', 'stat', 'uptime', 'version'];
const procComm = (P) => P.comm || String((P.argv && P.argv[0]) || '?').split('/').pop().slice(0, 15);   // comm: prctl(PR_SET_NAME)
// The CPU count is what sched_getaffinity reports (1), so nproc, os.cpu_count() and
// /proc/cpuinfo agree. Raising it would make `make -j$(nproc)` start one clang per core.
const PROC_CPUS = 1;
const procUid = (P) => (P.cred && P.cred.euid) || 0;
function procFdTarget(h) {
  return h.pty !== undefined ? (h.master ? '/dev/ptmx' : '/dev/pts/' + h.pty) : h.path ? h.path : h.std !== undefined ? '/dev/tty'
       : (h.fifo || h.spair) ? 'pipe:[' + inoOf(h.fifo || h.spair) + ']' : h.sock ? 'socket:[' + inoOf(h.sock) + ']' : '/dev/null';
}
function procMemBytes(P) { try { return P.memory ? P.memory.buffer.byteLength : 0; } catch (_) { return 0; } }
function procText(S, P, name) {
  const pid = P.pid, mem = procMemBytes(P), ticks = (ms) => Math.max(0, Math.round((ms - KSTART) / 10));   // HZ = 100
  const state = P === S ? 'R' : 'S', comm = procComm(P), uid = procUid(P), gid = (P.cred && P.cred.egid) || 0;
  switch (name) {
    case 'stat': return `${pid} (${comm}) ${state} ${P.ppid || 0} ${P.pgid || pid} ${P.sid || pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 ${ticks(P.startMs || KSTART)} ${mem} ${Math.ceil(mem / 4096)} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n`;
    case 'statm': { const pg = Math.ceil(mem / 4096); return `${pg} ${pg} 0 0 0 ${pg} 0\n`; }
    case 'status': return `Name:\t${comm}\nUmask:\t${('000' + (P.umask ?? 0o22).toString(8)).slice(-4)}\nState:\t${state === 'R' ? 'R (running)' : 'S (sleeping)'}\n`
      + `Tgid:\t${pid}\nPid:\t${pid}\nPPid:\t${P.ppid || 0}\nTracerPid:\t0\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\nGid:\t${gid}\t${gid}\t${gid}\t${gid}\n`
      + `FDSize:\t${Math.max(64, P.nextFd || 0)}\nVmSize:\t${mem >> 10} kB\nVmRSS:\t${mem >> 10} kB\nThreads:\t${1 + ((P._threads && P._threads.length) || 0)}\n`;
    case 'cmdline': return (P.argv || []).map((a) => a + '\0').join('');
    case 'comm': return comm + '\n';
    case 'environ': return (P.env || []).map((e) => e + '\0').join('');
  }
  return '';
}
function procGlobalText(name) {
  const up = (Date.now() - KSTART) / 1000, n = procs.size, cpus = PROC_CPUS;
  switch (name) {
    case 'uptime': return `${up.toFixed(2)} ${(up * cpus).toFixed(2)}\n`;
    case 'loadavg': return `0.00 0.00 0.00 1/${n} ${nextPid - 1}\n`;
    case 'meminfo': return 'MemTotal:        4194304 kB\nMemFree:         2097152 kB\nMemAvailable:    2097152 kB\nBuffers:               0 kB\nCached:                0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n';
    case 'cpuinfo': return Array.from({ length: cpus }, (_, i) => `processor\t: ${i}\nmodel name\t: WebAssembly (walios)\ncpu MHz\t\t: 0.000\nbogomips\t: 0.00\n\n`).join('');
    case 'stat': return `cpu  0 0 0 0 0 0 0 0 0 0\n${Array.from({ length: cpus }, (_, i) => `cpu${i} 0 0 0 0 0 0 0 0 0 0\n`).join('')}intr 0\nctxt 0\nbtime ${Math.floor(KSTART / 1000)}\nprocesses ${nextPid - 100}\nprocs_running 1\nprocs_blocked 0\n`;
    case 'version': return 'Linux version 6.1.0-wali (walios) #1 WALI-browser\n';
    case 'mounts': return 'rootfs / rootfs rw 0 0\nproc /proc proc ro 0 0\n'
      + (opfsMount ? `opfs ${opfsMount} opfs rw 0 0\n` : '') ;
  }
  return '';
}
// Resolve a /proc path for process S. Returns null (no such entry) or one of
//   { kind: 'dir', path, names: Map(name -> 'dir'|'file'|'link'), uid }
//   { kind: 'file', path, text, uid }   { kind: 'link', path, target }
//   { kind: 'redirect', path }          -- leaves /proc (cwd/... or a followed link): resolve normally
function procNode(S, p, follow = true) {
  const segs = p.split('/').filter(Boolean);
  if (segs[0] !== 'proc') return null;
  if (segs[1] === 'self' || segs[1] === 'thread-self') {
    const target = '/proc/' + S.pid;
    if (segs.length === 2 && !follow) return { kind: 'link', path: p, target: String(S.pid) };
    return procNode(S, target + (segs.length > 2 ? '/' + segs.slice(2).join('/') : ''), follow);
  }
  if (segs.length === 1) {
    const names = new Map([['self', 'link'], ['thread-self', 'link']]);
    for (const pid of [...procs.keys()].sort((a, b) => a - b)) names.set(String(pid), 'dir');
    for (const f of PROC_FILES) names.set(f, 'file');
    return { kind: 'dir', path: '/proc', names, uid: 0 };
  }
  if (!/^\d+$/.test(segs[1])) {
    if (segs.length === 2 && PROC_FILES.includes(segs[1])) return { kind: 'file', path: p, text: procGlobalText(segs[1]), uid: 0 };
    return null;
  }
  const P = procs.get(+segs[1]); if (!P) return null;
  const base = '/proc/' + P.pid, uid = procUid(P);
  if (segs.length === 2) {
    const names = new Map([['cwd', 'link'], ['exe', 'link'], ['fd', 'dir']]);
    for (const f of PROC_PID_FILES) names.set(f, 'file');
    return { kind: 'dir', path: base, names, uid };
  }
  const leaf = segs[2], rest = segs.slice(3);
  const link = (target, more) => {
    if (more.length) return target.startsWith('/') ? { kind: 'redirect', path: target.replace(/\/$/, '') + '/' + more.join('/') } : null;
    if (!follow) return { kind: 'link', path: p, target };
    return target.startsWith('/') ? (isProcPath(target) ? procNode(S, target, true) : { kind: 'redirect', path: target }) : null;   // pipe:[..] cannot be opened by path
  };
  if (PROC_PID_FILES.includes(leaf)) return rest.length ? null : { kind: 'file', path: p, text: procText(S, P, leaf), uid };
  if (leaf === 'cwd') return link((P.cwd && P.cwd.p) || '/', rest);
  if (leaf === 'exe') return rest.length ? null : link('/bin/' + String((P.argv && P.argv[0]) || 'wasm').split('/').pop(), []);
  if (leaf === 'fd') {
    const fds = P.fds;
    if (!rest.length) { const names = new Map(); for (const k of [...fds.keys()].sort((a, b) => a - b)) names.set(String(k), 'link'); return { kind: 'dir', path: base + '/fd', names, uid }; }
    const h = /^\d+$/.test(rest[0]) ? fds.get(+rest[0]) : null; if (!h) return null;
    return link(procFdTarget(h), rest.slice(1));
  }
  return null;
}
function procStat(n) {
  if (n.kind === 'dir') return { size: 0, mode: 0o040555, uid: n.uid, gid: n.uid, ino: inoOf(n.path), nlink: 2 };
  if (n.kind === 'link') return { size: n.target.length, mode: 0o120777, uid: 0, gid: 0, ino: inoOf(n.path) };
  return { size: 0, mode: 0o100444, uid: n.uid, gid: n.uid, ino: inoOf(n.path) };
}
// unlink / rmdir on a resolved path (the bodies of the syscalls; unlinkat shares them).
function unlinkPath(S, p) {
  pyTreeTouch(p);
  if (isProcPath(p)) return err(E.ACCES);
  // Linux: unlink() of a directory is EISDIR, not ENOENT (Python's os.remove, Git's
  // remove-or-rmdir fallbacks all branch on it).
  opfsFault(p); if (!files.has(p)) return err(dirs.has(p) ? E.ISDIR : E.NOENT);
  if (protectedDelete(S, p)) return err(E.PERM);
  const f = files.get(p);
  if (f.nlinkRef && f.nlinkRef.n > 1) f.nlinkRef.n--;   // one name fewer (st_nlink)
  if (f.pendingFrom) {                       // a pending link alias: never stored, nothing to delete
    const pl = pendingLinks.get(p); if (pl) { clearTimeout(pl.timer); pendingLinks.delete(p); }
    rmEntry(p); return 0n;
  }
  if (f.br !== undefined && pendingLinks.size) {
    // The source of pending links goes: the store file is RENAMED to the first new name
    // (git's link-then-unlink of every object) instead of copied and deleted.
    const heirs = [...pendingLinks].filter(([, pl]) => pl.src === f);
    if (heirs.length && !opfsFileInUse(f)) {
      const [pb0, pl0] = heirs[0], fa = files.get(pb0);
      if (f.brId) { try { initOpfs().call(OFS.CLOSE, f.brId, 0, 0, null); } catch (_) {} f.brId = 0; if (f.brRel) { clearTimeout(f.brRel); f.brRel = 0; } }
      const r = opfsPathOp(OFS.RENAME, f.br, opfsRel(pb0));
      if (r >= 0 && fa) {
        clearTimeout(pl0.timer); pendingLinks.delete(pb0); delete fa.pendingFrom;
        for (const [pbx, plx] of heirs.slice(1)) { plx.src = fa; const fx = files.get(pbx); if (fx) fx.pendingFrom = fa; }
        rmEntry(p); return 0n;
      }
    }
    if (heirs.length) linkFlushFrom(f);      // otherwise: copies first, then the ordinary unlink
  }
  if (f.br !== undefined) { const r = opfsPathOp(OFS.UNLINK, f.br); if (r < 0) return BigInt(r); f.brId = 0; }
  rmEntry(p); return 0n;
}
function rmdirPath(S, p) {
  pyTreeTouch(p);
  if (isProcPath(p)) return err(E.ACCES);
  opfsFault(p); if (!dirs.has(p)) return err(E.NOENT);
  if (protectedDelete(S, p)) return err(E.PERM);
  if (dirs.get(p).size) return err(E.NOTEMPTY);
  if (inOpfs(p) && p !== opfsMount) { const r = opfsPathOp(OFS.RMDIR, opfsRel(p)); if (r < 0 && r !== -E.NOENT) return BigInt(r); }
  rmEntry(p); return 0n;
}
function addZombie(pid, parent, pgid) {
  if (!parent || procs.get(parent.pid) !== parent) return;
  const h = parent.sig && parent.sig.handlers.get(SIG.CHLD);
  if (h && isSigIgn(h.ptr)) return;
  zombies.set(pid, { ppid: parent.pid, pgid });
}
let rootProc = null;                 // tree root (fallback Ctrl-C target)
function postSignal(P, sig) {
  if (!P || !sig) return;
  if (sig === SIG.CONT) { for (const st of SIG_STOPPERS) P.sig.pending.delete(st); // POSIX: CONT discards pending stops
    if (P.stopped) { P.stopped = 0; const c = P.contWaiters; P.contWaiters = []; for (const f of c) f(); } }
  if (SIG_STOPPERS.has(sig)) P.sig.pending.delete(SIG.CONT);   // and a stop discards a pending CONT
  const h = P.sig.handlers.get(sig);
  if (h && isSigIgn(h.ptr) && sig !== SIG.KILL) return;         // SIG_IGN
  if ((!h || !h.ptr) && SIG_DFL_IGNORE.has(sig)) return;       // default-ignore
  P.sig.pending.add(sig);
  const w = P.sig.waiters; P.sig.waiters = []; for (const f of w) f('sig');
}
function signalPgrp(pgid, sig) { let n = 0; for (const P of procs.values()) if (P.pgid === pgid) { postSignal(P, sig); n++; } return n; }
// a child just STOPPED (job control): the parent must learn about it — SIGCHLD plus a
// wake of its suspended wait4(WUNTRACED), exactly like on exit. Without this, ^Z left
// the shell asleep in waitpid forever (it is only woken when a child *exits*).
function notifyStopped(child) {
  for (const P of procs.values()) if (P !== child && P.childTasks && P.childTasks.has(child.pid)) { postSignal(P, SIG.CHLD); wakeWaiters(P); return; }
}
function pipeRead(fifo, n) {
  if (!fifo.chunks.length) return new Uint8Array(0);
  let total = 0; const parts = [];
  while (fifo.chunks.length && total < n) {
    const c = fifo.chunks[0];
    const take = Math.min(c.length, n - total);
    parts.push(c.subarray(0, take)); total += take;
    if (take === c.length) fifo.chunks.shift(); else fifo.chunks[0] = c.subarray(take);
  }
  const out = new Uint8Array(total); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// ---- stdio ----
// Host diagnostics go straight to the page, not through the pty. Under a terminal that
// means no ONLCR: a bare "\n" moved the cursor down but not back, and the next program
// output was drawn from that column -- the "staircase" `ls` after a walios: warning.
// Translate the way the pty would, and start on a fresh line.
// stdout/stderr bytes -> text with a streaming decoder per fd: a UTF-8 character split across
// two write() calls (× → é...) came out as two U+FFFD before (run_walios output, 2026-11-10).
const _stdDec = new Map();
function stdDec(fd) { let d = _stdDec.get(fd); if (!d) _stdDec.set(fd, d = new TextDecoder()); return d; }
function post(s, fd) {
  if (termPty !== null && (fd === 2 || fd === 1)) s = '\r\n' + String(s).replace(/\r?\n/g, '\r\n').replace(/\r\n$/, '') + '\r\n';
  self.postMessage({ t: 'out', fd: fd || 1, s });
}

// ---- /dev/hostcall ----
// One request per line, in either encoding the stdio channel accepted: plain JSON, or
// \x02<base64 json>\x03 (the Python clients' frame). The reply comes back on the same fd,
// one line, in the SAME encoding, so a client only has to change which fd it uses.
// `mount` is served right here (the kernel owns loadTar); every other op goes to the
// host as {t:'hostcall', id, frame} and comes back as {t:'hostcall-reply', id, reply}.
let hostcallSeq = 0;
const hostcallPending = new Map();       // kernel id -> { ch, f, plain }
function b64enc(str) { const b = te.encode(str); let bin = ''; for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(bin); }
function b64dec(s) { return td.decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0))); }
function hostcallDeliver(ch, obj, plain) {
  const body = JSON.stringify(obj);
  ch.chunks.push(te.encode((plain ? body : '\x02' + b64enc(body) + '\x03') + '\n'));
  const w = ch.waiters; ch.waiters = []; for (const f of w) f();
}
function hostcallWrite(ch, bytes) {
  ch.inbuf += td.decode(bytes);
  let nl;
  while ((nl = ch.inbuf.indexOf('\n')) >= 0) {
    let raw = ch.inbuf.slice(0, nl).trim(); ch.inbuf = ch.inbuf.slice(nl + 1);
    if (!raw) continue;
    let plain = false, f = null;
    if (raw.startsWith('\x02')) raw = raw.slice(1, raw.endsWith('\x03') ? -1 : undefined);
    try { f = JSON.parse(b64dec(raw)); } catch (_) { try { f = JSON.parse(raw); plain = true; } catch (_2) { post('[host] /dev/hostcall: unparseable request\n', 2); continue; } }
    if (!f || f.t !== 'call') continue;
    const a = f.args || {};
    if (f.op === 'mount') {
      if (!a.url) { hostcallDeliver(ch, { t: 'reply', id: f.id, ok_call: false, error: 'mount without url' }, plain); continue; }
      loadTar(a.url, a.prefix).then(() => hostcallDeliver(ch, { t: 'reply', id: f.id, ok_call: true }, plain),
                                    (e) => hostcallDeliver(ch, { t: 'reply', id: f.id, ok_call: false, error: String((e && e.message) || e) }, plain));
      continue;
    }
    const kid = ++hostcallSeq;
    hostcallPending.set(kid, { ch, f, plain });
    try { self.postMessage({ t: 'hostcall', id: kid, frame: f }); }
    catch (e) { hostcallPending.delete(kid); hostcallDeliver(ch, { t: 'reply', id: f.id, ok_call: false, error: String((e && e.message) || e) }, plain); }
  }
}
function hostcallReply(kid, reply) {
  const p = hostcallPending.get(kid); if (!p) return;
  hostcallPending.delete(kid);
  hostcallDeliver(p.ch, Object.assign({ t: 'reply', id: p.f.id }, reply || { ok_call: false, error: 'empty reply' }), p.plain);
}
// ---- WISP socket bridge: a sibling wisp-worker (spawned by the page) owns the
// WebSocket; we share a SAB with it (set via the 'wisp-sab' message). ----
let wisp = null, wispSab = null;
function initWisp() {
  if (wisp) return wisp;
  if (wispPort) {
    // SEND/SENDTO answer their length at once (the worker buffers towards the relay);
    // CLOSE answers 0. Everything else carries an answer the kernel needs.
    // POLL probes answer 0 (nothing to read) and PINGPOLL -11 (EAGAIN: still in flight) until a reply lands.
    const br = portBridge(wispPort, 'wisp', { 2: (a0, a1) => a1, 7: (a0, a1) => a1, 4: 0 }, { 5: 0, 12: -11 });
    wisp = { call: br.call, port: true, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, LISTEN: 10, ACCEPT: 11, PING: 9, PINGPOLL: 12 } };
    return wisp;
  }
  if (!wispSab) { post('[host] no WISP bridge (sockets unavailable)\n', 2); return { call: () => ({ res: -38, data: new Uint8Array(0) }), OP: {} }; }
  const sab = wispSab;
  const ctl = new Int32Array(sab, 0, 8), wdata = new Uint8Array(sab, 32);
  const call = (op, a0, a1, a2, bytes) => {
    if (bytes) wdata.set(bytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0;
    const prev = Atomics.load(ctl, 1);
    Atomics.add(ctl, 0, 1); Atomics.notify(ctl, 0);
    while (Atomics.load(ctl, 1) === prev) Atomics.wait(ctl, 1, prev);
    return { res: ctl[6], aux: ctl[7], data: wdata };
  };
  wisp = { call, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, LISTEN: 10, ACCEPT: 11, PING: 9, PINGPOLL: 12 } };
  return wisp;
}
function readSockaddr(S, p) { S.refresh();
  const fam = S.dv.getUint16(p, true), port = S.dv.getUint16(p + 2, false); let ip;
  if (fam === 10) {
    // Canonical text (RFC 5952): the groups were joined uncompressed, so '::' (the any-address
    // busybox nc -l binds) read as 0:0:0:0:0:0:0:0, missed the loopback check and went to the
    // relay, which cannot listen: "nc: listen: Address in use". A v4-mapped ::ffff:a.b.c.d is
    // that IPv4 address, as a dual-stack socket treats it.
    const g = []; for (let i = 0; i < 16; i += 2) g.push(S.dv.getUint16(p + 8 + i, false));
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) ip = `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    else {
      let bs = -1, bl = 0;
      for (let i = 0; i < 8;) { if (g[i]) { i++; continue; } let j = i; while (j < 8 && !g[j]) j++; if (j - i > bl && j - i >= 2) { bs = i; bl = j - i; } i = j; }
      const h = g.map((x) => x.toString(16));
      ip = bs < 0 ? h.join(':') : h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
    }
  }
  else ip = `${S.u8[p+4]}.${S.u8[p+5]}.${S.u8[p+6]}.${S.u8[p+7]}`; return { ip, port }; }
function writeSockaddr(S, p, d) { S.refresh(); S.u8.fill(0, p, p + 16);
  S.dv.setUint16(p, 2, true); S.dv.setUint16(p + 2, d.port, false);
  const o = d.ip.split('.').map(Number); S.u8[p+4]=o[0]; S.u8[p+5]=o[1]; S.u8[p+6]=o[2]; S.u8[p+7]=o[3]; return 16; }

// Internet checksum (RFC 1071): 16-bit one's-complement sum, for our synthetic
// ICMP echo replies (the relay confirms reachability; the client owns the packet).
function inetChecksum(b) { let s = 0; for (let i = 0; i + 1 < b.length; i += 2) s += (b[i] << 8) | b[i + 1];
  if (b.length & 1) s += b[b.length - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return (~s) & 0xffff; }
// Build the ICMP echo REPLY the guest's ping expects: echo the request's id/seq and
// data (so its RTT timestamp round-trips), and — for a SOCK_RAW socket — prepend a
// minimal IPv4 header with the pinged host as source (ping reads ihl then the ICMP).
function buildIcmpReply(pg) { const data = pg.data || new Uint8Array(0);
  const icmp = new Uint8Array(8 + data.length);
  icmp[0] = 0; icmp[1] = 0; icmp[4] = (pg.icmpId >> 8) & 255; icmp[5] = pg.icmpId & 255;
  icmp[6] = (pg.icmpSeq >> 8) & 255; icmp[7] = pg.icmpSeq & 255; icmp.set(data, 8);
  const ck = inetChecksum(icmp); icmp[2] = (ck >> 8) & 255; icmp[3] = ck & 255;
  if (!pg.rawhdr) return icmp;
  const ip = new Uint8Array(20 + icmp.length), dv = new DataView(ip.buffer);
  ip[0] = 0x45; dv.setUint16(2, ip.length, false); ip[8] = 64; ip[9] = 1;   // ttl=64, proto=ICMP
  const src = pg.dst.ip.split('.').map(Number); for (let i = 0; i < 4; i++) ip[12 + i] = src[i] || 0;
  ip[16] = 127; ip[17] = 0; ip[18] = 0; ip[19] = 1;                          // dst = 127.0.0.1 (loopback)
  const ick = inetChecksum(ip.subarray(0, 20)); ip[10] = (ick >> 8) & 255; ip[11] = ick & 255;
  ip.set(icmp, 20); return ip; }

class ExitError extends Error { constructor(code, group) { super('exit'); this.code = code; this.group = !!group; } }   // group: exit_group/proc_exit -- the whole process, not just the calling thread
// In-process engine, execve: the calling image is unwound by this rejection and `task`
// is the new image running under the same pid (its exit code is the caller's).
class ReplacedError extends Error { constructor(task) { super('replaced'); this.task = task; } }
// A JS exception thrown from an import and crossing wasm frames comes back wrapped in a
// WebAssembly.Exception carrying the JS tag, so `e instanceof ExitError` is FALSE on the
// SYNCHRONOUS path: a clean exit(0) was reported as a trap (exit 139). Measured -- even
// `echo ok` printed its output and then "died".
function unwrapJS(e) {
  try {
    if (typeof WebAssembly.JSTag !== 'undefined' && e instanceof WebAssembly.Exception && e.is(WebAssembly.JSTag))
      return e.getArg(WebAssembly.JSTag, 0);
  } catch (_) {}
  return e;
}

// ================= Process =================
class Process {
  // The fd table is per PROCESS -- except inside a vfork child window, where the thread
  // that called fork() runs the child branch on a COPY (see sys 'fork'); every OTHER
  // thread keeps seeing the parent's table. The copy used to be installed process-wide,
  // so a sibling thread's close() in the window hit the child's copy instead of its own.
  // The same rule covers everything else the child branch may change before it execs --
  // cwd (run_command's cmd->dir), umask, signal dispositions and mask (git resets every
  // handler to SIG_DFL in the child). Those used to be changed process-wide and put back at
  // CHILD_DONE, so a sibling thread ran with the CHILD's state for the whole window: a
  // SIGPIPE it raised took the default action (kill) instead of the parent's handler, and
  // a relative path resolved against the child's cwd.
  _win() { const cs = this.childStack; if (cs && cs.length) { const c = cs[cs.length - 1]; if (c.tid === (this.curTid || 0)) return c; } return null; }
  get fds() { const c = this._win(); return c ? c.fds : this._fds; }
  set fds(v) { this._fds = v; }
  get cwd() { const c = this._win(); return c ? c.cwd : this._cwd; }
  set cwd(v) { this._cwd = v; }
  get umask() { const c = this._win(); return c ? c.umask : this._umask; }
  set umask(v) { const c = this._win(); if (c) c.umask = v; else this._umask = v; }
  get sig() { const c = this._win(); return c ? c.sig : this._sig; }
  set sig(v) { this._sig = v; }
  // Process group and session, also per window: subprocess's start_new_session /
  // process_group= call setsid()/setpgid() in the child branch, which used to move the
  // PARENT into the new session and group. The exec'd image takes the window's values.
  get pgid() { const c = this._win(); return c && c.pgid !== undefined ? c.pgid : this._pgid; }
  set pgid(v) { const c = this._win(); if (c && c.pgid !== undefined) c.pgid = v; else this._pgid = v; }
  get sid() { const c = this._win(); return c && c.sid !== undefined ? c.sid : this._sid; }
  set sid(v) { const c = this._win(); if (c && c.sid !== undefined) c.sid = v; else this._sid = v; }
  // The pid the RUNNING context has: the child's inside a vfork window.
  get selfPid() { const c = this._win(); return c ? c.pid : this.pid; }
  constructor(modKey, argv, env, fdTable, cwd) {
    this.modKey = modKey;
    this.argv = argv; this.env = env;   // env: array of "K=V"
    this.fds = fdTable;
    this.nextFd = Math.max(3, ...[...fdTable.keys()].map(k => k + 1));
    // A wasm32-wasi program can only reach the filesystem through PREOPENED directory
    // fds: wasi-libc scans fd 3, 4, ... at startup (fd_prestat_get) and resolves every
    // path against the preopen whose name is its longest prefix -- no preopen, no way
    // to open ANY path, and libc answers ENOENT before the host is even asked. The
    // boot code gave the ROOT module fd 3 = "/", and the wasi-threads path did the same,
    // but a plain WASI child exec'd from the shell (qjs, qjsc, ...) got nothing: `qjs -e`
    // worked while `qjs /tmp/t.js` and std.open() failed "No such file". Every WASI
    // process now gets fd 3 = "/" unless the table already has a preopen. (Relative
    // paths still resolve against "/", not the shell's cwd: wasi-libc has no cwd of its
    // own -- pass absolute paths to WASI programs.)
    { const mod = modCache.get(modKey);
      if (mod && WebAssembly.Module.imports(mod).some(i => i.module === 'wasi_snapshot_preview1')
          && ![...fdTable.values()].some(h => h && h.preopen)) {
        if (!fdTable.has(3)) { fdTable.set(3, { preopen: '/', dir: true, path: '/' }); this.nextFd = Math.max(this.nextFd, 4); }
        else post('[host] wasi: fd 3 is already open, so no "/" preopen could be installed -- this program cannot open files by path\n', 2);
      } }
    this.cwd = { p: cwd || '/' };
    this.pid = nextPid++;
    this.startMs = Date.now();       // /proc/<pid>/stat starttime (execve keeps the old one: startProcess)
    this.heapBrk = 0;
    this.dlHandles = [];             // dlopen()'d side modules (wasm dynamic linking)
    this.mmapFree = [];              // recycled anon regions [{base,len}], address-sorted
    this.mmapLive = new Map();       // base -> len, so munmap knows the true extent
    this.childStack = [];
    this.dirState = new Map();
    this.pending = [];
    this.reaped = new Map();
    this.childTasks = new Map();     // pid -> in-flight child task
    this.waitWaiters = [];           // resolvers for a process suspended in wait4
    this.forkState = 'none';         // Asyncify fork: 'none' | 'unwinding' | 'rewinding'
    this.asyncifyBuf = 0; this.forkRet = 0n;
    this.syscalls = 0;
    this.pgid = this.pid; this.sid = this.pid;
    // Signal masks are PER THREAD (POSIX). This was one mask for the whole process, and musl's
    // thread exit blocks every application signal in the exiting thread -- so after ANY thread
    // ended, the main thread had 61 signals blocked: SIGPIPE stayed pending (git, with its
    // preload-index threads, wrote on into a closed pipe and exited 0 instead of dying 141),
    // and Ctrl-C / SIGCHLD went quiet in every threaded program. Unknown tids read the main
    // thread's mask; threadSpawn gives a new thread its creator's.
    const masks = new Map([[0, 0n]]), P = this;
    this.sig = { handlers: new Map(), pending: new Set(), waiters: [], masks,
      get mask() { const t = P.curTid || 0; return masks.has(t) ? masks.get(t) : masks.get(0); },
      set mask(v) { masks.set(P.curTid || 0, v); } };
    this.timers = new Map();         // which(0=ITIMER_REAL) -> {deadline, intervalMs, to}
    this.stopped = 0; this.stopReported = false; this.contWaiters = [];
    this.cred = { uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0, groups: [] }; // root by default
    this.shmAt = new Map();          // SysV shm attachments: base -> segment
    this.futexWaiters = new Map();   // pthread futexes: uaddr -> [{fin, addr, gone, woken}] (see sysAsync 'futex')
    this.curTid = 0;                 // tid of the thread whose syscall is being served (0 = main)
    this.umask = 0o22;
    procs.set(this.pid, this);
  }
  retire() {
    if (lockTab.size) { const me = this.pid; procs.delete(this.pid);
      lockDrop((f, l) => (l.kind === 'posix' && l.owner === me) || (l.kind !== 'posix' && !ofdLive(l.owner))); }
    rmEntry(`/.wali_env_${this.pid}`); // else one env file per exec'd process accumulates in / forever
    procs.delete(this.pid);
    if (this.ppid && this.ppid !== this.pid) addZombie(this.pid, procs.get(this.ppid), this.pgid);
    for (const [zp, z] of zombies) if (z.ppid === this.pid) zombies.delete(zp);   // init reaps our unreaped children
    for (const t of this.timers.values()) if (t.to) clearTimeout(t.to);
    this.timers.clear();
    const w = this.sig.waiters; this.sig.waiters = []; for (const f of w) f('sig');
  }
  pollTimers() {
    if (!this.timers.size) return;
    const now = Date.now();
    for (const [which, t] of this.timers) {
      if (t.deadline && now >= t.deadline) {
        // Cancel the OTHER source before delivering. Without this the pending
        // setTimeout still fired after we deleted the entry, so one one-shot timer
        // delivered SIGALRM twice.
        if (t.to) { clearTimeout(t.to); t.to = null; }
        if (t.intervalMs > 0) { t.deadline = now + t.intervalMs;
                                if (t.fire) t.to = setTimeout(t.fire, t.intervalMs); }
        else this.timers.delete(which);
        postSignal(this, SIG.ALRM);
      }
    }
  }
  armItimer(which, valueMs, intervalMs) {
    const old = this.timers.get(which);
    if (old && old.to) clearTimeout(old.to);
    this.timers.delete(which);
    if (valueMs <= 0) return;
    const t = { deadline: Date.now() + valueMs, intervalMs, to: null };
    {
      const fire = () => { postSignal(this, SIG.ALRM);
        if (t.intervalMs > 0) { t.deadline = Date.now() + t.intervalMs; t.to = setTimeout(fire, t.intervalMs); }
        else this.timers.delete(which); };
      t.fire = fire;              // so pollTimers can re-arm the other source
      t.to = setTimeout(fire, valueMs);
    }
    this.timers.set(which, t);
  }
  predeliver() {
    // Worker model: delivery needs the guest's own thread, so the serve loop drives it
    // through predeliverAsync/callGuest. Consuming the queue here would swallow the
    // signal and warn about --export-table instead.
    if (this.callGuest) return null;
    if (!this.sig.pending.size) return null;
    // After a handler runs, scan again: a signal raised WHILE it ran (blocked then) is
    // delivered as the handler returns, as on Linux -- not at some later syscall the program
    // may never make (git's sigchain re-raises SIGTERM to reach the next handler, then the
    // default action; test-tool exited 0 instead of dying by the signal).
    for (let rescan = 0; rescan < 64; rescan++) { let ran = false;
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && isSigIgn(h.ptr)) continue;                    // SIG_IGN
      if (h && isSigHandler(h.ptr) && sig !== SIG.KILL) {
        const table = this.inst && this.inst.exports.__indirect_function_table;
        if (table) {
          try { table.get(h.ptr)(sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false; // !SA_RESTART
            ran = true; break; }
          catch (e) { post(`[host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`, 2); }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          post(`[host] pid ${this.pid} (${(this.argv||[]).slice(0,2).join(' ')}): handler set for signal ${sig} but binary lacks --export-table; default action\n`, 2); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;
      if (SIG_STOPPERS.has(sig)) {                           // job control: park until SIGCONT
        if (!this.inChild()) { this.stopped = sig; this.stopReported = false; notifyStopped(this); }
        continue;
      }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);
    }
    if (!ran) break; }
    return null;
  }
  // Async delivery: run the handler in the guest worker (callGuest), where it sits on
  // the instance's own thread and its syscalls come back here as ordinary requests.
  // This is what makes busybox ping (SIGALRM handler -> sendto) work. Every process
  // runs on its own worker, so callGuest is always set for anything that can carry a
  // handler; a guest whose binary lacks --export-table takes the default action.
  async predeliverAsync() {
    if (!this.sig.pending.size) return null;
    for (let rescan = 0; rescan < 64; rescan++) { let ran = false;   // see predeliver
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && isSigIgn(h.ptr)) continue;                    // SIG_IGN
      if (h && isSigHandler(h.ptr) && sig !== SIG.KILL) {
        if (this.callGuest && this._plan && !this._plan.table) {
          // Worker model, binary linked without --export-table: there is no way to reach
          // the handler, so fall through to the default action -- but SAY SO. This used to
          // be a silent downgrade (the warning below sits in the !callGuest branch, which
          // this path never reaches), so a program whose handler was simply unreachable
          // looked like one whose signal never arrived. bin/cc passes --export-table now;
          // this stays for binaries built elsewhere.
          if (!this.warnedNoTable) { this.warnedNoTable = true;
            post(`[host] pid ${this.pid} (${(this.argv || []).slice(0, 2).join(' ')}): signal ${sig} has a handler but this binary exports no __indirect_function_table (link with -Wl,--export-table) -- taking the DEFAULT action instead
`, 2); }
        } else if (this.callGuest) {
          // The instance is on another thread; ask it to run the handler.
          const savedMask = this.sig.mask;
          this.sig.mask |= (1n << BigInt(sig - 1)) | BigInt(h.mask || 0n);
          try { await this.callGuest(h.ptr, sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false;
            ran = true; break; }
          catch (e) { if (e instanceof ExitError) throw e;
            post(`[host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`, 2); }
          finally { this.sig.mask = savedMask; }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          post(`[host] pid ${this.pid} (${(this.argv||[]).slice(0,2).join(' ')}): handler set for signal ${sig} but binary lacks --export-table; default action\n`, 2); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;
      // Job control was COSMETIC: a stopper set P.stopped and told the parent (so ^Z made
      // the shell print "Stopped" and hand back the prompt) but the child NEVER stopped
      // running. contWaiters was initialised and drained by SIGCONT, yet nothing ever
      // pushed to it, so no code path waited for one. Measured: a `kill -STOP` on a busy
      // job kept writing straight through it -- 9652 bytes before the stop, 20944 after,
      // 32532 later still.
      // Now it really parks: this is the ASYNC delivery path, so the syscall simply does
      // not return until SIGCONT drains contWaiters (line ~579). The kernel is an async
      // syscall server, so a parked process costs nothing while it waits.
      // NB the SYNC twin (predeliver) cannot await and still only sets the flag; a process
      // spinning in pure computation therefore parks at its next BLOCKING syscall, not
      // instantly. That is fine for builds, which are syscall-bound, but it is why the
      // caller must keep a kill fallback for a genuine runaway.
      if (SIG_STOPPERS.has(sig)) {
        if (!this.inChild()) {
          this.stopped = sig; this.stopReported = false; notifyStopped(this);
          await new Promise((res) => { this.contWaiters.push(res); });
        }
        continue;
      }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);
    }
    if (!ran) break; }
    return null;
  }
  async onSigWakeAsync(restartable) {   // deliver pending signals (handlers run in the guest worker), then EINTR or restart
    this.sigDelivered = false; this.sigAllRestart = true;
    const dv = await this.predeliverAsync(); if (dv !== null) return dv;
    if (!this.sigDelivered) return null;
    return (restartable && this.sigAllRestart) ? null : err(E.INTR);
  }
  // Wait until a WISP socket is readable or a signal arrives. Polls the bridge
  // on a short timer and races it against a pending signal so a stuck recv stays
  // interruptible by ^C. Returns an EINTR (or restart) sentinel, or null once readable.
  async sockWait(h) {
    const tid = this.curTid;   // re-asserted after each wait (see sysAsync)
    const br = initWisp();
    while (true) {
      if (h.sock.icmp) {
        const pg = h.sock.ping;
        if (pg && pg.status === null) { const pk = br.call(br.OP.PINGPOLL, pg.id, 0, 0);
          if (pk.res === 0) { pg.status = 0; return null; }       // got a reply -> recv synthesises it
          if (pk.res !== -11) { pg.status = pk.res; h.sock.ping = null; } } // unreachable: wait for ping's own timeout
      } else {
        const pk = br.call(br.OP.POLL, h.sock.id, 0, 0);
        if (pk.res !== 0) return null;                            // readable, or error/closed -> let S.sys report it
      }
      const w = await this.sigRace(res => setTimeout(() => res('t'), 5));
      if (w === 'sig') { const v = await (this.curTid = tid, this).onSigWakeAsync(true); if (v !== null) return v; }
    }
  }
  sigRace(arm) {
    return new Promise((res) => {
      let done = false; const fin = (v) => { if (!done) { done = true; res(v); } };
      arm(fin); this.sig.waiters.push(fin);
    });
  }
  nextTimerDeadline() {
    let d = 0;
    for (const t of this.timers.values()) if (t.deadline && (!d || t.deadline < d)) d = t.deadline;
    return d;
  }
  sleepMs(name, a) { // handles clock_nanosleep TIMER_ABSTIME
    const abs = name === 'clock_nanosleep' && (a[1] & 1);
    const tp = name === 'nanosleep' ? a[0] : a[2];
    if (!tp) return 0;
    this.refresh();
    const sec = Number(this.r64(tp)), ns = this.tsNs(tp);
    if (!abs) return sec * 1000 + ns / 1e6;
    const nowMs = ((a[0] | 0) === 1 || (a[0] | 0) === 4) ? performance.now() : Date.now();
    return sec * 1000 + ns / 1e6 - nowMs;
  }
  wrTs(p, ms) { this.i64(p, BigInt(Math.floor(ms / 1000))); this.i64(p + 8, BigInt(Math.round((ms % 1000) * 1e6))); }
  wrItimer(p, which) { // struct itimerval as musl passes it: long[4] {interval s, us, value s, us}
    const t = this.timers.get(which);
    const iv = t ? t.intervalMs : 0, rem = t && t.deadline ? Math.max(0, t.deadline - Date.now()) : 0;
    this.wLong(p, 0, Math.floor(iv / 1000)); this.wLong(p, 1, Math.round((iv % 1000) * 1000));
    this.wLong(p, 2, Math.floor(rem / 1000)); this.wLong(p, 3, Math.round((rem % 1000) * 1000));
  }
  pollTfd(_t) { /* timerfd expirations are driven by the setTimeout armed in timerfd_settime */ }
  selectReady(fd, forWrite) { // one fd's readiness, for select() (mirrors poll's logic)
    const h = this.fds.get(fd);
    if (!h) return true;                                  // report ready; the read/write reports EBADF
    if (forWrite) return true;                            // pipes/sockets buffer unboundedly here
    if (h.std === 0) return stdinChunks.length > 0 || stdinEOF;
    if (h.std !== undefined) return true;
    if (h.fifo) return h.fifo.chunks.length > 0 || fifoEOF(h.fifo);
    if (h.spair) return h.spair.rd.chunks.length > 0 || h.spair.rd.writers <= 0;
    // A listening socket is "readable" when a connection is waiting, which is how a
    // poll/select-driven server (rather than a blocking-accept one) learns to accept.
    if (h.sock && h.sock.local && h.sock.listener) return h.sock.local.backlog.length > 0;
    if (h.pty !== undefined) { const p = ptys.get(h.pty); return h.master ? p.toMaster.length > 0 : (p.toSlave.length > 0 || !!p.slaveEof); }
    if (h.tfd) { this.pollTfd(h.tfd); return h.tfd.count > 0; }
    if (h.sock && h.sock.icmp) { const pg = h.sock.ping;
      if (pg && pg.status === null) { const pk = initWisp().call(initWisp().OP.PINGPOLL, pg.id, 0, 0);
        if (pk.res === 0) pg.status = 0; else if (pk.res !== -11) pg.status = pk.res; }
      return !!(pg && pg.status === 0); }
    if (h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); return pk.res !== 0; }
    return true;
  }
  epollEval(ep, evp, maxev) { // write ready epoll_events (x86_64 PACKED layout: events u32 @0, data u64 @4, stride 12)
    this.refresh(); let n = 0;
    for (const [fd, it] of ep) {
      if (n >= maxev) break;
      let re = 0;
      if (!this.fds.has(fd)) re |= 0x10;                                   // EPOLLHUP for a closed fd
      else { if ((it.events & 1) && this.selectReady(fd, false)) re |= 1;  // EPOLLIN
             if (it.events & 4) re |= 4; }                                 // EPOLLOUT: always writable here
      if (re) { this.i32(evp + n * 12, re); this.i64(evp + n * 12 + 4, it.data); n++; }
    }
    return n;
  }
  selectParse(name, a) { // shared select/pselect6 decode: fd lists + timeout ms (-1 = infinite)
    this.refresh();
    const nfds = Math.min(Math.max(a[0] | 0, 0), 1024), rp = a[1], wp = a[2], ep = a[3], tp = a[4]; // FD_SETSIZE clamp (garbage nfds must not scan gigabits)
    const bit = (p, fd) => p ? (this.u8[p + (fd >> 3)] >> (fd & 7)) & 1 : 0;
    const rd = [], wr = [];
    for (let fd = 0; fd < nfds; fd++) { if (bit(rp, fd)) rd.push(fd); if (bit(wp, fd)) wr.push(fd); }
    let tmo = -1;
    // musl passes the timeout as long[2] {s, us} (select) or {s, ns} (pselect6)
    if (tp) { const s = this.rLong(tp, 0), x = this.rLong(tp, 1); tmo = s * 1000 + x / (name === 'select' ? 1000 : 1e6); }
    const nb = (nfds + 7) >> 3;
    const commit = () => { this.refresh(); let n = 0;
      for (const p2 of [rp, wp, ep]) if (p2) this.u8.fill(0, p2, p2 + nb);
      for (const fd of rd) if (this.selectReady(fd, false)) { this.u8[rp + (fd >> 3)] |= 1 << (fd & 7); n++; }
      for (const fd of wr) if (this.selectReady(fd, true)) { this.u8[wp + (fd >> 3)] |= 1 << (fd & 7); n++; }
      return n; };
    return { rd, wr, tmo, commit };
  }
  allocFd() { let g = 0; while (this.fds.has(g)) g++; return g; } // POSIX lowest-free fd
  bumpFifo(h) { if (h && h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') { h.fifo.readers++; if (h.alsoW) h.fifo.writers++; } } else if (h && h.spair) { h.spair.wr.writers++; h.spair.rd.readers++; } }
  refresh() { const buf = this.memory.buffer; if (this.membuf !== buf || (this.u8 && this.u8.byteLength !== buf.byteLength)) { this.membuf = buf; this.u8 = new Uint8Array(buf); this.dv = new DataView(buf); } }
  cstr(p) { this.refresh(); let e = p; while (this.u8[e] !== 0) e++; return td.decode(this.u8.slice(p, e)); }
  wbytes(p, b) { this.refresh(); this.u8.set(b, p); }
  wstr(p, s, max) { const b = te.encode(s); const n = max ? Math.min(b.length, max - 1) : b.length; this.wbytes(p, b.subarray(0, n)); this.u8[p + n] = 0; return n; }
  // argv/env strings: bytes, not UTF-8 (bdec/benc)
  cstrB(p) { this.refresh(); let e = p; while (this.u8[e] !== 0) e++; return bdec(this.u8.slice(p, e)); }
  wstrB(p, s) { const b = benc(s); this.wbytes(p, b); this.u8[p + b.length] = 0; return b.length; }
  i64(p, v) { this.refresh(); this.dv.setBigInt64(p, BigInt(v), true); }
  i32(p, v) { this.refresh(); this.dv.setInt32(p, Number(v), true); }
  r32(p) { this.refresh(); return this.dv.getInt32(p, true); }
  r64(p) { this.refresh(); return this.dv.getBigInt64(p, true); }
  // C long in this process's ABI (makeImports reads it from the module): WALI's wasm32 has a
  // 64-bit long, walios ILP32 binaries (custom section wali.abi = "ilp32") a 32-bit one.
  // Element i of a long[] (musl passes select/ppoll/itimer/rusage times as long[]), and a
  // timespec's tv_nsec: a long after the 64-bit tv_sec, whose other half is ILP32 padding.
  get L() { return this.ilp32 ? 4 : 8; }
  rLong(p, i = 0) { this.refresh(); return this.ilp32 ? this.dv.getInt32(p + 4 * i, true) : Number(this.dv.getBigInt64(p + 8 * i, true)); }
  wLong(p, i, v) { this.refresh(); if (this.ilp32) this.dv.setInt32(p + 4 * i, Number(v), true); else this.dv.setBigInt64(p + 8 * i, BigInt(v), true); }
  tsNs(p) { return this.rLong(p + 8); }
  // struct msghdr / cmsghdr: 64-bit long pads msg_iovlen and msg_controllen to 8 bytes and the
  // cmsghdr header to 16; ILP32 has neither pad.
  get msgCtl() { return this.ilp32 ? { ctl: 16, ctllen: 20, flags: 24, hdr: 12 } : { ctl: 20, ctllen: 24, flags: 32, hdr: 16 }; }
  rPtrArray(p) { const out = []; for (;;) { const q = this.r32(p); if (!q) break; out.push(this.cstrB(q)); p += 4; } return out; }
  // A syscall's path, with symlinks in its PARENT components resolved (the last one is left for
  // the caller: open/stat follow it, lstat/unlink/rename/mkdir do not) -- what Linux does for
  // every path argument. mkdir/unlink/rmdir/rename took the path literally, so `mkdir
  // there/sub` with `there` a symlink worked by accident in RAM and failed on the OPFS mount
  // (git checkout-index --prefix=<symlinked dir>/: "cannot create directory ... Is a directory").
  atPath(dirfd, s) {
    let p;
    if (s.startsWith('/')) p = norm(s, '/');
    else if ((dirfd | 0) === -100) p = norm(s, this.cwd.p);
    else { const h = this.fds.get(dirfd); p = norm(s, h && h.path && dirs.has(h.path) ? h.path : this.cwd.p); }
    // A trailing slash names the DIRECTORY, so a final symlink is followed even by lstat
    // (POSIX path resolution): `stat link/`, `ls -ld link/` see the directory.
    if (s.length > 1 && s.endsWith('/')) return this.follow(p);
    return this.followDir(p);
  }
  // ---- wasm dynamic linking: load a CPython C-extension .so (a PIC wasm side module) ----
  // Shares the interpreter's linear memory + growable table; resolves env.<Py*> from the
  // MAIN module's exports; bump-allocates the module's own data/table region. dlopen()/dlsym()
  // in the guest (wali_dlfcn.c) upcall here via env.__wali_dlopen / env.__wali_dlsym.
  // ---- anonymous mmap pool ----
  // wasm linear memory only ever GROWS, so a no-op munmap means a malloc/free-heavy
  // guest never reuses anything: musl's mallocng creates and destroys size-class
  // groups constantly, each one a fresh mmap, each mmap a memory.grow. Measured in
  // Chrome before this pool: ~226us for a 1KB bytearray and ~7.7ms for 1MB, which is
  // what made `import pandas` exceed 120s in the browser while taking ~3s on the node
  // host. Recycling regions turns the common case into a free-list hit with no grow.
  mmapAlloc(len) {
    const need = Math.max(PAGE, Math.ceil(len / PAGE) * PAGE);
    const fl = mmapPool ? this.mmapFree : [];
    for (let i = 0; i < fl.length; i++) {
      if (fl[i].len < need) continue;
      const base = fl[i].base;
      if (fl[i].len === need) fl.splice(i, 1); else { fl[i].base += need; fl[i].len -= need; }
      this.refresh();
      this.u8.fill(0, base, base + need);   // an anonymous mapping must read as zero
      this.mmapLive.set(base, need);
      return base;
    }
    this.refresh();
    const base = this.membuf.byteLength;
    this.memory.grow(need / PAGE);
    this.refresh();
    this.mmapLive.set(base, need);
    return base;
  }
  mmapRelease(base, len) {
    const n = Math.max(PAGE, Math.ceil(len / PAGE) * PAGE), end = base + n;
    // A guest may unmap only PART of a mapping (aligned allocators mmap extra and
    // trim the head/tail), so locate the live region that CONTAINS this range and
    // split it. Recycling a range we cannot account for would risk handing the same
    // memory out twice, so an unrecognised release leaks instead: never corrupt.
    let hb = -1, hl = 0;
    for (const [b, l] of this.mmapLive) { if (base >= b && end <= b + l) { hb = b; hl = l; break; } }
    if (hb < 0) return;
    this.mmapLive.delete(hb);
    if (base > hb) this.mmapLive.set(hb, base - hb);          // head stays mapped
    if (end < hb + hl) this.mmapLive.set(end, hb + hl - end); // tail stays mapped
    // Insert in address order with a binary search and coalesce ONLY the immediate
    // neighbours. Re-sorting and re-scanning the whole list on every release is
    // O(n log n) per call, which turns into the dominant cost once a big import has
    // produced thousands of free blocks.
    const fl = this.mmapFree;
    let lo = 0, hi = fl.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (fl[mid].base < base) lo = mid + 1; else hi = mid; }
    fl.splice(lo, 0, { base, len: n });
    if (lo + 1 < fl.length && fl[lo].base + fl[lo].len === fl[lo + 1].base) { fl[lo].len += fl[lo + 1].len; fl.splice(lo + 1, 1); }
    if (lo > 0 && fl[lo - 1].base + fl[lo - 1].len === fl[lo].base) { fl[lo - 1].len += fl[lo].len; fl.splice(lo, 1); }
  }

  dlopen(guestPath) {
    let _ph = 'resolve';
    try {
      const p = this.follow(this.atPath(-100, guestPath)); opfsFault(p);
      const f = files.get(p); if (!f) throw new Error('not found: ' + p);
      const bytes = fileRead(f, 0, f.size);
      _ph = 'abi'; const mis = abiMismatch(this, bytes, p); if (mis) throw new Error(mis);
      _ph = 'compile';
      const mod = new WebAssembly.Module(bytes);
      const info = parseDylink(mod);
      const exp = this.inst.exports, table = exp.__indirect_function_table;
      let memBase = 0;
      if (info.memsize > 0) {
        // honor the module's required data alignment (dylink memalign, log2) — malloc only gives 16B;
        // over-allocate + round up so higher-aligned statics (SIMD/64B) land correctly.
        const align = 1 << (info.memalign || 0);
        // Take the region the way the host's own mmap does (grow at the end of
        // linear memory) instead of calling the guest's malloc. A guest call made from
        // THIS JS frame can park — musl's malloc drops into an mmap/brk syscall — and
        // that is why dlopen failed for EVERY C extension in the browser while working
        // in the node host (asyncify).
        // memory.grow is a pure JS-side operation, and `case 'mmap'` allocates with
        // exactly this base+grow pattern, so the two allocators stay consistent.
        _ph = 'grow';
        this.refresh();
        const raw = this.membuf.byteLength;
        this.memory.grow(Math.ceil((info.memsize + align) / 65536));
        memBase = align > 1 ? ((raw + align - 1) & ~(align - 1)) : raw;
        // grown pages are zero, but be explicit: the module's BSS must start zeroed
        this.refresh(); this.u8.fill(0, memBase, memBase + info.memsize);
      }
      const tableBase = table.length;
      if (info.tablesize > 0) table.grow(info.tablesize);
      const Gi = v => new WebAssembly.Global({ value: 'i32', mutable: false }, v >>> 0);
      const BASE = new Set(['memory', '__indirect_function_table', '__stack_pointer', '__memory_base', '__table_base']);
      const env = { memory: exp.memory, __indirect_function_table: table, __stack_pointer: exp.__stack_pointer,
                    __memory_base: Gi(memBase), __table_base: Gi(tableBase) };
      const gotMem = {}, gotFunc = {};
      for (const im of WebAssembly.Module.imports(mod)) {
        if (im.module === 'env') { if (BASE.has(im.name)) continue; const s = exp[im.name];
          if (s === undefined && !unknownSyscalls.has('dlsym:' + im.name)) { unknownSyscalls.add('dlsym:' + im.name); post(`[host] dlopen: unresolved env.${im.name}\n`, 2); }
          // Self-resolving trampoline (parity with the node host loader). A symbol the
          // MAIN doesn't export may still be DEFINED BY THIS .so: libc++ weak template
          // instantiations are imported AND exported by the same module (ft2font's
          // std::__hash_table<...,FT2Font*>::__do_rehash is the canonical case). Binding
          // it to `undefined` is a LinkError; binding it to ()=>0 silently corrupts (a
          // rehash that never allocates -> the next insert indexes a 0-size bucket array
          // -> "memory access out of bounds"). Resolve at CALL time to this module's own
          // export, else another loaded .so's, else throw loudly.
          env[im.name] = (s !== undefined) ? s : ((...a) => {
            const self = inst.exports[im.name];
            if (typeof self === 'function') return self(...a);
            const alt = this.dlHandles.map(h => h.inst.exports[im.name]).find(f => typeof f === 'function');
            if (alt) return alt(...a);
            throw new Error('[host] unresolved dynamic fn: ' + im.name);
          }); }
        else if (im.module === 'GOT.mem') { const s = exp[im.name]; gotMem[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, (s && s.value !== undefined) ? s.value : Number(s || 0)); }
        else if (im.module === 'GOT.func') { gotFunc[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, this.funcIdx(exp[im.name], { h: -1, name: im.name })); }
      }
      const waliProxy = new Proxy(this.wali || {}, { get: (t, n) => t[n] || (typeof n !== 'string' ? undefined : (() => { throw new Error('[host] unresolved wali import from side module: ' + n); })) });
      _ph = 'instantiate';
      const inst = new WebAssembly.Instance(mod, { env, wali: waliProxy, 'GOT.mem': gotMem, 'GOT.func': gotFunc });
      // GOT back-fill, and it MUST run before the relocs. A GOT entry for a symbol the
      // .so defines ITSELF was seeded 0 above (the main has no such export), and
      // __wasm_apply_data_relocs BAKES GOT values into memory (PyMethodDef ml_meth
      // function pointers, type slots) -> a 0 becomes a permanent null function pointer
      // and the first call_indirect traps. This is the Pillow/lxml encoder fix.
      for (const k in gotMem) { const e = inst.exports[k]; if (e && e.value !== undefined) gotMem[k].value = memBase + e.value; }
      for (const k in gotFunc) { if (gotFunc[k].value === 0) { const e = inst.exports[k]; if (typeof e === 'function') gotFunc[k].value = this.funcIdx(e, { h: this.dlHandles.length, name: k }); } }
      _ph = 'apply_data_relocs';
      if (inst.exports.__wasm_apply_data_relocs) inst.exports.__wasm_apply_data_relocs();
      // Thread-locals (C++ EH's __wasm_lpad_context, ...): the .so has its own __tls_base, 0 until
      // __wasm_init_tls points it at a block, and a TLS access at 0 silently corrupts low memory.
      // The block is taken the same way as the data region above.
      let tlsBase = -1, tlsSize = 0;
      if (typeof inst.exports.__wasm_init_tls === 'function') {
        _ph = 'init_tls';
        const ts = inst.exports.__tls_size ? inst.exports.__tls_size.value : 0;
        const ta = Math.max(inst.exports.__tls_align ? inst.exports.__tls_align.value : 16, 16);
        this.refresh();
        const raw = this.membuf.byteLength;
        this.memory.grow(Math.ceil((ts + ta) / 65536) || 1);
        const tb = (raw + ta - 1) & ~(ta - 1);
        this.refresh(); this.u8.fill(0, tb, tb + ts);
        inst.exports.__wasm_init_tls(tb);
        tlsBase = tb; tlsSize = ts;
      }
      _ph = 'call_ctors';
      if (inst.exports.__wasm_call_ctors) inst.exports.__wasm_call_ctors();
      this.refresh();
      { const gf = {}; for (const k in gotFunc) gf[k] = gotFunc[k].value;   // for a python snapshot (pySnapCapture)
        (this.dlRecs = this.dlRecs || []).push({ mod, memBase, memSize: info.memsize || 0, tableBase, tlsBase, tlsSize, gotFunc: gf }); }
      this.dlHandles.push({ inst, symCache: new Map() });
      return this.dlHandles.length - 1;
    } catch (e) {
      if (e instanceof NeedAsync) throw e;   // in-process engine: the .so is being fetched; the import re-runs this
      post('[host] dlopen(' + guestPath + ') failed at [' + (typeof _ph === 'string' ? _ph : '?') + ']: ' + e.message + '\n', 2); return _ph === 'abi' ? -2 : -1;   // -2: wrong ABI (wali_dlfcn.c)
    }
  }
  dlsym(handle, sym) {
    const h = this.dlHandles[handle]; if (!h) return -1;
    if (h.symCache.has(sym)) return h.symCache.get(sym);
    const fn = h.inst.exports[sym]; if (typeof fn !== 'function') return -1;
    const idx = this.funcIdx(fn, { h: handle, name: sym }); h.symCache.set(sym, idx); return idx;
  }
  // Install a funcref into the shared table, return its index (dlsym / GOT.func). `desc` says
  // which export it is, so a python snapshot can refill the slot; a slot of unknown origin
  // makes the process unsnapshotable.
  funcIdx(fn, desc) {
    if (typeof fn !== 'function') return 0;
    const table = this.inst.exports.__indirect_function_table;
    const idx = table.length; table.grow(1); table.set(idx, fn);
    if (desc) (this.tableLog = this.tableLog || new Map()).set(idx, desc); else this.snapUnsafe = this.snapUnsafe || 'table slot of unknown origin';
    return idx;
  }
  putStat(p, o) {
    this.refresh(); this.u8.fill(0, p, p + 144);
    this.i64(p, BigInt(o.dev || 1)); this.i64(p + 8, BigInt(o.ino || 1)); this.i64(p + 16, BigInt(o.nlink || 1));
    this.i32(p + 24, o.mode); this.i32(p + 28, o.uid ?? 1000); this.i32(p + 32, o.gid ?? 1000);
    this.i64(p + 40, BigInt(o.rdev || 0));
    this.i64(p + 48, BigInt(o.size)); this.i64(p + 56, 4096n); this.i64(p + 64, BigInt(Math.ceil(o.size / 512)));
    const t = (off, ms) => { this.i64(p + off, BigInt(Math.floor(ms / 1000))); this.i64(p + off + 8, BigInt(Math.floor((ms % 1000) * 1e6))); };
    { const mt = o.mtimeMs ?? Date.now(); t(72, mt); t(88, mt); t(104, mt); }   // ?? not ||: mtime 0 (the epoch, `touch -d @0`, git chmtime =0) is a time, not "unknown"
  }
  followDir(p) {         // resolve symlinks in the parent components only (lstat semantics)
    const i = p.lastIndexOf('/');
    return i <= 0 ? p : this.follow(p.slice(0, i)) + p.slice(i);
  }
  follow(p, depth = 0) { // resolve symlinks (parents + final component), max 8 hops
    if (depth > 8) return p;
    const segs = p.split('/').filter(Boolean); let cur = '';
    for (let i = 0; i < segs.length; i++) {
      cur += '/' + segs[i];
      const f = files.get(cur);
      if (f && f.sym !== undefined) {
        const tgt = f.sym.startsWith('/') ? f.sym : cur.slice(0, cur.lastIndexOf('/') + 1) + f.sym;
        return this.follow(norm(tgt + '/' + segs.slice(i + 1).join('/'), '/'), depth + 1);
      }
    }
    return p;
  }
  // classic rwx check against this process's creds (euid 0 bypasses; want: r4 w2)
  syncShmOne(base, at) { // 3-way byte merge: local vs shadow vs segment truth
    this.refresh();
    const local = this.u8.subarray(base, base + at.seg.size), truth = at.seg.buf, shadow = at.shadow;
    for (let i = 0; i < shadow.length; i++) {
      if (local[i] !== shadow[i]) { truth[i] = local[i]; shadow[i] = local[i]; }
      else if (truth[i] !== shadow[i]) { local[i] = truth[i]; shadow[i] = truth[i]; }
    }
  }
  syncShm() { for (const [base, at] of this.shmAt) this.syncShmOne(base, at); }
  mayAccess(f, want) {
    if (this.cred.euid === 0) return true;
    const cls = (f.uid ?? 0) === this.cred.euid ? 6 : ((f.gid ?? 0) === this.cred.egid || (this.cred.groups || []).includes(f.gid ?? 0)) ? 3 : 0;
    return !(want & ~((f.mode >> cls) & 7));
  }
  statPath(path2, sp, followLinks = true) {
    if (path2 === '/proc/self/exe') { this.putStat(sp, { size: 1, mode: 0o100755 }); return 0n; }
    if (path2 === '/dev/hostcall') { this.putStat(sp, { size: 0, mode: 0o020666 }); return 0n; }   // so `[ -e /dev/hostcall ]` and os.path.exists() say yes
    if (path2 === '/dev/walios-snapshot') { this.putStat(sp, { size: 0, mode: 0o020222 }); return 0n; }
    if (isProcPath(path2)) {
      const n = procNode(this, path2, followLinks);
      if (!n) return err(E.NOENT);
      if (n.kind === 'redirect') return this.statPath(n.path, sp, followLinks);
      this.putStat(sp, procStat(n)); return 0n;
    }
    // lstat still resolves the PARENT components (only the final one is left alone), and
    // the OPFS fault-in has to happen on the resolved path -- `ls /files/` stats each
    // entry as /files/<name> with lstat, which used to miss everything behind the link.
    path2 = followLinks ? this.follow(path2) : this.followDir(path2);
    opfsFault(path2);
    if (dirs.has(path2)) { if (!dirMtimes.has(path2)) dirTouch(path2); const ow = dirOwners.get(path2);
      this.putStat(sp, { size: 4096, mode: 0o040000 | (dirModes.has(path2) ? dirModes.get(path2) : 0o755), ino: inoOf(path2), mtimeMs: dirMtimes.get(path2), uid: ow ? ow.uid : 0, gid: ow ? ow.gid : 0 }); return 0n; }
    let f = files.get(path2); if (!f) return err(E.NOENT);
    if (f.sym !== undefined) { this.putStat(sp, { size: f.sym.length, mode: 0o120777, ino: inoOf(f), mtimeMs: f.mtimeMs, uid: f.uid ?? 0, gid: f.gid ?? 0 }); return 0n; }
    if (f.mtimeDirty) { opfsSettleMtime(f, path2); f = files.get(path2) || f; }
    this.putStat(sp, { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs, uid: f.uid ?? 0, gid: f.gid ?? 0, ino: inoOf(f), nlink: f.nlinkRef ? f.nlinkRef.n : 1 });
    return 0n;
  }
  openAt(path2, flags, mode) {
    const O_CREAT = 0o100, O_TRUNC = 0o1000, O_APPEND = 0o2000, O_DIRECTORY = 0o200000, O_EXCL = 0o200;
    const ce = !!(flags & 0o2000000); // O_CLOEXEC: dropped from the fd table at execve
    if ((flags & 3) || (flags & (O_CREAT | O_TRUNC))) pyTreeTouch(path2);
    if (path2 === '/proc/self/exe') { const g = this.allocFd(); this.fds.set(g, { exe: true, cloexec: ce }); return BigInt(g); }
    opfsFault(path2);
    if (path2 === '/dev/ptmx') { const id = newPty(); const g = this.allocFd(); this.fds.set(g, { pty: id, master: true, cloexec: ce }); return BigInt(g); }
    if (path2 === '/dev/null') { const g = this.allocFd(); this.fds.set(g, { devnull: true, cloexec: ce }); return BigInt(g); }
    // /dev/stdin, /dev/stdout, /dev/stderr: open() them and you get a DUP of that fd, which
    // is what Linux gives you (they are symlinks into /proc/self/fd). Shell and build glue
    // leans on them constantly -- `cmd > /dev/stdout`, `... < /dev/stdin`, and the
    // "write to stdout by name" idiom autoconf and many Makefiles use -- and here they did
    // not exist at all, so every one of those was a plain ENOENT.
    {
      const stdio = { '/dev/stdin': 0, '/dev/stdout': 1, '/dev/stderr': 2 };
      if (path2 in stdio) {
        const src = this.fds.get(stdio[path2]);
        if (!src) return err(E.BADF);
        const g = this.allocFd();
        // A dup SHARES the open-file description (offset included), which is why this
        // copies the handle by reference rather than making a fresh one -- the same rule
        // the fork/dup2 paths follow.
        this.fds.set(g, { ...src, cloexec: ce });
        this.bumpFifo(src);
        return BigInt(g);
      }
    }
    // /dev/zero and /dev/full. zero reads as endless NULs and swallows writes; full does
    // the same on read but every write fails ENOSPC, which is exactly what it is for --
    // configure scripts and test suites use it to check an out-of-space path.
    if (path2 === '/dev/zero') { const g = this.allocFd(); this.fds.set(g, { devzero: true, cloexec: ce }); return BigInt(g); }
    if (path2 === '/dev/full') { const g = this.allocFd(); this.fds.set(g, { devzero: true, devfull: true, cloexec: ce }); return BigInt(g); }
    // /dev/hostcall: the guest<->host RPC channel that does NOT ride stdio. The old channel
    // (frames on fd 1, replies on fd 0) broke the moment a program was piped or fed a
    // heredoc: `python3 -c "import matplotlib" | head` sent its bundle request into the
    // pipe and waited for a reply on stdin that went to the shell. Each open() is an
    // independent channel; write one request per line, read one reply line back.
    if (path2 === '/dev/hostcall') { const g = this.allocFd(); this.fds.set(g, { hostcall: { inbuf: '', chunks: [], waiters: [] }, cloexec: ce }); return BigInt(g); }
    // A snapshot builder writes here to be copied (see pySnapCapture).
    if (path2 === '/dev/walios-snapshot') { const g = this.allocFd(); this.fds.set(g, { snapdev: true, cloexec: ce }); return BigInt(g); }
    if (path2 === '/dev/urandom' || path2 === '/dev/random' || path2 === '/dev/hwrng') { const g = this.allocFd(); this.fds.set(g, { devrandom: true, cloexec: ce }); return BigInt(g); }
    // /dev/tty = the process's CONTROLLING terminal. ssh (and sudo, passwd, git) read
    // prompts here, NOT from stdin — so without this an unknown-host "yes/no" or a
    // password prompt can't be answered and the tool fails outright.
    if (path2 === '/dev/tty') { let ptyId = this.ctty;
      if (ptyId === undefined) for (const fd of [0, 1, 2]) { const h0 = this.fds.get(fd); if (h0 && h0.pty !== undefined) { ptyId = h0.pty; break; } }
      if (ptyId === undefined || ptyId === null) ptyId = termPty;
      if (ptyId !== undefined && ptyId !== null && ptys.has(ptyId)) { const g = this.allocFd(); this.fds.set(g, { pty: ptyId, master: false, cloexec: ce }); return BigInt(g); }
      return err(E.NXIO); }
    { const m = path2.match(/^\/dev\/pts\/(\d+)$/); if (m) { const id = +m[1]; if (!ptys.has(id)) return err(E.NOENT); ptys.get(id).fg = this; const g = this.allocFd(); this.fds.set(g, { pty: id, master: false, cloexec: ce }); return BigInt(g); } }
    if (isProcPath(path2)) {      // read-only, generated now (see procNode)
      const n = procNode(this, path2, true);
      if (!n) return err((flags & O_CREAT) ? E.ACCES : E.NOENT);
      if (n.kind === 'redirect') return this.openAt(n.path, flags, mode);
      if ((flags & 3) || (flags & (O_CREAT | O_TRUNC))) return err(E.ACCES);
      if (n.kind !== 'dir' && (flags & O_DIRECTORY)) return err(E.NOTDIR);
      const g = this.allocFd();
      if (n.kind === 'dir') { this.fds.set(g, { path: n.path, dir: true, proc: true, cloexec: ce }); return BigInt(g); }
      const data = benc(n.text);   // /proc/<pid>/cmdline, environ: the argv/env bytes
      this.fds.set(g, { path: n.path, file: { data, size: data.length, mode: 0o100444, uid: n.uid, gid: n.uid, mtimeMs: Date.now() }, off: { v: 0 }, append: false, cloexec: ce });
      return BigInt(g);
    }
    // O_NOFOLLOW: a symlink as the LAST component is ELOOP (git opens .gitattributes, .gitignore and
    // .mailmap that way so an in-tree symlink cannot point them outside the repo). It was followed.
    if (flags & 0o400000) { const lp = this.followDir(path2); opfsFault(lp); const lf = files.get(lp); if (lf && lf.sym !== undefined) return err(40); }
    // O_CREAT|O_EXCL never follows a final symlink: the name exists, EEXIST -- even a dangling
    // link. It was followed and the TARGET created: git apply --reject's .rej went through a
    // planted symlink into the file it pointed at (t4115), exactly what O_EXCL is there to stop.
    if ((flags & O_CREAT) && (flags & O_EXCL)) { const lf = files.get(this.followDir(path2));   // no opfsFault: for a missing name it re-lists the directory (every exclusive create -- git gc ran 60% slower); opfsFault(path2) at the top already listed it
      if (lf && lf.sym !== undefined) return err(E.EXIST); }
    path2 = this.follow(path2);   // a symlink to a directory (/files -> /root) opens the directory it points at
    opfsFault(path2);             // ...and the fault-in must be on the RESOLVED path
    // A directory opened for writing (or truncated) is EISDIR on Linux; it opened as a directory
    // fd, so the write silently went nowhere -- git format-patch "wrote" a cover letter onto a
    // directory and exited 0 (t4014).
    if (dirs.has(path2) && ((flags & 3) || (flags & O_TRUNC))) return err(E.ISDIR);
    if (dirs.has(path2)) { const g = this.allocFd(); this.fds.set(g, { path: path2, dir: true, cloexec: ce }); return BigInt(g); }
    if (flags & O_DIRECTORY) {   // POSIX: a MISSING dir is ENOENT, not ENOTDIR (git index-pack scans objects/XX and treats ENOTDIR as fatal)
      if (files.has(path2)) return err(E.NOTDIR);                                   // path exists as a file
      const _par = path2.slice(0, path2.lastIndexOf('/')) || '/';
      return err(dirs.has(_par) ? E.NOENT : E.NOTDIR);                              // missing under a real dir -> ENOENT; parent not a dir -> ENOTDIR
    }
    path2 = this.follow(path2);
    let f = files.get(path2);
    if (f && pendingLinks.size && (f.pendingFrom || (flags & 3) || (flags & O_TRUNC))) { linkFlushPath(path2); f = files.get(path2); }
    if (f && f.sym === undefined) {   // existing regular file: enforce rw bits
      const acc = flags & 3, want = (acc !== 1 ? 4 : 0) | (acc !== 0 ? 2 : 0);
      if (!this.mayAccess(f, want)) return err(E.ACCES);
    }
    if (f && f.fnode) {               // a named pipe: an end of its shared pipe (see fifoOpen)
      const g = this.allocFd();
      this.fds.set(g, { ...fifoOpen(f, flags & 3), cloexec: ce, nonblock: !!(flags & 0o4000) });
      return BigInt(g);
    }
    if (!f) {
      if (!(flags & O_CREAT)) return err(E.NOENT);
      // The parent directory must exist: O_CREAT makes the file, never its directories (addFile
      // would mkdir -p them). mkstemp("nodir/tXXXXXX") succeeded instead of ENOENT (t0070).
      { const par = path2.slice(0, path2.lastIndexOf('/')) || '/';   // (opfsFault(path2) above has listed it)
        if (!dirs.has(par)) return err(files.has(par) ? E.NOTDIR : E.NOENT); }
      addFile(path2, new Uint8Array(0), 0o100000 | ((mode || 0o666) & ~this.umask & 0o7777));
      f = files.get(path2);
      f.uid = this.cred.euid; f.gid = this.cred.egid;
      // In the in-process engine the bridge create below restarts this syscall (NeedAsync);
      // the replay must not find the entry added just above, or O_CREAT|O_EXCL (mutool's
      // output, mkstemp) fails EEXIST on its own file: take it back before the restart.
      if (inOpfs(path2)) { f.br = opfsRel(path2); f.data = null;
        // O_CREAT|O_EXCL is decided AT THE STORAGE LAYER: the worker answers EEXIST when the
        // file is already there (its serialized request loop makes check-and-create atomic),
        // so a lock file git took in another tab's kernel is honoured here too. The replay
        // after NeedAsync consumes the SAME cached answer (same bridge key), so the worker
        // sees the request exactly once.
        try { if (!opfsHandle(f, true, !!(flags & O_EXCL)) && opfsOpenErr === E.EXIST) { rmEntry(path2); return err(E.EXIST); } }
        catch (e) { if (e instanceof NeedAsync) rmEntry(path2); throw e; }   // new files under the mount persist
        if ((f.mode & 0o7777) !== (OPFS_DEFAULT_MODE & 0o7777)) opfsSaveMode(f); }   // ...and so does a 0600 asked for at create (ssh-keygen)
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) return err(E.EXIST);
    if (flags & O_TRUNC) {
      if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, 0, 0, null); f.ownWrite = true; f.mtimeMs = Date.now(); }
      else f.data = new Uint8Array(0);
      f.size = 0;
    }
    const g = this.allocFd();
    // `off` is a shared cell (the POSIX "open file description" offset). dup/dup2/F_DUPFD and
    // fork copy the handle with `{...h}`, which copies `off` BY REFERENCE — so all those fds
    // share ONE file offset. Storing the offset as a bare number would give each a private copy,
    // which corrupts `{ echo a; cmd|cmd; echo b; } > file` (forked writers clobber each other).
    this.fds.set(g, { path: path2, file: f, off: { v: (flags & O_APPEND) ? f.size : 0 }, append: !!(flags & O_APPEND), cloexec: ce, acc: flags & 3 });
    return BigInt(g);
  }
  // Only the thread that called fork() is "in the child": its fork() returned 0 and it is
  // running the child branch until execve/_exit. A sibling thread's syscalls -- git's
  // sideband demuxer exiting while the main thread spawns index-pack -- used to count as
  // the child's: the thread's exit(0) was taken for the child's _exit and closed the
  // window, so the main thread's execve then replaced the PARENT. git fetch turned into
  // index-pack, read the shell's stdin and died with "fatal: early EOF" on every
  // deepening fetch of a shallow clone (a race: whichever finished first).
  inChild() { const cs = this.childStack; return cs.length > 0 && cs[cs.length - 1].tid === (this.curTid || 0); }
  parkChild(fill) {
    const ctx = this.childStack.pop();
    // The child branch ran on a COPY of the fd table, with a ref taken on every pipe
    // end it inherited (see sys 'fork'). An exec HANDS that copy to the new image,
    // which releases it when it finishes — but a child that merely EXITS was dropping
    // the copy on the floor, so each pipe end kept a phantom writer for ever and the
    // reader never saw EOF. That is why `git clone ... | tail` hung: git forks
    // children that exit without exec'ing, and every one of them left the pipe to
    // `tail` looking like it still had a writer.
    if (!fill.exec) releaseFds(ctx.fds);
    this.unVfork(ctx);
    if (!fill.exec) addZombie(ctx.pid, this, this.pgid);       // an exec'd child is a live process, not a zombie
    this.pending.push({ pid: ctx.pid, ...fill });
    // The window is closed: this process is the PARENT again, so anything the child sent it
    // is deliverable now (see 'kill' above).
    if (this.sigQueuedForParent && this.sigQueuedForParent.length) {
      const q = this.sigQueuedForParent; this.sigQueuedForParent = [];
      for (const sg of q) postSignal(this, sg);
    }
    return CHILD_DONE;
  }
  // The child branch ran in this process (vfork protocol, see sys 'fork'): give the
  // parent back the cwd, umask and signal state it had before fork().
  unVfork(_ctx) { /* nothing to put back: the child branch only ever touched its own view (see _win) */ }

  sys(name, a) {
    const S = this;
    switch (name) {
      case 'read': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.file && h.acc === 1) return err(E.BADF);   // O_WRONLY
        if (h.std !== undefined) { if (h.std !== 0) return err(E.BADF);
          const b = drainStdinAsync(a[2]); if (b === null) return h.nonblock ? err(E.AGAIN) : 0n; S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.fifo) { if (!h.fifo.chunks.length && h.nonblock && !fifoEOF(h.fifo)) return err(E.AGAIN); const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.spair) { if (!h.spair.rd.chunks.length && h.nonblock && h.spair.rd.writers > 0) return err(E.AGAIN); const b = pipeRead(h.spair.rd, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.hostcall) { if (!h.hostcall.chunks.length) return err(E.AGAIN); const b = pipeRead(h.hostcall, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }   // a blocking read waits in sysAsync
        if (h.devnull) return 0n;
        if (h.devzero) { const n = a[2] | 0; S.wbytes(a[1], new Uint8Array(n)); return BigInt(n); }   // endless NULs
        if (h.devrandom) { const n = a[2] | 0; let done = 0; while (done < n) { const k = Math.min(n - done, 65536); const b = new Uint8Array(k); crypto.getRandomValues(b); S.wbytes(a[1] + done, b); done += k; } return BigInt(n); }
        if (h.tfd) { const t = h.tfd; // timerfd: 8-byte expiration count (a blocking read waits in sysAsync)
          if (!t.count) return err(E.AGAIN);
          if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(t.count)); t.count = 0; return 8n; }
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
          if (!q.length) {
            if (!h.master && p.slaveEof) { p.slaveEof--; return 0n; } // ^D on an empty line = EOF
            return S.sigDelivered ? err(E.INTR) : err(E.AGAIN); } // ^C at this boundary reads as EINTR
          const k = Math.min(q.length, a[2]); S.wbytes(a[1], Uint8Array.from(q.splice(0, k))); return BigInt(k); }
        if (h.sock) { const br = initWisp(); if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); } const r = br.call(h.sock.udp ? br.OP.RECVFROM : br.OP.RECV, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res)); return BigInt(r.res); }
        if (h.dir) return err(E.ISDIR);
        if (!h.file) return err(E.BADF);
        const b = fileRead(h.file, h.off.v, a[2]); { const ie = ioFailed(); if (ie) return err(ie); } S.wbytes(a[1], b); h.off.v += b.length; return BigInt(b.length);
      }
      case 'write': { if ((a[2] | 0) < 0) return err(E.INVAL); // guard: negative size must not slice from the end
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.file && h.acc === 0) return err(E.BADF);   // O_RDONLY: was written anyway
        S.refresh();
        if (h.std !== undefined) { const sfd = h.std === 0 ? 1 : h.std; post(stdDec(sfd).decode(S.u8.slice(a[1], a[1] + a[2]), { stream: true }), sfd); return BigInt(a[2]); }
        if (h.snapdev) { const why = pySnapCapture(S, a[0], td.decode(S.u8.slice(a[1], a[1] + a[2]))); if (why) { if (pySnapDebug(S)) post('[snapshot] refused: ' + why + '\n', 2); return err(E.INVAL); } return BigInt(a[2]); }
        if (h.fifo) { if (fifoNoReader(h.fifo)) { postSignal(S, SIG.PIPE); return err(E.PIPE); } // no reader will ever come back: SIGPIPE (dfl kills) + EPIPE
          // POSIX: a 0-length write to a pipe transfers nothing and has no effect.
          // Pushing an empty chunk woke the reader, which read 0 bytes and took it
          // for EOF -- a writer that probed with write(fd, p, 0) silently killed its
          // own pipeline.
          if (a[2] === 0) return 0n;
          h.fifo.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.fifo); return BigInt(a[2]); }
        if (h.spair) { if (h.spair.wr.readers <= 0) { postSignal(S, SIG.PIPE); return err(E.PIPE); } // peer end closed
          if (a[2] === 0) return 0n;                                   // same rule as the pipe above
          h.spair.wr.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.spair.wr); return BigInt(a[2]); }
        if (h.devnull) return BigInt(a[2]);
        if (h.devfull) return err(E.NOSPC);      // the whole point of /dev/full
        if (h.devzero) return BigInt(a[2]);
        if (h.hostcall) { hostcallWrite(h.hostcall, S.u8.slice(a[1], a[1] + a[2])); return BigInt(a[2]); }
        if (h.devrandom) return BigInt(a[2]);
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const b = S.u8.slice(a[1], a[1] + a[2]); if (h.master) ptyMasterWrite(p, b); else ptySlaveWrite(p, b); return BigInt(a[2]); }
        if (h.sock) { const br = initWisp(); const r = br.call(br.OP.SEND, h.sock.id, a[2], 0, S.u8.slice(a[1], a[1] + a[2])); return BigInt(r.res); }
        if (!h.file) return err(E.BADF);
        const w = fileWrite(h.file, h.append ? h.file.size : h.off.v, S.u8.slice(a[1], a[1] + a[2])); { const ie = ioFailed(); if (ie) return err(ie); } h.off.v += w; return BigInt(w);
      }
      case 'writev': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('write', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; } return t; }
      case 'readv': {
        { const h0 = S.fds.get(a[0]); if (h0 && h0.file && h0.acc === 1) return err(E.BADF); }   // O_WRONLY
        // A regular file is read in ONE fileRead for all the buffers, then scattered: the
        // per-buffer loop below moved the offset and wrote guest memory after the first
        // buffer, and in the in-process engine the second buffer's bridge read restarts the
        // whole syscall (NeedAsync) -- the replay then read from the moved offset. musl's
        // stdio reads files with a 2-buffer readv, so mutool saw shifted bytes and a false
        // EOF on any /root file bigger than its first read (2026-11-09, Android/no isolation).
        { const h = S.fds.get(a[0]);
          if (h && h.file && !h.dir && h.std === undefined && !h.fifo && !h.spair && !h.sock && h.pty === undefined && !h.hostcall && !h.tfd && !h.devnull && !h.devzero && !h.devrandom) {
            const iov = []; let total = 0;
            for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (l) { iov.push([p, l]); total += l; } }
            const b = fileRead(h.file, h.off.v, total); { const ie = ioFailed(); if (ie) return err(ie); }
            let done = 0;
            for (const [p, l] of iov) { if (done >= b.length) break; const k = Math.min(l, b.length - done); S.wbytes(p, b.subarray(done, done + k)); done += k; }
            h.off.v += b.length; return BigInt(b.length);
          } }
        let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('read', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; if (Number(r) < l) break; } return t; }
      case 'pread64': case 'pread': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); if (!h.file) return err(E.SPIPE); if (h.acc === 1) return err(E.BADF);
        const b = fileRead(h.file, Number(a[3]), a[2]); { const ie = ioFailed(); if (ie) return err(ie); } S.wbytes(a[1], b); return BigInt(b.length); }   // positional read, does NOT move the fd offset (git reads packs this way)
      case 'pwrite64': case 'pwrite': { const h = S.fds.get(a[0]); if (!h || !h.file || h.acc === 0) return err(E.BADF);
        const w = fileWrite(h.file, Number(a[3]), S.u8.slice(a[1], a[1] + a[2])); { const ie = ioFailed(); if (ie) return err(ie); } return BigInt(w); }   // a failed write was a silent 0
      case 'open': return S.openAt(S.atPath(-100, S.cstr(a[0])), a[1], a[2]);
      case 'openat': return S.openAt(S.atPath(a[0], S.cstr(a[1])), a[2], a[3]);
      case 'close': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fifo) { fifoDrop(h); if (h.alsoW) fifoDrop({ fifo: h.fifo, end: 'w' }); S.fds.delete(a[0]); return 0n; }
        if (h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.tfd) { if (h.tfd.to) clearTimeout(h.tfd.to); const w = h.tfd.waiters; h.tfd.waiters = []; for (const f of w) f('t'); S.fds.delete(a[0]); return 0n; }
        // a dup'd/forked socket fd shares ONE wisp stream — only an unshared close may
        // tear it down, or a child's close_range kills the parent's live connection.
        // Closing a local listener frees the port, or the next bind of it would get a
        // (this time genuine) EADDRINUSE from a listener nobody can reach any more.
        if (h.sock && h.sock.local && h.sock.listener && !h.shared
            && localListeners.get(h.sock.local.port) === h.sock.local) localListeners.delete(h.sock.local.port);
        else if (h.sock && h.sock.listener) { S.fds.delete(a[0]); listenerSweepSoon(); }   // shared: free it once nobody holds it
        if (h.sock && h.sock.id && !h.shared) initWisp().call(initWisp().OP.CLOSE, h.sock.id, 0, 0);
        S.fds.delete(a[0]); S.dirState.delete(a[0]);
        if (h.file && lockTab.has(h.file)) { const f0 = h.file, me = S.selfPid, ofd = h.off;
          lockDrop((f, l) => f === f0 && ((l.kind === 'posix' && l.owner === me) || (l.kind !== 'posix' && l.owner === ofd && !ofdLive(ofd)))); }
        if (h.file && h.file.brId) opfsMaybeRelease(h.file);   // last fd gone -> give the OPFS lock back
        return 0n; }
      case 'lseek': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock || h.pty !== undefined || h.devnull || h.devrandom || h.devzero) return err(E.SPIPE);
        const size = h.file ? h.file.size : 0; const o = (h.off ??= { v: 0 });
        o.v = a[2] === 0 ? Number(a[1]) : a[2] === 1 ? o.v + Number(a[1]) : size + Number(a[1]);
        return BigInt(o.v); }
      case 'fstat': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.pty !== undefined) { S.putStat(a[1], ptyStatObj(h.pty, h.master)); return 0n; }
        if (h.devnull) { S.putStat(a[1], { size: 0, mode: 0o020620 }); return 0n; }
        if (h.devzero) { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        if (h.devrandom) { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        if (h.std !== undefined || h.fifo || h.sock || h.spair) { S.putStat(a[1], { size: 0, mode: (h.fifo || h.sock || h.spair) ? 0o010600 : 0o020620 }); return 0n; }
        if (h.exe) { S.putStat(a[1], { size: 1, mode: 0o100755 }); return 0n; }
        // An open OPFS-backed file: stat THE FILE (not whatever its path names now) with its
        // CURRENT size from the bridge -- another tab may have rewritten or replaced it, and
        // git mmaps exactly st_size bytes (see the bridge's STAT).
        if (h.file && h.file.br !== undefined && h.file.sym === undefined) {
          const f = h.file, id = opfsHandle(f);
          // A size the bridge reported moments ago (the OPEN just before -- git's open+fstat) is
          // current: skip the round trip. Only an fd whose size is older asks again.
          if (f.mtimeDirty) opfsSettleMtime(f, h.path);
          if (id && !(Date.now() - (f.sizeAt || 0) < 25)) { const r = initOpfs().call(OFS.STAT, id, 0, 0, null); if (r.res >= 0) { const ab = auxBig(r); if (ab > 0) { f.size = ab - 1; f.sizeAt = Date.now(); } } }
          S.putStat(a[1], { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs, uid: f.uid ?? 0, gid: f.gid ?? 0, ino: inoOf(f), nlink: f.nlinkRef ? f.nlinkRef.n : 1 });
          return 0n;
        }
        return S.statPath(h.path, a[1]); }
      case 'stat': case 'lstat': { const p = S.atPath(-100, S.cstr(a[0])); let m;
        if (p === '/dev/ptmx') { S.putStat(a[1], ptyStatObj(0, true)); return 0n; }
        if ((m = p.match(/^\/dev\/pts\/(\d+)$/))) { if (!ptys.has(+m[1])) return err(E.NOENT); S.putStat(a[1], ptyStatObj(+m[1], false)); return 0n; }
        if (p === '/dev/null' || p === '/dev/tty' || p === '/dev/urandom' || p === '/dev/random'
            || p === '/dev/zero' || p === '/dev/full' || p === '/dev/stdin' || p === '/dev/stdout' || p === '/dev/stderr')
          { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        return S.statPath(p, a[1], name === 'stat'); }
      // flags (a[3]) & AT_SYMLINK_NOFOLLOW (0x100) is lstat: musl's lstat() is fstatat(AT_FDCWD,
      // path, st, AT_SYMLINK_NOFOLLOW). This followed links regardless, so an rsync'd symlink
      // whose target was not copied yet "failed to stat" (ENOENT). busybox calls SYS_lstat.
      case 'newfstatat': { const s = S.cstr(a[1]); return s === '' ? S.sys('fstat', [a[0], a[2]]) : S.statPath(S.atPath(a[0], s), a[2], !((a[3] | 0) & 0x100)); }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        if (isProcPath(p)) {
          const n = procNode(S, p, true); if (!n) return err(E.NOENT);
          const want = (name === 'access' ? (a[1] | 0) : (a[2] | 0)) & 6;
          if (n.kind !== 'redirect') return (want & 2) ? err(E.ACCES) : 0n;   // /proc itself is read-only
          // left /proc (/proc/self/cwd/x, a followed fd link): the ordinary check on the real path
          opfsFault(n.path); const rf = S.follow(n.path);
          if (dirs.has(rf)) return 0n;
          const f = files.get(rf); if (!f) return err(E.NOENT);
          return (!want || S.mayAccess(f, want)) ? 0n : err(E.ACCES);
        }
        if (p === '/dev/null' || p === '/dev/tty' || p === '/dev/ptmx' || p === '/dev/urandom' || p === '/dev/random'
            || p === '/dev/zero' || p === '/dev/full' || p === '/dev/stdin' || p === '/dev/stdout' || p === '/dev/stderr')
          return 0n; // devices exist (scripts' `test -e`)
        { const m = p.match(/^\/dev\/pts\/(\d+)$/); if (m) return ptys.has(+m[1]) ? 0n : err(E.NOENT); }
        opfsFault(p); const pf = S.follow(p);
        const want = (name === 'access' ? (a[1] | 0) : (a[2] | 0)) & 7;
        if (dirs.has(pf)) return 0n;
        const f = files.get(pf); if (!f) return err(E.NOENT);
        // X_OK on a regular file needs an execute bit -- for root too (Linux: root passes X_OK
        // only if SOME x bit is set). git skips a hook that is not executable ("hook was ignored
        // because it's not set as executable"); with X_OK always true it ran it (t7503, t7504).
        if ((want & 1) && f.sym === undefined && !((f.mode ?? 0o100644) & 0o111)) return err(E.ACCES);
        return (!want || S.mayAccess(f, want)) ? 0n : err(E.ACCES); }
      case 'readlink': case 'readlinkat': { const p = S.atPath(name === 'readlink' ? -100 : a[0], S.cstr(name === 'readlink' ? a[0] : a[1]));
        const lbuf = name === 'readlink' ? a[1] : a[2], llen = name === 'readlink' ? a[2] : a[3];
        // readlink: copy at most llen bytes, NO NUL terminator, return the count
        const put = (str) => { const b = te.encode(str); const n = Math.min(b.length, llen); S.wbytes(lbuf, b.subarray(0, n)); return BigInt(n); };
        opfsFault(p); const lf = files.get(p);
        if (lf && lf.sym !== undefined) return put(lf.sym);
        if (p === '/proc/self/exe') return put('/bin/' + (S.argv[0] || 'wasm'));
        let m2; if ((m2 = p.match(/^\/proc\/self\/fd\/(\d+)$/))) { const h = S.fds.get(+m2[1]); if (!h) return err(E.BADF);
          return put(h.pty !== undefined ? (h.master ? '/dev/ptmx' : '/dev/pts/' + h.pty) : h.path ? h.path : h.std !== undefined ? '/dev/tty' : '/dev/null'); }
        if (isProcPath(p)) { const n = procNode(S, p, false); if (!n) return err(E.NOENT);
          if (n.kind === 'link') return put(n.target);
          if (n.kind !== 'redirect') return err(E.INVAL);
          opfsFault(n.path); const rl = files.get(n.path);   // /proc/self/cwd/x: x itself may be a symlink
          if (rl && rl.sym !== undefined) return put(rl.sym); }
        return err(E.INVAL); }
      case 'unlink': return unlinkPath(S, S.atPath(-100, S.cstr(a[0])));
      case 'rmdir': return rmdirPath(S, S.atPath(-100, S.cstr(a[0])));
      // unlinkat(dirfd, path, flags): AT_REMOVEDIR (0x200) = rmdir. It was missing (ENOSYS), and
      // Python's shutil.rmtree deletes through it (os.unlink/os.rmdir with dir_fd): every
      // rmtree failed -- pip's temp-dir cleanup printed "Function not implemented" tracebacks.
      case 'unlinkat': { const p = S.atPath(a[0], S.cstr(a[1])); return (a[2] & 0x200) ? rmdirPath(S, p) : unlinkPath(S, p); }
      case 'mknod': case 'mknodat': {
        // mkfifo(3) is mknod(path, S_IFIFO|mode, 0). Named pipes live in the kernel's file
        // table only (on the mount too: OPFS cannot hold one; a fresh kernel does not see it).
        // A type-less mode makes a regular file, as POSIX says; devices are EPERM, as for a
        // process without CAP_MKNOD.
        const p = name === 'mknod' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        const mode = (name === 'mknod' ? a[1] : a[2]) | 0, fmt = mode & 0o170000;
        if (fmt !== 0o010000 && fmt !== 0 && fmt !== 0o100000) return err(E.PERM);
        const par = p.slice(0, p.lastIndexOf('/')) || '/'; opfsFault(par); opfsFault(p);
        if (!dirs.has(par)) return err(files.has(par) ? E.NOTDIR : E.NOENT);
        if (files.has(p) || dirs.has(p)) return err(E.EXIST);
        const perm = mode & 0o7777 & ~S.umask;
        if (fmt === 0o010000) {
          addFile(p, new Uint8Array(0), 0o010000 | perm);
          const nf = files.get(p); nf.fnode = { pipe: null }; nf.uid = S.cred.euid; nf.gid = S.cred.egid;
          return 0n;
        }
        // regular file: the ordinary create path (OPFS-backed on the mount)
        const fd = S.openAt(p, 0o100 | 0o200 | 1, perm);
        if (fd < 0n) return fd;
        S.sys('close', [Number(fd)]); return 0n; }
      // mkdirat: rsync's receiver makes every directory with it (it was ENOSYS, so `rsync -a`
      // of a tree failed on each subdirectory). Same semantics, relative to a dirfd.
      case 'mkdir': case 'mkdirat': { const p = name === 'mkdir' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1])); opfsFault(p);
        // POSIX: mkdir(2) on an existing path is EEXIST. This used to call mkdirp()
        // straight away, which is idempotent, so the syscall had `mkdir -p` semantics and
        // silently succeeded on a directory that was already there. `mkdir -p` still works:
        // busybox tolerates EEXIST itself, which is exactly how it is meant to be built.
        if (dirs.has(p) || files.has(p)) return err(E.EXIST);
        // ...and in a directory that does not exist it is ENOENT (ENOTDIR under a file): mkdirp
        // made the missing parents too, so `mkdir a/b/c` worked without -p.
        { const par = p.slice(0, p.lastIndexOf('/')) || '/'; if (!dirs.has(par)) return err(files.has(par) ? E.NOTDIR : E.NOENT); }
        mkdirp(p); if (S.cred.euid !== 0 || S.cred.egid !== 0) dirOwners.set(p, { uid: S.cred.euid, gid: S.cred.egid });
        { const want = (name === 'mkdir' ? a[1] : a[2]) & 0o7777 & ~S.umask; if (want !== 0o755) dirSetMode(p, want); else dirModes.set(p, want); }
        // opfsLoaded is a MAP (path -> when we last listed it), not a Set. This said
        // .add(p), which threw TypeError -- and the dispatcher turns ANY handler exception
        // into -1, so every mkdir in the workspace reported EPERM "Operation not permitted"
        // while having actually SUCCEEDED (the directory was there afterwards, which is what
        // made it so confusing). It broke `tar x` into /root, `mkdir -p`, git clone into a new
        // directory, and `mkdir ~/.ssh`. We just created it and it is empty, so record it as
        // freshly listed rather than force a re-listing.
        if (inOpfs(p) && p !== opfsMount) { const r = opfsPathOp(OFS.MKDIR, opfsRel(p)); if (r < 0) return BigInt(r); opfsLoaded.set(p, Date.now()); }
        return 0n; }
      case 'rename': case 'renameat': case 'renameat2': {
        const pa = name === 'rename' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        const pb = name === 'rename' ? S.atPath(-100, S.cstr(a[1])) : S.atPath(a[2], S.cstr(a[3]));
        opfsFault(pa); opfsFault(pb); pyTreeTouch(pa); pyTreeTouch(pb);
        linkFlushPath(pa); linkFlushPath(pb);   // pending link() copies (see pendingLinks)
        if (!isAppPath(pb) && protectedDelete(S, pa)) return err(E.PERM);   // moving out of the workspace == deleting it
        // the new name keeps the old file's identity: mode (+x!), owner, times, symlink target
        const keepAttrs = (nf, of) => { nf.mode = of.mode; if (of.uid !== undefined) nf.uid = of.uid; if (of.gid !== undefined) nf.gid = of.gid; nf.mtimeMs = of.mtimeMs; if (of.sym !== undefined) nf.sym = of.sym; };
        if (dirs.has(pa)) {                              // directory rename: re-key the whole subtree
          if (files.has(pb)) return err(E.NOTDIR);
          if (pb === pa) return 0n;                     // POSIX: a name onto itself does nothing
          if (pb.startsWith(pa + '/')) return err(E.INVAL);
          if (dirs.has(pb) && dirs.get(pb).size) return err(E.NOTEMPTY);
          const opa = inOpfs(pa), opb = inOpfs(pb);
          if (opa !== opb || pa === opfsMount || pb === opfsMount) return err(E.XDEV); // RAM<->OPFS: mv copies
          if (opa) {
            // OPFS -> OPFS: the bridge moves every file by handle (no copying), crash-safe via
            // its rename journal. EXDEV only when the tree holds cloud-only files (mv then
            // copies them through the store, downloading them, as before).
            const r = opfsPathOp(OFS.RENAMEDIR, opfsRel(pa), opfsRel(pb));
            if (r < 0) return BigInt(r);
            for (const k of [...opfsLoaded.keys()]) if (k === pa || k.startsWith(pa + '/') || k === pb || k.startsWith(pb + '/')) opfsLoaded.delete(k);
          }
          rmEntry(pb);
          const paParent = pa.slice(0, pa.lastIndexOf('/')) || '/';
          const pd = dirs.get(paParent); if (pd) pd.delete(pa.slice(pa.lastIndexOf('/') + 1));
          for (const [k, v] of [...files]) if (k.startsWith(pa + '/')) { files.delete(k); const nk = pb + k.slice(pa.length); files.set(nk, v); if (v.br !== undefined) v.br = opfsRel(nk); }
          for (const [k, v] of [...dirs]) if (k === pa || k.startsWith(pa + '/')) { dirs.delete(k); dirs.set(pb + k.slice(pa.length), v); }
          const pbParent = pb.slice(0, pb.lastIndexOf('/')) || '/'; mkdirp(pbParent);
          dirs.get(pbParent).add(pb.slice(pb.lastIndexOf('/') + 1));
          return 0n; }
        const f = files.get(pa); if (!f) return err(E.NOENT);
        if (dirs.has(pb)) return err(E.ISDIR);           // a file onto a directory (was EEXIST from the store)
        if (pb === pa) return 0n;
        if (f.br !== undefined && inOpfs(pb)) {          // OPFS -> OPFS: rename in the store
          const r = opfsPathOp(OFS.RENAME, f.br, opfsRel(pb)); if (r < 0) return BigInt(r);
          rmEntry(pb); rmEntry(pa);
          addFile(pb, new Uint8Array(0)); const nf = files.get(pb);
          nf.br = opfsRel(pb); nf.brId = 0; nf.data = null; nf.size = f.size; keepAttrs(nf, f);
          if ((nf.mode & 0o7777) !== (OPFS_DEFAULT_MODE & 0o7777)) opfsSaveMode(nf); return 0n; }
        if (f.br !== undefined) {                        // OPFS -> RAM: pull bytes out, drop the store copy
          const bytes = fileRead(f, 0, f.size); const r = opfsPathOp(OFS.UNLINK, f.br); if (r < 0) return BigInt(r);
          rmEntry(pb); rmEntry(pa); addFile(pb, bytes.slice()); keepAttrs(files.get(pb), f); return 0n; }
        if (inOpfs(pb)) {                                // RAM -> OPFS: persist into the store
          const bytes = f.data ? f.data.subarray(0, f.size) : new Uint8Array(0);
          rmEntry(pb); rmEntry(pa);
          addFile(pb, new Uint8Array(0)); const nf = files.get(pb);
          nf.br = opfsRel(pb); nf.data = null; nf.size = 0;
          if (!opfsHandle(nf, true)) return err(E.ACCES);
          initOpfs().call(OFS.TRUNC, nf.brId, 0, 0, null);
          fileWrite(nf, 0, bytes); keepAttrs(nf, f);
          if ((nf.mode & 0o7777) !== (OPFS_DEFAULT_MODE & 0o7777)) opfsSaveMode(nf); return 0n; }
        rmEntry(pb); rmEntry(pa);                        // RAM -> RAM
        addFile(pb, f.data || new Uint8Array(0)); const nf = files.get(pb); nf.size = f.size; keepAttrs(nf, f); return 0n; }
      case 'chdir': { let p = S.atPath(-100, S.cstr(a[0]));
        if (isProcPath(p)) { const n = procNode(S, p, true); if (!n) return err(E.NOENT);
          if (n.kind === 'dir') { S.cwd.p = n.path; return 0n; }
          if (n.kind !== 'redirect') return err(E.NOTDIR);
          p = n.path; }                  // cd /proc/self/cwd: into the real directory
        // chdir FOLLOWS the final component too: `cd link` with link -> a directory enters that
        // directory, and the cwd (getcwd, `pwd -P`) is the resolved path, as on Linux. Only the
        // parents were resolved, so every cd into a symlinked directory failed ENOTDIR (git's
        // t2300 cd_to_toplevel; any repo reached through a link).
        p = S.follow(p);
        opfsFault(p); if (!dirs.has(p)) return err(files.has(p) ? E.NOTDIR : E.NOENT); S.cwd.p = p; return 0n; }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': { if (te.encode(S.cwd.p).length + 1 > (a[1] >>> 0)) return err(34);   // ERANGE: was silently truncated
        return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1); }
      case 'chmod': case 'fchmodat': { const p = S.follow(S.atPath(name === 'chmod' ? -100 : a[0], S.cstr(name === 'chmod' ? a[0] : a[1])));
        opfsFault(p); const md = name === 'chmod' ? a[1] : a[2];
        if (dirs.has(p)) { const ow = dirOwners.get(p); if (S.cred.euid !== 0 && (ow ? ow.uid : 0) !== S.cred.euid) return err(E.PERM); dirSetMode(p, md); return 0n; }
        linkFlushPath(p);
        const f = files.get(p); if (!f) return err(E.NOENT);
        if (S.cred.euid !== 0 && (f.uid ?? 0) !== S.cred.euid) return err(E.PERM);
        f.mode = (f.mode & ~0o7777) | (md & 0o7777); opfsSaveMode(f); return 0n; }
      case 'fchmod': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        if (S.cred.euid !== 0 && (h.file.uid ?? 0) !== S.cred.euid) return err(E.PERM);
        h.file.mode = (h.file.mode & ~0o7777) | (a[1] & 0o7777); opfsSaveMode(h.file); return 0n; }
      case 'chown': case 'lchown': case 'fchownat': { const pi = name === 'fchownat' ? 1 : 0, di = name === 'fchownat' ? a[0] : -100;
        const p = S.follow(S.atPath(di, S.cstr(a[pi]))); opfsFault(p);
        if (S.cred.euid !== 0) return err(E.PERM);
        const f = files.get(p); if (!f && !dirs.has(p)) return err(E.NOENT);
        if (f) { const u = a[pi + 1] | 0, g = a[pi + 2] | 0; if (u !== -1) f.uid = u; if (g !== -1) f.gid = g; }
        else { const o = dirOwners.get(p) || { uid: 0, gid: 0 }, u = a[pi + 1] | 0, g = a[pi + 2] | 0; dirOwners.set(p, { uid: u !== -1 ? u : o.uid, gid: g !== -1 ? g : o.gid }); }
        return 0n; }
      case 'fchown': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        if (S.cred.euid !== 0) return err(E.PERM);
        if ((a[1] | 0) !== -1) h.file.uid = a[1] | 0; if ((a[2] | 0) !== -1) h.file.gid = a[2] | 0; return 0n; }
      case 'umask': { const old = S.umask; S.umask = a[0] & 0o777; return BigInt(old); }
      case 'symlink': case 'symlinkat': { const tgt = S.cstr(a[0]);
        const lp = S.atPath(name === 'symlink' ? -100 : a[1], S.cstr(name === 'symlink' ? a[1] : a[2]));
        opfsFault(lp); if (files.has(lp) || dirs.has(lp)) return err(E.EXIST);
        if (inOpfs(lp) && lp !== opfsMount) { const e = opfsSymlink(lp, tgt); if (e) return err(e); }
        addFile(lp, new Uint8Array(0), 0o120777); const lf = files.get(lp);
        if (inOpfs(lp)) { lf.br = opfsRel(lp); lf.data = null; lf.size = te.encode(tgt).length; }
        lf.sym = tgt; lf.uid = S.cred.euid; lf.gid = S.cred.egid; return 0n; }
      case 'link': case 'linkat': { const oi = name === 'link' ? 0 : 1, ni = name === 'link' ? 1 : 3;
        const pa = S.follow(S.atPath(name === 'link' ? -100 : a[0], S.cstr(a[oi])));
        const pb = S.atPath(name === 'link' ? -100 : a[2], S.cstr(a[ni]));
        opfsFault(pa); const f = files.get(pa); if (!f) return err(E.NOENT);
        if (dirs.has(pa)) return err(E.PERM);                       // no links to directories
        opfsFault(pb);
        if (files.has(pb) || dirs.has(pb)) return err(E.EXIST);
        if ((f.br !== undefined) !== inOpfs(pb)) return err(E.XDEV); // RAM <-> the mount: two filesystems
        if (f.br !== undefined) {
          // On the mount: OPFS has no hard links, so the bridge makes a COPY under the new
          // name, mode and mtime included (opfs-worker OP.LINK). git's clone --local and its pack
          // tmp files link objects that never change, which is what this serves; writes through
          // one name are not seen through the other. A bridge without the op (the desktop folder
          // one) answers EINVAL: EPERM then, as a filesystem without links.
          const parent = pb.slice(0, pb.lastIndexOf('/')) || '/';
          opfsFault(parent); if (!dirs.has(parent)) return err(E.NOENT);
          if (!initOpfs()) return err(E.IO);
          if (f.pendingFrom) linkMaterialize(pa);   // a link of a link: the first one becomes real
          dirs.get(parent).add(pb.slice(pb.lastIndexOf('/') + 1));
          // Same inode as the source, in this kernel: git's clone --local checks a fresh link by
          // comparing st_ino/mode/size/uid with the source ("hardlink different from source").
          // A pending alias (pendingLinks above): the copy -- or a rename -- comes later.
          // st_nlink: both names count each other in this kernel (find -links, git's t5605)
          const ref = f.nlinkRef || (f.nlinkRef = { n: 1 }); ref.n++;
          files.set(pb, { br: opfsRel(pb), size: f.size, mtimeMs: f.mtimeMs, opfsM: undefined, data: null, mode: f.mode,
                          linkIno: inoOf(f), pendingFrom: f, nlinkRef: ref, ...(f.uid !== undefined ? { uid: f.uid, gid: f.gid } : {}) });
          pendingLinks.set(pb, { src: f, timer: linkTimer(pb) });
          return 0n;
        }
        const parent = pb.slice(0, pb.lastIndexOf('/')) || '/'; mkdirp(parent);
        dirs.get(parent).add(pb.slice(pb.lastIndexOf('/') + 1));
        (f.nlinkRef || (f.nlinkRef = { n: 1 })).n++;
        files.set(pb, f); return 0n; } // same object: a real hard link
      case 'truncate': { const p = S.follow(S.atPath(-100, S.cstr(a[0]))); opfsFault(p); linkFlushPath(p);
        const f = files.get(p); if (!f) return err(E.NOENT);
        if (!S.mayAccess(f, 2)) return err(E.ACCES);
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, Number(a[1]), 0, null); f.ownWrite = true; f.mtimeMs = Date.now(); }
        f.size = Number(a[1]); return 0n; }
      case 'ftruncate': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF); if (h.acc === 0) return err(E.INVAL);   // Linux: EINVAL for a read-only fd
        const f = h.file; linkFlushFrom(f);
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, Number(a[1]), 0, null); f.ownWrite = true; f.mtimeMs = Date.now(); }
        f.size = Number(a[1]); return 0n; }
      case 'fsync': case 'fdatasync': {
        // A durability barrier for OPFS-backed files: the bridge flushes the file's writer, or
        // (file locked elsewhere, writes in a private copy) tries to save the copy -- EIO if it
        // cannot. A write that failed earlier on this file (port bridge: writes are answered
        // before they land) is reported here too. RAM files have nothing to make durable.
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        const f = h.file;
        if (!f || f.br === undefined || !f.brId) return 0n;
        const br = initOpfs(); if (!br) return err(E.IO);
        const r = br.call(OFS.FSYNC, f.brId, 0, 0, null);
        const late = br.takeErr ? br.takeErr(f.brId) : 0;
        if (late < 0) return err(ioErrno(late));
        if (r.res < 0) return err(ioErrno(r.res));
        return 0n;
      }
      case 'utimensat': case 'utimes': case 'futimesat': { // touch/make set mtimes (atime not modeled)
        const UTIME_NOW = 0x3fffffff, UTIME_OMIT = 0x3ffffffe;
        let f, dirP = null;
        if (name !== 'utimes' && !a[1]) { const h = S.fds.get(a[0]); if (!h || (!h.file && !h.dir)) return err(E.BADF); if (h.dir) dirP = h.path; else f = h.file; } // futimens: NULL path = the fd itself
        else { const p = S.follow(name === 'utimes' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1])));
          opfsFault(p); linkFlushPath(p);
          if (dirs.has(p)) dirP = p;
          else { f = files.get(p); if (!f) return err(E.NOENT); } }
        const tp = name === 'utimes' ? a[1] : a[2];
        let mt = Date.now();
        if (tp) { S.refresh();
          if (name === 'utimes') mt = Number(S.r64(tp + 16)) * 1000 + Number(S.r64(tp + 24)) / 1000; // timeval[1] = mtime
          else { const ns = S.tsNs(tp + 16);                                                         // timespec[1] = mtime
            if (ns === UTIME_OMIT) return 0n;
            if (ns !== UTIME_NOW) mt = Number(S.r64(tp + 16)) * 1000 + ns / 1e6; } }
        // A directory's time was ignored: git's untracked cache (t7063) back-dates directories
        // with chmtime and then expects the change to be seen. Kept in this kernel (dirMtimes).
        if (dirP !== null) { dirMtimes.set(dirP, mt); return 0n; }
        f.mtimeMs = mt;
        // On the mount the time must outlive this kernel's memory: OPFS keeps its own
        // lastModified, which the next listing reported instead (git's cruft packs, prune and
        // repack read object mtimes a test set with chmtime; tar x / touch -d / make stamps).
        // The bridge records it beside the file (opfs-worker MT_KEY); listings then report it,
        // so opfsM -- what this kernel expects the next listing to say -- is that value.
        if (f.br !== undefined && f.sym === undefined) {
          const br = initOpfs();
          if (br) { const ms = Math.max(0, Math.round(mt)), pb = te.encode(f.br);
            try { const r = br.call(OFS.SETMTIME, pb.length, Math.floor(ms / 1000) | 0, ms % 1000, pb); if (r.res >= 0) { f.opfsM = ms; f.ownWrite = false; } } catch (_) {} }
        }
        return 0n; }
      case 'statfs': case 'fstatfs': { const sp2 = a[1]; S.refresh();
        S.u8.fill(0, sp2, sp2 + 120);
        S.i64(sp2, 0x858458f6n); S.i64(sp2 + 8, 4096n); S.i64(sp2 + 16, 1n << 20n);
        S.i64(sp2 + 24, 1n << 19n); S.i64(sp2 + 32, 1n << 19n); S.i64(sp2 + 40, 1n << 16n);
        S.i64(sp2 + 48, 1n << 15n); S.i64(sp2 + 64, 255n); S.i64(sp2 + 72, 4096n); return 0n; }
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true; const g = S.allocFd(); S.fds.set(g, { ...h, cloexec: false }); S.bumpFifo(h); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true;
        if (a[0] !== a[1]) { const old = S.fds.get(a[1]);
          if (old && old.fifo) { fifoDrop(old); if (old.alsoW) fifoDrop({ fifo: old.fifo, end: 'w' }); }
          else if (old && old.spair) { if (--old.spair.wr.writers <= 0) wakePipe(old.spair.wr); old.spair.rd.readers--; }
          S.fds.set(a[1], { ...h, cloexec: name === 'dup3' && !!(a[2] & 0o2000000) }); S.bumpFifo(h); } return BigInt(a[1]); }
      case 'pipe': case 'pipe2': {
        const nb = name === 'pipe2' && !!(a[1] & 0x800);
        const cx = name === 'pipe2' && !!(a[1] & 0o2000000);
        const fifo = mkPipe();
        const r = S.allocFd(); S.fds.set(r, { fifo, end: 'r', nonblock: nb, cloexec: cx });
        const w = S.allocFd(); S.fds.set(w, { fifo, end: 'w', nonblock: nb, cloexec: cx });
        S.i32(a[0], r); S.i32(a[0] + 4, w); return 0n; }
      case 'socketpair': { const nb = !!(a[1] & 0x800), cx = !!(a[1] & 0x80000);
        const f1 = mkPipe(), f2 = mkPipe();
        const A = S.allocFd(); S.fds.set(A, { spair: { rd: f2, wr: f1 }, nonblock: nb, cloexec: cx });
        const B = S.allocFd(); S.fds.set(B, { spair: { rd: f1, wr: f2 }, nonblock: nb, cloexec: cx });
        S.i32(a[3], A); S.i32(a[3] + 4, B); return 0n; }

      case 'fork': case 'vfork': {
        // The vfork protocol of wali-musl. Its fork() is a macro: __wali_fork() -> this
        // syscall, which answers the CHILD pid, then setjmp -> fork() evaluates to 0 and
        // the child branch runs HERE, in the parent, against a copy of the fd table.
        // When that branch reaches execve/_exit we answer CHILD_DONE (0x7e57): the libc
        // wrapper longjmps back to the fork site, which now evaluates to the saved pid,
        // and the parent branch continues. Binaries built with the current toolchain carry
        // this wrapper (git, the remote helpers, python_cxx since its rebuild) -- one that
        // exports asyncify_* (busybox) never gets here; its fork is the real, twice-returning one.
        if (PLAIN_MUSL_FORK.test(S.modKey || '') && !S.forkMacro) {
          if (!unknownSyscalls.has('fork:plainmusl')) {
            unknownSyscalls.add('fork:plainmusl');
            post('[host] this binary was linked against the older wali-musl (plain fork(), no Asyncify) -> fork ENOSYS; use the walios shell for subprocess work' + String.fromCharCode(10), 2);
          }
          return err(E.NOSYS);
        }
        const pid = nextPid++;
        const cfds = new Map([...S.fds].map(([k, v]) => { v.shared = true; return [k, { ...v }]; })); // both copies shared: closing one must not tear down the backing socket
        for (const v of cfds.values()) S.bumpFifo(v); // child inherits a ref on each pipe end
        // The child branch runs on the parent's state: chdir/sigaction/sigprocmask/umask
        // in it belong to the child, so snapshot them and put them back at CHILD_DONE.
        // The child's own view of the process state (see _win()): its fd copy, cwd, umask
        // and signal table; pending signals and their waiters stay the process's.
        const psig = S.sig;
        const csig = { handlers: new Map(psig.handlers), mask: psig.mask,
                       get pending() { return psig.pending; }, get waiters() { return psig.waiters; }, set waiters(v) { psig.waiters = v; } };
        S.childStack.push({ pid, fds: cfds, tid: S.curTid || 0, cwd: { p: S.cwd.p }, umask: S.umask, sig: csig, pgid: S.pgid, sid: S.sid });
        return BigInt(pid); }
      // execve is served by the worker loop (a new image on a fresh worker under the same
      // pid); wait4 and every other name in BLOCKING run in sysAsync.
      case 'exit': case 'exit_group': {
        if (S.inChild()) return S.parkChild({ exited: a[0] & 0xff });
        throw new ExitError(a[0], name === 'exit_group'); }
      case 'brk': { S.refresh(); if (!S.heapBrk) S.heapBrk = S.membuf.byteLength;
        if (a[0] === 0 || a[0] <= S.heapBrk) return BigInt(S.heapBrk); return err(E.NOMEM); }
      case 'mmap': {
        const base = S.mmapAlloc(a[1]);
        if (!(a[3] & 0x20)) {
          const h = S.fds.get(a[4]); if (!h || !h.file) return err(E.BADF);
          S.wbytes(base, fileRead(h.file, Number(a[5]), a[1]));
        }
        return BigInt(base); }
      case 'munmap': { S.mmapRelease(a[0] >>> 0, a[1]); return 0n; }
      case 'mprotect': case 'madvise': return 0n;
      case 'mremap': { if (a[2] <= a[1]) return BigInt(a[0]);
        const b = Number(S.sys('mmap', [0, a[2], 3, 0x22, -1, 0n])); S.refresh(); S.u8.copyWithin(b, a[0], a[0] + a[1]); return BigInt(b); }
      case 'shmget': { const key = a[0] | 0, size = a[1] >>> 0, flags = a[2] | 0;
        let seg = key !== 0 ? shmSegs.get(key) : null;
        if (!seg) {
          if (key !== 0 && !(flags & 0o1000)) return err(E.NOENT); // no IPC_CREAT
          seg = { id: nextShmId++, key, buf: new Uint8Array(size), size };
          shmSegs.set(key || -seg.id, seg); shmById.set(seg.id, seg);
        }
        return BigInt(seg.id); }
      case 'shmat': { const seg = shmById.get(a[0] | 0); if (!seg) return err(E.INVAL);
        S.refresh(); const base = S.membuf.byteLength;
        S.memory.grow(Math.ceil(seg.size / PAGE)); S.refresh();
        S.wbytes(base, seg.buf);
        S.shmAt.set(base, { seg, shadow: seg.buf.slice() });
        return BigInt(base); }
      case 'shmdt': { const base = a[0] >>> 0; const at = S.shmAt.get(base); if (!at) return err(E.INVAL);
        S.syncShmOne(base, at); S.shmAt.delete(base); return 0n; }
      case 'shmctl': { if ((a[1] | 0) === 0) { const seg = shmById.get(a[0] | 0); if (seg) { shmById.delete(seg.id); shmSegs.delete(seg.key || -seg.id); } } return 0n; } // IPC_RMID
      case 'getdents64': {
        const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF);
        let st = S.dirState.get(a[0]);
        if (!st) {
          // Re-read the OPFS listing at the start of each enumeration, so entries
          // created by another tab / the host app since we first looked show up
          // (the fault-in cache is once-only and would otherwise be stale).
          if (h.proc) {
            const n = procNode(S, h.path, true);
            const kinds = n && n.kind === 'dir' ? n.names : new Map();
            st = { names: ['.', '..', ...kinds.keys()], kinds, pos: 0 };
          } else {
            if (inOpfs(h.path)) opfsLoadDir(h.path, true, true);
            st = { names: ['.', '..', ...(dirs.get(h.path) || [])], pos: 0 };   // || []: it may have just been found gone
            if (h.path === '/' && !st.names.includes('proc')) st.names.push('proc');
          }
          S.dirState.set(a[0], st);
        }
        let off = 0;
        while (st.pos < st.names.length) {
          const nm = st.names[st.pos]; const nb = te.encode(nm);
          const reclen = (19 + nb.length + 1 + 7) & ~7;
          if (off + reclen > a[2]) break;
          const full = h.path === '/' ? '/' + nm : h.path + '/' + nm;
          const fe = files.get(full);
          const pk = st.kinds && st.kinds.get(nm);
          const type = pk ? (pk === 'dir' ? 4 : pk === 'link' ? 10 : 8)
                     : dirs.has(full) || full === '/proc' || nm === '.' || nm === '..' ? 4 : (fe && fe.sym !== undefined) ? 10 : 8; // DT_DIR/DT_LNK/DT_REG
          S.i64(a[1] + off, 1n); S.i64(a[1] + off + 8, BigInt(st.pos + 1));
          S.refresh(); S.dv.setUint16(a[1] + off + 16, reclen, true); S.u8[a[1] + off + 18] = type;
          S.wbytes(a[1] + off + 19, nb); S.u8[a[1] + off + 19 + nb.length] = 0;
          off += reclen; st.pos++;
        }
        return BigInt(off); }
      case 'ioctl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); S.refresh(); const req = a[1] >>> 0;
        if (req === 0x5421) { const on = S.r32(a[2]) !== 0; h.nonblock = on; if (h.sock) h.sock.nonblock = on; return 0n; } // FIONBIO
        if (req === 0x541b) { let n = 0; // FIONREAD: bytes available to read
          if (h.fifo) n = h.fifo.chunks.reduce((t, c) => t + c.length, 0);
          else if (h.spair) n = h.spair.rd.chunks.reduce((t, c) => t + c.length, 0);
          else if (h.pty !== undefined) { const p = ptys.get(h.pty); n = (h.master ? p.toMaster : p.toSlave).length; }
          else if (h.file) n = Math.max(0, h.file.size - (h.off ? h.off.v : 0));
          else if (h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); n = pk.res > 0 ? pk.res : 0; }
          S.i32(a[2], n); return 0n; }
        if (h.pty !== undefined) { const p = ptys.get(h.pty);
          switch (req) {
            case 0x5401: S.wbytes(a[2], p.termios); return 0n;
            case 0x5402: case 0x5403: case 0x5404: p.termios = S.u8.slice(a[2], a[2] + 60); return 0n;
            case 0x5413: S.dv.setUint16(a[2], p.rows, true); S.dv.setUint16(a[2] + 2, p.cols, true); S.i32(a[2] + 4, 0); return 0n;
            case 0x5414: p.rows = S.dv.getUint16(a[2], true); p.cols = S.dv.getUint16(a[2] + 2, true); return 0n;
            case 0x80045430: S.i32(a[2], h.pty); return 0n;
            case 0x40045431: return 0n;
            case 0x540e: S.ctty = h.pty; return 0n;
            case 0x540f: S.i32(a[2], p.pgrp || S.pid); return 0n;
            case 0x5410: p.pgrp = S.r32(a[2]); return 0n;
            case 0x40045441: { const p2 = ptys.get(h.pty); if (p2) p2.fg = S; const g = S.allocFd(); S.fds.set(g, { pty: h.pty, master: false }); return BigInt(g); }
            default: return 0n;
          } }
        if (h.std === undefined) return err(E.NOTTY);
        if (req === 0x5413) { S.dv.setUint16(a[2], winRows, true); S.dv.setUint16(a[2] + 2, winCols, true); S.i32(a[2] + 4, 0); } // ssh reads local tty size here
        if (req === 0x5401) S.wbytes(a[2], defaultTermios());
        return 0n; }
      case 'fcntl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[1] === 0 || a[1] === 1030) { // F_DUPFD / F_DUPFD_CLOEXEC: arg is a 32-bit int (the
          // minimum fd). musl passes it variadic as a 64-bit long with garbage high bits, so mask
          // to 32 bits — else the dup lands at a bogus fd number and poisons the fd table.
          const min = Number(BigInt.asUintN(32, BigInt(a[2] || 0))); let g = min; while (S.fds.has(g)) g++;
          h.shared = true; S.fds.set(g, { ...h, cloexec: a[1] === 1030 }); S.bumpFifo(h); return BigInt(g);
        }
        if (a[1] === 1) return h.cloexec ? 1n : 0n;                      // F_GETFD
        // F_SETFD / F_SETFL: same 64-bit vararg with garbage high bits. Number() of such a
        // value rounds (doubles carry 53 bits), so `Number(x) & 1` read FD_CLOEXEC as 0 --
        // git's notify pipe then stayed open in the exec'd pack-objects and send-pack waited
        // on it forever (every `git push` hung after the ref negotiation).
        const lo = (x) => Number(BigInt.asUintN(32, BigInt(x || 0)));
        if (a[1] === 2) { h.cloexec = !!(lo(a[2]) & 1); return 0n; }     // F_SETFD (FD_CLOEXEC)
        if (a[1] === 3) return BigInt(2 | (h.nonblock ? 0x800 : 0));
        if (a[1] === 4) { h.nonblock = !!(lo(a[2]) & 0x800); return 0n; }
        if (a[1] === 5 || a[1] === 6 || a[1] === 7 || a[1] === 36 || a[1] === 37 || a[1] === 38) return lockTry(S, 'fcntl', [a[0], a[1], a[2]]);
        return 0n; }
      case 'flock': return lockTry(S, 'flock', a);
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const ms = performance.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt(Math.floor((ms % 1000) * 1e6))); return 0n; }
        // CLOCK_REALTIME with sub-ms resolution, as on Linux: musl's mkdtemp/mkstemp name their
        // retries from tv_nsec, and Date.now()'s whole ms gave all 100 retries in one ms the same
        // name (git's mks_tempfile_dt died "unable to create temp-file: File exists", t4020)
        const ms = nowEpoch(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt(Math.floor((ms % 1000) * 1e6))); return 0n; }
      case 'gettimeofday': { const ms = nowEpoch(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt(Math.floor((ms % 1000) * 1000))); return 0n; }
      case 'clock_getres': { if (a[1]) { S.i64(a[1], 0n); S.i64(a[1] + 8, 1000n); } return 0n; }
      case 'times': { if (a[0]) { S.refresh(); S.u8.fill(0, a[0], a[0] + 4 * S.L); } return BigInt(Math.floor(performance.now() / 10) & 0x7fffffff); }
      case 'setitimer': { const which = a[0] | 0; S.refresh();
        if (a[2]) S.wrItimer(a[2], which);
        if (a[1] && which === 0) {
          const ivMs = S.rLong(a[1], 0) * 1000 + S.rLong(a[1], 1) / 1000;
          const vMs = S.rLong(a[1], 2) * 1000 + S.rLong(a[1], 3) / 1000;
          S.armItimer(0, vMs, ivMs);
        }
        return 0n; }
      case 'getitimer': { if (a[1]) { S.refresh(); S.wrItimer(a[1], a[0] | 0); } return 0n; }
      case 'timerfd_create': { const g = S.allocFd();
        S.fds.set(g, { tfd: { count: 0, deadline: 0, intervalMs: 0, to: null, waiters: [] }, nonblock: !!(a[1] & 0x800) });
        return BigInt(g); }
      case 'timerfd_settime': { const h = S.fds.get(a[0]); if (!h || !h.tfd) return err(E.BADF);
        S.refresh(); const t = h.tfd;
        if (a[3]) { S.wrTs(a[3], t.intervalMs); S.wrTs(a[3] + 16, t.deadline ? Math.max(0, t.deadline - Date.now()) : 0); }
        const ivMs = Number(S.r64(a[2])) * 1000 + S.tsNs(a[2]) / 1e6;
        let vMs = Number(S.r64(a[2] + 16)) * 1000 + S.tsNs(a[2] + 16) / 1e6;
        if ((a[1] & 1) && vMs > 0) vMs -= Date.now();
        if (t.to) { clearTimeout(t.to); t.to = null; }
        t.deadline = 0; t.intervalMs = ivMs; t.count = 0;
        if (vMs > 0) { t.deadline = Date.now() + vMs;
          { const fire = () => { t.count++; const w = t.waiters; t.waiters = []; for (const f of w) f('t');
              if (t.intervalMs > 0) { t.deadline = Date.now() + t.intervalMs; t.to = setTimeout(fire, t.intervalMs); } else { t.deadline = 0; t.to = null; } };
            t.to = setTimeout(fire, vMs); } }
        return 0n; }
      case 'timerfd_gettime': { const h = S.fds.get(a[0]); if (!h || !h.tfd) return err(E.BADF); S.refresh();
        S.wrTs(a[1], h.tfd.intervalMs); S.wrTs(a[1] + 16, h.tfd.deadline ? Math.max(0, h.tfd.deadline - Date.now()) : 0);
        return 0n; }
      case 'uname': { ['Linux', 'wali', '6.1.0-wali', '#1 WALI-browser', 'wasm32', ''].forEach((s, i) => S.wstr(a[0] + i * 65, s, 65)); return 0n; }
      case 'getuid': return BigInt(S.cred.uid); case 'geteuid': return BigInt(S.cred.euid);
      case 'getgid': return BigInt(S.cred.gid); case 'getegid': return BigInt(S.cred.egid);
      case 'setuid': { const u = a[0] | 0;
        if (S.cred.euid === 0) { S.cred.uid = S.cred.euid = S.cred.suid = u; return 0n; }
        if (u === S.cred.uid || u === S.cred.suid) { S.cred.euid = u; return 0n; }
        return err(E.PERM); }
      case 'setgid': { const g = a[0] | 0;
        if (S.cred.euid === 0) { S.cred.gid = S.cred.egid = S.cred.sgid = g; return 0n; }
        if (g === S.cred.gid || g === S.cred.sgid) { S.cred.egid = g; return 0n; }
        return err(E.PERM); }
      case 'setreuid': case 'setresuid': { const ids = name === 'setreuid' ? [a[0] | 0, a[1] | 0, -1] : [a[0] | 0, a[1] | 0, a[2] | 0];
        const ok = (x) => x === -1 || S.cred.euid === 0 || x === S.cred.uid || x === S.cred.euid || x === S.cred.suid;
        if (!ids.every(ok)) return err(E.PERM);
        if (ids[0] !== -1) S.cred.uid = ids[0]; if (ids[1] !== -1) S.cred.euid = ids[1]; if (ids[2] !== -1) S.cred.suid = ids[2];
        return 0n; }
      case 'setregid': case 'setresgid': { const ids = name === 'setregid' ? [a[0] | 0, a[1] | 0, -1] : [a[0] | 0, a[1] | 0, a[2] | 0];
        const ok = (x) => x === -1 || S.cred.euid === 0 || x === S.cred.gid || x === S.cred.egid || x === S.cred.sgid;
        if (!ids.every(ok)) return err(E.PERM);
        if (ids[0] !== -1) S.cred.gid = ids[0]; if (ids[1] !== -1) S.cred.egid = ids[1]; if (ids[2] !== -1) S.cred.sgid = ids[2];
        return 0n; }
      case 'getresuid': { S.i32(a[0], S.cred.uid); S.i32(a[1], S.cred.euid); S.i32(a[2], S.cred.suid); return 0n; }
      case 'getresgid': { S.i32(a[0], S.cred.gid); S.i32(a[1], S.cred.egid); S.i32(a[2], S.cred.sgid); return 0n; }
      case 'getgroups': { const size = a[0] | 0, g = S.cred.groups || [];
        if (size === 0) return BigInt(g.length);
        if (size < g.length) return err(E.INVAL);
        S.refresh(); for (let i = 0; i < g.length; i++) S.i32(a[1] + i * 4, g[i]); return BigInt(g.length); }
      case 'setgroups': { if (S.cred.euid !== 0) return err(E.PERM);
        const n = a[0] | 0; S.refresh(); const g = [];
        for (let i = 0; i < n; i++) g.push(S.r32(a[1] + i * 4));
        S.cred.groups = g; return 0n; }
      case 'chroot': return 0n;
      case 'getpid': return BigInt(S.inChild() ? S.childStack[S.childStack.length - 1].pid : S.pid);
      // ORPHANS REPARENT TO INIT. This returned S.ppid unconditionally, so a child whose
      // parent had already exited still named the DEAD pid -- Linux says 1. It matters
      // because the idiom for "did my parent survive?" is exactly this comparison, and
      // OpenSSH's configure uses it to decide whether to SIGKILL:
      //     pid = getppid(); ... kill(pid, SIGTERM); sleep(1);
      //     if (getppid() == pid) kill(pid, SIGKILL);   /* "parent did not exit, shoot it" */
      // With a stale ppid that test is always true, so the child fires SIGKILL at a pid it
      // no longer owns -- which, once pids are reused, is somebody else's process.
      case 'getppid': { if (S.inChild()) return BigInt(S.pid);
        const pp = S.ppid || 0;
        return BigInt(pp && procs.has(pp) ? pp : 1); }
      case 'gettid': return BigInt(S.curTid || S.pid);
      case 'getpgid': { const q = a[0] | 0; if (!q || q === S.selfPid) return BigInt(S.pgid);
        const T = procs.get(q); if (T) return BigInt(T.pgid);
        const Z = zombies.get(q); return Z ? BigInt(Z.pgid) : err(E.SRCH); }
      case 'getpgrp': return BigInt(S.pgid);
      case 'setpgid': { const q = a[0] | 0, me = S.selfPid; const T = (!q || q === me) ? S : procs.get(q);
        if (!T) return err(E.SRCH); T.pgid = (a[1] | 0) || (T === S ? me : T.pid); return 0n; }
      case 'setsid': { const me = S.selfPid; S.pgid = me; S.sid = me; return BigInt(me); }
      case 'getsid': { const q = a[0] | 0; if (!q || q === S.selfPid) return BigInt(S.sid);
        const T = procs.get(q); return T ? BigInt(T.sid) : err(E.SRCH); }
      case 'set_tid_address': return BigInt(S.curTid || S.pid);
      case 'tkill': case 'tgkill': case 'kill': {
        const sig = name === 'tgkill' ? (a[2] | 0) : (a[1] | 0);
        const pid = name === 'tgkill' ? (a[1] | 0) : (a[0] | 0);
        const isSelf = (q) => q === S.pid || (S.inChild() && S.childStack.some(c => c.pid === q));
        if (!sig) { if (name === 'kill' && pid <= 0) return 0n; return (procs.has(pid) || isSelf(pid) || zombies.has(pid)) ? 0n : err(E.SRCH); }
        const targets = [];
        if (name === 'kill' && pid <= 0) {
          if (pid === -1) { for (const T of procs.values()) if (T !== S) targets.push(T); } // Linux: -1 excludes the caller
          else { const pg = pid === 0 ? S.pgid : -pid; for (const T of procs.values()) if (T.pgid === pg) targets.push(T); }
          if (!targets.length) return [...zombies.values()].some((z) => z.pgid === (pid === 0 ? S.pgid : -pid)) ? 0n : err(E.SRCH);
        } else if (name === 'kill' && S.inChild() && pid === S.pid) {
          // THE CHILD IS SIGNALLING ITS PARENT, and in the vfork protocol both run on THIS
          // Process object -- the child inside the parent's window, the parent suspended at
          // the fork site. Delivering now runs the PARENT's handler in the CHILD's context
          // and consumes the signal, so the parent resumes having never seen it.
          //
          // That is the whole reason OpenSSH's configure hung: its SA_RESTART probe forks,
          // the child kills the parent, and the parent then waits in select(NULL) for a
          // signal the child had already absorbed. Measured: kill(128) from child 136 was
          // "delivering to [128]" -- correct pid, wrong running context.
          //
          // So queue it. parkChild() drains the queue when the window closes, which is
          // exactly when the parent becomes the running context again; predeliver runs at
          // its next syscall entry, so a parked select() returns EINTR as POSIX promises.
          (S.sigQueuedForParent || (S.sigQueuedForParent = [])).push(sig);
          return 0n;
        } else {
          const T = procs.get(pid) || (isSelf(pid) ? S : null);
          if (!T) return zombies.has(pid) ? 0n : err(E.SRCH);          // a zombie accepts and ignores signals
          targets.push(T);
        }
        for (const T of targets) postSignal(T, sig);
        return 0n; }
      case 'rt_sigaction': { const sig = a[0] | 0; S.refresh();
        const old = S.sig.handlers.get(sig);
        if (a[2]) { S.i32(a[2], old ? old.ptr : 0); S.i32(a[2] + 4, old ? old.flags : 0); S.i64(a[2] + 8, 0n); S.i64(a[2] + 16, BigInt.asIntN(64, (old && old.mask) || 0n)); }
        // k_sigaction (verified by dumping a real sigaction call): handler@0, flags@4, sa_mask@16
        if (a[1]) S.sig.handlers.set(sig, { ptr: S.r32(a[1]), flags: S.r32(a[1] + 4), mask: BigInt.asUintN(64, S.r64(a[1] + 16)) });
        return 0n; }
      case 'rt_sigprocmask': { const how = a[0] | 0; S.refresh();
        // Read the new set BEFORE writing the old one: ash's sigprocmask2() passes the SAME
        // buffer for both (block everything, get the old mask back in place). Writing first
        // replaced the guest's fillset with the old mask, so nothing was blocked between
        // its "any SIGCHLD yet?" check and sigsuspend(old) -- a child exiting in that window
        // had its SIGCHLD delivered early, and sigsuspend then waited for a signal that had
        // already been consumed: `sleep 5 & kill $!; wait $!` hung about one run in five.
        const m = a[1] ? BigInt.asUintN(64, S.r64(a[1])) : null;
        if (a[2]) S.i64(a[2], BigInt.asIntN(64, S.sig.mask));
        if (m !== null) { if (how === 0) S.sig.mask |= m; else if (how === 1) S.sig.mask &= ~m; else S.sig.mask = m; }
        return 0n; }
      case 'rt_sigpending': { S.refresh(); let m = 0n; for (const s of S.sig.pending) m |= 1n << BigInt(s - 1); S.i64(a[0], BigInt.asIntN(64, m)); return 0n; }
      case 'prctl': {
        // PR_SET_NAME / PR_GET_NAME: the task name /proc/<pid>/comm and stat show. busybox
        // runs a NOEXEC applet (sleep, yes, ...) in the forked shell WITHOUT exec and names
        // it this way (set_task_comm), which is how pidof / killall / pgrep find it.
        if ((a[0] | 0) === 15) { S.comm = S.cstr(a[1]).slice(0, 15); return 0n; }
        if ((a[0] | 0) === 16) { S.wstr(a[1], S.comm || procComm(S), 16); return 0n; }
        return 0n; }
      case 'sigaltstack': case 'rt_sigreturn': return 0n;
      // Not implemented, ON PURPOSE and quietly: callers try them as a fast path and fall back
      // to read/write on ENOSYS (Python's shutil.copyfile, coreutils cp). As unknown syscalls
      // they printed "unimplemented syscall ... this program may fail" on every file copy.
      case 'sendfile': case 'copy_file_range': return err(E.NOSYS);
      // posix_fadvise / readahead: ADVICE about the page cache, which this kernel does not
      // have. Success without doing anything is what Linux returns for advice it ignores (xz
      // calls fadvise(SEQUENTIAL) on every input; it printed "unimplemented syscall").
      case 'fadvise': case 'fadvise64': case 'readahead': return 0n;
      // Extended attributes: this VFS has none, so EOPNOTSUPP (95), what Linux answers on a
      // filesystem mounted without xattr support. rsync probes lgetxattr at startup; as an
      // unknown syscall it printed "unimplemented syscall" on every run.
      case 'getxattr': case 'lgetxattr': case 'fgetxattr': case 'setxattr': case 'lsetxattr': case 'fsetxattr':
      case 'listxattr': case 'llistxattr': case 'flistxattr': case 'removexattr': case 'lremovexattr': case 'fremovexattr':
        return err(95);
      case 'futex': { const uaddr = a[0] >>> 0, fop = a[1] & 0x7f, val = a[2] | 0;
        S.refresh(); S.syncShm();
        let at = null, base = 0;
        for (const [b, x] of S.shmAt) if (uaddr >= b && uaddr < b + x.seg.size) { at = x; base = b; break; }
        if (fop === 1 || fop === 10) { if (!at) return 0n; // WAKE
          const off = uaddr - base, wl = at.seg.waiters && at.seg.waiters.get(off); let n = 0;
          if (wl) while (wl.length && n < val) { wl.shift()('wake'); n++; } return BigInt(n); }
        if (fop === 0 || fop === 9) { // WAIT: value check only -- a real wait is the guest's own memory.atomic.wait
          if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
          return 0n; }
        return 0n; }
      case 'sched_getaffinity': { S.i64(a[2], 1n); return 8n; }
      case 'sched_yield': return 0n;
      // RLIMIT_NOFILE (res 7) MUST be small: closefrom()/close-all-fds loops up to this
      // limit, so a huge value = millions of close() calls (ssh spun ~8.3M and took ~10s).
      case 'prlimit64': { const res = a[1] | 0, v = res === 7 ? 1024n : 0x800000n; if (a[3]) { S.i64(a[3], v); S.i64(a[3] + 8, v); } return 0n; }
      case 'getrlimit': { const res = a[0] | 0, v = res === 7 ? 1024n : 0x800000n; S.i64(a[1], v); S.i64(a[1] + 8, v); return 0n; }
      case 'setrlimit': return 0n;
      case 'close_range': { const first = a[0] >>> 0, last = a[1] >>> 0;  // close only the OPEN fds in range (O(open), not O(range))
        for (const fd of [...S.fds.keys()]) if (fd >= first && fd <= last) S.sys('close', [fd]); return 0n; }
      // the kernel's rusage = long[18] (two timevals as long pairs, then 14 counters); musl
      // converts the ILP32 one into its 64-bit-time struct
      case 'getrusage': { S.refresh(); S.u8.fill(0, a[1], a[1] + 18 * S.L); return 0n; }
      case 'sysinfo': { // uptime, loads[3], totalram, freeram, ... (unsigned long), procs (u16),
        // pad, totalhigh (11 L), freehigh (12 L), mem_unit (u32, 13 L): 4 GiB total / 2 GiB free
        // in 4 KiB units (an ILP32 unsigned long cannot count 4 GiB of bytes)
        const L = S.L, p = a[0]; S.refresh(); S.u8.fill(0, p, p + 13 * L + 4);
        S.wLong(p, 0, Math.floor((Date.now() - KSTART) / 1000)); S.wLong(p, 4, 1 << 20); S.wLong(p, 5, 1 << 19);   // real uptime, as /proc/uptime
        S.dv.setUint16(p + 10 * L, 1, true); S.dv.setUint32(p + 13 * L, 4096, true);
        return 0n; }
      case 'getrandom': { const b = new Uint8Array(Math.min(a[1], 65536)); crypto.getRandomValues(b); S.wbytes(a[0], b); return BigInt(b.length); }
      // ---- epoll (level-triggered approximation over the same readiness logic).
      // CPython's asyncio picks EpollSelector on linux builds — ENOSYS killed it outright.
      case 'epoll_create': case 'epoll_create1': { const g = S.allocFd();
        S.fds.set(g, { ep: new Map(), cloexec: name === 'epoll_create1' && !!(a[0] & 0x80000) });
        return BigInt(g); }
      case 'epoll_ctl': { const h = S.fds.get(a[0]); if (!h || !h.ep) return err(E.BADF);
        const op = a[1] | 0, fd = a[2] | 0;
        if (op === 2) return h.ep.delete(fd) ? 0n : err(E.NOENT);        // EPOLL_CTL_DEL
        if (!S.fds.has(fd)) return err(E.BADF);
        S.refresh(); const it = { events: S.r32(a[3]), data: S.r64(a[3] + 4) };
        if (op === 1) { if (h.ep.has(fd)) return err(E.EXIST); h.ep.set(fd, it); return 0n; } // ADD
        if (op === 3) { if (!h.ep.has(fd)) return err(E.NOENT); h.ep.set(fd, it); return 0n; } // MOD
        return err(E.INVAL); }
      // SOCK_NONBLOCK in the type argument has to land on the FD as well as on the
      // socket. The blocking-wait guards in sysAsync test h.nonblock, and only
      // ioctl(FIONBIO) was setting that — so a socket born non-blocking (curl does
      // socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP)) still took the
      // waiting path, and recvfrom parked in sockWait instead of returning EAGAIN.
      // On a keep-alive connection nothing more ever arrives, so curl hung there for
      // ever and its own --max-time timer never got to run. `Connection: close` hid
      // it: the server closes, the wait ends, and curl finishes.
      case 'socket': { const dom = a[0] & 0xff, type = a[1] & 0xff, proto = a[2] | 0, nonblock = !!(a[1] & 0x800), cx = !!(a[1] & 0x80000);
        if (dom !== 2 && dom !== 10) return err(E.NOSYS);
        const br = initWisp();
        // ICMP: SOCK_RAW (rawhdr -> recv includes the IP header) or the unprivileged
        // SOCK_DGRAM "ping socket" (IPPROTO_ICMP). Reachability comes from the relay.
        if (type === 3 || (type === 2 && (proto === 1 || proto === 58))) {
          const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, icmp: true, rawhdr: type === 3, v6: dom === 10, nonblock }, cloexec: cx, nonblock }); return BigInt(g); }
        if (type === 2) { const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, udp: true, nonblock }, cloexec: cx, nonblock }); return BigInt(g); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, dom, nonblock }, cloexec: cx, nonblock }); return BigInt(g); }
      case 'bind': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh(); h.sock.bindAddr = readSockaddr(S, a[1]); return 0n; }
      case 'listen': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        const ba = h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        // Loopback/any: keep it in the kernel. See localListeners above for why the relay
        // path cannot serve this (and reported every port as already in use).
        if (isLocalBindIp(ba.ip)) {
          if (!ba.port) return err(E.INVAL);                       // ephemeral port 0: not supported locally
          const prev = localListeners.get(ba.port);
          if (prev && prev !== h.sock.local) return err(E.ADDRINUSE);   // a REAL collision, unlike before
          const L = h.sock.local || { port: ba.port, backlog: [] };
          localListeners.set(ba.port, L);
          h.sock.listener = true; h.sock.local = L; h.sock.boundPort = ba.port;
          return 0n; }
        const br = initWisp(); if (!br.OP.LISTEN) return err(E.NOSYS);
        const r = br.call(br.OP.LISTEN, ba.port, 0, 0);
        if (r.res < 0) return BigInt(r.res);
        h.sock.id = r.res; h.sock.listener = true; h.sock.boundPort = r.aux;
        return 0n; }
      case 'accept': case 'accept4': { const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        if (h.sock.local) {
          const c = h.sock.local.backlog.shift();
          // EAGAIN is how a blocking accept waits here: sysAsync retries it. Same contract
          // the relay accept below documents, so nothing special is needed to park.
          if (!c) return err(E.AGAIN);
          S.refresh();
          if (a[1]) { const n = writeSockaddr(S, a[1], { ip: '127.0.0.1', port: h.sock.local.port }); if (a[2]) S.i32(a[2], n); }
          const g = S.allocFd();
          S.fds.set(g, { spair: c.srv, nonblock: !!(a[3] & 0x800), cloexec: !!(a[3] & 0x80000) });
          return BigInt(g); }
        const br = initWisp();
        const r = br.call(br.OP.ACCEPT, h.sock.id, 1, 0);   // never park here: sysAsync loops on EAGAIN
        if (r.res < 0) return BigInt(r.res);
        S.refresh();
        const [pip, pport] = td.decode(r.data.slice(0, r.aux)).split('|');
        if (a[1]) { const n = writeSockaddr(S, a[1], { ip: pip || '0.0.0.0', port: +pport || 0 }); if (a[2]) S.i32(a[2], n); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, dom: h.sock.dom, nonblock: !!(a[3] & 0x800) }, cloexec: !!(a[3] & 0x80000) });
        return BigInt(g); }
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF); S.refresh();
        const dst = readSockaddr(S, a[1]);
        if (h.sock.udp || h.sock.icmp) { h.sock.dest = dst; return 0n; }
        // A loopback destination is served in here, by whoever is listening on that port.
        // The two ends are an ordinary socketpair, so from here on this fd behaves like any
        // connected socket (read/write/poll/close all go through the spair paths, which are
        // checked BEFORE h.sock everywhere).
        if (dst.ip && (dst.ip === '127.0.0.1' || dst.ip.startsWith('127.') || dst.ip === '::1')) {
          const L = localListeners.get(dst.port);
          if (!L) return err(E.CONNREFUSED);        // nothing listening: the honest answer
          const f1 = mkPipe(), f2 = mkPipe();
          L.backlog.push({ srv: { rd: f1, wr: f2 } });
          h.spair = { rd: f2, wr: f1 };
          h.sock.connectedLocal = true;
          return 0n; }
        const br = initWisp(); const spec = te.encode(`${dst.ip}|${dst.port}${h.sock.tls ? '|T' : ''}`);
        const r = br.call(br.OP.CONNECT, spec.length, 0, 0, spec); if (r.res < 0) return BigInt(r.res); h.sock.id = r.res; return 0n; }
      case 'sendto': case 'sendmsg': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh(); let payload;
          if (name === 'sendmsg') {
            const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
            for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(S.u8.slice(p, p + l)); }
            payload = concatU8(parts);
            const M = S.msgCtl, ctl = S.r32(a[1] + M.ctl), ctllen = S.r32(a[1] + M.ctllen);
            if (ctl && ctllen >= M.hdr) { const clen = S.r32(ctl), lvl = S.r32(ctl + M.hdr - 8), typ = S.r32(ctl + M.hdr - 4);
              if (lvl === 1 && typ === 1) { const nf = (clen - M.hdr) >> 2; h.spair.wr.fds = h.spair.wr.fds || [];
                for (let i = 0; i < nf; i++) { const fd = S.r32(ctl + M.hdr + i * 4); const hh = S.fds.get(fd); if (hh) { h.spair.wr.fds.push({ ...hh, shared: true }); S.bumpFifo(hh); } } } }
          } else payload = S.u8.slice(a[1], a[1] + a[2]);
          if (h.spair.wr.readers <= 0) { postSignal(S, SIG.PIPE); return err(E.PIPE); }
          h.spair.wr.chunks.push(payload); wakePipe(h.spair.wr); return BigInt(payload.length); }
        if (!h.sock) return err(E.BADF);
        const br = initWisp(); S.refresh(); let payload, dest = h.sock.dest;
        if (name === 'sendmsg') { const np = S.r32(a[1]); if (np) dest = readSockaddr(S, np);
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(S.u8.slice(p, p + l)); }
          payload = new Uint8Array(parts.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of parts) { payload.set(x, o); o += x.length; } }
        else { payload = S.u8.slice(a[1], a[1] + a[2]); if (a[4]) dest = readSockaddr(S, a[4]); }
        if (h.sock.icmp) { if (!dest) return err(E.INVAL); h.sock.lastDest = dest;
          // payload = ICMP echo request; ask the relay to ping the host (it resolves
          // the synthetic IP back to a name), and remember id/seq/data for the reply.
          const icmpId = payload.length >= 6 ? ((payload[4] << 8) | payload[5]) : 0;
          const icmpSeq = payload.length >= 8 ? ((payload[6] << 8) | payload[7]) : 0;
          const spec = te.encode(dest.ip);
          const kr = br.call(br.OP.PING, spec.length, 0, 0, spec);   // kickoff -> ping id
          h.sock.ping = { id: kr.res, dst: dest, icmpId, icmpSeq, data: payload.slice(8), rawhdr: h.sock.rawhdr, status: null };
          return BigInt(payload.length); }
        if (h.sock.udp) { if (!dest) return err(E.INVAL); h.sock.lastDest = dest;
          const addr = te.encode(`${dest.ip}|${dest.port}`); const packed = new Uint8Array(payload.length + addr.length); packed.set(payload, 0); packed.set(addr, payload.length);
          const r = br.call(br.OP.SENDTO, h.sock.id, payload.length, addr.length, packed); return BigInt(r.res); }
        const r = br.call(br.OP.SEND, h.sock.id, payload.length, 0, payload); return BigInt(r.res); }
      case 'recvmsg': case 'recvfrom': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh();
          if (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length)) { if (h.spair.rd.writers <= 0) return 0n; if (h.nonblock) return err(E.AGAIN); }
          // recvfrom is NOT recvmsg: its a[1] is a plain buffer and a[2] its length, while
          // recvmsg's a[1] is a msghdr. The code below reads a[1]+8 as an iov pointer, so a
          // recvfrom landed on a wild address -- and the exception that followed came back
          // as -1, i.e. EPERM, which is what conn.recv() reported after a local accept:
          //     PermissionError: [Errno 1] Operation not permitted
          // The sendto/sendmsg twin already separates the two; this side never did, because
          // until loopback sockets existed nothing reached it by the recvfrom shape (the
          // socketpair users all go through recvmsg, for SCM_RIGHTS).
          if (name === 'recvfrom') {
            const b = pipeRead(h.spair.rd, a[2]); S.wbytes(a[1], b);
            if (a[4]) { const n = writeSockaddr(S, a[4], { ip: '127.0.0.1', port: 0 }); if (a[5]) S.i32(a[5], n); }
            return BigInt(b.length); }
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue; const b = pipeRead(h.spair.rd, l); if (!b.length) break; S.wbytes(p, b); total += b.length; if (b.length < l) break; }
          const M = S.msgCtl, ctl = S.r32(a[1] + M.ctl), ctllen = S.r32(a[1] + M.ctllen);
          if (ctl && ctllen >= M.hdr + 4 && h.spair.rd.fds && h.spair.rd.fds.length) { const hh = h.spair.rd.fds.shift(); const g = S.allocFd(); S.fds.set(g, hh);
            S.i32(ctl, M.hdr + 4); S.i32(ctl + M.hdr - 8, 1); S.i32(ctl + M.hdr - 4, 1); S.i32(ctl + M.hdr, g); S.i32(a[1] + M.ctllen, M.hdr + 4);
          } else if (ctl) S.i32(a[1] + M.ctllen, 0);
          return BigInt(total); }
        if (!h.sock) return err(E.BADF);
        if (h.sock.icmp) { const pg = h.sock.ping;   // reply synthesised locally once the relay confirms
          if (pg && pg.status === null) { const pk = initWisp().call(initWisp().OP.PINGPOLL, pg.id, 0, 0);  // self-drive (nonblock ping via poll)
            if (pk.res === 0) pg.status = 0; else if (pk.res !== -11) pg.status = pk.res; }
          if (!pg || pg.status !== 0) return err(E.AGAIN);   // no reply yet / unreachable -> ping's own timeout ends it
          const pkt = buildIcmpReply(pg); h.sock.ping = null;
          if (name === 'recvfrom') { const k = Math.min(pkt.length, a[2]); S.wbytes(a[1], pkt.subarray(0, k));
            if (a[4]) { const n = writeSockaddr(S, a[4], pg.dst); if (a[5]) S.i32(a[5], n); } return BigInt(k); }
          const np = S.r32(a[1]); if (np) { const n = writeSockaddr(S, np, pg.dst); S.i32(a[1] + 4, n); }
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let off = 0, tot = 0;
          for (let i = 0; i < iovn && off < pkt.length; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
            const k = Math.min(l, pkt.length - off); S.wbytes(p, pkt.subarray(off, off + k)); off += k; tot += k; }
          return BigInt(tot); }
        const br = initWisp(); const op = h.sock.udp ? br.OP.RECVFROM : br.OP.RECV;
        if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); }
        if (name === 'recvfrom') { const r = br.call(op, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res));
          if (a[4] && h.sock.lastDest) { const n = writeSockaddr(S, a[4], h.sock.lastDest); if (a[5]) S.i32(a[5], n); } return BigInt(r.res); }
        const np = S.r32(a[1]); if (np && h.sock.lastDest) { const n = writeSockaddr(S, np, h.sock.lastDest); S.i32(a[1] + 4, n); }
        const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
        for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
          const r = br.call(op, h.sock.id, l, 0); if (r.res < 0) return total || BigInt(r.res); if (r.res === 0) break; S.wbytes(p, r.data.subarray(0, r.res)); total += r.res;
          if (r.res < l || br.port) break; }   // message bridge: one receive per call (a second one would restart the syscall and lose the first)
        return BigInt(total); }
      case 'getsockname': case 'getpeername': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.spair) { // AF_UNIX pair is unnamed — python's socket(fileno=) sniffs the family here (EBADF broke asyncio's self-pipe)
          S.u8.fill(0, a[1], a[1] + 4); S.dv.setUint16(a[1], 1, true); if (a[2]) S.i32(a[2], 2); return 0n; }
        if (!h.sock) return err(E.BADF);
        const ba = (name === 'getpeername' ? (h.sock.dest || h.sock.lastDest) : null) || h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        const n = writeSockaddr(S, a[1], { ip: ba.ip === '::' ? '0.0.0.0' : ba.ip, port: (name === 'getsockname' && h.sock.boundPort) || ba.port });
        if (a[2]) S.i32(a[2], n); return 0n; }
      case 'setsockopt': { // private: level 0x5457 ('WT') marks this socket TLS -> WISP relay terminates (wisp.js conntype 3)
        const h = S.fds.get(a[0]); if (h && h.sock && (a[1]|0) === 0x5457) h.sock.tls = true; return 0n; }
      case 'shutdown': return 0n;
      case 'getsockopt': { // enough for ssh/curl. SOL_SOCKET=1: SO_ERROR=4 ->0 (connected),
        // SO_TYPE=3 -> socket type, SO_SNDBUF=7/SO_RCVBUF=8 -> a real size (ssh sizes its
        // channel window from these; returning 0 stalls the session). Everything else -> 0.
        const level = a[1] | 0, opt = a[2] | 0, optval = a[3], optlen = a[4];
        if (optval) { let v = 0;
          if (level === 1 && opt === 3) { const h = S.fds.get(a[0]); v = (h && h.sock && (h.sock.udp || h.sock.icmp)) ? 2 : 1; } // SO_TYPE
          else if (level === 1 && (opt === 7 || opt === 8)) v = 262144; // SO_SNDBUF / SO_RCVBUF
          S.i32(optval, v); }
        if (optlen) S.i32(optlen, 4);
        return 0n; }
      default:
        // NOT '[host]'-prefixed: the terminal routes those to console.debug, which
        // Chrome hides unless Verbose is on -- so the one line that explains why a
        // program just died was invisible exactly when it mattered (this is how the
        // ppoll gap above stayed hidden). Once per syscall name, so it cannot spam.
        if (!unknownSyscalls.has(name)) { unknownSyscalls.add(name); post(`walios: unimplemented syscall SYS_${name} (ENOSYS) -- this program may fail\n`, 2); }
        return err(E.NOSYS);
    }
  }

  // ---- async syscall path: the BLOCKING names (the rest delegate to sys) ----
  async sysAsync(name, a) {
    const S = this;
    // Another thread's syscall may be served while this one is parked, and curTid is what
    // inChild()/fds key on -- so put the caller back before anything that consults them.
    const tid = S.curTid; const back = () => { S.curTid = tid; };
    switch (name) {
      case 'read': case 'readv': {
        const h = S.fds.get(a[0]);
        if (h && h.std === 0 && !h.nonblock) { while (!stdinChunks.length && !stdinEOF) {           const w = await S.sigRace(res => stdinWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } return (back(), S).sys(name, a); }
        if (h && h.hostcall && !h.nonblock) { while (!h.hostcall.chunks.length) {
          const w = await S.sigRace(res => h.hostcall.waiters.push(() => res('ev')));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } return (back(), S).sys(name, a); }
        if (h && h.pty !== undefined && !h.nonblock) { const p = ptys.get(h.pty); const q = () => h.master ? p.toMaster : p.toSlave; const wl = h.master ? p.masterWaiters : p.slaveWaiters;
          while (!q().length && !(!h.master && p.slaveEof)) {             const w = await S.sigRace(res => wl.push(() => res('ev')));
            if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } return (back(), S).sys(name, a); }
        if (h && h.fifo && !h.nonblock) { while (!h.fifo.chunks.length && !fifoEOF(h.fifo)) {           const w = await S.sigRace(res => h.fifo.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } return (back(), S).sys(name, a); }
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && h.spair.rd.writers > 0) {           const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } return (back(), S).sys(name, a); }
        if (h && h.tfd && !h.nonblock) { while (!h.tfd.count) {
            const w = await S.sigRace(res => h.tfd.waiters.push(res));
            if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } }
          S.refresh(); if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(h.tfd.count)); h.tfd.count = 0; return 8n; }
        // Blocking socket read: poll the WISP bridge with a signal race instead of a
        // frozen Atomics.wait, so ^C (SIGINT) can interrupt a stuck recv (e.g. telnet).
        if (h && h.sock && (h.sock.id || h.sock.icmp) && !h.nonblock) { const v = await S.sockWait(h); if (v !== null) return v; }
        return (back(), S).sys(name, a);
      }
      case 'recvmsg': case 'recvfrom': {
        const h = S.fds.get(a[0]);
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length) && h.spair.rd.writers > 0) {           const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; } } }
        if (h && h.sock && (h.sock.id || h.sock.icmp) && !h.nonblock) { const v = await S.sockWait(h); if (v !== null) return v; }
        return (back(), S).sys(name, a);
      }
      case 'futex': {
        // Real futexes for pthreads (wali-musl's __wait/__wake go through SYS_futex, not
        // memory.atomic.wait). Every thread of a process is served by this one kernel
        // thread, so "check the value, then register the waiter" is atomic with respect to
        // any WAKE: a waker's store+WAKE either lands before our check (we see the new
        // value: EAGAIN) or after our registration (we are woken). A SysV shm address is
        // the cross-PROCESS futex and keeps its own path in sys().
        const uaddr = a[0] >>> 0, fop = a[1] & 0x7f, val = a[2] | 0;
        S.refresh();
        for (const [b, x] of S.shmAt) if (uaddr >= b && uaddr < b + x.seg.size) return (back(), S).sys(name, a);
        // A waiter is { fin, addr, gone, woken }: addr changes when REQUEUE moves it; gone is set
        // the moment it stops waiting (woken, timed out, signal), so a WAKE never spends itself
        // on a waiter that is already leaving -- that lost the wake for the next one in line.
        const fwWake = (addr, max) => {
          const wl = S.futexWaiters.get(addr); let n = 0;
          while (wl && wl.length && n < max) { const e = wl.shift(); if (e.gone) continue; e.gone = e.woken = true; e.fin('wake'); n++; }
          if (wl && !wl.length) S.futexWaiters.delete(addr);
          return n;
        };
        if (fop === 1 || fop === 10) return BigInt(fwWake(uaddr, val));   // FUTEX_WAKE / WAKE_BITSET
        if (fop === 3 || fop === 4) {                        // FUTEX_REQUEUE / CMP_REQUEUE
          // musl's condition variables hand a signalled waiter over to the mutex with REQUEUE
          // (pthread_cond_timedwait.c unlock_requeue). Answering it with "0, nothing moved" left
          // that waiter asleep on the condvar word, which nobody wakes again: git grep's work
          // queue deadlocked under contention (t7810 --threads=8..10 on 4-core CI runners).
          if (fop === 4 && S.dv.getInt32(uaddr, true) !== (a[5] | 0)) return err(E.AGAIN);
          const uaddr2 = a[4] >>> 0, nMove = Number(a[3]) | 0;
          let n = fwWake(uaddr, val), m = 0;
          const wl = S.futexWaiters.get(uaddr);
          if (wl && nMove > 0 && uaddr2 !== uaddr) {
            let wl2 = S.futexWaiters.get(uaddr2); if (!wl2) S.futexWaiters.set(uaddr2, wl2 = []);
            while (wl.length && m < nMove) { const e = wl.shift(); if (e.gone) continue; e.addr = uaddr2; wl2.push(e); m++; }
            if (!wl.length) S.futexWaiters.delete(uaddr);
          }
          return BigInt(n + m); }
        if (fop === 0 || fop === 9) {                        // FUTEX_WAIT / WAIT_BITSET (absolute time)
          if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
          let ms = Infinity;
          if (a[3]) { const abs = fop === 9, realtime = !!(a[1] & 0x100);
            ms = Number(S.r64(a[3])) * 1000 + S.tsNs(a[3]) / 1e6;
            if (abs) ms -= realtime ? nowEpoch() : performance.now(); }
          let wl = S.futexWaiters.get(uaddr); if (!wl) S.futexWaiters.set(uaddr, wl = []);
          const e = { fin: null, addr: uaddr, gone: false, woken: false };
          const w = await S.sigRace((fin) => { e.fin = fin; wl.push(e);
            if (Number.isFinite(ms)) setTimeout(() => { if (!e.gone) { e.gone = true; fin('t'); } }, Math.max(0, Math.min(ms, 3600000))); });
          e.gone = true;
          const cur = S.futexWaiters.get(e.addr);
          if (cur) { const k = cur.indexOf(e); if (k >= 0) cur.splice(k, 1); if (!cur.length) S.futexWaiters.delete(e.addr); }
          if (w === 'wake' || e.woken) return 0n;
          if (w === 't') return err(E.TIMEDOUT);
          const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v;
          return err(E.INTR); }
        return (back(), S).sys(name, a);
      }
      case 'fcntl': case 'flock': {
        // F_SETLKW / F_OFD_SETLKW / flock without LOCK_NB: wait for the lock, interruptible.
        // Woken by any unlock in this kernel; polled every 50ms for holders in other tabs.
        const blocking = name === 'flock' ? !((a[1] | 0) & 4) && ((a[1] | 0) & ~4) !== 8 : (a[1] === 7 || a[1] === 38);
        if (!blocking) return (back(), S).sys(name, a);
        for (;;) {
          const r = (back(), S).sys(name, name === 'flock' ? [a[0], (a[1] | 0) | 4] : [a[0], a[1] === 7 ? 6 : 37, a[2]]);
          if (r !== -BigInt(E.AGAIN)) return r;
          let mine = null;
          const w = await S.sigRace((fin) => { mine = fin; lockWaiters.add(fin); setTimeout(() => fin('t'), 50); });
          lockWaiters.delete(mine);
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v; return err(E.INTR); }
        }
      }
      case 'nanosleep': case 'clock_nanosleep': { // interruptible (EINTR) + TIMER_ABSTIME
        const end = Date.now() + S.sleepMs(name, a);
        while (Date.now() < end) {
          const w = await S.sigRace(res => setTimeout(() => res('t'), Math.min(end - Date.now(), 3600000)));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v; }
        }
        return 0n;
      }
      case 'pause': case 'sigsuspend': case 'rt_sigsuspend': { // suspend until a signal is DELIVERED
        const oldMask = S.sig.mask;
        if (name !== 'pause' && a[0]) { S.refresh(); S.sig.mask = BigInt.asUintN(64, S.r64(a[0])); }
        try {
          for (;;) {
            if (S.sig.pending.size) { const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v; }
            await S.sigRace(() => {});
          }
        } finally { S.sig.mask = oldMask; }
      }
      case 'accept': case 'accept4': { // probe + wait so siblings run while we wait
        const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        for (;;) {
          const r = (back(), S).sys(name, a);
          if (r !== BigInt(-E.AGAIN) || h.nonblock || h.sock.nonblock) return r;
          const w = await S.sigRace(res => setTimeout(() => res('t'), 20));
          if (w === 'sig') { const v = await (back(), S).onSigWakeAsync(true); if (v !== null) return v; }
        }
      }
      case 'wait4': return await S.wait4Async(a);
      case 'poll': case 'ppoll': return await S.pollAsync(name, a);
      case 'select': case 'pselect6': { // suspend-capable select: waiters for fifos/ptys/stdin, ticker for sockets
        const { rd, wr, tmo, commit } = S.selectParse(name, a);
        const end = tmo >= 0 ? Date.now() + tmo : Infinity;
        for (;;) {
          if (rd.some(fd => S.selectReady(fd, false)) || wr.some(fd => S.selectReady(fd, true))) return BigInt(commit());
          const remaining = end - Date.now();
          if (remaining <= 0) { commit(); return 0n; }
          const woke = await S.sigRace((fin) => {
            let hasSock = false, hasOther = false;
            for (const fd of rd) { const h = S.fds.get(fd); if (!h) continue;
              if (h.fifo) { h.fifo.readWaiters.push(() => fin(true)); hasOther = true; }
              else if (h.spair) { h.spair.rd.readWaiters.push(() => fin(true)); hasOther = true; }
              else if (h.pty !== undefined) { const p = ptys.get(h.pty); (h.master ? p.masterWaiters : p.slaveWaiters).push(() => fin(true)); hasOther = true; }
              else if (h.tfd) { h.tfd.waiters.push(() => fin(true)); hasOther = true; }
              else if (h.std === 0) { stdinWaiters.push(() => fin(true)); hasOther = true; }
              else if (h.sock) hasSock = true; }
            let ms = hasSock ? 15 : (hasOther ? Infinity : 50);
            ms = Math.min(ms, remaining);
            if (Number.isFinite(ms)) setTimeout(() => fin(false), ms);
          });
          if (woke === 'sig') { const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v; }
        } }
      case 'epoll_wait': case 'epoll_pwait': { // suspend-capable epoll: waiters for fifos/ptys/stdin, ticker for sockets
        const h = S.fds.get(a[0]); if (!h || !h.ep) return err(E.BADF);
        const evp = a[1], maxev = Math.max(1, Math.min(a[2] | 0, 4096)), tmo = a[3] | 0;
        const end = tmo >= 0 ? Date.now() + tmo : Infinity;
        for (;;) {
          const n = S.epollEval(h.ep, evp, maxev);
          if (n > 0) return BigInt(n);
          const remaining = end - Date.now();
          if (remaining <= 0) return 0n;
          const woke = await S.sigRace((fin) => {
            let hasSock = false, hasOther = false;
            for (const [fd, it] of h.ep) { if (!(it.events & 1)) continue; const hh = S.fds.get(fd); if (!hh) continue;
              if (hh.fifo) { hh.fifo.readWaiters.push(() => fin(true)); hasOther = true; }
              else if (hh.spair) { hh.spair.rd.readWaiters.push(() => fin(true)); hasOther = true; }
              else if (hh.pty !== undefined) { const p = ptys.get(hh.pty); (hh.master ? p.masterWaiters : p.slaveWaiters).push(() => fin(true)); hasOther = true; }
              else if (hh.tfd) { hh.tfd.waiters.push(() => fin(true)); hasOther = true; }
              else if (hh.std === 0) { stdinWaiters.push(() => fin(true)); hasOther = true; }
              else if (hh.sock) hasSock = true; }
            let ms = hasSock ? 15 : (hasOther ? Infinity : 50);
            ms = Math.min(ms, remaining);
            if (Number.isFinite(ms)) setTimeout(() => fin(false), ms);
          });
          if (woke === 'sig') { const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v; }
        } }
      default: return (back(), S).sys(name, a);
    }
  }
  // WASI fd_read has no async twin (it is not a wali.SYS_ name), so the serve loop parks
  // here first: wait until the fd has data or EOF, then let the synchronous shim read it.
  // Without this a WASI program reading a pipe or the terminal saw EOF at once.
  async waitReadable(fd) {
    const S = this, h = S.fds.get(fd); if (!h || h.nonblock) return;
    const race = (arm) => S.sigRace((res) => arm(() => res('ev')));
    if (h.std === 0) { while (!stdinChunks.length && !stdinEOF) await race((f) => stdinWaiters.push(f)); return; }
    if (h.pty !== undefined) { const p = ptys.get(h.pty); const q = () => h.master ? p.toMaster : p.toSlave; const wl = h.master ? p.masterWaiters : p.slaveWaiters;
      while (!q().length && !(!h.master && p.slaveEof)) await race((f) => wl.push(f)); return; }
    if (h.fifo) { while (!h.fifo.chunks.length && !fifoEOF(h.fifo)) await race((f) => h.fifo.readWaiters.push(f)); return; }
    if (h.hostcall) { while (!h.hostcall.chunks.length) await race((f) => h.hostcall.waiters.push(f)); return; }
  }
  async wait4Async(a) {
    const S = this; const want = a[0] | 0;
    while (S.pending.length) { const c = S.pending.shift(); if (c.exited !== undefined) S.reaped.set(c.pid, c.exited); }
    for (;;) {
      let pid = -1;
      if (want > 0) { if (S.reaped.has(want)) pid = want; }
      else if (S.reaped.size) pid = S.reaped.keys().next().value;
      if (pid >= 0) { const code = S.reaped.get(pid); S.reaped.delete(pid); zombies.delete(pid); if (a[1]) S.i32(a[1], (code & 0xff) << 8);
        if (a[3]) { S.refresh(); S.u8.fill(0, a[3], a[3] + 18 * S.L); } // rusage, as getrusage
        return BigInt(pid); }
      if (a[2] & 2) { // WUNTRACED: report a stopped child once
        for (const cpid of S.childTasks.keys()) {
          if (want > 0 && cpid !== want) continue;
          const C = procs.get(cpid);
          if (C && C.stopped && !C.stopReported) { C.stopReported = true;
            if (a[1]) S.i32(a[1], (C.stopped << 8) | 0x7f); return BigInt(cpid); }
        }
      }
      const stillRunning = want > 0 ? S.childTasks.has(want) : S.childTasks.size > 0;
      if (!stillRunning) return err(E.CHILD);
      if (a[2] & 1) return 0n; // WNOHANG
      const w = await S.sigRace(res => S.waitWaiters.push(() => res('ev')));
      if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
    }
  }
  async pollAsync(name, a) {
    const S = this; const nfds = a[1];
    S.refresh();
    const timeout = name === 'poll' ? (a[2] | 0)
      : (a[2] ? Math.ceil(S.rLong(a[2], 0) * 1000 + S.rLong(a[2], 1) / 1e6) : -1); // ppoll: musl's long[2] {s, ns} or NULL
    const evalReady = () => { S.refresh(); let ready = 0; const waitFifos = []; const waitPtys = []; let waitStdin = false, waitSock = false;
      for (let i = 0; i < nfds; i++) {
        const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
        const h = S.fds.get(fd); let re = 0;
        if (h && h.std === 0) { const rdy = stdinChunks.length || stdinEOF; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitStdin = true; }
        else if (h && h.fifo) { const rdy = h.fifo.chunks.length || fifoEOF(h.fifo); if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.fifo); }
        else if (h && h.spair) { const rdy = h.spair.rd.chunks.length || h.spair.rd.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.spair.rd); }
        else if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; else if (ev & 1) waitSock = true; if (ev & 4) re |= 4; }
        else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; const rdy = q.length || (!h.master && p.slaveEof); if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitPtys.push(h.master ? p.masterWaiters : p.slaveWaiters); }
        else if (h && h.tfd) { S.pollTfd(h.tfd); if ((ev & 1) && h.tfd.count > 0) re |= 1; if (!h.tfd.count) waitPtys.push(h.tfd.waiters); }
        else if (fd < 0) re = 0; else if (!h) re = 0x20; else re = ev & 5;
        S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++;
      }
      return { ready, waitFifos, waitPtys, waitStdin, waitSock };
    };
    const deadline = timeout >= 0 ? Date.now() + timeout : Infinity;
    for (;;) {
      const r = evalReady();
      if (r.ready > 0) return BigInt(r.ready);
      const remaining = deadline - Date.now();
      if (remaining <= 0) return 0n;
      const woke = await S.sigRace((fin) => {
        for (const f of r.waitFifos) f.readWaiters.push(() => fin(true));
        for (const wl of r.waitPtys) wl.push(() => fin(true));
        if (r.waitStdin) stdinWaiters.push(() => fin(true));
        // A WISP socket has no event-driven waiter — its readiness must be re-polled on
        // a short ticker, ALWAYS, even when a pty/stdin/fifo waiter is also armed. Without
        // this, poll([socket, stdin]) blocks on stdin and never notices socket data (the
        // ssh handshake deadlock). Also tick when there's nothing else to wake us.
        let ms = r.waitSock ? 15 : ((!r.waitFifos.length && !r.waitPtys.length && !r.waitStdin) ? 50 : Infinity);
        ms = Math.min(ms, remaining);
        if (Number.isFinite(ms)) setTimeout(() => fin(false), ms);
      });
      if (woke === 'sig') { const v = await S.onSigWakeAsync(false); if (v !== null) return v; }
    }
  }

  makeImports(mod) {
    const wali = {}; const extra = {};
    const S = this;
    const needWasi = WebAssembly.Module.imports(mod).some(i => i.module === 'wasi_snapshot_preview1');
    const wasi = needWasi ? this.makeWasi() : null;
    // A binary whose libc carries the vfork protocol exports its entry point (CPython
    // links with --export-dynamic); see PLAIN_MUSL_FORK.
    this.forkMacro = WebAssembly.Module.exports(mod).some((e) => e.name === '__wali_fork_begin');
    // walios ILP32 binaries (32-bit long; walios/build/sysroot32) say so in a custom section
    this.ilp32 = WebAssembly.Module.customSections(mod, 'wali.abi').some((b) => td.decode(new Uint8Array(b)).includes('ilp32'));
    for (const im of WebAssembly.Module.imports(mod)) {
      if (im.module === 'wasi_snapshot_preview1') {
        (extra.wasi_snapshot_preview1 = extra.wasi_snapshot_preview1 || {})[im.name] =
          wasi[im.name] || ((...a2) => { if (!unknownSyscalls.has('wasi.' + im.name)) { unknownSyscalls.add('wasi.' + im.name); post(`[host] WASI stub ${im.name}\n`, 2); } return 0; });
        continue;
      }
      if (im.module === 'env' && im.name === 'memory' && im.kind === 'memory') {
        (extra.env = extra.env || {}).memory = S.getSharedMemory();   // wasi-threads: shared linear memory
        continue;
      }
      if (im.module === 'wasi' && im.name === 'thread-spawn') {
        (extra.wasi = extra.wasi || {})['thread-spawn'] = (startArg) => S.threadSpawn(startArg);
        continue;
      }
      if (im.module === 'env' && (im.name === '__wali_dlopen' || im.name === '__wali_dlsym')) {
        (extra.env = extra.env || {})[im.name] = im.name === '__wali_dlopen'
          ? (pathPtr, _flags) => S.dlopen(S.cstr(pathPtr))
          : (handle, symPtr) => S.dlsym(handle, S.cstr(symPtr));
        continue;
      }
      if (im.module !== 'wali') {
        (extra[im.module] = extra[im.module] || {})[im.name] = () => -38n;
        continue;
      }
      const name = im.name;
      if (name === '__init' || name === '__deinit') wali[name] = () => 0;
      else if (name === '__get_init_envfile0') wali[name] = (buf, sz) => {
        // walios libc (musl-patches/src/env/initenv.c): the environment as a NUL-separated file,
        // like /proc/self/environ -- values may contain newlines (a multi-line GIT_EDITOR,
        // autoconf's as_nl). Binaries built before it import __get_init_envfile below.
        if (!S.env.length) return 0;
        const parts = S.env.map((e) => benc(e));
        const out = new Uint8Array(parts.reduce((n, b) => n + b.length + 1, 0));
        let o = 0; for (const b of parts) { out.set(b, o); o += b.length + 1; }   // each entry NUL-terminated
        addFile(`/.wali_env_${S.pid}`, out);
        S.wstr(buf, `/.wali_env_${S.pid}`, sz); return 1;
      };
      else if (name === '__get_init_envfile') wali[name] = (buf, sz) => {
        if (!S.env.length) return 0;
        // The env reaches a new process as a NEWLINE-SEPARATED file that wali-musl's
        // init_env() splits and putenv()s token by token. So a VALUE that itself contains a
        // newline splits into a fragment with no '=', musl's putenv rejects it (EINVAL), and
        // init_env aborts the process with WALI_ENV_READ_FAIL before main ever runs.
        //
        // That killed EVERY autotools build. Autoconf's preamble is literally
        //     as_nl='<newline>' ; export as_nl
        // so from that line on every command configure spawned died instantly with a silent
        // exit 3 (259 & 0xff) -- no message, no stderr. Even `sh -c :` failed. It looked like
        // a broken compiler; it was the environment.
        //
        // Properly this file should be NUL-separated like Linux's /proc/self/environ, but the
        // reader is compiled into every wasm binary we ship, so that is a libc change plus a
        // relink of everything. Until then drop what we cannot represent, LOUDLY, rather than
        // let it kill the process: losing a variable beats losing the process, and configure
        // re-derives as_nl at the top of every script anyway.
        const safe = [], bad = [];
        for (const e of S.env) { if (e.indexOf('\n') >= 0) bad.push(e.slice(0, e.indexOf('=')) || '?'); else safe.push(e); }
        if (bad.length) WARN('env: dropped ' + bad.length + ' variable(s) whose value contains a newline (' + bad.join(', ') + '): the env file is newline-separated, so a child cannot receive them');
        if (!safe.length) return 0;
        addFile(`/.wali_env_${S.pid}`, benc(safe.join('\n') + '\n'));
        S.wstr(buf, `/.wali_env_${S.pid}`, sz); return 1;
      };
      else if (name === 'log_execution') { // wasm-opt --log-execution preemption hook
        // (see farm/instrument-preempt.sh; instrumented binaries must be linked
        // WITHOUT --shared-memory so the start section stays uninstrumented)
        let fuel = 0;
        wali[name] = () => { if (++fuel & 0x3fff) return; S.pollTimers(); if (S.sig.pending.size) { S.sigDelivered = false; S.predeliver(); } };
      }
      else if (name === '__cl_get_argc') wali[name] = () => S.argv.length;
      else if (name === '__cl_get_argv_len') wali[name] = (i) => benc(S.argv[i] || '').length;
      else if (name === '__cl_copy_argv') wali[name] = (buf, i) => S.wstrB(buf, S.argv[i] || '');
      else if (name === '__proc_exit') wali[name] = (c) => { throw new ExitError(c, true); };
      else if (name === 'setjmp' || name === 'sigsetjmp' || name === '_setjmp') wali[name] = () => 0;
      else if (name === "__wasm_thread_spawn") {
        // WALI pthread_create hook (wali-musl pthread_create.c): __wasm_thread_spawn(entry,
        // args) must start a new thread that runs the module's exported
        // __wasm_thread_start_libc(tid, args) -- which sets __stack_pointer and __tls_base
        // from args and calls the user function -- and return its tid (>0), or a negative
        // value that musl maps to EAGAIN. A thread is a second instance of the module on
        // the same shared memory (threadSpawn), so the module must IMPORT its memory
        // (scripts/wasm-import-memory.mjs converts a binary that defines one). For a binary
        // that still defines its memory, threadSpawn answers -1 and Python raises
        // RuntimeError, as before. (The old catch-all returned 0n: SUCCESS with tid 0, and
        // the BigInt tripped a type error that trapped the whole interpreter, exit 139.)
        wali[name] = (_entryFn, args) => S.threadSpawn(Number(args), '__wasm_thread_start_libc');
      }
      else if (name === 'longjmp' || name === 'siglongjmp' || name === '_longjmp') wali[name] = () => { throw new Error('host-import longjmp (old binary)'); };
      // a fresh stack for a deep recursion (farm/ci/stackhop.mjs): served where the instance is
      // -- wali-proc-worker.js stackHop, or _makeInProcImports -- never by the kernel.
      else if (name === '__stackhop') wali[name] = () => { throw new Error('[host] wali.__stackhop reached the kernel'); };
      else if (name.startsWith('SYS_')) {
        const sysname = name.slice(4);
        const map = (a2) => a2.map(x => typeof x === 'bigint' && sysname !== 'mmap' ? i64arg(x) : x);
        // fork never reaches here: the worker unwinds it locally (Asyncify) and asks for a
        // pid through the FORKED handshake. BLOCKING names are dispatched to sysAsync by the
        // serve loop before the handler table is consulted.
        wali[name] = (...a2) => {
          S.syscalls++; syscallTotal++;
          S.pollTimers();
          if (S.shmAt.size) S.syncShm();
          S.sigDelivered = false;
          const dv = S.predeliver(); if (dv !== null) return dv;
          return S.sys(sysname, map(a2));
        };
      } else wali[name] = (...a2) => {
        // Loud by design: this was `() => 0n`, which silently reports success for a
        // host call that never happened. Nothing legitimately lands here today --
        // checked across every .wasm and all 95 .so, the ONLY unhandled wali import
        // was __wasm_thread_spawn, handled above -- so reaching this is a real bug.
        throw new Error("[host] unimplemented host import wali." + name + " (" + a2.length + " args) - refusing to silently return 0");
      };
    }
      // C99 floating-point environment. numpy (_multiarray_umath, _simd, _umath_linalg)
      // imports these but the MAIN does not, so they arrive ONLY via the dlopen
      // side-module proxy below. wasm exposes no FP status register, so 0 is the
      // CORRECT answer rather than a stub: fetestexcept -> no exception flags raised,
      // feraiseexcept -> nothing to raise, success. Consequence: numpy cannot emit its
      // divide-by-zero / overflow / invalid RuntimeWarnings. Anything OTHER than these
      // two reaching the proxy is a genuine unresolved import and throws.
      if (!wali.fetestexcept) wali.fetestexcept = () => 0;
      if (!wali.feraiseexcept) wali.feraiseexcept = () => 0;
    this.wali = wali;                 // expose for side-module (dlopen) imports
    return { wali, ...extra };
  }

  // ---- WASI preview1 shim (browser): run standard wasm32-wasi binaries,
  //      incl. the eventual clang.wasm, over the in-memory VFS + terminal ----
  makeWasi() {
    const S = this;
    const OK = 0, BADF = 8, NOENT = 44;
    // Linux errno (negative BigInt from sys()) -> WASI preview1 errno.
    const WASI_ERRNO = { [E.PERM]: 63, [E.NOENT]: 44, [E.INTR]: 27, [E.IO]: 29, [E.BADF]: 8, [E.AGAIN]: 6, [E.NOMEM]: 48, [E.ACCES]: 2, [E.EXIST]: 20, [E.NOTDIR]: 54, [E.ISDIR]: 31, [E.INVAL]: 28, [E.PIPE]: 64, [E.NOSYS]: 52, [E.NOTEMPTY]: 55 };
    const wasiErrno = (r) => WASI_ERRNO[Number(-r)] || 29;   // unknown -> EIO
    const iovs = (ptr, n) => { const r = []; for (let i = 0; i < n; i++) r.push([S.r32(ptr + i * 8), S.r32(ptr + i * 8 + 4)]); return r; };
    const w = {
      proc_exit: (code) => { throw new ExitError(code, true); },
      // ONE read and ONE write for every kind of fd. These used to be a second copy of the
      // Linux-ABI branches with kinds missing: no pty, so a WASI program's output vanished
      // in the terminal (`qjs -e "print('x')"` printed nothing in /walios/ while working in
      // the walios() tool); no socketpair, no /dev/random, no wake of a parked pipe reader.
      // Now they are the same code path as the WALI syscalls, iov by iov, with errnos
      // translated -- a new fd kind is handled in one place or in none.
      fd_write: (fd, iptr, icnt, nptr) => { let tot = 0;
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue;
          const r = S.sys('write', [fd, p, l]); if (r < 0n) return wasiErrno(r);
          tot += Number(r); if (Number(r) < l) break; }
        S.i32(nptr, tot); return OK; },
      fd_read: (fd, iptr, icnt, nptr) => { let tot = 0;
        // Blocking happened BEFORE this ran: the serve loop parks in waitReadable() for a
        // WASI fd_read, so EAGAIN from a blocking fd here means EOF, not "try later".
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue;
          const h = S.fds.get(fd); let r = S.sys('read', [fd, p, l]);
          if (r === err(E.AGAIN) && h && !h.nonblock) r = 0n;
          if (r < 0n) return wasiErrno(r);
          tot += Number(r); if (Number(r) < l) break; }
        S.i32(nptr, tot); return OK; },
      // Through the real close: it drops pipe refcounts (a WASI writer's exit must give the
      // reader EOF), tears down unshared sockets and releases the file's OPFS lock -- a bare
      // fds.delete did none of that.
      fd_close: (fd) => { const r = S.sys('close', [fd]); return r < 0n ? wasiErrno(r) : OK; },
      fd_seek: (fd, off, whence, nptr) => { const h = S.fds.get(fd); if (!h || !h.file) return BADF;
        const size = h.file.size; const o = (h.off ??= { v: 0 }); o.v = whence === 0 ? Number(off) : whence === 1 ? o.v + Number(off) : size + Number(off);
        S.dv.setBigInt64(nptr, BigInt(o.v), true); return OK; },
      fd_fdstat_get: (fd, ptr) => { S.refresh(); S.u8.fill(0, ptr, ptr + 24); const h = S.fds.get(fd);
        S.u8[ptr] = h ? (h.dir ? 3 : (h.std !== undefined || h.fifo || h.pty !== undefined) ? 2 : 4) : 4;  // filetype
        S.dv.setBigUint64(ptr + 8, ~0n, true);    // fs_rights_base: grant all rights (preopen -> files inherit these)
        S.dv.setBigUint64(ptr + 16, ~0n, true);   // fs_rights_inheriting
        return OK; },
      fd_prestat_get: (fd, ptr) => { const h = S.fds.get(fd); if (h && h.preopen) { S.u8[ptr] = 0; S.i32(ptr + 4, h.preopen.length); return OK; } return BADF; },
      fd_prestat_dir_name: (fd, ptr, len) => { const h = S.fds.get(fd); if (!h || !h.preopen) return BADF; S.wbytes(ptr, te.encode(h.preopen).subarray(0, len)); return OK; },
      path_open: (dirfd, df, pptr, plen, oflags, r1, r2, fdflags, fdptr) => {
        const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p;
        const g = S.openAt(norm(name, base), (oflags & 1) ? 0o1101 : 0, 0o644);
        if (g < 0n) return NOENT; S.i32(fdptr, Number(g)); return OK; },
      // --- filestat / dir reads (rustc scans the sysroot rlibs) ---
      fd_filestat_get: (fd, buf) => { S.refresh(); const h = S.fds.get(fd); if (!h) return BADF;
        S.u8.fill(0, buf, buf + 64);
        S.dv.setBigUint64(buf, 1n, true);                                                              // dev
        S.dv.setBigUint64(buf + 8, BigInt(h.file ? inoOf(h.file) : h.dir ? inoOf(h.path) : 1), true); // ino: unique per file (see inoOf)
        S.u8[buf + 16] = h.dir ? 3 : (h.std !== undefined || h.fifo) ? 2 : 4;   // filetype
        S.dv.setBigUint64(buf + 24, 1n, true);                                   // nlink
        S.dv.setBigUint64(buf + 32, BigInt(h.file ? h.file.size : 0), true);     // size
        return OK; },
      path_filestat_get: (dirfd, flags, pptr, plen, buf) => { S.refresh();
        const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p;
        let p = norm(name, base); opfsFault(p); const pf = S.follow(p);
        S.u8.fill(0, buf, buf + 64); S.dv.setBigUint64(buf, 1n, true);   // dev
        if (dirs.has(pf)) { S.u8[buf + 16] = 3; S.dv.setBigUint64(buf + 8, BigInt(inoOf(pf)), true); S.dv.setBigUint64(buf + 24, 1n, true); return OK; }
        const f = files.get(pf); if (!f) return NOENT;
        S.dv.setBigUint64(buf + 8, BigInt(inoOf(f)), true);                  // ino: unique per file
        S.u8[buf + 16] = f.sym !== undefined ? 7 : 4; S.dv.setBigUint64(buf + 24, 1n, true);
        S.dv.setBigUint64(buf + 32, BigInt(f.size), true);
        if (f.mtimeMs) { const ns = BigInt(Math.floor(f.mtimeMs)) * 1000000n; S.dv.setBigUint64(buf + 40, ns, true); S.dv.setBigUint64(buf + 48, ns, true); S.dv.setBigUint64(buf + 56, ns, true); }
        return OK; },
      fd_pread: (fd, iptr, icnt, offset, nptr) => { S.refresh(); let tot = 0; const h = S.fds.get(fd);
        if (!h || !h.file) return BADF; let off = Number(offset);
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue; const b = fileRead(h.file, off, l); S.wbytes(p, b); off += b.length; tot += b.length; if (b.length < l) break; }
        S.i32(nptr, tot); return OK; },
      fd_readdir: (fd, buf, buf_len, cookie, nptr) => { S.refresh(); const h = S.fds.get(fd); if (!h || !h.dir) return BADF;
        opfsFault(h.path); const set = dirs.get(h.path); if (!set) return BADF;
        const names = ['.', '..', ...set]; let written = 0; const start = Number(cookie);
        // WASI: fill the buffer as full as possible; a partial final entry (written==buf_len)
        // tells libc to page again. Stopping short (written<buf_len) signals end-of-dir, so
        // NEVER break early with room to spare or libc misses the remaining entries.
        for (let i = start; i < names.length; i++) {
          const nm = names[i]; const nb = te.encode(nm);
          const hdr = new Uint8Array(24); const hv = new DataView(hdr.buffer);
          hv.setBigUint64(0, BigInt(i + 1), true);             // d_next = resume-at index
          hv.setBigUint64(8, BigInt(i + 1), true);             // d_ino (MUST be non-zero: 0 = skipped slot)
          hv.setUint32(16, nb.length, true);                   // d_namlen
          const cp = norm(nm, h.path); hdr[20] = (nm === '.' || nm === '..' || dirs.has(cp)) ? 3 : 4; // d_type
          const hcopy = Math.min(24, buf_len - written); if (hcopy <= 0) break;
          S.u8.set(hdr.subarray(0, hcopy), buf + written); written += hcopy; if (hcopy < 24) break;
          const ncopy = Math.min(nb.length, buf_len - written);
          S.u8.set(nb.subarray(0, ncopy), buf + written); written += ncopy; if (ncopy < nb.length) break;
        }
        S.i32(nptr, written); return OK; },
      path_readlink: (dirfd, pptr, plen, buf, blen, nptr) => { S.refresh();
        const name = td.decode(S.u8.slice(pptr, pptr + plen)); const h = S.fds.get(dirfd);
        const base = h && h.preopen ? h.preopen : S.cwd.p; const p = norm(name, base); opfsFault(p);
        const f = files.get(p); if (!f || f.sym === undefined) return NOENT;
        const b = te.encode(f.sym).subarray(0, blen); S.wbytes(buf, b); S.i32(nptr, b.length); return OK; },
      path_create_directory: (dirfd, pptr, plen) => { const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p; mkdirp(norm(name, base)); return OK; },
      // protectedDelete on BOTH ABIs. The Linux syscalls (unlink/rmdir/rename) have
      // gated the app's own workspace since the `rm -rf /root/sandpie` incidents, but
      // these three went straight to rmEntry() -- so a wasm32-wasi guest could still
      // delete sandpie/{conversations,memory,secrets,skills}. EPERM is 63 in preview1.
      path_unlink_file: (dirfd, pptr, plen) => { const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p; const p = norm(name, base);
        if (!files.has(p)) return NOENT;
        if (protectedDelete(S, p)) return 63;
        rmEntry(p); return OK; },
      path_remove_directory: (dirfd, pptr, plen) => { const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p; const p = norm(name, base);
        if (!dirs.has(p)) return NOENT;
        if (protectedDelete(S, p)) return 63;
        rmEntry(p); return OK; },
      path_rename: (odfd, optr, olen, ndfd, nptr, nlen) => { S.refresh();
        const on = td.decode(S.u8.slice(optr, optr + olen)), nn = td.decode(S.u8.slice(nptr, nptr + nlen));
        const oh = S.fds.get(odfd), nh = S.fds.get(ndfd);
        const op = norm(on, oh && oh.preopen ? oh.preopen : S.cwd.p);
        const np = norm(nn, nh && nh.preopen ? nh.preopen : S.cwd.p);
        opfsFault(op); const f = files.get(op); if (!f) return NOENT;
        if (!isAppPath(np) && protectedDelete(S, op)) return 63;   // moving out of the workspace == deleting it
        const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
        addFile(np, bytes.slice(), f.mode || 0o100644); rmEntry(op); return OK; },
      path_link: (odfd, oflags, optr, olen, ndfd, nptr, nlen) => { S.refresh();
        const on = td.decode(S.u8.slice(optr, optr + olen)), nn = td.decode(S.u8.slice(nptr, nptr + nlen));
        const oh = S.fds.get(odfd), nh = S.fds.get(ndfd);
        const op = norm(on, oh && oh.preopen ? oh.preopen : S.cwd.p);
        const np = norm(nn, nh && nh.preopen ? nh.preopen : S.cwd.p);
        opfsFault(op); const f = files.get(op); if (!f) return NOENT;
        const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
        addFile(np, bytes.slice(), f.mode || 0o100644); return OK; },
      // LLVM (yowasp's clang, run as a guest) needs these three as well.
      path_symlink: (optr, olen, dirfd, nptr, nlen) => { S.refresh();
        const target = td.decode(S.u8.slice(optr, optr + olen)), nn = td.decode(S.u8.slice(nptr, nptr + nlen));
        const h = S.fds.get(dirfd); const lp = norm(nn, h && h.preopen ? h.preopen : S.cwd.p);
        opfsFault(lp); if (files.has(lp) || dirs.has(lp)) return 20;                // EEXIST
        if (inOpfs(lp) && lp !== opfsMount) { const e = opfsSymlink(lp, target); if (e) return e === E.EXIST ? 20 : 29; }
        addFile(lp, new Uint8Array(0), 0o120777); const lf = files.get(lp);
        if (inOpfs(lp)) { lf.br = opfsRel(lp); lf.data = null; lf.size = te.encode(target).length; }
        lf.sym = target; return OK; },
      fd_filestat_set_size: (fd, size) => { const h = S.fds.get(fd); if (!h || !h.file) return BADF;
        const n = Number(size); const f = h.file;
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, n, 0, null); f.size = n; f.ownWrite = true; f.mtimeMs = Date.now(); return OK; }
        if (n <= f.size) { f.size = n; return OK; }
        const nd = new Uint8Array(Math.max(n, f.data ? f.data.length : 0)); if (f.data) nd.set(f.data.subarray(0, f.size)); f.data = nd; f.size = n; return OK; },
      fd_filestat_set_times: () => OK,
      environ_sizes_get: (cptr, sptr) => { S.i32(cptr, S.env.length); S.i32(sptr, S.env.reduce((a, e) => a + benc(e).length + 1, 0)); return OK; },
      environ_get: (eptr, bptr) => { let b = bptr; for (const e of S.env) { S.i32(eptr, b); eptr += 4; b += S.wstrB(b, e) + 1; } return OK; },
      args_sizes_get: (cptr, sptr) => { S.i32(cptr, S.argv.length); S.i32(sptr, S.argv.reduce((a, e) => a + benc(e).length + 1, 0)); return OK; },
      args_get: (aptr, bptr) => { let b = bptr; for (const a of S.argv) { S.i32(aptr, b); aptr += 4; b += S.wstrB(b, a) + 1; } return OK; },
      clock_time_get: (id, prec, ptr) => { S.dv.setBigInt64(ptr, BigInt(Date.now()) * 1000000n, true); return OK; },
      random_get: (ptr, len) => { const b = new Uint8Array(len); crypto.getRandomValues(b); S.wbytes(ptr, b); return OK; },
      fd_fdstat_set_flags: () => OK, fd_sync: () => OK, fd_datasync: () => OK, sched_yield: () => OK,
      // poll_oneoff used to be `() => OK` -- success with *nevents never written, so libc
      // read a stack leftover as the event count. Report every subscription as fired
      // right away (a clock sub returns immediately, so a timer loop spins rather than
      // sleeps; an fd sub says readable) and write the count. subscription = 48 bytes
      // {userdata u64, tag u8, u: clock{..} | fd_readwrite{fd u32 @16}}; event = 32 bytes
      // {userdata u64, error u16, type u8, fd_readwrite{nbytes u64 @16, flags u16 @24}}.
      poll_oneoff: (inp, outp, nsubs, nevp) => { S.refresh();
        for (let i = 0; i < nsubs; i++) { const s = inp + i * 48, e = outp + i * 32;
          S.u8.fill(0, e, e + 32);
          S.dv.setBigUint64(e, S.dv.getBigUint64(s, true), true);   // userdata
          S.u8[e + 10] = S.u8[s + 8];                                  // type = subscription tag
          if (S.u8[s + 8] !== 0) S.dv.setBigUint64(e + 16, 1n, true); // fd_read/fd_write: "1 byte available"
        }
        S.i32(nevp, nsubs); return OK; },
    };
    // EVERY entry re-syncs the memory views first. The guest grows linear memory
    // between calls (malloc -> memory.grow), which detaches the old ArrayBuffer; a
    // function that touched S.dv/S.u8 without refresh() then threw on a detached
    // buffer and the process died with exit 139. Measured with QuickJS: `qjs -q`
    // grows once during JS_NewRuntime and the next call is clock_time_get -- every
    // real run crashed while `--version` (no growth) worked. Wrapping here beats
    // auditing each entry forever: refresh() is two comparisons when nothing changed.
    for (const k of Object.keys(w)) { const f = w[k]; w[k] = (...a) => { S.refresh(); return f(...a); }; }
    return w;
  }

  // wasi-threads: the shared linear memory (env.memory import), created once per process
  getSharedMemory() {
    if (!this.sharedMem) {
      const lim = modSharedMem.get(this.modKey) || { initial: 256, maximum: 16384 };
      this.sharedMem = new WebAssembly.Memory({ initial: lim.initial, maximum: lim.maximum, shared: true });
    }
    return this.sharedMem;
  }

  // Run this process on its OWN thread and serve its syscalls from here.
  //
  // The guest parks in Atomics.wait inside a host import; this kernel thread stays free,
  // so other processes keep running and a blocked read no longer stops the world. Every
  // syscall implementation is reused verbatim -- the handler table is the same one
  // makeImports() builds -- because the guest's linear memory is SHARED and therefore
  // visible from here. A module that IMPORTS its memory (wasm32-wasi-threads builds:
  // qjs, rustc) is handed one created here, and a wasi `thread-spawn` starts another
  // worker on the same memory (threadSpawn) served by the same loop. This used to be a
  // second, WASI-only proxy (runProxied) with its own worker source and SAB layout.
  _workerPlan(mod) {
    const sigs = modSigs.get(this.modKey);
    if (!sigs) return null;
    const fns = WebAssembly.Module.imports(mod).filter((i) => i.kind === 'function');
    const names = fns.map((i) => i.module + '.' + i.name);
    names.push('@.dlbytes');                     // kernel-only op, not a wasm import
    // Rebuild each argument as the type the module DECLARED. wasm hands a JS import
    // its i32 params as Numbers and its i64 params as BigInts; the SAB carries every
    // slot as an i64, so converting back by declared type is what makes the handler
    // see exactly what an in-process instance would have passed it. Without this,
    // __get_init_envfile got a BigInt where wstr() wanted a Number and died with
    // "Cannot mix BigInt and other types" before the guest printed anything.
    const sigv = names.map((n) => ((sigs.get(n) || {}).retI64 ? 1 : 0));
    const parms = names.map((n) => (sigs.get(n) || {}).params || []);
    const imp = this.makeImports(mod);           // the handler table: exactly what an in-process instance got
    const handlers = names.map((n) => { const dot = n.indexOf('.'); const bag = imp[n.slice(0, dot)]; return bag ? bag[n.slice(dot + 1)] : null; });
    const memory = (imp.env && imp.env.memory instanceof WebAssembly.Memory) ? imp.env.memory : null;   // imported shared memory
    // A signal handler is a function-table index the worker calls (callGuest). Without
    // the table export there is nothing to call: predeliverAsync must take the default
    // action instead of asking the worker to run a handler it cannot reach.
    const table = WebAssembly.Module.exports(mod).some((e) => e.name === '__indirect_function_table' && e.kind === 'table');
    return { names, sigv, parms, handlers, memory, table };
  }

  async runInWorker(opts) {
    // A python3 that can start from a snapshot (decided before anything is built for it).
    const pick = opts ? null : await pySnapPick(this).catch((e) => { if (pySnapDebug(this)) post('[snapshot] cold: ' + ((e && e.message) || e) + '\n', 2); return null; });
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); return 127; }
    // Take a spare BEFORE building the plan: for a module that imports its memory,
    // makeImports hands out this.sharedMem, which has to be the memory the spare's
    // instance was built on.
    const spare = this.sharedMem ? null : takeSpare(this.modKey);
    if (spare && spare.memory) this.sharedMem = spare.memory;
    const plan = this._workerPlan(mod);
    if (!plan) { post(`[host] no import signatures for ${this.modKey} (compiled without bytes)\n`, 2); return 127; }
    this._plan = plan;
    // Staging buffer for dlopen: the guest links side modules itself (it owns the
    // instance) but cannot read the VFS, and a parked thread cannot be handed a new
    // SharedArrayBuffer -- so one growable buffer is installed up front and every .so
    // travels through it. Growable SAB is Chrome 111+; fall back to a fixed 32MB.
    let bulk;
    if (spare) { bulk = spare.bulk; }
    else {
      try { bulk = new SharedArrayBuffer(1 << 20, { maxByteLength: 64 << 20 }); }
      catch (_) { bulk = new SharedArrayBuffer(32 << 20); }
    }
    this._bulk = bulk;
    const ctl = spare ? spare.ctl : new SharedArrayBuffer(KCTL.BYTES);
    const w = spare ? spare.w : new Worker(NODE_STUB_RE.test(this.modKey) ? NODE_WORKER_URL : 'wali-proc-worker.js?v=tfork5');
    this.procWorker = w;
    const st = { exit: null };
    const ready = spare ? spare.ready : new Promise((res) => { this._procReady = res; });
    // The spare may not have seen its own 'ready' yet, and installing this process's
    // onmessage below replaces the handler that was waiting for it -- so route it here.
    if (spare) this._procReady = spare.settle;
    this._ctl = ctl;
    w.onmessage = (ev) => {
      const m = ev.data;
      if (m.t === 'ready') { this._procReady(m); return; }
      if (m.t === 'snap-dl') { pySnapLoaderLog(this, m); return; }
      if (m.t === 'restored' || m.t === 'restore-failed') { if (this._restoreAck) this._restoreAck(m); return; }
      if (m.t === 'warn') { post('[host] ' + m.s + '\n', 2); return; }
      if (m.t === 'trap') { post(`[host] trap in pid ${this.pid}: ${m.error}\n`, 2); return; }
      if (m.t === 'exit') { st.exit = m.code; }
    };
    w.onerror = (ev) => { if (this._restoreAck) { this._restoreAck({ t: 'restore-failed', error: 'worker failed: ' + (ev.message || ev) }); return; }   // (before the guest ran: start cold)
                          post(`[host] process worker for pid ${this.pid} failed: ${ev.message || ev}\n`, 2);
                          if (st.exit === null) st.exit = 139; Atomics.store(new Int32Array(ctl), 0, KCTL.DONE); Atomics.notify(new Int32Array(ctl), 0); };
    if (!spare) w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk, memory: plan.memory });
    const r = await ready;
    // Start the NEXT ones warming while this process runs -- a shell or a build is the same
    // few modules over and over, so the guess is nearly always right.
    try { prepareSpare(this.modKey, plan); } catch (_) {}
    if (!r.ok) { post(`[host] pid ${this.pid} failed to start: ${r.error}\n`, 2); w.terminate(); this.retire(); return 127; }
    this.memory = r.memory; this.membuf = null; this.refresh();

    if (opts && opts.forkFrom) {
      // Copy the parent's linear memory -- this IS its stack, which is what makes fork
      // work at all. The parent is parked unwound while we do it, so the snapshot is
      // consistent. Skip a trailing run of zero pages: the child's memory is already zero
      // there (same reduction as the in-process path).
      const src = new Uint8Array(opts.forkFrom.memory.buffer);
      const need = src.length - this.memory.buffer.byteLength;
      if (need > 0) { this.memory.grow(Math.ceil(need / PAGE)); this.membuf = null; this.refresh(); }
      let hw = src.length;
      for (let a = Math.floor((src.length - 1) / PAGE) * PAGE; a >= 0; a -= PAGE) {
        let nz = false; const end = Math.min(a + PAGE, src.length);
        for (let b = a; b < end; b++) if (src[b]) { nz = true; break; }
        if (nz) break;
        hw = a;
      }
      new Uint8Array(this.memory.buffer).set(src.subarray(0, hw));
      if (opts.onForkReady) opts.onForkReady();
      w.postMessage({ t: 'rewind', asyncifyBuf: opts.asyncifyBuf, sp: opts.sp, tls: opts.tls, thread: opts.thread || null });
    } else if (pick) {
      // Start from a Python snapshot (see pySnapPick): the guest half in the worker
      // (driveRestore in wali-proc-worker.js), then the kernel half here -- only once the
      // worker says the copy is in place, so a failed restore leaves nothing to undo.
      const s = pick.snap, t0 = performance.now();
      const ack = new Promise((res) => { this._restoreAck = res; });
      w.postMessage({ t: 'restore', snap: { mem: s.mem, len: s.len, ranges: s.ranges, dl: s.dl, table: s.table, tableLen: s.tableLen },
                      code: pyResumeCode(this.argv, this.env),
                      // e2e-python-snapshot.mjs: make this restore fail, to see the cold fallback work
                      testFail: (this.env || []).includes('WALIOS_SNAPSHOT_TEST_FAIL=1') });
      const r2 = await ack;
      this._restoreAck = null;
      if (r2.t !== 'restored') {
        // Nothing of the copy ran: start this same process cold, and stop using the layer.
        pySnaps.delete(s.layer); pySnapDead.add(s.layer);
        self.postMessage({ t: 'py-snap-failed', layer: s.layer, why: 'restore: ' + r2.error, drop: true });
        if (pySnapDebug(this)) post('[snapshot] restore failed, starting cold: ' + r2.error + '\n', 2);
        try { w.terminate(); } catch (_) {}
        this.procWorker = null; this.memory = null; this.membuf = null; this.sharedMem = null; procCount--;
        return this.runInWorker({ cold: true });
      }
      this.heapBrk = s.k.heapBrk;
      this.mmapFree = s.k.mmapFree.map((x) => ({ ...x }));
      this.mmapLive = new Map(s.k.mmapLive);
      for (const [sg, h] of s.k.sig) this.sig.handlers.set(sg, { ...h });
      for (const k of s.hostcallFds || []) if (!this.fds.has(k)) { this.fds.set(k, { hostcall: { inbuf: '', chunks: [], waiters: [] }, cloexec: false }); this.nextFd = Math.max(this.nextFd, k + 1); }
      if (pySnapDebug(this)) post(`[snapshot] '${s.layer}' (${pick.mode}): mount ${pick.mountMs.toFixed(0)}ms, restore ${(performance.now() - t0).toFixed(0)}ms ${JSON.stringify(r2.ms)}, ${(s.stat.kept / 1048576).toFixed(0)} of ${(s.len / 1048576).toFixed(0)}MB, built in ${s.stat.buildMs}ms\n`, 2);
    } else {
      w.postMessage({ t: 'run' });
    }
    const res = await this._serve(w, ctl, plan, bulk, st, true, this.pid);
    for (const t of this._threads || []) { try { t.terminate(); } catch (_) {} }
    // This run wanted a snapshot nobody had: ask for it now that it is done, so the build
    // (if this kernel gets to do it) runs while the result is being read.
    if (this.pySnapWant) { try { pySnapWant(this.pySnapWant); } catch (_) {} this.pySnapWant = null; }
    if (res.replaced !== undefined) return res.replaced;   // execve: the new image owns this pid; it retires itself
    this.retire();
    return res.code;
  }

  // wasi-threads: pthread_create in the guest -> a new worker running
  // wasi_thread_start(tid, arg) on THIS process's memory, served by the same loop as the
  // main thread. The kernel (never blocked) creates it, so a main thread that parks in a
  // futex right after spawning cannot deadlock the start. Returns the tid.
  threadSpawn(startArg, entry) {
    entry = entry || 'wasi_thread_start';
    if (this._inproc) {
      // A thread is a second instance on the same memory served by another worker, and
      // there are no workers here (no SharedArrayBuffer). EAGAIN: Python raises RuntimeError.
      if (!unknownSyscalls.has('threads:inproc')) { unknownSyscalls.add('threads:inproc');
        post(`[host] pid ${this.pid}: threads are unavailable in the in-process engine (no SharedArrayBuffer) -> pthread_create EAGAIN\n`, 2); }
      return -1;
    }
    const plan = this._plan, mod = modCache.get(this.modKey);
    if (!plan || !mod || !this.memory) return -1;
    // A second instance only shares memory if the module IMPORTS it. One that defines its
    // own would get a private copy -- threads that cannot see each other -- so refuse.
    if (!plan.memory) {
      if (!unknownSyscalls.has('threads:' + this.modKey)) { unknownSyscalls.add('threads:' + this.modKey);
        post(`[host] pid ${this.pid}: this binary defines its own memory, so threads cannot share it -> pthread_create EAGAIN (relink with --import-memory or run scripts/wasm-import-memory.mjs)\n`, 2); }
      return -1;
    }
    if (!WebAssembly.Module.exports(mod).some((e) => e.name === entry)) { post(`[host] pid ${this.pid}: no ${entry} export; cannot start a thread\n`, 2); return -1; }
    const tid = this._nextTid = (this._nextTid || 1) + 1;
    if (this.sig.masks) this.sig.masks.set(tid, this.sig.mask);   // a new thread starts with its creator's mask
    const ctl = new SharedArrayBuffer(KCTL.BYTES);
    const w = new Worker('wali-proc-worker.js?v=tfork5');
    w._ph = 'new';   // thread startup phase, shown in the stats list: new -> ready -> run
    (this._threads = this._threads || []).push(w);
    const st = { exit: null };
    const ready = new Promise((res) => {
      w.onmessage = (ev) => { const m = ev.data;
        if (m.t === 'ready') { w._ph = 'ready'; res(m); }
        else if (m.t === 'warn') post('[host] ' + m.s + '\n', 2);
        else if (m.t === 'trap') post(`[host] thread ${tid} of pid ${this.pid}: ${m.error}\n`, 2); };
    });
    w.onerror = (ev) => { post(`[host] thread ${tid} of pid ${this.pid} failed: ${ev.message || ev}\n`, 2);
                          Atomics.store(new Int32Array(ctl), 0, KCTL.DONE); Atomics.notify(new Int32Array(ctl), 0); };
    w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk: this._bulk, memory: this.memory });
    ready.then((r) => {
      if (!r.ok) { post(`[host] thread ${tid} of pid ${this.pid} failed to start: ${r.error}\n`, 2); return; }
      w._ph = 'run'; w.postMessage({ t: 'run', mode: 'thread', entry, tid, startArg: Number(startArg) });
      return this._serve(w, ctl, plan, this._bulk, st, false, tid);
    }).catch((e) => post(`[host] thread ${tid} of pid ${this.pid}: ${(e && e.stack) || e}\n`, 2))
      .finally(() => { try { w.terminate(); } catch (_) {} const i = (this._threads || []).indexOf(w); if (i >= 0) this._threads.splice(i, 1); });
    return tid;
  }

  // exit_group from any thread: the whole process ends with that code -- every thread
  // worker and the main worker are terminated, and the main serve loop is released.
  groupExit(code) {
    if (this._inproc) {
      // No worker to terminate: the guest unwinds at its next syscall boundary (a parked
      // one right away, through the race in its Suspending import). Pure computation
      // cannot be stopped from here, as in the worker model's SIGSTOP note above.
      this._dead = code & 0xff;
      if (this._goneRes) this._goneRes();
      return;
    }
    const m = this._main; if (!m) return;
    for (const t of this._threads || []) { try { t.terminate(); } catch (_) {} }
    try { m.w.terminate(); } catch (_) {}
    m.st.exit = code & 0xff;
    Atomics.store(m.i32, 0, KCTL.DONE); Atomics.notify(m.i32, 0);
    if (this._goneRes) this._goneRes();
  }

  // Serve one worker (the main thread of this process, or one of its wasi threads) until
  // it reports DONE. Returns { code } or, when the main thread exec'd a new image,
  // { replaced: <exit code of the image that took over this pid> }.
  async _serve(w, ctl, plan, bulk, st, isMain, tid) {
    const rec = { P: this, f64: new Float64Array(ctl) };
    cpuLive.add(rec);
    try { return await this._serveLoop(w, ctl, plan, bulk, st, isMain, tid); }
    finally { cpuLive.delete(rec); const c = cpuOfRec(rec); this.cpuMs = (this.cpuMs || 0) + c; cpuDoneMs += c; }
  }
  async _serveLoop(w, ctl, plan, bulk, st, isMain, tid) {
    const { names, parms, handlers } = plan;
    const I64 = 0x7e;
    const i32 = new Int32Array(ctl), i64 = new BigInt64Array(ctl);
    const reply = (v) => { i64[KCTL.RET >> 3] = v; Atomics.store(i32, 0, KCTL.REPLY); Atomics.notify(i32, 0); };
    if (isMain) this._main = { w, i32, st };   // so a thread's exit_group can end the process (groupExit)
    // Resolved by groupExit: every serve loop of this process (main and threads) races its
    // waits against it, because the main thread may be parked in a syscall that the dead
    // thread was going to complete -- CPython's main waiting on the GIL futex while the
    // thread that held it called os._exit -- and would otherwise never see DONE.
    const gone = this._gone || (this._gone = new Promise((res) => { this._goneRes = res; }));
    let exited = false; gone.then(() => { exited = true; });

    // One request, served. Lifted out of the loop because a signal handler runs
    // INSIDE the guest and makes its own syscalls, so the nested loop in callGuest
    // has to serve them with exactly this code.
    const serveReq = async () => {
      const idx = Atomics.load(i32, 1), argc = Atomics.load(i32, 2);
      const pk = parms[idx];
      const args = [];
      for (let k = 0; k < argc; k++) {
        const raw = i64[(KCTL.ARGS >> 3) + k];
        args.push(pk[k] === I64 ? raw : Number(raw));
      }
      let ret = 0n;
      try {
        // Deliver anything pending BEFORE the call, the way the in-process syscall
        // wrapper does with predeliver(). It has to be the async twin here: the sync one
        // cannot re-enter the guest, and with it disabled a SIGPIPE queued by write()
        // was simply never delivered -- `yes` kept writing to a pipe with no reader
        // forever, so the pipeline printed the right answer and then hung.
        this.curTid = tid;      // before predeliver: a fatal signal parks the CHILD only if the window check sees the right thread
        if (isMain) {
          this.sigDelivered = false;
          const dv0 = this.sig.pending.size ? await this.predeliverAsync() : null;
          if (dv0 !== null) { reply((typeof dv0 === 'bigint') ? dv0 : BigInt(Math.trunc(Number(dv0) || 0))); return; }
        }
        const nm = names[idx];
        const sysname = nm.startsWith('wali.SYS_') ? nm.slice(9) : null;
        let v;
        this.curTid = tid;      // which thread of this process is calling (gettid, set_tid_address)
        if (nm === 'wasi_snapshot_preview1.fd_read') { await this.waitReadable(args[0]); this.curTid = tid; }   // WASI's blocking read
        if (sysname && isBlocking(sysname, args)) {
          // A blocking syscall must NOT run inline on this thread: sysAsync is the
          // promise-based twin; awaiting it keeps the event loop free, which is the
          // whole point of running guests on their own threads.
          const margs = args.map((x) => (typeof x === 'bigint' && sysname !== 'mmap') ? i64arg(x) : x);
          if (STRACE) stracePost(`[strace ${this.pid}${tid && tid !== this.pid ? '.' + tid : ''}] ${sysname}(${margs.join(', ')}) ...\n`, 2);   // entry of a blocking call: a hang shows who is parked where
          const tk = performance.now(), pr = S_await(this, sysname, margs);   // (its synchronous part counts as kernel load)
          kBusyMs += performance.now() - tk;
          v = await pr;
          this.curTid = tid;    // another thread's syscall may have been served meanwhile (inChild/fds key on it)
        } else {
          const h = handlers[idx];
          if (!h) throw new Error('no handler for ' + nm);
          const tk = performance.now();
          try { v = h(...args); } finally { kBusyMs += performance.now() - tk; }
        }
        ret = (typeof v === 'bigint') ? v : BigInt(Math.trunc(Number(v) || 0));
      } catch (e0) {
        const e = unwrapJS(e0);
        if (e instanceof ExitError) {
          // exit/exit_group/__proc_exit unwind the GUEST's stack when the instance
          // lives here. It does not any more, so the guest would take the return
          // value and keep running. Answer with DIE and let its stub throw.
          // From a THREAD, exit_group (os._exit, exit(), a fatal error) used to end only
          // that thread's worker while the main thread kept running.
          if (!isMain && e.group) this.groupExit(e.code);
          st.exit = e.code & 0xff;
          Atomics.store(i32, 3, st.exit | 0);
          Atomics.store(i32, 0, KCTL.DIE);
          Atomics.notify(i32, 0);
          return;
        }
        post(`[host] pid ${this.pid} syscall ${names[idx]}: ${e.stack || e}\n`, 2); ret = -1n;
      }
      if (STRACE) stracePost(`[strace ${this.pid}${tid && tid !== this.pid ? '.' + tid : ''}${this.inChild() ? '>' + this.childStack[this.childStack.length - 1].pid : ''}] ${names[idx].replace(/^wali\.SYS_/, '')}(${args.map(String).join(', ')}) = ${ret}\n`, 2);
      reply(ret);
    };

    if (isMain) {
      // Run a signal handler in the guest and wait for it to come back. The instance
      // (and its indirect function table) lives in the worker, so the handler runs
      // there, at the same point the in-process model would have re-entered wasm; its
      // own syscalls come back here as ordinary requests, hence the nested loop.
      this.callGuest = async (ptr, sig) => {
        Atomics.store(i32, 4, ptr | 0);
        Atomics.store(i32, 5, sig | 0);
        Atomics.store(i32, 0, KCTL.SIGNAL);
        Atomics.notify(i32, 0);
        for (;;) {
          const st2 = Atomics.load(i32, 0);
          if (st2 === KCTL.SIGDONE || st2 === KCTL.DONE) return;
          // The handler exited instead of returning (see the ST_DIE note in
          // wali-proc-worker.js). Raise it as the exit it is, so the process dies the
          // ordinary way -- reaped, parent woken -- rather than looking like a handler
          // that came back to a guest which is in fact already unwinding.
          if (st2 === KCTL.DIE) throw new ExitError(Atomics.load(i32, 3) & 0xff, true);
          if (st2 === KCTL.REQ) { await serveReq(); continue; }
          const q2 = Atomics.waitAsync(i32, 0, st2);
          if (q2.async) await q2.value; else await new Promise((res) => setTimeout(res, 0));
        }
      };
    }

    // Serve until the guest reports it is finished. waitAsync keeps this thread's event
    // loop alive, which is the whole point: postMessage, timers and other processes'
    // replies all still get through while this one is parked.
    let justServed = false;
    for (;;) {
      const state = Atomics.load(i32, 0);
      if (state === KCTL.DONE) break;
      if (state === KCTL.FORKED) {
        // The guest has unwound and wants a child. Build it, boot its worker and copy the
        // snapshot BEFORE replying -- the parent must not resume until the copy is taken.
        // From ANY thread: git starts its filters, parallel-checkout workers and other async
        // helpers from a pthread, which forks and execs. That fork's unwind used to end the
        // thread silently (only the main thread had the handshake) and the main thread then
        // waited forever on the pipe the helper should have fed -- every clean/smudge filter
        // (git-lfs too) hung. The child, like on Linux, is a copy of just the calling thread;
        // it rewinds through that thread's entry instead of _start (proc worker driveThread).
        if (!isMain) this.curTid = tid;   // the child inherits THIS thread's signal mask
        const childPid = nextPid++;
        const child = this.spawnForkChildMeta(childPid);
        const buf = Number(i64[KCTL.RET >> 3]);
        const sp = Number(i64[KCTL.ARGS >> 3]), tls = Number(i64[(KCTL.ARGS >> 3) + 1]);   // parent's stack pointer / TLS base (-1: not exported)
        const tEntry = Number(i64[(KCTL.ARGS >> 3) + 2]);   // 0: main (_start); 1 wasi_thread_start; 2 __wasm_thread_start_libc
        const thread = tEntry > 0 ? { entry: tEntry === 1 ? 'wasi_thread_start' : '__wasm_thread_start_libc',
          tid: Number(i64[(KCTL.ARGS >> 3) + 3]), startArg: Number(i64[(KCTL.ARGS >> 3) + 4]) } : null;
        let started;
        const boot = new Promise((res) => { started = res; });
        const task = child.runInWorker({ forkFrom: this, asyncifyBuf: buf, sp, tls, thread, onForkReady: started })
          .then((code) => {
            this.reaped.set(childPid, code);
            if (STRACE) stracePost(`[strace ${childPid}] exited ${code} (fork child of ${this.pid})\n`, 2);
            releaseFds(child.fds);
            this.childTasks.delete(childPid);
            postSignal(this, SIG.CHLD); wakeWaiters(this);
            return code;
          });
        inflight.add(task); task.finally(() => inflight.delete(task));
        this.childTasks.set(childPid, task);
        await Promise.race([boot, task]);
        reply(BigInt(childPid));
        continue;
      }
      if (state === KCTL.REQ && names[Atomics.load(i32, 1)] === '@.dlbytes') {
        // Resolve the .so the way dlopen used to, and copy it into the staging buffer.
        let n = -1;
        try {
          const p = this.follow(this.atPath(-100, this.cstr(Number(i64[KCTL.ARGS >> 3]))));
          opfsFault(p);
          const f = files.get(p);
          if (f) {
            const bytes = fileRead(f, 0, f.size);
            const mis = abiMismatch(this, bytes, p); if (mis) { post('[host] dlopen: ' + mis + '\n', 2); reply(-2n); continue; }
            if (bulk.byteLength < bytes.length) {
              if (bulk.grow) bulk.grow(Math.min(bulk.maxByteLength, Math.ceil(bytes.length / 65536) * 65536));
              else throw new Error('.so larger than the staging buffer');
            }
            if (bulk.byteLength < bytes.length) throw new Error('.so does not fit the staging buffer');
            new Uint8Array(bulk).set(bytes);
            n = bytes.length;
          }
        } catch (e) { post('[host] dlbytes: ' + ((e && e.message) || e) + '\n', 2); n = -1; }
        reply(BigInt(n));
        continue;
      }
      // posix_spawn(pathPtr, argvPtr, envpPtr, fdmapPtr, fdmapLen) -> pid | -errno
      // fdmapLen pairs of int32 [childFd, parentFd]; parentFd < 0 closes childFd.
      // fdmapLen's HIGH 16 bits are flags (bit 0: setsid). They ride on an argument every
      // caller already passes: a 6th one would read a stale slot for the old 5-arg callers.
      // Unlike execve this starts a NEW pid and leaves the caller running, so the
      // existing wait4/SIGCHLD machinery reaps it with no change.
      if (state === KCTL.REQ && names[Atomics.load(i32, 1)] === 'wali.SYS_posix_spawn') {
        this.curTid = tid;
        const b = KCTL.ARGS >> 3;
        const a0 = Number(i64[b]), a1 = Number(i64[b + 1]), a2 = Number(i64[b + 2]),
              a3 = Number(i64[b + 3]), a4 = Number(i64[b + 4]);
        let path = '', av = [], ev = null; const spec = [];
        try {
          path = this.cstr(a0); av = this.rPtrArray(a1);
          ev = a2 ? this.rPtrArray(a2) : null;
          for (let k = 0; k < (a4 & 0xffff); k++) spec.push([this.r32(a3 + k * 8), this.r32(a3 + k * 8 + 4)]);
        } catch (_) { reply(BigInt(-E.INVAL)); continue; }
        const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
        // The await let other threads run and they move curTid, which is what fds keys
        // on (see the execve handler for what that cost the last time).
        this.curTid = tid;
        if (!target || target.eacces) { reply(BigInt(-(target ? E.ACCES : E.NOENT))); continue; }
        let childFds;
        try { childFds = spawnFdTable(this.fds, spec); }
        catch (e) { reply(BigInt(-(e && e.badf ? E.BADF : E.INVAL))); continue; }
        const proc = new Process(target.key, target.argv, ev || this.env, childFds, this.cwd.p);
        if (this.cred) proc.cred = { ...this.cred };
        proc.umask = this.umask;   // POSIX: inherited (every child started with 022: git's shared-repo dirs came out 755 under umask 002)
        proc.ppid = this.pid; proc.pgid = this.pgid; proc.sid = this.sid;
        if (a4 >>> 16 & 1) { proc.pgid = proc.pid; proc.sid = proc.pid; }   // POSIX_SPAWN_SETSID
        const childPid = proc.pid;
        if (STRACE) stracePost(`[strace ${this.pid}] posix_spawn(${JSON.stringify(path)}) = ${childPid}
`, 2);
        const task = Promise.resolve(proc.run()).then((code) => {
          this.reaped.set(childPid, code === null ? 127 : code);
          releaseFds(childFds);
          this.childTasks.delete(childPid);
          postSignal(this, SIG.CHLD); wakeWaiters(this);
          return code;
        });
        inflight.add(task); task.finally(() => inflight.delete(task));
        this.childTasks.set(childPid, task);
        reply(BigInt(childPid));
        continue;
      }
      if (state === KCTL.REQ && names[Atomics.load(i32, 1)] === 'wali.SYS_execve') {
        this.curTid = tid;
        // A thread may fork+exec (the child branch runs on IT): served here like the main
        // thread's. A thread replacing the whole image is not supported.
        if (!isMain && !this.inChild()) { post('[host] pid ' + this.pid + ': execve from a thread outside fork() is not supported (ENOSYS)\n', 2); reply(BigInt(-E.NOSYS)); continue; }
        // execve replaces this process's image. The image is a wasm instance living in
        // the worker, so "replace" means: start the new one on a fresh worker under the
        // SAME pid, and tell this worker to stop. Resolve (and fetch/compile) FIRST, so a
        // missing program is an ordinary ENOENT to the guest rather than a dead process.
        const a0 = Number(i64[KCTL.ARGS >> 3]), a1 = Number(i64[(KCTL.ARGS >> 3) + 1]), a2 = Number(i64[(KCTL.ARGS >> 3) + 2]);
        this.curTid = tid;
        let path = '', av = [], ev = [];
        try { path = this.cstr(a0); av = this.rPtrArray(a1); ev = a2 ? this.rPtrArray(a2) : []; } catch (_) {}
        if (STRACE) stracePost(`[strace ${this.pid}${this.inChild() ? '>' + this.childStack[this.childStack.length - 1].pid : ''}] execve(${JSON.stringify(path)}) ...\n`, 2);
        const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
        // The await above let other threads' syscalls run, and they move curTid -- which is
        // what inChild()/fds key on. Put this thread back before deciding WHOSE execve this
        // is: with a sideband thread busy during index-pack's spawn, the vfork child's exec
        // was taken for the parent's and git fetch turned into index-pack.
        this.curTid = tid;
        if (!target || target.eacces) { reply(BigInt(-(target ? E.ACCES : E.NOENT))); continue; }
        const fdsnap = execDropCloexec(this.fds);
        if (this.inChild()) {
          // vfork protocol (see sys 'fork'): the guest is in the child branch, so this
          // execve is the CHILD's. Start it on its own worker under the pid fork()
          // reported, hand the parent its state back and answer CHILD_DONE so the libc
          // wrapper longjmps to the fork site.
          const ctx = this.childStack[this.childStack.length - 1];
          const childPid = ctx.pid;
          const ccwd = this.cwd.p;   // the child's cwd: read it before the pop puts the parent's view back
          this.childStack.pop(); this.unVfork(ctx);
          const task = Promise.resolve(startProcess(target, ev, fdsnap, ccwd, this.cred, childPid, this.umask)).then((code) => {
            this.reaped.set(childPid, code === null ? 127 : code);
            releaseFds(fdsnap);
            this.childTasks.delete(childPid);
            postSignal(this, SIG.CHLD); wakeWaiters(this);
            return code;
          });
          const cp = procs.get(childPid); if (cp) { cp.ppid = this.pid; cp.pgid = ctx.pgid; cp.sid = ctx.sid; }
          inflight.add(task); task.finally(() => inflight.delete(task));
          this.childTasks.set(childPid, task);
          reply(CHILD_DONE);
          continue;
        }
        Atomics.store(i32, 3, 0);
        Atomics.store(i32, 0, KCTL.DIE);
        Atomics.notify(i32, 0);
        const code = await startProcess(target, ev, fdsnap, this.cwd.p, this.cred, this.pid, this.umask);
        w.terminate();
        // NOT retire(): the new image owns this pid now, and retire() does
        // procs.delete(this.pid) -- which would delete the process that just replaced us
        // and leave the parent's wait4 with nothing to reap.
        return { replaced: (code === null ? 127 : code) & 0xff };
      }
      if (state === KCTL.REQ) { await Promise.race([serveReq(), gone]); if (exited) break; justServed = true; continue; }
      // Poll before parking. A guest busy with syscalls sends its next request a few
      // microseconds after our reply, but waitAsync only resumes this loop on a later turn
      // of the event loop: profiled under busybox awk (a flush per printed line), the guest
      // sat 90% in hostCall waiting while this thread was 74% idle. Only right after serving
      // a request, and only for KSPIN_MS, so a quiet process costs the other processes at
      // most that once before we park as before.
      if (justServed) {
        justServed = false;
        const t0 = performance.now(); let s2;
        while (((s2 = Atomics.load(i32, 0)) === KCTL.IDLE || s2 === KCTL.REPLY) && performance.now() - t0 < KSPIN_MS) {}
        if (s2 === KCTL.REQ || s2 === KCTL.DONE || s2 === KCTL.FORKED) continue;
      }
      const q = Atomics.waitAsync(i32, 0, state);
      if (q.async) await Promise.race([q.value, gone]); else await new Promise((res) => setTimeout(res, 0));
      if (exited) break;
    }
    const code = st.exit !== null ? st.exit : (Atomics.load(i32, 3) | 0);
    // wali-musl uses codes ABOVE 255 for startup failures precisely so they can be told apart
    // from a real main() status (init_env.h: WALI_STARTUP_FAIL 257 .. WALI_ENV_MALLOC_FAIL 261).
    // Masking to a byte threw that distinction away: ENV_READ_FAIL 259 became a baffling silent
    // "exit 3". Say what actually happened.
    if (code > 255) {
      const WALI_FAIL = { 257: 'startup failed', 258: 'cleanup failed', 259: 'could not read its environment file',
                          260: 'could not get its environment filename', 261: 'out of memory building its environment' };
      post(`[host] pid ${this.pid} died before main: ${WALI_FAIL[code] || 'wali startup code ' + code}\n`, 2);
    }
    w.terminate();
    return { code: code & 0xff };
  }

  // Run this process on whichever engine the page allows (see INPROC).
  run() { return INPROC ? this.runInProc() : this.runInWorker(); }

  // ---- in-process engine (JSPI) ----
  // No SharedArrayBuffer (a page without cross-origin isolation: the Android system
  // WebView never grants it) means no process workers: a guest's memory could not be
  // seen from this thread and nothing could park in Atomics.wait. So every process runs
  // HERE, on the kernel's own thread, and each wali syscall import is a
  // WebAssembly.Suspending wrapper: when the handler returns a promise, JSPI suspends the
  // guest's wasm stack (stack switching, not Asyncify), this thread goes back to its
  // event loop to serve the other processes, and the guest resumes when the promise
  // settles. A handler that answers at once returns a plain value and nothing is
  // suspended. The handler table and the sysAsync twins are the worker model's, verbatim.
  // What this engine cannot do: run two guests at the same time (they interleave at
  // syscall boundaries, so a pure-CPU loop holds everyone up until its next syscall),
  // threads (shared memory between workers -> pthread_create EAGAIN), or stop a guest that
  // never makes a syscall. fork() still works through Asyncify: busybox unwinds, the child
  // is a second instance over a copy of the memory, and both rewind as concurrent
  // promising tasks. The JSPI engine deleted in sandpie-server 1ff7abf is this code's ancestor.
  _makeInProcImports(mod) {
    const S = this;
    const imp = this.makeImports(mod);           // the handler table, exactly what a worker-proxied instance gets
    const wali = imp.wali;
    const asyncifyCap = WebAssembly.Module.exports(mod).some((e) => e.name === 'asyncify_start_unwind');
    for (const im of WebAssembly.Module.imports(mod)) {
      if (im.module !== 'wali' || !im.name.startsWith('SYS_')) continue;
      const name = im.name, sysname = name.slice(4);
      if (sysname === 'fork' && asyncifyCap) {
        // Asyncify fork, as wali-proc-worker.js does it locally: unwind the guest's stack
        // into a buffer at the end of linear memory; _driveInProc builds the child from it.
        // Plain (not Suspending): the unwind must return to the guest synchronously.
        wali[name] = () => {
          if (S.forkState === 'rewinding') { S.inst.exports.asyncify_stop_rewind(); S.forkState = 'none'; return S.forkRet; }
          if (!S.asyncifyBuf) { S.refresh(); const old = S.memory.buffer.byteLength; S.memory.grow(INPROC_ASYNC_PAGES); S.asyncifyBuf = old; S.refresh(); }
          const d = new DataView(S.memory.buffer);
          d.setUint32(S.asyncifyBuf, S.asyncifyBuf + 8, true);
          d.setUint32(S.asyncifyBuf + 4, S.asyncifyBuf + INPROC_ASYNC_PAGES * PAGE, true);
          S.inst.exports.asyncify_start_unwind(S.asyncifyBuf);
          S.forkState = 'unwinding';
          return 0n;
        };
        continue;
      }
      const map = (a2) => a2.map((x) => (typeof x === 'bigint' && sysname !== 'mmap') ? i64arg(x) : x);
      const special = sysname === 'execve' || sysname === 'posix_spawn';
      const blocking = BLOCKING.has(sysname);
      // The slow path: anything that may suspend. Signals are delivered here (handlers run
      // under their own promising context, see _inprocInit), SIGSTOP parks here, and
      // every QUANTUM_MS the guest yields one event-loop turn so messages (stdin, killall)
      // and the other processes get through even when it never blocks.
      // `needed`: a NeedAsync the fast path ran into (a bridge answer to wait for first).
      const slow = async (a2, needed) => {
        const dv = await S.predeliverAsync(); if (dv !== null) return dv;
        while (S.stopped) { await new Promise((res) => S.contWaiters.push(res)); const dv2 = await S.predeliverAsync(); if (dv2 !== null) return dv2; }
        if (S._dead !== undefined) throw new ExitError(S._dead, true);
        const now = Date.now();
        if (now - S.lastYield >= QUANTUM_MS) { S.lastYield = now; await new Promise((res) => setTimeout(res, 0)); }
        if (STRACE && (blocking || special)) stracePost(`[strace ${S.pid}] ${sysname}(${map(a2).join(', ')}) ...\n`, 2);
        let v;
        for (;;) {
          if (needed) { await needed.promise; needed = null; if (S._dead !== undefined) throw new ExitError(S._dead, true); }
          try {
            if (sysname === 'execve') v = await S._execveInProc(map(a2));
            else if (sysname === 'posix_spawn') v = await S._posixSpawnInProc(map(a2));
            else if (blocking || ((sysname === 'fcntl' || sysname === 'flock') && lockWaits(sysname, a2))) v = await Promise.race([S_await(S, sysname, map(a2)), S._goneP]);
            else v = S.sys(sysname, map(a2));
            break;
          } catch (e) {
            if (!(e instanceof NeedAsync)) throw e;
            needed = e;                                // a bridge answer is on its way: wait, then run the syscall again
          }
        }
        if (S._dead !== undefined) throw new ExitError(S._dead, true);
        if (STRACE) stracePost(`[strace ${S.pid}] ${sysname}(${map(a2).join(', ')}) = ${v}\n`, 2);
        return v;
      };
      wali[name] = new WebAssembly.Suspending((...a2) => {
        S.syscalls++; syscallTotal++;
        S.pollTimers();
        if (S.shmAt.size) S.syncShm();
        S.sigDelivered = false;
        if (blocking || ((sysname === 'fcntl' || sysname === 'flock') && lockWaits(sysname, a2)) || special || S.sig.pending.size || S.stopped || S._dead !== undefined || Date.now() - S.lastYield >= QUANTUM_MS) return slow(a2);
        let v;
        try { v = S.sys(sysname, map(a2)); }         // a value, not a promise: the guest is not suspended
        catch (e) { if (e instanceof NeedAsync) return slow(a2, e); throw e; }
        if (STRACE) stracePost(`[strace ${S.pid}] ${sysname}(${map(a2).join(', ')}) = ${v}\n`, 2);
        return v;
      });
    }
    // dlopen reads the .so through the VFS, which may have to fetch it from the bridge:
    // the same wait-and-run-again as a syscall.
    const envI = imp.env;
    if (envI && envI.__wali_dlopen) {
      const dl = envI.__wali_dlopen;
      envI.__wali_dlopen = new WebAssembly.Suspending((p, fl) => {
        try { return dl(p, fl); }
        catch (e) {
          if (!(e instanceof NeedAsync)) throw e;
          return (async () => { let ne = e; for (;;) { await ne.promise; try { return dl(p, fl); } catch (e2) { if (!(e2 instanceof NeedAsync)) throw e2; ne = e2; } } })();
        }
      });
    }
    // libffi (walios/build/libffi): calls and closures through this instance's table, on JSPI
    // stacks of their own so a callee's syscall can still suspend.
    if (envI) { const ffi = waliFfiImports(() => S.inst.exports, true); for (const k of Object.keys(ffi)) if (k in envI) envI[k] = ffi[k];
      if ('__wali_ffi_table_alloc' in envI) envI.__wali_ffi_table_alloc = (...a) => { S.snapUnsafe = S.snapUnsafe || 'libffi closure'; return ffi.__wali_ffi_table_alloc(...a); }; }
    // wali.__stackhop (farm/ci/stackhop.mjs; the worker engine's twin is wali-proc-worker.js
    // stackHop): continue a deep recursion on a fresh JSPI stack. Here the guest itself runs on
    // a promising stack and its syscalls may suspend, so the hop is a Suspending import that
    // awaits the new stack: a suspension inside suspends the outer one too, and an exit or trap
    // arrives through the await. A fork() unwinding inside returns early with
    // __stackhop_done 0 and Asyncify carries on unwinding the outer frames.
    if ('__stackhop' in wali) wali.__stackhop = new WebAssembly.Suspending(async () => {
      const ex = S.inst.exports;
      await WebAssembly.promising(ex.__stackhop_enter)();
      ex.__stackhop_done.value = 0;
    });
    // WASI: fd_read blocks BEFORE the sync shim runs (the worker loop parks in waitReadable).
    const wasi = imp.wasi_snapshot_preview1;
    if (wasi && wasi.fd_read) { const fdRead = wasi.fd_read; wasi.fd_read = new WebAssembly.Suspending(async (fd, ...rest) => { await S.waitReadable(fd); return fdRead(fd, ...rest); }); }
    return imp;
  }

  _inprocInit() {
    this._inproc = true;
    this.memory = this.inst.exports.memory || this.sharedMem; this.membuf = null; this.refresh();
    this.lastYield = Date.now();
    this._goneP = new Promise((res) => { this._goneRes = res; });
    // Signal handlers run in the guest under their OWN promising context, so a handler
    // that makes a syscall (busybox ping's SIGALRM -> sendto) suspends like any other
    // code; calling table.get(ptr)(sig) bare would trap on its first Suspending import.
    // predeliverAsync takes the default action instead when the binary has no table.
    const table = this.inst.exports.__indirect_function_table;
    this._plan = { table: !!table, names: [], memory: null };
    this.callGuest = async (ptr, sig) => { await WebAssembly.promising(table.get(ptr))(sig); };
  }

  async runInProc() {
    const pick = await pySnapPick(this).catch((e) => { if (pySnapDebug(this)) post('[snapshot] cold: ' + ((e && e.message) || e) + '\n', 2); return null; });
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); this.retire(); return 127; }
    // A clean JS stack: a promising export must not start inside another guest's
    // suspending import (execve and posix_spawn get here from one).
    await new Promise((res) => setTimeout(res, 0));
    try { this.inst = new WebAssembly.Instance(mod, this._makeInProcImports(mod)); }
    catch (e) { post(`[host] pid ${this.pid} failed to start: ${(e && e.message) || e}\n`, 2); this.retire(); return 127; }
    this._inprocInit();
    let res = null;
    if (pick) {
      // Start from a Python snapshot (see pySnapPick). Everything before the guest runs is
      // synchronous here; if it fails, a fresh instance starts cold and the layer is retired.
      const t0 = performance.now();
      let ms = null, why = '';
      try { ms = this._restoreInProc(pick.snap); } catch (e) { why = String((e && e.message) || e); }
      if (why) {
        pySnaps.delete(pick.snap.layer); pySnapDead.add(pick.snap.layer);
        self.postMessage({ t: 'py-snap-failed', layer: pick.snap.layer, why: 'restore: ' + why });   // (its own copy: nothing for the host to drop)
        if (pySnapDebug(this)) post('[snapshot] restore failed, starting cold: ' + why + '\n', 2);
        this.sharedMem = null; this.dlHandles = []; this.dlRecs = []; this.tableLog = new Map(); this.snapUnsafe = '';
        try { this.inst = new WebAssembly.Instance(mod, this._makeInProcImports(mod)); }
        catch (e) { post(`[host] pid ${this.pid} failed to start: ${(e && e.message) || e}\n`, 2); this.retire(); return 127; }
        this._inprocInit();
      } else {
        if (pySnapDebug(this)) post(`[snapshot] '${pick.snap.layer}' (${pick.mode}, in-process): mount ${pick.mountMs.toFixed(0)}ms, restore ${(performance.now() - t0).toFixed(0)}ms ${JSON.stringify(ms)}, ${(pick.snap.stat.kept / 1048576).toFixed(0)} of ${(pick.snap.len / 1048576).toFixed(0)}MB, built in ${pick.snap.stat.buildMs}ms\n`, 2);
        res = await this._driveRestoreInProc(pyResumeCode(this.argv, this.env));
      }
    }
    if (!res) res = await this._driveInProc(false);
    if (this.pySnapWant) { try { pySnapWant(this.pySnapWant); } catch (_) {} this.pySnapWant = null; }
    if (res.replaced !== undefined) return res.replaced;   // execve: the new image owns this pid; it retires itself
    this.retire();
    return res.code;
  }

  // The in-process half of a Python snapshot restore (the worker engine's is driveRestore in
  // wali-proc-worker.js): re-link the side modules at their recorded bases, refill the table,
  // copy the memory in, then the kernel's own state for the process. Throws before touching
  // anything the caller cannot throw away.
  _restoreInProc(snap) {
    const t0 = performance.now();
    const exp = this.inst.exports, table = exp.__indirect_function_table, mem = this.memory;
    const initLen = mem.buffer.byteLength;
    if (snap.len > initLen) mem.grow(Math.ceil((snap.len - initLen) / PAGE));
    if (table.length < snap.tableLen) table.grow(snap.tableLen - table.length);
    const Gi = (v) => new WebAssembly.Global({ value: 'i32', mutable: false }, v >>> 0);
    const BASE = new Set(['memory', '__indirect_function_table', '__stack_pointer', '__memory_base', '__table_base']);
    this.dlRecs = []; this.tableLog = new Map();
    for (const r of snap.dl) {
      const env = { memory: mem, __indirect_function_table: table, __stack_pointer: exp.__stack_pointer,
                    __memory_base: Gi(r.memBase), __table_base: Gi(r.tableBase) };
      const gotMem = {}, gotFunc = {};
      let inst = null;
      for (const im of WebAssembly.Module.imports(r.mod)) {
        if (im.module === 'env') {
          if (BASE.has(im.name)) continue;
          const sym = exp[im.name];
          env[im.name] = (sym !== undefined) ? sym : ((...a) => {
            const own = inst && inst.exports[im.name];
            if (typeof own === 'function') return own(...a);
            const alt = this.dlHandles.map((h) => h.inst.exports[im.name]).find((f) => typeof f === 'function');
            if (alt) return alt(...a);
            throw new Error('[host] unresolved dynamic fn: ' + im.name);
          });
        } else if (im.module === 'GOT.mem') {
          const sym = exp[im.name];
          gotMem[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, (sym && sym.value !== undefined) ? sym.value : Number(sym || 0));
        } else if (im.module === 'GOT.func') {
          gotFunc[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, (r.gotFunc[im.name] || 0) >>> 0);
        }
      }
      const waliProxy = new Proxy(this.wali || {}, { get: (t, n) => t[n] || (typeof n !== 'string' ? undefined : (() => { throw new Error('[host] unresolved wali import from side module: ' + n); })) });
      inst = new WebAssembly.Instance(r.mod, { env, wali: waliProxy, 'GOT.mem': gotMem, 'GOT.func': gotFunc });
      for (const k in gotMem) { const e = inst.exports[k]; if (e && e.value !== undefined) gotMem[k].value = r.memBase + e.value; }
      if (r.tlsBase >= 0 && typeof inst.exports.__wasm_init_tls === 'function') inst.exports.__wasm_init_tls(r.tlsBase);
      this.dlHandles.push({ inst, symCache: new Map() });
      this.dlRecs.push(r);
    }
    for (const [idx, d] of snap.table) {
      const fn = d.h < 0 ? exp[d.name] : this.dlHandles[d.h].inst.exports[d.name];
      if (typeof fn !== 'function') throw new Error('table slot ' + idx + ': no export ' + d.name);
      table.set(idx, fn); this.tableLog.set(idx, d);
    }
    const tLink = performance.now() - t0;
    if ((this.env || []).includes('WALIOS_SNAPSHOT_TEST_FAIL=1')) throw new Error('test failure (WALIOS_SNAPSHOT_TEST_FAIL)');
    const src = new Uint8Array(snap.mem, 0, snap.len), dst = new Uint8Array(mem.buffer);
    const put = (a, b) => { a = Math.max(0, a); b = Math.min(b, snap.len); if (b > a) dst.set(src.subarray(a, b), a); };
    put(0, initLen);
    for (const r of snap.dl) { put(r.memBase, r.memBase + (r.memSize || 0)); if (r.tlsBase >= 0) put(r.tlsBase, r.tlsBase + (r.tlsSize || 0)); }
    for (const [a, b] of snap.ranges) put(a, b);
    this.membuf = null; this.refresh();
    this.heapBrk = snap.k.heapBrk;
    this.mmapFree = snap.k.mmapFree.map((x) => ({ ...x }));
    this.mmapLive = new Map(snap.k.mmapLive);
    for (const [sg, h] of snap.k.sig) this.sig.handlers.set(sg, { ...h });
    for (const k of snap.hostcallFds || []) if (!this.fds.has(k)) { this.fds.set(k, { hostcall: { inbuf: '', chunks: [], waiters: [] }, cloexec: false }); this.nextFd = Math.max(this.nextFd, k + 1); }
    return { link: Math.round(tLink), copy: Math.round(performance.now() - t0 - tLink) };
  }

  // Run a restored Python: through its C API, each call on a JSPI stack of its own so the
  // syscalls it makes can suspend. The resume code ends in sys.exit (ExitError).
  async _driveRestoreInProc(code) {
    const exp = this.inst.exports, P = (f) => WebAssembly.promising(f);
    try {
      const bytes = te.encode(code);
      const p = await P(exp.malloc)(bytes.length + 1);
      this.membuf = null; this.refresh(); this.u8.set(bytes, p); this.u8[p + bytes.length] = 0;
      await P(exp.PyGILState_Ensure)();
      const r = await P(exp.PyRun_SimpleString)(p);
      await P(exp.exit)(r === 0 ? 0 : 1);
      return { code: this._dead !== undefined ? this._dead : (r === 0 ? 0 : 1) };
    } catch (e0) {
      const e = unwrapJS(e0);
      if (e instanceof ReplacedError) { const c = await e.task; return { replaced: (c === null ? 127 : c) & 0xff }; }
      if (e instanceof ExitError) return { code: e.code & 0xff };
      post(`[host] trap in pid ${this.pid} (restored python): ${(e && e.stack) || e}\n`, 2);
      return { code: 139 };
    }
  }

  // Run the guest until it exits, building a fork child at every Asyncify unwind.
  async _driveInProc(rewind) {
    const start = WebAssembly.promising(this.inst.exports._start);
    if (rewind) this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    for (;;) {
      try { await start(); }
      catch (e0) {
        const e = unwrapJS(e0);
        if (e instanceof ReplacedError) { const code = await e.task; return { replaced: (code === null ? 127 : code) & 0xff }; }
        if (e instanceof ExitError) return { code: e.code & 0xff };
        if (typeof WebAssembly.Exception !== 'undefined' && e instanceof WebAssembly.Exception) { post(`[host] trap in pid ${this.pid}: WebAssembly.Exception (wasm-tag)\n`, 2); return { code: 139 }; }
        post(`[host] trap in pid ${this.pid}: ${(e && e.stack) || e}\n`, 2);
        return { code: 139 };
      }
      if (this.forkState !== 'unwinding') return { code: this._dead !== undefined ? this._dead : 0 };
      // fork(): the guest is unwound. Build the child over a copy of this memory NOW, on
      // this plain JS stack, before this process rewinds -- the copy is what makes it a
      // fork rather than a race. The child then runs as a concurrent task.
      this.inst.exports.asyncify_stop_unwind();
      const childPid = nextPid++;
      const child = this._spawnForkChildInProc(childPid);
      const ctask = child._driveInProc(true).then((r) => {
        const code = r.replaced !== undefined ? r.replaced : r.code;
        if (r.replaced === undefined) child.retire();
        this.reaped.set(childPid, code);
        if (STRACE) stracePost(`[strace ${childPid}] exited ${code} (fork child of ${this.pid})\n`, 2);
        releaseFds(child.fds);
        this.childTasks.delete(childPid);
        postSignal(this, SIG.CHLD); wakeWaiters(this);
        return code;
      });
      inflight.add(ctask); ctask.finally(() => inflight.delete(ctask));
      this.childTasks.set(childPid, ctask);
      this.forkRet = BigInt(childPid); this.forkState = 'rewinding';
      this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    }
  }

  _spawnForkChildInProc(childPid) {
    const mod = modCache.get(this.modKey);
    const child = this.spawnForkChildMeta(childPid);
    child.inst = new WebAssembly.Instance(mod, child._makeInProcImports(mod));
    child._inprocInit();
    // The parent's linear memory IS its stack: copy it, minus a trailing run of zero
    // pages (the child's fresh memory is already zero there).
    this.refresh();
    const src = new Uint8Array(this.memory.buffer);
    const need = src.length - child.memory.buffer.byteLength;
    if (need > 0) { child.memory.grow(Math.ceil(need / PAGE)); child.membuf = null; child.refresh(); }
    let hw = src.length;
    for (let a = Math.floor((src.length - 1) / PAGE) * PAGE; a >= 0; a -= PAGE) {
      let nz = false; const end = Math.min(a + PAGE, src.length);
      for (let b = a; b < end; b++) if (src[b]) { nz = true; break; }
      if (nz) break;
      hw = a;
    }
    new Uint8Array(child.memory.buffer).set(src.subarray(0, hw));
    child.membuf = null; child.refresh();
    // The child rewinds on a fresh instance whose __stack_pointer / __tls_base hold their
    // initial values, while the frames it replays sit at OUR stack pointer (see the
    // ST_FORKED handshake in wali-proc-worker.js for what went wrong without this).
    const spg = this.inst.exports.__stack_pointer, tlsg = this.inst.exports.__tls_base;
    if (spg && child.inst.exports.__stack_pointer) child.inst.exports.__stack_pointer.value = spg.value;
    if (tlsg && child.inst.exports.__tls_base) child.inst.exports.__tls_base.value = tlsg.value;
    child.asyncifyBuf = this.asyncifyBuf; child.forkState = 'rewinding'; child.forkRet = 0n;
    return child;
  }

  // execve, in-process: the worker model's _serve branch, except that "replace this
  // image" is a rejection that unwinds the caller's wasm stack (ReplacedError) while the
  // new image runs under the same pid.
  async _execveInProc(a) {
    const [a0, a1, a2] = a;
    let path = '', av = [], ev = [];
    try { path = this.cstr(a0); av = this.rPtrArray(a1); ev = a2 ? this.rPtrArray(a2) : []; } catch (_) {}
    if (STRACE) stracePost(`[strace ${this.pid}${this.inChild() ? '>' + this.childStack[this.childStack.length - 1].pid : ''}] execve(${JSON.stringify(path)}) ...\n`, 2);
    const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
    if (!target || target.eacces) return err(target ? E.ACCES : E.NOENT);
    const fdsnap = execDropCloexec(this.fds);
    if (this.inChild()) {
      // vfork protocol (see sys 'fork'): the guest is in the child branch, so this execve
      // is the CHILD's. Start it under the pid fork() reported, hand the parent its state
      // back and answer CHILD_DONE so the libc wrapper longjmps to the fork site.
      const ctx = this.childStack[this.childStack.length - 1];
      const childPid = ctx.pid;
      const ccwd = this.cwd.p;   // the child's cwd: read it before the pop puts the parent's view back
      this.childStack.pop(); this.unVfork(ctx);
      const task = Promise.resolve(startProcess(target, ev, fdsnap, ccwd, this.cred, childPid, this.umask)).then((code) => {
        this.reaped.set(childPid, code === null ? 127 : code);
        releaseFds(fdsnap);
        this.childTasks.delete(childPid);
        postSignal(this, SIG.CHLD); wakeWaiters(this);
        return code;
      });
      const cp = procs.get(childPid); if (cp) { cp.ppid = this.pid; cp.pgid = ctx.pgid; cp.sid = ctx.sid; }
      inflight.add(task); task.finally(() => inflight.delete(task));
      this.childTasks.set(childPid, task);
      return CHILD_DONE;
    }
    throw new ReplacedError(Promise.resolve(startProcess(target, ev, fdsnap, this.cwd.p, this.cred, this.pid, this.umask)));
  }

  // posix_spawn(pathPtr, argvPtr, envpPtr, fdmapPtr, fdmapLen) -> pid | -errno, in-process.
  async _posixSpawnInProc(a) {
    const [a0, a1, a2, a3, a4] = a;
    let path = '', av = [], ev = null; const spec = [];
    try {
      path = this.cstr(a0); av = this.rPtrArray(a1); ev = a2 ? this.rPtrArray(a2) : null;
      for (let k = 0; k < (a4 & 0xffff); k++) spec.push([this.r32(a3 + k * 8), this.r32(a3 + k * 8 + 4)]);
    } catch (_) { return err(E.INVAL); }
    const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
    if (!target || target.eacces) return err(target ? E.ACCES : E.NOENT);
    let childFds;
    try { childFds = spawnFdTable(this.fds, spec); }
    catch (e) { return err(e && e.badf ? E.BADF : E.INVAL); }
    const proc = new Process(target.key, target.argv, ev || this.env, childFds, this.cwd.p);
    if (this.cred) proc.cred = { ...this.cred };
    proc.umask = this.umask;
    proc.ppid = this.pid; proc.pgid = this.pgid; proc.sid = this.sid;
    if (a4 >>> 16 & 1) { proc.pgid = proc.pid; proc.sid = proc.pid; }     // POSIX_SPAWN_SETSID
    const childPid = proc.pid;
    if (STRACE) stracePost(`[strace ${this.pid}] posix_spawn(${JSON.stringify(path)}) = ${childPid}\n`, 2);
    const task = Promise.resolve(proc.run()).then((code) => {
      this.reaped.set(childPid, code === null ? 127 : code);
      releaseFds(childFds);
      this.childTasks.delete(childPid);
      postSignal(this, SIG.CHLD); wakeWaiters(this);
      return code;
    });
    inflight.add(task); task.finally(() => inflight.delete(task));
    this.childTasks.set(childPid, task);
    return BigInt(childPid);
  }

  // spawnForkChild without the instance: in the worker model the child's module is
  // instantiated on ITS thread and the memory copy happens in runInWorker.
  spawnForkChildMeta(childPid) {
    const child = new Process(this.modKey, this.argv, this.env, new Map(), this.cwd.p);
    procs.delete(child.pid);
    child.pid = childPid; child.pgid = this.pgid; child.sid = this.sid; child.ppid = this.pid; child.cred = { ...this.cred }; child.umask = this.umask;
    for (const [b, at] of this.shmAt) child.shmAt.set(b, { seg: at.seg, shadow: at.shadow.slice() });
    procs.set(childPid, child);
    child.fds = new Map([...this.fds].map(([k, v]) => { v.shared = true; return [k, { ...v }]; }));
    for (const v of child.fds.values()) child.bumpFifo(v);
    child.heapBrk = this.heapBrk; child.ctty = this.ctty; child.ilp32 = this.ilp32; child.comm = this.comm;   // fork keeps the task name; execve resets it
    child.nextFd = this.nextFd; child.umask = this.umask;
    child.sig.handlers = new Map(this.sig.handlers); child.sig.mask = this.sig.mask;
    return child;
  }

}

let lazyTars = {};                 // moduleKey -> [[tarUrl, mountPrefix], ...] (loaded once, on first exec)
let mmapPool = true;               // recycle munmap'd anon regions; run-message `noMmapPool` disables (A/B only)
const lazyTarsDone = new Set();
const lazyTarsBusy = new Map();     // moduleKey -> the companion mount in flight
// lazily fetch+compile a manifest URL on first use, plus any companion tar the
// program needs (e.g. python.wasm -> pylib.tar.gz at /py). Returns whether the
// key is (now) compiled. VFS keys are compiled at resolve time.
async function ensureModule(key) {
  if (!key || key.startsWith('vfs:')) return !!modCache.has(key);
  if (!modCache.has(key)) {
    try {
      const t0 = performance.now();
      // Fetch bytes (not compileStreaming) so we can parse a shared env.memory import
      // (wasi-threads binaries like rustc.wasm) and record its limits for the memory the kernel creates.
      const buf = new Uint8Array(await (await fetchArt(key)).arrayBuffer());
      compileGuest(key, buf);
      post(`[host] loaded ${key} (${(performance.now() - t0).toFixed(0)}ms)\n`, 2);
    } catch (e) { post(`[host] failed to load ${key}: ${e.message || e}\n`, 2); return false; }
  }
  // companion data (python's stdlib at /py, etc.). Marked done only once every tar is in: it
  // used to be marked BEFORE mounting, so a mount that failed or was cut short (a `timeout 30
  // python3` killed during the first, slow pylib mount on a loaded PC) left /py empty and
  // every later python3 in that kernel died "No module named 'encodings'" (lean A/B co2vol,
  // 2026-11-10: 80 failed runs). A failed mount is retried by the next exec; concurrent
  // execs share the one mount in flight.
  if (lazyTars[key] && !lazyTarsDone.has(key)) {
    let p = lazyTarsBusy.get(key);
    if (!p) {
      p = (async () => {
        let ok = true;
        for (const [url, prefix] of lazyTars[key]) { try { await loadTar(url, prefix); } catch (e) { ok = false; post(`[host] companion ${url} failed: ${e.message || e}\n`, 2); } }
        if (ok) lazyTarsDone.add(key);
        lazyTarsBusy.delete(key);
        return ok;
      })();
      lazyTarsBusy.set(key, p);
    }
    await p;
  }
  return true;
}

// Resolve a program name to a module key WITHOUT requiring it compiled yet — the
// async exec path calls ensureModule() on the result. VFS binaries are compiled
// here (bytes are local). Returns the key, or null if unresolvable.
function resolveExecKey(p, cwd, selfKey) {
  let key = resolveModuleKey(p, selfKey);   // manifest URL (maybe uncompiled) or null
  if (!key) {
    // not in the manifest — maybe it's a wasm binary sitting in the VFS
    // (e.g. one microcc just emitted, or a file under the OPFS mount).
    const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
    opfsFault(vp);
    const f = files.get(vp);
    if (f) {
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) {
        // Keyed by content identity too: `cc` rewrites /root/hello and the next `./hello`
        // must run the NEW binary, not the cached compile of the old one.
        key = 'vfs:' + vp + '@' + f.size + ':' + Math.floor(f.mtimeMs || 0);
        if (!modCache.has(key)) compileGuest(key, bytes.slice());   // incl. the import signatures the process worker needs
      }
    }
  }
  // busybox multi-call fallback: any still-unresolved name runs busybox, which
  // dispatches on argv[0] (busybox itself may still be a lazy manifest URL).
  //
  // NOT for an explicit path to a file that does not exist. That must be ENOENT, or
  // execvp() can never walk $PATH: it tries /bin/foo first, the fallback makes that
  // "succeed" by running busybox, busybox prints "foo: applet not found" and exits -- and
  // the loop never reaches /usr/bin/foo, where the program actually is. Measured:
  //     timeout 260 build-pkg tree   -> "build-pkg: applet not found"  (it is in /usr/bin)
  //     timeout 5 /usr/bin/build-pkg -> runs
  // which silently broke `timeout CMD`, `env CMD`, `find -exec CMD` and anything else that
  // spawns a helper by name. A whole batch of package builds reported failure in 0s each
  // because of it -- none of them had started.
  //
  // A name with NO slash still falls back: "run the applet" is the intended meaning there,
  // and that is what /bin/sed and the other 17-byte applet stubs rely on (they EXIST, so
  // they come through the branch above and are not affected by this).
  const explicitPath = p.includes('/');
  const existsInVfs = files.has(p.startsWith('/') ? norm(p, '/') : norm(p, cwd));
  if (!key && explicitPath && !existsInVfs) {
    return null;                       // -> ENOENT, so the caller's PATH walk continues
  }
  if (!key && manifest['busybox']) key = manifest['busybox'];
  if (!key) { post(`[host] execve: cannot resolve ${p}\n`, 2); return null; }
  return key;
}

// execve of a NON-wasm file: "#!" scripts run their interpreter with the script
// path appended (what make/configure/libtool need); an executable file without a
// shebang runs as a shell script (the kernel-ENOEXEC fallback shells implement).
// Manifest names win (checked by the callers) so /bin stubs never reach this.
// `given`: the script's name as execve got it -- what the interpreter receives as its file
// argument, so the script's $0 is "hooks/update", not an absolute path (git's t1416 compares).
function scriptExecRewrite(p, argv, cwd, given) {
  const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
  const name = given || vp;
  opfsFault(vp);
  const f = files.get(vp);
  if (!f || f.sym !== undefined || f.data === undefined && f.br === undefined) return null;
  const head = f.br !== undefined ? fileRead(f, 0, 256) : f.data.subarray(0, Math.min(256, f.size));
  if (head.length >= 4 && head[0] === 0 && head[1] === 0x61 && head[2] === 0x73 && head[3] === 0x6d) return null; // wasm
  if (head.includes(0)) return null; // binary data — not a script
  if (head.length >= 2 && head[0] === 0x23 && head[1] === 0x21) { // '#!'
    let nl = head.indexOf(0x0a); if (nl < 0) nl = head.length;
    const line = td.decode(head.subarray(2, nl)).trim();
    if (!line || !line.startsWith('/')) return null;           // e.g. the '#!wali-manifest' /bin stubs
    const sp = line.search(/\s/);
    const interp = sp < 0 ? line : line.slice(0, sp);
    const arg = sp < 0 ? '' : line.slice(sp + 1).trim();
    return { path: interp, argv: [interp.split('/').pop(), ...(arg ? [arg] : []), name, ...argv.slice(1)] };
  }
  if (f.mode & 0o111) return { path: '/bin/sh', argv: ['sh', name, ...argv.slice(1)] }; // ENOEXEC fallback
  return null;
}

// Await a blocking syscall on the kernel's event loop. CHILD_DONE is the vfork protocol's
// internal sentinel and must never reach a guest.
async function S_await(S, sysname, args) {
  const v = await S.sysAsync(sysname, args);
  return (v === CHILD_DONE) ? 0n : v;
}

// ---- the ONE exec path ----
// Resolve what execve(p) should run: a "#!" script rewrite, or a wasm module -- fetched
// and compiled HERE on first use, since this thread is never blocked. null = ENOENT.
// (cc/clang/ar used to be forwarded to a compiler running on the PAGE, which only the
// terminal answered -- in the tool `cc` hung to the timeout. clang is a guest now.) Every caller (boot, the worker
// loop's execve, the vfork child's execve) goes through resolveExec + startProcess, so
// pid/pgid inheritance, the fd table and lazy loading are decided in one place.
// execvp() also accepts a BARE name and looks it up along $PATH. The shell does that
// itself, so shell-run commands were fine; a program exec'ing a bare name was not. Manifest
// names still win (checked first), so `sed` keeps resolving to busybox rather than to a
// stray /bin/sed stub. /bin:/usr/bin is hardcoded because this layer has no env, and it is
// walios' PATH.
function pathSearch(p, cwd) {
  if (!p || p.includes('/')) return null;
  for (const d of ['/bin', '/usr/bin']) {
    const cand = d + '/' + p;
    opfsFault(cand);
    if (files.has(cand)) return cand;
  }
  return null;
}

// Resolve symlinks in a VFS path (every component, the last one too: exec follows it), max 8
// hops -- Process.follow without a process. A program reached through a symlinked DIRECTORY
// was "not found": git's compiled-in exec-path is a symlink to /usr/libexec/git-core, and
// `git submodule` died "die() should not be called in child" when GIT_EXEC_PATH was unset.
function vfsFollow(p, depth = 0) {
  if (depth > 8) return p;
  const segs = p.split('/').filter(Boolean); let cur = '';
  for (let i = 0; i < segs.length; i++) {
    cur += '/' + segs[i];
    if (inOpfs(cur)) opfsFault(cur);
    const f = files.get(cur);
    if (f && f.sym !== undefined) {
      const tgt = f.sym.startsWith('/') ? f.sym : cur.slice(0, cur.lastIndexOf('/') + 1) + f.sym;
      return vfsFollow(norm(tgt + '/' + segs.slice(i + 1).join('/'), '/'), depth + 1);
    }
  }
  return p;
}
async function resolveExec(p, argv, cwd, selfKey, depth) {
  let given = p;   // the name a "#!" interpreter receives: the path as execve got it (Linux)
  if (p.includes('/') && !resolveModuleKey(p, selfKey)) {
    const vp = vfsFollow(p.startsWith('/') ? norm(p, '/') : norm(p, cwd));
    if (vp !== (p.startsWith('/') ? norm(p, '/') : norm(p, cwd))) p = vp;
  }
  if (!resolveModuleKey(p, selfKey)) {
    const onPath = pathSearch(p, cwd);
    if (onPath) { p = onPath; given = onPath; }
  }
  if (!resolveModuleKey(p, selfKey)) {
    // A file with no execute bit at all is EACCES, as on Linux -- it ran anyway (git's
    // run_command must report EACCES for a non-executable script, t0061). Manifest programs
    // never get here; their /bin stubs are 0755.
    const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
    opfsFault(vp); const xf = files.get(vp);
    if (xf && xf.sym === undefined && !((xf.mode ?? 0o100755) & 0o111)) return { eacces: true };
  }
  if (!resolveModuleKey(p, selfKey) && (depth || 0) < 4) {
    const sc = scriptExecRewrite(p, argv, cwd, given);
    if (sc) return resolveExec(sc.path, sc.argv, cwd, selfKey, (depth || 0) + 1);
  }
  let key = resolveExecKey(p, cwd, selfKey);
  if (!key) return null;
  // ash is built FEATURE_SH_STANDALONE: an applet name never goes through $PATH, a plain
  // applet re-execs as execve("/proc/self/exe", ["tree", ...]). So a package `apk add`ed
  // under an applet's name must be swapped in HERE, or `apk add tree` keeps running
  // busybox's tree. NOEXEC/NOFORK applets (find, which, ...) never exec; apk says so.
  const a0 = argv && argv[0] ? String(argv[0]).split('/').pop() : '';
  if (a0 && key === manifest['busybox'] && pkgAdded.has(a0) && manifest[a0]) key = manifest[a0];
  if (!(await ensureModule(key))) return null;   // LAZY: fetch + compile on first exec
  return { key, argv };
}

// A spawned child SHARES fd handles with its parent (both hold the same pipe), so every
// inherited handle must take a reference; releaseFds() gives it back when the child
// exits. Getting this wrong does not fail loudly -- the reader simply never sees EOF.
function retainFd(h) {
  if (!h) return h;
  if (h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') { h.fifo.readers++; if (h.alsoW) h.fifo.writers++; } }
  else if (h.spair) { h.spair.wr.writers++; h.spair.rd.readers++; }
  return h;
}
// Build the child's fd table: the parent's non-cloexec fds, then the explicit
// redirections. An explicit action wins over FD_CLOEXEC, exactly as dup2 clears it --
// node marks its pipe ends cloexec and then maps them onto 0/1/2.
function spawnFdTable(parentFds, spec) {
  const out = new Map();
  for (const [fd, h] of parentFds) if (!(h && h.cloexec)) out.set(fd, h);
  for (const [childFd, parentFd] of spec) {
    if (parentFd < 0) { out.delete(childFd); continue; }
    const h = parentFds.get(parentFd);
    if (!h) { const e = new Error('EBADF'); e.badf = true; throw e; }
    out.set(childFd, h);
  }
  for (const h of out.values()) retainFd(h);
  return out;
}

// ---- Python snapshots --------------------------------------------------------------------
// python3 is slow to START here: booting the interpreter is ~0.4s, and importing the packages
// people actually use costs seconds (prod binary, 2026-11-08: requests 2.6s, openpyxl 4.1s,
// pandas 6-7s, the eight most used together 10-12s). A snapshot is a python3 that has already
// imported them, copied at that moment. A later `python3 -c CODE`, `python3 SCRIPT` or
// `python3 - <<EOF` whose source imports one of those packages starts as a copy of it.
//
// An accelerator only. Every run it does not cover starts cold, exactly as before: the
// in-process (JSPI) engine, interpreter flags, -m, a program that imports none of the
// packages, a layer not built yet, a different PYTHON*/package environment, a failed restore.
//
//   layers   the HOST names them (run message `pySnap`), smallest first, each a superset of
//            the one before: e.g. office (requests, openpyxl, pypdf, docx, PIL, reportlab),
//            then data (office + pandas, numpy). A run uses the smallest one covering its
//            imports, so a docx script does not pay pandas' memory.
//   build    the first run that needs a layer starts cold; when it exits the kernel asks the
//            host for the layer ('py-snap-need'), and the host either hands over one another
//            kernel built or lets this one build it ('py-snap-build'): a hidden python3
//            (pySnapBuild, its own pid range, immune to killall/stopall) imports the layer and
//            writes /dev/walios-snapshot. It runs while the model reads the result.
//   capture  that write copies the process's memory (non-zero pages only) and the kernel's
//            state for it (brk, mmap lists, signal dispositions, /dev/hostcall fds, the bundles
//            mounted so far); the process's worker then sends what only it knows: its side
//            modules (numpy, lxml, PIL, ...) with their memory/table/TLS bases and every
//            function-table slot it filled (wali-proc-worker.js sendSnapLog).
//   share    a finished snapshot goes to the host, which gives it to every kernel of the tab.
//            Nothing is copied: the memory is a SharedArrayBuffer and the side modules are
//            compiled modules. The host drops them when the tab's last kernel goes.
//   restore  the bundles the snapshot had mounted are mounted here first; the worker re-links
//            the side modules at their recorded bases, copies the memory in and runs the
//            program through Python's C API (driveRestore, pyResumeCode). If anything before
//            the program fails, the process starts cold instead and the layer is dropped.
let pySnapCfg = null;              // { layers: [{ name, pkgs: ['pandas', 'PIL.Image', ...] }] }; null = off
const pySnaps = new Map();         // layer -> ready snapshot (built here or handed over by the host)
const pySnapCapture0 = new Map();  // pid -> snapshot being captured (waiting for its worker's 'snap-dl')
const pySnapAsked = new Set();     // layers asked of the host, not answered yet
const pySnapDead = new Set();      // layers that failed in this kernel: not asked for again
let pySnapNextPid = 1 << 20;       // builders' pids: a run resets nextPid, and a builder outlives runs
const mountedTars = new Map();     // url -> prefix: every bundle this kernel has unpacked
// Top-level module names changed in Python's import roots by something other than python's own
// bundles: a write, delete or rename by a program, or an `apk add`ed module (the farm has its
// own requests, lxml, urllib3, ... that land over the bundle's). A snapshot holding one of
// them would run the OLD code where a cold start imports the new: such runs start cold, and
// this kernel builds no snapshot that holds one. (__pycache__ writes are Python's own.)
const pyTouched = new Set();
const PY_TREES = ['/site-packages/_shims/', '/site-packages/', '/py/Lib/', '/ext/'];
function pyTreeTouch(p) {
  if (typeof p !== 'string' || p.includes('/__pycache__/')) return;
  for (const t of PY_TREES) if (p.startsWith(t)) {
    const name = p.slice(t.length).split('/')[0].split('.')[0].split('-')[0];
    if (name) pyTouched.add(name);
    return;
  }
}
// Environment a package may read AT IMPORT (so a snapshot made under other values would
// behave differently from a cold start): it must be the same as the builder's, or start cold.
const PY_SNAP_ENV = (k) => /^(PYTHON|SANDPIE_LAZY_PKGS$|SANDPIE_HOST_RPC$|SANDPIE_ASYNCIO$|NUMPY|NPY_|OMP_|OPENBLAS|MKL_|PANDAS|MPL|MATPLOTLIB|SSL_|REQUESTS_|CURL_CA|LANG$|LC_)/.test(k);
// What the builder's environment keeps. Never secrets or the session token: the snapshot's
// memory is shared by every conversation of the tab.
const PY_SNAP_BUILD_ENV = (k) => PY_SNAP_ENV(k) || /^(PATH|HOME|USER|LOGNAME|SHELL|TERM|NO_COLOR|CONFIG_SITE|TMPDIR|TZ)$/.test(k);
const envMap = (env) => { const o = {}; for (const kv of env || []) { const i = kv.indexOf('='); if (i > 0) o[kv.slice(0, i)] = kv.slice(i + 1); } return o; };
const pyEngine = () => (INPROC ? 'inproc' : 'worker');
const pyIsPython = (key) => !!(pySnapCfg && key && (key === manifest.python3 || key === manifest.python));
const pySnapDebug = (P) => STRACE || (P && (P.env || []).includes('WALIOS_SNAPSHOT_DEBUG=1'));
const topOf = (n) => String(n).split('.')[0];
// What a layer offers: what it asks for, plus the non-stdlib modules its snapshot turned out
// to hold (lxml under docx, dateutil under pandas, ...).
const pyLayerOffer = (L) => { const s = pySnaps.get(L.name); return new Set([...L.pkgs.map(topOf), ...(s ? s.mods : [])]); };

// Top-level modules a program imports, read from its source. A heuristic, and allowed to be:
// a name it misses only costs the speed-up, an extra one only picks a bigger layer.
function pyImportsOf(src) {
  const out = new Set();
  const re = /^[ \t]*(?:from[ \t]+([A-Za-z_]\w*)[\w.]*[ \t]+import\b|import[ \t]+([^\n#]+))/gm;
  for (const m of String(src).replace(/;/g, '\n').matchAll(re)) {
    if (m[1]) { out.add(m[1]); continue; }
    for (const part of m[2].split(',')) { const n = part.trim().split(/[\s.]/)[0]; if (/^[A-Za-z_]\w*$/.test(n)) out.add(n); }
  }
  return out;
}
// The source of `python3 SCRIPT` (its first 512KB is plenty to see the imports).
function pyReadScript(P, path) {
  const vp = path.startsWith('/') ? norm(path, '/') : norm(path, P.cwd.p);
  opfsFault(vp);
  const f = files.get(vp);
  if (!f || f.sym !== undefined || (f.data === undefined && f.br === undefined)) return null;
  const n = Math.min(f.size, 512 << 10);
  const b = f.br !== undefined ? fileRead(f, 0, n) : f.data.subarray(0, n);
  return td.decode(b);
}
// The source of `python3 -` / `python3 <<EOF`: what is in the stdin pipe, without taking it.
// A here-document is written by the shell before (or right as) python starts, so wait a moment
// for the writer to finish; a pipe from a long-running producer just gets what is there.
async function pyPeekStdin(P) {
  const h = P.fds.get(0);
  if (!h || !h.fifo || h.end !== 'r') return null;
  for (let i = 0; i < 60 && h.fifo.writers > 0; i++) await new Promise((r) => setTimeout(r, 5));
  let n = 0; for (const c of h.fifo.chunks) n += c.length;
  const all = new Uint8Array(n); let o = 0;
  for (const c of h.fifo.chunks) { all.set(c, o); o += c.length; }
  return td.decode(all);
}

// A synchronous VFS step that may need the file bridge: in the in-process engine a bridge call
// that has to wait throws NeedAsync instead; wait for it and run the step again (as the
// syscalls do).
async function pySync(fn) {
  for (;;) { try { return fn(); } catch (e) { if (!(e instanceof NeedAsync)) throw e; await e.promise; } }
}
// Which snapshot this process should start from, or null (= cold). Async: it may read the
// script, peek stdin and mount the bundles the snapshot needs.
async function pySnapPick(P) {
  if (!pySnapCfg || P.pySnapLayer || !pyIsPython(P.modKey)) return null;
  const e = envMap(P.env);
  if (e.WALIOS_NO_SNAPSHOT) return null;
  const a = P.argv || [];
  let src = null, mode = '';
  if (a[1] === '-c' && a.length >= 3) { mode = 'c'; src = a[2]; }
  else if (a[1] === '-' || (a.length === 1 && P.fds.get(0) && P.fds.get(0).fifo)) { mode = 'stdin'; src = await pyPeekStdin(P); }
  else if (a[1] && !a[1].startsWith('-')) { mode = 'script'; src = await pySync(() => pyReadScript(P, a[1])); }
  if (src === null) return null;
  const layers = pySnapCfg.layers;
  const want = pyImportsOf(src);
  const offers = layers.map(pyLayerOffer);
  const need = [...want].filter((n) => offers.some((o) => o.has(n)));
  // A program that imports none of them: only a layer meant for any program ('any', the
  // stdlib one) -- a big layer would cost it memory for nothing.
  if (!need.length && !layers[0].any) return null;
  // The smallest layer that has everything needed (else the biggest), and the smallest READY
  // one from there up -- a bigger layer holds everything a smaller one does.
  let target = need.length ? layers.findIndex((L, i) => need.every((n) => offers[i].has(n))) : 0;
  if (target < 0) target = layers.length - 1;
  const top = need.length ? layers.length : 1;
  const envOk = (s) => { for (const k of new Set([...Object.keys(e), ...Object.keys(s.env)])) if (PY_SNAP_ENV(k) && e[k] !== s.env[k]) return false; return true; };
  let snap = null;
  let at = -1, other = false;
  for (let i = target; i < top && !snap; i++) {
    const s = pySnaps.get(layers[i].name);
    if (s && s.modKey === P.modKey && s.engine === pyEngine() && envOk(s)) { snap = s; at = i; } else if (s) other = true;
  }
  if (snap) {
    const changed = (snap.loaded || snap.mods).filter((n) => pyTouched.has(n));
    if (changed.length) { if (pySnapDebug(P)) post(`[snapshot] cold: changed here since the snapshot: ${changed.join(', ')}\n`, 2); return null; }
  }
  // A file next to the program (or in the current directory, for -c and stdin) that has the
  // name of a module the snapshot holds would be imported INSTEAD of it by a cold start.
  if (snap) {
    let dir = P.cwd.p;
    if (mode === 'script') { const vp = a[1].startsWith('/') ? norm(a[1], '/') : norm(a[1], P.cwd.p); dir = vp.slice(0, vp.lastIndexOf('/')) || '/'; }
    for (const n of (snap.loaded || snap.mods)) {
      const base = (dir === '/' ? '' : dir) + '/' + n;
      await pySync(() => { opfsFault(base + '.py'); opfsFault(base); });
      if (files.has(base + '.py') || dirs.has(base)) {
        if (pySnapDebug(P)) post(`[snapshot] cold: ${base} would shadow the snapshot's ${n}\n`, 2);
        return null;
      }
    }
  }
  // The layer this run should have had is asked for when the run exits (runInWorker) --
  // also when a bigger one served it, so the next such run costs less memory.
  if (at !== target && !(other && !snap)) P.pySnapWant = { layer: layers[target], modKey: P.modKey, env: P.env };
  if (!snap) {
    if (pySnapDebug(P)) post(`[snapshot] cold: no '${layers[target].name}' snapshot yet (imports ${need.join(', ') || 'nothing heavy'})\n`, 2);
    return null;
  }
  // The bundles it was built with (numpy, docs, ...) must be here too: the restored Python
  // already believes they are mounted, and its packages read more of their files later.
  const t0 = performance.now();
  for (const [url, prefix] of snap.tars) if (!mountedTars.has(url)) {
    try { await loadTar(url, prefix); } catch (err) { if (pySnapDebug(P)) post(`[snapshot] cold: bundle ${url}: ${err.message || err}\n`, 2); return null; }
  }
  return { snap, mode, mountMs: performance.now() - t0 };
}

// A run needed a layer nobody has: ask the host (once). It answers with a snapshot another
// kernel built, or tells this kernel to build it.
function pySnapWant(w) {
  const L = w.layer;
  if (!pySnapCfg || pySnapDead.has(L.name) || pySnapAsked.has(L.name)) return;
  pySnapAsked.add(L.name);
  pySnapCfg.want = pySnapCfg.want || new Map();
  pySnapCfg.want.set(L.name, w);
  self.postMessage({ t: 'py-snap-need', layer: L.name, local: INPROC || undefined });   // (in-process: this kernel's own copy)
}
function pySnapBuild(name) {
  const w = pySnapCfg && pySnapCfg.want && pySnapCfg.want.get(name);
  if (!w) { self.postMessage({ t: 'py-snap-failed', layer: name, why: 'nothing to build from' }); return; }
  const L = w.layer;
  const code = [
    'import os, sys, json, gc',
    "base = {m.split('.')[0] for m in sys.modules}",
    'ok = []',
    'for n in ' + JSON.stringify(L.pkgs) + ':',
    '    try:',
    '        __import__(n)',
    '        ok.append(n)',
    '    except Exception:',
    '        pass',
    "loaded = sorted({m.split('.')[0] for m in sys.modules} - base)",
    "mods = sorted(set(loaded) - set(sys.stdlib_module_names))",
    // Only what the shipped bundles provide: a package installed in THIS conversation (pip,
    // apk) is not in the other conversations the snapshot is shared with.
    "home = ('/py/', '/ext/', '/site-packages/')",
    "own = [n for n, m in list(sys.modules.items()) if getattr(m, '__file__', None) and not m.__file__.startswith(home)]",
    'if own:',
    "    sys.exit('not from the bundles: ' + ', '.join(own[:5]))",
    // Everything imported so far lives as long as the process: keep the cyclic GC of every
    // restored run from walking it again and again.
    'gc.collect()',
    'gc.freeze()',
    "fd = os.open('/dev/walios-snapshot', os.O_WRONLY)",
    'try:',
    '    os.write(fd, json.dumps({"layer": ' + JSON.stringify(L.name) + ', "mods": mods, "loaded": loaded, "ok": ok}).encode())',
    'finally:',
    '    os.close(fd)',
  ].join('\n');
  const env = (w.env || []).filter((kv) => PY_SNAP_BUILD_ENV(kv.slice(0, kv.indexOf('='))));
  const fds = new Map([[0, { devnull: true }], [1, { devnull: true }], [2, { devnull: true }]]);
  const P = new Process(w.modKey, ['python3', '-c', code], env, fds, '/tmp');
  procs.delete(P.pid); P.pid = pySnapNextPid++; P.pgid = P.sid = P.pid; P.ppid = 0; procs.set(P.pid, P);
  P.pySnapLayer = L.name; P.daemon = true;
  const t0 = P.pySnapT0 = performance.now();
  P.run().then((rc) => setTimeout(() => {   // (its worker's 'snap-dl' may still be on the way)
    if (pySnaps.has(L.name) && pySnaps.get(L.name).builtBy === P.pid) return;
    pySnapCapture0.delete(P.pid);
    pySnapDead.add(L.name);
    self.postMessage({ t: 'py-snap-failed', layer: L.name, why: 'builder exited ' + rc + ' after ' + Math.round(performance.now() - t0) + 'ms without a snapshot' });
  }, 1000), (err) => {
    pySnapDead.add(L.name);
    self.postMessage({ t: 'py-snap-failed', layer: L.name, why: String((err && err.message) || err) });
  });
}
// The host handed over a snapshot (built by another kernel of the tab, or by this one).
function pySnapAccept(s) {
  if (!s || !s.layer) return;
  pySnaps.set(s.layer, s);
  pySnapAsked.delete(s.layer);
}

// The bundles a snapshot needs mounted: python's own (stdlib, extras) and the lazy package
// bundles it pulled in -- never anything else this kernel unpacked (a conversation's saved VM
// state, apk packages): those belong to this conversation, not to the tab.
function pyBundlesMounted(S) {
  const ok = new Set((lazyTars[S.modKey] || []).map((x) => x[0]));
  try { for (const v of Object.values(JSON.parse(envMap(S.env).SANDPIE_LAZY_PKGS || '{}'))) if (Array.isArray(v)) ok.add(v[0]); } catch (_) {}
  return [...mountedTars].filter(([u]) => ok.has(u));
}
// A builder wrote /dev/walios-snapshot. Returns '' or why it was refused.
function pySnapCapture(S, fd, payload) {
  if (!S.pySnapLayer) return 'only a snapshot builder can write here';
  if (!INPROC && (!S.procWorker || !S._ctl)) return 'no process worker';
  if (S._threads && S._threads.length) return 'the process has threads';
  let info; try { info = JSON.parse(payload); } catch (_) { return 'bad request'; }
  { const mine = (info.loaded || []).filter((n) => pyTouched.has(n)); if (mine.length) return 'changed in this kernel: ' + mine.join(', '); }
  // /dev/hostcall channels (sitecustomize's bundle mounts) are re-created at the same numbers
  // in each restored process; any other open file would be a dangling handle in the copy.
  const hostcallFds = [], extra = [];
  for (const [k, h] of S.fds) { if (k <= 2 || k === fd) continue; if (h && h.hostcall) hostcallFds.push(k); else extra.push(k); }
  if (extra.length) return 'open files: fds ' + extra.join(',');
  S.refresh();
  const t0 = performance.now();
  const len = S.memory.buffer.byteLength;
  const src = new Uint8Array(S.memory.buffer, 0, len);
  const mem = INPROC ? new ArrayBuffer(len) : new SharedArrayBuffer(len);
  const dst = new Uint8Array(mem);
  // Only non-zero pages are copied, and only they are copied back on restore: a fresh
  // process's memory is already zero there (the parts instantiation writes are handled in
  // driveRestore).
  const ranges = [];
  const w64 = new BigUint64Array(S.memory.buffer, 0, len >> 3);
  const P8 = PAGE >> 3;
  for (let pg = 0, npg = Math.ceil(len / PAGE); pg < npg; pg++) {
    let nz = false;
    for (let i = pg * P8, e = Math.min((pg + 1) * P8, w64.length); i < e; i++) if (w64[i] !== 0n) { nz = true; break; }
    if (!nz) continue;
    const a = pg * PAGE, b = Math.min(a + PAGE, len);
    const last = ranges[ranges.length - 1];
    if (last && last[1] === a) last[1] = b; else ranges.push([a, b]);
  }
  for (const [a, b] of ranges) dst.set(src.subarray(a, b), a);
  const kept = ranges.reduce((t, [a, b]) => t + b - a, 0);
  pySnapCapture0.set(S.pid, {
    layer: S.pySnapLayer, engine: pyEngine(), modKey: S.modKey, builtBy: S.pid, mem, len, ranges, mods: info.mods || [], loaded: info.loaded || [],
    env: envMap(S.env), hostcallFds, tars: pyBundlesMounted(S),
    k: { heapBrk: S.heapBrk, mmapFree: S.mmapFree.map((x) => ({ ...x })), mmapLive: [...S.mmapLive],
         sig: [...S.sig.handlers].map(([s, h]) => [s, { ...h }]) },
    stat: { captureMs: Math.round(performance.now() - t0), buildMs: Math.round(performance.now() - (S.pySnapT0 || t0)), bytes: len, kept },
  });
  // The side modules and table slots: in-process they are right here; a process worker sends
  // its own after this reply (wali-proc-worker.js KSNAP).
  if (INPROC) {
    const table = S.inst.exports.__indirect_function_table;
    pySnapLoaderLog(S, { unsafe: S.snapUnsafe || '', dl: (S.dlRecs || []).slice(), table: [...(S.tableLog || new Map())], tableLen: table ? table.length : 0 });
  } else Atomics.store(new Int32Array(S._ctl), 8, 1);
  return '';
}
// The builder's worker sent its side modules and table slots ('snap-dl'): the snapshot is whole.
function pySnapLoaderLog(P, m) {
  const s = pySnapCapture0.get(P.pid);
  if (!s) return;
  pySnapCapture0.delete(P.pid);
  if (m.unsafe) { pySnapDead.add(s.layer); self.postMessage({ t: 'py-snap-failed', layer: s.layer, why: m.unsafe }); return; }
  Object.assign(s, { dl: m.dl, table: m.table, tableLen: m.tableLen, at: Date.now() });
  s.stat.sideModules = m.dl.length; s.stat.tableSlots = m.table.length;
  pySnaps.set(s.layer, s);
  pySnapAsked.delete(s.layer);
  // In-process snapshots stay in this kernel: without SharedArrayBuffer, handing one to the
  // host (and on to other kernels) would COPY it each time. The host only learns it is built.
  if (s.engine === 'inproc') self.postMessage({ t: 'py-snap-ready', layer: s.layer, local: true });
  else self.postMessage({ t: 'py-snap-ready', snap: s });
}

// Run by PyRun_SimpleString in the restored interpreter: make it THIS process (environment,
// argv, fresh random state, timezone, stdio buffering, import caches, a new __main__) and run
// the program the way `python3 -c` / `python3 SCRIPT` / `python3 -` would, ending in sys.exit
// so Python finalizes and exits normally.
function pyResumeCode(argv, env) {
  const body = `
def _walios_resume(argv, env):
    import os, sys, types, builtins, importlib
    for k in list(os.environ):
        if k not in env:
            del os.environ[k]
    for k, v in env.items():
        if os.environ.get(k) != v:
            os.environ[k] = v
    sys.orig_argv = list(argv)
    import random
    random.seed()
    np = sys.modules.get('numpy')
    if np is not None:
        try:
            np.random.seed()
        except Exception:
            pass
    import time
    try:
        time.tzset()
    except Exception:
        pass
    unbuf = bool(os.environ.get('PYTHONUNBUFFERED'))
    for f in (sys.stdout, sys.stderr):
        try:
            f.reconfigure(line_buffering=(f is sys.stderr) or f.isatty(), write_through=unbuf)
        except Exception:
            pass
    # Relative sys.path entries ('' = the current directory) were resolved to the builder's
    # directory when their finders were made: drop them so they are made again here.
    for k in list(sys.path_importer_cache):
        if not k or not os.path.isabs(k):
            del sys.path_importer_cache[k]
    # site-packages directories that appeared after the snapshot was made (apk add, pip
    # install): a cold start's site.py would have put them on sys.path, .pth files included.
    try:
        import site
        dirs = list(site.getsitepackages())
        if site.ENABLE_USER_SITE:
            dirs.insert(0, site.getusersitepackages())
        for d in dirs:
            if d not in sys.path and os.path.isdir(d):
                site.addsitedir(d)
        # A cold start's sitecustomize runs AFTER site.py added those, so what it appends
        # (/usr/lib/sandpie, the app's own modules) comes last there too.
        if '/usr/lib/sandpie' in sys.path:
            sys.path.remove('/usr/lib/sandpie')
            sys.path.append('/usr/lib/sandpie')
    except Exception:
        pass
    importlib.invalidate_caches()
    main = types.ModuleType('__main__')
    main.__builtins__ = builtins
    if len(argv) == 1 or argv[1] == '-':
        sys.argv = list(argv[1:]) or ['']
        src, fname = sys.stdin.buffer.read(), '<stdin>'
    elif argv[1] == '-c':
        sys.argv = ['-c'] + list(argv[3:])
        src, fname = argv[2], '<string>'
    else:
        path = argv[1]
        sys.argv = list(argv[1:])
        sys.path[0] = os.path.dirname(os.path.realpath(path))
        with open(path, 'rb') as fh:
            src = fh.read()
        fname = os.path.abspath(path)
        main.__file__ = fname
        main.__cached__ = None
    sys.modules['__main__'] = main
    import linecache
    linecache.clearcache()
    code = None
    try:
        code = compile(src, fname, 'exec')
        # python3 -c shows its source in tracebacks (keyed by the code object, which is
        # how CPython registers it: warnings, which look up by file name, do not see it).
        if fname == '<string>':
            reg = getattr(linecache, '_register_code', None)
            if reg is not None:
                reg(code, src, fname)
            else:
                linecache.cache[fname] = (len(src), None, src.splitlines(True), fname)
        exec(code, main.__dict__)
    except SystemExit:
        raise
    except BaseException as e:
        import traceback
        tb = e.__traceback__
        while tb is not None and tb.tb_frame.f_code is not code:
            tb = tb.tb_next
        traceback.print_exception(type(e), e, tb)
        sys.exit(130 if isinstance(e, KeyboardInterrupt) else 1)
    sys.exit(0)
`;
  return 'exec(compile(' + JSON.stringify(body) + ", '<walios-resume>', 'exec'))\n"
    + '_walios_resume(__import__("json").loads(' + JSON.stringify(JSON.stringify(argv)) + '), __import__("json").loads(' + JSON.stringify(JSON.stringify(envMap(env))) + '))\n';
}

// Start a resolved program as a process on its own worker. `asPid` is the pid of the
// image it replaces -- execve keeps pid, pgid and ppid -- otherwise it gets a fresh one.
// Returns a promise of the exit code (null = could not start).
function startProcess(target, envp, fdTable, cwd, cred, asPid, umask) {
  const proc = new Process(target.key, target.argv, envp, fdTable, cwd);
  if (umask !== undefined) proc.umask = umask;
  if (STRACE) stracePost(`[strace ${asPid || proc.pid}] exec ${target.key} ${JSON.stringify(target.argv.slice(0, 8))}\n`, 2);
  if (cred) proc.cred = { ...cred };
  if (asPid) {
    const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid;
    if (old && umask === undefined) proc.umask = old.umask;   // execve keeps the umask
    proc.pgid = old ? old.pgid : asPid; proc.sid = old ? old.sid : asPid;
    if (old && old.ppid) proc.ppid = old.ppid;
    // POSIX: the signal mask and PENDING signals survive execve (handlers reset). A kill
    // that raced the child between fork and exec used to vanish with the old Process
    // object -- `sleep 5 & kill $!` then ran the full 5s and reported 0.
    if (old) { proc.sig.mask = old.sig.mask; for (const s of old.sig.pending) proc.sig.pending.add(s); proc.startMs = old.startMs || proc.startMs; }
    else for (const Q of procs.values()) if (Q.childTasks && Q.childTasks.has(asPid)) { proc.ppid = Q.pid; break; }
    procs.set(asPid, proc);
  }
  return proc.run();
}

async function runProgramInWorker(p, argv, envp, fdTable, cwd, selfKey, cred, asPid) {
  const target = await resolveExec(p, argv, cwd, selfKey, 0);
  if (!target || target.eacces) return null;
  return await startProcess(target, envp, fdTable, cwd, cred, asPid);
}

// ================= entry =================
self.onmessage = async (ev) => {
  const m = ev.data;
  if (m.t === 'wisp-sab') { wispSab = m.sab; return; }
  if (m.t === 'wisp-port') { wispPort = m.port; return; }   // no SharedArrayBuffer on the page: message bridges (portBridge)
  if (m.t === 'opfs-port') { opfsPort = m.port; return; }
  if (m.t === 'add-pkg') { // register a package into the live manifest -> runnable (lazy-compiled on first exec)
    if (m.name && m.url) {
      manifest[m.name] = m.url; pkgAdded.add(m.name);
      pkgAddedMsgs.set(m.name, { name: m.name, url: m.url, tars: m.tars, lazyTars: m.lazyTars });
      // lazyTars is keyed by MODULE URL (see ensureModule), not by name. `tars` is the
      // repo index's [[url, prefix], ...] for this binary; `lazyTars` is the older
      // {url: tars} object form terminal.html sends -- merge it as-is.
      if (Array.isArray(m.tars) && m.tars.length) lazyTars[m.url] = m.tars;
      if (m.lazyTars && typeof m.lazyTars === 'object') Object.assign(lazyTars, m.lazyTars);
      // Same /bin/<name> stub boot gives every manifest program: the shell stat()s
      // $PATH before exec, so a package added mid-session was "not found" by name
      // until the next boot, even though execve could already resolve it.
      const bp = '/bin/' + m.name;
      if (!files.has(bp)) { mkdirp('/bin'); addFile(bp, te.encode('#!wali-manifest\n'), 0o100755); }
    }
    return; }
  // a host call may have written files under /root (dbx get, soffice, look's renders): re-read
  // listings from now on, or the very next command misses them for OPFS_LIST_TTL (2026-11-10)
  if (m.t === 'hostcall-reply') { opfsEpoch = Date.now(); hostcallReply(m.id, m.reply); return; }
  // Python snapshots (see pySnapPick): one built by another kernel of the tab, the go-ahead
  // to build one here, or the host dropping one.
  if (m.t === 'py-snap') { pySnapAccept(m.snap); return; }
  if (m.t === 'py-snap-build') { if (pySnapCfg) pySnapBuild(m.layer); else self.postMessage({ t: 'py-snap-failed', layer: m.layer, why: 'snapshots are off here' }); return; }
  if (m.t === 'py-snap-drop') { pySnaps.delete(m.layer); return; }   // the host answered a /dev/hostcall request
  if (m.t === 'vm-snapshot') {   // per-conversation VM state; see vmSnapshot
    let r;
    try { r = vmSnapshot(m.roots || ['/tmp', '/usr/local', '/opt'], m.max || (128 << 20)); }
    catch (e) { r = { error: String((e && e.message) || e) }; }
    r.pkgs = [...pkgAddedMsgs.values()];
    self.postMessage(Object.assign({ t: 'vm-snapshot', id: m.id }, r), r.buf ? [r.buf.buffer] : []);
    return; }
  if (m.t === 'mount-tar') {   // lazy package bundle, requested by the guest on an import miss
    loadTar(m.url, m.prefix, pyTreeTouch).then(() => self.postMessage({ t: 'tar-mounted', url: m.url, ok: true }),
                                  (e) => self.postMessage({ t: 'tar-mounted', url: m.url, ok: false, err: String(e && e.message || e) }));
    return; }
  if (m.t === 'opfs-sab') { opfsSab = m.sab; return; }
  if (m.t === 'winsize') { if (m.rows) winRows = m.rows; if (m.cols) winCols = m.cols;
    for (const p of ptys.values()) { p.rows = winRows; p.cols = winCols; if (p.pgrp) signalPgrp(p.pgrp, SIG.WINCH); } // POSIX: a size change raises SIGWINCH on the fg group so TUIs (vi, ssh) re-render
    return; }
  if (m.t === 'killall') {
    // Stop every process but KEEP this kernel: the VFS, the compiled modules and the OPFS
    // bridge all survive. The tool's deadline used to terminate the whole worker, which
    // threw away /tmp along with it -- so a build that ran out of budget lost the work it
    // had already done, every time. groupExit() is the same teardown exit_group uses, so a
    // parked wait4 or a blocked read is released rather than left hanging.
    // 137 = 128 + SIGKILL, what a shell reports for a killed job.
    for (const P of [...procs.values()]) { if (P.daemon) continue; try { P.groupExit(137); } catch (_) {} }   // (a snapshot builder is the kernel's, not the run's)
    self.postMessage({ t: 'killed-all' });
    return; }
  // SUSPEND / RESUME. killall preserves the FILESYSTEM but destroys the RUN: a ./configure
  // that ran out of budget still had to start over, because configure is not resumable.
  // These park the processes instead, so the work in flight survives and the next call
  // carries on from the same instruction.
  //
  // The reply says how many are CONFIRMED parked, not how many were signalled, because the
  // two differ: a stopper is honoured in the async delivery path, so a process parks at its
  // next BLOCKING syscall. Builds are syscall-bound and park within milliseconds, but a
  // process spinning in pure computation would not -- and the caller must be able to tell,
  // so it can fall back to killing rather than silently leave something burning CPU.
  if (m.t === 'stopall' || m.t === 'contall') {
    const sig = m.t === 'stopall' ? SIG.STOP : SIG.CONT;
    const all = [...procs.values()].filter((P) => !P.daemon);
    for (const P of all) { try { postSignal(P, sig); } catch (_) {} }
    const settle = () => {
      const parked = all.filter((P) => procs.has(P.pid) && P.stopped).length;
      const live = all.filter((P) => procs.has(P.pid)).length;
      for (const P of all) {
        if (procs.has(P.pid) && !P.stopped) {
          post('[spin] pid=' + P.pid + ' NOT parked: ' + (P.argv || []).join(' ').slice(0, 70)
            + ' inChild=' + P.inChild() + ' pendingSig=' + [...P.sig.pending]
            + ' queuedForParent=' + JSON.stringify(P.sigQueuedForParent || []) + " + NL + ", 2);
        }
      }
      self.postMessage({ t: m.t === 'stopall' ? 'stopped-all' : 'contd-all', parked, live });
    };
    // One turn of the loop is enough for anything already blocked in a syscall; the grace
    // gives a running process time to reach its next one.
    if (m.t === 'stopall') setTimeout(settle, 250); else settle();
    return; }
  if (m.t === 'sigint') { // page-level Ctrl-C -> guest foreground group (pty pgrp if set, else the root)
    let fg = 0; for (const p of ptys.values()) if (p.pgrp) fg = p.pgrp;
    if (!(fg && signalPgrp(fg, SIG.INT))) postSignal(rootProc, SIG.INT);
    return; }
  if (m.t === 'stdin') { opfsEpoch = Date.now();   // input from the host (a warm REPL's next run, a keystroke): later OPFS listings are re-read once
    const b = typeof m.data === 'string' ? te.encode(m.data) : new Uint8Array(m.data);
    if (termPty !== null) ptyMasterWrite(ptys.get(termPty), b); else pushStdin(b); return; } // terminal: keystrokes -> pty; else async stdin
  if (m.t === 'stdin-eof') { stdinEOF = true; const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); return; }
  if (m.t === 'dumpfile') { try { const p = norm(m.path, '/'); const f = files.get(p);
    if (!f) { self.postMessage({ t: 'dumpfile', path: m.path, b64: null }); return; }
    const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
    let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    self.postMessage({ t: 'dumpfile', path: m.path, b64: btoa(s) }); } catch (e) { self.postMessage({ t: 'dumpfile', path: m.path, b64: null, err: String(e) }); } return; }
  if (m.t === 'readfile') { try { const p = norm(m.path, '/'); const f = files.get(p); const isdir = dirs.has(p);
    const kids = isdir ? [...dirs.get(p)].slice(0, 12) : null;
    self.postMessage({ t: 'readfile', path: m.path, size: f ? f.size : -1, isdir, kids }); } catch (e) { self.postMessage({ t: 'readfile', path: m.path, size: -2 }); } return; }
  if (m.t !== 'run') return;
  try {
    const boot0 = performance.now();
    // The page measured the terminal before it sent this; without it every pty was
    // born 80x24 and the shell's line editor wrapped at 80 in a much wider window.
    // Must happen before newPty(): newPty copies these into the pty it creates.
    if (m.cols) winCols = m.cols;
    if (m.rows) winRows = m.rows;
    STRACE = !!m.strace;
    opfsEpoch = Date.now();   // listings from earlier runs are refreshed on first use (see opfsLoadDir)
    if (m.engine === 'inproc') INPROC = true;
    pySnapCfg = (m.pySnap && Array.isArray(m.pySnap.layers) && m.pySnap.layers.length) ? { layers: m.pySnap.layers, want: pySnapCfg && pySnapCfg.want } : null;
    if (INPROC && !INPROC_AVAILABLE) throw new Error('this browser has neither SharedArrayBuffer (cross-origin isolation) nor JSPI (WebAssembly.Suspending); walios cannot run here');
    if (INPROC) post(`[host] engine: in-process (JSPI${typeof SharedArrayBuffer === 'function' ? ', forced' : ', no SharedArrayBuffer'})\n`, 2);
    artFallback = m.artFallback || {};   // CDN url -> this server's copy (see fetchArt); before the first tar
    for (const [url, prefix] of m.tars || []) await loadTar(url, prefix);
    if (m.opfs) {
      opfsMount = norm(m.opfs, '/'); mkdirp(opfsMount);
      post((opfsSab || opfsPort) ? `[host] OPFS lazily mounted at ${opfsMount}${opfsPort ? ' (message bridge)' : ''}\n` : `[host] OPFS requested but no opfs bridge; ${opfsMount} is RAM-only\n`, 2);
    }
    manifest = m.manifest || {};
    lazyTars = m.lazyTars || {};   // moduleKey -> companion tars, mounted on first exec of that program
    if (m.noMmapPool) { mmapPool = false; post('[host] mmap pool DISABLED (always-grow)\n', 2); }
    // PATH discoverability: the shell stat()s $PATH for a command before exec'ing
    // it, so give every manifest program a tiny executable stub at /bin/<name>.
    // execve resolves the real module by basename via the manifest (the stub's
    // bytes are never run), so this only lets `python`, `ssh`, etc. be found by
    // name and appear in tab-completion. Non-applet programs would be "not found"
    // otherwise (rootfs /bin is empty).
    for (const name of new Set(Object.keys(manifest))) {
      const bp = '/bin/' + name;
      if (!files.has(bp)) addFile(bp, te.encode('#!wali-manifest\n'), 0o100755);
    }
    addFile('/etc/resolv.conf', te.encode('nameserver 1.1.1.1\n')); // DNS goes via DoH in the WISP worker
    addFile('/etc/hosts', te.encode('127.0.0.1 localhost\n'));
    // seed VFS with inline binaries (e.g. wasm just produced by clang.wasm)
    // A seeded "#!" script is meant to be RUN by name, and busybox will not exec a 0644
    // file -- every host used to need a `chmod +x` prelude for its own seeds.
    if (m.blobs) for (const [p, buf] of Object.entries(m.blobs)) { const u = new Uint8Array(buf);
      addFile(norm(p, '/'), u, (u.length > 1 && u[0] === 0x23 && u[1] === 0x21) ? 0o100755 : 0o100644); }
    // Symlinks the host wants in place before the guest runs, e.g. /files -> /root so the
    // paths the Pyodide backend taught the model ("/files/sandpie/scripts/x.py") resolve
    // here too: both roots are the same OPFS directory.
    if (m.links) for (const [p, tgt] of Object.entries(m.links)) { const lp = norm(p, '/');
      if (!files.has(lp) && !dirs.has(lp)) { addFile(lp, new Uint8Array(0), 0o120777); files.get(lp).sym = tgt; } }
    // Compile the ROOT module; everything else lazy-compiles on its first exec (ensureModule).
    for (const rk of new Set([m.vfsMain ? null : m.wasm])) {
      if (rk && !modCache.has(rk)) {
        // compileStreaming never hands back the bytes, and the process-worker proxy
        // needs the import signatures, so read the buffer and compile from it.
        const rb = new Uint8Array(await (await fetchArt(rk)).arrayBuffer());
        compileGuest(rk, rb);
      }
    }
    let rootKey = m.wasm;
    if (m.vfsMain) { // run a wasm sitting in the VFS as the root process
      const vp = norm(m.vfsMain, '/'); const f = files.get(vp);
      if (!f) throw new Error('vfsMain not found: ' + vp);
      rootKey = 'vfs:' + vp;
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (!modCache.has(rootKey)) compileGuest(rootKey, bytes.slice());
    }
    let rootFds;
    if (m.pty) { // terminal mode: run the shell on a fresh pty; bridge master <-> page
      termPty = newPty();
      rootFds = new Map([[0, { pty: termPty, master: false }], [1, { pty: termPty, master: false }], [2, { pty: termPty, master: false }]]);
    } else {
      termPty = null;
      rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
    }
    // WASI programs resolve absolute paths through PREOPENED dirs (libc scans fd 3+).
    // Give a wasi root module fd 3 = "/" so it can open the VFS by absolute path.
    { const rm = modCache.get(rootKey);
      if (rm && WebAssembly.Module.imports(rm).some(i => i.module === 'wasi_snapshot_preview1'))
        rootFds.set(3, { preopen: '/', dir: true, path: '/' }); }
    const env = Object.entries(m.env || {}).map(([k, v]) => k + '=' + v);
    nextPid = 100; syscallTotal = 0; procCount = 0; stdinChunks = []; stdinEOF = false; stdinWaiters = [];
    const root = new Process(rootKey, m.argv, env, rootFds, m.cwd || '/');
    if (m.uid !== undefined) { const u = m.uid | 0; root.cred = { uid: u, euid: u, suid: u, gid: u, egid: u, sgid: u }; } // run as a non-root user
    rootProc = root;
    self.postMessage({ t: 'boot', ms: performance.now() - boot0 });
    const t0 = performance.now();
    // Live gauges for the terminal header: total wasm memory across processes,
    // live process count, and cumulative syscalls (the page derives a rate = speed).
    // (+ the walios monitor's CPU / kernel-load / per-process numbers: statsSnapshot)
    let tickAt = performance.now();
    const statsTimer = setInterval(() => {
      const now = performance.now(), lag = Math.max(0, now - tickAt - 1000); tickAt = now;
      try { self.postMessage(Object.assign(statsSnapshot(t0), { lag: Math.round(lag) })); } catch (_) {}
    }, 1000);
    let code;
    try { code = await root.run(); }
    finally { clearInterval(statsTimer); try { self.postMessage(Object.assign(statsSnapshot(t0), { lag: 0, done: true })); } catch (_) {} }
    for (let i = 0; pendingLinks.size && i < 100000; i++) {   // pending link() copies (see pendingLinks)
      const pb = pendingLinks.keys().next().value;
      try { linkMaterialize(pb); } catch (e) { if (e instanceof NeedAsync) await e.promise; else { const pl = pendingLinks.get(pb); if (pl) clearTimeout(pl.timer); pendingLinks.delete(pb); } }
    }
    if (opfsBr) { try { opfsBr.call(OFS.RELEASE, 0, 0, 0, null); } catch {}
      for (const f of files.values()) { if (f.brRel) { clearTimeout(f.brRel); f.brRel = 0; } if (f.brId) f.brId = 0; } }
    straceFlush();
    self.postMessage({ t: 'exit', code, ms: performance.now() - t0, syscalls: syscallTotal, procs: procCount });
  } catch (e) {
    post('[host] fatal: ' + (e.stack || e) + '\n', 2);
    self.postMessage({ t: 'exit', code: 127, ms: 0, syscalls: syscallTotal, procs: procCount });
  }
};
