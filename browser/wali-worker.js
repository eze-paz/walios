// WALI browser syscall host v2 — process model edition.
// vfork/execve/wait4/pipes on top of the in-memory VFS + OPFS mount.
// Child branch runs in-place under an fd overlay (vfork semantics, guest
// longjmps back via wasm-EH SJLJ); wait4 runs parked children synchronously.
'use strict';

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
try { self.addEventListener('unhandledrejection', (e) => { try { self.postMessage({ t: 'out', fd: 2, s: '[host] UNHANDLED: ' + ((e.reason && e.reason.stack) || e.reason) + '\n' }); } catch {} }); } catch {}
const E = { PERM:1, NOENT:2, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, EXIST:17, NOTDIR:20, ISDIR:21, INVAL:22, NOTTY:25, SPIPE:29, NOSYS:38, NOTEMPTY:39 };
const err = (e) => BigInt(-e);
const td = new TextDecoder(), te = new TextEncoder();

// ================= VFS (global, shared by all processes) =================
const files = new Map(), dirs = new Map([['/', new Set()]]);
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
}
function addFile(p, data, mode = 0o100644) {
  const parent = p.slice(0, p.lastIndexOf('/')) || '/';
  mkdirp(parent);
  dirs.get(parent).add(p.slice(p.lastIndexOf('/') + 1));
  files.set(p, { data, size: data.length, mode, mtimeMs: Date.now() });
}
function rmEntry(p) {
  const parent = p.slice(0, p.lastIndexOf('/')) || '/';
  files.delete(p); dirs.delete(p);
  const d = dirs.get(parent); if (d) d.delete(p.slice(p.lastIndexOf('/') + 1));
}
async function loadTar(url, prefix) {
  const resp = await fetch(url);
  const ds = new DecompressionStream('gzip');
  const buf = new Uint8Array(await new Response(resp.body.pipeThrough(ds)).arrayBuffer());
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
    if (type === '0' || type === '\0') addFile(norm(prefix + '/' + name, '/'), buf.slice(off, off + size), 0o100000 | (tmode & 0o7777));
    else if (type === '5') mkdirp(norm(prefix + '/' + name, '/'));
    off += Math.ceil(size / 512) * 512;
  }
}
// ---- lazy OPFS mount (the riscv-vm ?p9lazy model): a sibling opfs-worker
// (spawned by the page, SAB set via the 'opfs-sab' message) owns every OPFS
// handle. We fault a directory's LISTING in on first touch of any path under
// it, and open a per-file handle only when the file is actually read/written —
// so mount cost is O(1) and untouched files hold no exclusive locks. ----
let opfsSab = null, opfsMount = null, opfsBr = null;
const opfsLoaded = new Set();   // dirs whose OPFS listing has been merged into the VFS
const OFS = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11 };
function initOpfs() {
  if (opfsBr) return opfsBr;
  if (!opfsSab) return null;
  const ctl = new Int32Array(opfsSab, 0, 8), bdata = new Uint8Array(opfsSab, 32);
  const call = (op, a0, a1, a2, bytes) => {
    if (bytes) bdata.set(bytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0;
    const prev = Atomics.load(ctl, 1);
    Atomics.add(ctl, 0, 1); Atomics.notify(ctl, 0);
    while (Atomics.load(ctl, 1) === prev) Atomics.wait(ctl, 1, prev);
    return { res: ctl[6], aux: ctl[7], data: bdata };
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
function opfsLoadDir(p) {       // merge one directory's OPFS listing (once)
  if (opfsLoaded.has(p)) return; opfsLoaded.add(p);
  const br = initOpfs(); if (!br) return;
  const pb = te.encode(opfsRel(p));
  const r = br.call(OFS.READDIR, pb.length, 0, 0, pb);
  if (r.res < 0) return;
  mkdirp(p);
  for (const e of JSON.parse(td.decode(r.data.slice(0, r.res)))) { // slice: TextDecoder rejects SAB views
    const child = p + '/' + e.n;
    if (e.d) mkdirp(child);
    else if (!files.has(child)) {
      dirs.get(p).add(e.n);
      files.set(child, { br: opfsRel(child), size: e.s, mode: 0o100644, mtimeMs: e.m, data: null });
    }
  }
}
function opfsFault(p) {         // fault in listings along p (and p itself if it is a dir)
  if (!inOpfs(p)) return;
  opfsLoadDir(opfsMount);
  if (p === opfsMount) return;
  let cur = opfsMount;
  for (const seg of opfsRel(p).split('/')) {
    cur = cur + '/' + seg;
    if (dirs.has(cur) && !files.has(cur)) opfsLoadDir(cur); else break;
  }
}
function opfsHandle(f, create) { // lazily open the per-file bridge handle
  if (f.brId) return f.brId;
  const br = initOpfs(); if (!br) return 0;
  const pb = te.encode(f.br);
  const r = br.call(OFS.OPEN, pb.length, create ? 1 : 0, 0, pb);
  if (r.res <= 0) return 0;
  f.brId = r.res;
  return f.brId;
}
function fileRead(f, pos, n) {
  if (f.br !== undefined) {
    const br = initOpfs(), id = opfsHandle(f); if (!id) return new Uint8Array(0);
    const want = Math.min(n, Math.max(0, f.size - pos)), out = new Uint8Array(want);
    let got = 0;
    while (got < want) {
      const chunk = Math.min(want - got, br.max);
      const r = br.call(OFS.READ, id, pos + got, chunk, null);
      if (r.res <= 0) break;
      out.set(r.data.subarray(0, r.res), got); got += r.res;
      if (r.res < chunk) break;
    }
    return out.subarray(0, got);
  }
  return f.data.subarray(pos, Math.min(pos + n, f.size));
}
function fileWrite(f, pos, bytes) {
  if (f.br !== undefined) {
    const br = initOpfs(), id = opfsHandle(f, true); if (!id) return 0;
    let done = 0;
    while (done < bytes.length) {
      const chunk = Math.min(bytes.length - done, br.max);
      const r = br.call(OFS.WRITE, id, pos + done, chunk, bytes.subarray(done, done + chunk));
      if (r.res <= 0) break;
      done += r.res;
    }
    f.size = Math.max(f.size, pos + done); f.mtimeMs = Date.now();
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
const unknownSyscalls = new Set();
const modCache = new Map();   // key -> WebAssembly.Module

// ---- concurrent scheduler (JSPI) ----
// Default: synchronous model (children run to completion at wait4). When the page
// passes jspi:true in the run message AND the browser supports JSPI (Chrome), each
// fork+exec'd child runs as a CONCURRENT WebAssembly.promising(_start) task, and
// blocking syscalls (read on an empty pipe, wait4, poll, nanosleep) SUSPEND via
// WebAssembly.Suspending and yield to the scheduler — enabling live interactive
// sessions (a shell driving a running pipeline, sshd) instead of run-at-wait4.
let JSPI = false;
const jspiAvailable = typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function';
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'nanosleep', 'clock_nanosleep', 'execve', 'recvmsg']);
const ASYNC_PAGES = 16;       // 1MB asyncify unwind buffer (grown at first fork)
const inflight = new Set();   // live child task promises
let pipeSuspends = 0, waitSuspends = 0; // JSPI concurrency evidence
// async stdin (JSPI): page posts {t:'stdin'} msgs; stdin reads suspend, not block
let stdinChunks = [], stdinEOF = false, stdinWaiters = [];
let winRows = 24, winCols = 80; // terminal size (set by the page's {t:'winsize'} message)
function pushStdin(u8) { stdinChunks.push(u8); const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); }
function concatU8(arr) { let n = 0; for (const a of arr) n += a.length; const o = new Uint8Array(n); let k = 0; for (const a of arr) { o.set(a, k); k += a.length; } return o; }
function drainStdinAsync(max) { if (stdinChunks.length) { let b = concatU8(stdinChunks); const take = b.subarray(0, max); const rest = b.subarray(take.length); stdinChunks = rest.length ? [rest.slice()] : []; return take.slice(); } if (stdinEOF) return new Uint8Array(0); return null; }
let manifest = {};            // basename -> module key (url)
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
  t[17] = 3; t[19] = 21; t[19] = 21; t[17 + 2] = 127; t[17 + 4] = 4; t[17 + 6] = 1; return t; }
function newPty() { const id = nextPtyId++; ptys.set(id, { toSlave: [], toMaster: [], line: [], termios: defaultTermios(), rows: winRows, cols: winCols, pgrp: 0, slaveWaiters: [], masterWaiters: [] }); return id; }
function wakePty(list) { if (list && list.length) { const w = list.splice(0); for (const f of w) f(); } }
function ptyStatObj(id, master) { return { size: 0, mode: 0o020620, nlink: 1, uid: 1000, gid: 5, dev: 6, ino: master ? 2 : 1000 + id, rdev: master ? ((5 << 8) | 2) : ((136 << 8) | id) }; }
const tflag = (p, off) => new DataView(p.termios.buffer).getUint32(off, true);
function ptyMasterWrite(p, bytes) { const lf = tflag(p, 12), canon = lf & ICANON, echo = lf & ECHO, icrnl = tflag(p, 0) & ICRNL;
  for (let c of bytes) { if (canon) {
      if (c === 0x7f || c === 0x08) { if (p.line.length) { p.line.pop(); if (echo) p.toMaster.push(8, 32, 8); } continue; }
      if (c === 0x0d && icrnl) c = 0x0a; p.line.push(c); if (echo) p.toMaster.push(c);
      if (c === 0x0a) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
    } else { p.toSlave.push(c); if (echo) p.toMaster.push(c); } }
  if (p.toSlave.length) wakePty(p.slaveWaiters); if (p.toMaster.length) wakePty(p.masterWaiters); }
function ptySlaveWrite(p, bytes) { const of = tflag(p, 4), onlcr = (of & OPOST) && (of & ONLCR);
  for (const c of bytes) { if (onlcr && c === 0x0a) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); }
  if (p.toMaster.length) wakePty(p.masterWaiters); }

// writers/readers are refcounts (bumped on fork/dup of an end, dropped on close);
// in JSPI mode a reader on an empty pipe suspends until a write wakes it or the
// last writer closes (writers==0 => EOF). readWaiters holds suspend resolvers.
function mkPipe() { return { chunks: [], writers: 1, readers: 1, readWaiters: [] }; }
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
function releaseFds(fdMap) { for (const h of fdMap.values()) {
  if (h && h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; }
  else if (h && h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; } } }
function wakeWaiters(S) { if (S.waitWaiters.length) { const w = S.waitWaiters; S.waitWaiters = []; for (const f of w) f(); } }
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
function post(s, fd) { self.postMessage({ t: 'out', fd: fd || 1, s }); }
let stdinCtl = null, stdinData = null;
// ---- WISP socket bridge: a sibling wisp-worker (spawned by the page) owns the
// WebSocket; we share a SAB with it (set via the 'wisp-sab' message). ----
let wisp = null, wispSab = null;
function initWisp() {
  if (wisp) return wisp;
  if (!wispSab) { post('[host] no WISP bridge (sockets unavailable)\n', 2); return { call: () => ({ res: -38, data: new Uint8Array(0) }), OP: {} }; }
  const sab = wispSab;
  const ctl = new Int32Array(sab, 0, 8), wdata = new Uint8Array(sab, 32);
  const call = (op, a0, a1, a2, bytes) => {
    if (bytes) wdata.set(bytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0;
    const prev = Atomics.load(ctl, 1);
    Atomics.add(ctl, 0, 1); Atomics.notify(ctl, 0);
    while (Atomics.load(ctl, 1) === prev) Atomics.wait(ctl, 1, prev);
    return { res: ctl[6], data: wdata };
  };
  wisp = { call, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8 } };
  return wisp;
}
function readSockaddr(S, p) { S.refresh();
  const fam = S.dv.getUint16(p, true), port = S.dv.getUint16(p + 2, false); let ip;
  if (fam === 10) { const g = []; for (let i = 0; i < 16; i += 2) g.push(S.dv.getUint16(p + 8 + i, false).toString(16)); ip = g.join(':'); }
  else ip = `${S.u8[p+4]}.${S.u8[p+5]}.${S.u8[p+6]}.${S.u8[p+7]}`; return { ip, port }; }
function writeSockaddr(S, p, d) { S.refresh(); S.u8.fill(0, p, p + 16);
  S.dv.setUint16(p, 2, true); S.dv.setUint16(p + 2, d.port, false);
  const o = d.ip.split('.').map(Number); S.u8[p+4]=o[0]; S.u8[p+5]=o[1]; S.u8[p+6]=o[2]; S.u8[p+7]=o[3]; return 16; }

function readStdin(n) {
  if (!stdinCtl) return new Uint8Array(0);
  while (true) {
    const st = Atomics.load(stdinCtl, 0);
    if (st === 2) return new Uint8Array(0);
    if (st === 1) {
      const len = Math.min(Atomics.load(stdinCtl, 1), n);
      const out = stdinData.slice(0, len);
      const rem = Atomics.load(stdinCtl, 1) - len;
      if (rem > 0) { stdinData.copyWithin(0, len, len + rem); Atomics.store(stdinCtl, 1, rem); }
      else Atomics.store(stdinCtl, 0, 0);
      Atomics.notify(stdinCtl, 0);
      return out;
    }
    Atomics.wait(stdinCtl, 0, 0);
  }
}

class ExitError extends Error { constructor(code) { super('exit'); this.code = code; } }

// ================= Process =================
class Process {
  constructor(modKey, argv, env, fdTable, cwd) {
    this.modKey = modKey;
    this.argv = argv; this.env = env;   // env: array of "K=V"
    this.fds = fdTable;
    this.nextFd = Math.max(3, ...[...fdTable.keys()].map(k => k + 1));
    this.cwd = { p: cwd || '/' };
    this.pid = nextPid++;
    this.heapBrk = 0;
    this.childStack = [];
    this.dirState = new Map();
    this.pending = [];
    this.reaped = new Map();
    this.childTasks = new Map();     // JSPI: pid -> in-flight concurrent task
    this.waitWaiters = [];           // JSPI: resolvers for a process suspended in wait4
    this.forkState = 'none';         // Asyncify fork: 'none' | 'unwinding' | 'rewinding'
    this.asyncifyBuf = 0; this.forkRet = 0n;
    this.syscalls = 0;
  }
  allocFd() { let g = 0; while (this.fds.has(g)) g++; return g; } // POSIX lowest-free fd
  bumpFifo(h) { if (h && h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') h.fifo.readers++; } else if (h && h.spair) { h.spair.wr.writers++; h.spair.rd.readers++; } }
  refresh() { if (this.membuf !== this.memory.buffer) { this.membuf = this.memory.buffer; this.u8 = new Uint8Array(this.membuf); this.dv = new DataView(this.membuf); } }
  cstr(p) { this.refresh(); let e = p; while (this.u8[e] !== 0) e++; return td.decode(this.u8.slice(p, e)); }
  wbytes(p, b) { this.refresh(); this.u8.set(b, p); }
  wstr(p, s, max) { const b = te.encode(s); const n = max ? Math.min(b.length, max - 1) : b.length; this.wbytes(p, b.subarray(0, n)); this.u8[p + n] = 0; return n; }
  i64(p, v) { this.refresh(); this.dv.setBigInt64(p, BigInt(v), true); }
  i32(p, v) { this.refresh(); this.dv.setInt32(p, Number(v), true); }
  r32(p) { this.refresh(); return this.dv.getInt32(p, true); }
  r64(p) { this.refresh(); return this.dv.getBigInt64(p, true); }
  rPtrArray(p) { const out = []; for (;;) { const q = this.r32(p); if (!q) break; out.push(this.cstr(q)); p += 4; } return out; }
  atPath(dirfd, s) {
    if (s.startsWith('/')) return norm(s, '/');
    if ((dirfd | 0) === -100) return norm(s, this.cwd.p);
    const h = this.fds.get(dirfd); return norm(s, h && h.path && dirs.has(h.path) ? h.path : this.cwd.p);
  }
  putStat(p, o) {
    this.refresh(); this.u8.fill(0, p, p + 144);
    this.i64(p, BigInt(o.dev || 1)); this.i64(p + 8, BigInt(o.ino || 1)); this.i64(p + 16, BigInt(o.nlink || 1));
    this.i32(p + 24, o.mode); this.i32(p + 28, o.uid ?? 1000); this.i32(p + 32, o.gid ?? 1000);
    this.i64(p + 40, BigInt(o.rdev || 0));
    this.i64(p + 48, BigInt(o.size)); this.i64(p + 56, 4096n); this.i64(p + 64, BigInt(Math.ceil(o.size / 512)));
    const t = (off, ms) => { this.i64(p + off, BigInt(Math.floor(ms / 1000))); this.i64(p + off + 8, BigInt(Math.floor((ms % 1000) * 1e6))); };
    t(72, o.mtimeMs || Date.now()); t(88, o.mtimeMs || Date.now()); t(104, o.mtimeMs || Date.now());
  }
  statPath(path2, sp) {
    if (path2 === '/proc/self/exe') { this.putStat(sp, { size: 1, mode: 0o100755 }); return 0n; }
    opfsFault(path2);
    if (dirs.has(path2)) { this.putStat(sp, { size: 4096, mode: 0o040755 }); return 0n; }
    const f = files.get(path2); if (!f) return err(E.NOENT);
    this.putStat(sp, { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs });
    return 0n;
  }
  openAt(path2, flags, mode) {
    const O_CREAT = 0o100, O_TRUNC = 0o1000, O_APPEND = 0o2000, O_DIRECTORY = 0o200000, O_EXCL = 0o200;
    if (path2 === '/proc/self/exe') { const g = this.allocFd(); this.fds.set(g, { exe: true }); return BigInt(g); }
    opfsFault(path2);
    if (path2 === '/dev/ptmx') { const id = newPty(); const g = this.allocFd(); this.fds.set(g, { pty: id, master: true }); return BigInt(g); }
    if (path2 === '/dev/null') { const g = this.allocFd(); this.fds.set(g, { devnull: true }); return BigInt(g); }
    { const m = path2.match(/^\/dev\/pts\/(\d+)$/); if (m) { const id = +m[1]; if (!ptys.has(id)) return err(E.NOENT); const g = this.allocFd(); this.fds.set(g, { pty: id, master: false }); return BigInt(g); } }
    if (dirs.has(path2)) { const g = this.allocFd(); this.fds.set(g, { path: path2, dir: true }); return BigInt(g); }
    if (flags & O_DIRECTORY) return err(E.NOTDIR);
    let f = files.get(path2);
    if (!f) {
      if (!(flags & O_CREAT)) return err(E.NOENT);
      addFile(path2, new Uint8Array(0));
      f = files.get(path2);
      if (inOpfs(path2)) { f.br = opfsRel(path2); f.data = null; opfsHandle(f, true); } // new files under the mount persist
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) return err(E.EXIST);
    if (flags & O_TRUNC) {
      if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, 0, 0, null); }
      else f.data = new Uint8Array(0);
      f.size = 0;
    }
    const g = this.allocFd();
    this.fds.set(g, { path: path2, file: f, pos: (flags & O_APPEND) ? f.size : 0, append: !!(flags & O_APPEND) });
    return BigInt(g);
  }
  inChild() { return this.childStack.length > 0; }
  parkChild(fill) {
    const ctx = this.childStack.pop();
    this.fds = ctx.savedFds;
    this.pending.push({ pid: ctx.pid, ...fill });
    return CHILD_DONE;
  }

  sys(name, a) {
    const S = this;
    switch (name) {
      case 'read': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined) { if (h.std !== 0) return err(E.BADF);
          if (JSPI) { const b = drainStdinAsync(a[2]); if (b === null) return h.nonblock ? err(E.AGAIN) : 0n; S.wbytes(a[1], b); return BigInt(b.length); }
          const b = readStdin(a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.fifo) { if (!h.fifo.chunks.length && h.nonblock && h.fifo.writers > 0) return err(E.AGAIN); const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.spair) { if (!h.spair.rd.chunks.length && h.nonblock && h.spair.rd.writers > 0) return err(E.AGAIN); const b = pipeRead(h.spair.rd, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.devnull) return 0n;
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
          if (!q.length) return err(E.AGAIN); const k = Math.min(q.length, a[2]); S.wbytes(a[1], Uint8Array.from(q.splice(0, k))); return BigInt(k); }
        if (h.sock) { const br = initWisp(); if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); } const r = br.call(h.sock.udp ? br.OP.RECVFROM : br.OP.RECV, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res)); return BigInt(r.res); }
        if (!h.file) return err(E.BADF);
        const b = fileRead(h.file, h.pos, a[2]); S.wbytes(a[1], b); h.pos += b.length; return BigInt(b.length);
      }
      case 'write': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.std !== undefined) { post(td.decode(S.u8.slice(a[1], a[1] + a[2])), h.std === 0 ? 1 : h.std); return BigInt(a[2]); }
        if (h.fifo) { h.fifo.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.fifo); return BigInt(a[2]); }
        if (h.spair) { h.spair.wr.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.spair.wr); return BigInt(a[2]); }
        if (h.devnull) return BigInt(a[2]);
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const b = S.u8.slice(a[1], a[1] + a[2]); if (h.master) ptyMasterWrite(p, b); else ptySlaveWrite(p, b); return BigInt(a[2]); }
        if (h.sock) { const br = initWisp(); const r = br.call(br.OP.SEND, h.sock.id, a[2], 0, S.u8.slice(a[1], a[1] + a[2])); return BigInt(r.res); }
        if (!h.file) return err(E.BADF);
        const w = fileWrite(h.file, h.append ? h.file.size : h.pos, S.u8.slice(a[1], a[1] + a[2])); h.pos += w; return BigInt(w);
      }
      case 'writev': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('write', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; } return t; }
      case 'readv': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('read', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; if (Number(r) < l) break; } return t; }
      case 'open': return S.openAt(S.atPath(-100, S.cstr(a[0])), a[1], a[2]);
      case 'openat': return S.openAt(S.atPath(a[0], S.cstr(a[1])), a[2], a[3]);
      case 'close': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.sock && h.sock.id) initWisp().call(initWisp().OP.CLOSE, h.sock.id, 0, 0);
        S.fds.delete(a[0]); S.dirState.delete(a[0]); return 0n; }
      case 'lseek': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock || h.pty !== undefined || h.devnull) return err(E.SPIPE);
        const size = h.file ? h.file.size : 0;
        h.pos = a[2] === 0 ? Number(a[1]) : a[2] === 1 ? (h.pos || 0) + Number(a[1]) : size + Number(a[1]);
        return BigInt(h.pos); }
      case 'fstat': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.pty !== undefined) { S.putStat(a[1], ptyStatObj(h.pty, h.master)); return 0n; }
        if (h.devnull) { S.putStat(a[1], { size: 0, mode: 0o020620 }); return 0n; }
        if (h.std !== undefined || h.fifo || h.sock || h.spair) { S.putStat(a[1], { size: 0, mode: (h.fifo || h.sock || h.spair) ? 0o010600 : 0o020620 }); return 0n; }
        if (h.exe) { S.putStat(a[1], { size: 1, mode: 0o100755 }); return 0n; }
        return S.statPath(h.path, a[1]); }
      case 'stat': case 'lstat': { const p = S.atPath(-100, S.cstr(a[0])); let m;
        if (p === '/dev/ptmx') { S.putStat(a[1], ptyStatObj(0, true)); return 0n; }
        if ((m = p.match(/^\/dev\/pts\/(\d+)$/))) { if (!ptys.has(+m[1])) return err(E.NOENT); S.putStat(a[1], ptyStatObj(+m[1], false)); return 0n; }
        if (p === '/dev/null' || p === '/dev/tty') { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        return S.statPath(p, a[1]); }
      case 'newfstatat': { const s = S.cstr(a[1]); return s === '' ? S.sys('fstat', [a[0], a[2]]) : S.statPath(S.atPath(a[0], s), a[2]); }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        opfsFault(p);
        return (files.has(p) || dirs.has(p)) ? 0n : err(E.NOENT); }
      case 'readlink': { const p = S.atPath(-100, S.cstr(a[0]));
        if (p === '/proc/self/exe') return BigInt(S.wstr(a[1], '/bin/' + (S.argv[0] || 'wasm'), a[2] + 1));
        let m2; if ((m2 = p.match(/^\/proc\/self\/fd\/(\d+)$/))) { const h = S.fds.get(+m2[1]); if (!h) return err(E.BADF);
          const tgt = h.pty !== undefined ? (h.master ? '/dev/ptmx' : '/dev/pts/' + h.pty) : h.path ? h.path : h.std !== undefined ? '/dev/tty' : '/dev/null';
          return BigInt(S.wstr(a[1], tgt, a[2] + 1)); }
        return err(E.INVAL); }
      case 'unlink': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); if (!files.has(p)) return err(E.NOENT);
        const f = files.get(p);
        if (f.br !== undefined) { const r = opfsPathOp(OFS.UNLINK, f.br); if (r < 0) return BigInt(r); f.brId = 0; }
        rmEntry(p); return 0n; }
      case 'rmdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); if (!dirs.has(p)) return err(E.NOENT);
        if (dirs.get(p).size) return err(E.NOTEMPTY);
        if (inOpfs(p) && p !== opfsMount) { const r = opfsPathOp(OFS.RMDIR, opfsRel(p)); if (r < 0 && r !== -E.NOENT) return BigInt(r); }
        rmEntry(p); return 0n; }
      case 'mkdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); mkdirp(p);
        if (inOpfs(p) && p !== opfsMount) { const r = opfsPathOp(OFS.MKDIR, opfsRel(p)); if (r < 0) return BigInt(r); opfsLoaded.add(p); }
        return 0n; }
      case 'rename': { const pa = S.atPath(-100, S.cstr(a[0])), pb = S.atPath(-100, S.cstr(a[1]));
        opfsFault(pa); opfsFault(pb);
        const f = files.get(pa); if (!f) return err(E.NOENT);
        if (f.br !== undefined && inOpfs(pb)) {          // OPFS -> OPFS: rename in the store
          const r = opfsPathOp(OFS.RENAME, f.br, opfsRel(pb)); if (r < 0) return BigInt(r);
          rmEntry(pb); rmEntry(pa);
          addFile(pb, new Uint8Array(0)); const nf = files.get(pb);
          nf.br = opfsRel(pb); nf.brId = 0; nf.data = null; nf.size = f.size; return 0n; }
        if (f.br !== undefined) {                        // OPFS -> RAM: pull bytes out, drop the store copy
          const bytes = fileRead(f, 0, f.size); const r = opfsPathOp(OFS.UNLINK, f.br); if (r < 0) return BigInt(r);
          rmEntry(pb); rmEntry(pa); addFile(pb, bytes.slice()); return 0n; }
        if (inOpfs(pb)) {                                // RAM -> OPFS: persist into the store
          const bytes = f.data ? f.data.subarray(0, f.size) : new Uint8Array(0);
          rmEntry(pb); rmEntry(pa);
          addFile(pb, new Uint8Array(0)); const nf = files.get(pb);
          nf.br = opfsRel(pb); nf.data = null; nf.size = 0;
          if (!opfsHandle(nf, true)) return err(E.ACCES);
          initOpfs().call(OFS.TRUNC, nf.brId, 0, 0, null);
          fileWrite(nf, 0, bytes); return 0n; }
        rmEntry(pb); rmEntry(pa);                        // RAM -> RAM (original behavior)
        addFile(pb, f.data || new Uint8Array(0)); files.get(pb).size = f.size; return 0n; }
      case 'chdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); if (!dirs.has(p)) return err(E.NOTDIR); S.cwd.p = p; return 0n; }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1);
      case 'chmod': case 'fchmod': case 'chown': return 0n;
      case 'umask': return 0o22n;
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); const g = S.allocFd(); S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[0] !== a[1]) { const old = S.fds.get(a[1]);
          if (old && old.fifo) { if (old.end === 'w') { if (--old.fifo.writers <= 0) wakePipe(old.fifo); } else old.fifo.readers--; }
          else if (old && old.spair) { if (--old.spair.wr.writers <= 0) wakePipe(old.spair.wr); old.spair.rd.readers--; }
          S.fds.set(a[1], { ...h }); S.bumpFifo(h); } return BigInt(a[1]); }
      case 'pipe': case 'pipe2': {
        const nb = name === 'pipe2' && !!(a[1] & 0x800);
        const fifo = mkPipe();
        const r = S.allocFd(); S.fds.set(r, { fifo, end: 'r', nonblock: nb });
        const w = S.allocFd(); S.fds.set(w, { fifo, end: 'w', nonblock: nb });
        S.i32(a[0], r); S.i32(a[0] + 4, w); return 0n; }
      case 'socketpair': { const nb = !!(a[1] & 0x800);
        const f1 = mkPipe(), f2 = mkPipe();
        const A = S.allocFd(); S.fds.set(A, { spair: { rd: f2, wr: f1 }, nonblock: nb });
        const B = S.allocFd(); S.fds.set(B, { spair: { rd: f1, wr: f2 }, nonblock: nb });
        S.i32(a[3], A); S.i32(a[3] + 4, B); return 0n; }

      case 'fork': case 'vfork': {
        const pid = nextPid++;
        const savedFds = S.fds;
        S.fds = new Map([...savedFds].map(([k, v]) => [k, { ...v }]));
        for (const v of S.fds.values()) S.bumpFifo(v); // child inherits a ref on each pipe end
        S.childStack.push({ pid, savedFds });
        return BigInt(pid); }
      case 'execve': {
        const p = S.cstr(a[0]);
        const argv = S.rPtrArray(a[1]);
        const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) {
          const code = runProgram(p, argv, envp, S.fds, S.cwd.p, S.modKey);
          if (code === null) return err(E.NOENT);
          throw new ExitError(code);
        }
        const fdsnap = S.fds;
        if (JSPI) { // spawn the child as a CONCURRENT task; parent longjmps back and keeps running
          const ctx = S.childStack.pop(); S.fds = ctx.savedFds; const childPid = ctx.pid;
          const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modKey)
            .then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); wakeWaiters(S); });
          inflight.add(task); task.finally(() => inflight.delete(task));
          S.childTasks.set(childPid, task);
          return CHILD_DONE;
        }
        return S.parkChild({ exec: { path: p, argv, envp, fds: fdsnap, cwd: S.cwd.p, selfKey: S.modKey } }); }
      case 'exit': case 'exit_group': {
        if (S.inChild()) return S.parkChild({ exited: a[0] & 0xff });
        throw new ExitError(a[0]); }
      case 'wait4': {
        const want = a[0] | 0;
        while (S.pending.length) {
          const c = S.pending.shift();
          if (c.exited !== undefined) { S.reaped.set(c.pid, c.exited); continue; }
          const code = runProgram(c.exec.path, c.exec.argv, c.exec.envp, c.exec.fds, c.exec.cwd, c.exec.selfKey);
          S.reaped.set(c.pid, code === null ? 127 : code);
        }
        let pid = -1;
        if (want > 0) { if (S.reaped.has(want)) pid = want; }
        else if (S.reaped.size) pid = S.reaped.keys().next().value;
        if (pid < 0) return err(E.CHILD);
        const code = S.reaped.get(pid); S.reaped.delete(pid);
        if (a[1]) S.i32(a[1], (code & 0xff) << 8);
        return BigInt(pid); }

      case 'brk': { S.refresh(); if (!S.heapBrk) S.heapBrk = S.membuf.byteLength;
        if (a[0] === 0 || a[0] <= S.heapBrk) return BigInt(S.heapBrk); return err(E.NOMEM); }
      case 'mmap': {
        S.refresh(); const base = S.membuf.byteLength;
        S.memory.grow(Math.ceil(a[1] / PAGE)); S.refresh();
        if (!(a[3] & 0x20)) {
          const h = S.fds.get(a[4]); if (!h || !h.file) return err(E.BADF);
          S.wbytes(base, fileRead(h.file, Number(a[5]), a[1]));
        }
        return BigInt(base); }
      case 'munmap': case 'mprotect': case 'madvise': return 0n;
      case 'mremap': { if (a[2] <= a[1]) return BigInt(a[0]);
        const b = Number(S.sys('mmap', [0, a[2], 3, 0x22, -1, 0n])); S.refresh(); S.u8.copyWithin(b, a[0], a[0] + a[1]); return BigInt(b); }
      case 'getdents64': {
        const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF);
        let st = S.dirState.get(a[0]);
        if (!st) { st = { names: ['.', '..', ...dirs.get(h.path)], pos: 0 }; S.dirState.set(a[0], st); }
        let off = 0;
        while (st.pos < st.names.length) {
          const nm = st.names[st.pos]; const nb = te.encode(nm);
          const reclen = (19 + nb.length + 1 + 7) & ~7;
          if (off + reclen > a[2]) break;
          const full = h.path === '/' ? '/' + nm : h.path + '/' + nm;
          const type = dirs.has(full) || nm === '.' || nm === '..' ? 4 : 8;
          S.i64(a[1] + off, 1n); S.i64(a[1] + off + 8, BigInt(st.pos + 1));
          S.refresh(); S.dv.setUint16(a[1] + off + 16, reclen, true); S.u8[a[1] + off + 18] = type;
          S.wbytes(a[1] + off + 19, nb); S.u8[a[1] + off + 19 + nb.length] = 0;
          off += reclen; st.pos++;
        }
        return BigInt(off); }
      case 'ioctl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); S.refresh(); const req = a[1] >>> 0;
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
            case 0x40045441: { const g = S.allocFd(); S.fds.set(g, { pty: h.pty, master: false }); return BigInt(g); }
            default: return 0n;
          } }
        if (h.std === undefined) return err(E.NOTTY);
        if (req === 0x5413) { S.dv.setUint16(a[2], winRows, true); S.dv.setUint16(a[2] + 2, winCols, true); S.i32(a[2] + 4, 0); } // ssh reads local tty size here
        if (req === 0x5401) S.wbytes(a[2], defaultTermios());
        return 0n; }
      case 'fcntl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[1] === 0 || a[1] === 1030) {
          const min = Number(a[2]) || 0; let g = min; while (S.fds.has(g)) g++;
          S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g);
        }
        if (a[1] === 3) return BigInt(2 | (h.nonblock ? 0x800 : 0));
        if (a[1] === 4) { h.nonblock = !!(Number(a[2]) & 0x800); return 0n; }
        return 0n; }
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const ms = performance.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt(Math.floor((ms % 1000) * 1e6))); return 0n; }
        const ms = Date.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt((ms % 1000) * 1e6)); return 0n; }
      case 'gettimeofday': { const ms = Date.now(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt((ms % 1000) * 1000)); return 0n; }
      case 'nanosleep': case 'clock_nanosleep': return 0n;
      case 'uname': { ['Linux', 'wali', '6.1.0-wali', '#1 WALI-browser', 'wasm32', ''].forEach((s, i) => S.wstr(a[0] + i * 65, s, 65)); return 0n; }
      case 'getuid': case 'geteuid': case 'getgid': case 'getegid': return 1000n;
      case 'setuid': case 'setgid': case 'setreuid': case 'setregid': case 'setresuid': case 'setresgid': case 'getgroups': case 'setgroups': return 0n;
      case 'chroot': return 0n;
      case 'getpid': return BigInt(S.inChild() ? S.childStack[S.childStack.length - 1].pid : S.pid);
      case 'getppid': return 1n; case 'gettid': return BigInt(S.pid);
      case 'getpgid': return BigInt(S.pid); case 'setpgid': case 'setsid': return 0n;
      case 'set_tid_address': return BigInt(S.pid);
      case 'tkill': case 'kill': { if (S.inChild()) return S.parkChild({ exited: 128 + (a[1] | 0) }); throw new ExitError(128 + (a[1] | 0)); }
      case 'rt_sigaction': case 'rt_sigprocmask': case 'sigaltstack': case 'setitimer': return 0n;
      case 'futex': return 0n;
      case 'sched_getaffinity': { S.i64(a[2], 1n); return 8n; }
      case 'sched_yield': return 0n;
      case 'prlimit64': { if (a[3]) { S.i64(a[3], 0x800000n); S.i64(a[3] + 8, 0x800000n); } return 0n; }
      case 'getrlimit': { S.i64(a[1], 0x800000n); S.i64(a[1] + 8, 0x800000n); return 0n; }
      case 'setrlimit': return 0n;
      case 'getrusage': { S.refresh(); S.u8.fill(0, a[1], a[1] + 144); return 0n; }
      case 'sysinfo': { S.refresh(); S.u8.fill(0, a[0], a[0] + 112); S.i64(a[0], 1000n); S.i64(a[0] + 32, 4294967296n); S.i64(a[0] + 40, 2147483648n); return 0n; }
      case 'getrandom': { const b = new Uint8Array(Math.min(a[1], 65536)); crypto.getRandomValues(b); S.wbytes(a[0], b); return BigInt(b.length); }
      case 'poll': { S.refresh(); let ready = 0;
        for (let i = 0; i < a[1]; i++) { const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
          const h = S.fds.get(fd); let re = 0;
          if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; if (ev & 4) re |= 4; }
          else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; }
          else re = ev & 5;
          S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++; }
        return BigInt(ready); }
      case 'select': case 'pselect6': return 1n;
      case 'socket': { const dom = a[0] & 0xff, type = a[1] & 0xff, nonblock = !!(a[1] & 0x800);
        if (dom !== 2 && dom !== 10) return err(E.NOSYS);
        const br = initWisp();
        if (type === 2) { const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, udp: true, nonblock } }); return BigInt(g); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, dom, nonblock } }); return BigInt(g); }
      case 'bind': return 0n;
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF); S.refresh();
        const dst = readSockaddr(S, a[1]);
        if (h.sock.udp) { h.sock.dest = dst; return 0n; }
        const br = initWisp(); const spec = te.encode(`${dst.ip}|${dst.port}`);
        const r = br.call(br.OP.CONNECT, spec.length, 0, 0, spec); if (r.res < 0) return BigInt(r.res); h.sock.id = r.res; return 0n; }
      case 'sendto': case 'sendmsg': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh(); let payload;
          if (name === 'sendmsg') {
            const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
            for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(S.u8.slice(p, p + l)); }
            payload = concatU8(parts);
            const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24);
            if (ctl && ctllen >= 16) { const clen = S.r32(ctl), lvl = S.r32(ctl + 8), typ = S.r32(ctl + 12);
              if (lvl === 1 && typ === 1) { const nf = (clen - 16) >> 2; h.spair.wr.fds = h.spair.wr.fds || [];
                for (let i = 0; i < nf; i++) { const fd = S.r32(ctl + 16 + i * 4); const hh = S.fds.get(fd); if (hh) { h.spair.wr.fds.push({ ...hh, shared: true }); S.bumpFifo(hh); } } } }
          } else payload = S.u8.slice(a[1], a[1] + a[2]);
          h.spair.wr.chunks.push(payload); wakePipe(h.spair.wr); return BigInt(payload.length); }
        if (!h.sock) return err(E.BADF);
        const br = initWisp(); S.refresh(); let payload, dest = h.sock.dest;
        if (name === 'sendmsg') { const np = S.r32(a[1]); if (np) dest = readSockaddr(S, np);
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(S.u8.slice(p, p + l)); }
          payload = new Uint8Array(parts.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of parts) { payload.set(x, o); o += x.length; } }
        else { payload = S.u8.slice(a[1], a[1] + a[2]); if (a[4]) dest = readSockaddr(S, a[4]); }
        if (h.sock.udp) { if (!dest) return err(E.INVAL); h.sock.lastDest = dest;
          const addr = te.encode(`${dest.ip}|${dest.port}`); const packed = new Uint8Array(payload.length + addr.length); packed.set(payload, 0); packed.set(addr, payload.length);
          const r = br.call(br.OP.SENDTO, h.sock.id, payload.length, addr.length, packed); return BigInt(r.res); }
        const r = br.call(br.OP.SEND, h.sock.id, payload.length, 0, payload); return BigInt(r.res); }
      case 'recvmsg': case 'recvfrom': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh();
          if (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length)) { if (h.spair.rd.writers <= 0) return 0n; if (h.nonblock) return err(E.AGAIN); }
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue; const b = pipeRead(h.spair.rd, l); if (!b.length) break; S.wbytes(p, b); total += b.length; if (b.length < l) break; }
          const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24);
          if (ctl && ctllen >= 16 && h.spair.rd.fds && h.spair.rd.fds.length) { const hh = h.spair.rd.fds.shift(); const g = S.allocFd(); S.fds.set(g, hh);
            S.i32(ctl, 20); S.i32(ctl + 8, 1); S.i32(ctl + 12, 1); S.i32(ctl + 16, g); S.i32(a[1] + 24, 20);
          } else if (ctl) S.i32(a[1] + 24, 0);
          return BigInt(total); }
        if (!h.sock) return err(E.BADF);
        const br = initWisp(); const op = h.sock.udp ? br.OP.RECVFROM : br.OP.RECV;
        if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); }
        if (name === 'recvfrom') { const r = br.call(op, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res));
          if (a[4] && h.sock.lastDest) { const n = writeSockaddr(S, a[4], h.sock.lastDest); if (a[5]) S.i32(a[5], n); } return BigInt(r.res); }
        const np = S.r32(a[1]); if (np && h.sock.lastDest) { const n = writeSockaddr(S, np, h.sock.lastDest); S.i32(a[1] + 4, n); }
        const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
        for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
          const r = br.call(op, h.sock.id, l, 0); if (r.res < 0) return total || BigInt(r.res); if (r.res === 0) break; S.wbytes(p, r.data.subarray(0, r.res)); total += r.res; if (r.res < l) break; }
        return BigInt(total); }
      case 'setsockopt': case 'getsockname': case 'getpeername': case 'shutdown': return 0n;
      default:
        if (!unknownSyscalls.has(name)) { unknownSyscalls.add(name); post(`[host] ENOSYS SYS_${name}\n`, 2); }
        return err(E.NOSYS);
    }
  }

  // ---- JSPI: async syscall path (only the blocking ones; the rest delegate to sys) ----
  async sysAsync(name, a) {
    const S = this;
    switch (name) {
      case 'read': case 'readv': {
        const h = S.fds.get(a[0]);
        if (h && h.std === 0 && !h.nonblock) { while (!stdinChunks.length && !stdinEOF) { pipeSuspends++; await new Promise(res => stdinWaiters.push(res)); } return S.sys(name, a); }
        if (h && h.pty !== undefined && !h.nonblock) { const p = ptys.get(h.pty); const q = () => h.master ? p.toMaster : p.toSlave; const wl = h.master ? p.masterWaiters : p.slaveWaiters;
          while (!q().length) { pipeSuspends++; await new Promise(res => wl.push(res)); } return S.sys(name, a); }
        if (h && h.fifo && !h.nonblock) { while (!h.fifo.chunks.length && h.fifo.writers > 0) { pipeSuspends++; await new Promise(res => h.fifo.readWaiters.push(res)); } return S.sys(name, a); }
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && h.spair.rd.writers > 0) { pipeSuspends++; await new Promise(res => h.spair.rd.readWaiters.push(res)); } return S.sys(name, a); }
        return S.sys(name, a);
      }
      case 'recvmsg': {
        const h = S.fds.get(a[0]);
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length) && h.spair.rd.writers > 0) { pipeSuspends++; await new Promise(res => h.spair.rd.readWaiters.push(res)); } }
        return S.sys(name, a);
      }
      case 'execve': {
        const p = S.cstr(a[0]); const argv = S.rPtrArray(a[1]); const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) { const code = await runProgramAsync(p, argv, envp, S.fds, S.cwd.p, S.modKey); if (code === null) return err(E.NOENT); throw new ExitError(code); }
        const fdsnap = S.fds; const ctx = S.childStack.pop(); S.fds = ctx.savedFds; const childPid = ctx.pid;
        const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modKey).then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); wakeWaiters(S); });
        inflight.add(task); task.finally(() => inflight.delete(task)); S.childTasks.set(childPid, task);
        return CHILD_DONE;
      }
      case 'nanosleep': case 'clock_nanosleep': {
        const tp = name === 'nanosleep' ? a[0] : a[2];
        let ms = 0; if (tp) { S.refresh(); ms = Number(S.r64(tp)) * 1000 + Number(S.r64(tp + 8)) / 1e6; }
        if (ms > 0) await new Promise(res => setTimeout(res, Math.min(ms, 3600000)));
        return 0n;
      }
      case 'wait4': return await S.wait4Async(a);
      case 'poll': case 'ppoll': return await S.pollAsync(name, a);
      default: return S.sys(name, a);
    }
  }
  async wait4Async(a) {
    const S = this; const want = a[0] | 0;
    while (S.pending.length) { const c = S.pending.shift(); if (c.exited !== undefined) S.reaped.set(c.pid, c.exited); }
    for (;;) {
      let pid = -1;
      if (want > 0) { if (S.reaped.has(want)) pid = want; }
      else if (S.reaped.size) pid = S.reaped.keys().next().value;
      if (pid >= 0) { const code = S.reaped.get(pid); S.reaped.delete(pid); if (a[1]) S.i32(a[1], (code & 0xff) << 8); return BigInt(pid); }
      const stillRunning = want > 0 ? S.childTasks.has(want) : S.childTasks.size > 0;
      if (!stillRunning) return err(E.CHILD);
      waitSuspends++;
      await new Promise(res => S.waitWaiters.push(res));
    }
  }
  async pollAsync(name, a) {
    const S = this; const nfds = a[1];
    const timeout = name === 'poll' ? (a[2] | 0) : -1;
    const evalReady = () => { S.refresh(); let ready = 0; const waitFifos = []; const waitPtys = []; let waitStdin = false;
      for (let i = 0; i < nfds; i++) {
        const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
        const h = S.fds.get(fd); let re = 0;
        if (h && h.std === 0) { const rdy = stdinChunks.length || stdinEOF; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitStdin = true; }
        else if (h && h.fifo) { const rdy = h.fifo.chunks.length || h.fifo.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.fifo); }
        else if (h && h.spair) { const rdy = h.spair.rd.chunks.length || h.spair.rd.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.spair.rd); }
        else if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; if (ev & 4) re |= 4; }
        else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; if (!q.length) waitPtys.push(h.master ? p.masterWaiters : p.slaveWaiters); }
        else re = ev & 5;
        S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++;
      }
      return { ready, waitFifos, waitPtys, waitStdin };
    };
    for (;;) {
      const r = evalReady();
      if (r.ready > 0) return BigInt(r.ready);
      if (timeout === 0) return 0n;
      const woke = await new Promise(res => { let done = false; const fin = (v) => { if (!done) { done = true; res(v); } };
        for (const f of r.waitFifos) f.readWaiters.push(() => fin(true));
        for (const wl of r.waitPtys) wl.push(() => fin(true));
        if (r.waitStdin) stdinWaiters.push(() => fin(true));
        if (timeout > 0) setTimeout(() => fin(false), timeout);
        else if (!r.waitFifos.length && !r.waitPtys.length && !r.waitStdin) setTimeout(() => fin(false), 50);
      });
      if (timeout > 0 && woke === false) return BigInt(evalReady().ready);
    }
  }

  makeImports(mod) {
    const wali = {}; const extra = {};
    const S = this;
    S._asyncifyCap = WebAssembly.Module.exports(mod).some(e => e.name === 'asyncify_start_unwind'); // real fork() via Asyncify
    const needWasi = WebAssembly.Module.imports(mod).some(i => i.module === 'wasi_snapshot_preview1');
    const wasi = needWasi ? this.makeWasi() : null;
    for (const im of WebAssembly.Module.imports(mod)) {
      if (im.module === 'wasi_snapshot_preview1') {
        (extra.wasi_snapshot_preview1 = extra.wasi_snapshot_preview1 || {})[im.name] =
          wasi[im.name] || ((...a2) => { if (!unknownSyscalls.has('wasi.' + im.name)) { unknownSyscalls.add('wasi.' + im.name); post(`[host] WASI stub ${im.name}\n`, 2); } return 0; });
        continue;
      }
      if (im.module !== 'wali') {
        (extra[im.module] = extra[im.module] || {})[im.name] = () => -38n;
        continue;
      }
      const name = im.name;
      if (name === '__init' || name === '__deinit') wali[name] = () => 0;
      else if (name === '__get_init_envfile') wali[name] = (buf, sz) => {
        if (!S.env.length) return 0;
        addFile(`/.wali_env_${S.pid}`, te.encode(S.env.join('\n') + '\n'));
        S.wstr(buf, `/.wali_env_${S.pid}`, sz); return 1;
      };
      else if (name === '__cl_get_argc') wali[name] = () => S.argv.length;
      else if (name === '__cl_get_argv_len') wali[name] = (i) => te.encode(S.argv[i] || '').length;
      else if (name === '__cl_copy_argv') wali[name] = (buf, i) => S.wstr(buf, S.argv[i] || '', 0);
      else if (name === '__proc_exit') wali[name] = (c) => { throw new ExitError(c); };
      else if (name === 'setjmp' || name === 'sigsetjmp' || name === '_setjmp') wali[name] = () => 0;
      else if (name === 'longjmp' || name === 'siglongjmp' || name === '_longjmp') wali[name] = () => { throw new Error('host-import longjmp (old binary)'); };
      else if (name.startsWith('SYS_')) {
        const sysname = name.slice(4);
        const map = (a2) => a2.map(x => typeof x === 'bigint' && sysname !== 'mmap' ? Number(x) : x);
        if (JSPI && S._asyncifyCap && sysname === 'fork') { // real fork() via Asyncify (returns twice)
          wali[name] = () => {
            S.syscalls++; syscallTotal++;
            if (S.forkState === 'rewinding') { S.inst.exports.asyncify_stop_rewind(); S.forkState = 'none'; return S.forkRet; }
            if (!S.asyncifyBuf) { const old = S.memory.buffer.byteLength; S.memory.grow(ASYNC_PAGES); S.asyncifyBuf = old; S.refresh(); }
            const d = new DataView(S.memory.buffer);
            d.setUint32(S.asyncifyBuf, S.asyncifyBuf + 8, true); d.setUint32(S.asyncifyBuf + 4, S.asyncifyBuf + ASYNC_PAGES * PAGE, true);
            S.inst.exports.asyncify_start_unwind(S.asyncifyBuf); S.forkState = 'unwinding'; return 0n;
          };
        } else if (JSPI && BLOCKING.has(sysname)) { // suspend-capable: yields to the scheduler while blocked
          wali[name] = new WebAssembly.Suspending(async (...a2) => { S.syscalls++; syscallTotal++; return await S.sysAsync(sysname, map(a2)); });
        } else {
          wali[name] = (...a2) => { S.syscalls++; syscallTotal++; return S.sys(sysname, map(a2)); };
        }
      } else wali[name] = () => 0n;
    }
    return { wali, ...extra };
  }

  // ---- WASI preview1 shim (browser): run standard wasm32-wasi binaries,
  //      incl. the eventual clang.wasm, over the in-memory VFS + terminal ----
  makeWasi() {
    const S = this;
    const OK = 0, BADF = 8, NOENT = 44;
    const iovs = (ptr, n) => { const r = []; for (let i = 0; i < n; i++) r.push([S.r32(ptr + i * 8), S.r32(ptr + i * 8 + 4)]); return r; };
    return {
      proc_exit: (code) => { throw new ExitError(code); },
      fd_write: (fd, iptr, icnt, nptr) => { S.refresh(); let tot = 0; const h = S.fds.get(fd);
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue;
          if (h && h.std !== undefined) post(td.decode(S.u8.slice(p, p + l)), h.std === 0 ? 1 : h.std);
          else if (h && h.fifo) h.fifo.chunks.push(S.u8.slice(p, p + l));
          else if (h && h.file) { fileWrite(h.file, h.append ? h.file.size : (h.pos || 0), S.u8.slice(p, p + l)); h.pos = (h.pos || 0) + l; }
          else return BADF;
          tot += l; }
        S.i32(nptr, tot); return OK; },
      fd_read: (fd, iptr, icnt, nptr) => { S.refresh(); let tot = 0; const h = S.fds.get(fd);
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue; let b;
          if (fd === 0 || (h && h.std === 0)) b = readStdin(l);
          else if (h && h.fifo) b = pipeRead(h.fifo, l);
          else if (h && h.file) { b = fileRead(h.file, h.pos || 0, l); h.pos = (h.pos || 0) + b.length; }
          else return BADF;
          S.wbytes(p, b); tot += b.length; if (b.length < l) break; }
        S.i32(nptr, tot); return OK; },
      fd_close: (fd) => { S.fds.delete(fd); return OK; },
      fd_seek: (fd, off, whence, nptr) => { const h = S.fds.get(fd); if (!h || !h.file) return BADF;
        const size = h.file.size; h.pos = whence === 0 ? Number(off) : whence === 1 ? (h.pos || 0) + Number(off) : size + Number(off);
        S.dv.setBigInt64(nptr, BigInt(h.pos), true); return OK; },
      fd_fdstat_get: (fd, ptr) => { S.refresh(); S.u8.fill(0, ptr, ptr + 24); const h = S.fds.get(fd); S.u8[ptr] = (h && h.std !== undefined) ? 2 : 4; return OK; },
      fd_prestat_get: (fd, ptr) => { const h = S.fds.get(fd); if (h && h.preopen) { S.u8[ptr] = 0; S.i32(ptr + 4, h.preopen.length); return OK; } return BADF; },
      fd_prestat_dir_name: (fd, ptr, len) => { const h = S.fds.get(fd); if (!h || !h.preopen) return BADF; S.wbytes(ptr, te.encode(h.preopen).subarray(0, len)); return OK; },
      path_open: (dirfd, df, pptr, plen, oflags, r1, r2, fdflags, fdptr) => {
        const name = td.decode(S.u8.slice(pptr, pptr + plen));
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p;
        const g = S.openAt(norm(name, base), (oflags & 1) ? 0o1101 : 0, 0o644);
        if (g < 0n) return NOENT; S.i32(fdptr, Number(g)); return OK; },
      environ_sizes_get: (cptr, sptr) => { S.i32(cptr, S.env.length); S.i32(sptr, S.env.reduce((a, e) => a + te.encode(e).length + 1, 0)); return OK; },
      environ_get: (eptr, bptr) => { let b = bptr; for (const e of S.env) { S.i32(eptr, b); eptr += 4; b += S.wstr(b, e, 0) + 1; } return OK; },
      args_sizes_get: (cptr, sptr) => { S.i32(cptr, S.argv.length); S.i32(sptr, S.argv.reduce((a, e) => a + te.encode(e).length + 1, 0)); return OK; },
      args_get: (aptr, bptr) => { let b = bptr; for (const a of S.argv) { S.i32(aptr, b); aptr += 4; b += S.wstr(b, a, 0) + 1; } return OK; },
      clock_time_get: (id, prec, ptr) => { S.dv.setBigInt64(ptr, BigInt(Date.now()) * 1000000n, true); return OK; },
      random_get: (ptr, len) => { const b = new Uint8Array(len); crypto.getRandomValues(b); S.wbytes(ptr, b); return OK; },
      fd_fdstat_set_flags: () => OK, fd_sync: () => OK, fd_datasync: () => OK, sched_yield: () => OK, poll_oneoff: () => OK,
    };
  }

  run() {
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); return 127; }
    const inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = inst.exports.memory; this.membuf = null; this.refresh();
    try { inst.exports._start(); return 0; }
    catch (e) {
      if (e instanceof ExitError) return e.code & 0xff;
      post(`[host] trap in pid ${this.pid}: ${e.stack || e}\n`, 2);
      return 139;
    }
  }

  // JSPI: run _start as a promising export so its blocking syscalls can suspend
  async runAsync() {
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); return 127; }
    this.inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = this.inst.exports.memory; this.membuf = null; this.refresh();
    return this._drive(false);
  }

  async _drive(rewind) {
    const start = WebAssembly.promising(this.inst.exports._start);
    if (rewind) this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    for (;;) {
      try { await start(); }
      catch (e) { if (e instanceof ExitError) return e.code & 0xff; post(`[host] trap in pid ${this.pid}: ${e.stack || e}\n`, 2); return 139; }
      if (this.forkState !== 'unwinding') return 0;
      this.inst.exports.asyncify_stop_unwind();
      const childPid = nextPid++;
      const child = this.spawnForkChild(childPid);
      const ctask = child._drive(true).then((code) => { releaseFds(child.fds); this.reaped.set(childPid, code); this.childTasks.delete(childPid); wakeWaiters(this); });
      inflight.add(ctask); ctask.finally(() => inflight.delete(ctask));
      this.childTasks.set(childPid, ctask);
      this.forkRet = BigInt(childPid); this.forkState = 'rewinding';
      this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    }
  }

  spawnForkChild(childPid) {
    const mod = modCache.get(this.modKey);
    const child = new Process(this.modKey, this.argv, this.env, new Map(), this.cwd.p);
    child.pid = childPid;
    child.fds = new Map([...this.fds].map(([k, v]) => [k, { ...v, shared: true }]));
    for (const v of child.fds.values()) child.bumpFifo(v);
    child.heapBrk = this.heapBrk; child.ctty = this.ctty;
    child.inst = new WebAssembly.Instance(mod, child.makeImports(mod));
    child.memory = child.inst.exports.memory; child.membuf = null; child.refresh();
    const need = this.memory.buffer.byteLength - child.memory.buffer.byteLength;
    if (need > 0) child.memory.grow(Math.ceil(need / PAGE));
    // fork = copy the parent's linear memory (this IS the stack, which is why JSPI alone
    // can't fork). The memory is mostly live (heap brk + stack), so .set() — an optimal
    // memcpy — is the floor. The only always-safe reduction is skipping a trailing run of
    // zero pages: the child's fresh memory is already zero there. (Measured on sshd: ~10MB
    // copied in ~10ms/fork; internal pages are live so a sparse copy would cost a full scan.)
    const src = new Uint8Array(this.memory.buffer), P = 65536;
    let hw = 0;
    for (let a = Math.floor((src.length - 1) / P) * P; a >= 0; a -= P) {
      let nz = false; const end = Math.min(a + P, src.length);
      for (let b = a; b < end; b++) if (src[b]) { nz = true; break; }
      if (nz) { hw = end; break; }
    }
    new Uint8Array(child.memory.buffer).set(src.subarray(0, hw)); // [hw, end) already zero in child
    child.membuf = null; child.refresh();
    child.asyncifyBuf = this.asyncifyBuf; child.forkState = 'rewinding'; child.forkRet = 0n;
    return child;
  }
}

function runProgram(p, argv, envp, fdTable, cwd, selfKey) {
  let key = resolveModuleKey(p, selfKey);
  if (!key) {
    // not in the manifest — maybe it's a wasm binary sitting in the VFS
    // (e.g. one microcc just emitted). Compile it from its bytes and run.
    const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
    const f = files.get(vp);
    if (f) {
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) {
        key = 'vfs:' + vp;
        if (!modCache.has(key)) modCache.set(key, new WebAssembly.Module(bytes.slice()));
      }
    }
  }
  if (!key || !modCache.has(key)) { post(`[host] execve: cannot resolve ${p}\n`, 2); return null; }
  const proc = new Process(key, argv, envp, fdTable, cwd);
  return proc.run();
}

// JSPI variant: run the child concurrently (its blocking syscalls suspend, not stall)
async function runProgramAsync(p, argv, envp, fdTable, cwd, selfKey) {
  let key = resolveModuleKey(p, selfKey);
  if (!key) {
    const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
    const f = files.get(vp);
    if (f) {
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) {
        key = 'vfs:' + vp;
        if (!modCache.has(key)) modCache.set(key, new WebAssembly.Module(bytes.slice()));
      }
    }
  }
  if (!key || !modCache.has(key)) { post(`[host] execve: cannot resolve ${p}\n`, 2); return null; }
  const proc = new Process(key, argv, envp, fdTable, cwd);
  return await proc.runAsync();
}

// ================= entry =================
self.onmessage = async (ev) => {
  const m = ev.data;
  if (m.t === 'stdin-sab') { stdinCtl = new Int32Array(m.sab, 0, 4); stdinData = new Uint8Array(m.sab, 16); return; }
  if (m.t === 'wisp-sab') { wispSab = m.sab; return; }
  if (m.t === 'opfs-sab') { opfsSab = m.sab; return; }
  if (m.t === 'winsize') { if (m.rows) winRows = m.rows; if (m.cols) winCols = m.cols; for (const p of ptys.values()) { p.rows = winRows; p.cols = winCols; } return; }
  if (m.t === 'stdin') { pushStdin(typeof m.data === 'string' ? te.encode(m.data) : new Uint8Array(m.data)); return; } // async stdin (JSPI)
  if (m.t === 'stdin-eof') { stdinEOF = true; const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); return; }
  if (m.t !== 'run') return;
  try {
    const boot0 = performance.now();
    for (const [url, prefix] of m.tars || []) await loadTar(url, prefix);
    if (m.opfs) {
      opfsMount = norm(m.opfs, '/'); mkdirp(opfsMount);
      post(opfsSab ? `[host] OPFS lazily mounted at ${opfsMount}\n` : `[host] OPFS requested but no opfs-sab bridge; ${opfsMount} is RAM-only\n`, 2);
    }
    manifest = m.manifest || {};
    addFile('/etc/resolv.conf', te.encode('nameserver 1.1.1.1\n')); // DNS goes via DoH in the WISP worker
    addFile('/etc/hosts', te.encode('127.0.0.1 localhost\n'));
    // seed VFS with inline binaries (e.g. wasm just produced by clang.wasm)
    if (m.blobs) for (const [p, buf] of Object.entries(m.blobs)) addFile(norm(p, '/'), new Uint8Array(buf));
    // compile URL-based modules (root + manifest); skip when running a VFS binary
    for (const key of new Set([m.vfsMain ? null : m.wasm, ...Object.values(manifest)])) {
      if (key && !modCache.has(key)) modCache.set(key, await WebAssembly.compileStreaming(fetch(key)));
    }
    let rootKey = m.wasm;
    if (m.vfsMain) { // run a wasm sitting in the VFS as the root process
      const vp = norm(m.vfsMain, '/'); const f = files.get(vp);
      if (!f) throw new Error('vfsMain not found: ' + vp);
      rootKey = 'vfs:' + vp;
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (!modCache.has(rootKey)) modCache.set(rootKey, new WebAssembly.Module(bytes.slice()));
    }
    const rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
    const env = Object.entries(m.env || {}).map(([k, v]) => k + '=' + v);
    nextPid = 100; syscallTotal = 0; procCount = 0; stdinChunks = []; stdinEOF = false; stdinWaiters = [];
    JSPI = !!m.jspi && jspiAvailable;
    if (m.jspi && !jspiAvailable) post('[host] jspi requested but unavailable in this browser; using synchronous model\n', 2);
    pipeSuspends = 0; waitSuspends = 0;
    const root = new Process(rootKey, m.argv, env, rootFds, m.cwd || '/');
    self.postMessage({ t: 'boot', ms: performance.now() - boot0 });
    const t0 = performance.now();
    const code = JSPI ? await root.runAsync() : root.run();
    if (opfsBr) { try { opfsBr.call(OFS.RELEASE, 0, 0, 0, null); } catch {} for (const f of files.values()) if (f.brId) f.brId = 0; }
    self.postMessage({ t: 'exit', code, ms: performance.now() - t0, syscalls: syscallTotal, procs: procCount, jspi: JSPI, pipeSuspends, waitSuspends });
  } catch (e) {
    post('[host] fatal: ' + (e.stack || e) + '\n', 2);
    self.postMessage({ t: 'exit', code: 127, ms: 0, syscalls: syscallTotal, procs: procCount });
  }
};
