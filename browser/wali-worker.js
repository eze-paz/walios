// WALI browser syscall host v2 — process model edition.
// vfork/execve/wait4/pipes on top of the in-memory VFS + OPFS mount.
// Child branch runs in-place under an fd overlay (vfork semantics, guest
// longjmps back via wasm-EH SJLJ); wait4 runs parked children synchronously.
'use strict';

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
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
    const type = String.fromCharCode(hdr[156] || 48);
    off += 512;
    if (type === '0' || type === '\0') addFile(norm(prefix + '/' + name, '/'), buf.slice(off, off + size));
    else if (type === '5') mkdirp(norm(prefix + '/' + name, '/'));
    off += Math.ceil(size / 512) * 512;
  }
}
async function mountOpfs(mount) {
  try {
    const root = await navigator.storage.getDirectory();
    try {
      const fh = await root.getFileHandle('hello-from-opfs.txt', { create: true });
      const sh = await fh.createSyncAccessHandle();
      if (sh.getSize() === 0) sh.write(te.encode('greetings from real OPFS storage\n'), { at: 0 });
      sh.close();
    } catch {}
    let n = 0;
    async function walk(dirHandle, vpath) {
      mkdirp(vpath);
      for await (const [name, h] of dirHandle.entries()) {
        const child = vpath + '/' + name;
        if (h.kind === 'directory') await walk(h, child);
        else {
          try {
            const sh = await h.createSyncAccessHandle();
            const parent = child.slice(0, child.lastIndexOf('/')) || '/';
            mkdirp(parent); dirs.get(parent).add(name);
            files.set(child, { opfs: sh, size: sh.getSize(), mode: 0o100644, mtimeMs: Date.now(), data: null });
            n++;
          } catch (e) { post(`[opfs] skip ${child}: ${e.message}\n`, 2); }
        }
      }
    }
    await walk(root, mount);
    return n;
  } catch (e) { post(`[opfs] mount failed: ${e.message}\n`, 2); return -1; }
}
function fileRead(f, pos, n) {
  if (f.opfs) { const b = new Uint8Array(Math.min(n, Math.max(0, f.size - pos))); f.opfs.read(b, { at: pos }); return b; }
  return f.data.subarray(pos, Math.min(pos + n, f.size));
}
function fileWrite(f, pos, bytes) {
  if (f.opfs) { f.opfs.write(bytes, { at: pos }); f.size = Math.max(f.size, pos + bytes.length); return bytes.length; }
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
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'nanosleep', 'clock_nanosleep']);
const inflight = new Set();   // live child task promises
let pipeSuspends = 0, waitSuspends = 0; // JSPI concurrency evidence
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
function newPty() { const id = nextPtyId++; ptys.set(id, { toSlave: [], toMaster: [], line: [], termios: defaultTermios(), rows: 24, cols: 80, pgrp: 0 }); return id; }
const tflag = (p, off) => new DataView(p.termios.buffer).getUint32(off, true);
function ptyMasterWrite(p, bytes) { const lf = tflag(p, 12), canon = lf & ICANON, echo = lf & ECHO, icrnl = tflag(p, 0) & ICRNL;
  for (let c of bytes) { if (canon) {
      if (c === 0x7f || c === 0x08) { if (p.line.length) { p.line.pop(); if (echo) p.toMaster.push(8, 32, 8); } continue; }
      if (c === 0x0d && icrnl) c = 0x0a; p.line.push(c); if (echo) p.toMaster.push(c);
      if (c === 0x0a) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
    } else { p.toSlave.push(c); if (echo) p.toMaster.push(c); } } }
function ptySlaveWrite(p, bytes) { const of = tflag(p, 4), onlcr = (of & OPOST) && (of & ONLCR);
  for (const c of bytes) { if (onlcr && c === 0x0a) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); } }

// writers/readers are refcounts (bumped on fork/dup of an end, dropped on close);
// in JSPI mode a reader on an empty pipe suspends until a write wakes it or the
// last writer closes (writers==0 => EOF). readWaiters holds suspend resolvers.
function mkPipe() { return { chunks: [], writers: 1, readers: 1, readWaiters: [] }; }
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
function releaseFds(fdMap) { for (const h of fdMap.values()) { if (h && h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; } } }
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
    this.syscalls = 0;
  }
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
    this.i64(p, 1n); this.i64(p + 8, 1n); this.i64(p + 16, 1n);
    this.i32(p + 24, o.mode); this.i32(p + 28, 1000); this.i32(p + 32, 1000);
    this.i64(p + 48, BigInt(o.size)); this.i64(p + 56, 4096n); this.i64(p + 64, BigInt(Math.ceil(o.size / 512)));
    const t = (off, ms) => { this.i64(p + off, BigInt(Math.floor(ms / 1000))); this.i64(p + off + 8, BigInt(Math.floor((ms % 1000) * 1e6))); };
    t(72, o.mtimeMs || Date.now()); t(88, o.mtimeMs || Date.now()); t(104, o.mtimeMs || Date.now());
  }
  statPath(path2, sp) {
    if (path2 === '/proc/self/exe') { this.putStat(sp, { size: 1, mode: 0o100755 }); return 0n; }
    if (dirs.has(path2)) { this.putStat(sp, { size: 4096, mode: 0o040755 }); return 0n; }
    const f = files.get(path2); if (!f) return err(E.NOENT);
    this.putStat(sp, { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs });
    return 0n;
  }
  openAt(path2, flags, mode) {
    const O_CREAT = 0o100, O_TRUNC = 0o1000, O_APPEND = 0o2000, O_DIRECTORY = 0o200000, O_EXCL = 0o200;
    if (path2 === '/proc/self/exe') { const g = this.nextFd++; this.fds.set(g, { exe: true }); return BigInt(g); }
    if (path2 === '/dev/ptmx') { const id = newPty(); const g = this.nextFd++; this.fds.set(g, { pty: id, master: true }); return BigInt(g); }
    if (path2 === '/dev/null') { const g = this.nextFd++; this.fds.set(g, { devnull: true }); return BigInt(g); }
    { const m = path2.match(/^\/dev\/pts\/(\d+)$/); if (m) { const id = +m[1]; if (!ptys.has(id)) return err(E.NOENT); const g = this.nextFd++; this.fds.set(g, { pty: id, master: false }); return BigInt(g); } }
    if (dirs.has(path2)) { const g = this.nextFd++; this.fds.set(g, { path: path2, dir: true }); return BigInt(g); }
    if (flags & O_DIRECTORY) return err(E.NOTDIR);
    let f = files.get(path2);
    if (!f) {
      if (!(flags & O_CREAT)) return err(E.NOENT);
      addFile(path2, new Uint8Array(0));
      f = files.get(path2);
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) return err(E.EXIST);
    if (flags & O_TRUNC) { if (f.opfs) f.opfs.truncate(0); else f.data = new Uint8Array(0); f.size = 0; }
    const g = this.nextFd++;
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
        if (h.std !== undefined) { if (h.std !== 0) return err(E.BADF); const b = readStdin(a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.fifo) { const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
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
        if (h.sock && h.sock.id) initWisp().call(initWisp().OP.CLOSE, h.sock.id, 0, 0);
        S.fds.delete(a[0]); S.dirState.delete(a[0]); return 0n; }
      case 'lseek': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock || h.pty !== undefined || h.devnull) return err(E.SPIPE);
        const size = h.file ? h.file.size : 0;
        h.pos = a[2] === 0 ? Number(a[1]) : a[2] === 1 ? (h.pos || 0) + Number(a[1]) : size + Number(a[1]);
        return BigInt(h.pos); }
      case 'fstat': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.pty !== undefined || h.devnull) { S.putStat(a[1], { size: 0, mode: 0o020620 }); return 0n; }
        if (h.std !== undefined || h.fifo || h.sock) { S.putStat(a[1], { size: 0, mode: (h.fifo || h.sock) ? 0o010600 : 0o020620 }); return 0n; }
        if (h.exe) { S.putStat(a[1], { size: 1, mode: 0o100755 }); return 0n; }
        return S.statPath(h.path, a[1]); }
      case 'stat': case 'lstat': return S.statPath(S.atPath(-100, S.cstr(a[0])), a[1]);
      case 'newfstatat': { const s = S.cstr(a[1]); return s === '' ? S.sys('fstat', [a[0], a[2]]) : S.statPath(S.atPath(a[0], s), a[2]); }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        return (files.has(p) || dirs.has(p)) ? 0n : err(E.NOENT); }
      case 'readlink': { const p = S.atPath(-100, S.cstr(a[0]));
        if (p === '/proc/self/exe') return BigInt(S.wstr(a[1], '/bin/' + (S.argv[0] || 'wasm'), a[2] + 1));
        return err(E.INVAL); }
      case 'unlink': { const p = S.atPath(-100, S.cstr(a[0])); if (!files.has(p)) return err(E.NOENT);
        const f = files.get(p); if (f.opfs) { f.opfs.truncate(0); f.opfs.close(); } rmEntry(p); return 0n; }
      case 'rmdir': { const p = S.atPath(-100, S.cstr(a[0])); if (!dirs.has(p)) return err(E.NOENT);
        if (dirs.get(p).size) return err(E.NOTEMPTY); rmEntry(p); return 0n; }
      case 'mkdir': { mkdirp(S.atPath(-100, S.cstr(a[0]))); return 0n; }
      case 'rename': { const pa = S.atPath(-100, S.cstr(a[0])), pb = S.atPath(-100, S.cstr(a[1]));
        const f = files.get(pa); if (!f) return err(E.NOENT); rmEntry(pb); rmEntry(pa);
        addFile(pb, f.data || new Uint8Array(0)); const nf = files.get(pb);
        if (f.opfs) nf.opfs = f.opfs; nf.size = f.size; return 0n; }
      case 'chdir': { const p = S.atPath(-100, S.cstr(a[0])); if (!dirs.has(p)) return err(E.NOTDIR); S.cwd.p = p; return 0n; }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1);
      case 'chmod': case 'fchmod': case 'chown': return 0n;
      case 'umask': return 0o22n;
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); const g = S.nextFd++; S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[0] !== a[1]) { const old = S.fds.get(a[1]); if (old && old.fifo) { if (old.end === 'w') { if (--old.fifo.writers <= 0) wakePipe(old.fifo); } else old.fifo.readers--; } // dup2 closes target first
          S.fds.set(a[1], { ...h }); S.bumpFifo(h); } return BigInt(a[1]); }
      case 'pipe': case 'pipe2': {
        const fifo = mkPipe();
        const r = S.nextFd++, w = S.nextFd++;
        S.fds.set(r, { fifo, end: 'r' }); S.fds.set(w, { fifo, end: 'w' });
        S.i32(a[0], r); S.i32(a[0] + 4, w); return 0n; }

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
            case 0x40045441: { const g = S.nextFd++; S.fds.set(g, { pty: h.pty, master: false }); return BigInt(g); }
            default: return 0n;
          } }
        if (h.std === undefined) return err(E.NOTTY);
        if (req === 0x5413) { S.dv.setUint16(a[2], 24, true); S.dv.setUint16(a[2] + 2, 80, true); S.i32(a[2] + 4, 0); }
        if (req === 0x5401) S.wbytes(a[2], defaultTermios());
        return 0n; }
      case 'fcntl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[1] === 0 || a[1] === 1030) {
          const min = Number(a[2]) || 0;
          let g = Math.max(S.nextFd, min); while (S.fds.has(g)) g++;
          S.nextFd = Math.max(S.nextFd, g + 1);
          S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g);
        }
        if (a[1] === 3) return 2n; return 0n; }
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const ms = performance.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt(Math.floor((ms % 1000) * 1e6))); return 0n; }
        const ms = Date.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt((ms % 1000) * 1e6)); return 0n; }
      case 'gettimeofday': { const ms = Date.now(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt((ms % 1000) * 1000)); return 0n; }
      case 'nanosleep': case 'clock_nanosleep': return 0n;
      case 'uname': { ['Linux', 'wali', '6.1.0-wali', '#1 WALI-browser', 'wasm32', ''].forEach((s, i) => S.wstr(a[0] + i * 65, s, 65)); return 0n; }
      case 'getuid': case 'geteuid': case 'getgid': case 'getegid': return 1000n;
      case 'setuid': case 'setgid': case 'setreuid': case 'setregid': case 'setresuid': case 'setresgid': case 'getgroups': return 0n;
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
        if (type === 2) { const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.nextFd++; S.fds.set(g, { sock: { id: r.res, udp: true, nonblock } }); return BigInt(g); }
        const g = S.nextFd++; S.fds.set(g, { sock: { id: 0, dom, nonblock } }); return BigInt(g); }
      case 'bind': return 0n;
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF); S.refresh();
        const dst = readSockaddr(S, a[1]);
        if (h.sock.udp) { h.sock.dest = dst; return 0n; }
        const br = initWisp(); const spec = te.encode(`${dst.ip}|${dst.port}`);
        const r = br.call(br.OP.CONNECT, spec.length, 0, 0, spec); if (r.res < 0) return BigInt(r.res); h.sock.id = r.res; return 0n; }
      case 'sendto': case 'sendmsg': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
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
      case 'recvmsg': case 'recvfrom': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
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

  bumpFifo(h) { if (h && h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') h.fifo.readers++; } }

  // ---- JSPI: async syscall path (only the blocking ones; the rest delegate to sys) ----
  async sysAsync(name, a) {
    const S = this;
    switch (name) {
      case 'read': case 'readv': {
        const h = S.fds.get(a[0]);
        if (h && h.fifo) { while (!h.fifo.chunks.length && h.fifo.writers > 0) { pipeSuspends++; await new Promise(res => h.fifo.readWaiters.push(res)); } return S.sys(name, a); }
        return S.sys(name, a);
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
    const evalReady = () => { S.refresh(); let ready = 0; const waitFifos = [];
      for (let i = 0; i < nfds; i++) {
        const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
        const h = S.fds.get(fd); let re = 0;
        if (h && h.fifo) { const rdy = h.fifo.chunks.length || h.fifo.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.fifo); }
        else if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; if (ev & 4) re |= 4; }
        else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; }
        else re = ev & 5;
        S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++;
      }
      return { ready, waitFifos };
    };
    for (;;) {
      const r = evalReady();
      if (r.ready > 0) return BigInt(r.ready);
      if (timeout === 0) return 0n;
      const woke = await new Promise(res => { let done = false; const fin = (v) => { if (!done) { done = true; res(v); } };
        for (const f of r.waitFifos) f.readWaiters.push(() => fin(true));
        if (timeout > 0) setTimeout(() => fin(false), timeout);
        else if (!r.waitFifos.length) setTimeout(() => fin(false), 50);
      });
      if (timeout > 0 && woke === false) return BigInt(evalReady().ready);
    }
  }

  makeImports(mod) {
    const wali = {}; const extra = {};
    const S = this;
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
        if (JSPI && BLOCKING.has(sysname)) { // suspend-capable: yields to the scheduler while blocked
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
    const inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = inst.exports.memory; this.membuf = null; this.refresh();
    const start = WebAssembly.promising(inst.exports._start);
    try { await start(); return 0; }
    catch (e) {
      if (e instanceof ExitError) return e.code & 0xff;
      post(`[host] trap in pid ${this.pid}: ${e.stack || e}\n`, 2);
      return 139;
    }
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
      const bytes = f.opfs ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
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
      const bytes = f.opfs ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
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
  if (m.t !== 'run') return;
  try {
    const boot0 = performance.now();
    for (const [url, prefix] of m.tars || []) await loadTar(url, prefix);
    if (m.opfs) { const n = await mountOpfs(m.opfs); if (n >= 0) post(`[host] OPFS mounted at ${m.opfs}: ${n} files\n`, 2); }
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
      const bytes = f.opfs ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (!modCache.has(rootKey)) modCache.set(rootKey, new WebAssembly.Module(bytes.slice()));
    }
    const rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
    const env = Object.entries(m.env || {}).map(([k, v]) => k + '=' + v);
    nextPid = 100; syscallTotal = 0; procCount = 0;
    JSPI = !!m.jspi && jspiAvailable;
    if (m.jspi && !jspiAvailable) post('[host] jspi requested but unavailable in this browser; using synchronous model\n', 2);
    pipeSuspends = 0; waitSuspends = 0;
    const root = new Process(rootKey, m.argv, env, rootFds, m.cwd || '/');
    self.postMessage({ t: 'boot', ms: performance.now() - boot0 });
    const t0 = performance.now();
    const code = JSPI ? await root.runAsync() : root.run();
    for (const f of files.values()) if (f.opfs) { try { f.opfs.flush(); } catch {} }
    self.postMessage({ t: 'exit', code, ms: performance.now() - t0, syscalls: syscallTotal, procs: procCount, jspi: JSPI, pipeSuspends, waitSuspends });
  } catch (e) {
    post('[host] fatal: ' + (e.stack || e) + '\n', 2);
    self.postMessage({ t: 'exit', code: 127, ms: 0, syscalls: syscallTotal, procs: procCount });
  }
};
