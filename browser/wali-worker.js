// WALI browser syscall host v2 — process model edition.
// vfork/execve/wait4/pipes on top of the in-memory VFS + OPFS mount.
// Child branch runs in-place under an fd overlay (vfork semantics, guest
// longjmps back via wasm-EH SJLJ); wait4 runs parked children synchronously.
'use strict';

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
try { self.addEventListener('unhandledrejection', (e) => { try { self.postMessage({ t: 'out', fd: 2, s: '[host] UNHANDLED: ' + ((e.reason && e.reason.stack) || e.reason) + '\n' }); } catch {} }); } catch {}
const E = { PERM:1, NOENT:2, SRCH:3, INTR:4, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, EXIST:17, NOTDIR:20, ISDIR:21, INVAL:22, NOTTY:25, SPIPE:29, PIPE:32, NOSYS:38, NOTEMPTY:39 };
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
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'nanosleep', 'clock_nanosleep', 'execve', 'recvmsg', 'recvfrom', 'pause', 'sigsuspend', 'rt_sigsuspend', 'accept', 'accept4']);
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
let termPty = null; // pty-terminal mode: the root shell runs on this pty; master <-> page
function pumpTerm(p) { // flush a terminal pty's master-side bytes to the page (screen)
  if (termPty === null || ptys.get(termPty) !== p || !p.toMaster.length) return;
  self.postMessage({ t: 'out', fd: 1, s: td.decode(Uint8Array.from(p.toMaster)) }); p.toMaster.length = 0;
}
function ptyMasterWrite(p, bytes) { const lf = tflag(p, 12), canon = lf & ICANON, echo = lf & ECHO, icrnl = tflag(p, 0) & ICRNL;
  const isig = lf & ISIG;
  for (let c of bytes) {
    if (isig && c && (c === p.termios[17] || c === p.termios[18])) { // VINTR (^C) / VQUIT
      const sig = c === p.termios[17] ? SIG.INT : SIG.QUIT;
      p.line = [];
      if (echo) p.toMaster.push(94, 64 + (c & 31)); // echo ^C / ^\
      if (p.pgrp) signalPgrp(p.pgrp, sig);
      else if (p.fg) postSignal(p.fg, sig);
      continue;
    }
    if (canon) {
      if (c === 0x7f || c === 0x08) { if (p.line.length) { p.line.pop(); if (echo) p.toMaster.push(8, 32, 8); } continue; }
      if (c === 0x0d && icrnl) c = 0x0a; p.line.push(c); if (echo) p.toMaster.push(c);
      if (c === 0x0a) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
    } else { p.toSlave.push(c); if (echo) p.toMaster.push(c); } }
  if (p.toSlave.length) wakePty(p.slaveWaiters); if (p.toMaster.length) wakePty(p.masterWaiters); pumpTerm(p); }
function ptySlaveWrite(p, bytes) { const of = tflag(p, 4), onlcr = (of & OPOST) && (of & ONLCR);
  for (const c of bytes) { if (onlcr && c === 0x0a) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); }
  if (p.toMaster.length) wakePty(p.masterWaiters); pumpTerm(p); }

// writers/readers are refcounts (bumped on fork/dup of an end, dropped on close);
// in JSPI mode a reader on an empty pipe suspends until a write wakes it or the
// last writer closes (writers==0 => EOF). readWaiters holds suspend resolvers.
function mkPipe() { return { chunks: [], writers: 1, readers: 1, readWaiters: [] }; }
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
function releaseFds(fdMap) { for (const h of fdMap.values()) {
  if (h && h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; }
  else if (h && h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; } } }
function wakeWaiters(S) { if (S.waitWaiters.length) { const w = S.waitWaiters; S.waitWaiters = []; for (const f of w) f(); } }

// ---- signals (mirror of the node host): per-process handlers/mask/pending;
// delivery at syscall boundaries; handlers invoked via the exported function
// table (--export-table --table-base=16), else default action. ----
const SIG = { HUP:1, INT:2, QUIT:3, ILL:4, ABRT:6, KILL:9, USR1:10, SEGV:11, USR2:12, PIPE:13, ALRM:14, TERM:15, CHLD:17, CONT:18, STOP:19, TSTP:20, TTIN:21, TTOU:22, URG:23, WINCH:28 };
const SIG_DFL_IGNORE = new Set([SIG.CHLD, SIG.CONT, SIG.URG, SIG.WINCH]);
const SIG_STOPPERS = new Set([SIG.STOP, SIG.TSTP, SIG.TTIN, SIG.TTOU]);
// SysV shared memory: host-side buffers, snapshot in/out at attach/detach (see node host)
const shmSegs = new Map(), shmById = new Map(); let nextShmId = 1;
const QUANTUM_MS = 10;               // JSPI preemption: max run between event-loop yields
const procs = new Map();             // live pid -> Process (kill routing)
let rootProc = null;                 // tree root (fallback Ctrl-C target)
function postSignal(P, sig) {
  if (!P || !sig) return;
  if (sig === SIG.CONT) { for (const st of SIG_STOPPERS) P.sig.pending.delete(st); // POSIX: CONT discards pending stops
    if (P.stopped) { P.stopped = 0; const c = P.contWaiters; P.contWaiters = []; for (const f of c) f(); } }
  if (SIG_STOPPERS.has(sig)) P.sig.pending.delete(SIG.CONT);   // and a stop discards a pending CONT
  const h = P.sig.handlers.get(sig);
  if (h && (h.ptr === -2 || h.ptr === 1) && sig !== SIG.KILL) return; // SIG_IGN (this musl: -2; classic ABI: 1)
  if ((!h || !h.ptr) && SIG_DFL_IGNORE.has(sig)) return;       // default-ignore
  P.sig.pending.add(sig);
  const w = P.sig.waiters; P.sig.waiters = []; for (const f of w) f('sig');
}
function signalPgrp(pgid, sig) { let n = 0; for (const P of procs.values()) if (P.pgid === pgid) { postSignal(P, sig); n++; } return n; }
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
    return { res: ctl[6], aux: ctl[7], data: wdata };
  };
  wisp = { call, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, LISTEN: 10, ACCEPT: 11, PING: 9, PINGPOLL: 12 } };
  return wisp;
}
function readSockaddr(S, p) { S.refresh();
  const fam = S.dv.getUint16(p, true), port = S.dv.getUint16(p + 2, false); let ip;
  if (fam === 10) { const g = []; for (let i = 0; i < 16; i += 2) g.push(S.dv.getUint16(p + 8 + i, false).toString(16)); ip = g.join(':'); }
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
    this.pgid = this.pid;
    this.sig = { handlers: new Map(), mask: 0n, pending: new Set(), waiters: [] };
    this.timers = new Map();         // which(0=ITIMER_REAL) -> {deadline, intervalMs, to}
    this.lastYield = 0;
    this.stopped = 0; this.stopReported = false; this.contWaiters = [];
    this.cred = { uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0, groups: [] }; // root by default
    this.shmAt = new Map();          // SysV shm attachments: base -> segment
    this.umask = 0o22;
    procs.set(this.pid, this);
  }
  retire() {
    procs.delete(this.pid);
    for (const t of this.timers.values()) if (t.to) clearTimeout(t.to);
    this.timers.clear();
    const w = this.sig.waiters; this.sig.waiters = []; for (const f of w) f('sig');
  }
  pollTimers() {
    if (!this.timers.size) return;
    const now = Date.now();
    for (const [which, t] of this.timers) {
      if (t.deadline && now >= t.deadline) {
        if (t.intervalMs > 0) t.deadline = now + t.intervalMs; else this.timers.delete(which);
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
    if (JSPI) {
      const fire = () => { postSignal(this, SIG.ALRM);
        if (t.intervalMs > 0) { t.deadline = Date.now() + t.intervalMs; t.to = setTimeout(fire, t.intervalMs); }
        else this.timers.delete(which); };
      t.to = setTimeout(fire, valueMs);
    }
    this.timers.set(which, t);
  }
  predeliver() {
    if (!this.sig.pending.size) return null;
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && (h.ptr === -2 || h.ptr === 1)) continue;      // SIG_IGN
      if (h && h.ptr > 1 && sig !== SIG.KILL) {
        const table = this.inst && this.inst.exports.__indirect_function_table;
        if (table) {
          try { table.get(h.ptr)(sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false; // !SA_RESTART
            continue; }
          catch (e) { post(`[host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`, 2); }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          post(`[host] pid ${this.pid}: signal handler set but binary lacks --export-table; default action\n`, 2); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;
      if (SIG_STOPPERS.has(sig)) {                           // job control: park until SIGCONT
        if (JSPI && !this.inChild()) { this.stopped = sig; this.stopReported = false; }
        continue;
      }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);
    }
    return null;
  }
  // Async delivery (JSPI): run the handler via WebAssembly.promising so a handler
  // that makes a syscall can suspend. Calling table.get(ptr)(sig) directly re-enters
  // wasm outside a promising execution, where any Suspending import (every syscall)
  // throws "trying to suspend without WebAssembly.promising" — even non-blocking.
  // Nested promising establishes a suspender for the handler (verified). This is
  // what makes busybox ping (SIGALRM handler -> sendto) work.
  async predeliverAsync() {
    if (!this.sig.pending.size) return null;
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && (h.ptr === -2 || h.ptr === 1)) continue;      // SIG_IGN
      if (h && h.ptr > 1 && sig !== SIG.KILL) {
        const table = this.inst && this.inst.exports.__indirect_function_table;
        if (table) {
          const savedMask = this.sig.mask;
          this.sig.mask |= (1n << BigInt(sig - 1)) | BigInt(h.mask || 0n); // POSIX: block this signal (+ sa_mask) during its handler
          try { await WebAssembly.promising(table.get(h.ptr))(sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false;
            continue; }
          catch (e) { if (e instanceof ExitError) throw e;   // a real exit from the handler must propagate
            post(`[host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`, 2); }
          finally { this.sig.mask = savedMask; }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          post(`[host] pid ${this.pid}: signal handler set but binary lacks --export-table; default action\n`, 2); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;
      if (SIG_STOPPERS.has(sig)) { if (JSPI && !this.inChild()) { this.stopped = sig; this.stopReported = false; } continue; }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);
    }
    return null;
  }
  onSigWake(restartable) {   // sync-model callers (non-JSPI): handlers can't suspend anyway
    this.sigDelivered = false; this.sigAllRestart = true;
    const dv = this.predeliver(); if (dv !== null) return dv;
    if (!this.sigDelivered) return null;
    return (restartable && this.sigAllRestart) ? null : err(E.INTR);
  }
  async onSigWakeAsync(restartable) {   // JSPI: deliver via promising so handlers can suspend
    this.sigDelivered = false; this.sigAllRestart = true;
    const dv = await this.predeliverAsync(); if (dv !== null) return dv;
    if (!this.sigDelivered) return null;
    return (restartable && this.sigAllRestart) ? null : err(E.INTR);
  }
  // Wait (JSPI) until a WISP socket is readable or a signal arrives. Polls the bridge
  // on a short timer and races it against a pending signal so a stuck recv stays
  // interruptible by ^C. Returns an EINTR (or restart) sentinel, or null once readable.
  async sockWait(h) {
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
      const w = await this.sigRace(res => setTimeout(() => res('t'), 20));
      if (w === 'sig') { const v = await this.onSigWakeAsync(true); if (v !== null) return v; }
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
    const sec = Number(this.r64(tp)), ns = Number(this.r64(tp + 8));
    if (!abs) return sec * 1000 + ns / 1e6;
    const nowMs = ((a[0] | 0) === 1 || (a[0] | 0) === 4) ? performance.now() : Date.now();
    return sec * 1000 + ns / 1e6 - nowMs;
  }
  wrTs(p, ms) { this.i64(p, BigInt(Math.floor(ms / 1000))); this.i64(p + 8, BigInt(Math.round((ms % 1000) * 1e6))); }
  wrItimer(p, which) {
    const t = this.timers.get(which);
    const iv = t ? t.intervalMs : 0, rem = t && t.deadline ? Math.max(0, t.deadline - Date.now()) : 0;
    this.i64(p, BigInt(Math.floor(iv / 1000))); this.i64(p + 8, BigInt(Math.round((iv % 1000) * 1000)));
    this.i64(p + 16, BigInt(Math.floor(rem / 1000))); this.i64(p + 24, BigInt(Math.round((rem % 1000) * 1000)));
  }
  pollTfd(t) {
    if (!JSPI && t.deadline && Date.now() >= t.deadline) {
      t.count++;
      if (t.intervalMs > 0) t.deadline = Date.now() + t.intervalMs; else t.deadline = 0;
    }
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
    opfsFault(path2);
    if (followLinks) path2 = this.follow(path2);
    if (dirs.has(path2)) { this.putStat(sp, { size: 4096, mode: 0o040755 }); return 0n; }
    const f = files.get(path2); if (!f) return err(E.NOENT);
    if (f.sym !== undefined) { this.putStat(sp, { size: f.sym.length, mode: 0o120777 }); return 0n; }
    this.putStat(sp, { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs, uid: f.uid ?? 0, gid: f.gid ?? 0 });
    return 0n;
  }
  openAt(path2, flags, mode) {
    const O_CREAT = 0o100, O_TRUNC = 0o1000, O_APPEND = 0o2000, O_DIRECTORY = 0o200000, O_EXCL = 0o200;
    if (path2 === '/proc/self/exe') { const g = this.allocFd(); this.fds.set(g, { exe: true }); return BigInt(g); }
    opfsFault(path2);
    if (path2 === '/dev/ptmx') { const id = newPty(); const g = this.allocFd(); this.fds.set(g, { pty: id, master: true }); return BigInt(g); }
    if (path2 === '/dev/null') { const g = this.allocFd(); this.fds.set(g, { devnull: true }); return BigInt(g); }
    // /dev/tty = the process's CONTROLLING terminal. ssh (and sudo, passwd, git) read
    // prompts here, NOT from stdin — so without this an unknown-host "yes/no" or a
    // password prompt can't be answered and the tool fails outright.
    if (path2 === '/dev/tty') { let ptyId = this.ctty;
      if (ptyId === undefined) for (const fd of [0, 1, 2]) { const h0 = this.fds.get(fd); if (h0 && h0.pty !== undefined) { ptyId = h0.pty; break; } }
      if (ptyId === undefined || ptyId === null) ptyId = termPty;
      if (ptyId !== undefined && ptyId !== null && ptys.has(ptyId)) { const g = this.allocFd(); this.fds.set(g, { pty: ptyId, master: false }); return BigInt(g); }
      return err(E.NXIO); }
    { const m = path2.match(/^\/dev\/pts\/(\d+)$/); if (m) { const id = +m[1]; if (!ptys.has(id)) return err(E.NOENT); ptys.get(id).fg = this; const g = this.allocFd(); this.fds.set(g, { pty: id, master: false }); return BigInt(g); } }
    if (dirs.has(path2)) { const g = this.allocFd(); this.fds.set(g, { path: path2, dir: true }); return BigInt(g); }
    if (flags & O_DIRECTORY) return err(E.NOTDIR);
    path2 = this.follow(path2);
    let f = files.get(path2);
    if (f && f.sym === undefined) {   // existing regular file: enforce rw bits
      const acc = flags & 3, want = (acc !== 1 ? 4 : 0) | (acc !== 0 ? 2 : 0);
      if (!this.mayAccess(f, want)) return err(E.ACCES);
    }
    if (!f) {
      if (!(flags & O_CREAT)) return err(E.NOENT);
      addFile(path2, new Uint8Array(0), 0o100000 | ((mode || 0o666) & ~this.umask & 0o7777));
      f = files.get(path2);
      f.uid = this.cred.euid; f.gid = this.cred.egid;
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
        if (h.tfd) { const t = h.tfd; S.pollTfd(t); // timerfd: 8-byte expiration count
          while (!t.count) {
            if (h.nonblock || JSPI) return err(E.AGAIN);
            const nd = t.deadline || S.nextTimerDeadline();
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, nd ? Math.max(1, Math.min(nd - Date.now(), 3600000)) : 50);
            S.pollTfd(t); S.pollTimers();
            if (S.sig.pending.size) { const w = S.onSigWake(true); if (w !== null) return w; }
          }
          if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(t.count)); t.count = 0; return 8n; }
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
          if (!q.length) return S.sigDelivered ? err(E.INTR) : err(E.AGAIN); // ^C at this boundary reads as EINTR
          const k = Math.min(q.length, a[2]); S.wbytes(a[1], Uint8Array.from(q.splice(0, k))); return BigInt(k); }
        if (h.sock) { const br = initWisp(); if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); } const r = br.call(h.sock.udp ? br.OP.RECVFROM : br.OP.RECV, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res)); return BigInt(r.res); }
        if (!h.file) return err(E.BADF);
        const b = fileRead(h.file, h.pos, a[2]); S.wbytes(a[1], b); h.pos += b.length; return BigInt(b.length);
      }
      case 'write': { if ((a[2] | 0) < 0) return err(E.INVAL); // guard: negative size must not slice from the end
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.std !== undefined) { post(td.decode(S.u8.slice(a[1], a[1] + a[2])), h.std === 0 ? 1 : h.std); return BigInt(a[2]); }
        if (h.fifo) { if (h.fifo.readers <= 0) return err(E.PIPE); // no reader will ever come back
          h.fifo.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.fifo); return BigInt(a[2]); }
        if (h.spair) { if (h.spair.wr.readers <= 0) return err(E.PIPE); // peer end closed
          h.spair.wr.chunks.push(S.u8.slice(a[1], a[1] + a[2])); wakePipe(h.spair.wr); return BigInt(a[2]); }
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
        if (h.tfd) { if (h.tfd.to) clearTimeout(h.tfd.to); const w = h.tfd.waiters; h.tfd.waiters = []; for (const f of w) f('t'); S.fds.delete(a[0]); return 0n; }
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
        return S.statPath(p, a[1], name === 'stat'); }
      case 'newfstatat': { const s = S.cstr(a[1]); return s === '' ? S.sys('fstat', [a[0], a[2]]) : S.statPath(S.atPath(a[0], s), a[2]); }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        opfsFault(p); const pf = S.follow(p);
        const want = (name === 'access' ? (a[1] | 0) : (a[2] | 0)) & 6; // X not enforced
        if (dirs.has(pf)) return 0n;
        const f = files.get(pf); if (!f) return err(E.NOENT);
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
      case 'chmod': case 'fchmodat': { const p = S.follow(S.atPath(name === 'chmod' ? -100 : a[0], S.cstr(name === 'chmod' ? a[0] : a[1])));
        opfsFault(p); const md = name === 'chmod' ? a[1] : a[2];
        if (dirs.has(p)) return 0n;
        const f = files.get(p); if (!f) return err(E.NOENT);
        if (S.cred.euid !== 0 && (f.uid ?? 0) !== S.cred.euid) return err(E.PERM);
        f.mode = (f.mode & ~0o7777) | (md & 0o7777); return 0n; }
      case 'fchmod': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        if (S.cred.euid !== 0 && (h.file.uid ?? 0) !== S.cred.euid) return err(E.PERM);
        h.file.mode = (h.file.mode & ~0o7777) | (a[1] & 0o7777); return 0n; }
      case 'chown': case 'lchown': case 'fchownat': { const pi = name === 'fchownat' ? 1 : 0, di = name === 'fchownat' ? a[0] : -100;
        const p = S.follow(S.atPath(di, S.cstr(a[pi]))); opfsFault(p);
        if (S.cred.euid !== 0) return err(E.PERM);
        const f = files.get(p); if (!f && !dirs.has(p)) return err(E.NOENT);
        if (f) { const u = a[pi + 1] | 0, g = a[pi + 2] | 0; if (u !== -1) f.uid = u; if (g !== -1) f.gid = g; }
        return 0n; }
      case 'fchown': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        if (S.cred.euid !== 0) return err(E.PERM);
        if ((a[1] | 0) !== -1) h.file.uid = a[1] | 0; if ((a[2] | 0) !== -1) h.file.gid = a[2] | 0; return 0n; }
      case 'umask': { const old = S.umask; S.umask = a[0] & 0o777; return BigInt(old); }
      case 'symlink': case 'symlinkat': { const tgt = S.cstr(a[0]);
        const lp = S.atPath(name === 'symlink' ? -100 : a[1], S.cstr(name === 'symlink' ? a[1] : a[2]));
        if (files.has(lp) || dirs.has(lp)) return err(E.EXIST);
        addFile(lp, new Uint8Array(0), 0o120777); const lf = files.get(lp);
        lf.sym = tgt; lf.uid = S.cred.euid; lf.gid = S.cred.egid; return 0n; }
      case 'link': case 'linkat': { const oi = name === 'link' ? 0 : 1, ni = name === 'link' ? 1 : 3;
        const pa = S.follow(S.atPath(name === 'link' ? -100 : a[0], S.cstr(a[oi])));
        const pb = S.atPath(name === 'link' ? -100 : a[2], S.cstr(a[ni]));
        opfsFault(pa); const f = files.get(pa); if (!f) return err(E.NOENT);
        if (f.br !== undefined) return err(E.PERM); // OPFS-backed: a hard link would double-delete the store file
        if (files.has(pb) || dirs.has(pb)) return err(E.EXIST);
        const parent = pb.slice(0, pb.lastIndexOf('/')) || '/'; mkdirp(parent);
        dirs.get(parent).add(pb.slice(pb.lastIndexOf('/') + 1));
        files.set(pb, f); return 0n; } // same object: a real hard link
      case 'truncate': { const p = S.follow(S.atPath(-100, S.cstr(a[0]))); opfsFault(p);
        const f = files.get(p); if (!f) return err(E.NOENT);
        if (!S.mayAccess(f, 2)) return err(E.ACCES);
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, Number(a[1]), 0, null); }
        f.size = Number(a[1]); return 0n; }
      case 'ftruncate': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        const f = h.file;
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, Number(a[1]), 0, null); }
        f.size = Number(a[1]); return 0n; }
      case 'fsync': case 'fdatasync': return 0n; // VFS writes are synchronous; OPFS flushes at RELEASE
      case 'statfs': case 'fstatfs': { const sp2 = a[1]; S.refresh();
        S.u8.fill(0, sp2, sp2 + 120);
        S.i64(sp2, 0x858458f6n); S.i64(sp2 + 8, 4096n); S.i64(sp2 + 16, 1n << 20n);
        S.i64(sp2 + 24, 1n << 19n); S.i64(sp2 + 32, 1n << 19n); S.i64(sp2 + 40, 1n << 16n);
        S.i64(sp2 + 48, 1n << 15n); S.i64(sp2 + 64, 255n); S.i64(sp2 + 72, 4096n); return 0n; }
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
          const code = runProgram(p, argv, envp, S.fds, S.cwd.p, S.modKey, S.cred, S.pid);
          if (code === null) return err(E.NOENT);
          throw new ExitError(code);
        }
        const fdsnap = S.fds;
        if (JSPI) { // spawn the child as a CONCURRENT task; parent longjmps back and keeps running
          const ctx = S.childStack.pop(); S.fds = ctx.savedFds; const childPid = ctx.pid;
          const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modKey, S.cred, childPid)
            .then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); postSignal(S, SIG.CHLD); wakeWaiters(S); });
          inflight.add(task); task.finally(() => inflight.delete(task));
          S.childTasks.set(childPid, task);
          return CHILD_DONE;
        }
        return S.parkChild({ exec: { path: p, argv, envp, fds: fdsnap, cwd: S.cwd.p, selfKey: S.modKey, cred: { ...S.cred } } }); }
      case 'exit': case 'exit_group': {
        if (S.inChild()) return S.parkChild({ exited: a[0] & 0xff });
        throw new ExitError(a[0]); }
      case 'wait4': {
        const want = a[0] | 0;
        while (S.pending.length) {
          const c = S.pending.shift();
          if (c.exited !== undefined) { S.reaped.set(c.pid, c.exited); continue; }
          const code = runProgram(c.exec.path, c.exec.argv, c.exec.envp, c.exec.fds, c.exec.cwd, c.exec.selfKey, c.exec.cred, c.pid);
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
          if (inOpfs(h.path)) { opfsLoaded.delete(h.path); opfsLoadDir(h.path); }
          st = { names: ['.', '..', ...dirs.get(h.path)], pos: 0 }; S.dirState.set(a[0], st);
        }
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
            case 0x40045441: { const p2 = ptys.get(h.pty); if (p2) p2.fg = S; const g = S.allocFd(); S.fds.set(g, { pty: h.pty, master: false }); return BigInt(g); }
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
      case 'nanosleep': case 'clock_nanosleep': { // sync model: sliced sleep, timers fire, signals interrupt
        let ms = S.sleepMs(name, a);
        const end = Date.now() + ms;
        while (ms > 0) {
          const nd = S.nextTimerDeadline();
          const slice = Math.min(ms, 50, nd ? Math.max(1, nd - Date.now()) : 1e12, 3600000);
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, slice);
          S.pollTimers();
          if (S.sig.pending.size) { const w = S.onSigWake(false); if (w !== null) return w; }
          ms = end - Date.now();
        }
        return 0n; }
      case 'pause': case 'sigsuspend': case 'rt_sigsuspend': { // sync model: sliced wait for a signal
        const oldMask = S.sig.mask;
        if (name !== 'pause' && a[0]) { S.refresh(); S.sig.mask = BigInt.asUintN(64, S.r64(a[0])); }
        try {
          for (;;) {
            if (S.sig.pending.size) { const w = S.onSigWake(false); if (w !== null) return w; }
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
            S.pollTimers();
          }
        } finally { S.sig.mask = oldMask; } }
      case 'clock_getres': { if (a[1]) { S.i64(a[1], 0n); S.i64(a[1] + 8, 1000000n); } return 0n; }
      case 'times': { if (a[0]) { S.refresh(); S.u8.fill(0, a[0], a[0] + 16); } return BigInt(Math.floor(performance.now() / 10) & 0x7fffffff); }
      case 'setitimer': { const which = a[0] | 0; S.refresh();
        if (a[2]) S.wrItimer(a[2], which);
        if (a[1] && which === 0) {
          const ivMs = Number(S.r64(a[1])) * 1000 + Number(S.r64(a[1] + 8)) / 1000;
          const vMs = Number(S.r64(a[1] + 16)) * 1000 + Number(S.r64(a[1] + 24)) / 1000;
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
        const ivMs = Number(S.r64(a[2])) * 1000 + Number(S.r64(a[2] + 8)) / 1e6;
        let vMs = Number(S.r64(a[2] + 16)) * 1000 + Number(S.r64(a[2] + 24)) / 1e6;
        if ((a[1] & 1) && vMs > 0) vMs -= Date.now();
        if (t.to) { clearTimeout(t.to); t.to = null; }
        t.deadline = 0; t.intervalMs = ivMs; t.count = 0;
        if (vMs > 0) { t.deadline = Date.now() + vMs;
          if (JSPI) { const fire = () => { t.count++; const w = t.waiters; t.waiters = []; for (const f of w) f('t');
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
      case 'getppid': return 1n; case 'gettid': return BigInt(S.pid);
      case 'getpgid': { const q = a[0] | 0; if (!q || q === S.pid) return BigInt(S.pgid);
        const T = procs.get(q); return T ? BigInt(T.pgid) : err(E.SRCH); }
      case 'getpgrp': return BigInt(S.pgid);
      case 'setpgid': { const T = (a[0] | 0) && (a[0] | 0) !== S.pid ? procs.get(a[0] | 0) : S;
        if (!T) return err(E.SRCH); T.pgid = (a[1] | 0) || T.pid; return 0n; }
      case 'setsid': { S.pgid = S.pid; return BigInt(S.pid); }
      case 'set_tid_address': return BigInt(S.pid);
      case 'tkill': case 'tgkill': case 'kill': {
        const sig = name === 'tgkill' ? (a[2] | 0) : (a[1] | 0);
        const pid = name === 'tgkill' ? (a[1] | 0) : (a[0] | 0);
        const isSelf = (q) => q === S.pid || (S.inChild() && S.childStack.some(c => c.pid === q));
        if (!sig) { if (name === 'kill' && pid <= 0) return 0n; return (procs.has(pid) || isSelf(pid)) ? 0n : err(E.SRCH); }
        const targets = [];
        if (name === 'kill' && pid <= 0) {
          if (pid === -1) { for (const T of procs.values()) targets.push(T); }
          else { const pg = pid === 0 ? S.pgid : -pid; for (const T of procs.values()) if (T.pgid === pg) targets.push(T); }
          if (!targets.length) return err(E.SRCH);
        } else {
          const T = procs.get(pid) || (isSelf(pid) ? S : null);
          if (!T) return err(E.SRCH);
          targets.push(T);
        }
        for (const T of targets) postSignal(T, sig);
        if (targets.includes(S) && !JSPI) { const dv = S.predeliver(); if (dv !== null) return dv; } // JSPI: defer to async boundary
        return 0n; }
      case 'rt_sigaction': { const sig = a[0] | 0; S.refresh();
        const old = S.sig.handlers.get(sig);
        if (a[2]) { S.i32(a[2], old ? old.ptr : 0); S.i32(a[2] + 4, old ? old.flags : 0); S.i32(a[2] + 8, 0); S.i64(a[2] + 12, 0n); }
        if (a[1]) S.sig.handlers.set(sig, { ptr: S.r32(a[1]), flags: S.r32(a[1] + 4) });
        return 0n; }
      case 'rt_sigprocmask': { const how = a[0] | 0; S.refresh();
        if (a[2]) S.i64(a[2], BigInt.asIntN(64, S.sig.mask));
        if (a[1]) { const m = BigInt.asUintN(64, S.r64(a[1]));
          if (how === 0) S.sig.mask |= m; else if (how === 1) S.sig.mask &= ~m; else S.sig.mask = m;
          if (S.sig.pending.size && !JSPI) { const dv = S.predeliver(); if (dv !== null) return dv; } }
        return 0n; }
      case 'rt_sigpending': { S.refresh(); let m = 0n; for (const s of S.sig.pending) m |= 1n << BigInt(s - 1); S.i64(a[0], BigInt.asIntN(64, m)); return 0n; }
      case 'sigaltstack': case 'prctl': case 'rt_sigreturn': return 0n;
      case 'futex': { const uaddr = a[0] >>> 0, fop = a[1] & 0x7f, val = a[2] | 0;
        S.refresh(); S.syncShm();
        let at = null, base = 0;
        for (const [b, x] of S.shmAt) if (uaddr >= b && uaddr < b + x.seg.size) { at = x; base = b; break; }
        if (fop === 1 || fop === 10) { if (!at) return 0n; // WAKE
          const off = uaddr - base, wl = at.seg.waiters && at.seg.waiters.get(off); let n = 0;
          if (wl) while (wl.length && n < val) { wl.shift()('wake'); n++; } return BigInt(n); }
        if (fop === 0 || fop === 9) { // WAIT (sync model: sliced poll; JSPI handled in sysAsync)
          if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
          if (!at || JSPI) return 0n;
          for (let spins = 0; spins < 200; spins++) {
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
            S.pollTimers(); S.syncShm();
            if (S.dv.getInt32(uaddr, true) !== val) return 0n;
            if (S.sig.pending.size) { const w = S.onSigWake(false); if (w !== null) return w; }
          }
          return err(E.AGAIN); }
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
      case 'getrusage': { S.refresh(); S.u8.fill(0, a[1], a[1] + 144); return 0n; }
      case 'sysinfo': { S.refresh(); S.u8.fill(0, a[0], a[0] + 112); S.i64(a[0], 1000n); S.i64(a[0] + 32, 4294967296n); S.i64(a[0] + 40, 2147483648n); return 0n; }
      case 'getrandom': { const b = new Uint8Array(Math.min(a[1], 65536)); crypto.getRandomValues(b); S.wbytes(a[0], b); return BigInt(b.length); }
      case 'poll': { S.refresh(); let ready = 0;
        for (let i = 0; i < a[1]; i++) { const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
          const h = S.fds.get(fd); let re = 0;
          if (h && h.sock && h.sock.icmp) { const pg = h.sock.ping;   // readable once the relay's ping resolves
            if (pg && pg.status === null) { const pk = initWisp().call(initWisp().OP.PINGPOLL, pg.id, 0, 0); if (pk.res === 0) pg.status = 0; else if (pk.res !== -11) pg.status = pk.res; }
            if ((ev & 1) && pg && pg.status === 0) re |= 1; if (ev & 4) re |= 4; }
          else if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; if (ev & 4) re |= 4; }
          else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; }
          else if (fd < 0) re = 0; else if (!h) re = 0x20; else re = ev & 5;
          S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++; }
        return BigInt(ready); }
      case 'select': case 'pselect6': return 1n;
      case 'socket': { const dom = a[0] & 0xff, type = a[1] & 0xff, proto = a[2] | 0, nonblock = !!(a[1] & 0x800);
        if (dom !== 2 && dom !== 10) return err(E.NOSYS);
        const br = initWisp();
        // ICMP: SOCK_RAW (rawhdr -> recv includes the IP header) or the unprivileged
        // SOCK_DGRAM "ping socket" (IPPROTO_ICMP). Reachability comes from the relay.
        if (type === 3 || (type === 2 && (proto === 1 || proto === 58))) {
          const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, icmp: true, rawhdr: type === 3, v6: dom === 10, nonblock } }); return BigInt(g); }
        if (type === 2) { const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, udp: true, nonblock } }); return BigInt(g); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, dom, nonblock } }); return BigInt(g); }
      case 'bind': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh(); h.sock.bindAddr = readSockaddr(S, a[1]); return 0n; }
      case 'listen': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        const ba = h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        const br = initWisp(); if (!br.OP.LISTEN) return err(E.NOSYS);
        const r = br.call(br.OP.LISTEN, ba.port, 0, 0);
        if (r.res < 0) return BigInt(r.res);
        h.sock.id = r.res; h.sock.listener = true; h.sock.boundPort = r.aux;
        return 0n; }
      case 'accept': case 'accept4': { const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        const br = initWisp();
        const r = br.call(br.OP.ACCEPT, h.sock.id, (h.nonblock || h.sock.nonblock || JSPI) ? 1 : 0, 0);
        if (r.res < 0) return BigInt(r.res); // EAGAIN under JSPI: sysAsync loops with suspends
        S.refresh();
        const [pip, pport] = td.decode(r.data.slice(0, r.aux)).split('|');
        if (a[1]) { const n = writeSockaddr(S, a[1], { ip: pip || '0.0.0.0', port: +pport || 0 }); if (a[2]) S.i32(a[2], n); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, dom: h.sock.dom, nonblock: !!(a[3] & 0x800) } });
        return BigInt(g); }
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF); S.refresh();
        const dst = readSockaddr(S, a[1]);
        if (h.sock.udp || h.sock.icmp) { h.sock.dest = dst; return 0n; }
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
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue; const b = pipeRead(h.spair.rd, l); if (!b.length) break; S.wbytes(p, b); total += b.length; if (b.length < l) break; }
          const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24);
          if (ctl && ctllen >= 16 && h.spair.rd.fds && h.spair.rd.fds.length) { const hh = h.spair.rd.fds.shift(); const g = S.allocFd(); S.fds.set(g, hh);
            S.i32(ctl, 20); S.i32(ctl + 8, 1); S.i32(ctl + 12, 1); S.i32(ctl + 16, g); S.i32(a[1] + 24, 20);
          } else if (ctl) S.i32(a[1] + 24, 0);
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
          const r = br.call(op, h.sock.id, l, 0); if (r.res < 0) return total || BigInt(r.res); if (r.res === 0) break; S.wbytes(p, r.data.subarray(0, r.res)); total += r.res; if (r.res < l) break; }
        return BigInt(total); }
      case 'getsockname': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh(); const ba = h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        const n = writeSockaddr(S, a[1], { ip: ba.ip === '::' ? '0.0.0.0' : ba.ip, port: h.sock.boundPort || ba.port });
        if (a[2]) S.i32(a[2], n); return 0n; }
      case 'setsockopt': case 'getpeername': case 'shutdown': return 0n;
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
        if (h && h.std === 0 && !h.nonblock) { while (!stdinChunks.length && !stdinEOF) { pipeSuspends++;
          const w = await S.sigRace(res => stdinWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } } return S.sys(name, a); }
        if (h && h.pty !== undefined && !h.nonblock) { const p = ptys.get(h.pty); const q = () => h.master ? p.toMaster : p.toSlave; const wl = h.master ? p.masterWaiters : p.slaveWaiters;
          while (!q().length) { pipeSuspends++;
            const w = await S.sigRace(res => wl.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } } return S.sys(name, a); }
        if (h && h.fifo && !h.nonblock) { while (!h.fifo.chunks.length && h.fifo.writers > 0) { pipeSuspends++;
          const w = await S.sigRace(res => h.fifo.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } } return S.sys(name, a); }
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && h.spair.rd.writers > 0) { pipeSuspends++;
          const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } } return S.sys(name, a); }
        if (h && h.tfd && !h.nonblock) { while (!h.tfd.count) {
            const w = await S.sigRace(res => h.tfd.waiters.push(res));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } }
          S.refresh(); if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(h.tfd.count)); h.tfd.count = 0; return 8n; }
        // Blocking socket read: poll the WISP bridge with a signal race instead of a
        // frozen Atomics.wait, so ^C (SIGINT) can interrupt a stuck recv (e.g. telnet).
        if (h && h.sock && (h.sock.id || h.sock.icmp) && !h.nonblock) { const v = await S.sockWait(h); if (v !== null) return v; }
        return S.sys(name, a);
      }
      case 'recvmsg': case 'recvfrom': {
        const h = S.fds.get(a[0]);
        if (h && h.spair && !h.nonblock) { while (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length) && h.spair.rd.writers > 0) { pipeSuspends++;
          const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } } }
        if (h && h.sock && (h.sock.id || h.sock.icmp) && !h.nonblock) { const v = await S.sockWait(h); if (v !== null) return v; }
        return S.sys(name, a);
      }
      case 'execve': {
        const p = S.cstr(a[0]); const argv = S.rPtrArray(a[1]); const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) { const code = await runProgramAsync(p, argv, envp, S.fds, S.cwd.p, S.modKey, S.cred, S.pid); if (code === null) return err(E.NOENT); throw new ExitError(code); }
        const fdsnap = S.fds; const ctx = S.childStack.pop(); S.fds = ctx.savedFds; const childPid = ctx.pid;
        const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modKey, S.cred, childPid).then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); postSignal(S, SIG.CHLD); wakeWaiters(S); });
        inflight.add(task); task.finally(() => inflight.delete(task)); S.childTasks.set(childPid, task);
        return CHILD_DONE;
      }
      case 'nanosleep': case 'clock_nanosleep': { // interruptible (EINTR) + TIMER_ABSTIME
        const end = Date.now() + S.sleepMs(name, a);
        while (Date.now() < end) {
          const w = await S.sigRace(res => setTimeout(() => res('t'), Math.min(end - Date.now(), 3600000)));
          if (w === 'sig') { const v = await S.onSigWakeAsync(false); if (v !== null) return v; }
        }
        return 0n;
      }
      case 'pause': case 'sigsuspend': case 'rt_sigsuspend': { // suspend until a signal is DELIVERED
        const oldMask = S.sig.mask;
        if (name !== 'pause' && a[0]) { S.refresh(); S.sig.mask = BigInt.asUintN(64, S.r64(a[0])); }
        try {
          for (;;) {
            if (S.sig.pending.size) { const v = await S.onSigWakeAsync(false); if (v !== null) return v; }
            await S.sigRace(() => {});
          }
        } finally { S.sig.mask = oldMask; }
      }
      case 'accept': case 'accept4': { // JSPI: probe + suspend so siblings run while we wait
        const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        for (;;) {
          const r = S.sys(name, a);
          if (r !== BigInt(-E.AGAIN) || h.nonblock || h.sock.nonblock) return r;
          const w = await S.sigRace(res => setTimeout(() => res('t'), 20));
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
        }
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
      waitSuspends++;
      const w = await S.sigRace(res => S.waitWaiters.push(() => res('ev')));
      if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
    }
  }
  async pollAsync(name, a) {
    const S = this; const nfds = a[1];
    S.refresh();
    const timeout = name === 'poll' ? (a[2] | 0)
      : (a[2] ? Math.ceil(Number(S.r64(a[2])) * 1000 + Number(S.r64(a[2] + 8)) / 1e6) : -1); // ppoll: timespec or NULL
    const evalReady = () => { S.refresh(); let ready = 0; const waitFifos = []; const waitPtys = []; let waitStdin = false, waitSock = false;
      for (let i = 0; i < nfds; i++) {
        const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
        const h = S.fds.get(fd); let re = 0;
        if (h && h.std === 0) { const rdy = stdinChunks.length || stdinEOF; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitStdin = true; }
        else if (h && h.fifo) { const rdy = h.fifo.chunks.length || h.fifo.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.fifo); }
        else if (h && h.spair) { const rdy = h.spair.rd.chunks.length || h.spair.rd.writers <= 0; if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.spair.rd); }
        else if (h && h.sock && h.sock.id) { const pk = initWisp().call(initWisp().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; else if (ev & 1) waitSock = true; if (ev & 4) re |= 4; }
        else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave; if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; if (!q.length) waitPtys.push(h.master ? p.masterWaiters : p.slaveWaiters); }
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
      else if (name === 'log_execution') { // wasm-opt --log-execution preemption hook
        // (see farm/instrument-preempt.sh; instrumented binaries must be linked
        // WITHOUT --shared-memory so the start section stays uninstrumented)
        let fuel = 0;
        const check = () => {
          S.pollTimers();
          S.sigDelivered = false;
          const dv = S.predeliver(); if (dv !== null) return null;
          const now = Date.now();
          if (!S.stopped && now - S.lastYield < QUANTUM_MS) return null;
          return (async () => {
            while (S.stopped) await new Promise(res => S.contWaiters.push(res));
            S.lastYield = Date.now();
            await new Promise(res => setTimeout(res, 0));
            return 0;
          })();
        };
        wali[name] = JSPI
          ? new WebAssembly.Suspending(() => { if (++fuel & 0x3fff) return 0; return check() || 0; })
          : (() => { if (++fuel & 0x3fff) return; S.pollTimers(); if (S.sig.pending.size) { S.sigDelivered = false; S.predeliver(); } });
      }
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
        } else if (JSPI) { // every syscall is suspend-capable: signals deliver here
          // and the preemption quantum yields, so busy loops can't starve siblings
          wali[name] = new WebAssembly.Suspending(async (...a2) => {
            S.syscalls++; syscallTotal++;
            S.pollTimers();
            S.sigDelivered = false;
            if (S.shmAt.size) S.syncShm();          // shm coherence at every boundary
            const dv = await S.predeliverAsync(); if (dv !== null) return dv;   // handlers run under promising
            while (S.stopped) { await new Promise(res => S.contWaiters.push(res)); // SIGSTOP parks until SIGCONT
              const dv2 = await S.predeliverAsync(); if (dv2 !== null) return dv2; }
            const now = Date.now();
            if (now - S.lastYield >= QUANTUM_MS) { S.lastYield = now; await new Promise(res => setTimeout(res, 0)); }
            return BLOCKING.has(sysname) ? await S.sysAsync(sysname, map(a2)) : S.sys(sysname, map(a2));
          });
        } else {
          wali[name] = (...a2) => {
            S.syscalls++; syscallTotal++;
            S.pollTimers();
            if (S.shmAt.size) S.syncShm();
            S.sigDelivered = false;
            const dv = S.predeliver(); if (dv !== null) return dv;
            return S.sys(sysname, map(a2));
          };
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
    this.inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = this.inst.exports.memory; this.membuf = null; this.refresh();
    try { this.inst.exports._start(); return 0; }
    catch (e) {
      if (e instanceof ExitError) return e.code & 0xff;
      post(`[host] trap in pid ${this.pid}: ${e.stack || e}\n`, 2);
      return 139;
    } finally { this.retire(); }
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
    try { return await this._driveInner(rewind); } finally { this.retire(); }
  }
  async _driveInner(rewind) {
    const start = WebAssembly.promising(this.inst.exports._start);
    if (rewind) this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    for (;;) {
      try { await start(); }
      catch (e) { if (e instanceof ExitError) return e.code & 0xff; post(`[host] trap in pid ${this.pid}: ${e.stack || e}\n`, 2); return 139; }
      if (this.forkState !== 'unwinding') return 0;
      this.inst.exports.asyncify_stop_unwind();
      const childPid = nextPid++;
      const child = this.spawnForkChild(childPid);
      const ctask = child._drive(true).then((code) => { releaseFds(child.fds); this.reaped.set(childPid, code); this.childTasks.delete(childPid); postSignal(this, SIG.CHLD); wakeWaiters(this); });
      inflight.add(ctask); ctask.finally(() => inflight.delete(ctask));
      this.childTasks.set(childPid, ctask);
      this.forkRet = BigInt(childPid); this.forkState = 'rewinding';
      this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    }
  }

  spawnForkChild(childPid) {
    const mod = modCache.get(this.modKey);
    const child = new Process(this.modKey, this.argv, this.env, new Map(), this.cwd.p);
    procs.delete(child.pid);                 // re-register under the pid fork() reported
    child.pid = childPid; child.pgid = this.pgid; child.cred = { ...this.cred };
    for (const [b, at] of this.shmAt) child.shmAt.set(b, { seg: at.seg, shadow: at.shadow.slice() }); // shm survives fork
    procs.set(childPid, child);
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

let lazyTars = {};                 // moduleKey -> [[tarUrl, mountPrefix], ...] (loaded once, on first exec)
const lazyTarsDone = new Set();
// lazily fetch+compile a manifest URL on first use, plus any companion tar the
// program needs (e.g. python.wasm -> pylib.tar.gz at /py). Returns whether the
// key is (now) compiled. VFS keys are compiled at resolve time.
async function ensureModule(key) {
  if (!key || key.startsWith('vfs:')) return !!modCache.has(key);
  if (!modCache.has(key)) {
    try {
      const t0 = performance.now();
      modCache.set(key, await WebAssembly.compileStreaming(fetch(key)));
      post(`[host] loaded ${key} (${(performance.now() - t0).toFixed(0)}ms)\n`, 2);
    } catch (e) { post(`[host] failed to load ${key}: ${e.message || e}\n`, 2); return false; }
  }
  if (lazyTars[key] && !lazyTarsDone.has(key)) { lazyTarsDone.add(key); // companion data (stdlib, etc.)
    for (const [url, prefix] of lazyTars[key]) { try { await loadTar(url, prefix); } catch (e) { post(`[host] companion ${url} failed: ${e.message || e}\n`, 2); } }
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
        key = 'vfs:' + vp;
        if (!modCache.has(key)) modCache.set(key, new WebAssembly.Module(bytes.slice()));
      }
    }
  }
  // busybox multi-call fallback: any still-unresolved name runs busybox, which
  // dispatches on argv[0] (busybox itself may still be a lazy manifest URL).
  if (!key && manifest['busybox']) key = manifest['busybox'];
  if (!key) { post(`[host] execve: cannot resolve ${p}\n`, 2); return null; }
  return key;
}

function runProgram(p, argv, envp, fdTable, cwd, selfKey, cred, asPid) {
  const key = resolveExecKey(p, cwd, selfKey);
  if (!key) return null;
  if (!modCache.has(key)) { post(`[host] ${key} not preloaded (sync exec cannot lazy-fetch; use JSPI)\n`, 2); return null; }
  const proc = new Process(key, argv, envp, fdTable, cwd);
  if (cred) proc.cred = { ...cred };
  // execve keeps the process's identity: preserve the pid AND the pgid of the image
  // being replaced. new Process() seeded pgid from its throwaway temp pid, so without
  // this the exec'd process would carry a stale pgid and job control (tcsetpgrp/^C)
  // would signal a group nothing is in.
  if (asPid) { const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid; proc.pgid = old ? old.pgid : asPid; procs.set(asPid, proc); }
  return proc.run();
}

// JSPI variant: run the child concurrently (its blocking syscalls suspend, not stall)
async function runProgramAsync(p, argv, envp, fdTable, cwd, selfKey, cred, asPid) {
  const key = resolveExecKey(p, cwd, selfKey);
  if (!key) return null;
  if (!(await ensureModule(key))) return null; // LAZY: fetch+compile on first exec
  const proc = new Process(key, argv, envp, fdTable, cwd);
  if (cred) proc.cred = { ...cred };
  // execve keeps the process's identity: preserve pid AND pgid of the replaced image
  // (new Process() seeded pgid from a throwaway temp pid). Without this the exec'd
  // process carries a stale pgid, so tcsetpgrp/^C signal a group with no members.
  if (asPid) { const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid; proc.pgid = old ? old.pgid : asPid; procs.set(asPid, proc); }
  await new Promise(res => setTimeout(res, 0)); // clean JS stack: child _start must not run inside the parent's suspending import
  return await proc.runAsync();
}

// ================= entry =================
self.onmessage = async (ev) => {
  const m = ev.data;
  if (m.t === 'stdin-sab') { stdinCtl = new Int32Array(m.sab, 0, 4); stdinData = new Uint8Array(m.sab, 16); return; }
  if (m.t === 'wisp-sab') { wispSab = m.sab; return; }
  if (m.t === 'add-pkg') { // register an aports package into the live manifest -> runnable (lazy-compiled on first exec)
    if (m.name && m.url) { manifest[m.name] = m.url; if (m.lazyTars) lazyTars[m.name] = m.lazyTars; }
    return; }
  if (m.t === 'opfs-sab') { opfsSab = m.sab; return; }
  if (m.t === 'winsize') { if (m.rows) winRows = m.rows; if (m.cols) winCols = m.cols;
    for (const p of ptys.values()) { p.rows = winRows; p.cols = winCols; if (p.pgrp) signalPgrp(p.pgrp, SIG.WINCH); } // POSIX: a size change raises SIGWINCH on the fg group so TUIs (vi, ssh) re-render
    return; }
  if (m.t === 'sigint') { // page-level Ctrl-C -> guest foreground group (pty pgrp if set, else the root)
    let fg = 0; for (const p of ptys.values()) if (p.pgrp) fg = p.pgrp;
    if (!(fg && signalPgrp(fg, SIG.INT))) postSignal(rootProc, SIG.INT);
    return; }
  if (m.t === 'stdin') { const b = typeof m.data === 'string' ? te.encode(m.data) : new Uint8Array(m.data);
    if (termPty !== null) ptyMasterWrite(ptys.get(termPty), b); else pushStdin(b); return; } // terminal: keystrokes -> pty; else async stdin
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
    lazyTars = m.lazyTars || {};   // moduleKey -> companion tars, mounted on first exec of that program
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
    if (m.blobs) for (const [p, buf] of Object.entries(m.blobs)) addFile(norm(p, '/'), new Uint8Array(buf));
    // Compile the ROOT module up front. Under JSPI the rest of the manifest
    // (python.wasm 31 MB, lua, ssh, ...) is NOT fetched here — each lazy-compiles
    // on its first exec via ensureModule(). The sync fallback can't lazy-fetch, so
    // it still has to preload the whole manifest. (skip all when running a VFS binary)
    const canLazy = !!m.jspi && jspiAvailable;
    const preload = canLazy ? [m.vfsMain ? null : m.wasm] : [m.vfsMain ? null : m.wasm, ...Object.values(manifest)];
    for (const key of new Set(preload)) {
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
    let rootFds;
    if (m.pty) { // terminal mode: run the shell on a fresh pty; bridge master <-> page
      termPty = newPty();
      rootFds = new Map([[0, { pty: termPty, master: false }], [1, { pty: termPty, master: false }], [2, { pty: termPty, master: false }]]);
    } else {
      termPty = null;
      rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
    }
    const env = Object.entries(m.env || {}).map(([k, v]) => k + '=' + v);
    nextPid = 100; syscallTotal = 0; procCount = 0; stdinChunks = []; stdinEOF = false; stdinWaiters = [];
    JSPI = !!m.jspi && jspiAvailable;
    if (m.jspi && !jspiAvailable) post('[host] jspi requested but unavailable in this browser; using synchronous model\n', 2);
    pipeSuspends = 0; waitSuspends = 0;
    const root = new Process(rootKey, m.argv, env, rootFds, m.cwd || '/');
    if (m.uid !== undefined) { const u = m.uid | 0; root.cred = { uid: u, euid: u, suid: u, gid: u, egid: u, sgid: u }; } // run as a non-root user
    rootProc = root;
    self.postMessage({ t: 'boot', ms: performance.now() - boot0 });
    const t0 = performance.now();
    // Live gauges for the terminal header: total wasm memory across processes,
    // live process count, and cumulative syscalls (the page derives a rate = speed).
    const statsTimer = setInterval(() => {
      let mem = 0; for (const p of procs.values()) { try { mem += p.memory.buffer.byteLength; } catch {} }
      self.postMessage({ t: 'stats', mem, procs: procs.size, syscalls: syscallTotal, ms: performance.now() - t0 });
    }, 1000);
    let code;
    try { code = JSPI ? await root.runAsync() : root.run(); }
    finally { clearInterval(statsTimer); }
    if (opfsBr) { try { opfsBr.call(OFS.RELEASE, 0, 0, 0, null); } catch {} for (const f of files.values()) if (f.brId) f.brId = 0; }
    self.postMessage({ t: 'exit', code, ms: performance.now() - t0, syscalls: syscallTotal, procs: procCount, jspi: JSPI, pipeSuspends, waitSuspends });
  } catch (e) {
    post('[host] fatal: ' + (e.stack || e) + '\n', 2);
    self.postMessage({ t: 'exit', code: 127, ms: 0, syscalls: syscallTotal, procs: procCount });
  }
};
