// WALI JS syscall host v2 — process model edition.
// Runs wasm32-linux-muslwali binaries in node/V8 with vfork/execve/wait4/pipes:
//   fork: child branch runs in-place under an fd overlay (vfork semantics,
//         guest longjmps back via wasm-EH SJLJ); execve/_exit park the child.
//   wait4: parked children run synchronously as fresh instances.
'use strict';
const fs = require('fs');
const path = require('path');

// ---- synchronous TCP bridge (worker_thread + SAB) ----
let sockBridge = null;
function initSockBridge() {
  if (sockBridge) return sockBridge;
  const { Worker } = require('worker_threads');
  const sab = new SharedArrayBuffer(32 + 65536);
  const ctl = new Int32Array(sab, 0, 8);
  const data = new Uint8Array(sab, 32);
  const worker = new Worker(path.join(__dirname, 'sock-bridge.js'), { workerData: { sab } });
  worker.on('error', (e) => process.stderr.write('[sock-bridge] ' + e + '\n'));
  worker.unref();
  const call = (op, a0, a1, a2, reqBytes) => {
    if (reqBytes) data.set(reqBytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0;
    const prev = Atomics.load(ctl, 1);
    Atomics.add(ctl, 0, 1); Atomics.notify(ctl, 0);
    while (Atomics.load(ctl, 1) === prev) Atomics.wait(ctl, 1, prev);
    return { res: ctl[6], aux: ctl[7], data };
  };
  sockBridge = { call, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, LISTEN: 9, ACCEPT: 10 } };
  return sockBridge;
}

const wasmPath = process.argv[2];
if (!wasmPath) { console.error('usage: node host.js prog.wasm [args...]'); process.exit(2); }

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
const E = { PERM:1, NOENT:2, SRCH:3, INTR:4, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, FAULT:14, EXIST:17, NOTDIR:20, ISDIR:21, INVAL:22, MFILE:24, NOTTY:25, SPIPE:29, PIPE:32, RANGE:34, NOSYS:38, NOTEMPTY:39 };
const err = (e) => BigInt(-e);
function sysErr(e) {
  const m = { EPERM:E.PERM, ENOENT:E.NOENT, EBADF:E.BADF, EACCES:E.ACCES, EEXIST:E.EXIST, ENOTDIR:E.NOTDIR, EISDIR:E.ISDIR, EINVAL:E.INVAL, ENOTEMPTY:E.NOTEMPTY, EMFILE:E.MFILE, ESPIPE:E.SPIPE, EAGAIN:E.AGAIN };
  return err(m[e.code] ?? E.INVAL);
}
// parse sockaddr_in (AF_INET=2) / sockaddr_in6 (AF_INET6=10) -> {ip, port}
function readSockaddr(S, p) {
  S.refresh();
  const fam = S.dv.getUint16(p, true);
  const port = S.dv.getUint16(p + 2, false);
  let ip;
  if (fam === 10) { const g = []; for (let i = 0; i < 16; i += 2) g.push(S.dv.getUint16(p + 8 + i, false).toString(16)); ip = g.join(':'); }
  else ip = `${S.u8[p+4]}.${S.u8[p+5]}.${S.u8[p+6]}.${S.u8[p+7]}`;
  return { ip, port };
}
// write a sockaddr_in (AF_INET) into guest memory; returns bytes written (16)
function writeSockaddr(S, p, dest) {
  S.refresh(); S.u8.fill(0, p, p + 16);
  S.dv.setUint16(p, 2, true);                 // AF_INET
  S.dv.setUint16(p + 2, dest.port, false);    // port (network order)
  const o = dest.ip.split('.').map(Number);
  S.u8[p + 4] = o[0]; S.u8[p + 5] = o[1]; S.u8[p + 6] = o[2]; S.u8[p + 7] = o[3];
  return 16;
}

// ---- global kernel state (shared across processes) ----
let nextPid = 100;
const modCache = new Map();          // resolved path -> WebAssembly.Module
// children are owned by the process that forked them (per-Process queues)
let syscallTotal = 0, procCount = 0;
const unknownSyscalls = new Set();

// ---- concurrent scheduler (JSPI) ----
// Default host runs the synchronous model (children run to completion at wait4).
// With WALI_JSPI=1 on node 24 (--experimental-wasm-jspi), each fork+exec'd child
// runs as a CONCURRENT task (WebAssembly.promising(_start)); blocking syscalls
// (read on an empty pipe, wait4, poll, nanosleep) SUSPEND the calling process
// (WebAssembly.Suspending) and yield to the event loop so siblings run. This is
// what makes live interactive sessions (a shell driving a running pipeline, sshd)
// possible instead of atomic run-at-wait4.
const JSPI = !!process.env.WALI_JSPI && typeof WebAssembly.Suspending === 'function'
          && typeof WebAssembly.promising === 'function';
if (process.env.WALI_JSPI && !JSPI) process.stderr.write('[wali-host] WALI_JSPI set but JSPI unavailable (need node 24 + --experimental-wasm-jspi); using synchronous model\n');
// syscalls that may block -> wrapped as WebAssembly.Suspending in JSPI mode
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'nanosleep', 'clock_nanosleep', 'execve', 'recvmsg', 'pause', 'sigsuspend', 'rt_sigsuspend', 'accept', 'accept4', 'futex']);
const ASYNC_PAGES = 16;               // 1MB asyncify unwind buffer (grown at first fork)
const QUANTUM_MS = 10;                // JSPI preemption: max run between event-loop yields
const inflight = new Set();           // live child task promises (keeps event loop alive)
let pipeSuspends = 0, waitSuspends = 0; // JSPI concurrency evidence: times a process actually suspended

// binary manifest: how execve paths resolve to wasm modules
function resolveModulePath(p, selfPath) {
  if (p === '/proc/self/exe') return selfPath;
  p = redir(p); // WALI_MAP/WALI_ETC: virtualize exec paths (e.g. sshd-session)
  if (fs.existsSync(p)) {
    const fd = fs.openSync(p, 'r'); const b = Buffer.alloc(4);
    fs.readSync(fd, b, 0, 4, 0); fs.closeSync(fd);
    if (b.readUInt32LE(0) === 0x6d736100) return p;
  }
  const base = path.basename(p);
  if (base.startsWith('python')) return path.join(process.env.HOME || '', 'wali-py', 'python');
  // busybox multi-call: sh/hush and every applet (tr, rev, cat, grep, sort, ...) map
  // to the busybox binary; it dispatches on argv[0]. Fallback for any unresolved name.
  const bb = path.join(process.env.HOME || '', 'busybox-1.36.1', 'busybox');
  if (fs.existsSync(bb)) return bb;
  return null;
}
function getModule(p) {
  if (!modCache.has(p)) modCache.set(p, new WebAssembly.Module(fs.readFileSync(p)));
  return modCache.get(p);
}

// ---- pseudo-terminals (module-level: master in parent, slave in child share) ----
const ptys = new Map(); let nextPtyId = 0;
// termios flag bits (asm-generic): c_lflag ISIG|ICANON|ECHO|ECHOE; c_iflag ICRNL;
// c_oflag OPOST|ONLCR. struct: c_iflag,c_oflag,c_cflag,c_lflag (u32 each), c_line,
// c_cc[32]. c_cc VINTR@0 VERASE@2 VEOF@4 VMIN@6.
const ICANON = 0x2, ECHO = 0x8, ISIG = 0x1, ICRNL = 0x100, OPOST = 0x1, ONLCR = 0x4;
function defaultTermios() { const t = new Uint8Array(60); const dv = new DataView(t.buffer);
  dv.setUint32(0, ICRNL | 0x400, true); dv.setUint32(4, OPOST | ONLCR, true);
  dv.setUint32(8, 0xbf, true); dv.setUint32(12, ISIG | ICANON | ECHO | 0x10, true);
  t[17] = 3; t[19] = 21; t[17 + 2] = 127; t[17 + 4] = 4; t[17 + 6] = 1; return t; }
function newPty() { const id = nextPtyId++; ptys.set(id, { toSlave: [], toMaster: [], line: [], termios: defaultTermios(), rows: 24, cols: 80, pgrp: 0, slaveWaiters: [], masterWaiters: [] }); return id; }
function wakePty(list) { if (list && list.length) { const w = list.splice(0); for (const f of w) f(); } }
// stat for a pty device — dev+ino MUST match between fstat(fd) and stat("/dev/pts/N")
// or musl ttyname_r fails (breaks sshd pty allocation).
function ptyStatObj(id, master) { return { size: 0, mode: 0o020620, nlink: 1, uid: 1000, gid: 5, dev: 6, ino: master ? 2 : 1000 + id, rdev: master ? ((5 << 8) | 2) : ((136 << 8) | id) }; }
const tflag = (p, off) => new DataView(p.termios.buffer).getUint32(off, true);
function ptyMasterWrite(p, bytes) { // user input -> line discipline -> slave
  const lf = tflag(p, 12), canon = lf & ICANON, echo = lf & ECHO, icrnl = tflag(p, 0) & ICRNL, isig = lf & ISIG;
  for (let c of bytes) {
    if (isig && c && (c === p.termios[17] || c === p.termios[18])) { // VINTR (^C) / VQUIT
      const sig = c === p.termios[17] ? SIG.INT : SIG.QUIT;
      p.line = [];                                     // flush the input line
      if (echo) p.toMaster.push(94, 64 + (c & 31));    // echo ^C / ^\
      if (p.pgrp) signalPgrp(p.pgrp, sig);
      else if (p.fg) postSignal(p.fg, sig);            // no pgrp set: last slave opener
      continue;
    }
    if (canon) {
      if (c === 0x7f || c === 0x08) { if (p.line.length) { p.line.pop(); if (echo) p.toMaster.push(8, 32, 8); } continue; }
      if (c === 0x0d && icrnl) c = 0x0a;
      p.line.push(c); if (echo) p.toMaster.push(c);
      if (c === 0x0a) { for (const x of p.line) p.toSlave.push(x); p.line = []; }
    } else { p.toSlave.push(c); if (echo) p.toMaster.push(c); }
  }
  if (p.toSlave.length) wakePty(p.slaveWaiters);   // wake the program reading the pty
  if (p.toMaster.length) wakePty(p.masterWaiters);  // wake whoever reads echoed input
}
function ptySlaveWrite(p, bytes) { // program output -> ONLCR -> master
  const of = tflag(p, 4), onlcr = (of & OPOST) && (of & ONLCR);
  for (const c of bytes) { if (onlcr && c === 0x0a) p.toMaster.push(0x0d, 0x0a); else p.toMaster.push(c); }
  if (p.toMaster.length) wakePty(p.masterWaiters);  // wake sshd reading the pty master
}

// ---- pipes ----
// writers/readers are reference counts (bumped on fork/dup of an end, dropped on
// close). In JSPI mode a reader on an empty pipe suspends until a write wakes it
// or the last writer closes (writers==0 => EOF). readWaiters holds suspend
// resolvers; wakePipe() releases them.
function mkPipe() { return { chunks: [], writers: 1, readers: 1, readWaiters: [] }; }
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
function pipeRead(fifo, n) {
  if (!fifo.chunks.length) return new Uint8Array(0); // empty: 0 bytes = EOF (writers==0 guaranteed by the JSPI await, or sequential model)
  let out = Buffer.concat(fifo.chunks);
  const take = out.subarray(0, n);
  const rest = out.subarray(n);
  fifo.chunks = rest.length ? [rest] : [];
  return take;
}
// a process exited: release its pipe ends so EOF propagates to the other side (JSPI)
function releaseFds(fdMap) { for (const h of fdMap.values()) {
  if (h && h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; }
  else if (h && h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; } } }
// wake a process suspended in wait4 (a child just finished)
function wakeWaiters(S) { if (S.waitWaiters.length) { const w = S.waitWaiters; S.waitWaiters = []; for (const f of w) f(); } }

// ---- signals: per-process handlers/mask/pending; delivery happens at syscall
// boundaries (the only safe points — wasm can't be interrupted mid-loop). A
// handler is invoked by calling its function-table index, which needs the
// binary linked with -Wl,--export-table; without the table, handled signals
// degrade to their default action (SIG_IGN is always honored). ----
const SIG = { HUP:1, INT:2, QUIT:3, ILL:4, ABRT:6, KILL:9, USR1:10, SEGV:11, USR2:12, PIPE:13, ALRM:14, TERM:15, CHLD:17, CONT:18, STOP:19, TSTP:20, TTIN:21, TTOU:22, URG:23, WINCH:28 };
const SIG_DFL_IGNORE = new Set([SIG.CHLD, SIG.CONT, SIG.URG, SIG.WINCH]);
const SIG_STOPPERS = new Set([SIG.STOP, SIG.TSTP, SIG.TTIN, SIG.TTOU]);
const procs = new Map();              // live pid -> Process (kill routing)
let rootProc = null;                  // the tree root (fallback Ctrl-C target)
// SysV shared memory: segments are host-side buffers; a process snapshots the
// content in at shmat and writes it back at shmdt/exit. Coherent for
// vfork-in-place children (same instance memory); forked children see the
// attach-time snapshot — LIVE cross-process stores need same-memory domains
// (--import-memory process groups), which wasm can't retrofit per-mapping.
const shmSegs = new Map(), shmById = new Map(); let nextShmId = 1;
function postSignal(P, sig) {
  if (!P || !sig) return;
  if (sig === SIG.CONT) { for (const st of SIG_STOPPERS) P.sig.pending.delete(st); // POSIX: CONT discards pending stops
    if (P.stopped) { P.stopped = 0; const c = P.contWaiters; P.contWaiters = []; for (const f of c) f(); } }
  if (SIG_STOPPERS.has(sig)) P.sig.pending.delete(SIG.CONT);   // and a stop discards a pending CONT // resume regardless of disposition
  const h = P.sig.handlers.get(sig);
  if (h && (h.ptr === -2 || h.ptr === 1) && sig !== SIG.KILL) return; // SIG_IGN (this musl: -2; classic ABI: 1)
  if ((!h || !h.ptr) && SIG_DFL_IGNORE.has(sig)) return;        // default-ignore
  P.sig.pending.add(sig);
  const w = P.sig.waiters; P.sig.waiters = []; for (const f of w) f('sig'); // wake blocked syscalls
}
function signalPgrp(pgid, sig) { let n = 0; for (const P of procs.values()) if (P.pgid === pgid) { postSignal(P, sig); n++; } return n; }

// ---- path redirect: virtualize specific guest paths (e.g. /etc/passwd) onto real
// files without a full chroot. Populated from WALI_ETC (a dir whose files shadow
// /etc/<name>). Lets sshd read a custom user DB / shells without touching the host's.
const pathMap = {};
if (process.env.WALI_ETC) { try { for (const f of fs.readdirSync(process.env.WALI_ETC)) pathMap['/etc/' + f] = path.join(process.env.WALI_ETC, f); } catch {} }
// WALI_MAP="guest=real,guest2=real2" — map arbitrary guest paths (e.g. sshd's
// /usr/local/libexec/sshd-session) onto real files, for both open and execve.
if (process.env.WALI_MAP) for (const pair of process.env.WALI_MAP.split(',')) { const i = pair.indexOf('='); if (i > 0) pathMap[pair.slice(0, i)] = pair.slice(i + 1); }
const redir = (p) => pathMap[p] || p;

// ---- async stdin (JSPI): event-driven so a process reading stdin SUSPENDS instead
// of blocking the whole scheduler — required for live interactive sessions (ssh -t)
// where sshd/shell must run while the client waits for the next keystroke. ----
let stdinChunks = [], stdinEOF = false, stdinWaiters = [], stdinStarted = false;
function startStdin() {
  if (stdinStarted) return; stdinStarted = true;
  try { process.stdin.on('data', (d) => { stdinChunks.push(Buffer.from(d)); const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); });
        process.stdin.on('end', () => { stdinEOF = true; const w = stdinWaiters; stdinWaiters = []; for (const f of w) f(); }); } catch {}
}
function drainStdin(max) { // returns Buffer (empty = EOF) or null (would block)
  if (stdinChunks.length) { let b = Buffer.concat(stdinChunks); const take = b.subarray(0, max); const rest = b.subarray(take.length); stdinChunks = rest.length ? [Buffer.from(rest)] : []; return Buffer.from(take); }
  if (stdinEOF) return Buffer.alloc(0);
  return null;
}

// ---- one process = one instance + its syscall state ----
class Process {
  constructor(modPath, argv, env, fdTable, cwd) {
    this.modPath = modPath;
    this.argv = argv; this.env = env;
    this.fds = fdTable;              // Map fd -> handle
    this.nextFd = Math.max(3, ...[...fdTable.keys()].map(k => k + 1));
    this.cwd = { p: cwd || process.cwd() };
    this.pid = nextPid++;
    this.heapBrk = 0;
    this.childStack = [];            // active in-place child contexts
    this.dirState = new Map();
    this.pending = [];               // exit-parked children (sequential + non-exec)
    this.reaped = new Map();         // pid -> exit code, awaiting wait4
    this.childTasks = new Map();     // JSPI: pid -> in-flight concurrent task promise
    this.waitWaiters = [];           // JSPI: resolvers for a process suspended in wait4
    this.forkState = 'none';         // Asyncify fork: 'none' | 'unwinding' | 'rewinding'
    this.asyncifyBuf = 0; this.forkRet = 0n;
    this.syscalls = 0;
    this.pgid = this.pid;
    this.sig = { handlers: new Map(), mask: 0n, pending: new Set(), waiters: [] };
    this.timers = new Map();         // which(0=ITIMER_REAL) -> {deadline, intervalMs, to}
    this.lastYield = 0;              // JSPI preemption quantum bookkeeping
    this.stopped = 0;                // job control: stopping signal number, 0 = running
    this.stopReported = false; this.contWaiters = [];
    const u = process.env.WALI_UID !== undefined ? (+process.env.WALI_UID | 0) : 0; // root by default (sshd drops privs itself)
    this.cred = { uid: u, euid: u, suid: u, gid: u, egid: u, sgid: u, groups: [] };
    this.maps = new Map();           // MAP_SHARED file mappings: base -> {len, fd, off}
    this.shmAt = new Map();          // SysV shm attachments: base -> segment
    this.umask = 0o22;
    procs.set(this.pid, this);
  }

  msyncMap(base, m) { // write a MAP_SHARED file mapping back to its file
    try { this.refresh(); fs.writeSync(m.fd, this.u8, base, m.len, m.off); } catch {}
  }
  // shm coherence: 3-way byte merge between this process's view, its shadow
  // (last-synced), and the segment truth. Runs at every syscall boundary while
  // segments are attached — cross-process stores become visible at syscalls
  // (and at futex, which is where correct programs synchronize anyway).
  syncShmOne(base, at) {
    this.refresh();
    const local = this.u8.subarray(base, base + at.seg.size), truth = at.seg.buf, shadow = at.shadow;
    for (let i = 0; i < shadow.length; i++) {
      if (local[i] !== shadow[i]) { truth[i] = local[i]; shadow[i] = local[i]; }       // my write wins
      else if (truth[i] !== shadow[i]) { local[i] = truth[i]; shadow[i] = truth[i]; }  // pull theirs
    }
  }
  syncShm() { for (const [base, at] of this.shmAt) this.syncShmOne(base, at); }
  retire() {                         // process is gone: unregister + disarm timers
    for (const [base, m] of this.maps) this.msyncMap(base, m);            // flush shared file mappings
    try { this.syncShm(); } catch {}                                      // flush shm
    procs.delete(this.pid);
    for (const t of this.timers.values()) if (t.to) clearTimeout(t.to);
    this.timers.clear();
    const w = this.sig.waiters; this.sig.waiters = []; for (const f of w) f('sig');
  }

  // fire any expired timers (the sync model has no event loop while wasm runs,
  // so deadlines are also polled at every syscall boundary)
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
    if (JSPI) {                      // event-driven fire; sync model polls deadlines
      const fire = () => { postSignal(this, SIG.ALRM);
        if (t.intervalMs > 0) { t.deadline = Date.now() + t.intervalMs; t.to = setTimeout(fire, t.intervalMs); }
        else this.timers.delete(which); };
      t.to = setTimeout(fire, valueMs);
    }
    this.timers.set(which, t);
  }

  // deliver pending unblocked signals NOW (a syscall boundary). Returns null if
  // nothing to do, or a BigInt the current syscall must return (in-place vfork
  // child termination parks the child instead of throwing). Handlers with an
  // exported function table are invoked re-entrantly; otherwise default action.
  predeliver() {
    if (!this.sig.pending.size) return null;
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && (h.ptr === -2 || h.ptr === 1)) continue;     // SIG_IGN
      if (h && h.ptr > 1 && sig !== SIG.KILL) {
        const table = this.inst && this.inst.exports.__indirect_function_table;
        if (table) {
          try { table.get(h.ptr)(sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false; // !SA_RESTART
            continue; }
          catch (e) { process.stderr.write(`[wali-host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`); }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          process.stderr.write(`[wali-host] pid ${this.pid}: signal handler registered but binary lacks --export-table; using default action\n`); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;                // default-ignore
      if (SIG_STOPPERS.has(sig)) {                          // job control: park until SIGCONT
        if (JSPI && !this.inChild()) { this.stopped = sig; this.stopReported = false; }
        continue;                                           // (sync model: a stopped proc would deadlock — ignore)
      }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);                       // default-terminate
    }
    return null;
  }

  // Async signal delivery (JSPI): invoke the handler via WebAssembly.promising so a
  // handler that makes a blocking syscall can SUSPEND. table.get(ptr)(sig) called
  // directly re-enters wasm OUTSIDE a promising execution, where any Suspending
  // import (i.e. every syscall) throws "trying to suspend without WebAssembly.
  // promising" — even for a non-blocking call. Running the handler under its own
  // promising execution fixes it (verified: nested promising suspends correctly).
  async predeliverAsync() {
    if (!this.sig.pending.size) return null;
    for (const sig of [...this.sig.pending]) {
      if (this.sig.mask & (1n << BigInt(sig - 1))) continue;
      this.sig.pending.delete(sig);
      const h = this.sig.handlers.get(sig);
      if (h && (h.ptr === -2 || h.ptr === 1)) continue;     // SIG_IGN
      if (h && h.ptr > 1 && sig !== SIG.KILL) {
        const table = this.inst && this.inst.exports.__indirect_function_table;
        if (table) {
          const savedMask = this.sig.mask;
          this.sig.mask |= (1n << BigInt(sig - 1)) | BigInt(h.mask || 0n); // POSIX: block this signal (+ sa_mask) during its handler
          try { await WebAssembly.promising(table.get(h.ptr))(sig); this.sigDelivered = true;
            if (!(h.flags & 0x10000000)) this.sigAllRestart = false;
            continue; }
          catch (e) { if (e instanceof ExitError) throw e;   // a real exit()/default-action from the handler must propagate
            process.stderr.write(`[wali-host] signal handler trap pid ${this.pid} sig ${sig}: ${e}\n`); }
          finally { this.sig.mask = savedMask; }
        } else if (!this.warnedNoTable) { this.warnedNoTable = true;
          process.stderr.write(`[wali-host] pid ${this.pid}: signal handler registered but binary lacks --export-table; using default action\n`); }
      }
      if (SIG_DFL_IGNORE.has(sig)) continue;
      if (SIG_STOPPERS.has(sig)) { if (JSPI && !this.inChild()) { this.stopped = sig; this.stopReported = false; } continue; }
      if (this.inChild()) return this.parkChild({ exited: 128 + sig });
      throw new ExitError(128 + sig);
    }
    return null;
  }

  // race an event arm against signal arrival; resolves 'sig' or the armed value
  sigRace(arm) {
    return new Promise((res) => {
      let done = false; const fin = (v) => { if (!done) { done = true; res(v); } };
      arm(fin); this.sig.waiters.push(fin);
    });
  }
  // wake from a blocking syscall with 'sig': run handlers; null = resume waiting
  // (signal ignored, or all handlers had SA_RESTART and the call is restartable),
  // BigInt = value the syscall must return (park/EINTR).
  // POSIX: sleep/pause/poll are NEVER restarted — those sites pass restartable=false.
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
  nextTimerDeadline() {
    let d = 0;
    for (const t of this.timers.values()) if (t.deadline && (!d || t.deadline < d)) d = t.deadline;
    return d;
  }
  sleepMs(name, a) { // nanosleep/clock_nanosleep request in ms (handles TIMER_ABSTIME)
    const abs = name === 'clock_nanosleep' && (a[1] & 1);
    const tp = name === 'nanosleep' ? a[0] : a[2];
    if (!tp) return 0;
    const sec = Number(this.r64(tp)), ns = Number(this.r64(tp + 8));
    if (!abs) return sec * 1000 + ns / 1e6;
    const clk = a[0] | 0;
    const nowMs = (clk === 1 || clk === 4) ? (() => { const t = process.hrtime(); return t[0] * 1000 + t[1] / 1e6; })() : Date.now();
    return sec * 1000 + ns / 1e6 - nowMs;
  }
  wrTs(p, ms) { this.i64(p, BigInt(Math.floor(ms / 1000))); this.i64(p + 8, BigInt(Math.round((ms % 1000) * 1e6))); }
  wrItimer(p, which) { // itimerval {interval, value} as {i64 sec, i64 usec} pairs
    const t = this.timers.get(which);
    const iv = t ? t.intervalMs : 0, rem = t && t.deadline ? Math.max(0, t.deadline - Date.now()) : 0;
    this.i64(p, BigInt(Math.floor(iv / 1000))); this.i64(p + 8, BigInt(Math.round((iv % 1000) * 1000)));
    this.i64(p + 16, BigInt(Math.floor(rem / 1000))); this.i64(p + 24, BigInt(Math.round((rem % 1000) * 1000)));
  }
  pollTfd(t) { // sync model: fire an expired timerfd at this boundary
    if (!JSPI && t.deadline && Date.now() >= t.deadline) {
      t.count++;
      if (t.intervalMs > 0) t.deadline = Date.now() + t.intervalMs; else t.deadline = 0;
    }
  }

  refresh() { if (this.membuf !== this.memory.buffer) { this.membuf = this.memory.buffer; this.u8 = new Uint8Array(this.membuf); this.dv = new DataView(this.membuf); } }
  cstr(p) { this.refresh(); let e = p; while (this.u8[e] !== 0) e++; return Buffer.from(this.membuf, p, e - p).toString('utf8'); }
  wbytes(p, b) { this.refresh(); this.u8.set(b, p); }
  wstr(p, s, max) { const b = Buffer.from(s, 'utf8'); const n = max ? Math.min(b.length, max - 1) : b.length; this.wbytes(p, b.subarray(0, n)); this.u8[p + n] = 0; return n; }
  i64(p, v) { this.refresh(); this.dv.setBigInt64(p, BigInt(v), true); }
  i32(p, v) { this.refresh(); this.dv.setInt32(p, Number(v), true); }
  r32(p) { this.refresh(); return this.dv.getInt32(p, true); }
  r64(p) { this.refresh(); return this.dv.getBigInt64(p, true); }
  rPtrArray(p) { const out = []; for (;;) { const q = this.r32(p); if (!q) break; out.push(this.cstr(q)); p += 4; } return out; }
  rpath(s) { return redir(path.resolve(this.cwd.p, s)); }
  atPath(dirfd, s) {
    if (s.startsWith('/')) return redir(s);
    if ((dirfd | 0) === -100) return this.rpath(s);
    const h = this.fds.get(dirfd); return redir(h && h.path ? path.join(h.path, s) : path.resolve(this.cwd.p, s));
  }
  putStat(p, st) {
    this.refresh(); this.u8.fill(0, p, p + 144);
    this.i64(p, BigInt(st.dev || 1)); this.i64(p + 8, BigInt(st.ino || 1)); this.i64(p + 16, BigInt(st.nlink || 1));
    this.i32(p + 24, st.mode); this.i32(p + 28, st.uid ?? 1000); this.i32(p + 32, st.gid ?? 1000);
    this.i64(p + 40, BigInt(st.rdev || 0)); this.i64(p + 48, BigInt(st.size));
    this.i64(p + 56, BigInt(st.blksize || 4096)); this.i64(p + 64, BigInt(st.blocks || Math.ceil(st.size / 512)));
    const t = (o, ms) => { this.i64(p + o, BigInt(Math.floor(ms / 1000))); this.i64(p + o + 8, BigInt(Math.floor((ms % 1000) * 1e6))); };
    t(72, st.atimeMs ?? Date.now()); t(88, st.mtimeMs ?? Date.now()); t(104, st.ctimeMs ?? Date.now());
  }
  growPages(n) { this.refresh(); const b = this.membuf.byteLength; this.memory.grow(n); this.refresh(); return b; }

  // ---- child-record mode helpers ----
  inChild() { return this.childStack.length > 0; }
  parkChild(fill) {
    const ctx = this.childStack.pop();
    this.fds = ctx.savedFds;                // restore parent's view
    this.pending.push({ pid: ctx.pid, ...fill });
    return CHILD_DONE;
  }

  // ---- syscall implementations ----
  sys(name, a) {
    const S = this;
    switch (name) {
      case 'read': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined) {
          if (h.std !== 0) return err(E.BADF);
          if (JSPI) { startStdin(); const b = drainStdin(a[2]); if (b === null) return h.nonblock ? err(E.AGAIN) : 0n; S.wbytes(a[1], b); return BigInt(b.length); }
          const b = Buffer.alloc(a[2]); let got = 0;
          try { got = fs.readSync(0, b, 0, a[2], null); } catch (e) { if (e.code !== 'EAGAIN' && e.code !== 'EOF') return sysErr(e); }
          S.wbytes(a[1], b.subarray(0, got)); return BigInt(got);
        }
        if (h.fifo) { if (!h.fifo.chunks.length && h.nonblock && h.fifo.writers > 0) return err(E.AGAIN); const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.spair) { if (!h.spair.rd.chunks.length && h.nonblock && h.spair.rd.writers > 0) return err(E.AGAIN); const b = pipeRead(h.spair.rd, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.tfd) { const t = h.tfd; S.pollTfd(t); // timerfd: 8-byte expiration count
          while (!t.count) {
            if (h.nonblock || JSPI) return err(E.AGAIN); // JSPI blocking waits in sysAsync
            const nd = t.deadline || S.nextTimerDeadline();
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, nd ? Math.max(1, Math.min(nd - Date.now(), 3600000)) : 50);
            S.pollTfd(t); S.pollTimers();
            if (S.sig.pending.size) { const w = S.onSigWake(true); if (w !== null) return w; }
          }
          if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(t.count)); t.count = 0; return 8n; }
        if (h.devnull) return 0n;
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
          if (!q.length) return S.sigDelivered ? err(E.INTR) : err(E.AGAIN); // ^C at this boundary reads as EINTR
          const k = Math.min(q.length, a[2]); S.wbytes(a[1], Uint8Array.from(q.splice(0, k))); return BigInt(k); }
        if (h.sock) { const br = initSockBridge(); const r = br.call(br.OP.RECV, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res)); return BigInt(r.res); }
        if (h.fd === undefined) return err(E.BADF);
        if (h.pos === undefined) h.pos = 0;
        const b = Buffer.alloc(a[2]); let got;
        try { got = fs.readSync(h.fd, b, 0, a[2], h.pos); } catch (e) { return sysErr(e); }
        h.pos += got; S.wbytes(a[1], b.subarray(0, got)); return BigInt(got);
      }
      case 'write': { if ((a[2] | 0) < 0) return err(E.INVAL); // guard: negative size must not slice from the end
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.std !== undefined) { try { return BigInt(fs.writeSync(h.std === 0 ? 1 : h.std, S.u8, a[1], a[2])); } catch (e) { return sysErr(e); } }
        if (h.fifo) { if (h.fifo.readers <= 0) return err(E.PIPE); // no reader will ever come back
          h.fifo.chunks.push(Buffer.from(S.u8.slice(a[1], a[1] + a[2]))); wakePipe(h.fifo); return BigInt(a[2]); }
        if (h.spair) { if (h.spair.wr.readers <= 0) return err(E.PIPE); // peer end closed
          h.spair.wr.chunks.push(Buffer.from(S.u8.slice(a[1], a[1] + a[2]))); wakePipe(h.spair.wr); return BigInt(a[2]); }
        if (h.devnull) return BigInt(a[2]);
        if (h.pty !== undefined) { const p = ptys.get(h.pty); const b = S.u8.slice(a[1], a[1] + a[2]);
          if (h.master) ptyMasterWrite(p, b); else ptySlaveWrite(p, b); return BigInt(a[2]); }
        if (h.sock) { const br = initSockBridge(); const r = br.call(br.OP.SEND, h.sock.id, a[2], 0, S.u8.slice(a[1], a[1] + a[2])); return BigInt(r.res); }
        if (h.fd === undefined) return err(E.BADF);
        if (h.pos === undefined) h.pos = 0;
        try { const w = fs.writeSync(h.fd, S.u8, a[1], a[2], h.append ? undefined : h.pos); h.pos += w; return BigInt(w); } catch (e) { return sysErr(e); }
      }
      case 'writev': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('write', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; } return t; }
      case 'readv': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('read', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; if (Number(r) < l) break; } return t; }
      case 'open': return S.openAt(S.rpath(S.cstr(a[0])), a[1], a[2]);
      case 'openat': return S.openAt(S.atPath(a[0], S.cstr(a[1])), a[2], a[3]);
      case 'close': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fifo) { // drop this end's refcount; last writer closing => readers see EOF
          if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') { h.fifo.readers--; }
          S.fds.delete(a[0]); return 0n; }
        if (h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.tfd) { if (h.tfd.to) clearTimeout(h.tfd.to); const w = h.tfd.waiters; h.tfd.waiters = []; for (const f of w) f('t'); S.fds.delete(a[0]); return 0n; }
        if (h.sock && h.sock.id && !S.shared(h)) { const br = initSockBridge(); br.call(br.OP.CLOSE, h.sock.id, 0, 0); }
        else if (h.fd > 2 && !S.shared(h)) { try { fs.closeSync(h.fd); } catch {} }
        S.fds.delete(a[0]); S.dirState.delete(a[0]); return 0n; }
      case 'lseek': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock || h.pty !== undefined || h.devnull) return err(E.SPIPE);
        const size = h.dir ? 0 : fs.fstatSync(h.fd).size;
        h.pos = a[2] === 0 ? Number(a[1]) : a[2] === 1 ? (h.pos || 0) + Number(a[1]) : size + Number(a[1]);
        return BigInt(h.pos); }
      case 'fstat': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.pty !== undefined) { S.putStat(a[1], ptyStatObj(h.pty, h.master)); return 0n; } // char device (a tty)
        if (h.devnull) { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        if (h.std !== undefined || h.fifo || h.sock || h.spair) { S.putStat(a[1], { size: 0, mode: (h.fifo || h.sock || h.spair) ? 0o010600 : 0o020620 }); return 0n; }
        try { S.putStat(a[1], h.dir ? fs.statSync(h.path) : fs.fstatSync(h.fd)); return 0n; } catch (e) { return sysErr(e); } }
      case 'stat': case 'lstat': {
        const p = S.rpath(S.cstr(a[0]));
        if (p === '/proc/self/exe') { S.putStat(a[1], { size: 1, mode: 0o100755 }); return 0n; }
        let m; if (p === '/dev/ptmx') { S.putStat(a[1], ptyStatObj(0, true)); return 0n; }
        if ((m = p.match(/^\/dev\/pts\/(\d+)$/))) { if (!ptys.has(+m[1])) return err(E.NOENT); S.putStat(a[1], ptyStatObj(+m[1], false)); return 0n; }
        if (p === '/dev/null' || p === '/dev/tty') { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        try { S.putStat(a[1], name === 'stat' ? fs.statSync(p) : fs.lstatSync(p)); return 0n; } catch (e) { return sysErr(e); } }
      case 'newfstatat': { const s = S.cstr(a[1]); if (s === '') return S.sys('fstat', [a[0], a[2]]);
        const p = S.atPath(a[0], s);
        if (p === '/proc/self/exe') { S.putStat(a[2], { size: 1, mode: 0o100755 }); return 0n; }
        try { S.putStat(a[2], (a[3] & 0x100) ? fs.lstatSync(p) : fs.statSync(p)); return 0n; } catch (e) { return sysErr(e); } }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.rpath(S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        const want = name === 'access' ? (a[1] | 0) : (a[2] | 0); // F_OK=0 R=4 W=2 X=1
        if (p === '/proc/self/exe') return 0n;
        try { const st = fs.statSync(p);
          if (want && S.cred.euid !== 0) {
            const bits = (st.mode >> (st.uid === S.cred.euid ? 6 : 0)) & 7;
            if ((want & ~1) & ~bits) return err(E.ACCES); // X not enforced (wasm binaries are data)
          }
          return 0n;
        } catch (e) { return sysErr(e); } }
      case 'readlink': case 'readlinkat': { const p = name === 'readlink' ? S.rpath(S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        const bp = name === 'readlink' ? a[1] : a[2], bl = name === 'readlink' ? a[2] : a[3];
        // readlink: copy at most bl bytes, NO NUL terminator, return the count
        const put = (str) => { const b = Buffer.from(str, 'utf8'); const n = Math.min(b.length, bl); S.wbytes(bp, b.subarray(0, n)); return BigInt(n); };
        if (p === '/proc/self/exe') return put(S.modPath);
        let m2; if ((m2 = p.match(/^\/proc\/self\/fd\/(\d+)$/))) { // ttyname_r reads this
          const h = S.fds.get(+m2[1]); if (!h) return err(E.BADF);
          return put(h.pty !== undefined ? (h.master ? '/dev/ptmx' : '/dev/pts/' + h.pty) : h.path ? h.path : h.std !== undefined ? '/dev/tty' : '/dev/null'); }
        try { return put(fs.readlinkSync(p)); } catch (e) { return sysErr(e); } }
      case 'utimensat': case 'utimes': case 'futimesat': { // touch & friends set file times
        const UTIME_OMIT = 0x3ffffffe;
        const p = name === 'utimes' ? S.rpath(S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        const tp = name === 'utimes' ? a[1] : a[2];
        const now = Date.now() / 1000;
        let at = now, mt = now;
        if (tp) { S.refresh();
          if (name === 'utimes') { at = Number(S.r64(tp)) + Number(S.r64(tp + 8)) / 1e6; mt = Number(S.r64(tp + 16)) + Number(S.r64(tp + 24)) / 1e6; }
          else { const ts = (o) => { const s = Number(S.r64(tp + o)), ns = Number(S.r64(tp + o + 8)); return ns === UTIME_OMIT ? null : ns >= 0x3ffffffd ? now : s + ns / 1e9; };
            at = ts(0); mt = ts(16); } }
        try { const st = fs.statSync(p);
          fs.utimesSync(p, at === null ? st.atimeMs / 1000 : at, mt === null ? st.mtimeMs / 1000 : mt); return 0n;
        } catch (e) { return sysErr(e); } }
      case 'unlink': { try { fs.unlinkSync(S.rpath(S.cstr(a[0]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'rmdir': { try { fs.rmdirSync(S.rpath(S.cstr(a[0]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'mkdir': { try { fs.mkdirSync(S.rpath(S.cstr(a[0])), a[1]); return 0n; } catch (e) { return sysErr(e); } }
      case 'rename': { try { fs.renameSync(S.rpath(S.cstr(a[0])), S.rpath(S.cstr(a[1]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'chdir': { const p = S.rpath(S.cstr(a[0])); try { if (!fs.statSync(p).isDirectory()) return err(E.NOTDIR); S.cwd.p = p; return 0n; } catch (e) { return sysErr(e); } }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1);
      case 'chmod': { try { fs.chmodSync(S.rpath(S.cstr(a[0])), a[1]); return 0n; } catch (e) { return sysErr(e); } }
      case 'fchmodat': { try { fs.chmodSync(S.atPath(a[0], S.cstr(a[1])), a[2]); return 0n; } catch (e) { return sysErr(e); } }
      case 'fchmod': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fd === undefined) return 0n;
        try { fs.fchmodSync(h.fd, a[1]); return 0n; } catch (e) { return sysErr(e); } }
      case 'chown': case 'lchown': case 'fchown': case 'fchownat':
        return S.cred.euid === 0 ? 0n : err(E.PERM); // only root may chown (ownership itself is the host's)
      case 'umask': { const old = S.umask; S.umask = a[0] & 0o777; return BigInt(old); }
      case 'symlink': { try { fs.symlinkSync(S.cstr(a[0]), S.rpath(S.cstr(a[1]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'symlinkat': { try { fs.symlinkSync(S.cstr(a[0]), S.atPath(a[1], S.cstr(a[2]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'link': { try { fs.linkSync(S.rpath(S.cstr(a[0])), S.rpath(S.cstr(a[1]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'linkat': { try { fs.linkSync(S.atPath(a[0], S.cstr(a[1])), S.atPath(a[2], S.cstr(a[3]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'truncate': { try { fs.truncateSync(S.rpath(S.cstr(a[0])), Number(a[1])); return 0n; } catch (e) { return sysErr(e); } }
      case 'ftruncate': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fd === undefined) return err(E.INVAL);
        try { fs.ftruncateSync(h.fd, Number(a[1])); return 0n; } catch (e) { return sysErr(e); } }
      case 'fsync': case 'fdatasync': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fd !== undefined && h.fd > 2) { try { fs.fsyncSync(h.fd); } catch {} } return 0n; }
      case 'statfs': case 'fstatfs': { const p = a[1]; S.refresh();
        S.u8.fill(0, p, p + 120);
        S.i64(p, 0x858458f6n);            // f_type: ramfs
        S.i64(p + 8, 4096n);              // f_bsize
        S.i64(p + 16, 1n << 20n);         // f_blocks
        S.i64(p + 24, 1n << 19n);         // f_bfree
        S.i64(p + 32, 1n << 19n);         // f_bavail
        S.i64(p + 40, 1n << 16n);         // f_files
        S.i64(p + 48, 1n << 15n);         // f_ffree
        S.i64(p + 64, 255n);              // f_namelen
        S.i64(p + 72, 4096n);             // f_frsize
        return 0n; }
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true; const g = S.allocFd(); S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true;
        if (a[0] !== a[1]) { const old = S.fds.get(a[1]); if (old && old.fifo) { if (old.end === 'w') { if (--old.fifo.writers <= 0) wakePipe(old.fifo); } else old.fifo.readers--; } // dup2 closes the target first
          S.fds.set(a[1], { ...h }); S.bumpFifo(h); } return BigInt(a[1]); }
      case 'pipe': case 'pipe2': {
        const nb = name === 'pipe2' && !!(a[1] & 0x800); // O_NONBLOCK
        const fifo = mkPipe();
        const r = S.allocFd(); S.fds.set(r, { fifo, end: 'r', nonblock: nb });
        const w = S.allocFd(); S.fds.set(w, { fifo, end: 'w', nonblock: nb });
        S.i32(a[0], r); S.i32(a[0] + 4, w); return 0n; }

      // ---- process model ----
      case 'fork': case 'vfork': {
        const pid = nextPid++;
        const savedFds = S.fds;
        S.fds = new Map([...savedFds].map(([k, v]) => [k, { ...v, shared: true }]));
        for (const v of S.fds.values()) S.bumpFifo(v); // child inherits a ref on each pipe end
        S.childStack.push({ pid, savedFds });
        return BigInt(pid); }
      case 'execve': {
        const p = S.cstr(a[0]);
        const argv = S.rPtrArray(a[1]);
        const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) { // exec without fork: replace this process = run child, exit with its code
          const code = runProgram(p, argv, envp, S.fds, S.cwd.p, S.modPath, S.cred, S.pid);
          if (code === null) return err(E.NOENT);
          throw new ExitError(code);
        }
        const fdsnap = S.fds;
        if (JSPI) { // spawn the child as a CONCURRENT task; parent longjmps back and keeps running
          const ctx = S.childStack.pop(); S.fds = ctx.savedFds; // restore parent's fd view
          const childPid = ctx.pid;
          const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modPath, S.cred, childPid)
            .then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); postSignal(S, SIG.CHLD); wakeWaiters(S); });
          inflight.add(task); task.finally(() => inflight.delete(task));
          S.childTasks.set(childPid, task);
          return CHILD_DONE;
        }
        const r = S.parkChild({ exec: { path: p, argv, envp, fds: fdsnap, cwd: S.cwd.p, selfPath: S.modPath, cred: { ...S.cred } } });
        return r; }
      case 'exit': case 'exit_group': {
        if (S.inChild()) return S.parkChild({ exited: a[0] & 0xff });
        throw new ExitError(a[0]); }
      case 'wait4': {
        const want = a[0] | 0;
        // run parked children (FIFO) until we have something to report
        while (S.pending.length) {
          const c = S.pending.shift();
          if (c.exited !== undefined) { S.reaped.set(c.pid, c.exited); continue; }
          const code = runProgram(c.exec.path, c.exec.argv, c.exec.envp, c.exec.fds, c.exec.cwd, c.exec.selfPath, c.exec.cred, c.pid);
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
        const n = Math.ceil(a[1] / PAGE); const base = S.growPages(n);
        if (!(a[3] & 0x20)) { // file-backed
          const h = S.fds.get(a[4]); if (!h || h.fd === undefined) return err(E.BADF);
          const buf = Buffer.alloc(a[1]);
          const got = fs.readSync(h.fd, buf, 0, a[1], Number(a[5]));
          S.wbytes(base, buf.subarray(0, got));
          if (a[3] & 0x1) S.maps.set(base, { len: a[1], fd: h.fd, off: Number(a[5]) }); // MAP_SHARED: writeback at msync/munmap
        }
        return BigInt(base); }
      case 'pread64': { const h = S.fds.get(a[0]); if (!h || h.fd === undefined) return err(E.BADF);
        const b = Buffer.alloc(a[2]); let got = 0;
        try { got = fs.readSync(h.fd, b, 0, a[2], Number(a[3])); } catch (e) { return sysErr(e); }
        S.wbytes(a[1], b.subarray(0, got)); return BigInt(got); }
      case 'pwrite64': { const h = S.fds.get(a[0]); if (!h || h.fd === undefined) return err(E.BADF);
        S.refresh();
        try { return BigInt(fs.writeSync(h.fd, S.u8, a[1], a[2], Number(a[3]))); } catch (e) { return sysErr(e); } }
      case 'msync': { const m = S.maps.get(a[0] >>> 0); if (m) S.msyncMap(a[0] >>> 0, m); return 0n; }
      case 'munmap': { const m = S.maps.get(a[0] >>> 0); if (m) { S.msyncMap(a[0] >>> 0, m); S.maps.delete(a[0] >>> 0); } return 0n; }
      case 'mprotect': case 'madvise': return 0n;
      case 'shmget': { // key -> segment id; content lives host-side, snapshot in/out at attach/detach
        const key = a[0] | 0, size = a[1] >>> 0, flags = a[2] | 0;
        let seg = key !== 0 ? shmSegs.get(key) : null;
        if (!seg) {
          if (key !== 0 && !(flags & 0o1000)) return err(E.NOENT); // no IPC_CREAT
          seg = { id: nextShmId++, key, buf: Buffer.alloc(size), size };
          shmSegs.set(key || -seg.id, seg); shmById.set(seg.id, seg);
        }
        return BigInt(seg.id); }
      case 'shmat': { const seg = shmById.get(a[0] | 0); if (!seg) return err(E.INVAL);
        const base = S.growPages(Math.ceil(seg.size / PAGE));
        S.wbytes(base, seg.buf);
        S.shmAt.set(base, { seg, shadow: Buffer.from(seg.buf) }); // shadow = last-synced view (3-way merge)
        return BigInt(base); }
      case 'shmdt': { const base = a[0] >>> 0; const at = S.shmAt.get(base); if (!at) return err(E.INVAL);
        S.syncShmOne(base, at);
        S.shmAt.delete(base); return 0n; }
      case 'futex': { // uaddr, op, val, timeout — real cross-process wait/wake on shm addresses
        const uaddr = a[0] >>> 0, fop = a[1] & 0x7f, val = a[2] | 0;
        S.refresh(); S.syncShm();
        let at = null, base = 0;
        for (const [b, x] of S.shmAt) if (uaddr >= b && uaddr < b + x.seg.size) { at = x; base = b; break; }
        if (fop === 0 || fop === 9) { // FUTEX_WAIT / WAIT_BITSET
          if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
          if (!at || JSPI) return 0n; // private single-threaded: spurious wakeup is legal; JSPI waits in sysAsync
          for (let spins = 0; spins < 200; spins++) { // sync model: sliced poll of the shared value
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
            S.pollTimers(); S.syncShm();
            if (S.dv.getInt32(uaddr, true) !== val) return 0n;
            if (S.sig.pending.size) { const w = S.onSigWake(false); if (w !== null) return w; }
          }
          return err(E.AGAIN); }
        if (fop === 1 || fop === 10) { // FUTEX_WAKE / WAKE_BITSET
          if (!at) return 0n;
          const off = uaddr - base, wl = at.seg.waiters && at.seg.waiters.get(off);
          let n = 0;
          if (wl) while (wl.length && n < val) { wl.shift()('wake'); n++; }
          return BigInt(n); }
        return 0n; }
      case 'shmctl': { if ((a[1] | 0) === 0) { const seg = shmById.get(a[0] | 0); if (seg) { shmById.delete(seg.id); shmSegs.delete(seg.key || -seg.id); } } return 0n; } // IPC_RMID
      case 'mremap': { if (a[2] <= a[1]) return BigInt(a[0]);
        const b = Number(S.sys('mmap', [0, a[2], 3, 0x22, -1, 0n])); S.refresh(); S.u8.copyWithin(b, a[0], a[0] + a[1]); return BigInt(b); }
      case 'getdents64': {
        const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF);
        let st = S.dirState.get(a[0]);
        if (!st) { st = { names: ['.', '..', ...fs.readdirSync(h.path)], pos: 0 }; S.dirState.set(a[0], st); }
        let off = 0;
        while (st.pos < st.names.length) {
          const nm = st.names[st.pos]; const nb = Buffer.from(nm, 'utf8');
          const reclen = (19 + nb.length + 1 + 7) & ~7;
          if (off + reclen > a[2]) break;
          let type = 8; try { const s = fs.lstatSync(path.join(h.path, nm)); type = s.isDirectory() ? 4 : s.isSymbolicLink() ? 10 : 8; } catch {}
          S.i64(a[1] + off, 1n); S.i64(a[1] + off + 8, BigInt(st.pos + 1));
          S.refresh(); S.dv.setUint16(a[1] + off + 16, reclen, true); S.u8[a[1] + off + 18] = type;
          S.wbytes(a[1] + off + 19, nb); S.u8[a[1] + off + 19 + nb.length] = 0;
          off += reclen; st.pos++;
        }
        return BigInt(off); }
      case 'ioctl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); S.refresh();
        const req = a[1] >>> 0;
        if (h.pty !== undefined) { const p = ptys.get(h.pty);
          switch (req) {
            case 0x5401: S.wbytes(a[2], p.termios); return 0n;                 // TCGETS
            case 0x5402: case 0x5403: case 0x5404:                              // TCSETS/W/F
              p.termios = Buffer.from(S.u8.slice(a[2], a[2] + 60)); return 0n;
            case 0x5413: S.dv.setUint16(a[2], p.rows, true); S.dv.setUint16(a[2] + 2, p.cols, true); S.i32(a[2] + 4, 0); return 0n; // TIOCGWINSZ
            case 0x5414: p.rows = S.dv.getUint16(a[2], true); p.cols = S.dv.getUint16(a[2] + 2, true); return 0n; // TIOCSWINSZ
            case 0x80045430: S.i32(a[2], h.pty); return 0n;                    // TIOCGPTN
            case 0x40045431: return 0n;                                        // TIOCSPTLCK (unlock)
            case 0x540e: S.ctty = h.pty; return 0n;                            // TIOCSCTTY
            case 0x540f: S.i32(a[2], p.pgrp || S.pid); return 0n;              // TIOCGPGRP
            case 0x5410: p.pgrp = S.r32(a[2]); return 0n;                      // TIOCSPGRP
            case 0x40045441: { const g = S.allocFd(); S.fds.set(g, { pty: h.pty, master: false }); return BigInt(g); } // TIOCGPTPEER
            default: return 0n;
          }
        }
        if (h.std === undefined) return err(E.NOTTY);
        if (req === 0x5413) { S.dv.setUint16(a[2], 24, true); S.dv.setUint16(a[2] + 2, 80, true); S.i32(a[2] + 4, 0); } // TIOCGWINSZ on stdio
        if (req === 0x5401) S.wbytes(a[2], defaultTermios()); // TCGETS on stdio -> looks like a tty
        return 0n; }
      case 'fcntl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[1] === 0 || a[1] === 1030) { // F_DUPFD / F_DUPFD_CLOEXEC: honor min-fd hint
          const min = Number(a[2]) || 0;
          let g = min; while (S.fds.has(g)) g++; // F_DUPFD: lowest free >= min
          h.shared = true; S.fds.set(g, { ...h }); S.bumpFifo(h); return BigInt(g);
        }
        if (a[1] === 3) return BigInt(2 | (h.nonblock ? 0x800 : 0)); // F_GETFL: O_RDWR | O_NONBLOCK?
        if (a[1] === 4) { h.nonblock = !!(Number(a[2]) & 0x800); return 0n; } // F_SETFL: track O_NONBLOCK
        return 0n; }
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const t = process.hrtime(); S.i64(a[1], BigInt(t[0])); S.i64(a[1] + 8, BigInt(t[1])); return 0n; }
        const ms = Date.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt((ms % 1000) * 1e6)); return 0n; }
      case 'gettimeofday': { const ms = Date.now(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt((ms % 1000) * 1000)); return 0n; }
      case 'nanosleep': case 'clock_nanosleep': { // sync model: sliced sleep so timers fire and signals interrupt (EINTR)
        S.refresh();
        let ms = S.sleepMs(name, a);
        const end = Date.now() + ms;
        while (ms > 0) {
          const nd = S.nextTimerDeadline();
          const slice = Math.min(ms, 50, nd ? Math.max(1, nd - Date.now()) : 1e12, 3600000);
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, slice);
          S.pollTimers();
          if (S.sig.pending.size) { S.sigDelivered = false; const dv = S.predeliver(); if (dv !== null) return dv; if (S.sigDelivered) return err(E.INTR); }
          ms = end - Date.now();
        }
        return 0n; }
      case 'pause': case 'sigsuspend': case 'rt_sigsuspend': { // sync model: sliced wait for a signal
        const oldMask = S.sig.mask;
        if (name !== 'pause' && a[0]) { S.refresh(); S.sig.mask = BigInt.asUintN(64, S.r64(a[0])); }
        try {
          for (;;) {
            if (S.sig.pending.size) { S.sigDelivered = false; const dv = S.predeliver(); if (dv !== null) return dv; if (S.sigDelivered) return err(E.INTR); }
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
            S.pollTimers();
          }
        } finally { S.sig.mask = oldMask; } }
      case 'clock_getres': { if (a[1]) { S.i64(a[1], 0n); S.i64(a[1] + 8, 1000000n); } return 0n; }
      case 'times': { if (a[0]) { S.refresh(); S.u8.fill(0, a[0], a[0] + 16); } return BigInt(Math.floor(performance.now() / 10) & 0x7fffffff); }
      case 'setitimer': { const which = a[0] | 0; S.refresh();
        if (a[2]) S.wrItimer(a[2], which);
        if (a[1] && which === 0) { // ITIMER_REAL only (itimerval = two {i64 sec, i64 usec})
          const ivMs = Number(S.r64(a[1])) * 1000 + Number(S.r64(a[1] + 8)) / 1000;
          const vMs = Number(S.r64(a[1] + 16)) * 1000 + Number(S.r64(a[1] + 24)) / 1000;
          S.armItimer(0, vMs, ivMs);
        }
        return 0n; }
      case 'getitimer': { if (a[1]) { S.refresh(); S.wrItimer(a[1], a[0] | 0); } return 0n; }
      case 'timerfd_create': { const g = S.allocFd ? S.allocFd() : S.nextFd++;
        S.fds.set(g, { tfd: { count: 0, deadline: 0, intervalMs: 0, to: null, waiters: [] }, nonblock: !!(a[1] & 0x800) });
        return BigInt(g); }
      case 'timerfd_settime': { const h = S.fds.get(a[0]); if (!h || !h.tfd) return err(E.BADF);
        S.refresh(); const t = h.tfd;
        if (a[3]) { S.wrTs(a[3], t.intervalMs); S.wrTs(a[3] + 16, t.deadline ? Math.max(0, t.deadline - Date.now()) : 0); }
        const ivMs = Number(S.r64(a[2])) * 1000 + Number(S.r64(a[2] + 8)) / 1e6;
        let vMs = Number(S.r64(a[2] + 16)) * 1000 + Number(S.r64(a[2] + 24)) / 1e6;
        if ((a[1] & 1) && vMs > 0) vMs -= Date.now(); // TFD_TIMER_ABSTIME (realtime)
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
      case 'uname': { ['Linux', 'wali', '6.1.0-wali', '#1 WALI-js', 'wasm32', ''].forEach((s, i) => S.wstr(a[name === 'uname' ? 0 : 2] + i * 65, s, 65)); return 0n; }
      case 'getuid': return BigInt(S.cred.uid); case 'geteuid': return BigInt(S.cred.euid);
      case 'getgid': return BigInt(S.cred.gid); case 'getegid': return BigInt(S.cred.egid);
      case 'setuid': { const u = a[0] | 0; // root drops all ids; others may only toggle to real uid
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
      case 'chroot': return 0n; // no real chroot; sshd privsep chroots to /var/empty — treat as success
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
        if (name === 'kill' && pid <= 0) {                    // process group / broadcast
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
        if (a[1]) { S.sig.handlers.set(sig, { ptr: S.r32(a[1]), flags: S.r32(a[1] + 4) }); if (process.env.WALI_DBG_SIG) process.stderr.write(`[sig] pid ${S.pid} sigaction(${sig}) ptr=${S.r32(a[1])} flags=0x${(S.r32(a[1]+4)>>>0).toString(16)}
`); }
        return 0n; }
      case 'rt_sigprocmask': { const how = a[0] | 0; S.refresh();
        if (a[2]) S.i64(a[2], BigInt.asIntN(64, S.sig.mask));
        if (a[1]) { const m = BigInt.asUintN(64, S.r64(a[1]));
          if (how === 0) S.sig.mask |= m; else if (how === 1) S.sig.mask &= ~m; else S.sig.mask = m;
          if (S.sig.pending.size && !JSPI) { const dv = S.predeliver(); if (dv !== null) return dv; } } // unblocking delivers
        return 0n; }
      case 'rt_sigpending': { S.refresh(); let m = 0n; for (const s of S.sig.pending) m |= 1n << BigInt(s - 1); S.i64(a[0], BigInt.asIntN(64, m)); return 0n; }
      case 'sigaltstack': case 'prctl': case 'rt_sigreturn': return 0n;
      case 'sched_getaffinity': { S.i64(a[2], 1n); return 8n; }
      case 'sched_yield': return 0n;
      // RLIMIT_NOFILE (res 7) MUST be small: closefrom()/close-all-fds loops up to it.
      case 'prlimit64': { const res = a[1] | 0, v = res === 7 ? 1024n : 0x800000n; if (a[3]) { S.i64(a[3], v); S.i64(a[3] + 8, v); } return 0n; }
      case 'getrlimit': { const res = a[0] | 0, v = res === 7 ? 1024n : 0x800000n; S.i64(a[1], v); S.i64(a[1] + 8, v); return 0n; }
      case 'setrlimit': return 0n;
      case 'close_range': { const first = a[0] >>> 0, last = a[1] >>> 0;
        for (const fd of [...S.fds.keys()]) if (fd >= first && fd <= last) S.sys('close', [fd]); return 0n; }
      case 'getrusage': { S.refresh(); S.u8.fill(0, a[1], a[1] + 144); return 0n; }
      case 'sysinfo': { S.refresh(); S.u8.fill(0, a[0], a[0] + 112); S.i64(a[0], 1000n); S.i64(a[0] + 32, 4294967296n); S.i64(a[0] + 40, 2147483648n); return 0n; }
      case 'getrandom': { const b = require('crypto').randomBytes(Math.min(a[1], 65536)); S.wbytes(a[0], b); return BigInt(b.length); }
      case 'poll': { S.refresh(); let ready = 0; // pollfd: fd(i32) events(i16) revents(i16), stride 8
        for (let i = 0; i < a[1]; i++) {
          const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
          const h = S.fds.get(fd); let re = 0;
          if (h && h.sock && h.sock.id) { const pk = initSockBridge().call(initSockBridge().OP.POLL, h.sock.id, 0, 0);
            if ((ev & 1) && pk.res > 0) re |= 1; if (ev & 4) re |= 4; } // POLLIN if data, POLLOUT always
          else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
            if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; } // pty: POLLIN if data buffered
          else if (h && h.spair) { if ((ev & 1) && (h.spair.rd.chunks.length || h.spair.rd.writers <= 0)) re |= 1; if (ev & 4) re |= 4; }
          else if (fd < 0) re = 0; // POSIX: negative fds are ignored
          else if (!h) re = 0x20; // POLLNVAL
          else re = ev & 5; // stdio/pipe/file: ready
          S.dv.setInt16(a[0] + i * 8 + 6, re, true); if (re) ready++;
        }
        return BigInt(ready); }
      case 'select': case 'pselect6': return 1n;
      case 'socket': { // AF_INET(2)/AF_INET6(10); SOCK_STREAM(1) or SOCK_DGRAM(2)
        const dom = a[0] & 0xff, type = a[1] & 0xff; const nonblock = !!(a[1] & 0x800); // SOCK_NONBLOCK
        if (dom !== 2 && dom !== 10) return err(E.NOSYS);
        if (type === 2) { const br = initSockBridge(); const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, dom, udp: true, nonblock } }); return BigInt(g); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: 0, dom, nonblock } }); return BigInt(g); }
      case 'socketpair': { // AF_UNIX full-duplex pair = two cross-connected fifos
        const nb = !!(a[1] & 0x800); // SOCK_NONBLOCK
        const f1 = mkPipe(), f2 = mkPipe();
        const A = S.allocFd(); S.fds.set(A, { spair: { rd: f2, wr: f1 }, nonblock: nb }); // A reads what B wrote
        const B = S.allocFd(); S.fds.set(B, { spair: { rd: f1, wr: f2 }, nonblock: nb });
        S.i32(a[3], A); S.i32(a[3] + 4, B); return 0n; }
      case 'bind': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh(); h.sock.bindAddr = readSockaddr(S, a[1]); return 0n; } // UDP auto-binds ephemeral in the bridge
      case 'listen': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        const ba = h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        const br = initSockBridge();
        const spec = Buffer.from(`${ba.ip === '::' ? '0.0.0.0' : ba.ip}|${ba.port}`, 'utf8');
        const r = br.call(br.OP.LISTEN, spec.length, 0, 0, spec);
        if (r.res < 0) return BigInt(r.res);
        h.sock.id = r.res; h.sock.listener = true; h.sock.boundPort = r.aux;
        return 0n; }
      case 'accept': case 'accept4': { const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        const br = initSockBridge();
        const r = br.call(br.OP.ACCEPT, h.sock.id, (h.nonblock || h.sock.nonblock || JSPI) ? 1 : 0, 0);
        if (r.res < 0) return BigInt(r.res); // EAGAIN under JSPI: sysAsync loops with suspends
        S.refresh();
        const [pip, pport] = Buffer.from(r.data.subarray(0, r.aux)).toString('utf8').split('|');
        if (a[1]) { const n = writeSockaddr(S, a[1], { ip: (pip || '0.0.0.0').replace(/^::ffff:/, ''), port: +pport || 0 }); if (a[2]) S.i32(a[2], n); }
        const g = S.allocFd(); S.fds.set(g, { sock: { id: r.res, dom: h.sock.dom, nonblock: !!(a[3] & 0x800) } });
        return BigInt(g); }
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh();
        const dst = readSockaddr(S, a[1]);
        if (h.sock.udp) { h.sock.dest = dst; return 0n; } // UDP connect = remember peer, no TCP
        const br = initSockBridge();
        const spec = Buffer.from(`${dst.ip}|${dst.port}`, 'utf8');
        const r = br.call(br.OP.CONNECT, spec.length, 0, 0, spec);
        if (r.res < 0) return BigInt(r.res);
        h.sock.id = r.res; return 0n; }
      case 'sendto': case 'sendmsg': case 'write_sock': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh(); // AF_UNIX socketpair, incl. SCM_RIGHTS fd passing (sshd privsep)
          let payload;
          if (name === 'sendmsg') {
            const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
            for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(Buffer.from(S.u8.slice(p, p + l))); }
            payload = Buffer.concat(parts);
            const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24); // wasm32-wali: long=64b padding shifts these
            if (ctl && ctllen >= 16) { const clen = S.r32(ctl), lvl = S.r32(ctl + 8), typ = S.r32(ctl + 12);
              if (lvl === 1 && typ === 1) { const nf = (clen - 16) >> 2; h.spair.wr.fds = h.spair.wr.fds || []; // SCM_RIGHTS, data @ctl+16
                for (let i = 0; i < nf; i++) { const fd = S.r32(ctl + 16 + i * 4); const hh = S.fds.get(fd); if (hh) { h.spair.wr.fds.push({ ...hh, shared: true }); S.bumpFifo(hh); } } } }
          } else payload = Buffer.from(S.u8.slice(a[1], a[1] + a[2]));
          h.spair.wr.chunks.push(payload); wakePipe(h.spair.wr);
          if (process.env.WALI_DBG) process.stderr.write(`[spair] p${S.pid} send ${payload.length}B fds=${(h.spair.wr.fds || []).length}\n`);
          return BigInt(payload.length);
        }
        if (!h.sock) return err(E.BADF);
        const br = initSockBridge(); S.refresh();
        // gather payload + destination
        let payload, dest = h.sock.dest;
        if (name === 'sendmsg') {
          const nameptr = S.r32(a[1]); if (nameptr) dest = readSockaddr(S, nameptr);
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); const parts = [];
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (l) parts.push(S.u8.slice(p, p + l)); }
          payload = Buffer.concat(parts.map(Buffer.from));
        } else { // sendto(fd, buf, len, flags, dest, addrlen)
          payload = Buffer.from(S.u8.slice(a[1], a[1] + a[2]));
          if (a[4]) dest = readSockaddr(S, a[4]);
        }
        if (process.env.WALI_DBG) process.stderr.write(`[dbg] ${name} udp=${!!h.sock.udp} dest=${JSON.stringify(dest)} qid=${payload.slice(0,2).toString('hex')} q=${payload.slice(0,Math.min(payload.length,32)).toString('hex')}\n`);
        if (h.sock.udp) {
          if (!dest) return err(E.INVAL);
          h.sock.lastDest = dest; // remember peer so recvmsg can report the source (musl checks it)
          const addr = Buffer.from(`${dest.ip}|${dest.port}`, 'utf8');
          const packed = new Uint8Array(payload.length + addr.length); packed.set(payload, 0); packed.set(addr, payload.length);
          const r = br.call(br.OP.SENDTO, h.sock.id, payload.length, addr.length, packed);
          return BigInt(r.res);
        }
        const r = br.call(br.OP.SEND, h.sock.id, payload.length, 0, payload);
        return BigInt(r.res); }
      case 'recvmsg': case 'recvfrom': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.spair) { S.refresh(); // socketpair recv, incl. SCM_RIGHTS fd delivery
          if (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length)) {
            if (h.spair.rd.writers <= 0) return 0n;   // EOF
            if (h.nonblock) return err(E.AGAIN);       // (blocking case suspends in sysAsync)
          }
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
            const b = pipeRead(h.spair.rd, l); if (!b.length) break; S.wbytes(p, b); total += b.length; if (b.length < l) break; }
          const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24); // long=64b padding
          if (ctl && ctllen >= 16 && h.spair.rd.fds && h.spair.rd.fds.length) { // deliver one passed fd
            const hh = h.spair.rd.fds.shift(); const g = S.allocFd(); S.fds.set(g, hh);
            S.i32(ctl, 20); S.i32(ctl + 8, 1); S.i32(ctl + 12, 1); S.i32(ctl + 16, g); // cmsg_len=20, SOL_SOCKET, SCM_RIGHTS, fd@+16
            S.i32(a[1] + 24, 20);                       // msg_controllen
          } else if (ctl) S.i32(a[1] + 24, 0);
          if (process.env.WALI_DBG) process.stderr.write(`[spair] p${S.pid} recv ${total}B ctl=${ctl} ctllen=${ctllen} qfds=${(h.spair.rd.fds || []).length}\n`);
          return BigInt(total);
        }
        if (!h.sock) return err(E.BADF);
        const br = initSockBridge();
        const op = h.sock.udp ? br.OP.RECVFROM : br.OP.RECV;
        // nonblocking socket: don't block the bridge — peek readiness, EAGAIN if empty
        if (h.sock.nonblock) { const pk = br.call(br.OP.POLL, h.sock.id, 0, 0); if (pk.res <= 0) return err(E.AGAIN); }
        if (name === 'recvfrom') { const r = br.call(op, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res));
          if (a[4] && h.sock.lastDest) { const n = writeSockaddr(S, a[4], h.sock.lastDest); if (a[5]) S.i32(a[5], n); }
          return BigInt(r.res); }
        // recvmsg: fill msg_name (source addr) so musl's anti-spoof check passes
        const nameptr = S.r32(a[1]); if (nameptr && h.sock.lastDest) { const n = writeSockaddr(S, nameptr, h.sock.lastDest); S.i32(a[1] + 4, n); }
        const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 12); let total = 0;
        for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
          const r = br.call(op, h.sock.id, l, 0); if (r.res < 0) return total || BigInt(r.res);
          if (r.res === 0) break;
          if (process.env.WALI_DBG) process.stderr.write(`[dbg] recv ${r.res}B resp=${Buffer.from(r.data.subarray(0,Math.min(r.res,16))).toString('hex')}\n`);
          S.wbytes(p, r.data.subarray(0, r.res)); total += r.res; if (r.res < l) break; }
        return BigInt(total); }
      case 'getsockname': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh(); const ba = h.sock.bindAddr || { ip: '0.0.0.0', port: 0 };
        const n = writeSockaddr(S, a[1], { ip: ba.ip === '::' ? '0.0.0.0' : ba.ip, port: h.sock.boundPort || ba.port });
        if (a[2]) S.i32(a[2], n); return 0n; }
      case 'setsockopt': case 'getpeername': case 'shutdown': return 0n;
      case 'getsockopt': { // enough for ssh/curl: SO_ERROR=0 (connect succeeded), SO_TYPE by socket, else 0
        const level = a[1] | 0, opt = a[2] | 0, optval = a[3], optlen = a[4];
        if (optval) { let v = 0;
          if (level === 1 && opt === 3) { const h = S.fds.get(a[0]); v = (h && h.sock && (h.sock.udp || h.sock.icmp)) ? 2 : 1; } // SO_TYPE
          S.i32(optval, v); }
        if (optlen) S.i32(optlen, 4);
        return 0n; }
      default:
        if (!unknownSyscalls.has(name)) { unknownSyscalls.add(name); process.stderr.write(`[wali-host] ENOSYS SYS_${name}\n`); }
        return err(E.NOSYS);
    }
  }

  // ---- JSPI: async syscall path (only the blocking ones; the rest delegate to sys) ----
  async sysAsync(name, a) {
    const S = this;
    switch (name) {
      case 'read': case 'readv': {
        const h = S.fds.get(a[0]);
        if (h && h.std === 0 && !h.nonblock) { // stdin: suspend until a keystroke/line or EOF
          startStdin(); while (!stdinChunks.length && !stdinEOF) { pipeSuspends++;
            const w = await S.sigRace(res => stdinWaiters.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } }
          return S.sys(name, a);
        }
        if (h && h.pty !== undefined && !h.nonblock) { // pty read: suspend until the line discipline delivers
          const p = ptys.get(h.pty); const q = () => h.master ? p.toMaster : p.toSlave; const wl = h.master ? p.masterWaiters : p.slaveWaiters;
          while (!q().length) { pipeSuspends++;
            const w = await S.sigRace(res => wl.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } }
          return S.sys(name, a);
        }
        // nonblocking fds never suspend here — the program polls, and poll suspends
        if (h && h.fifo && !h.nonblock) { // blocking: suspend until data or last writer closes (EOF)
          while (!h.fifo.chunks.length && h.fifo.writers > 0) { pipeSuspends++;
            const w = await S.sigRace(res => h.fifo.readWaiters.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } }
          return S.sys(name, a);
        }
        if (h && h.spair && !h.nonblock) { // blocking socketpair: suspend until peer writes or closes
          while (!h.spair.rd.chunks.length && h.spair.rd.writers > 0) { pipeSuspends++;
            const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } }
          return S.sys(name, a);
        }
        if (h && h.tfd && !h.nonblock) { // blocking timerfd read: suspend until expiry
          while (!h.tfd.count) {
            const w = await S.sigRace(res => h.tfd.waiters.push(res));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
          }
          S.refresh(); if (a[2] < 8) return err(E.INVAL);
          S.i64(a[1], BigInt(h.tfd.count)); h.tfd.count = 0; return 8n;
        }
        return S.sys(name, a);
      }
      case 'nanosleep': case 'clock_nanosleep': { // interruptible (EINTR) + TIMER_ABSTIME
        S.refresh();
        const end = Date.now() + S.sleepMs(name, a);
        while (Date.now() < end) {
          const w = await S.sigRace(res => { setTimeout(() => res('t'), Math.min(end - Date.now(), 3600000)); });
          if (w === 'sig') { const v = await S.onSigWakeAsync(); if (v !== null) return v; }
        }
        return 0n;
      }
      case 'pause': case 'sigsuspend': case 'rt_sigsuspend': { // suspend until a signal is DELIVERED
        const oldMask = S.sig.mask;
        if (name !== 'pause' && a[0]) { S.refresh(); S.sig.mask = BigInt.asUintN(64, S.r64(a[0])); }
        try {
          for (;;) {
            if (S.sig.pending.size) { const v = await S.onSigWakeAsync(); if (v !== null) return v; }
            await S.sigRace(() => {});
          }
        } finally { S.sig.mask = oldMask; }
      }
      case 'recvmsg': {
        const h = S.fds.get(a[0]);
        if (h && h.spair && !h.nonblock) { // blocking fd-passing recv (sshd privsep): suspend until a msg/fd arrives
          while (!h.spair.rd.chunks.length && (!h.spair.rd.fds || !h.spair.rd.fds.length) && h.spair.rd.writers > 0) {
            pipeSuspends++;
            const w = await S.sigRace(res => h.spair.rd.readWaiters.push(() => res('ev')));
            if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
          }
        }
        return S.sys(name, a);
      }
      case 'futex': { // JSPI FUTEX_WAIT on a shm address: suspend until a cross-process WAKE (or value change/signal)
        const uaddr = a[0] >>> 0, fop = a[1] & 0x7f, val = a[2] | 0;
        if (fop !== 0 && fop !== 9) return S.sys(name, a);
        S.refresh(); S.syncShm();
        let at = null, base = 0;
        for (const [b, x] of S.shmAt) if (uaddr >= b && uaddr < b + x.seg.size) { at = x; base = b; break; }
        if (!at) return S.sys(name, a);
        if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
        const off = uaddr - base, seg = at.seg;
        if (!seg.waiters) seg.waiters = new Map();
        if (!seg.waiters.has(off)) seg.waiters.set(off, []);
        const w = await S.sigRace(res => { seg.waiters.get(off).push(res);
          const to = setTimeout(() => res('t'), 100); void to; }); // re-check periodically too
        S.syncShm();
        if (w === 'sig') { const v = await S.onSigWakeAsync(false); if (v !== null) return v; }
        return 0n;
      }
      case 'accept': case 'accept4': { // JSPI: probe + suspend so siblings run while we wait
        const h = S.fds.get(a[0]); if (!h || !h.sock || !h.sock.listener) return err(E.INVAL);
        for (;;) {
          const r = S.sys(name, a);
          if (r !== BigInt(-E.AGAIN) || h.nonblock || h.sock.nonblock) return r;
          const w = await S.sigRace(res => { setTimeout(() => res('t'), 20); });
          if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; }
        }
      }
      case 'wait4': return await S.wait4Async(a);
      case 'poll': case 'ppoll': return await S.pollAsync(name, a);
      case 'execve': {
        const p = S.cstr(a[0]);
        const argv = S.rPtrArray(a[1]);
        const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) { // exec-without-fork (e.g. sshd re-exec): run the replacement to completion, then exit with its code
          const code = await runProgramAsync(p, argv, envp, S.fds, S.cwd.p, S.modPath, S.cred, S.pid);
          if (code === null) return err(E.NOENT);
          throw new ExitError(code);
        }
        // fork+exec: spawn the child as a concurrent task; parent longjmps back
        const fdsnap = S.fds;
        const ctx = S.childStack.pop(); S.fds = ctx.savedFds; const childPid = ctx.pid;
        const task = runProgramAsync(p, argv, envp, fdsnap, S.cwd.p, S.modPath, S.cred, childPid)
          .then((code) => { S.reaped.set(childPid, code === null ? 127 : code); releaseFds(fdsnap); S.childTasks.delete(childPid); postSignal(S, SIG.CHLD); wakeWaiters(S); });
        inflight.add(task); task.finally(() => inflight.delete(task));
        S.childTasks.set(childPid, task);
        return CHILD_DONE;
      }
      default: return S.sys(name, a);
    }
  }
  async wait4Async(a) {
    const S = this; const want = a[0] | 0;
    while (S.pending.length) { const c = S.pending.shift(); if (c.exited !== undefined) S.reaped.set(c.pid, c.exited); } // exit-parked (non-exec) children
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
      const w = await S.sigRace(res => S.waitWaiters.push(() => res('ev'))); // suspend until a child finishes
      if (w === 'sig') { const v = await S.onSigWakeAsync(true); if (v !== null) return v; } // interruptible (sshd waits with SIGCHLD/EINTR)
    }
  }
  async pollAsync(name, a) {
    const S = this; const nfds = a[1];
    S.refresh();
    const timeout = name === 'poll' ? (a[2] | 0)
      : (a[2] ? Math.ceil(Number(S.r64(a[2])) * 1000 + Number(S.r64(a[2] + 8)) / 1e6) : -1); // ppoll: timespec or NULL=block
    const evalReady = () => { S.refresh(); let ready = 0; const waitFifos = []; const waitPtys = []; let waitStdin = false, waitSock = false;
      for (let i = 0; i < nfds; i++) {
        const fd = S.r32(a[0] + i * 8), ev = S.dv.getInt16(a[0] + i * 8 + 4, true);
        const h = S.fds.get(fd); let re = 0;
        if (h && h.std === 0) { startStdin(); const rdy = stdinChunks.length || stdinEOF; // real stdin readiness
          if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitStdin = true; }
        else if (h && h.fifo) { const rdy = h.fifo.chunks.length || h.fifo.writers <= 0;
          if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.fifo); }
        else if (h && h.spair) { const rdy = h.spair.rd.chunks.length || h.spair.rd.writers <= 0;
          if ((ev & 1) && rdy) re |= 1; if (ev & 4) re |= 4; if (!rdy) waitFifos.push(h.spair.rd); }
        else if (h && h.pty !== undefined) { const p = ptys.get(h.pty); const q = h.master ? p.toMaster : p.toSlave;
          if ((ev & 1) && q.length) re |= 1; if (ev & 4) re |= 4; if (!q.length) waitPtys.push(h.master ? p.masterWaiters : p.slaveWaiters); }
        else if (h && h.tfd) { S.pollTfd(h.tfd); if ((ev & 1) && h.tfd.count > 0) re |= 1; if (!h.tfd.count) waitPtys.push(h.tfd.waiters); }
        else if (h && h.sock && h.sock.id) { const pk = initSockBridge().call(initSockBridge().OP.POLL, h.sock.id, 0, 0); if ((ev & 1) && pk.res > 0) re |= 1; else if (ev & 1) waitSock = true; if (ev & 4) re |= 4; }
        else if (fd < 0) re = 0; // POSIX: negative fds are ignored
        else if (!h) re = 0x20; // POLLNVAL
        else re = ev & 5; // stdio/file: ready
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
        if (r.waitStdin) { startStdin(); stdinWaiters.push(() => fin(true)); }
        // A WISP socket has no event-driven waiter — re-poll it on a short ticker even
        // when another waiter is armed, else poll([socket, stdin]) misses socket data.
        let ms = r.waitSock ? 15 : ((!r.waitFifos.length && !r.waitPtys.length && !r.waitStdin) ? 50 : Infinity);
        ms = Math.min(ms, remaining);
        if (Number.isFinite(ms)) setTimeout(() => fin(false), ms);
      });
      if (woke === 'sig') { const v = await S.onSigWakeAsync(); if (v !== null) return v; }
    }
  }

  shared(h) { return h.shared; }
  allocFd() { let g = 0; while (this.fds.has(g)) g++; return g; } // POSIX: lowest free fd (sshd relies on open()==0 after closing stdio)
  // bump the refcount of a pipe end when its fd is duplicated (dup/dup2/fcntl/fork)
  bumpFifo(h) { if (h && h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') h.fifo.readers++; }
    else if (h && h.spair) { h.spair.wr.writers++; h.spair.rd.readers++; } }
  openAt(fp, flags, mode) {
    const O_DIRECTORY = 0o200000;
    const c = fs.constants;
    try {
      if (fp === '/proc/self/exe') fp = this.modPath;
      // PTY devices
      if (fp === '/dev/ptmx') { const id = newPty(); const g = this.allocFd(); this.fds.set(g, { pty: id, master: true }); return BigInt(g); }
      let m;
      if ((m = fp.match(/^\/dev\/pts\/(\d+)$/))) { const id = +m[1]; if (!ptys.has(id)) return err(E.NOENT); ptys.get(id).fg = this; const g = this.allocFd(); this.fds.set(g, { pty: id, master: false }); return BigInt(g); }
      if (fp === '/dev/tty') { let ptyId = this.ctty;  // controlling terminal (ssh/sudo/git read prompts here, not stdin)
        if (ptyId === undefined) for (const fd of [0, 1, 2]) { const h0 = this.fds.get(fd); if (h0 && h0.pty !== undefined) { ptyId = h0.pty; break; } }
        if (ptyId !== undefined && ptys.has(ptyId)) { const g = this.allocFd(); this.fds.set(g, { pty: ptyId, master: false }); return BigInt(g); } }
      if (fp === '/dev/null') { const g = this.allocFd(); this.fds.set(g, { devnull: true }); return BigInt(g); }
      const ex = fs.existsSync(fp) && fs.statSync(fp);
      if (ex && ex.isDirectory()) {
        if ((flags & 3) !== 0) return err(E.ISDIR);
        const g = this.allocFd(); this.fds.set(g, { fd: -1, path: fp, dir: true }); return BigInt(g);
      }
      if (flags & O_DIRECTORY) return err(E.NOTDIR);
      if (ex && this.cred.euid !== 0) { // non-root: enforce mode bits (owner/group/other class)
        const cls = ex.uid === this.cred.euid ? 6 : (ex.gid === this.cred.egid || (this.cred.groups || []).includes(ex.gid)) ? 3 : 0;
        const bits = (ex.mode >> cls) & 7;
        const acc = flags & 3;
        if ((acc !== 1 && !(bits & 4)) || (acc !== 0 && !(bits & 2))) return err(E.ACCES);
      }
      let o = (flags & 3) === 0 ? c.O_RDONLY : (flags & 3) === 1 ? c.O_WRONLY : c.O_RDWR;
      if (flags & 0o100) o |= c.O_CREAT; if (flags & 0o200) o |= c.O_EXCL;
      if (flags & 0o1000) o |= c.O_TRUNC;
      const fd = fs.openSync(fp, o, (mode || 0o666) & ~this.umask);
      const g = this.allocFd();
      this.fds.set(g, { fd, path: fp, pos: (flags & 0o2000) ? fs.fstatSync(fd).size : 0, append: !!(flags & 0o2000) });
      return BigInt(g);
    } catch (e) { return sysErr(e); }
  }

  makeImports(mod) {
    const wali = {};
    const S = this;
    const extra = {};
    // Asyncify-capable module (has the unwind/rewind controls wasm-opt --asyncify adds)?
    // If so, SYS_fork is implemented by unwinding the live stack into linear memory,
    // copying that memory into a child instance, and rewinding both to the fork point.
    S._asyncifyCap = WebAssembly.Module.exports(mod).some(e => e.name === 'asyncify_start_unwind');
    const needWasi = WebAssembly.Module.imports(mod).some(i => i.module === 'wasi_snapshot_preview1');
    const wasi = needWasi ? this.makeWasi() : null;
    for (const im of WebAssembly.Module.imports(mod)) {
      if (im.module === 'wasi_snapshot_preview1') {
        (extra.wasi_snapshot_preview1 = extra.wasi_snapshot_preview1 || {})[im.name] =
          wasi[im.name] || ((...a2) => { if (!unknownSyscalls.has('wasi.' + im.name)) { unknownSyscalls.add('wasi.' + im.name); process.stderr.write(`[wali-host] WASI stub ${im.name}\n`); } return 0; });
        continue;
      }
      if (im.module !== 'wali') {
        (extra[im.module] = extra[im.module] || {})[im.name] = (...a2) => {
          if (!unknownSyscalls.has(im.name)) { unknownSyscalls.add(im.name); process.stderr.write(`[wali-host] stub import ${im.module}.${im.name}\n`); }
          return -38n;
        };
        continue;
      }
      const name = im.name;
      if (name === '__init' || name === '__deinit') wali[name] = () => 0;
      else if (name === '__get_init_envfile') wali[name] = (buf, sz) => {
        if (!S.env.length) return 0;
        const f = path.join(require('os').tmpdir(), `wali_env_${S.pid}`);
        fs.writeFileSync(f, S.env.join('\n') + '\n');
        S.wstr(buf, f, sz); return 1;
      };
      else if (name === 'log_execution') { // wasm-opt --log-execution instrumentation: a hook at every
        // basic-block entry. This is the compute-loop preemption point: even a
        // syscall-free spin can deliver signals, park on SIGSTOP, and yield its
        // quantum. Opt-in per binary (build with farm/instrument-preempt.sh).
        // V8 traps ANY Suspending call outside a promising context, and shared-memory
        // links put an instrumented __wasm_init_memory in the START section — so
        // preempt-instrumented binaries must be linked WITHOUT --shared-memory
        // (see farm/instrument-preempt.sh). Under JSPI the slow path really
        // yields/parks; in the sync model it delivers signals and timers only.
        let fuel = 0;
        const check = () => {                          // shared fast-path body
          S.pollTimers();
          S.sigDelivered = false;
          const dv = S.predeliver(); if (dv !== null) return null;
          const now = Date.now();
          if (!S.stopped && now - S.lastYield < QUANTUM_MS) return null;
          return (async () => {                        // yield / park on SIGSTOP
            while (S.stopped) await new Promise(res => S.contWaiters.push(res));
            S.lastYield = Date.now();
            await new Promise(res => setImmediate(res));
            return 0;
          })();
        };
        wali[name] = JSPI
          ? new WebAssembly.Suspending(() => { if (++fuel & 0x3fff) return 0; return check() || 0; })
          : (() => { if (++fuel & 0x3fff) return; S.pollTimers(); if (S.sig.pending.size) { S.sigDelivered = false; S.predeliver(); } });
      }
      else if (name === '__cl_get_argc') wali[name] = () => S.argv.length;
      else if (name === '__cl_get_argv_len') wali[name] = (i) => Buffer.byteLength(S.argv[i] || '', 'utf8');
      else if (name === '__cl_copy_argv') wali[name] = (buf, i) => S.wstr(buf, S.argv[i] || '', 0);
      else if (name === '__proc_exit') wali[name] = (c2) => { throw new ExitError(c2); };
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
            d.setUint32(S.asyncifyBuf, S.asyncifyBuf + 8, true);              // current
            d.setUint32(S.asyncifyBuf + 4, S.asyncifyBuf + ASYNC_PAGES * PAGE, true); // end
            S.inst.exports.asyncify_start_unwind(S.asyncifyBuf);
            S.forkState = 'unwinding';
            return 0n; // dummy; the wasm now unwinds to _start
          };
        } else if (JSPI) { // every syscall is suspend-capable: the boundary where
          // pending signals deliver and the preemption quantum yields, so a
          // syscalling busy loop cannot starve its siblings.
          wali[name] = new WebAssembly.Suspending(async (...a2) => {
            S.syscalls++; syscallTotal++;
            S.pollTimers();
            if (S.shmAt.size) S.syncShm();          // shm coherence at every boundary
            S.sigDelivered = false;
            const dv = await S.predeliverAsync(); if (dv !== null) return dv;   // handlers run under promising
            while (S.stopped) { await new Promise(res => S.contWaiters.push(res)); // SIGSTOP parks here until SIGCONT
              const dv2 = await S.predeliverAsync(); if (dv2 !== null) return dv2; }
            const now = Date.now();
            if (now - S.lastYield >= QUANTUM_MS) { S.lastYield = now; await new Promise(res => setImmediate(res)); }
            const r = BLOCKING.has(sysname) ? await S.sysAsync(sysname, map(a2)) : S.sys(sysname, map(a2));
            if (process.env.WALI_TRACE) process.stderr.write(`[p${S.pid}:${S.syscalls}] ${sysname}(${a2.join(',')}) = ${r} (async)\n`);
            return r;
          });
        } else {
          wali[name] = (...a2) => {
            S.syscalls++; syscallTotal++;
            S.pollTimers();
            if (S.shmAt.size) S.syncShm();          // shm coherence at every boundary
            S.sigDelivered = false;
            const dv = S.predeliver(); if (dv !== null) return dv;
            const r = S.sys(sysname, map(a2));
            if (process.env.WALI_TRACE) process.stderr.write(`[p${S.pid}:${S.syscalls}] ${sysname}(${a2.join(',')}) = ${r}\n`);
            return r;
          };
        }
      } else wali[name] = () => 0n;
    }
    return { wali, ...extra };
  }

  // ---- WASI preview1 shim: lets the OS run standard wasm32-wasi binaries
  //      (the whole prebuilt-wasi ecosystem, and the eventual clang.wasm) ----
  makeWasi() {
    const S = this;
    const W = { OK: 0, BADF: 8, NOENT: 44 };
    const iovs = (ptr, n) => { const r = []; for (let i = 0; i < n; i++) { r.push([S.r32(ptr + i * 8), S.r32(ptr + i * 8 + 4)]); } return r; };
    return {
      proc_exit: (code) => { throw new ExitError(code); },
      fd_write: (fd, iptr, icnt, nptr) => { S.refresh(); let tot = 0;
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue;
          if (fd === 1 || fd === 2) { try { tot += fs.writeSync(fd, S.u8, p, l); } catch { return W.BADF; } }
          else { const h = S.fds.get(fd); if (!h || h.fd === undefined) return W.BADF; if (h.pos === undefined) h.pos = 0; const w = fs.writeSync(h.fd, S.u8, p, l, h.pos); h.pos += w; tot += w; } }
        S.i32(nptr, tot); return W.OK; },
      fd_read: (fd, iptr, icnt, nptr) => { S.refresh(); let tot = 0;
        for (const [p, l] of iovs(iptr, icnt)) { if (!l) continue; const b = Buffer.alloc(l); let got = 0;
          const h = S.fds.get(fd);
          try { if (fd === 0) got = fs.readSync(0, b, 0, l, null); else { if (!h || h.fd === undefined) return W.BADF; if (h.pos === undefined) h.pos = 0; got = fs.readSync(h.fd, b, 0, l, h.pos); h.pos += got; } }
          catch (e) { if (e.code !== 'EOF' && e.code !== 'EAGAIN') return W.BADF; }
          S.wbytes(p, b.subarray(0, got)); tot += got; if (got < l) break; }
        S.i32(nptr, tot); return W.OK; },
      fd_close: (fd) => { const h = S.fds.get(fd); if (h && h.fd > 2) { try { fs.closeSync(h.fd); } catch {} } S.fds.delete(fd); return W.OK; },
      fd_seek: (fd, off, whence, nptr) => { const h = S.fds.get(fd); if (!h || h.fd === undefined) return W.BADF;
        const size = fs.fstatSync(h.fd).size; if (h.pos === undefined) h.pos = 0;
        h.pos = whence === 0 ? Number(off) : whence === 1 ? h.pos + Number(off) : size + Number(off);
        S.i64 ? S.i64(nptr, BigInt(h.pos)) : S.dv.setBigInt64(nptr, BigInt(h.pos), true); return W.OK; },
      fd_fdstat_get: (fd, ptr) => { S.refresh(); S.u8.fill(0, ptr, ptr + 24); S.u8[ptr] = (fd <= 2) ? 2 : 4; /* filetype char/reg */ return W.OK; },
      fd_prestat_get: (fd, ptr) => { const h = S.fds.get(fd); if (h && h.preopen) { S.u8[ptr] = 0; S.i32(ptr + 4, h.preopen.length); return W.OK; } return W.BADF; },
      fd_prestat_dir_name: (fd, ptr, len) => { const h = S.fds.get(fd); if (!h || !h.preopen) return W.BADF; S.wbytes(ptr, Buffer.from(h.preopen).subarray(0, len)); return W.OK; },
      path_open: (dirfd, df, pptr, plen, oflags, rights, rights2, fdflags, fdptr) => {
        const name = Buffer.from(S.u8.slice(pptr, pptr + plen)).toString('utf8');
        const h = S.fds.get(dirfd); const base = h && h.preopen ? h.preopen : S.cwd.p;
        try { const fd = fs.openSync(path.resolve(base, name), (oflags & 1) ? 'w' : 'r'); const g = S.allocFd(); S.fds.set(g, { fd, pos: 0 }); S.i32(fdptr, g); return W.OK; } catch { return W.NOENT; } },
      environ_sizes_get: (cptr, sptr) => { S.i32(cptr, S.env.length); S.i32(sptr, S.env.reduce((a, e) => a + Buffer.byteLength(e) + 1, 0)); return W.OK; },
      environ_get: (eptr, bptr) => { let b = bptr; for (const e of S.env) { S.i32(eptr, b); eptr += 4; b += S.wstr(b, e, 0) + 1; } return W.OK; },
      args_sizes_get: (cptr, sptr) => { S.i32(cptr, S.argv.length); S.i32(sptr, S.argv.reduce((a, e) => a + Buffer.byteLength(e) + 1, 0)); return W.OK; },
      args_get: (aptr, bptr) => { let b = bptr; for (const a of S.argv) { S.i32(aptr, b); aptr += 4; b += S.wstr(b, a, 0) + 1; } return W.OK; },
      clock_time_get: (id, prec, ptr) => { const ns = BigInt(Date.now()) * 1000000n; S.dv.setBigInt64(ptr, ns, true); return W.OK; },
      random_get: (ptr, len) => { const b = require('crypto').randomBytes(len); S.wbytes(ptr, b); return W.OK; },
      fd_fdstat_set_flags: () => W.OK, fd_sync: () => W.OK, fd_datasync: () => W.OK,
      sched_yield: () => W.OK, poll_oneoff: () => W.OK,
    };
  }

  run() {
    procCount++;
    const mod = getModule(this.modPath);
    this.inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = this.inst.exports.memory; this.membuf = null; this.refresh();
    try { this.inst.exports._start(); return 0; }
    catch (e) {
      if (e instanceof ExitError) return e.code & 0xff;
      process.stderr.write(`[wali-host] trap in pid ${this.pid}: ${e.stack || e}\n`);
      return 139;
    } finally { this.retire(); }
  }

  // JSPI: run _start as a promising export so its blocking syscalls can suspend.
  async runAsync() {
    procCount++;
    const mod = getModule(this.modPath);
    this.inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = this.inst.exports.memory; this.membuf = null; this.refresh();
    return this._drive(false);
  }

  // the run loop: each time _start returns we check whether it was a real exit or an
  // Asyncify fork-unwind; on a fork we spawn the child (a memory copy) and rewind.
  async _drive(rewind) {
    try { return await this._driveInner(rewind); } finally { this.retire(); }
  }
  async _driveInner(rewind) {
    const start = WebAssembly.promising(this.inst.exports._start);
    if (rewind) this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
    this._promised = true; // suspension is legal from here on (log_execution slow path)
    for (;;) {
      try { await start(); }
      catch (e) {
        if (e instanceof ExitError) return e.code & 0xff;
        process.stderr.write(`[wali-host] trap in pid ${this.pid}: ${e.stack || e}\n`);
        return 139;
      }
      if (this.forkState !== 'unwinding') return 0; // genuine _start return
      this.inst.exports.asyncify_stop_unwind();
      const childPid = nextPid++;
      if (process.env.WALI_SCHED_DBG) process.stderr.write(`[sched] fork pid=${this.pid} -> child pid=${childPid}\n`);
      const child = this.spawnForkChild(childPid);
      const ctask = child._drive(true).then((code) => { if (process.env.WALI_SCHED_DBG) process.stderr.write(`[sched] exit fork pid=${childPid} code=${code}\n`); releaseFds(child.fds); this.reaped.set(childPid, code); this.childTasks.delete(childPid); postSignal(this, SIG.CHLD); wakeWaiters(this); });
      inflight.add(ctask); ctask.finally(() => inflight.delete(ctask));
      this.childTasks.set(childPid, ctask);
      this.forkRet = BigInt(childPid); this.forkState = 'rewinding';       // parent gets the child pid
      this.inst.exports.asyncify_start_rewind(this.asyncifyBuf);
      // loop: re-enter _start, which rewinds to the fork point and SYS_fork returns childPid
    }
  }

  // fork: a child Process on a fresh instance whose memory is a byte copy of ours,
  // rewound to the same fork point (SYS_fork will return 0 in the child).
  spawnForkChild(childPid) {
    const mod = getModule(this.modPath);
    const child = new Process(this.modPath, this.argv, this.env, new Map(), this.cwd.p);
    procs.delete(child.pid);                 // re-register under the pid fork() reported
    child.pid = childPid; child.pgid = this.pgid; child.cred = { ...this.cred };
    procs.set(childPid, child);
    child.fds = new Map([...this.fds].map(([k, v]) => [k, { ...v, shared: true }])); // COW-ish: share handle objects
    for (const v of child.fds.values()) child.bumpFifo(v);
    child.nextFd = this.nextFd; child.heapBrk = this.heapBrk; child.ctty = this.ctty;
    child.umask = this.umask;
    for (const [b, at] of this.shmAt) child.shmAt.set(b, { seg: at.seg, shadow: Buffer.from(at.shadow) }); // shm attachments survive fork
    child.inst = new WebAssembly.Instance(mod, child.makeImports(mod));
    child.memory = child.inst.exports.memory; child.membuf = null; child.refresh();
    const need = this.memory.buffer.byteLength - child.memory.buffer.byteLength;
    if (need > 0) child.memory.grow(Math.ceil(need / PAGE));
    Buffer.from(child.memory.buffer).set(Buffer.from(this.memory.buffer)); // inherit parent memory (5x faster than whole-SAB Uint8Array.set)
    child.membuf = null; child.refresh();
    child.asyncifyBuf = this.asyncifyBuf; child.forkState = 'rewinding'; child.forkRet = 0n;
    return child;
  }
}
class ExitError extends Error { constructor(code) { super('exit'); this.code = code; } }

// run a program synchronously, return exit code (null if module unresolvable)
// setuid/setgid bit on the executable: exec raises the effective id to the
// file's owner/group (this is how a dropped-privilege process regains root for
// e.g. su/ping). The saved id records it so the program can drop and restore.
function applySuid(proc, mp) {
  try {
    if (mp === '/proc/self/exe' || mp.startsWith('vfs:')) return;
    const st = fs.statSync(mp);
    if (st.mode & 0o4000) { proc.cred.euid = st.uid; proc.cred.suid = st.uid; }
    if (st.mode & 0o2000) { proc.cred.egid = st.gid; proc.cred.sgid = st.gid; }
  } catch {}
}
function runProgram(p, argv, envp, fdTable, cwd, selfPath, cred, asPid) {
  // "compiler as a service": the browser can't run native clang, but a build is
  // just a process the shell spawns. Here (node host) we resolve cc/clang to the
  // real toolchain so a WASM shell can drive a compile+run loop through our
  // syscall layer. Swap this for a wasm-compiled clang module = fully in-browser.
  const base = path.basename(p);
  if (base === 'cc' || base === 'clang' || base === 'wcc') {
    const W = path.join(process.env.HOME, 'wali/build');
    const flags = `--target=wasm32-unknown-linux-muslwali --sysroot=${W}/sysroot -O2 -mllvm -wasm-enable-sjlj -fwasm-exceptions -pthread -matomics -mbulk-memory -mexception-handling -L${W}/sysroot/lib -Wl,--shared-memory,--export-memory,--max-memory=2147483648,-z,stack-size=8388608 -Wno-unused-command-line-argument`.split(/\s+/);
    try {
      require('child_process').execFileSync(`${W}/llvm/bin/clang`, [...flags, ...argv.slice(1)],
        { cwd, stdio: ['ignore', 'inherit', 'inherit'] });
      return 0;
    } catch (e) { return e.status || 1; }
  }
  const pabs = (p.startsWith('/') || !p.includes('/')) ? p : path.resolve(cwd, p);
  const mp = resolveModulePath(pabs, selfPath);
  if (!mp) { process.stderr.write(`[wali-host] execve: cannot resolve ${p}\n`); return null; }
  const proc = new Process(mp, argv, envp, fdTable, cwd); if (cred) proc.cred = { ...cred }; if (asPid) { const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid; proc.pgid = old ? old.pgid : asPid; procs.set(asPid, proc); } applySuid(proc, mp);
  return proc.run();
}

// JSPI variant: run the child concurrently (its blocking syscalls suspend, not stall)
async function runProgramAsync(p, argv, envp, fdTable, cwd, selfPath, cred, asPid) {
  const base = path.basename(p);
  if (base === 'cc' || base === 'clang' || base === 'wcc') return runProgram(p, argv, envp, fdTable, cwd, selfPath, cred, asPid); // native compile stays sync
  const pabs = (p.startsWith('/') || !p.includes('/')) ? p : path.resolve(cwd, p);
  const mp = resolveModulePath(pabs, selfPath);
  if (!mp) { process.stderr.write(`[wali-host] execve: cannot resolve ${p}\n`); return null; }
  const proc = new Process(mp, argv, envp, fdTable, cwd); if (cred) proc.cred = { ...cred }; if (asPid) { const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid; proc.pgid = old ? old.pgid : asPid; procs.set(asPid, proc); } applySuid(proc, mp);
  if (process.env.WALI_SCHED_DBG) process.stderr.write(`[sched] start pid=${proc.pid} ${path.basename(mp)} argv=[${argv.join(' ')}]\n`);
  await new Promise(res => setImmediate(res)); // clean JS stack: the child's _start must not run inside the parent's suspending import (SuspendError)
  const code = await proc.runAsync();
  if (process.env.WALI_SCHED_DBG) process.stderr.write(`[sched] exit  pid=${proc.pid} ${path.basename(mp)} code=${code}\n`);
  return code;
}

// ---- main ----
const rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
const rootEnv = Object.entries(process.env).filter(([k]) => k.startsWith('WALIENV_')).map(([k, v]) => k.slice(8) + '=' + v);
const rootArgv = process.argv.slice(2).map((x, i) => i === 0 ? path.basename(x).replace(/\.wasm$/, '') : x);
if (process.env.WALI_ARGV0) rootArgv[0] = process.env.WALI_ARGV0; // some programs (sshd) require an absolute argv[0]
(async () => {
  const t0 = Date.now();
  const root = new Process(path.resolve(wasmPath), rootArgv, rootEnv, rootFds, process.cwd());
  rootProc = root;
  if (JSPI) process.on('SIGINT', () => { // host Ctrl-C -> guest foreground group (pty pgrp if set, else the root)
    let fg = 0; for (const p of ptys.values()) if (p.pgrp) fg = p.pgrp;
    if (!(fg && signalPgrp(fg, SIG.INT))) postSignal(rootProc, SIG.INT);
  });
  const code = JSPI ? await root.runAsync() : root.run();
  process.stderr.write(`[wali-host] exit=${code} procs=${procCount} syscalls=${syscallTotal} wall=${((Date.now() - t0) / 1000).toFixed(2)}s${JSPI ? ` [jspi] suspends=${pipeSuspends}pipe/${waitSuspends}wait` : ''}\n`);
  process.exit(code);
})();
