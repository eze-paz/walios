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
    return { res: ctl[6], data };
  };
  sockBridge = { call, OP: { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8 } };
  return sockBridge;
}

const wasmPath = process.argv[2];
if (!wasmPath) { console.error('usage: node host.js prog.wasm [args...]'); process.exit(2); }

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
const E = { PERM:1, NOENT:2, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, FAULT:14, EXIST:17, NOTDIR:20, ISDIR:21, INVAL:22, MFILE:24, NOTTY:25, SPIPE:29, RANGE:34, NOSYS:38, NOTEMPTY:39 };
const err = (e) => BigInt(-e);
function sysErr(e) {
  const m = { EPERM:E.PERM, ENOENT:E.NOENT, EBADF:E.BADF, EACCES:E.ACCES, EEXIST:E.EXIST, ENOTDIR:E.NOTDIR, EISDIR:E.ISDIR, EINVAL:E.INVAL, ENOTEMPTY:E.NOTEMPTY, EMFILE:E.MFILE, ESPIPE:E.SPIPE, EAGAIN:E.AGAIN };
  return err(m[e.code] ?? E.INVAL);
}

// ---- global kernel state (shared across processes) ----
let nextPid = 100;
const modCache = new Map();          // resolved path -> WebAssembly.Module
// children are owned by the process that forked them (per-Process queues)
let syscallTotal = 0, procCount = 0;
const unknownSyscalls = new Set();

// binary manifest: how execve paths resolve to wasm modules
function resolveModulePath(p, selfPath) {
  if (p === '/proc/self/exe') return selfPath;
  if (fs.existsSync(p)) {
    const fd = fs.openSync(p, 'r'); const b = Buffer.alloc(4);
    fs.readSync(fd, b, 0, 4, 0); fs.closeSync(fd);
    if (b.readUInt32LE(0) === 0x6d736100) return p;
  }
  const base = path.basename(p);
  if (base === 'busybox' || base === 'sh' || base === 'hush') return path.join(process.env.HOME || '', 'busybox-1.36.1', 'busybox');
  if (base.startsWith('python')) return path.join(process.env.HOME || '', 'wali-py', 'python');
  return null;
}
function getModule(p) {
  if (!modCache.has(p)) modCache.set(p, new WebAssembly.Module(fs.readFileSync(p)));
  return modCache.get(p);
}

// ---- pipes ----
function mkPipe() { return { chunks: [], writers: 1, readers: 1 }; }
function pipeRead(fifo, n) {
  if (!fifo.chunks.length) return new Uint8Array(0); // sequential model: empty = EOF
  let out = Buffer.concat(fifo.chunks);
  const take = out.subarray(0, n);
  const rest = out.subarray(n);
  fifo.chunks = rest.length ? [rest] : [];
  return take;
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
    this.pending = [];
    this.reaped = new Map();
    this.syscalls = 0;
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
  rpath(s) { return path.resolve(this.cwd.p, s); }
  atPath(dirfd, s) {
    if (s.startsWith('/')) return s;
    if ((dirfd | 0) === -100) return this.rpath(s);
    const h = this.fds.get(dirfd); return h && h.path ? path.join(h.path, s) : this.rpath(s);
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
          const b = Buffer.alloc(a[2]); let got = 0;
          try { got = fs.readSync(0, b, 0, a[2], null); } catch (e) { if (e.code !== 'EAGAIN' && e.code !== 'EOF') return sysErr(e); }
          S.wbytes(a[1], b.subarray(0, got)); return BigInt(got);
        }
        if (h.fifo) { const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.sock) { const br = initSockBridge(); const r = br.call(br.OP.RECV, h.sock.id, a[2], 0); if (r.res <= 0) return BigInt(r.res); S.wbytes(a[1], r.data.subarray(0, r.res)); return BigInt(r.res); }
        if (h.fd === undefined) return err(E.BADF);
        if (h.pos === undefined) h.pos = 0;
        const b = Buffer.alloc(a[2]); let got;
        try { got = fs.readSync(h.fd, b, 0, a[2], h.pos); } catch (e) { return sysErr(e); }
        h.pos += got; S.wbytes(a[1], b.subarray(0, got)); return BigInt(got);
      }
      case 'write': {
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.std !== undefined) { try { return BigInt(fs.writeSync(h.std === 0 ? 1 : h.std, S.u8, a[1], a[2])); } catch (e) { return sysErr(e); } }
        if (h.fifo) { h.fifo.chunks.push(Buffer.from(S.u8.slice(a[1], a[1] + a[2]))); return BigInt(a[2]); }
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
        if (h.sock && h.sock.id && !S.shared(h)) { const br = initSockBridge(); br.call(br.OP.CLOSE, h.sock.id, 0, 0); }
        else if (h.fd > 2 && !S.shared(h)) { try { fs.closeSync(h.fd); } catch {} }
        S.fds.delete(a[0]); S.dirState.delete(a[0]); return 0n; }
      case 'lseek': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock) return err(E.SPIPE);
        const size = h.dir ? 0 : fs.fstatSync(h.fd).size;
        h.pos = a[2] === 0 ? Number(a[1]) : a[2] === 1 ? (h.pos || 0) + Number(a[1]) : size + Number(a[1]);
        return BigInt(h.pos); }
      case 'fstat': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.std !== undefined || h.fifo || h.sock) { S.putStat(a[1], { size: 0, mode: (h.fifo || h.sock) ? 0o010600 : 0o020620 }); return 0n; }
        try { S.putStat(a[1], h.dir ? fs.statSync(h.path) : fs.fstatSync(h.fd)); return 0n; } catch (e) { return sysErr(e); } }
      case 'stat': case 'lstat': {
        const p = S.rpath(S.cstr(a[0]));
        if (p === '/proc/self/exe') { S.putStat(a[1], { size: 1, mode: 0o100755 }); return 0n; }
        try { S.putStat(a[1], name === 'stat' ? fs.statSync(p) : fs.lstatSync(p)); return 0n; } catch (e) { return sysErr(e); } }
      case 'newfstatat': { const s = S.cstr(a[1]); if (s === '') return S.sys('fstat', [a[0], a[2]]);
        const p = S.atPath(a[0], s);
        if (p === '/proc/self/exe') { S.putStat(a[2], { size: 1, mode: 0o100755 }); return 0n; }
        try { S.putStat(a[2], (a[3] & 0x100) ? fs.lstatSync(p) : fs.statSync(p)); return 0n; } catch (e) { return sysErr(e); } }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.rpath(S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        try { fs.accessSync(p); return 0n; } catch (e) { return sysErr(e); } }
      case 'readlink': { const p = S.rpath(S.cstr(a[0]));
        if (p === '/proc/self/exe') return BigInt(S.wstr(a[1], S.modPath, a[2] + 1));
        try { return BigInt(S.wstr(a[1], fs.readlinkSync(p), a[2] + 1)); } catch (e) { return sysErr(e); } }
      case 'unlink': { try { fs.unlinkSync(S.rpath(S.cstr(a[0]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'rmdir': { try { fs.rmdirSync(S.rpath(S.cstr(a[0]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'mkdir': { try { fs.mkdirSync(S.rpath(S.cstr(a[0])), a[1]); return 0n; } catch (e) { return sysErr(e); } }
      case 'rename': { try { fs.renameSync(S.rpath(S.cstr(a[0])), S.rpath(S.cstr(a[1]))); return 0n; } catch (e) { return sysErr(e); } }
      case 'chdir': { const p = S.rpath(S.cstr(a[0])); try { if (!fs.statSync(p).isDirectory()) return err(E.NOTDIR); S.cwd.p = p; return 0n; } catch (e) { return sysErr(e); } }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1);
      case 'chmod': { try { fs.chmodSync(S.rpath(S.cstr(a[0])), a[1]); return 0n; } catch (e) { return sysErr(e); } }
      case 'fchmod': case 'chown': return 0n;
      case 'umask': return 0o22n;
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true; const g = S.nextFd++; S.fds.set(g, { ...h }); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true; if (a[0] !== a[1]) S.fds.set(a[1], { ...h }); return BigInt(a[1]); }
      case 'pipe': case 'pipe2': {
        const fifo = mkPipe();
        const r = S.nextFd++, w = S.nextFd++;
        S.fds.set(r, { fifo, end: 'r' }); S.fds.set(w, { fifo, end: 'w' });
        S.i32(a[0], r); S.i32(a[0] + 4, w); return 0n; }

      // ---- process model ----
      case 'fork': case 'vfork': {
        const pid = nextPid++;
        const savedFds = S.fds;
        S.fds = new Map([...savedFds].map(([k, v]) => [k, { ...v, shared: true }]));
        S.childStack.push({ pid, savedFds });
        return BigInt(pid); }
      case 'execve': {
        const p = S.cstr(a[0]);
        const argv = S.rPtrArray(a[1]);
        const envp = a[2] ? S.rPtrArray(a[2]) : [];
        if (!S.inChild()) { // exec without fork: replace this process = run child, exit with its code
          const code = runProgram(p, argv, envp, S.fds, S.cwd.p, S.modPath);
          if (code === null) return err(E.NOENT);
          throw new ExitError(code);
        }
        const fdsnap = S.fds;
        const r = S.parkChild({ exec: { path: p, argv, envp, fds: fdsnap, cwd: S.cwd.p, selfPath: S.modPath } });
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
          const code = runProgram(c.exec.path, c.exec.argv, c.exec.envp, c.exec.fds, c.exec.cwd, c.exec.selfPath);
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
        if (!(a[3] & 0x20)) {
          const h = S.fds.get(a[4]); if (!h || h.fd === undefined) return err(E.BADF);
          const buf = Buffer.alloc(a[1]);
          const got = fs.readSync(h.fd, buf, 0, a[1], Number(a[5]));
          S.wbytes(base, buf.subarray(0, got));
        }
        return BigInt(base); }
      case 'munmap': case 'mprotect': case 'madvise': return 0n;
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
      case 'ioctl': { const h = S.fds.get(a[0]);
        if (!h || h.std === undefined) return err(E.NOTTY);
        if (a[1] === 0x5413) { S.refresh(); S.dv.setUint16(a[2], 24, true); S.dv.setUint16(a[2] + 2, 80, true); S.i32(a[2] + 4, 0); }
        return 0n; }
      case 'fcntl': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (a[1] === 0 || a[1] === 1030) { // F_DUPFD / F_DUPFD_CLOEXEC: honor min-fd hint
          const min = Number(a[2]) || 0;
          let g = Math.max(S.nextFd, min); while (S.fds.has(g)) g++;
          S.nextFd = Math.max(S.nextFd, g + 1);
          h.shared = true; S.fds.set(g, { ...h }); return BigInt(g);
        }
        if (a[1] === 3) return 2n; return 0n; }
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const t = process.hrtime(); S.i64(a[1], BigInt(t[0])); S.i64(a[1] + 8, BigInt(t[1])); return 0n; }
        const ms = Date.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt((ms % 1000) * 1e6)); return 0n; }
      case 'gettimeofday': { const ms = Date.now(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt((ms % 1000) * 1000)); return 0n; }
      case 'nanosleep': case 'clock_nanosleep': return 0n;
      case 'uname': { ['Linux', 'wali', '6.1.0-wali', '#1 WALI-js', 'wasm32', ''].forEach((s, i) => S.wstr(a[name === 'uname' ? 0 : 2] + i * 65, s, 65)); return 0n; }
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
      case 'getrandom': { const b = require('crypto').randomBytes(Math.min(a[1], 65536)); S.wbytes(a[0], b); return BigInt(b.length); }
      case 'poll': { S.refresh(); for (let i = 0; i < a[1]; i++) { const ev = S.dv.getInt16(a[0] + i * 8 + 4, true); S.dv.setInt16(a[0] + i * 8 + 6, ev & 5, true); } return BigInt(a[1]); }
      case 'select': case 'pselect6': return 1n;
      case 'socket': { // AF_INET(2)/AF_INET6(10); SOCK_STREAM(1) or SOCK_DGRAM(2)
        const dom = a[0] & 0xff, type = a[1] & 0xff;
        if (dom !== 2 && dom !== 10) return err(E.NOSYS);
        if (type === 2) { const br = initSockBridge(); const r = br.call(br.OP.UDP, 0, 0, 0); if (r.res < 0) return BigInt(r.res); const g = S.nextFd++; S.fds.set(g, { sock: { id: r.res, dom, udp: true } }); return BigInt(g); }
        const g = S.nextFd++; S.fds.set(g, { sock: { id: 0, dom } }); return BigInt(g); }
      case 'connect': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        S.refresh();
        // sockaddr_in: family(2) port(2 BE) addr(4)  |  sockaddr_in6: family(2) port(2 BE) flow(4) addr(16)
        const fam = S.dv.getUint16(a[1], true);
        let ip, port = S.dv.getUint16(a[1] + 2, false);
        if (fam === 2) ip = `${S.u8[a[1]+4]}.${S.u8[a[1]+5]}.${S.u8[a[1]+6]}.${S.u8[a[1]+7]}`;
        else { const p = []; for (let i = 0; i < 16; i += 2) p.push(S.dv.getUint16(a[1]+8+i, false).toString(16)); ip = p.join(':'); }
        const br = initSockBridge();
        const spec = Buffer.from(`${ip}|${port}`, 'utf8');
        const r = br.call(br.OP.CONNECT, spec.length, 0, 0, spec);
        if (r.res < 0) return BigInt(r.res);
        h.sock.id = r.res; return 0n; }
      case 'sendto': case 'sendmsg': case 'write_sock': {
        const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        const br = initSockBridge(); S.refresh();
        if (h.sock.udp && name === 'sendto') { // sendto(fd, buf, len, flags, dest, addrlen)
          const dp = a[4], ip = `${S.u8[dp+4]}.${S.u8[dp+5]}.${S.u8[dp+6]}.${S.u8[dp+7]}`, port = S.dv.getUint16(dp + 2, false);
          const payload = S.u8.slice(a[1], a[1] + a[2]);
          const addr = Buffer.from(`${ip}|${port}`, 'utf8');
          const packed = new Uint8Array(payload.length + addr.length); packed.set(payload, 0); packed.set(addr, payload.length);
          const r = br.call(br.OP.SENDTO, h.sock.id, payload.length, addr.length, packed);
          return BigInt(r.res);
        }
        if (name === 'sendmsg') { // msghdr: iov at +8, iovlen at +16
          const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 16); let sent = 0;
          for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
            const r = br.call(br.OP.SEND, h.sock.id, l, 0, S.u8.slice(p, p + l)); if (r.res < 0) return sent || BigInt(r.res); sent += r.res; }
          return BigInt(sent);
        }
        const r = br.call(br.OP.SEND, h.sock.id, a[2], 0, S.u8.slice(a[1], a[1] + a[2]));
        return BigInt(r.res); }
      case 'recvmsg': { const h = S.fds.get(a[0]); if (!h || !h.sock) return err(E.BADF);
        const br = initSockBridge();
        const iov = S.r32(a[1] + 8), iovn = S.r32(a[1] + 16); let total = 0;
        for (let i = 0; i < iovn; i++) { const p = S.r32(iov + i * 8), l = S.r32(iov + i * 8 + 4); if (!l) continue;
          const r = br.call(br.OP.RECV, h.sock.id, l, 0); if (r.res < 0) return total || BigInt(r.res);
          if (r.res === 0) break; S.wbytes(p, r.data.subarray(0, r.res)); total += r.res; if (r.res < l) break; }
        return BigInt(total); }
      case 'setsockopt': case 'getsockname': case 'getpeername': case 'shutdown': return 0n;
      default:
        if (!unknownSyscalls.has(name)) { unknownSyscalls.add(name); process.stderr.write(`[wali-host] ENOSYS SYS_${name}\n`); }
        return err(E.NOSYS);
    }
  }

  shared(h) { return h.shared; }
  openAt(fp, flags, mode) {
    const O_DIRECTORY = 0o200000;
    const c = fs.constants;
    try {
      if (fp === '/proc/self/exe') fp = this.modPath;
      const ex = fs.existsSync(fp) && fs.statSync(fp);
      if (ex && ex.isDirectory()) {
        if ((flags & 3) !== 0) return err(E.ISDIR);
        const g = this.nextFd++; this.fds.set(g, { fd: -1, path: fp, dir: true }); return BigInt(g);
      }
      if (flags & O_DIRECTORY) return err(E.NOTDIR);
      let o = (flags & 3) === 0 ? c.O_RDONLY : (flags & 3) === 1 ? c.O_WRONLY : c.O_RDWR;
      if (flags & 0o100) o |= c.O_CREAT; if (flags & 0o200) o |= c.O_EXCL;
      if (flags & 0o1000) o |= c.O_TRUNC;
      const fd = fs.openSync(fp, o, mode || 0o666);
      const g = this.nextFd++;
      this.fds.set(g, { fd, path: fp, pos: (flags & 0o2000) ? fs.fstatSync(fd).size : 0, append: !!(flags & 0o2000) });
      return BigInt(g);
    } catch (e) { return sysErr(e); }
  }

  makeImports(mod) {
    const wali = {};
    const S = this;
    const extra = {};
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
      else if (name === '__cl_get_argc') wali[name] = () => S.argv.length;
      else if (name === '__cl_get_argv_len') wali[name] = (i) => Buffer.byteLength(S.argv[i] || '', 'utf8');
      else if (name === '__cl_copy_argv') wali[name] = (buf, i) => S.wstr(buf, S.argv[i] || '', 0);
      else if (name === '__proc_exit') wali[name] = (c2) => { throw new ExitError(c2); };
      else if (name === 'setjmp' || name === 'sigsetjmp' || name === '_setjmp') wali[name] = () => 0;
      else if (name === 'longjmp' || name === 'siglongjmp' || name === '_longjmp') wali[name] = () => { throw new Error('host-import longjmp (old binary)'); };
      else if (name.startsWith('SYS_')) {
        const sysname = name.slice(4);
        wali[name] = (...a2) => {
          S.syscalls++; syscallTotal++;
          const r = S.sys(sysname, a2.map(x => typeof x === 'bigint' && sysname !== 'mmap' ? Number(x) : x));
          if (process.env.WALI_TRACE) process.stderr.write(`[p${S.pid}:${S.syscalls}] ${sysname}(${a2.join(',')}) = ${r}\n`);
          return r;
        };
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
        try { const fd = fs.openSync(path.resolve(base, name), (oflags & 1) ? 'w' : 'r'); const g = S.nextFd++; S.fds.set(g, { fd, pos: 0 }); S.i32(fdptr, g); return W.OK; } catch { return W.NOENT; } },
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
    const inst = new WebAssembly.Instance(mod, this.makeImports(mod));
    this.memory = inst.exports.memory; this.membuf = null; this.refresh();
    try { inst.exports._start(); return 0; }
    catch (e) {
      if (e instanceof ExitError) return e.code & 0xff;
      process.stderr.write(`[wali-host] trap in pid ${this.pid}: ${e.stack || e}\n`);
      return 139;
    }
  }
}
class ExitError extends Error { constructor(code) { super('exit'); this.code = code; } }

// run a program synchronously, return exit code (null if module unresolvable)
function runProgram(p, argv, envp, fdTable, cwd, selfPath) {
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
  const proc = new Process(mp, argv, envp, fdTable, cwd);
  return proc.run();
}

// ---- main ----
const rootFds = new Map([[0, { std: 0 }], [1, { std: 1 }], [2, { std: 2 }]]);
const rootEnv = Object.entries(process.env).filter(([k]) => k.startsWith('WALIENV_')).map(([k, v]) => k.slice(8) + '=' + v);
const rootArgv = process.argv.slice(2).map((x, i) => i === 0 ? path.basename(x).replace(/\.wasm$/, '') : x);
const t0 = Date.now();
const root = new Process(path.resolve(wasmPath), rootArgv, rootEnv, rootFds, process.cwd());
const code = root.run();
process.stderr.write(`[wali-host] exit=${code} procs=${procCount} syscalls=${syscallTotal} wall=${((Date.now() - t0) / 1000).toFixed(2)}s\n`);
process.exit(code);
