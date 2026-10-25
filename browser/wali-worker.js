// WALI browser syscall host v2 — process model edition.
// vfork/execve/wait4/pipes on top of the in-memory VFS + OPFS mount.
// Child branch runs in-place under an fd overlay (vfork semantics, guest
// longjmps back via wasm-EH SJLJ); wait4 runs parked children synchronously.
'use strict';

const PAGE = 65536;
const CHILD_DONE = 0x7e57n;
try { self.addEventListener('unhandledrejection', (e) => { try { self.postMessage({ t: 'out', fd: 2, s: '[host] UNHANDLED: ' + ((e.reason && e.reason.stack) || e.reason) + '\n' }); } catch {} }); } catch {}
const E = { PERM:1, NOENT:2, SRCH:3, INTR:4, IO:5, BADF:9, CHILD:10, AGAIN:11, NOMEM:12, ACCES:13, EXIST:17, XDEV:18, NOTDIR:20, ISDIR:21, INVAL:22, NOTTY:25, SPIPE:29, PIPE:32, NOSPC:28, NOSYS:38, NOTEMPTY:39,
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
// Stable, unique inodes. Every regular file used to report ino 1: LLVM's FileManager keys
// its cache by (dev, ino), so <stddef.h> was "the same file" as the source that included
// it -- "#include nested too deeply" -- and Python's os.path.samefile() / git's index have
// the same need. Files carry theirs on the entry; directories are keyed by path.
let inoSeq = 1000; const dirInos = new Map();
function inoOf(x) {
  if (typeof x === 'string') { let n = dirInos.get(x); if (!n) dirInos.set(x, n = ++inoSeq); return n; }
  if (!x.ino) x.ino = ++inoSeq; return x.ino;
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
  installTar(new Uint8Array(await new Response(resp.body.pipeThrough(ds)).arrayBuffer()), prefix);
}
// Split out of loadTar so a bundle that arrived by another route can be installed too. (The
// guest is parked in Atomics.wait ON THIS THREAD, so this thread can no longer run its own
// message handler and the fetch half can never happen here -- the host does fetch+gunzip on
// its thread and hands the plain tar bytes over a SAB; the guest parses them with this,
// rather than a second copy of the parser.
function installTar(buf, prefix) {
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
const OFS = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11, SETMODE: 12 };
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
  const probed = new Map();   // key -> { res, aux, data, at, inflight }
  const PROBE_FRESH_MS = 10;
  port.onmessage = (ev) => { const m = ev.data; if (!m || m.t !== 'reply') return; const p = pending.get(m.id); if (!p) return; pending.delete(m.id); p(m); };
  const send = (op, a0, a1, a2, bytes) => new Promise((res) => {
    const id = ++bridgeSeq; pending.set(id, res);
    const copy = bytes ? bytes.slice() : null;
    port.postMessage({ t: 'call', id, op, a0: a0 | 0, a1: a1 | 0, a2: a2 | 0, bytes: copy ? copy.buffer : null }, copy ? [copy.buffer] : []);
  });
  const unpack = (m) => ({ res: m.res | 0, aux: m.aux | 0, data: m.data ? new Uint8Array(m.data) : EMPTY_U8 });
  const call = (op, a0, a1, a2, bytes) => {
    const ff = fireAndForget[op];
    if (ff !== undefined) { send(op, a0, a1, a2, bytes); return { res: typeof ff === 'function' ? ff(a0, a1, a2, bytes) : ff, aux: 0, data: EMPTY_U8 }; }
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
  return { call, max: 1 << 30, port: true };
}
const OPFS_FF = { [OFS.WRITE]: (a0, a1, a2) => a2, [OFS.TRUNC]: 0, [OFS.CLOSE]: 0, [OFS.UNLINK]: 0, [OFS.MKDIR]: 0,
                  [OFS.RMDIR]: 0, [OFS.RENAME]: 0, [OFS.RELEASE]: 0, [OFS.SETMODE]: 0 };
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
  try { const pb = te.encode(f.br); br.call(OFS.SETMODE, pb.length, f.mode & 0o7777, 0, pb); } catch (_) {}
}
function initOpfs() {
  if (opfsBr) return opfsBr;
  if (opfsPort) { opfsBr = portBridge(opfsPort, 'opfs', OPFS_FF); return opfsBr; }
  if (!opfsSab) return null;
  const ctl = new Int32Array(opfsSab, 0, 8), bdata = new Uint8Array(opfsSab, 32);
  const call = (op, a0, a1, a2, bytes) => {
    if (bytes) bdata.set(bytes, 0);
    ctl[2] = op; ctl[3] = a0 | 0; ctl[4] = a1 | 0; ctl[5] = a2 | 0;
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
      if (!pickedUp && waited >= 20000) { opfsDead = true; post('[host] the OPFS bridge did not answer in 20s; /' + (opfsMount || 'root').replace(/^\//, '') + ' is unavailable (EIO) from now on\n', 2); return { res: -E.IO, aux: 0, data: bdata }; }
      if (pickedUp && waited >= 600000) { post('[host] an OPFS operation did not finish in 10 minutes (a cloud-only file that would not download?); EIO for this file only\n', 2); return { res: -E.IO, aux: 0, data: bdata }; }
      if (pickedUp && !warned && waited >= 20000) { warned = true; post('[host] still waiting on the OPFS bridge (downloading a cloud-only file from Dropbox?)\n', 2); }
      Atomics.wait(ctl, 1, prev, 1000);
    }
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
function opfsLoadDir(p) {       // merge one directory's OPFS listing (refreshed after OPFS_LIST_TTL)
  const now = Date.now(), at = opfsLoaded.get(p);
  if (at !== undefined && now - at < OPFS_LIST_TTL) return; opfsLoaded.set(p, now);
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
    if (e.d) mkdirp(child);
    else { const f = files.get(child);
      if (!f) {
        dirs.get(p).add(e.n);
        files.set(child, { br: opfsRel(child), size: e.s, mtimeMs: e.m, data: null,
                           mode: e.p !== undefined ? (0o100000 | (e.p & 0o7777)) : opfsGuessMode(opfsRel(child)) });
      } else if (f.br !== undefined && !f.brId && e.s !== undefined) { f.size = e.s; f.mtimeMs = e.m; }   // rewritten by another kernel
    }
  }
  // A refresh (not the first listing): entries that are gone from OPFS -- deleted by another
  // kernel or by the sync -- leave the VFS too, unless a process still has the file open
  // (its handle keeps the bytes valid, as on Linux) or it is a RAM-only entry seeded here.
  if (at !== undefined) for (const n of [...dirs.get(p)]) {
    if (seen.has(n)) continue;
    const c = p + '/' + n, f = files.get(c);
    if (f) { if (f.br !== undefined && !f.brId && !opfsFileInUse(f)) { files.delete(c); dirs.get(p).delete(n); } }
    else if (dirs.has(c) && dirs.get(c).size === 0) { dirs.delete(c); dirs.get(p).delete(n); opfsLoaded.delete(c); }
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
const opfsOpenFailed = new Set();
// Set by fileRead/fileWrite when the OPFS handle could not be opened (typically a
// file that is still only in Dropbox and could not be fetched). Read and cleared
// by the read/write syscalls, which turn it into EIO -- a short read of zero bytes
// is indistinguishable from an empty file, and that is exactly how "my data is
// gone" gets reported when the data is merely unreachable.
let fileIoError = false;
const ioFailed = () => { const v = fileIoError; fileIoError = false; return v; };
const opfsCloudWarned = new Set();   // dirs we have already reported as holding unreachable cloud files
function opfsHandle(f, create) { // lazily open the per-file bridge handle
  if (f.brId) return f.brId;
  const br = initOpfs(); if (!br) return 0;
  const pb = te.encode(f.br);
  const r = br.call(OFS.OPEN, pb.length, create ? 1 : 0, 0, pb);
  if (r.res <= 0) {
    // A failed open used to read back as ZERO BYTES -- `cat` printed nothing and
    // looked like an empty file. The realistic cause is a file that is still only
    // in the user's Dropbox (listed from the cloud index) whose download failed:
    // no token in this tab, an expired one, or no network. Say which file.
    if (!opfsOpenFailed.has(f.br)) {
      opfsOpenFailed.add(f.br);
      // EBUSY: the file is LOCAL and intact but another OPFS handle holds it -- the bridge
      // of a run the host killed mid-write and never released. That used to print the
      // cloud message below, and a whole git repo "became not a repository" over it.
      if (r.res === -16) post('walios: /' + f.br + ' is locked by another OPFS handle (a previous run killed before it released its files?) - EBUSY; the host must terminate that run\'s bridge worker\n', 2);
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
  if (r.aux >= 0 && r.aux !== f.size) f.size = r.aux;
  return f.brId;
}
// Drop the bridge handle -- the EXCLUSIVE OPFS lock -- once no fd in any process refers to
// the file. Handles used to live until RELEASE at the end of the run (for the terminal:
// until the tab closed), so a file the shell had merely `cat`ed once stayed locked against
// the walios() tool, the Python REPL and every other conversation's kernel: EBUSY on open,
// which git reports as "not a git repository" or "unable to read <object>". A short grace
// keeps git's open/close/open churn on one object from paying a createSyncAccessHandle per
// touch, and a file reopened inside it keeps its handle (see opfsHandle).
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
    const br = initOpfs(), id = opfsHandle(f); if (!id) { fileIoError = true; return new Uint8Array(0); }
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
    const br = initOpfs(), id = opfsHandle(f, true); if (!id) { fileIoError = true; return 0; }
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
// A WARM SPARE per module. Measured: starting a process costs ~20-45ms, and nearly all of
// it is WebAssembly.instantiate INSIDE the worker -- `new Worker` itself is ~1ms, so a pool
// of blank workers would buy nothing. What costs is instantiating THIS module, so the spare
// is module-keyed and already past `init`: worker created, module instantiated, sitting on
// its 'ready'. Taking one turns process start into a postMessage.
//
// ONLY for modules that DEFINE their own memory (busybox and the WALI binaries -- the shell
// and its forks, i.e. most of the process count). A module that IMPORTS memory (clang) has
// that memory created per-process by makeImports, and fork additionally needs the parent's
// memory copied into it before the guest runs, so those keep the cold path. Never used for
// a fork child for the same reason.
const spares = new Map();          // modKey -> { w, ctl, bulk, ready } | 'pending'
const SPARE_OK = (plan, opts) => !plan.memory && !(opts && opts.forkFrom);
function takeSpare(modKey) {
  const sp = spares.get(modKey);
  if (!sp || sp === 'pending') return null;
  spares.delete(modKey);
  return sp;
}
function prepareSpare(modKey, plan) {
  if (spares.has(modKey) || !plan || plan.memory) return;
  spares.set(modKey, 'pending');
  try {
    const mod = modCache.get(modKey);
    if (!mod) { spares.delete(modKey); return; }
    let bulk;
    try { bulk = new SharedArrayBuffer(1 << 20, { maxByteLength: 64 << 20 }); }
    catch (_) { bulk = new SharedArrayBuffer(32 << 20); }
    const ctl = new SharedArrayBuffer(KCTL.BYTES);
    const w = new Worker(NODE_STUB_RE.test(modKey) ? NODE_WORKER_URL : 'wali-proc-worker.js');
    let settle;
    const ready = new Promise((res) => { settle = res; });
    const sp = { w, ctl, bulk, ready, settle: (m) => settle(m) };
    // The worker is silent after 'ready' until it is told to run, so buffering one message is enough.
    w.onmessage = (ev) => { if (ev.data && ev.data.t === 'ready') settle(ev.data); };
    w.onerror = () => { settle({ ok: false, error: 'spare worker failed' }); spares.delete(modKey); };
    w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk, memory: null });
    spares.set(modKey, sp);
  } catch (_) { spares.delete(modKey); }
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

// ---- process model ----
// Every process runs on its OWN worker (wali-proc-worker.js) and proxies each host
// import to this kernel over a SharedArrayBuffer; this thread is a never-blocked
// syscall server, so a parked guest blocks nothing else and pipelines run in parallel.
// Names in BLOCKING may park the caller: they run through the async implementations in
// sysAsync while the kernel keeps serving everyone else. (This used to be one of three
// engines; the other two -- and the SAB bridges that existed only to feed a parked
// kernel -- are gone.)
const BLOCKING = new Set(['read', 'readv', 'wait4', 'poll', 'ppoll', 'select', 'pselect6', 'epoll_wait', 'epoll_pwait', 'nanosleep', 'clock_nanosleep', 'execve', 'recvmsg', 'recvfrom', 'pause', 'sigsuspend', 'rt_sigsuspend', 'accept', 'accept4', 'futex']);
// Binaries linked against the OLDER wali-musl, whose fork() is plain musl _Fork(): it
// expects the syscall itself to return twice, which only Asyncify can do here. Without
// it the vfork protocol below would hand such a binary a pid it never treats as "run
// the child branch now", and it would then block forever on its own pipes -- so answer
// ENOSYS instead (python raises OSError at once). Everything built with the current
// toolchain carries the fork() macro and never hits this. Rebuilding python_cxx against
// the current wali-musl (or adding Asyncify to it) removes the entry.
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
function wakePipe(fifo) { if (fifo.readWaiters && fifo.readWaiters.length) { const w = fifo.readWaiters; fifo.readWaiters = []; for (const f of w) f(); } }
function releaseFds(fdMap) { for (const h of fdMap.values()) {
  if (h && h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; }
  else if (h && h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; }
  else if (h && h.file && h.file.brId) opfsMaybeRelease(h.file); } }   // a process that exits with files open
function wakeWaiters(S) { if (S.waitWaiters.length) { const w = S.waitWaiters; S.waitWaiters = []; for (const f of w) f(); } }
// execve: drop close-on-exec fds from the image's table (POSIX). Pipe ends must
// release their refcount or the reader never sees EOF (writers stays high).
function execDropCloexec(fdMap) {
  for (const [fd, h] of [...fdMap]) if (h && h.cloexec) {
    if (h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; }
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
    this.pgid = this.pid;
    this.sig = { handlers: new Map(), mask: 0n, pending: new Set(), waiters: [] };
    this.timers = new Map();         // which(0=ITIMER_REAL) -> {deadline, intervalMs, to}
    this.stopped = 0; this.stopReported = false; this.contWaiters = [];
    this.cred = { uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0, groups: [] }; // root by default
    this.shmAt = new Map();          // SysV shm attachments: base -> segment
    this.futexWaiters = new Map();   // pthread futexes: uaddr -> [resolver] (see sysAsync 'futex')
    this.curTid = 0;                 // tid of the thread whose syscall is being served (0 = main)
    this.umask = 0o22;
    procs.set(this.pid, this);
  }
  retire() {
    rmEntry(`/.wali_env_${this.pid}`); // else one env file per exec'd process accumulates in / forever
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
            continue; }
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
    return null;
  }
  // Async delivery: run the handler in the guest worker (callGuest), where it sits on
  // the instance's own thread and its syscalls come back here as ordinary requests.
  // This is what makes busybox ping (SIGALRM handler -> sendto) work. Every process
  // runs on its own worker, so callGuest is always set for anything that can carry a
  // handler; a guest whose binary lacks --export-table takes the default action.
  async predeliverAsync() {
    if (!this.sig.pending.size) return null;
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
            continue; }
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
  pollTfd(_t) { /* timerfd expirations are driven by the setTimeout armed in timerfd_settime */ }
  selectReady(fd, forWrite) { // one fd's readiness, for select() (mirrors poll's logic)
    const h = this.fds.get(fd);
    if (!h) return true;                                  // report ready; the read/write reports EBADF
    if (forWrite) return true;                            // pipes/sockets buffer unboundedly here
    if (h.std === 0) return stdinChunks.length > 0 || stdinEOF;
    if (h.std !== undefined) return true;
    if (h.fifo) return h.fifo.chunks.length > 0 || h.fifo.writers <= 0;
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
    if (tp) { const s = Number(this.r64(tp)), x = Number(this.r64(tp + 8)); tmo = s * 1000 + x / (name === 'select' ? 1000 : 1e6); }
    const nb = (nfds + 7) >> 3;
    const commit = () => { this.refresh(); let n = 0;
      for (const p2 of [rp, wp, ep]) if (p2) this.u8.fill(0, p2, p2 + nb);
      for (const fd of rd) if (this.selectReady(fd, false)) { this.u8[rp + (fd >> 3)] |= 1 << (fd & 7); n++; }
      for (const fd of wr) if (this.selectReady(fd, true)) { this.u8[wp + (fd >> 3)] |= 1 << (fd & 7); n++; }
      return n; };
    return { rd, wr, tmo, commit };
  }
  allocFd() { let g = 0; while (this.fds.has(g)) g++; return g; } // POSIX lowest-free fd
  bumpFifo(h) { if (h && h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') h.fifo.readers++; } else if (h && h.spair) { h.spair.wr.writers++; h.spair.rd.readers++; } }
  refresh() { const buf = this.memory.buffer; if (this.membuf !== buf || (this.u8 && this.u8.byteLength !== buf.byteLength)) { this.membuf = buf; this.u8 = new Uint8Array(buf); this.dv = new DataView(buf); } }
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
      _ph = 'compile';
      const mod = new WebAssembly.Module(fileRead(f, 0, f.size));
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
        else if (im.module === 'GOT.func') { gotFunc[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, this.funcIdx(exp[im.name])); }
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
      for (const k in gotFunc) { if (gotFunc[k].value === 0) { const e = inst.exports[k]; if (typeof e === 'function') gotFunc[k].value = this.funcIdx(e); } }
      _ph = 'apply_data_relocs';
      if (inst.exports.__wasm_apply_data_relocs) inst.exports.__wasm_apply_data_relocs();
      _ph = 'call_ctors';
      if (inst.exports.__wasm_call_ctors) inst.exports.__wasm_call_ctors();
      this.refresh();
      this.dlHandles.push({ inst, symCache: new Map() });
      return this.dlHandles.length - 1;
    } catch (e) {
      if (e instanceof NeedAsync) throw e;   // in-process engine: the .so is being fetched; the import re-runs this
      post('[host] dlopen(' + guestPath + ') failed at [' + (typeof _ph === 'string' ? _ph : '?') + ']: ' + e.message + '\n', 2); return -1;
    }
  }
  dlsym(handle, sym) {
    const h = this.dlHandles[handle]; if (!h) return -1;
    if (h.symCache.has(sym)) return h.symCache.get(sym);
    const fn = h.inst.exports[sym]; if (typeof fn !== 'function') return -1;
    const idx = this.funcIdx(fn); h.symCache.set(sym, idx); return idx;
  }
  funcIdx(fn) { // install a funcref into the shared table, return its index (dlsym / GOT.func)
    if (typeof fn !== 'function') return 0;
    const table = this.inst.exports.__indirect_function_table;
    const idx = table.length; table.grow(1); table.set(idx, fn); return idx;
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
    // lstat still resolves the PARENT components (only the final one is left alone), and
    // the OPFS fault-in has to happen on the resolved path -- `ls /files/` stats each
    // entry as /files/<name> with lstat, which used to miss everything behind the link.
    path2 = followLinks ? this.follow(path2) : this.followDir(path2);
    opfsFault(path2);
    if (dirs.has(path2)) { this.putStat(sp, { size: 4096, mode: 0o040755, ino: inoOf(path2) }); return 0n; }
    const f = files.get(path2); if (!f) return err(E.NOENT);
    if (f.sym !== undefined) { this.putStat(sp, { size: f.sym.length, mode: 0o120777, ino: inoOf(f) }); return 0n; }
    this.putStat(sp, { size: f.size, mode: f.mode, mtimeMs: f.mtimeMs, uid: f.uid ?? 0, gid: f.gid ?? 0, ino: inoOf(f) });
    return 0n;
  }
  openAt(path2, flags, mode) {
    const O_CREAT = 0o100, O_TRUNC = 0o1000, O_APPEND = 0o2000, O_DIRECTORY = 0o200000, O_EXCL = 0o200;
    const ce = !!(flags & 0o2000000); // O_CLOEXEC: dropped from the fd table at execve
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
    path2 = this.follow(path2);   // a symlink to a directory (/files -> /root) opens the directory it points at
    opfsFault(path2);             // ...and the fault-in must be on the RESOLVED path
    if (dirs.has(path2)) { const g = this.allocFd(); this.fds.set(g, { path: path2, dir: true, cloexec: ce }); return BigInt(g); }
    if (flags & O_DIRECTORY) {   // POSIX: a MISSING dir is ENOENT, not ENOTDIR (git index-pack scans objects/XX and treats ENOTDIR as fatal)
      if (files.has(path2)) return err(E.NOTDIR);                                   // path exists as a file
      const _par = path2.slice(0, path2.lastIndexOf('/')) || '/';
      return err(dirs.has(_par) ? E.NOENT : E.NOTDIR);                              // missing under a real dir -> ENOENT; parent not a dir -> ENOTDIR
    }
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
      if (inOpfs(path2)) { f.br = opfsRel(path2); f.data = null; opfsHandle(f, true); // new files under the mount persist
        if ((f.mode & 0o7777) !== (OPFS_DEFAULT_MODE & 0o7777)) opfsSaveMode(f); }   // ...and so does a 0600 asked for at create (ssh-keygen)
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) return err(E.EXIST);
    if (flags & O_TRUNC) {
      if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, 0, 0, null); }
      else f.data = new Uint8Array(0);
      f.size = 0;
    }
    const g = this.allocFd();
    // `off` is a shared cell (the POSIX "open file description" offset). dup/dup2/F_DUPFD and
    // fork copy the handle with `{...h}`, which copies `off` BY REFERENCE — so all those fds
    // share ONE file offset. Storing the offset as a bare number would give each a private copy,
    // which corrupts `{ echo a; cmd|cmd; echo b; } > file` (forked writers clobber each other).
    this.fds.set(g, { path: path2, file: f, off: { v: (flags & O_APPEND) ? f.size : 0 }, append: !!(flags & O_APPEND), cloexec: ce });
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
        if (h.std !== undefined) { if (h.std !== 0) return err(E.BADF);
          const b = drainStdinAsync(a[2]); if (b === null) return h.nonblock ? err(E.AGAIN) : 0n; S.wbytes(a[1], b); return BigInt(b.length); }
        if (h.fifo) { if (!h.fifo.chunks.length && h.nonblock && h.fifo.writers > 0) return err(E.AGAIN); const b = pipeRead(h.fifo, a[2]); S.wbytes(a[1], b); return BigInt(b.length); }
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
        const b = fileRead(h.file, h.off.v, a[2]); if (ioFailed()) return err(E.IO); S.wbytes(a[1], b); h.off.v += b.length; return BigInt(b.length);
      }
      case 'write': { if ((a[2] | 0) < 0) return err(E.INVAL); // guard: negative size must not slice from the end
        const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        S.refresh();
        if (h.std !== undefined) { post(td.decode(S.u8.slice(a[1], a[1] + a[2])), h.std === 0 ? 1 : h.std); return BigInt(a[2]); }
        if (h.fifo) { if (h.fifo.readers <= 0) { postSignal(S, SIG.PIPE); return err(E.PIPE); } // no reader will ever come back: SIGPIPE (dfl kills) + EPIPE
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
        const w = fileWrite(h.file, h.append ? h.file.size : h.off.v, S.u8.slice(a[1], a[1] + a[2])); if (ioFailed()) return err(E.IO); h.off.v += w; return BigInt(w);
      }
      case 'writev': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('write', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; } return t; }
      case 'readv': { let t = 0n; for (let i = 0; i < a[2]; i++) { const p = S.r32(a[1] + i * 8), l = S.r32(a[1] + i * 8 + 4); if (!l) continue; const r = S.sys('read', [a[0], p, l]); if (r < 0n) return t > 0n ? t : r; t += r; if (Number(r) < l) break; } return t; }
      case 'pread64': case 'pread': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); if (!h.file) return err(E.SPIPE);
        const b = fileRead(h.file, Number(a[3]), a[2]); S.wbytes(a[1], b); return BigInt(b.length); }   // positional read, does NOT move the fd offset (git reads packs this way)
      case 'pwrite64': case 'pwrite': { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF);
        const w = fileWrite(h.file, Number(a[3]), S.u8.slice(a[1], a[1] + a[2])); return BigInt(w); }
      case 'open': return S.openAt(S.atPath(-100, S.cstr(a[0])), a[1], a[2]);
      case 'openat': return S.openAt(S.atPath(a[0], S.cstr(a[1])), a[2], a[3]);
      case 'close': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF);
        if (h.fifo) { if (h.end === 'w') { if (--h.fifo.writers <= 0) wakePipe(h.fifo); } else if (h.end === 'r') h.fifo.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.spair) { if (--h.spair.wr.writers <= 0) wakePipe(h.spair.wr); h.spair.rd.readers--; S.fds.delete(a[0]); return 0n; }
        if (h.tfd) { if (h.tfd.to) clearTimeout(h.tfd.to); const w = h.tfd.waiters; h.tfd.waiters = []; for (const f of w) f('t'); S.fds.delete(a[0]); return 0n; }
        // a dup'd/forked socket fd shares ONE wisp stream — only an unshared close may
        // tear it down, or a child's close_range kills the parent's live connection.
        // Closing a local listener frees the port, or the next bind of it would get a
        // (this time genuine) EADDRINUSE from a listener nobody can reach any more.
        if (h.sock && h.sock.local && h.sock.listener && !h.shared
            && localListeners.get(h.sock.local.port) === h.sock.local) localListeners.delete(h.sock.local.port);
        if (h.sock && h.sock.id && !h.shared) initWisp().call(initWisp().OP.CLOSE, h.sock.id, 0, 0);
        S.fds.delete(a[0]); S.dirState.delete(a[0]);
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
        return S.statPath(h.path, a[1]); }
      case 'stat': case 'lstat': { const p = S.atPath(-100, S.cstr(a[0])); let m;
        if (p === '/dev/ptmx') { S.putStat(a[1], ptyStatObj(0, true)); return 0n; }
        if ((m = p.match(/^\/dev\/pts\/(\d+)$/))) { if (!ptys.has(+m[1])) return err(E.NOENT); S.putStat(a[1], ptyStatObj(+m[1], false)); return 0n; }
        if (p === '/dev/null' || p === '/dev/tty' || p === '/dev/urandom' || p === '/dev/random'
            || p === '/dev/zero' || p === '/dev/full' || p === '/dev/stdin' || p === '/dev/stdout' || p === '/dev/stderr')
          { S.putStat(a[1], { size: 0, mode: 0o020666 }); return 0n; }
        return S.statPath(p, a[1], name === 'stat'); }
      case 'newfstatat': { const s = S.cstr(a[1]); return s === '' ? S.sys('fstat', [a[0], a[2]]) : S.statPath(S.atPath(a[0], s), a[2]); }
      case 'access': case 'faccessat': case 'faccessat2': {
        const p = name === 'access' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1]));
        if (p === '/proc/self/exe') return 0n;
        if (p === '/dev/null' || p === '/dev/tty' || p === '/dev/ptmx' || p === '/dev/urandom' || p === '/dev/random'
            || p === '/dev/zero' || p === '/dev/full' || p === '/dev/stdin' || p === '/dev/stdout' || p === '/dev/stderr')
          return 0n; // devices exist (scripts' `test -e`)
        { const m = p.match(/^\/dev\/pts\/(\d+)$/); if (m) return ptys.has(+m[1]) ? 0n : err(E.NOENT); }
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
        if (protectedDelete(S, p)) return err(E.PERM);
        const f = files.get(p);
        if (f.br !== undefined) { const r = opfsPathOp(OFS.UNLINK, f.br); if (r < 0) return BigInt(r); f.brId = 0; }
        rmEntry(p); return 0n; }
      case 'rmdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); if (!dirs.has(p)) return err(E.NOENT);
        if (protectedDelete(S, p)) return err(E.PERM);
        if (dirs.get(p).size) return err(E.NOTEMPTY);
        if (inOpfs(p) && p !== opfsMount) { const r = opfsPathOp(OFS.RMDIR, opfsRel(p)); if (r < 0 && r !== -E.NOENT) return BigInt(r); }
        rmEntry(p); return 0n; }
      case 'mkdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p);
        // POSIX: mkdir(2) on an existing path is EEXIST. This used to call mkdirp()
        // straight away, which is idempotent, so the syscall had `mkdir -p` semantics and
        // silently succeeded on a directory that was already there. `mkdir -p` still works:
        // busybox tolerates EEXIST itself, which is exactly how it is meant to be built.
        if (dirs.has(p) || files.has(p)) return err(E.EXIST);
        mkdirp(p);
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
        opfsFault(pa); opfsFault(pb);
        if (!isAppPath(pb) && protectedDelete(S, pa)) return err(E.PERM);   // moving out of the workspace == deleting it
        // the new name keeps the old file's identity: mode (+x!), owner, times, symlink target
        const keepAttrs = (nf, of) => { nf.mode = of.mode; if (of.uid !== undefined) nf.uid = of.uid; if (of.gid !== undefined) nf.gid = of.gid; nf.mtimeMs = of.mtimeMs; if (of.sym !== undefined) nf.sym = of.sym; };
        if (dirs.has(pa)) {                              // directory rename: re-key the whole subtree
          if (files.has(pb)) return err(E.NOTDIR);
          if (pb === pa || pb.startsWith(pa + '/')) return err(E.INVAL);
          if (dirs.has(pb) && dirs.get(pb).size) return err(E.NOTEMPTY);
          if (inOpfs(pa) || inOpfs(pb)) return err(E.XDEV); // mv falls back to copy+rm through the store
          rmEntry(pb);
          const paParent = pa.slice(0, pa.lastIndexOf('/')) || '/';
          const pd = dirs.get(paParent); if (pd) pd.delete(pa.slice(pa.lastIndexOf('/') + 1));
          for (const [k, v] of [...files]) if (k.startsWith(pa + '/')) { files.delete(k); files.set(pb + k.slice(pa.length), v); }
          for (const [k, v] of [...dirs]) if (k === pa || k.startsWith(pa + '/')) { dirs.delete(k); dirs.set(pb + k.slice(pa.length), v); }
          const pbParent = pb.slice(0, pb.lastIndexOf('/')) || '/'; mkdirp(pbParent);
          dirs.get(pbParent).add(pb.slice(pb.lastIndexOf('/') + 1));
          return 0n; }
        const f = files.get(pa); if (!f) return err(E.NOENT);
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
      case 'chdir': { const p = S.atPath(-100, S.cstr(a[0])); opfsFault(p); if (!dirs.has(p)) return err(E.NOTDIR); S.cwd.p = p; return 0n; }
      case 'fchdir': { const h = S.fds.get(a[0]); if (!h || !h.dir) return err(E.BADF); S.cwd.p = h.path; return 0n; }
      case 'getcwd': return BigInt(S.wstr(a[0], S.cwd.p, a[1]) + 1);
      case 'chmod': case 'fchmodat': { const p = S.follow(S.atPath(name === 'chmod' ? -100 : a[0], S.cstr(name === 'chmod' ? a[0] : a[1])));
        opfsFault(p); const md = name === 'chmod' ? a[1] : a[2];
        if (dirs.has(p)) return 0n;
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
      case 'utimensat': case 'utimes': case 'futimesat': { // touch/make set mtimes (atime not modeled)
        const UTIME_NOW = 0x3fffffff, UTIME_OMIT = 0x3ffffffe;
        let f;
        if (name !== 'utimes' && !a[1]) { const h = S.fds.get(a[0]); if (!h || !h.file) return err(E.BADF); f = h.file; } // futimens: NULL path = the fd itself
        else { const p = S.follow(name === 'utimes' ? S.atPath(-100, S.cstr(a[0])) : S.atPath(a[0], S.cstr(a[1])));
          opfsFault(p);
          if (dirs.has(p)) return 0n;
          f = files.get(p); if (!f) return err(E.NOENT); }
        const tp = name === 'utimes' ? a[1] : a[2];
        let mt = Date.now();
        if (tp) { S.refresh();
          if (name === 'utimes') mt = Number(S.r64(tp + 16)) * 1000 + Number(S.r64(tp + 24)) / 1000; // timeval[1] = mtime
          else { const ns = Number(S.r64(tp + 16 + 8));                                              // timespec[1] = mtime
            if (ns === UTIME_OMIT) return 0n;
            if (ns !== UTIME_NOW) mt = Number(S.r64(tp + 16)) * 1000 + ns / 1e6; } }
        f.mtimeMs = mt; return 0n; }
      case 'statfs': case 'fstatfs': { const sp2 = a[1]; S.refresh();
        S.u8.fill(0, sp2, sp2 + 120);
        S.i64(sp2, 0x858458f6n); S.i64(sp2 + 8, 4096n); S.i64(sp2 + 16, 1n << 20n);
        S.i64(sp2 + 24, 1n << 19n); S.i64(sp2 + 32, 1n << 19n); S.i64(sp2 + 40, 1n << 16n);
        S.i64(sp2 + 48, 1n << 15n); S.i64(sp2 + 64, 255n); S.i64(sp2 + 72, 4096n); return 0n; }
      case 'dup': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true; const g = S.allocFd(); S.fds.set(g, { ...h, cloexec: false }); S.bumpFifo(h); return BigInt(g); }
      case 'dup2': case 'dup3': { const h = S.fds.get(a[0]); if (!h) return err(E.BADF); h.shared = true;
        if (a[0] !== a[1]) { const old = S.fds.get(a[1]);
          if (old && old.fifo) { if (old.end === 'w') { if (--old.fifo.writers <= 0) wakePipe(old.fifo); } else old.fifo.readers--; }
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
        // and the parent branch continues. Every walios binary carries this wrapper
        // (git, the remote helpers, python_cxx, busybox) -- a binary that ALSO exports
        // asyncify_* (busybox) never gets here; its fork is the real, twice-returning one.
        if (PLAIN_MUSL_FORK.test(S.modKey || '')) {
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
        S.childStack.push({ pid, fds: cfds, tid: S.curTid || 0, cwd: { p: S.cwd.p }, umask: S.umask, sig: csig });
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
          if (inOpfs(h.path)) { opfsLoaded.delete(h.path); opfsLoadDir(h.path); }
          st = { names: ['.', '..', ...dirs.get(h.path)], pos: 0 }; S.dirState.set(a[0], st);
        }
        let off = 0;
        while (st.pos < st.names.length) {
          const nm = st.names[st.pos]; const nb = te.encode(nm);
          const reclen = (19 + nb.length + 1 + 7) & ~7;
          if (off + reclen > a[2]) break;
          const full = h.path === '/' ? '/' + nm : h.path + '/' + nm;
          const fe = files.get(full);
          const type = dirs.has(full) || nm === '.' || nm === '..' ? 4 : (fe && fe.sym !== undefined) ? 10 : 8; // DT_DIR/DT_LNK/DT_REG
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
        return 0n; }
      case 'clock_gettime': { if (a[0] === 1 || a[0] === 4) { const ms = performance.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt(Math.floor((ms % 1000) * 1e6))); return 0n; }
        const ms = Date.now(); S.i64(a[1], BigInt(Math.floor(ms / 1000))); S.i64(a[1] + 8, BigInt((ms % 1000) * 1e6)); return 0n; }
      case 'gettimeofday': { const ms = Date.now(); S.i64(a[0], BigInt(Math.floor(ms / 1000))); S.i64(a[0] + 8, BigInt((ms % 1000) * 1000)); return 0n; }
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
      case 'getpgid': { const q = a[0] | 0; if (!q || q === S.pid) return BigInt(S.pgid);
        const T = procs.get(q); return T ? BigInt(T.pgid) : err(E.SRCH); }
      case 'getpgrp': return BigInt(S.pgid);
      case 'setpgid': { const T = (a[0] | 0) && (a[0] | 0) !== S.pid ? procs.get(a[0] | 0) : S;
        if (!T) return err(E.SRCH); T.pgid = (a[1] | 0) || T.pid; return 0n; }
      case 'setsid': { S.pgid = S.pid; return BigInt(S.pid); }
      case 'set_tid_address': return BigInt(S.curTid || S.pid);
      case 'tkill': case 'tgkill': case 'kill': {
        const sig = name === 'tgkill' ? (a[2] | 0) : (a[1] | 0);
        const pid = name === 'tgkill' ? (a[1] | 0) : (a[0] | 0);
        const isSelf = (q) => q === S.pid || (S.inChild() && S.childStack.some(c => c.pid === q));
        if (!sig) { if (name === 'kill' && pid <= 0) return 0n; return (procs.has(pid) || isSelf(pid)) ? 0n : err(E.SRCH); }
        const targets = [];
        if (name === 'kill' && pid <= 0) {
          if (pid === -1) { for (const T of procs.values()) if (T !== S) targets.push(T); } // Linux: -1 excludes the caller
          else { const pg = pid === 0 ? S.pgid : -pid; for (const T of procs.values()) if (T.pgid === pg) targets.push(T); }
          if (!targets.length) return err(E.SRCH);
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
          if (!T) return err(E.SRCH);
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
      case 'sigaltstack': case 'prctl': case 'rt_sigreturn': return 0n;
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
      case 'getrusage': { S.refresh(); S.u8.fill(0, a[1], a[1] + 144); return 0n; }
      case 'sysinfo': { S.refresh(); S.u8.fill(0, a[0], a[0] + 112); S.i64(a[0], 1000n); S.i64(a[0] + 32, 4294967296n); S.i64(a[0] + 40, 2147483648n); return 0n; }
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
            const ctl = S.r32(a[1] + 20), ctllen = S.r32(a[1] + 24);
            if (ctl && ctllen >= 16) { const clen = S.r32(ctl), lvl = S.r32(ctl + 8), typ = S.r32(ctl + 12);
              if (lvl === 1 && typ === 1) { const nf = (clen - 16) >> 2; h.spair.wr.fds = h.spair.wr.fds || [];
                for (let i = 0; i < nf; i++) { const fd = S.r32(ctl + 16 + i * 4); const hh = S.fds.get(fd); if (hh) { h.spair.wr.fds.push({ ...hh, shared: true }); S.bumpFifo(hh); } } } }
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
        if (h && h.fifo && !h.nonblock) { while (!h.fifo.chunks.length && h.fifo.writers > 0) {           const w = await S.sigRace(res => h.fifo.readWaiters.push(() => res('ev')));
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
        if (fop === 1 || fop === 10) {                       // FUTEX_WAKE / WAKE_BITSET
          const wl = S.futexWaiters.get(uaddr); let n = 0;
          if (wl) { while (wl.length && n < val) { wl.shift()('wake'); n++; } if (!wl.length) S.futexWaiters.delete(uaddr); }
          return BigInt(n); }
        if (fop === 0 || fop === 9) {                        // FUTEX_WAIT / WAIT_BITSET (absolute time)
          if (S.dv.getInt32(uaddr, true) !== val) return err(E.AGAIN);
          let ms = Infinity;
          if (a[3]) { const abs = fop === 9, realtime = !!(a[1] & 0x100);
            ms = Number(S.r64(a[3])) * 1000 + Number(S.r64(a[3] + 8)) / 1e6;
            if (abs) ms -= realtime ? Date.now() : performance.now(); }
          let wl = S.futexWaiters.get(uaddr); if (!wl) S.futexWaiters.set(uaddr, wl = []);
          let mine = null;
          const w = await S.sigRace((fin) => { mine = fin; wl.push(fin); if (Number.isFinite(ms)) setTimeout(() => fin('t'), Math.max(0, Math.min(ms, 3600000))); });
          const k = wl.indexOf(mine); if (k >= 0) wl.splice(k, 1);
          if (!wl.length && S.futexWaiters.get(uaddr) === wl) S.futexWaiters.delete(uaddr);
          if (w === 'wake') return 0n;
          if (w === 't') return err(E.TIMEDOUT);
          const v = await (back(), S).onSigWakeAsync(false); if (v !== null) return v;
          return err(E.INTR); }
        return (back(), S).sys(name, a);
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
    if (h.fifo) { while (!h.fifo.chunks.length && h.fifo.writers > 0) await race((f) => h.fifo.readWaiters.push(f)); return; }
    if (h.hostcall) { while (!h.hostcall.chunks.length) await race((f) => h.hostcall.waiters.push(f)); return; }
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
        addFile(`/.wali_env_${S.pid}`, te.encode(safe.join('\n') + '\n'));
        S.wstr(buf, `/.wali_env_${S.pid}`, sz); return 1;
      };
      else if (name === 'log_execution') { // wasm-opt --log-execution preemption hook
        // (see farm/instrument-preempt.sh; instrumented binaries must be linked
        // WITHOUT --shared-memory so the start section stays uninstrumented)
        let fuel = 0;
        wali[name] = () => { if (++fuel & 0x3fff) return; S.pollTimers(); if (S.sig.pending.size) { S.sigDelivered = false; S.predeliver(); } };
      }
      else if (name === '__cl_get_argc') wali[name] = () => S.argv.length;
      else if (name === '__cl_get_argv_len') wali[name] = (i) => te.encode(S.argv[i] || '').length;
      else if (name === '__cl_copy_argv') wali[name] = (buf, i) => S.wstr(buf, S.argv[i] || '', 0);
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
        if (files.has(lp) || dirs.has(lp)) return 20;                               // EEXIST
        addFile(lp, new Uint8Array(0), 0o120777); files.get(lp).sym = target; return OK; },
      fd_filestat_set_size: (fd, size) => { const h = S.fds.get(fd); if (!h || !h.file) return BADF;
        const n = Number(size); const f = h.file;
        if (f.br !== undefined) { const id = opfsHandle(f, true); if (id) initOpfs().call(OFS.TRUNC, id, n, 0, null); f.size = n; return OK; }
        if (n <= f.size) { f.size = n; return OK; }
        const nd = new Uint8Array(Math.max(n, f.data ? f.data.length : 0)); if (f.data) nd.set(f.data.subarray(0, f.size)); f.data = nd; f.size = n; return OK; },
      fd_filestat_set_times: () => OK,
      environ_sizes_get: (cptr, sptr) => { S.i32(cptr, S.env.length); S.i32(sptr, S.env.reduce((a, e) => a + te.encode(e).length + 1, 0)); return OK; },
      environ_get: (eptr, bptr) => { let b = bptr; for (const e of S.env) { S.i32(eptr, b); eptr += 4; b += S.wstr(b, e, 0) + 1; } return OK; },
      args_sizes_get: (cptr, sptr) => { S.i32(cptr, S.argv.length); S.i32(sptr, S.argv.reduce((a, e) => a + te.encode(e).length + 1, 0)); return OK; },
      args_get: (aptr, bptr) => { let b = bptr; for (const a of S.argv) { S.i32(aptr, b); aptr += 4; b += S.wstr(b, a, 0) + 1; } return OK; },
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
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); return 127; }
    const plan = this._workerPlan(mod);
    if (!plan) { post(`[host] no import signatures for ${this.modKey} (compiled without bytes)\n`, 2); return 127; }
    this._plan = plan;
    // Staging buffer for dlopen: the guest links side modules itself (it owns the
    // instance) but cannot read the VFS, and a parked thread cannot be handed a new
    // SharedArrayBuffer -- so one growable buffer is installed up front and every .so
    // travels through it. Growable SAB is Chrome 111+; fall back to a fixed 32MB.
    const spare = SPARE_OK(plan, opts) ? takeSpare(this.modKey) : null;
    let bulk;
    if (spare) { bulk = spare.bulk; }
    else {
      try { bulk = new SharedArrayBuffer(1 << 20, { maxByteLength: 64 << 20 }); }
      catch (_) { bulk = new SharedArrayBuffer(32 << 20); }
    }
    this._bulk = bulk;
    const ctl = spare ? spare.ctl : new SharedArrayBuffer(KCTL.BYTES);
    const w = spare ? spare.w : new Worker(NODE_STUB_RE.test(this.modKey) ? NODE_WORKER_URL : 'wali-proc-worker.js');
    this.procWorker = w;
    const st = { exit: null };
    const ready = spare ? spare.ready : new Promise((res) => { this._procReady = res; });
    // The spare may not have seen its own 'ready' yet, and installing this process's
    // onmessage below replaces the handler that was waiting for it -- so route it here.
    if (spare) this._procReady = spare.settle;
    w.onmessage = (ev) => {
      const m = ev.data;
      if (m.t === 'ready') { this._procReady(m); return; }
      if (m.t === 'warn') { post('[host] ' + m.s + '\n', 2); return; }
      if (m.t === 'trap') { post(`[host] trap in pid ${this.pid}: ${m.error}\n`, 2); return; }
      if (m.t === 'exit') { st.exit = m.code; }
    };
    w.onerror = (ev) => { post(`[host] process worker for pid ${this.pid} failed: ${ev.message || ev}\n`, 2);
                          if (st.exit === null) st.exit = 139; Atomics.store(new Int32Array(ctl), 0, KCTL.DONE); Atomics.notify(new Int32Array(ctl), 0); };
    if (!spare) w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk, memory: plan.memory });
    const r = await ready;
    // Start the NEXT one warming while this process runs -- a build is the same few modules
    // over and over, so the guess is nearly always right.
    if (SPARE_OK(plan, opts)) { try { prepareSpare(this.modKey, plan); } catch (_) {} }
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
      w.postMessage({ t: 'rewind', asyncifyBuf: opts.asyncifyBuf, sp: opts.sp, tls: opts.tls });
    } else {
      w.postMessage({ t: 'run' });
    }
    const res = await this._serve(w, ctl, plan, bulk, st, true, this.pid);
    for (const t of this._threads || []) { try { t.terminate(); } catch (_) {} }
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
    const ctl = new SharedArrayBuffer(KCTL.BYTES);
    const w = new Worker('wali-proc-worker.js');
    (this._threads = this._threads || []).push(w);
    const st = { exit: null };
    const ready = new Promise((res) => {
      w.onmessage = (ev) => { const m = ev.data;
        if (m.t === 'ready') res(m);
        else if (m.t === 'warn') post('[host] ' + m.s + '\n', 2);
        else if (m.t === 'trap') post(`[host] thread ${tid} of pid ${this.pid}: ${m.error}\n`, 2); };
    });
    w.onerror = (ev) => { post(`[host] thread ${tid} of pid ${this.pid} failed: ${ev.message || ev}\n`, 2);
                          Atomics.store(new Int32Array(ctl), 0, KCTL.DONE); Atomics.notify(new Int32Array(ctl), 0); };
    w.postMessage({ t: 'init', mod, ctl, names: plan.names, sigs: plan.sigv, bulk: this._bulk, memory: this.memory });
    ready.then((r) => {
      if (!r.ok) { post(`[host] thread ${tid} of pid ${this.pid} failed to start: ${r.error}\n`, 2); return; }
      w.postMessage({ t: 'run', mode: 'thread', entry, tid, startArg: Number(startArg) });
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
        if (sysname && BLOCKING.has(sysname)) {
          // A blocking syscall must NOT run inline on this thread: sysAsync is the
          // promise-based twin; awaiting it keeps the event loop free, which is the
          // whole point of running guests on their own threads.
          const margs = args.map((x) => (typeof x === 'bigint' && sysname !== 'mmap') ? i64arg(x) : x);
          if (STRACE) stracePost(`[strace ${this.pid}${tid && tid !== this.pid ? '.' + tid : ''}] ${sysname}(${margs.join(', ')}) ...\n`, 2);   // entry of a blocking call: a hang shows who is parked where
          v = await S_await(this, sysname, margs);
          this.curTid = tid;    // another thread's syscall may have been served meanwhile (inChild/fds key on it)
        } else {
          const h = handlers[idx];
          if (!h) throw new Error('no handler for ' + nm);
          v = h(...args);
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
    for (;;) {
      const state = Atomics.load(i32, 0);
      if (state === KCTL.DONE) break;
      if (state === KCTL.FORKED && isMain) {
        // The guest has unwound and wants a child. Build it, boot its worker and copy the
        // snapshot BEFORE replying -- the parent must not resume until the copy is taken.
        const childPid = nextPid++;
        const child = this.spawnForkChildMeta(childPid);
        const buf = Number(i64[KCTL.RET >> 3]);
        const sp = Number(i64[KCTL.ARGS >> 3]), tls = Number(i64[(KCTL.ARGS >> 3) + 1]);   // parent's stack pointer / TLS base (-1: not exported)
        let started;
        const boot = new Promise((res) => { started = res; });
        const task = child.runInWorker({ forkFrom: this, asyncifyBuf: buf, sp, tls, onForkReady: started })
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
          for (let k = 0; k < a4; k++) spec.push([this.r32(a3 + k * 8), this.r32(a3 + k * 8 + 4)]);
        } catch (_) { reply(BigInt(-E.INVAL)); continue; }
        const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
        // The await let other threads run and they move curTid, which is what fds keys
        // on (see the execve handler for what that cost the last time).
        this.curTid = tid;
        if (!target) { reply(BigInt(-E.NOENT)); continue; }
        let childFds;
        try { childFds = spawnFdTable(this.fds, spec); }
        catch (e) { reply(BigInt(-(e && e.badf ? E.BADF : E.INVAL))); continue; }
        const proc = new Process(target.key, target.argv, ev || this.env, childFds, this.cwd.p);
        if (this.cred) proc.cred = { ...this.cred };
        proc.ppid = this.pid; proc.pgid = this.pgid;
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
        if (!target) { reply(BigInt(-E.NOENT)); continue; }
        const fdsnap = execDropCloexec(this.fds);
        if (this.inChild()) {
          // vfork protocol (see sys 'fork'): the guest is in the child branch, so this
          // execve is the CHILD's. Start it on its own worker under the pid fork()
          // reported, hand the parent its state back and answer CHILD_DONE so the libc
          // wrapper longjmps to the fork site.
          const ctx = this.childStack[this.childStack.length - 1];
          const childPid = ctx.pid;
          this.childStack.pop(); this.unVfork(ctx);
          const task = Promise.resolve(startProcess(target, ev, fdsnap, this.cwd.p, this.cred, childPid)).then((code) => {
            this.reaped.set(childPid, code === null ? 127 : code);
            releaseFds(fdsnap);
            this.childTasks.delete(childPid);
            postSignal(this, SIG.CHLD); wakeWaiters(this);
            return code;
          });
          const cp = procs.get(childPid); if (cp) { cp.ppid = this.pid; cp.pgid = this.pgid; }
          inflight.add(task); task.finally(() => inflight.delete(task));
          this.childTasks.set(childPid, task);
          reply(CHILD_DONE);
          continue;
        }
        Atomics.store(i32, 3, 0);
        Atomics.store(i32, 0, KCTL.DIE);
        Atomics.notify(i32, 0);
        const code = await startProcess(target, ev, fdsnap, this.cwd.p, this.cred, this.pid);
        w.terminate();
        // NOT retire(): the new image owns this pid now, and retire() does
        // procs.delete(this.pid) -- which would delete the process that just replaced us
        // and leave the parent's wait4 with nothing to reap.
        return { replaced: (code === null ? 127 : code) & 0xff };
      }
      if (state === KCTL.REQ) { await Promise.race([serveReq(), gone]); if (exited) break; continue; }
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
            else if (blocking) v = await Promise.race([S_await(S, sysname, map(a2)), S._goneP]);
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
        if (blocking || special || S.sig.pending.size || S.stopped || S._dead !== undefined || Date.now() - S.lastYield >= QUANTUM_MS) return slow(a2);
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
    procCount++;
    const mod = modCache.get(this.modKey);
    if (!mod) { post(`[host] no module for ${this.modKey}\n`, 2); this.retire(); return 127; }
    // A clean JS stack: a promising export must not start inside another guest's
    // suspending import (execve and posix_spawn get here from one).
    await new Promise((res) => setTimeout(res, 0));
    try { this.inst = new WebAssembly.Instance(mod, this._makeInProcImports(mod)); }
    catch (e) { post(`[host] pid ${this.pid} failed to start: ${(e && e.message) || e}\n`, 2); this.retire(); return 127; }
    this._inprocInit();
    const res = await this._driveInProc(false);
    if (res.replaced !== undefined) return res.replaced;   // execve: the new image owns this pid; it retires itself
    this.retire();
    return res.code;
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
    if (!target) return err(E.NOENT);
    const fdsnap = execDropCloexec(this.fds);
    if (this.inChild()) {
      // vfork protocol (see sys 'fork'): the guest is in the child branch, so this execve
      // is the CHILD's. Start it under the pid fork() reported, hand the parent its state
      // back and answer CHILD_DONE so the libc wrapper longjmps to the fork site.
      const ctx = this.childStack[this.childStack.length - 1];
      const childPid = ctx.pid;
      this.childStack.pop(); this.unVfork(ctx);
      const task = Promise.resolve(startProcess(target, ev, fdsnap, this.cwd.p, this.cred, childPid)).then((code) => {
        this.reaped.set(childPid, code === null ? 127 : code);
        releaseFds(fdsnap);
        this.childTasks.delete(childPid);
        postSignal(this, SIG.CHLD); wakeWaiters(this);
        return code;
      });
      const cp = procs.get(childPid); if (cp) { cp.ppid = this.pid; cp.pgid = this.pgid; }
      inflight.add(task); task.finally(() => inflight.delete(task));
      this.childTasks.set(childPid, task);
      return CHILD_DONE;
    }
    throw new ReplacedError(Promise.resolve(startProcess(target, ev, fdsnap, this.cwd.p, this.cred, this.pid)));
  }

  // posix_spawn(pathPtr, argvPtr, envpPtr, fdmapPtr, fdmapLen) -> pid | -errno, in-process.
  async _posixSpawnInProc(a) {
    const [a0, a1, a2, a3, a4] = a;
    let path = '', av = [], ev = null; const spec = [];
    try {
      path = this.cstr(a0); av = this.rPtrArray(a1); ev = a2 ? this.rPtrArray(a2) : null;
      for (let k = 0; k < a4; k++) spec.push([this.r32(a3 + k * 8), this.r32(a3 + k * 8 + 4)]);
    } catch (_) { return err(E.INVAL); }
    const target = await resolveExec(path, av, this.cwd.p, this.modKey, 0);
    if (!target) return err(E.NOENT);
    let childFds;
    try { childFds = spawnFdTable(this.fds, spec); }
    catch (e) { return err(e && e.badf ? E.BADF : E.INVAL); }
    const proc = new Process(target.key, target.argv, ev || this.env, childFds, this.cwd.p);
    if (this.cred) proc.cred = { ...this.cred };
    proc.ppid = this.pid; proc.pgid = this.pgid;
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
    child.pid = childPid; child.pgid = this.pgid; child.ppid = this.pid; child.cred = { ...this.cred };
    for (const [b, at] of this.shmAt) child.shmAt.set(b, { seg: at.seg, shadow: at.shadow.slice() });
    procs.set(childPid, child);
    child.fds = new Map([...this.fds].map(([k, v]) => { v.shared = true; return [k, { ...v }]; }));
    for (const v of child.fds.values()) child.bumpFifo(v);
    child.heapBrk = this.heapBrk; child.ctty = this.ctty;
    child.nextFd = this.nextFd; child.umask = this.umask;
    child.sig.handlers = new Map(this.sig.handlers); child.sig.mask = this.sig.mask;
    return child;
  }

}

let lazyTars = {};                 // moduleKey -> [[tarUrl, mountPrefix], ...] (loaded once, on first exec)
let mmapPool = true;               // recycle munmap'd anon regions; run-message `noMmapPool` disables (A/B only)
const lazyTarsDone = new Set();
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
      const buf = new Uint8Array(await (await fetch(key)).arrayBuffer());
      modCache.set(key, new WebAssembly.Module(buf));
      modSigs.set(key, parseImportSigs(buf));
      const sm = parseSharedMemImport(buf); if (sm) modSharedMem.set(key, sm);
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
        // Keyed by content identity too: `cc` rewrites /root/hello and the next `./hello`
        // must run the NEW binary, not the cached compile of the old one.
        key = 'vfs:' + vp + '@' + f.size + ':' + Math.floor(f.mtimeMs || 0);
        if (!modCache.has(key)) { const b2 = bytes.slice(); modCache.set(key, new WebAssembly.Module(b2));
          modSigs.set(key, parseImportSigs(b2));                 // the process worker needs these (they were missing: "no import signatures")
          const sm = parseSharedMemImport(b2); if (sm) modSharedMem.set(key, sm); }
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
function scriptExecRewrite(p, argv, cwd) {
  const vp = p.startsWith('/') ? norm(p, '/') : norm(p, cwd);
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
    return { path: interp, argv: [interp.split('/').pop(), ...(arg ? [arg] : []), vp, ...argv.slice(1)] };
  }
  if (f.mode & 0o111) return { path: '/bin/sh', argv: ['sh', vp, ...argv.slice(1)] }; // ENOEXEC fallback
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

async function resolveExec(p, argv, cwd, selfKey, depth) {
  if (!resolveModuleKey(p, selfKey)) {
    const onPath = pathSearch(p, cwd);
    if (onPath) p = onPath;
  }
  if (!resolveModuleKey(p, selfKey) && (depth || 0) < 4) {
    const sc = scriptExecRewrite(p, argv, cwd);
    if (sc) return resolveExec(sc.path, sc.argv, cwd, selfKey, (depth || 0) + 1);
  }
  const key = resolveExecKey(p, cwd, selfKey);
  if (!key) return null;
  if (!(await ensureModule(key))) return null;   // LAZY: fetch + compile on first exec
  return { key, argv };
}

// A spawned child SHARES fd handles with its parent (both hold the same pipe), so every
// inherited handle must take a reference; releaseFds() gives it back when the child
// exits. Getting this wrong does not fail loudly -- the reader simply never sees EOF.
function retainFd(h) {
  if (!h) return h;
  if (h.fifo) { if (h.end === 'w') h.fifo.writers++; else if (h.end === 'r') h.fifo.readers++; }
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

// Start a resolved program as a process on its own worker. `asPid` is the pid of the
// image it replaces -- execve keeps pid, pgid and ppid -- otherwise it gets a fresh one.
// Returns a promise of the exit code (null = could not start).
function startProcess(target, envp, fdTable, cwd, cred, asPid) {
  const proc = new Process(target.key, target.argv, envp, fdTable, cwd);
  if (STRACE) stracePost(`[strace ${asPid || proc.pid}] exec ${target.key} ${JSON.stringify(target.argv.slice(0, 8))}\n`, 2);
  if (cred) proc.cred = { ...cred };
  if (asPid) {
    const old = procs.get(asPid); procs.delete(proc.pid); proc.pid = asPid;
    proc.pgid = old ? old.pgid : asPid;
    if (old && old.ppid) proc.ppid = old.ppid;
    // POSIX: the signal mask and PENDING signals survive execve (handlers reset). A kill
    // that raced the child between fork and exec used to vanish with the old Process
    // object -- `sleep 5 & kill $!` then ran the full 5s and reported 0.
    if (old) { proc.sig.mask = old.sig.mask; for (const s of old.sig.pending) proc.sig.pending.add(s); }
    else for (const Q of procs.values()) if (Q.childTasks && Q.childTasks.has(asPid)) { proc.ppid = Q.pid; break; }
    procs.set(asPid, proc);
  }
  return proc.run();
}

async function runProgramInWorker(p, argv, envp, fdTable, cwd, selfKey, cred, asPid) {
  const target = await resolveExec(p, argv, cwd, selfKey, 0);
  if (!target) return null;
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
      manifest[m.name] = m.url;
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
  if (m.t === 'hostcall-reply') { hostcallReply(m.id, m.reply); return; }   // the host answered a /dev/hostcall request
  if (m.t === 'mount-tar') {   // lazy package bundle, requested by the guest on an import miss
    loadTar(m.url, m.prefix).then(() => self.postMessage({ t: 'tar-mounted', url: m.url, ok: true }),
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
    for (const P of [...procs.values()]) { try { P.groupExit(137); } catch (_) {} }
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
    const all = [...procs.values()];
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
  if (m.t === 'stdin') { const b = typeof m.data === 'string' ? te.encode(m.data) : new Uint8Array(m.data);
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
    if (m.engine === 'inproc') INPROC = true;
    if (INPROC && !INPROC_AVAILABLE) throw new Error('this browser has neither SharedArrayBuffer (cross-origin isolation) nor JSPI (WebAssembly.Suspending); walios cannot run here');
    if (INPROC) post(`[host] engine: in-process (JSPI${typeof SharedArrayBuffer === 'function' ? ', forced' : ', no SharedArrayBuffer'})\n`, 2);
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
        const rb = new Uint8Array(await (await fetch(rk)).arrayBuffer());
        modCache.set(rk, new WebAssembly.Module(rb));
        modSigs.set(rk, parseImportSigs(rb));
        const rsm = parseSharedMemImport(rb); if (rsm) modSharedMem.set(rk, rsm);
      }
    }
    let rootKey = m.wasm;
    if (m.vfsMain) { // run a wasm sitting in the VFS as the root process
      const vp = norm(m.vfsMain, '/'); const f = files.get(vp);
      if (!f) throw new Error('vfsMain not found: ' + vp);
      rootKey = 'vfs:' + vp;
      const bytes = f.br !== undefined ? fileRead(f, 0, f.size) : f.data.subarray(0, f.size);
      if (!modCache.has(rootKey)) { const b2 = bytes.slice(); modCache.set(rootKey, new WebAssembly.Module(b2)); modSigs.set(rootKey, parseImportSigs(b2)); const sm = parseSharedMemImport(b2); if (sm) modSharedMem.set(rootKey, sm); }
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
    const statsTimer = setInterval(() => {
      let mem = 0; for (const p of procs.values()) { try { mem += p.memory.buffer.byteLength; } catch {} }
      self.postMessage({ t: 'stats', mem, procs: procs.size, syscalls: syscallTotal, ms: performance.now() - t0 });
    }, 1000);
    let code;
    try { code = await root.run(); }
    finally { clearInterval(statsTimer); }
    if (opfsBr) { try { opfsBr.call(OFS.RELEASE, 0, 0, 0, null); } catch {}
      for (const f of files.values()) { if (f.brRel) { clearTimeout(f.brRel); f.brRel = 0; } if (f.brId) f.brId = 0; } }
    straceFlush();
    self.postMessage({ t: 'exit', code, ms: performance.now() - t0, syscalls: syscallTotal, procs: procCount });
  } catch (e) {
    post('[host] fatal: ' + (e.stack || e) + '\n', 2);
    self.postMessage({ t: 'exit', code: 127, ms: 0, syscalls: syscallTotal, procs: procCount });
  }
};
