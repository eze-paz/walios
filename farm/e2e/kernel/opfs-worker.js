// OPFS bridge worker: owns ALL OPFS handles so the (synchronous) OS worker can
// fault the tree in lazily over a SharedArrayBuffer — the riscv-vm ?p9lazy model.
// Spawned by the PAGE (or the app worker) as a sibling of wali-worker (a nested worker would
// starve under its blocked parent).
//
// ONE bridge serves EVERY kernel of a tab (WORKER_V bridge4). Each kernel gets its own
// CHANNEL ({t:'sab', ch, sab|port, scope}): its own SAB window, folder scope, change reports,
// watchdog and poison flag. Channels are served concurrently (Atomics.waitAsync per SAB).
// A standalone host (the /walios/ terminal) sends one 'sab' without `ch`: that is channel 0
// and everything works as it always did.
//
// Locks. A sync access handle locks its file against every other handle in the browser
// (except, on Chromium, other 'readwrite-unsafe' ones), and there used to be one bridge per
// kernel: the shell's, the warm Python's and every other conversation's held their own handles
// on the same files, and whichever came second got EBUSY -- "OSError: [Errno 5] Input/output
// error" in Python. Now:
//   - READS take no lock at all: a file opened for reading is read through a File snapshot
//     (getFile()), which works in every browser while anything else holds the file;
//   - WRITES go through ONE sync handle per file for the whole tab, shared (ref-counted) by
//     every channel that writes it, opened 'readwrite-unsafe' where the browser honours that
//     (Chromium: then other tabs' walios bridges can hold it too);
//   - a write that still meets a lock (another tab, the app's own createWritable) goes to a
//     PRIVATE COPY of the file, saved over it when the last writer closes (retried until the
//     lock is gone) instead of failing with EBUSY.
// SAB layout (same shape as the wisp bridge): Int32Array ctl at 0 —
// [0]=req seq, [1]=done seq, [2]=op, [3..5]=args, [6]=res, [7]=aux; data at 32.
'use strict';
const OP = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11, SETMODE: 12, FSYNC: 13, SYMLINK: 14, RENAMEDIR: 15, STAT: 16, LOCK: 17, UNLOCK: 18 };
const EDQUOT = -122;   // shellfs download budget spent (the kernel names dbxsearch)
const ENOENT = -2, EIO = -5, EBADF = -9, EACCES = -13, EEXIST = -17, EBUSY = -16, EINVAL = -22, ENOSPC = -28, ENOTEMPTY = -39, EISDIR = -21, EXDEV = -18, ENOTDIR = -20;
const te = new TextEncoder(), td = new TextDecoder();
let root = null, rootReady = null;

// ---- channels ----------------------------------------------------------------
const chans = new Map();                      // ch id -> channel
function mkChan(id, scope) {
  return { id, scope, ctl: null, data: null, poisoned: false, closed: false, phase: '', phaseRel: '',
    noted: new Set(), changed: new Set(), changeTimer: null, removed: new Set(), removedTimer: null, hydrating: 0 };
}
// Every message about a channel carries its id, so the host routes it to that kernel.
function post(C, m) { try { self.postMessage(C ? Object.assign(m, { ch: C.id }) : m); } catch {} }

// Optional scope (per channel): every guest path is resolved under this OPFS folder
// ("projects/x"), so /root is that folder and nothing outside it is reachable. Unlike `subdir`,
// rels stay full workspace paths, so the cloud index, hydration and change reports all keep
// working unchanged. Set by the spawner (sandpie-worker: a conversation's folder).
// The home's dotfolders stay the home's in a scoped kernel: ~/.ssh is the workspace-root
// .ssh whatever the conversation's folder is (ssh reads $HOME/.ssh, and HOME=/root is the
// folder). Everything else under /root stays confined to the folder.
// Lean harness (>>> lean, sandpie-harness-nostore): memory, skills and routines are plain
// files the model writes under /root/sandpie, so there /root/sandpie is the APP's store
// whatever the folder (before, a scoped kernel wrote <folder>/sandpie/memory/..., which the
// app never reads). Off by default: a scoped kernel cannot see the app's store.
let shareStore = false;
let dlBudget = null;                          // shellfs: {files, bytes} per command, or null (no cap)                       // set by the host ('share-store', or on 'sab')
const HOME_SHARED = ['.ssh'];
const homeShared = (r) => HOME_SHARED.some((h) => r === h || r.startsWith(h + '/')) || (shareStore && (r === 'sandpie' || r.startsWith('sandpie/')));
const S = (C, rel) => { const scope = C.scope; const r = String(rel || '').replace(/^\/+/, ''); if (scope && homeShared(r)) return r; return scope ? (r ? scope + '/' + r : scope) : r; };

// ---- bounded, never-hanging service --------------------------------------
// The guest is BLOCKED (Atomics.wait) for as long as one request takes, and a channel's
// requests are served one at a time. So a single await in here that never settles -- an
// IndexedDB open queued behind another tab's transaction, a cloud download whose connection
// stalls, an OPFS call the browser never answers -- used to wedge /root for the life of the
// bridge: `ls` hung, the run could not be suspended (a process blocked inside a syscall never
// reaches a park point), the tool reported "spinning without syscalls", and run_python's next
// boot hung on the same thing for 180s. Seen in prod for ~16 hours in one tab (2026-11-06/07).
//
// Every request now answers within a budget whatever the cause:
//   - each external wait (IndexedDB, download) has its own bound and degrades instead
//     of hanging (no index = local files only; a download that stalls = EIO for that file);
//   - a watchdog around the whole request answers EIO when the budget runs out, tells the
//     host which step stalled ('stuck'), and POISONS that CHANNEL: from then on every request
//     on it is answered EIO at once. Poisoned rather than "carry on", because the stalled
//     request still owns the channel's ctl/data window -- if it ever woke up it would write a
//     stale answer over a later request's. The host detaches a poisoned channel with its
//     kernel and the next run boots a fresh kernel on a fresh channel (sandpie-worker.js,
//     k.sick). Other channels are not affected: they never wait on each other.
let debugStall = '';                          // test hook, see 'debug-stall'
let debugNoMove = false;                      // test hook: behave like a browser without handle.move()
let debugEio = '';                            // test hook, see 'debug-eio'
// Budgets can be shortened by the spawner (tests); prod uses the defaults below.
let BUDGET_MS = 30000;                        // any request that is not downloading cloud bytes
const DOWNLOAD_MS = 300000;                   // pulling one cloud-only file down (large file, slow link)
const IDB_MS = 8000;                          // reading the cloud index / the mode sidecar
function bounded(p, ms, what) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error(what + ' did not finish in ' + Math.round(ms / 1000) + 's'), { name: 'TimeoutError' })), ms); })])
    .finally(() => clearTimeout(t));
}
// One-line notes for the host to show the model (degraded, not failed): once each per channel and run.
function note(C, msg) {
  if (C) { if (C.noted.has(msg)) return; C.noted.add(msg); }
  post(C, { t: 'note', msg });
}

// ---- change reporting ------------------------------------------------------
// The app's sync ledger (localStorage 'dbxfull-sync-state') decides what survives
// cleanup: a local file with NO entry is an orphan and the sync provider deletes it. Every
// write that happens here is invisible to that ledger -- so a shell's `git clone`
// was deleted wholesale the next time the app synced. Report what changes; the page
// owns the marking, because a Worker has no localStorage.
//
// Batched on a microtask-ish timer: a build writes thousands of files and one
// postMessage each would be pure overhead. `hydrating` suppresses reports for the
// bytes we are pulling DOWN from the cloud -- those already match the cloud, and
// marking them dirty would upload them straight back (the sync provider guards its own
// downloads the same way, with _pulling). Per channel: the host attributes a channel's
// writes to the conversation that owns its kernel.

// Paths the guest deleted. Listing a cloud-only file (above) means the guest can
// see files whose bytes are still in the cloud -- and `rm` on one used to remove
// nothing and then re-list it from the index, so the file looked undeletable. The
// remote delete goes through the app's own handshake (Sandpie 'file:deleted' ->
// the sync provider's onFileDeleted), but that is asynchronous and needs a token, while `rm`
// has to look like it worked NOW. So a deleted path is remembered here and
// suppressed from every cloud-index merge; the page persists the set and replays it
// on boot, because a Worker has no storage of its own. Shared by every channel.
let tombs = new Set();
const isTomb = (rel) => tombs.has(String(rel).replace(/^\/+/, '').toLowerCase());
function flushChanged(C) {
  if (C.changeTimer) { clearTimeout(C.changeTimer); C.changeTimer = null; }
  if (C.changed.size) { const rels = [...C.changed]; C.changed = new Set(); post(C, { t: 'opfs-changed', rels }); }
}
function reportChange(C, rel) {
  if (!C || C.hydrating || !rel) return;
  C.changed.add(String(rel).replace(/^\/+/, ''));
  if (C.changeTimer) return;
  C.changeTimer = setTimeout(() => { C.changeTimer = null; flushChanged(C); }, 250);
}
function flushRemoved(C) {
  if (C.removedTimer) { clearTimeout(C.removedTimer); C.removedTimer = null; }
  if (C.removed.size) { const rels = [...C.removed]; C.removed = new Set(); post(C, { t: 'opfs-removed', rels }); }
}
function reportRemoved(C, rel) {
  if (!rel) return;
  const nr = String(rel).replace(/^\/+/, '');
  // Cancel any create for this path still sitting in the debounced batch, so a file
  // that was created and then deleted/renamed-away in the same run (git's temp pack
  // files, lock files, a scratch `rm -rf`) does NOT get flushed as a create AFTER the
  // delete already landed — which would leave a card for a gone file and mark a
  // non-existent path dirty in the sync ledger.
  C.changed.delete(nr);
  // Batched like reportChange: an `rm -rf` of a big tree used to post one message
  // per file while creates rode a 250ms debounce.
  C.removed.add(nr);
  if (C.removedTimer) return;
  C.removedTimer = setTimeout(() => flushRemoved(C), 250);
}

// ---- dehydrated (cloud-only) files ----------------------------------------
// sandpie's cloud sync is on-demand: a file can exist in the user's cloud storage and
// have NO bytes in OPFS at all. Those files were invisible to the guest, so a
// directory full of them listed EMPTY -- `ls /root/sandpie/secrets` looked like
// data loss when the data was merely not downloaded yet. So:
//   listing  -> the cloud INDEX (the sync provider writes it to IndexedDB; the store is
//               named in the provider config) is merged in,
//               giving the real name/size/mtime with no network at all;
//   opening  -> the bytes are pulled down on first touch (get_temporary_link ->
//               the provider's worker module (self.SandpieCloud.download), the same
//               path the file tools use).
//
// Provider-neutral: the spawner posts {t:'cloud', provider} (the sync provider's
// worker config, see core.js SandpieCloudWorkerClient); this bridge importScripts
// provider.workerModule and talks to self.SandpieCloud only.
// Placeholders are only ever shown when we hold a token to hydrate them with, so
// the guest never sees a file it cannot then read.
const IDB_DEFAULT = { db: 'sandpie-dbxfull', store: 'cloudIndex', key: 'index' };   // legacy default; the provider config's indexStore overrides it

// ---- POSIX mode sidecar ----------------------------------------------------
// OPFS stores bytes and a read-only mtime: there is no mode and no owner to set.
// The OS worker used to stamp every OPFS-backed file 0644 on fault-in and keep
// chmod in RAM only, so an ssh key was "UNPROTECTED PRIVATE KEY FILE" again after
// every reboot, +x never survived, and sshd's 0600 host-key check failed forever.
// Modes now live in a tiny IndexedDB store keyed by rel path -- ONLY paths the guest
// gave an explicit mode (chmod, open(O_CREAT, 0600), a rename keeping attrs), so it
// stays small. READDIR returns them alongside size/mtime; unlink/rmdir/rename keep
// the store in step. Per origin like OPFS itself: modes do not travel via cloud.
const META_DB = 'walios-fsmeta', META_STORE = 'modes';
let modes = null, modesPromise = null;         // rel path -> mode bits (0..0o7777)
const normRel = (rel) => String(rel).replace(/^\/+/, '');
// Bounded (IDB_MS): an open can queue forever behind another connection's version change
// or another tab's long transaction. A late success closes the connection it was given.
function metaDb(C) {
  return new Promise((resolve) => {
    let req, settled = false;
    const done = (db) => { if (settled) { try { db && db.close(); } catch {} return; } settled = true; clearTimeout(t); resolve(db); };
    const t = setTimeout(() => { note(C, 'walios: file modes unavailable (IndexedDB did not answer in ' + IDB_MS / 1000 + 's) - chmod bits fall back to defaults this run'); done(null); settled = true; }, IDB_MS);
    try { req = indexedDB.open(META_DB, 1); } catch { return done(null); }
    req.onupgradeneeded = () => { try { req.result.createObjectStore(META_STORE); } catch {} };
    req.onerror = () => done(null);
    req.onblocked = () => {};                 // keep waiting, but the timer above still bounds it
    req.onsuccess = () => done(req.result);
  });
}
async function loadModes(C) {
  if (modes) return modes;
  if (!modesPromise) modesPromise = (async () => {
    const m = new Map();
    if (C) C.phase = 'reading file modes (IndexedDB)';
    const db = await metaDb(C);
    // Unavailable: serve defaults, and only look again in a minute -- retrying on every
    // request would make each listing pay the whole IDB_MS while the store is stuck.
    if (!db) { modes = m; setTimeout(() => { if (modes === m) { modes = null; modesPromise = null; } }, 60000); return m; }
    await bounded(new Promise((res) => {
      let tx; try { tx = db.transaction(META_STORE, 'readonly'); } catch { return res(); }
      const st = tx.objectStore(META_STORE), rk = st.getAllKeys(), rv = st.getAll();
      tx.oncomplete = () => { const ks = rk.result || [], vs = rv.result || []; for (let i = 0; i < ks.length; i++) m.set(ks[i], vs[i] | 0); res(); };
      tx.onerror = tx.onabort = () => res();
    }), IDB_MS, 'reading file modes').catch(() => { note(C, 'walios: file modes unavailable (IndexedDB read stalled) - chmod bits fall back to defaults this run'); });
    try { db.close(); } catch {}
    modes = m;
    return modes;
  })();
  return modesPromise;
}
// Fire-and-forget persistence: the in-memory map is already updated, so the guest
// sees the new mode immediately; a lost write only costs the mode after a reboot.
function metaWrite(fn) {
  metaDb(null).then((db) => {
    if (!db) return;
    try { const tx = db.transaction(META_STORE, 'readwrite'); fn(tx.objectStore(META_STORE)); tx.oncomplete = tx.onerror = tx.onabort = () => db.close(); }
    catch { db.close(); }
  });
}
// A symlink on the mount is a small OPFS file holding its target, marked by a mode record
// that KEEPS the type bits (S_IFLNK); every other record is permission bits only.
const S_IFMT = 0o170000, S_IFLNK = 0o120000;
const isLinkMode = (m) => m !== undefined && (m & S_IFMT) === S_IFLNK;
const modeRecord = (mode) => isLinkMode(mode) ? (mode & 0o177777) : (mode & 0o7777);
// Every tab has its own bridge and its own copy of the mode map (loaded once). A change made
// in one tab is broadcast so the others' maps stay current -- without it a symlink (or a
// chmod 600) made in tab A read as a plain file (0644) in tab B until B's worker restarted.
let modesBus = null;
try {
  modesBus = new BroadcastChannel('walios-modes');
  modesBus.onmessage = (ev) => {
    const m = ev.data; if (!m || !modes) return;
    if (m.t === 'set') { if (m.v < 0) modes.delete(m.rel); else modes.set(m.rel, m.v); }
    else if (m.t === 'drop') { for (const k of [...modes.keys()]) if (k === m.rel || k.startsWith(m.rel + '/')) modes.delete(k); }
    else if (m.t === 'move') { for (const [o, n, v] of m.mv) { modes.delete(o); modes.set(n, v); } }
  };
} catch (_) { modesBus = null; }
const busPost = (m) => { try { if (modesBus) modesBus.postMessage(m); } catch (_) {} };
function setMode(rel, mode) {
  rel = normRel(rel); if (!modes || !rel) return;
  if (mode < 0) { modes.delete(rel); metaWrite((s) => s.delete(rel)); busPost({ t: 'set', rel, v: -1 }); }
  else { const v = modeRecord(mode); modes.set(rel, v); metaWrite((s) => s.put(v, rel)); busPost({ t: 'set', rel, v }); }
}
function dropModes(rel) {                      // a path (and anything under it) is gone
  rel = normRel(rel); if (!modes || !rel) return;
  const gone = []; for (const k of modes.keys()) if (k === rel || k.startsWith(rel + '/')) gone.push(k);
  if (!gone.length) return;
  for (const k of gone) modes.delete(k);
  metaWrite((s) => { for (const k of gone) s.delete(k); });
  busPost({ t: 'drop', rel });
}
function moveModes(oldRel, newRel) {
  oldRel = normRel(oldRel); newRel = normRel(newRel); if (!modes || !oldRel || !newRel) return;
  const mv = []; for (const [k, v] of modes) if (k === oldRel || k.startsWith(oldRel + '/')) mv.push([k, newRel + k.slice(oldRel.length), v]);
  if (!mv.length) return;
  for (const [o, n, v] of mv) { modes.delete(o); modes.set(n, v); }
  metaWrite((s) => { for (const [o, n, v] of mv) { s.delete(o); s.put(v, n); } });
  busPost({ t: 'move', mv });
}
let cloudCfg = null;   // the provider config (null = no cloud)
const cloudModulesLoaded = new Set();
function cloud() { const c = self.SandpieCloud; return (c && cloudCfg && c.connected()) ? c : null; }
function cloudName() { return (cloudCfg && cloudCfg.displayName) || 'cloud'; }
function indexStore() { return Object.assign({}, IDB_DEFAULT, (cloudCfg && cloudCfg.indexStore) || {}); }
function setCloud(provider) {
  if (provider && provider.workerModule && !cloudModulesLoaded.has(provider.workerModule)) {
    try { importScripts(provider.workerModule); cloudModulesLoaded.add(provider.workerModule); }
    catch (e) { try { console.error('[opfs-worker] cloud provider module failed to load:', provider.workerModule, (e && e.message) || e); } catch {} }
  }
  cloudCfg = provider || null;
  if (self.SandpieCloud) { try { self.SandpieCloud.configure(cloudCfg); } catch {} }
  // Re-read the index on next use -- unless the host pushes it (then it is already current:
  // every change the sync makes is pushed, see 'cloud-index').
  if (pushedIdx === undefined) dropIndex();
}
let idxByDir = null;         // lower-case dir path -> Map(lower name -> {n, e})
let idxByPath = null;        // lower-case rel path -> entry
let idxPromise = null;
let idxGen = 0;              // bumped whenever the index is dropped: a load that started earlier must not install its (older) result
// The index as the HOST pushed it ({t:'cloud-index'}): the page's sync provider holds it in
// memory and pushes every change to the app worker, which forwards it here -- the same feed
// the file tools and the Pyodide worker list from. undefined = never pushed (the standalone
// /walios/ terminal, an older host, or a disconnected provider): read it from IndexedDB.
//
// It used to come ONLY from IndexedDB, re-read before every run. That read is the one wait
// proven able to stall the bridge indefinitely (a readwrite transaction another context keeps
// open on the store queues every read behind it -- reproduced in e2e-bridge-stall.mjs), and it
// cost a full JSON.parse of the whole index per run.
let pushedIdx;
function dropIndex() { idxByDir = idxByPath = idxPromise = null; idxGen++; }

// Resolves the parsed index, null when there is none, or the string 'timeout' when
// IndexedDB did not answer within IDB_MS (open queued behind another connection, a read
// queued behind another tab's transaction). Never hangs.
function idbReadIndex(key) {
  return new Promise((resolve) => {
    const st = indexStore();
    let settled = false, dbRef = null;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(t); try { dbRef && dbRef.close(); } catch {} resolve(v); };
    const t = setTimeout(() => done('timeout'), IDB_MS);
    let req; try { req = indexedDB.open(st.db); } catch { return done(null); } // no version arg: a version bump by the owner (the sync provider) must not VersionError us into silently losing the index
    req.onupgradeneeded = () => { try { req.result.createObjectStore(st.store); } catch {} };
    req.onerror = () => done(null);
    req.onblocked = () => {};                 // bounded by the timer
    req.onsuccess = () => {
      const db = req.result; dbRef = db;
      if (settled) { try { db.close(); } catch {} return; }
      let g; try { g = db.transaction(st.store, 'readonly').objectStore(st.store).get(key); }
      catch { return done(null); }
      g.onerror = () => done(null);
      g.onsuccess = () => { let v = null; try { v = g.result ? JSON.parse(g.result) : null; } catch {} done(v); };
    };
  });
}
// Build parent->children once, not per listing: the index runs to tens of
// thousands of entries and READDIR is on the guest's blocking path.
// Is there a cloud index at all? Listing cloud-only entries does not need a
// token -- only hydrating them does.
function haveIndex() { return !!(idxByDir && idxByDir.size); }
async function loadIndex(C) {
  if (idxByDir) return idxByDir;
  if (!idxPromise) idxPromise = (async () => {
    const gen = idxGen;
    let raw;
    if (pushedIdx) raw = pushedIdx;
    else {
      if (C) C.phase = 'reading the cloud file list (IndexedDB)';
      raw = await idbReadIndex(indexStore().key);
      if (raw === 'timeout') {
        // Degrade, do not hang: list what is local, and look again in a minute (not on
        // every request -- each try costs IDB_MS while the store is stuck).
        note(C, 'walios: the cloud file list did not load (IndexedDB did not answer in ' + IDB_MS / 1000 + 's) - cloud-only files are not listed right now; local files work normally');
        setTimeout(() => { if (idxGen === gen && !pushedIdx) dropIndex(); }, 60000);
        raw = null;
      }
      // A push landed while IndexedDB was being read: it is newer, use it.
      if (gen !== idxGen) return loadIndex(C);
    }
    raw = raw || {};
    const byDir = new Map(), byPath = new Map();
    for (const k of Object.keys(raw)) {
      const rel = k.replace(/^\/+/, ''); if (!rel) continue;
      const e = raw[k];
      byPath.set(rel.toLowerCase(), e);
      const cut = rel.lastIndexOf('/');
      const dir = cut < 0 ? '' : rel.slice(0, cut).toLowerCase();
      const name = cut < 0 ? rel : rel.slice(cut + 1);
      // Every ancestor directory is implied by its children -- the cloud indexes
      // folders too, but a folder entry is not guaranteed for every level.
      let d = dir;
      for (;;) {
        if (!byDir.has(d)) byDir.set(d, new Map());
        const c2 = d.lastIndexOf('/'); const parent = c2 < 0 ? '' : d.slice(0, c2);
        if (d === '') break;
        const dn = c2 < 0 ? d : d.slice(c2 + 1);
        if (!byDir.has(parent)) byDir.set(parent, new Map());
        if (!byDir.get(parent).has(dn)) byDir.get(parent).set(dn, { n: dn, e: { kind: 'folder' } });
        d = parent;
      }
      byDir.get(dir).set(name.toLowerCase(), { n: name, e });
    }
    if (gen === idxGen) { idxByDir = byDir; idxByPath = byPath; }
    return byDir;
  })();
  return idxPromise;
}
const idxEntry = (rel) => (idxByPath ? idxByPath.get(String(rel).toLowerCase()) : null);

async function isLocal(rel) {
  try { const { d, name } = await parentOf(rel); await d.getFileHandle(name); return true; }
  catch { return false; }
}
// Pull a cloud-only file's bytes into OPFS. Returns true if the file is local
// afterwards; THROWS when it is indexed but could not be fetched, so the caller
// reports a real error instead of an empty read (the whole point of this work).
const inGitDir = (rel) => /(^|\/)\.git\//.test(String(rel));
// Dropbox compares names case-insensitively; OPFS (and Linux) do not. Two names that differ
// only in case (README and readme, a git tree with both) are two files here and ONE in the
// cloud, where one silently replaces the other. Said once per pair when such a name is
// created while a cloud is connected: against the cloud index, and against names created
// in this tab this session.
const createdCase = new Map();              // lower-case rel -> rel as created
function caseClash(C, rel) {
  rel = String(rel).replace(/^\/+/, '');
  if (!rel || !cloud()) return;
  const lo = rel.toLowerCase();
  let other = null;
  const prev = createdCase.get(lo);
  if (prev && prev !== rel) other = prev;
  if (!other && idxByDir) {
    const cut = rel.lastIndexOf('/');
    const kid = idxByDir.get(cut < 0 ? '' : rel.slice(0, cut).toLowerCase());
    const k = kid && kid.get((cut < 0 ? rel : rel.slice(cut + 1)).toLowerCase());
    if (k && k.n !== (cut < 0 ? rel : rel.slice(cut + 1))) other = (cut < 0 ? '' : rel.slice(0, cut + 1)) + k.n;
  }
  createdCase.set(lo, rel);
  if (other) note(C, 'walios: /' + rel + ' and /' + other + ' differ only in letter case; ' + cloudName()
    + ' treats them as ONE file, so in the cloud one will replace the other. Rename one of them.');
}
async function hydrate(C, rel) {
  if (await isLocal(rel)) return true;
  if (isTomb(rel)) return false;         // the guest deleted it; do not pull it back
  C.hydrating++;
  try { return await hydrateInner(C, rel); } finally { C.hydrating--; }
}
async function hydrateInner(C, rel) {
  await loadIndex(C);
  const e = idxEntry(rel);
  if (!e || e.kind === 'folder') return false;          // not a cloud file: normal ENOENT
  const c = cloud();
  if (!c) throw new Error('no ' + cloudName() + ' connection in this tab');
  // shellfs: one command may download only so many cloud-only files (grep -r over a Dropbox
  // tree would otherwise fetch all of it). Counted per channel, reset on the run's flush.
  // A git repository's internals are exempt: git needs every object it touches, and a repo
  // whose .git went cloud-only (the 24h purge, or a fresh device) failed mid-command with
  // EDQUOT after a few objects -- "git status" broken by a cap meant for grep -r.
  if (dlBudget && !inGitDir(rel) && (C.dlN >= dlBudget.files || C.dlBytes >= dlBudget.bytes)) { const q = new Error('download budget spent'); q.quota = true; throw q; }
  C.phase = 'downloading the cloud-only file'; C.phaseRel = rel;
  const bytes = await bounded(Promise.resolve().then(() => c.download(e.path || (c.workingRoot() + '/' + rel))), DOWNLOAD_MS, 'downloading ' + rel);
  const { d, name } = await parentOf(rel, 1);
  const sh = await openSync(await d.getFileHandle(name, { create: true }), 12);
  try { sh.truncate(0); shWrite(sh, bytes, 0); sh.flush(); } finally { sh.close(); }
  bump(rel);
  C.dlN = (C.dlN || 0) + 1; C.dlBytes = (C.dlBytes || 0) + bytes.length;
  // Tell the spawner, which records a clean sync-state entry so a later edit
  // writes back instead of the copy being re-downloaded or treated as new.
  post(C, { t: 'hydrated', rel, size: bytes.length });
  return true;
}

async function walkDir(rel, create) {        // -> dir handle at rel
  let d = root;
  for (const s of rel.split('/').filter(Boolean)) d = await d.getDirectoryHandle(s, { create: !!create });
  return d;
}
// READDIR's walk, with the ancestors' handles cached. Measured 2026-11-03 on a dehydrated
// workspace (1,813 directories, 96% of them cloud-only): one `du -s /root` made 3,626
// READDIRs, every one walking its path from the root a segment at a time -- 10,794
// getDirectoryHandle calls, 4.1-8.8s of the bridge's 5.9-16.2s.
//
// Why this cannot list something that is not there: a held directory handle resolves its
// PATH each time it is used (pinned by tests/walios/opfs-handle-semantics.mjs, Chromium
// 149; Electron 44 has no directory move()): deleted -> NotFoundError, deleted and
// re-created -> the new contents, an ancestor deleted -> NotFoundError. And the directory
// itself is never taken from the cache: its last segment is looked up LIVE from the
// cached parent, so a listing sees exactly what a walk from the root would. Only failures
// can differ in their error NAME (an ancestor replaced by a file reads NotFoundError here,
// TypeMismatchError on a full walk), and READDIR treats every failure alike while there
// is a cloud index; without one, readdirDir redoes the full walk so the errno is the same.
// Every other op (open, unlink, rmdir, mkdir, rename, hydrate) keeps the uncached walk.
const dirCache = new Map();                  // rel -> handle of a directory that EXISTED when cached
const DIR_CACHE_MAX = 20000;
async function walkDirCached(rel) {
  const segs = rel.split('/').filter(Boolean);
  let i = segs.length - 1, d = null;         // deepest cached PROPER ancestor
  for (; i > 0; i--) { d = dirCache.get(segs.slice(0, i).join('/')); if (d) break; }
  if (!d) { d = root; i = 0; }
  for (; i < segs.length; i++) {
    d = await d.getDirectoryHandle(segs[i]);
    if (dirCache.size >= DIR_CACHE_MAX) dirCache.clear();
    dirCache.set(segs.slice(0, i + 1).join('/'), d);
  }
  return d;
}
async function readdirDir(rel) {             // -> dir handle, or throws like walkDir(rel)
  try { return await walkDirCached(rel); }
  catch (e) { if (haveIndex()) throw e; return await walkDir(rel); }   // no index: the full walk's own error
}
async function parentOf(rel, create) {       // -> { d: parent dir handle, name }
  const segs = rel.split('/').filter(Boolean);
  let d = root;
  for (let i = 0; i < segs.length - 1; i++) d = await d.getDirectoryHandle(segs[i], { create: !!create });
  return { d, name: segs[segs.length - 1] };
}
// A poisoned channel ignores late answers from the request that stalled (see `poisoned`).
function finish(C, res, aux) { if (C.poisoned || C.closed) return; finishNow(C, res, aux); }
// 64-bit sizes/offsets over the Int32 ctl window: an offset argument's HIGH 32 bits arrive in
// ctl[7] (the kernel writes it with every request), and a size answer's high bits go back in
// ctl[2] (the op slot, free once the request is done). Files past 2 GiB (git packs, disk
// images, datasets) used to wrap: a read at 3 GiB read at -1 GiB.
const TWO32 = 4294967296;
// FileSystemSyncAccessHandle.read()/write() in Chromium (149) do not throw when the disk or
// the origin's quota is full: they RETURN base::File::Error as an unsigned 32-bit number
// (-8 = FILE_ERROR_NO_SPACE comes back as 4294967288). That went to the guest as errno 8
// (ENOEXEC, "Exec format error"), and loops doing `done += n` overshot. A count larger than
// what was asked for (or <= 0 for a write) is a failure; -8 is ENOSPC, the rest EIO.
const shBad = (n, asked) => !(n >= 0) || n > asked;
const ioErrOf = (n) => (n | 0) === -8 ? ENOSPC : EIO;
function shWrite(sh, bytes, at) {           // all of bytes, or throws (QuotaExceededError on NO_SPACE)
  let done = 0;
  while (done < bytes.length) {
    const k = sh.write(bytes.subarray(done), { at: at + done });
    if (!(k > 0) || k > bytes.length - done) throw Object.assign(new Error('write failed (' + (k | 0) + ')'), { name: (k | 0) === -8 ? 'QuotaExceededError' : 'WriteError' });
    done += k;
  }
  return done;
}
function finishNow(C, res, aux) {
  const ctl = C.ctl;
  ctl[6] = res | 0;
  ctl[2] = (typeof aux === 'number' && aux >= 2147483648) ? Math.floor(aux / TWO32) : 0;
  ctl[7] = aux | 0;
  Atomics.add(ctl, 1, 1); Atomics.notify(ctl, 1);
}

// ---- open files: lock-free reads, one shared writer per file, private copy on a lock ----
// handles: id -> { id, C, rel, fh, mode, file, fileAt, gen, gone }
//   mode 'r': no lock. Reads come from the shared writer or copy if this tab has one for the
//             file, else from a File snapshot (refreshed when this tab changed the file, or
//             when it is older than SNAP_MS: another tab / the app may have rewritten it).
//   mode 'w': holds a reference on writers.get(rel) -- the ONE sync handle for that file.
//   mode 'c': holds a reference on copies.get(rel) -- the private copy (see startCopy).
// An id opened for reading turns into a writer on its first WRITE/TRUNC, so the kernel needs
// no notion of open flags: O_RDONLY files never take a lock.
const handles = new Map(); let nextId = 1;
const writers = new Map();                   // rel -> { sh, refs: Set<id> }
const opening = new Map();                   // rel -> promise: a writer (or copy) being set up
const copies = new Map();                    // rel -> { rel, buf, size, dirty, refs: Set<id>, committing, C }
const gens = new Map();                      // rel -> generation: bumped on every change made through this bridge
const genOf = (rel) => gens.get(rel) | 0;
// Other tabs have their own bridge, and a change made through one of them never bumped THIS
// bridge's generations: a read snapshot of a file another tab had just replaced (git's
// rename of index.lock over index) stayed in use for up to SNAP_MS, so this tab's git read
// the OLD index -- or old and new bytes mixed -- and wrote that back (two tabs committing
// into one repo: "unordered stage entries in index"). Every bump is now told to the other
// bridges of this origin (coalesced per task) and they bump too.
let gensBus = null;
const gensOut = new Set();
try {
  gensBus = new BroadcastChannel('walios-gens');
  gensBus.onmessage = (ev) => { const m = ev.data; if (m && Array.isArray(m.rels)) for (const r of m.rels) gens.set(r, genOf(r) + 1); };
} catch (_) { gensBus = null; }
function gensTell(rel) {
  if (!gensBus) return;
  if (!gensOut.size) setTimeout(() => { const rels = [...gensOut]; gensOut.clear(); try { gensBus.postMessage({ rels }); } catch (_) {} }, 0);
  gensOut.add(rel);
}
const bump = (rel) => { gens.set(rel, genOf(rel) + 1); gensTell(rel); };
const SNAP_MS = 1000;
const COPY_MAX = 256 * 1024 * 1024;          // a bigger file stays EBUSY rather than being copied into RAM
const isLockErr = (e) => !!e && (e.name === 'NoModificationAllowedError' || e.name === 'InvalidStateError');
// Chromium: 'readwrite-unsafe' handles do not lock each other out (across tabs too), only
// exclusive ones and createWritable streams. Elsewhere the option is ignored and the handle is
// the usual exclusive one -- same code, today's behaviour.
let unsafeMode = null;                       // learned from the first handle: does the browser honour it?
async function openSyncOnce(fh) {
  const sh = await fh.createSyncAccessHandle({ mode: 'readwrite-unsafe' });
  if (unsafeMode === null) unsafeMode = sh.mode === 'readwrite-unsafe';
  return sh;
}
async function openSync(fh, tries) {         // with a short retry: a lock held by an app write lasts milliseconds
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    try { return await openSyncOnce(fh); }
    catch (e) { if (!isLockErr(e)) throw e; lastErr = e; if (i < tries - 1) await new Promise((r) => setTimeout(r, i < 5 ? 60 : 150)); }
  }
  throw lastErr;
}
async function fileHandleOf(rel) { const { d, name } = await parentOf(rel); return d.getFileHandle(name); }
async function getFH(e) { if (!e.fh) e.fh = await fileHandleOf(e.rel); return e.fh; }
function closeWriter(rel) {
  const w = writers.get(rel); if (!w) return;
  writers.delete(rel);
  try { w.sh.flush(); w.sh.close(); } catch {}
  bump(rel);
}
// A write met a lock this tab cannot release (another tab's exclusive handle, the app's own
// createWritable). Write a private copy instead of failing with EBUSY; it is saved over the
// file when its last writer closes (commitCopy). Meanwhile every channel of this tab reads and
// writes the copy, so they agree with each other.
async function startCopy(C, rel, fh) {
  const f = await fh.getFile();
  if (f.size > COPY_MAX) throw Object.assign(new Error('locked, and too big to copy'), { name: 'NoModificationAllowedError' });
  const buf = new Uint8Array(Math.max(f.size, 4096));
  buf.set(new Uint8Array(await f.arrayBuffer()), 0);
  copies.set(rel, { rel, buf, size: f.size, dirty: false, refs: new Set(), committing: false, C });
  note(C, 'walios: /' + rel + ' is open in another tab or by the app; writes go to a private copy that is saved over it once the file is closed');
}
async function toWriter(C, e) {
  for (;;) {
    if (e.mode !== 'r') return;
    const cp = copies.get(e.rel); if (cp) { cp.refs.add(e.id); e.mode = 'c'; return; }
    const w = writers.get(e.rel); if (w) { w.refs.add(e.id); e.mode = 'w'; return; }
    const p = opening.get(e.rel);
    if (p) { await p.catch(() => {}); if (!handles.has(e.id)) return; continue; }
    const rel = e.rel;
    C.phase = 'opening the file for writing (OPFS)'; C.phaseRel = rel;
    // Registered in `opening` in the same tick as the checks above (no await in between), so
    // two channels can never both open a writer for one file: the second waits and joins.
    const job = (async () => {
      const fh = await getFH(e);
      try { const sh = await openSync(fh, 12); writers.set(rel, { sh, refs: new Set() }); }
      catch (err) { if (!isLockErr(err)) throw err; await startCopy(C, rel, fh); }
    })();
    opening.set(rel, job);
    try { await job; } finally { if (opening.get(rel) === job) opening.delete(rel); }
    if (!handles.has(e.id)) {                // the channel went away while we were opening
      const w2 = writers.get(rel); if (w2 && !w2.refs.size) closeWriter(rel);
      return;
    }
  }
}
function ensureCap(cp, n) {
  if (n <= cp.buf.length) return;
  const nb = new Uint8Array(Math.max(n, cp.buf.length * 2)); nb.set(cp.buf.subarray(0, cp.size), 0); cp.buf = nb;
}
function cpWrite(cp, bytes, at) {
  ensureCap(cp, at + bytes.length);
  if (at > cp.size) cp.buf.fill(0, cp.size, at);
  cp.buf.set(bytes, at); cp.size = Math.max(cp.size, at + bytes.length); cp.dirty = true;
  return bytes.length;
}
function cpTrunc(cp, n) {
  ensureCap(cp, n);
  if (n > cp.size) cp.buf.fill(0, cp.size, n);
  cp.size = n; cp.dirty = true;
}
// Save a private copy over its file once nothing has it open. Retried (backing off to 10s)
// for as long as the file stays locked: giving up would lose the writes. Stops on its own if
// the file is reopened (the next close commits) or the copy is dropped (unlinked, renamed over).
async function commitCopy(cp) {
  if (cp.committing) return;
  cp.committing = true;
  const t0 = Date.now(); let warned = false;
  try {
    for (let i = 0; ; i++) {
      if (cp.refs.size || copies.get(cp.rel) !== cp) return;
      try {
        const sh = await openSyncOnce(await fileHandleOf(cp.rel));
        try {
          if (cp.refs.size || copies.get(cp.rel) !== cp) return;
          sh.truncate(cp.size);
          shWrite(sh, cp.buf.subarray(0, cp.size), 0);
          sh.flush();
        } finally { sh.close(); }
        copies.delete(cp.rel); bump(cp.rel);
        reportChange(cp.C, cp.rel);          // the sync ledger: these bytes are new
        return;
      } catch (e) {
        if (!isLockErr(e)) {
          try { console.error('[opfs-worker] could not save the private copy of', cp.rel, e); } catch {}
          note(cp.C, 'walios: could not save /' + cp.rel + ' (' + ((e && e.name) || e) + ') - the writes made to it while it was locked are lost');
          if (copies.get(cp.rel) === cp) copies.delete(cp.rel);
          return;
        }
        if (!warned && Date.now() - t0 > 30000) { warned = true; note(cp.C, 'walios: /' + cp.rel + ' is still locked by another tab or the app; its new contents are kept here and saved as soon as it is free'); }
        await new Promise((r) => setTimeout(r, Math.min(10000, 500 * (i + 1))));
      }
    }
  } finally { cp.committing = false; }
}
// Drop an id: its writer/copy reference first (the last one closes the writer / saves the copy).
function closeId(e) {
  handles.delete(e.id);
  if (e.mode === 'w') { const w = writers.get(e.rel); if (w) { w.refs.delete(e.id); if (!w.refs.size) closeWriter(e.rel); } }
  else if (e.mode === 'c') { const cp = copies.get(e.rel); if (cp) { cp.refs.delete(e.id); if (!cp.refs.size) { if (cp.dirty) commitCopy(cp); else copies.delete(e.rel); } } }
  e.mode = 'r';
}
function closeChannelIds(C) { for (const e of [...handles.values()]) if (e.C === C) closeId(e); }
// Before a path is removed or moved: no handle of this tab may hold it (removeEntry and move()
// fail while any sync handle is open). Writers on it close; their ids fall back to mode 'r'
// and take a writer again on their next write.
function letGo(rel) {
  if (writers.has(rel)) {
    for (const e of handles.values()) if (e.rel === rel && e.mode === 'w') e.mode = 'r';
    closeWriter(rel);
  }
}
// The path is gone (unlinked, or renamed over): its ids answer EBADF (the kernel reports EIO),
// and a private copy of it is dropped, as writes to an unlinked file vanish on Linux.
function markGone(rel) {
  for (const e of handles.values()) if (e.rel === rel) { if (e.mode !== 'r') closeIdRefOnly(e); e.gone = true; }
  copies.delete(rel); bump(rel);
}
function closeIdRefOnly(e) {                 // drop the writer/copy reference but keep the id
  if (e.mode === 'w') { const w = writers.get(e.rel); if (w) { w.refs.delete(e.id); if (!w.refs.size) closeWriter(e.rel); } }
  else if (e.mode === 'c') { const cp = copies.get(e.rel); if (cp) cp.refs.delete(e.id); }
  e.mode = 'r';
}
// Each File.slice().arrayBuffer() is a round trip to the browser's file backend: a 32MB read in
// 1MB requests was ~1.5x slower than a sync handle. Sequential reads therefore fetch ahead
// (256KB, doubling to 4MB while the reads stay sequential) and later requests are served from
// that buffer; a random read (SQLite pages, git objects) fetches just what it asked for.
const RA_MIN = 256 * 1024, RA_MAX = 4 * 1024 * 1024;
async function snapRead(C, e, at, len) {
  for (let i = 0; ; i++) {
    try {
      if (!e.file || e.gen !== genOf(e.rel) || Date.now() - e.fileAt > SNAP_MS) {
        C.phase = 'reading the file (OPFS)';
        e.file = await (await getFH(e)).getFile(); e.fileAt = Date.now(); e.gen = genOf(e.rel);
        e.ra = null;                         // read-ahead of the old snapshot
      }
      const size = e.file.size;
      if (at >= size) return new Uint8Array(0);
      const end = Math.min(at + len, size);
      const ra = e.ra;
      if (ra && at >= ra.at && end <= ra.at + ra.bytes.length) { e.next = end; return ra.bytes.subarray(at - ra.at, end - ra.at); }
      const seq = e.next === at;
      e.raw = seq ? Math.min(RA_MAX, Math.max(RA_MIN, (e.raw || RA_MIN) * 2)) : 0;
      const stop = Math.min(size, Math.max(end, at + e.raw));
      const bytes = new Uint8Array(await e.file.slice(at, stop).arrayBuffer());
      e.ra = stop > end ? { at, bytes } : null;
      e.next = end;
      return bytes.subarray(0, end - at);
    } catch (err) {
      e.file = null;
      if (i) throw err;
      e.fh = null;                           // re-resolve: the path may have been replaced
    }
  }
}

const OP_NAME = Object.fromEntries(Object.entries(OP).map(([k, v]) => [v, k]));
const PATH_OPS = new Set([OP.READDIR, OP.OPEN, OP.UNLINK, OP.RMDIR, OP.MKDIR, OP.RENAME, OP.SETMODE]);
// The watchdog every request goes through (both serve loops). handle() always answers by
// itself unless one of its awaits never settles; then this answers EIO at the budget,
// reports what it was waiting on, and poisons the channel (see the top of the file).
async function serve(C, op) {
  if (C.poisoned) return finishNow(C, EIO, 0);
  const ctl = C.ctl, a0 = ctl[3];
  let rel = '';
  try { rel = PATH_OPS.has(op) ? td.decode(C.data.slice(0, Math.min(a0 | 0, 4096))).split('\0')[0] : ((handles.get(a0) || {}).rel || ''); } catch {}
  C.phase = OP_NAME[op] || ('op ' + op); C.phaseRel = rel;
  // Test hook (tests/walios/e2e-android-mode.mjs): a WRITE to a matching path fails with EIO.
  if (debugEio && op === OP.WRITE && rel.includes(debugEio)) return finishNow(C, EIO, 0);
  const work = (debugStall && rel.includes(debugStall)) ? new Promise(() => { C.phase = 'debug stall'; }) : null;
  // OPEN and RENAME may download a cloud-only file first (bounded by DOWNLOAD_MS inside).
  const budget = (op === OP.OPEN || op === OP.RENAME) ? DOWNLOAD_MS + BUDGET_MS : BUDGET_MS;
  const t0 = Date.now();
  let timer;
  const r = await Promise.race([
    (work || handle(C, op)).then(() => 'ok', () => 'ok'),
    new Promise((res) => { timer = setTimeout(() => res('timeout'), budget); }),
  ]);
  clearTimeout(timer);
  const ms = Date.now() - t0;
  if (r === 'timeout') {
    const stuck = { t: 'stuck', op: OP_NAME[op] || op, phase: C.phase, rel: C.phaseRel, ms };
    C.poisoned = true;
    finishNow(C, EIO, 0);
    // This channel's writers/copies would keep the files busy for the rest of the tab.
    closeChannelIds(C);
    try { console.error('[opfs-worker] request stalled; channel poisoned:', stuck); } catch {}
    post(C, stuck);
  } else if (ms > 5000) {
    post(C, { t: 'slow', op: OP_NAME[op] || op, phase: C.phase, rel: C.phaseRel, ms });
  }
}

// Message bridge (kernel without SharedArrayBuffer): {t:'call', id, op, a0, a1, a2, bytes}
// -> {t:'reply', id, res, aux, data}. One request at a time, in order, exactly like the
// SAB loop; `data` is sized per request (a read wants its whole range at once: there is
// no SAB window here). Only the ops that answer with bytes send any back.
function servePort(C, port) {
  const CTL = new Int32Array(8);
  let chain = Promise.resolve();
  C.port = port;
  port.onmessage = (ev) => {
    const m = ev.data; if (!m || m.t !== 'call') return;
    chain = chain.then(async () => {
      if (C.closed) return;
      const inb = m.bytes ? new Uint8Array(m.bytes) : null;
      C.ctl = CTL; CTL.fill(0);
      C.data = new Uint8Array(Math.max(1 << 20, inb ? inb.length : 0, m.op === OP.READ ? (m.a2 | 0) : 0));
      if (inb) C.data.set(inb, 0);
      CTL[2] = m.op; CTL[3] = m.a0 | 0; CTL[4] = m.a1 | 0; CTL[5] = m.a2 | 0; CTL[7] = m.a1h | 0;
      try { await serve(C, m.op); } catch (e) { try { finishNow(C, EIO, 0); } catch (_) {} }
      const n = (m.op === OP.READ || m.op === OP.READDIR || m.op === OP.STAT) && CTL[6] > 0 ? Math.min(CTL[6], C.data.length) : 0;
      const out = C.data.slice(0, n);
      try { port.postMessage({ t: 'reply', id: m.id, res: CTL[6], aux: CTL[7], auxh: CTL[2], data: out.buffer }, [out.buffer]); } catch {}
    });
  };
}
async function serveSab(C) {
  const ctl = C.ctl;
  let last = 0;
  // waitAsync, not the blocking wait: a blocking Atomics.wait parks this thread
  // between requests, and queued message events (notably a refreshed the cloud
  // token) would then never be dispatched -- the loop's own microtask
  // continuation always beats them to the thread. And with several channels on one
  // bridge, a blocking wait on one would starve all the others (the host only shares a
  // bridge where waitAsync exists; a host that does not know channels gets channel 0 alone).
  const canAsync = typeof Atomics.waitAsync === 'function';
  while (!C.closed) {
    if (canAsync) { const r = Atomics.waitAsync(ctl, 0, last); if (r.async) await r.value; }
    else Atomics.wait(ctl, 0, last);
    if (C.closed) break;
    const seq = Atomics.load(ctl, 0); if (seq === last) continue; last = seq;
    try { await serve(C, ctl[2]); } catch (e) { try { finishNow(C, EIO, 0); } catch (_) {} }
  }
}

// Stamped into ctl[5] (the third argument slot, already read into a local) the moment a
// request is picked up, so the kernel can tell "the bridge is slow" (a cloud-only file
// being downloaded on open, which can legitimately take a while) from "the bridge is
// dead" (nothing ever picked the request up). Must match the kernel's SLOW_MARK.
const BRIDGE_BUSY = 0x7ea7;
async function handle(C, op) {
  const ctl = C.ctl, data = C.data;
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  const off = (a1 >>> 0) + (ctl[7] | 0) * TWO32;   // a1 as a 64-bit offset/size (READ, WRITE, TRUNC)
  Atomics.store(ctl, 5, BRIDGE_BUSY);
  if (!root) return finish(C, EIO, 0);         // no OPFS in this browser/context
  try {
    switch (op) {
      case OP.READDIR: {                     // in: path — out: JSON [{n, d?} | {n, s, m}]
        const rel = S(C, td.decode(data.slice(0, a0)));
        const out = [], seen = new Set();
        await loadIndex(C);                  // needed by haveIndex() below, and cheap after the first call
        // A directory can be cloud-ONLY (no local copy at all), in which case the
        // walk throws; that is not an error while we still have an index to list.
        let d = null;
        C.phase = 'listing the directory (OPFS)';
        try { d = await readdirDir(rel); } catch (e) { if (!haveIndex()) throw e; }
        if (d) {
          // Stat every entry IN PARALLEL. This awaited getFile() one entry at a time, so
          // listing a directory cost one OPFS round trip per file: a git objects/ tree of a
          // few thousand entries took whole seconds to fault in, and a fresh kernel (after a
          // timeout kill) paid that again for every directory git touched -- `git status`
          // timing out at 60s on a repo that lists in under a second here.
          const ents = []; for await (const ent of d.entries()) ents.push(ent);
          const dirRel = rel ? rel + '/' : '';
          await Promise.all(ents.map(async ([name, h]) => {
            seen.add(name.toLowerCase());
            if (h.kind === 'directory') { out.push({ n: name, d: 1 }); return; }
            // A file this tab is writing through a private copy: its size is the copy's.
            const cp = copies.get(dirRel + name);
            // getFile() may throw while another handle holds the file in some browsers.
            // Still list it (size unknown) rather than aborting the whole directory.
            try { const f = await h.getFile(); out.push({ n: name, s: cp ? cp.size : f.size, m: f.lastModified }); }
            catch { out.push({ n: name, s: cp ? cp.size : 0, m: 0 }); }
          }));
        }
        // Merge the not-yet-downloaded files. This used to be gated on holding a
        // token, on the reasoning that the guest should never see a file it cannot
        // then read -- but the failure mode that produces is a directory of
        // dehydrated files listing EMPTY, which reads as "my data is gone" and is
        // the worse lie. List them; opening one without a token fails loudly (the
        // kernel prints which file and why). `cloudOnly` counts what only the index
        // knows about, so the caller can say so.
        let cloudOnly = 0;
        const kids = (await loadIndex(C)).get(rel.toLowerCase());
        if (kids) for (const [lname, kid] of kids) {
          if (seen.has(lname)) continue;
          if (isTomb((rel ? rel + '/' : '') + kid.n)) continue;   // deleted by the guest
          if (kid.e.kind === 'folder') { out.push({ n: kid.n, d: 1 }); continue; }
          out.push({ n: kid.n, s: kid.e.size | 0, m: kid.e.cloudMtime ? (Date.parse(kid.e.cloudMtime) || 0) : 0 });
          cloudOnly++;
        }
        // The scope root lists the home's .ssh too (it lives outside the folder; see S).
        if (C.scope && rel === C.scope && !out.some((e) => e.n === '.ssh')) {
          let hasSsh = false;
          try { await walkDir('.ssh'); hasSsh = true; } catch (_) { const ix = await loadIndex(C); hasSsh = !!(ix.get('.ssh') || idxEntry('.ssh')); }
          if (hasSsh) out.push({ n: '.ssh', d: 1 });
        }
        if (C.scope && rel === C.scope && shareStore && !out.some((e) => e.n === 'sandpie')) out.push({ n: 'sandpie', d: 1 });
        // Not local and nothing indexed under it -- but if the index KNOWS it as a folder
        // (a cloud folder with no local copy and no indexed files, e.g. an empty one),
        // it is an empty directory, not a missing one. The parent listing showed it, so
        // ENOENT here read as "errno 2 -- this directory will look empty but may not be".
        const selfEntry = idxEntry(rel);
        const knownFolder = (selfEntry && selfEntry.kind === 'folder') || (idxByDir && idxByDir.has(rel.toLowerCase()));
        if (!d && !out.length && !knownFolder) throw Object.assign(new Error('no such dir'), { name: 'NotFoundError' });
        // Stored modes ride along as `p`; entries without one get the kernel's default.
        await loadModes(C);
        if (modes.size) for (const e of out) { const pm = modes.get((rel ? rel + '/' : '') + e.n); if (pm !== undefined) e.p = pm; }
        // Symlinks carry their target (`l`): the file's content. A cloud-only one (no local
        // copy yet) lists as a plain file until it is downloaded.
        if (d) await Promise.all(out.filter((e) => !e.d && isLinkMode(e.p)).map(async (e) => {
          try { e.l = await (await (await d.getFileHandle(e.n)).getFile()).text(); } catch (_) { delete e.p; }
        }));
        // aux carries how many entries are cloud-only AND unreadable right now, so
        // the kernel can warn once instead of the guest meeting an EIO per file.
        out.sort((x, y) => x.n < y.n ? -1 : x.n > y.n ? 1 : 0);   // Promise.all filled `out` in completion order: ls shuffled between calls
        const b = te.encode(JSON.stringify(out));
        if (b.length > data.length) return finish(C, EINVAL, 0);
        data.set(b, 0); return finish(C, b.length, cloud() ? 0 : cloudOnly);
      }
      case OP.OPEN: {                        // in: path, a1=flags (bit0 create, bit1 excl) — out: res=id, aux=size
        const rel = S(C, td.decode(data.slice(0, a0)));
        // Self-heal: an id of THIS channel still open on the path was leaked by a process the
        // kernel lost (it only opens a file it holds no id for).
        for (const e of [...handles.values()]) if (e.C === C && e.rel === rel) closeId(e);
        // Cloud-only file: fetch the bytes before handing out a handle. Also on
        // create -- opening a dehydrated file for writing must not start from an
        // empty one and silently discard what is in the cloud.
        try { await hydrate(C, rel); } catch (err) { return finish(C, err && err.quota ? EDQUOT : EIO, 0); }
        const { d, name } = await parentOf(rel, a1 & 1);
        C.phase = 'opening the file (OPFS)';
        // a1 is FLAGS now: bit0 = create, bit1 = exclusive (O_CREAT|O_EXCL). Git takes every
        // lock (index.lock, ref locks, mkstemp temps) with an exclusive create, so the
        // check-and-create must be ONE atomic step at the storage layer -- not a
        // check-then-create in the kernel, whose file map goes stale the moment another
        // tab's kernel writes the same OPFS tree. This worker serves requests strictly one
        // at a time (the SAB loop and the port chain both serialize), so the existence
        // probe here IS the test-and-set.
        let fh;
        if ((a1 & 1) && (a1 & 2)) {
          try { await d.getFileHandle(name); return finish(C, EEXIST, 0); }
          catch (e) { if (e && e.name !== 'NotFoundError') throw e; }
          fh = await d.getFileHandle(name, { create: true });
        } else {
          fh = await d.getFileHandle(name, { create: !!(a1 & 1) });
        }
        // No lock is taken here: the id reads lock-free until its first write (toWriter).
        let size, file = null;
        const cp = copies.get(rel), w = writers.get(rel);
        if (cp) size = cp.size;
        else if (w) size = w.sh.getSize();
        else { file = await fh.getFile(); size = file.size; }
        if (C.closed) return;
        const id = nextId++;
        handles.set(id, { id, C, rel, fh, mode: 'r', file, fileAt: Date.now(), gen: genOf(rel), gone: false });
        if (a1 & 1) { tombs.delete(String(rel).replace(/^\/+/, '').toLowerCase()); reportChange(C, rel); caseClash(C, rel); }
        return finish(C, id, size);
      }
      case OP.READ: {
        const e = handles.get(a0); if (!e || e.gone) return finish(C, EBADF, 0);
        const cp = copies.get(e.rel), w = writers.get(e.rel);
        let n, size;
        if (cp) { n = Math.max(0, Math.min(a2, cp.size - off)); data.set(cp.buf.subarray(off, off + n), 0); size = cp.size; }
        else if (w) { const b = new Uint8Array(a2); n = w.sh.read(b, { at: off }); if (shBad(n, a2)) return finish(C, ioErrOf(n), 0); data.set(b.subarray(0, n), 0); size = w.sh.getSize(); }   // scratch: handle IO on SAB views is engine-dependent
        else { const b = await snapRead(C, e, off, a2); n = b.length; if (C.closed) return; data.set(b, 0); size = e.file ? e.file.size : -1; }
        // aux = the file's CURRENT size + 1 (0 = unknown). The kernel bounds reads by the size it
        // saw when it opened the file; now that other kernels can write a file this one has open,
        // that size goes stale -- a re-read after the shell rewrote a file Python held came back
        // cut to the old length. The kernel takes this as the file's size (wali-worker fileRead).
        return finish(C, n, size >= 0 ? size + 1 : 0);
      }
      case OP.WRITE: {
        const e = handles.get(a0); if (!e || e.gone) return finish(C, EBADF, 0);
        await toWriter(C, e);
        if (!handles.has(a0) || C.closed) return finish(C, EBADF, 0);
        let n;
        if (e.mode === 'c') n = cpWrite(copies.get(e.rel), data.slice(0, a2), off);
        else n = writers.get(e.rel).sh.write(data.slice(0, a2), { at: off });
        if (shBad(n, a2)) return finish(C, ioErrOf(n), 0);
        bump(e.rel); reportChange(C, e.rel);
        return finish(C, n, 0);
      }
      case OP.TRUNC: {
        const e = handles.get(a0); if (!e || e.gone) return finish(C, EBADF, 0);
        await toWriter(C, e);
        if (!handles.has(a0) || C.closed) return finish(C, EBADF, 0);
        if (e.mode === 'c') cpTrunc(copies.get(e.rel), off);
        else writers.get(e.rel).sh.truncate(off);
        bump(e.rel); reportChange(C, e.rel);
        return finish(C, 0, 0);
      }
      case OP.CLOSE: { const e = handles.get(a0); if (e) closeId(e); return finish(C, 0, 0); }
      case OP.UNLINK: case OP.RMDIR: {       // in: path
        const rel = S(C, td.decode(data.slice(0, a0)));
        // Deleting used to hydrate first ("removeEntry needs a real entry"), so `rm`
        // on a cloud-only file failed with the DOWNLOAD's error -- ENOENT if there was
        // no token -- and the file stayed in the listing. A delete needs no bytes:
        // drop the local copy if there is one, tombstone the path either way, and let
        // the page propagate the remote delete.
        if (op === OP.UNLINK) {
          letGo(rel);
          // POSIX: unlink() on a directory is EISDIR -- never a silent directory delete
          // (removeEntry would happily remove an EMPTY directory). Probe the type first;
          // a missing file falls through to the NotFoundError -> ENOENT path below.
          {
            const { d: ud, name: un } = await parentOf(rel);
            try { await ud.getFileHandle(un); }
            catch (e) { if (e && e.name === 'TypeMismatchError') return finish(C, EISDIR, 0); }
          }
          let hadLocal = false;
          try { const { d, name } = await parentOf(rel); await d.removeEntry(name, { recursive: false }); hadLocal = true; }
          catch (e) { if (!(e && e.name === 'NotFoundError')) throw e; }
          tombs.add(String(rel).replace(/^\/+/, '').toLowerCase());
          markGone(rel);
          if (!hadLocal) await loadIndex(C);         // so a cloud-only path is still "known"
          const known = hadLocal || !!idxEntry(rel);
          reportRemoved(C, rel);
          await loadModes(C); dropModes(rel);
          return finish(C, known ? 0 : ENOENT, 0);
        }
        const { d, name } = await parentOf(rel);
        await d.removeEntry(name, { recursive: false });
        // Tombstone the dir AND everything the cloud index still knows under it --
        // otherwise the next listing resurrects the (now deleted) directory populated
        // with cloud-only children, the same lie UNLINK's tombstone already fixes for
        // plain files.
        await loadIndex(C);
        const lr = String(rel).replace(/^\/+/, '').toLowerCase();
        tombs.add(lr);
        for (const k of (idxByPath ? [...idxByPath.keys()] : []))
          if (k === lr || k.startsWith(lr + '/')) tombs.add(k);
        reportRemoved(C, rel);
        await loadModes(C); dropModes(rel);
        return finish(C, 0, 0);
      }
      case OP.LOCK: case OP.UNLOCK: {       // in: path, a1 = 1 shared / 2 exclusive (LOCK)
        // Cross-tab advisory locking for one kernel's aggregate lock on a file (see the
        // kernel's lock table): a Web Lock 'walios-lk:<rel>' held by this worker on behalf of
        // channel C. Whole-file granularity across tabs (byte ranges are exact within a tab):
        // conservative -- a range that would not overlap can still read as busy, never the
        // reverse. Not-available answers EAGAIN at once; the kernel retries for blocking calls.
        const rel = S(C, td.decode(data.slice(0, a0)));
        const held = C.locks || (C.locks = new Map());
        const cur = held.get(rel);
        const want = op === OP.UNLOCK ? 0 : (a1 === 2 ? 2 : 1);
        if (cur && cur.mode === want) return finish(C, 0, 0);
        if (cur) { held.delete(rel); cur.release(); }
        if (!want) return finish(C, 0, 0);
        if (!(self.navigator && navigator.locks)) return finish(C, 0, 0);   // no Web Locks: tab-local only
        const got = await new Promise((resolve) => {
          navigator.locks.request('walios-lk:' + rel, { mode: want === 2 ? 'exclusive' : 'shared', ifAvailable: true }, (lk) => {
            if (!lk) { resolve(null); return; }
            return new Promise((release) => resolve({ mode: want, release }));
          }).catch(() => resolve(null));
        });
        if (!got) {
          // An upgrade that lost: put the shared lock back so the kernel's view stays true.
          if (cur && cur.mode === 1) {
            const back = await new Promise((resolve) => navigator.locks.request('walios-lk:' + rel, { mode: 'shared', ifAvailable: true }, (lk) => lk ? new Promise((release) => resolve({ mode: 1, release })) : resolve(null)).catch(() => resolve(null)));
            if (back) held.set(rel, back);
          }
          return finish(C, -11, 0);           // EAGAIN
        }
        held.set(rel, got);
        return finish(C, 0, 0);
      }
      case OP.STAT: {                        // in: a0 = id -- out: aux = the file's CURRENT size + 1
        // fstat() on an open file. The kernel's own idea of the size goes stale when another
        // tab rewrites or replaces the file; git mmaps exactly st_size bytes of the index, and
        // a short map parses garbage entries. Always a fresh look (the path is re-resolved:
        // the file may have been replaced by a rename from another tab).
        // a1 bit0 = settle: the kernel holds no open fd on the file any more, so the writer can
        // be closed now (it would be at the end of the release grace anyway) -- then the file's
        // lastModified is final and goes back as the mtime (data: Float64). Other tabs list that
        // same lastModified, so every kernel reports one mtime for the file (git's index
        // compares it; a kernel-clock mtime made each fresh kernel re-read every file).
        const e = handles.get(a0); if (!e || e.gone) return finish(C, EBADF, 0);
        if ((a1 & 1) && !copies.get(e.rel)) letGo(e.rel);
        const cp = copies.get(e.rel), w = writers.get(e.rel);
        let size, mtime = -1;
        if (cp) size = cp.size;
        else if (w) size = w.sh.getSize();
        else {
          e.fh = null;
          const f = await (await getFH(e)).getFile();
          if (C.closed) return;
          e.file = f; e.fileAt = Date.now(); e.gen = genOf(e.rel); e.ra = null;
          size = f.size; mtime = f.lastModified;
        }
        new DataView(data.buffer, data.byteOffset, 8).setFloat64(0, mtime, true);
        return finish(C, 8, size + 1);
      }
      case OP.RENAMEDIR: {                   // in: old \0 new -- rename a DIRECTORY (see moveTree)
        const [oldRel, newRel] = td.decode(data.slice(0, a0)).split('\0').map((r) => S(C, r));
        if (!oldRel || !newRel) return finish(C, EINVAL, 0);
        if (newRel === oldRel) return finish(C, 0, 0);
        if (newRel.startsWith(oldRel + '/')) return finish(C, EINVAL, 0);
        let src;
        try { src = await walkDir(oldRel); }
        catch (e) { return finish(C, e && e.name === 'TypeMismatchError' ? ENOTDIR : ENOENT, 0); }
        // The destination: absent, or an EMPTY directory (replaced, as on Linux).
        try {
          const nd = await walkDir(newRel);
          for await (const _ of nd.keys()) return finish(C, ENOTEMPTY, 0);
          const { d: np, name: nn } = await parentOf(newRel);
          await np.removeEntry(nn, { recursive: false });
        } catch (e) {
          if (e && e.name === 'TypeMismatchError') return finish(C, ENOTDIR, 0);
          if (!(e && e.name === 'NotFoundError')) throw e;
        }
        const tree = await localTree(src, oldRel, { files: [], dirs: [] });
        // Cloud-only files cannot be moved by handle: keep the old answer (EXDEV -> mv copies
        // through the store, downloading them) rather than strand them under the old name.
        if (await cloudOnlyUnder(C, oldRel, tree.files)) return finish(C, EXDEV, 0);
        // ATOMIC where the browser has directory move() (Firefox 151; Chromium 149-153 does not).
        if (!debugNoMove && typeof src.move === 'function') {
          for (const f of tree.files) letGo(f);
          const { d: np, name: nn } = await parentOf(newRel, 1);
          let ok = false;
          try { await src.move(np, nn); ok = true; } catch (_) {}
          if (ok) {
            for (const o of tree.files) movedFile(C, o, newRel + o.slice(oldRel.length));
            for (const k of [...dirCache.keys()]) if (k === oldRel || k.startsWith(oldRel + '/')) dirCache.delete(k);
            await loadModes(C); moveModes(oldRel, newRel);
            return finish(C, 0, 0);
          }
        }
        const id = jid();
        const logged = await journalOp((st) => st.put({ id, from: oldRel, to: newRel }, id));
        await moveTree(C, oldRel, newRel); caseClash(C, newRel);
        await loadModes(C); moveModes(oldRel, newRel);
        if (logged) await journalOp((st) => st.delete(id));
        return finish(C, 0, 0);
      }
      case OP.SYMLINK: {                     // in: linkpath \0 target -- a symlink on the mount
        // Stored as a small file holding the target, marked S_IFLNK in the mode sidecar (OPFS
        // has no symlinks). Exclusive: an existing name of any kind is EEXIST, as on Linux.
        const [lrel0, target] = td.decode(data.slice(0, a0)).split('\0');
        const lrel = S(C, lrel0);
        const { d: ld, name: ln } = await parentOf(lrel);
        try { await ld.getFileHandle(ln); return finish(C, EEXIST, 0); }
        catch (e) { if (e && e.name === 'TypeMismatchError') return finish(C, EEXIST, 0); if (e && e.name !== 'NotFoundError') throw e; }
        const fh = await ld.getFileHandle(ln, { create: true });
        const sh = await openSync(fh, 12);
        try { const b = te.encode(target); sh.truncate(0); shWrite(sh, b, 0); sh.flush(); } finally { sh.close(); }
        await loadModes(C); setMode(lrel, S_IFLNK | 0o777);
        tombs.delete(String(lrel).replace(/^\/+/, '').toLowerCase()); reportChange(C, lrel); caseClash(C, lrel);
        return finish(C, 0, 0);
      }
      case OP.SETMODE: {                     // in: path, a1 = mode bits (or -1 to forget)
        const rel = S(C, td.decode(data.slice(0, a0)));
        await loadModes(C); setMode(rel, a1);
        return finish(C, 0, 0);
      }
      case OP.MKDIR: {                       // in: path
        const mrel = S(C, td.decode(data.slice(0, a0)));
        caseClash(C, mrel);
        // A segment that exists as a FILE made getDirectoryHandle(create:true) throw
        // TypeMismatchError, which the catch-all labelled EACCES ("Operation not
        // permitted") with no clue why. Name it: mkdir over an existing FILE is EEXIST.
        const segs = mrel.split('/').filter(Boolean);
        let md = root;
        for (let i = 0; i < segs.length; i++) {
          try { md = await md.getDirectoryHandle(segs[i]); }
          catch (e) {
            if (e && e.name === 'TypeMismatchError') return finish(C, EEXIST, 0);
            if (e && e.name === 'NotFoundError') {         // missing: create the rest
              for (let j = i; j < segs.length; j++) md = await md.getDirectoryHandle(segs[j], { create: true });
              return finish(C, 0, 0);
            }
            throw e;
          }
        }
        return finish(C, 0, 0);              // already a directory: mkdir -p semantics
      }
      case OP.RENAME: {                      // in: old \0 new
        const [oldRel, newRel] = td.decode(data.slice(0, a0)).split('\0').map((r) => S(C, r));
        letGo(oldRel); letGo(newRel);
        try { await hydrate(C, oldRel); } catch {}   // cannot move bytes that are still in the cloud
        const { d: od, name: on } = await parentOf(oldRel);
        const { d: nd, name: nn } = await parentOf(newRel, 1);
        const oh = await od.getFileHandle(on);
        // ATOMIC where the browser can do it (FileSystemFileHandle.move, Chromium): git
        // writes every object, ref and index as a temp file and rename()s it into place,
        // relying on the rename being all-or-nothing. The copy+delete below is not: a run
        // killed between the write and the removeEntry left a half-copied loose object or
        // a truncated ref -- the "inflate: data stream error" / "bad object HEAD" a repo
        // showed after a timeout kill. Fall back to copy+delete only where move() is missing.
        let moved = false;
        if (!debugNoMove && typeof oh.move === 'function') {
          try { if (nd === od || (await nd.isSameEntry(od))) await oh.move(nn); else await oh.move(nd, nn); moved = true; } catch {}
        }
        if (!moved) {                        // journalled copy + delete (see finishFileMove)
          const id = jid();
          const tmp = (newRel.includes('/') ? newRel.slice(0, newRel.lastIndexOf('/') + 1) : '') + '.walios-mv-' + id;
          await writeWhole(tmp, new Uint8Array(await (await oh.getFile()).arrayBuffer()));
          const logged = await journalOp((st) => st.put({ id, kind: 'file', from: oldRel, to: newRel, tmp }, id));
          await finishFileMove(oldRel, newRel, tmp);
          if (logged) await journalOp((st) => st.delete(id));
        }
        // Open files follow the file, as on Linux: the ids on the old path now name the new
        // one; whatever was open on the new path was replaced (gone). A private copy moves too.
        markGone(newRel); caseClash(C, newRel);
        for (const e of handles.values()) if (e.rel === oldRel) { e.rel = newRel; e.fh = null; e.file = null; }
        const cp = copies.get(oldRel); if (cp) { copies.delete(oldRel); cp.rel = newRel; copies.set(newRel, cp); }
        bump(oldRel); bump(newRel);
        reportChange(C, newRel); reportRemoved(C, oldRel);
        await loadModes(C); moveModes(oldRel, newRel);
        return finish(C, 0, 0);
      }
      case OP.FSYNC: {                       // durability barrier on an open handle
        const e = handles.get(a0); if (!e || e.gone) return finish(C, EBADF, 0);
        // Never a false "durable": a flush that throws is EIO.
        const w = writers.get(e.rel);
        if (w) { try { w.sh.flush(); } catch (_) { return finish(C, EIO, 0); } }
        // Copy mode: the bytes live only in this tab's private copy (the file is locked by
        // another tab or the app). One save attempt now; still locked = EIO. The copy stays
        // the live view while it has open ids -- close still commits anything written later.
        const cp = e.mode === 'c' ? copies.get(e.rel) : null;
        if (cp && cp.dirty) {
          try {
            const sh = await openSyncOnce(await fileHandleOf(cp.rel));
            try {
              sh.truncate(cp.size);
              shWrite(sh, cp.buf.subarray(0, cp.size), 0);
              sh.flush();
            } finally { sh.close(); }
          } catch (_) { return finish(C, EIO, 0); }
          cp.dirty = false; bump(cp.rel); reportChange(C, cp.rel);
        }
        return finish(C, 0, 0);
      }
      case OP.RELEASE: {                     // end of run: drop every id of THIS channel
        closeChannelIds(C); return finish(C, 0, 0);
      }
    }
    finish(C, EINVAL, 0);
  } catch (e) {
    // NEVER swallow silently: an unmapped exception used to become EACCES, which
    // busybox prints as "Operation not permitted" with zero clue about the cause.
    console.error('[opfs-worker] op', op, 'failed:', e);
    const n = e && e.name;
    // NoModificationAllowedError/InvalidStateError = a handle outside this tab holds the
    // file (another tab, the app's own writer) and it could not be worked around.
    finish(C, isLockErr(e) ? EBUSY :
           n === 'NotFoundError' ? ENOENT :
           n === 'TypeMismatchError' ? EEXIST :      // a path segment exists as a FILE
           n === 'InvalidModificationError' ? ENOTEMPTY :
           n === 'QuotaExceededError' ? ENOSPC :
           EACCES, 0);
  }
}


// ---- directory rename (RENAMEDIR) -------------------------------------------
// OPFS has no directory move() (Chromium 149-153: FileSystemDirectoryHandle.move is
// undefined), so rename(dir) used to be EXDEV and mv copied every byte. Now the bridge moves
// each FILE with handle.move() (a metadata op, no copying) into a re-created tree, then
// drops the old one. Not atomic to a concurrent observer, but crash-atomic: an intent record
// is written to IndexedDB first and removed last, and a bridge that starts and finds one
// finishes the move (roll forward; every step is idempotent), so a kill mid-rename never
// leaves the tree split between two names for the guest to find.
const JOURNAL_DB = 'walios-journal', JOURNAL_STORE = 'renames';
function journalDb() {
  return new Promise((resolve) => {
    let req, done = false;
    const fin = (db) => { if (done) { try { db && db.close(); } catch {} return; } done = true; clearTimeout(t); resolve(db); };
    const t = setTimeout(() => fin(null), IDB_MS);
    try { req = indexedDB.open(JOURNAL_DB, 1); } catch { return fin(null); }
    req.onupgradeneeded = () => { try { req.result.createObjectStore(JOURNAL_STORE); } catch {} };
    req.onerror = () => fin(null); req.onsuccess = () => fin(req.result);
  });
}
async function journalOp(fn) {             // -> result of fn(store)'s request once the tx completed, or null
  const db = await journalDb(); if (!db) return null;
  try {
    return await bounded(new Promise((res) => {
      const tx = db.transaction(JOURNAL_STORE, 'readwrite');
      const rq = fn(tx.objectStore(JOURNAL_STORE));
      tx.oncomplete = () => res(rq && rq.result !== undefined ? rq.result : true);
      tx.onerror = tx.onabort = () => res(null);
    }), IDB_MS, 'the rename journal');
  } catch (_) { return null; } finally { try { db.close(); } catch {} }
}
async function localTree(d, rel, out) {    // every local file/dir under d (rel-prefixed)
  for await (const [name, h] of d.entries()) {
    const r = rel + '/' + name;
    if (h.kind === 'directory') { out.dirs.push(r); await localTree(h, r, out); } else out.files.push(r);
  }
  return out;
}
// Index-only (cloud, not downloaded) files under rel: they cannot be moved by handle.
async function cloudOnlyUnder(C, rel, localFiles) {
  if (!haveIndex()) return 0;
  const ix = await loadIndex(C), lo = rel.toLowerCase(), local = new Set(localFiles.map((f) => f.toLowerCase()));
  let n = 0;
  for (const [dk, kids] of ix) {
    if (dk !== lo && !dk.startsWith(lo + '/')) continue;
    for (const [lname, kid] of kids) {
      if (kid.e.kind === 'folder') continue;
      const kr = (dk ? dk + '/' : '') + lname;
      if (!local.has(kr) && !isTomb(kr)) n++;
    }
  }
  return n;
}
// Bookkeeping after a file moved from o to n (by any means): ids and private copies follow
// it, generations bump, the sync ledger hears about both names.
function movedFile(C, o, n) {
  for (const e of handles.values()) if (e.rel === o) { e.rel = n; e.fh = null; e.file = null; }
  const cp = copies.get(o); if (cp) { copies.delete(o); cp.rel = n; copies.set(n, cp); }
  bump(o); bump(n);
  if (C) { reportChange(C, n); reportRemoved(C, o); }
}
async function writeWhole(rel, buf) {      // create/replace rel with buf, flushed
  const { d, name } = await parentOf(rel, 1);
  const sh = await openSync(await d.getFileHandle(name, { create: true }), 12);
  try {
    sh.truncate(0);
    shWrite(sh, buf, 0);
    sh.flush();
  } finally { sh.close(); }
}
async function removeIfThere(rel) {
  try { const { d, name } = await parentOf(rel); await d.removeEntry(name); }
  catch (e) { if (!(e && e.name === 'NotFoundError')) throw e; }
}
// A file rename WITHOUT handle.move() (a browser that lacks it): copy + delete is not
// atomic, so it is journalled. The bytes are first written to a temp sibling of the
// destination (flushed), the intent is recorded, then tmp -> destination, delete the source,
// delete tmp. A bridge that finds the record redoes the last three (idempotent): a kill at
// any point leaves the destination old-or-new after recovery, never half-written for good.
async function finishFileMove(from, to, tmp) {
  let buf;
  try { const { d, name } = await parentOf(tmp); buf = new Uint8Array(await (await (await d.getFileHandle(name)).getFile()).arrayBuffer()); }
  catch (e) { if (e && e.name === 'NotFoundError') return; throw e; }   // tmp gone: the move had finished
  await writeWhole(to, buf);
  if (from !== to) await removeIfThere(from);
  await removeIfThere(tmp);
}
const jid = () => Date.now().toString(36) + Math.random().toString(36).slice(2);
// Move the tree at oldRel to newRel (newRel absent, or an empty dir already removed).
// Idempotent: safe to re-run after a crash at any point.
async function moveTree(C, oldRel, newRel) {
  let src; try { src = await walkDir(oldRel); } catch (e) { if (e && e.name === 'NotFoundError') return; throw e; }
  const dst = await walkDir(newRel, true);
  const ents = []; for await (const ent of src.entries()) ents.push(ent);
  for (const [name, h] of ents) {
    const o = oldRel + '/' + name, n = newRel + '/' + name;
    if (h.kind === 'directory') { await moveTree(C, o, n); continue; }
    letGo(o);
    if (!debugNoMove && typeof h.move === 'function') await h.move(dst, name);
    else {                                   // no move(): copy then delete. The whole tree move is
      // journalled, and a re-run copies again from what is still under the old name.
      await writeWhole(n, new Uint8Array(await (await h.getFile()).arrayBuffer()));
      await src.removeEntry(name);
    }
    movedFile(C, o, n);
  }
  const { d: op, name: on } = await parentOf(oldRel);
  try { await op.removeEntry(on, { recursive: false }); } catch (e) { if (!(e && e.name === 'NotFoundError')) throw e; }
  for (const k of [...dirCache.keys()]) if (k === oldRel || k.startsWith(oldRel + '/')) dirCache.delete(k);
}
let journalRecovered = null;
function recoverRenames() {                // finish renames a killed bridge left half done
  if (!journalRecovered) journalRecovered = (async () => {
    const pending = await journalOp((st) => st.getAll());
    if (!pending || pending === true || !pending.length) return;
    for (const j of pending) {
      try {
        if (j.kind === 'file') await finishFileMove(j.from, j.to, j.tmp);
        else await moveTree(null, j.from, j.to);
        await loadModes(null); moveModes(j.from, j.to);
      }
      catch (e) { try { console.error('[opfs-worker] could not finish an interrupted rename', j, e); } catch {} continue; }
      await journalOp((st) => st.delete(j.id));
    }
  })().catch(() => {});
  return journalRecovered;
}
function initRoot(subdir) {
  if (!rootReady) rootReady = (async () => {
    // No OPFS here (a browser without it, or a context that lacks it): say so and keep
    // serving -- every request is answered EIO -- rather than never answering. The kernel
    // parks on the SAB waiting for us; an unanswered request used to hang the guest forever.
    try { root = await navigator.storage.getDirectory(); }
    catch (e) { root = null; post(null, { ready: false, error: 'OPFS unavailable: ' + ((e && e.message) || e) }); }
    // Optional isolation: scope this mount to an OPFS subdir so a shell can't see or
    // delete the host app's OPFS data (same origin). terminal.html passes subdir.
    if (root && subdir) { for (const s of subdir.split('/').filter(Boolean)) root = await root.getDirectoryHandle(s, { create: true }); }
    // (The legacy full-root mount used to plant a demo hello-from-opfs.txt at the workspace
    // root on every boot. It was clutter in the user's home, synced to their cloud; the
    // workspace check (organize.js) removes any left behind.)
  })();
  return rootReady;
}

self.onmessage = async (ev) => {
  const m = ev.data || {};
  const C = chans.get(m.ch === undefined ? 0 : m.ch) || null;
  if (m.t === 'tombstones') {                // replayed by the page at boot
    for (const r of m.rels || []) tombs.add(String(r).replace(/^\/+/, '').toLowerCase());
    return;
  }
  // The cloud provider config for hydrating cloud-only files. Sent before the
  // initial 'sab' message and re-sendable at any time (an access token lives ~4h;
  // the app refreshes it and pushes the new config). The host sends it before each run,
  // so the channel's degraded-mode notes may be said again.
  if (m.t === 'cloud') { setCloud(m.provider); if (C) C.noted.clear(); else if (m.ch === undefined) for (const c of chans.values()) c.noted.clear(); return; }
  // The host's copy of the cloud index (see pushedIdx). null = it has none: fall back to IndexedDB.
  if (m.t === 'cloud-index') {
    pushedIdx = (m.index && typeof m.index === 'object') ? m.index : undefined;
    dropIndex();
    return;
  }
  // Test hook (tests/walios/e2e-bridge-stall.mjs, via the host's 'walios-debug-stall'): a
  // request whose path contains this substring never settles, standing in for the
  // unexplained stalls seen in prod. Off unless a test sets it.
  if (m.t === 'share-store') { shareStore = !!m.on; return; }
  if (m.t === 'dl-budget') { dlBudget = m.budget || null; return; }
  if (m.t === 'debug-eio') { debugEio = m.rel ? String(m.rel) : ''; return; }
  if (m.t === 'debug-nomove') { debugNoMove = !!m.on; return; }
  if (m.t === 'debug-stall') { debugStall = m.rel ? String(m.rel) : ''; if (m.budgetMs > 0) BUDGET_MS = m.budgetMs | 0; return; }
  // Fire the pending change batch NOW instead of waiting out the 250ms debounce,
  // then ack. The walios() tool sends this on the guest's exit so every write is
  // reported (and attributed to the finishing run) before the tool result resolves.
  if (m.t === 'flush') {
    const list = C ? [C] : (m.ch === undefined ? [...chans.values()] : []);
    for (const c of list) { flushChanged(c); flushRemoved(c); c.dlN = 0; c.dlBytes = 0; }
    post(C, { t: 'flushed' });
    return;
  }
  // The host is done with this channel (its kernel was dropped): release what it holds.
  if (m.t === 'detach') {
    if (!C) return;
    flushChanged(C); flushRemoved(C);
    C.closed = true; chans.delete(C.id);
    closeChannelIds(C);
    if (C.locks) { for (const l of C.locks.values()) l.release(); C.locks.clear(); }
    if (C.ctl && !C.port) { try { Atomics.notify(C.ctl, 0); } catch {} }   // wake its serve loop so it ends
    if (C.port) { try { C.port.close(); } catch {} }
    return;
  }
  if (m.t !== 'sab') return;
  if (m.provider) setCloud(m.provider);
  if (m.shareStore !== undefined) shareStore = !!m.shareStore;
  if (m.dlBudget !== undefined) dlBudget = m.dlBudget || null;
  const id = m.ch === undefined ? 0 : m.ch;
  const old = chans.get(id); if (old) { old.closed = true; closeChannelIds(old); if (old.locks) { for (const l of old.locks.values()) l.release(); old.locks.clear(); } }
  const ch = mkChan(id, String(m.scope || '').replace(/^\/+|\/+$/g, ''));
  chans.set(id, ch);
  // No SharedArrayBuffer on the page (no cross-origin isolation): the kernel runs its
  // in-process engine and talks to this worker over a MessagePort instead (see
  // servePort); ctl/data are then private scratch the same handle() code writes to.
  const port = m.port || null;
  if (!port) { ch.ctl = new Int32Array(m.sab, 0, 8); ch.data = new Uint8Array(m.sab, 32); }
  await initRoot(m.subdir);
  if (root) await recoverRenames();
  post(m.ch === undefined ? null : ch, { ready: true });
  if (port) { servePort(ch, port); return; }
  serveSab(ch);
};
