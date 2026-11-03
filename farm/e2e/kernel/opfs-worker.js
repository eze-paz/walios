// OPFS bridge worker: owns ALL OPFS handles so the (synchronous) OS worker can
// fault the tree in lazily over a SharedArrayBuffer — the riscv-vm ?p9lazy model.
// Spawned by the PAGE as a sibling of wali-worker (a nested worker would starve
// under its blocked parent). Sync access handles are exclusive locks, so one is
// opened only when a file is actually read/written, and released on unlink,
// RELEASE (end of run), or self-healed on a stale re-OPEN.
// SAB layout (same shape as the wisp bridge): Int32Array ctl at 0 —
// [0]=req seq, [1]=done seq, [2]=op, [3..5]=args, [6]=res, [7]=aux; data at 32.
'use strict';
const OP = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11, SETMODE: 12 };
const ENOENT = -2, EIO = -5, EBADF = -9, EACCES = -13, EEXIST = -17, EBUSY = -16, EINVAL = -22, ENOSPC = -28, ENOTEMPTY = -39;
const te = new TextEncoder(), td = new TextDecoder();
let ctl, data, root;
// Optional scope: every guest path is resolved under this OPFS folder ("projects/x"),
// so /root is that folder and nothing outside it is reachable. Unlike `subdir`, rels
// stay full workspace paths, so the cloud index, hydration and change reports all
// keep working unchanged. Set by the spawner (sandpie-worker: a conversation's folder).
let scope = '';
// The home's dotfolders stay the home's in a scoped kernel: ~/.ssh is the workspace-root
// .ssh whatever the conversation's folder is (ssh reads $HOME/.ssh, and HOME=/root is the
// folder). Everything else under /root stays confined to the folder.
const HOME_SHARED = ['.ssh'];
const homeShared = (r) => HOME_SHARED.some((h) => r === h || r.startsWith(h + '/'));
const S = (rel) => { const r = String(rel || '').replace(/^\/+/, ''); if (scope && homeShared(r)) return r; return scope ? (r ? scope + '/' + r : scope) : r; };
const handles = new Map(); let nextId = 1;   // id -> { sh, rel }

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
// downloads the same way, with _pulling).
let changed = new Set(), changeTimer = null, hydrating = 0;

// Paths the guest deleted. Listing a cloud-only file (above) means the guest can
// see files whose bytes are still in the cloud -- and `rm` on one used to remove
// nothing and then re-list it from the index, so the file looked undeletable. The
// remote delete goes through the app's own handshake (Sandpie 'file:deleted' ->
// the sync provider's onFileDeleted), but that is asynchronous and needs a token, while `rm`
// has to look like it worked NOW. So a deleted path is remembered here and
// suppressed from every cloud-index merge; the page persists the set and replays it
// on boot, because a Worker has no storage of its own.
let tombs = new Set();
const isTomb = (rel) => tombs.has(String(rel).replace(/^\/+/, '').toLowerCase());
function reportChange(rel) {
  if (hydrating || !rel) return;
  changed.add(String(rel).replace(/^\/+/, ''));
  if (changeTimer) return;
  changeTimer = setTimeout(() => {
    changeTimer = null;
    const rels = [...changed]; changed = new Set();
    if (rels.length) { try { self.postMessage({ t: 'opfs-changed', rels }); } catch {} }
  }, 250);
}
let removed = new Set(), removedTimer = null;
function flushRemoved() {
  if (removedTimer) { clearTimeout(removedTimer); removedTimer = null; }
  if (removed.size) { const rels = [...removed]; removed = new Set();
    try { self.postMessage({ t: 'opfs-removed', rels }); } catch {} }
}
function reportRemoved(rel) {
  if (!rel) return;
  const nr = String(rel).replace(/^\/+/, '');
  // Cancel any create for this path still sitting in the debounced batch, so a file
  // that was created and then deleted/renamed-away in the same run (git's temp pack
  // files, lock files, a scratch `rm -rf`) does NOT get flushed as a create AFTER the
  // delete already landed — which would leave a card for a gone file and mark a
  // non-existent path dirty in the sync ledger.
  changed.delete(nr);
  // Batched like reportChange: an `rm -rf` of a big tree used to post one message
  // per file while creates rode a 250ms debounce.
  removed.add(nr);
  if (removedTimer) return;
  removedTimer = setTimeout(flushRemoved, 250);
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
function metaDb() {
  return new Promise((resolve) => {
    let req; try { req = indexedDB.open(META_DB, 1); } catch { return resolve(null); }
    req.onupgradeneeded = () => { try { req.result.createObjectStore(META_STORE); } catch {} };
    req.onerror = () => resolve(null);
    req.onsuccess = () => resolve(req.result);
  });
}
async function loadModes() {
  if (modes) return modes;
  if (!modesPromise) modesPromise = (async () => {
    modes = new Map();
    const db = await metaDb(); if (!db) return modes;
    await new Promise((res) => {
      let tx; try { tx = db.transaction(META_STORE, 'readonly'); } catch { return res(); }
      const st = tx.objectStore(META_STORE), rk = st.getAllKeys(), rv = st.getAll();
      tx.oncomplete = () => { const ks = rk.result || [], vs = rv.result || []; for (let i = 0; i < ks.length; i++) modes.set(ks[i], vs[i] | 0); res(); };
      tx.onerror = tx.onabort = () => res();
    });
    db.close();
    return modes;
  })();
  return modesPromise;
}
// Fire-and-forget persistence: the in-memory map is already updated, so the guest
// sees the new mode immediately; a lost write only costs the mode after a reboot.
function metaWrite(fn) {
  metaDb().then((db) => {
    if (!db) return;
    try { const tx = db.transaction(META_STORE, 'readwrite'); fn(tx.objectStore(META_STORE)); tx.oncomplete = tx.onerror = tx.onabort = () => db.close(); }
    catch { db.close(); }
  });
}
function setMode(rel, mode) {
  rel = normRel(rel); if (!modes || !rel) return;
  if (mode < 0) { modes.delete(rel); metaWrite((s) => s.delete(rel)); }
  else { modes.set(rel, mode & 0o7777); metaWrite((s) => s.put(mode & 0o7777, rel)); }
}
function dropModes(rel) {                      // a path (and anything under it) is gone
  rel = normRel(rel); if (!modes || !rel) return;
  const gone = []; for (const k of modes.keys()) if (k === rel || k.startsWith(rel + '/')) gone.push(k);
  if (!gone.length) return;
  for (const k of gone) modes.delete(k);
  metaWrite((s) => { for (const k of gone) s.delete(k); });
}
function moveModes(oldRel, newRel) {
  oldRel = normRel(oldRel); newRel = normRel(newRel); if (!modes || !oldRel || !newRel) return;
  const mv = []; for (const [k, v] of modes) if (k === oldRel || k.startsWith(oldRel + '/')) mv.push([k, newRel + k.slice(oldRel.length), v]);
  if (!mv.length) return;
  for (const [o, n, v] of mv) { modes.delete(o); modes.set(n, v); }
  metaWrite((s) => { for (const [o, n, v] of mv) { s.delete(o); s.put(v, n); } });
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
  idxByDir = idxByPath = idxPromise = null;   // re-read the index on next use
}
let idxByDir = null;         // lower-case dir path -> Map(lower name -> {n, e})
let idxByPath = null;        // lower-case rel path -> entry
let idxPromise = null;

function idbReadIndex(key) {
  return new Promise((resolve) => {
    const st = indexStore();
    let req; try { req = indexedDB.open(st.db); } catch { return resolve(null); } // no version arg: a version bump by the owner (the sync provider) must not VersionError us into silently losing the index
    req.onupgradeneeded = () => { try { req.result.createObjectStore(st.store); } catch {} };
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      const db = req.result;
      let g; try { g = db.transaction(st.store, 'readonly').objectStore(st.store).get(key); }
      catch { db.close(); return resolve(null); }
      g.onerror = () => { db.close(); resolve(null); };
      g.onsuccess = () => { db.close(); try { resolve(g.result ? JSON.parse(g.result) : null); } catch { resolve(null); } };
    };
  });
}
// Build parent->children once, not per listing: the index runs to tens of
// thousands of entries and READDIR is on the guest's blocking path.
// Is there a cloud index at all? Listing cloud-only entries does not need a
// token -- only hydrating them does.
function haveIndex() { return !!(idxByDir && idxByDir.size); }
async function loadIndex() {
  if (idxByDir) return idxByDir;
  if (!idxPromise) idxPromise = (async () => {
    const raw = await idbReadIndex(indexStore().key) || {};
    idxByDir = new Map(); idxByPath = new Map();
    for (const k of Object.keys(raw)) {
      const rel = k.replace(/^\/+/, ''); if (!rel) continue;
      const e = raw[k];
      idxByPath.set(rel.toLowerCase(), e);
      const cut = rel.lastIndexOf('/');
      const dir = cut < 0 ? '' : rel.slice(0, cut).toLowerCase();
      const name = cut < 0 ? rel : rel.slice(cut + 1);
      // Every ancestor directory is implied by its children -- the cloud indexes
      // folders too, but a folder entry is not guaranteed for every level.
      let d = dir;
      for (;;) {
        if (!idxByDir.has(d)) idxByDir.set(d, new Map());
        const c2 = d.lastIndexOf('/'); const parent = c2 < 0 ? '' : d.slice(0, c2);
        if (d === '') break;
        const dn = c2 < 0 ? d : d.slice(c2 + 1);
        if (!idxByDir.has(parent)) idxByDir.set(parent, new Map());
        if (!idxByDir.get(parent).has(dn)) idxByDir.get(parent).set(dn, { n: dn, e: { kind: 'folder' } });
        d = parent;
      }
      idxByDir.get(dir).set(name.toLowerCase(), { n: name, e });
    }
    return idxByDir;
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
async function hydrate(rel) {
  if (await isLocal(rel)) return true;
  if (isTomb(rel)) return false;         // the guest deleted it; do not pull it back
  hydrating++;
  try { return await hydrateInner(rel); } finally { hydrating--; }
}
async function hydrateInner(rel) {
  await loadIndex();
  const e = idxEntry(rel);
  if (!e || e.kind === 'folder') return false;          // not a cloud file: normal ENOENT
  const c = cloud();
  if (!c) throw new Error('no ' + cloudName() + ' connection in this tab');
  const bytes = await c.download(e.path || (c.workingRoot() + '/' + rel));
  const { d, name } = await parentOf(rel, 1);
  const sh = await (await d.getFileHandle(name, { create: true })).createSyncAccessHandle();
  try { sh.truncate(0); sh.write(bytes, { at: 0 }); sh.flush(); } finally { sh.close(); }
  // Tell the spawner, which records a clean sync-state entry so a later edit
  // writes back instead of the copy being re-downloaded or treated as new.
  try { self.postMessage({ t: 'hydrated', rel, size: bytes.length }); } catch {}
  return true;
}

async function walkDir(rel, create) {        // -> dir handle at rel
  let d = root;
  for (const s of rel.split('/').filter(Boolean)) d = await d.getDirectoryHandle(s, { create: !!create });
  return d;
}
async function parentOf(rel, create) {       // -> { d: parent dir handle, name }
  const segs = rel.split('/').filter(Boolean);
  let d = root;
  for (let i = 0; i < segs.length - 1; i++) d = await d.getDirectoryHandle(segs[i], { create: !!create });
  return { d, name: segs[segs.length - 1] };
}
function finish(res, aux) { ctl[6] = res | 0; ctl[7] = aux | 0; Atomics.add(ctl, 1, 1); Atomics.notify(ctl, 1); }
function closeByRel(rel) {
  for (const [id, h] of handles) if (h.rel === rel) { try { h.sh.flush(); h.sh.close(); } catch {} handles.delete(id); }
}

// Message bridge (kernel without SharedArrayBuffer): {t:'call', id, op, a0, a1, a2, bytes}
// -> {t:'reply', id, res, aux, data}. One request at a time, in order, exactly like the
// SAB loop; `data` is sized per request (a read wants its whole range at once: there is
// no SAB window here). Only the ops that answer with bytes send any back.
function servePort(port) {
  const CTL = new Int32Array(8);
  let chain = Promise.resolve();
  port.onmessage = (ev) => {
    const m = ev.data; if (!m || m.t !== 'call') return;
    chain = chain.then(async () => {
      const inb = m.bytes ? new Uint8Array(m.bytes) : null;
      ctl = CTL; ctl.fill(0);
      data = new Uint8Array(Math.max(1 << 20, inb ? inb.length : 0, m.op === OP.READ ? (m.a2 | 0) : 0));
      if (inb) data.set(inb, 0);
      ctl[2] = m.op; ctl[3] = m.a0 | 0; ctl[4] = m.a1 | 0; ctl[5] = m.a2 | 0;
      try { await handle(m.op); } catch (e) { try { finish(EIO, 0); } catch (_) {} }
      const n = (m.op === OP.READ || m.op === OP.READDIR) && ctl[6] > 0 ? Math.min(ctl[6], data.length) : 0;
      const out = data.slice(0, n);
      port.postMessage({ t: 'reply', id: m.id, res: ctl[6], aux: ctl[7], data: out.buffer }, [out.buffer]);
    });
  };
}

// Stamped into ctl[5] (the third argument slot, already read into a local) the moment a
// request is picked up, so the kernel can tell "the bridge is slow" (a cloud-only file
// being downloaded on open, which can legitimately take a while) from "the bridge is
// dead" (nothing ever picked the request up). Must match the kernel's SLOW_MARK.
const BRIDGE_BUSY = 0x7ea7;
async function handle(op) {
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  Atomics.store(ctl, 5, BRIDGE_BUSY);
  if (!root) return finish(EIO, 0);            // no OPFS in this browser/context
  try {
    switch (op) {
      case OP.READDIR: {                     // in: path — out: JSON [{n, d?} | {n, s, m}]
        const rel = S(td.decode(data.slice(0, a0)));
        const out = [], seen = new Set();
        await loadIndex();                   // needed by haveIndex() below, and cheap after the first call
        // A directory can be cloud-ONLY (no local copy at all), in which case the
        // walk throws; that is not an error while we still have an index to list.
        let d = null;
        try { d = await walkDir(rel); } catch (e) { if (!haveIndex()) throw e; }
        if (d) {
          // Stat every entry IN PARALLEL. This awaited getFile() one entry at a time, so
          // listing a directory cost one OPFS round trip per file: a git objects/ tree of a
          // few thousand entries took whole seconds to fault in, and a fresh kernel (after a
          // timeout kill) paid that again for every directory git touched -- `git status`
          // timing out at 60s on a repo that lists in under a second here.
          const ents = []; for await (const ent of d.entries()) ents.push(ent);
          await Promise.all(ents.map(async ([name, h]) => {
            seen.add(name.toLowerCase());
            if (h.kind === 'directory') { out.push({ n: name, d: 1 }); return; }
            // getFile() throws while another handle (the host app / Pyodide) holds an
            // exclusive sync-access lock on the file. Still list it (size unknown)
            // rather than aborting the whole directory on one locked entry.
            try { const f = await h.getFile(); out.push({ n: name, s: f.size, m: f.lastModified }); }
            catch { out.push({ n: name, s: 0, m: 0 }); }
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
        const kids = (await loadIndex()).get(rel.toLowerCase());
        if (kids) for (const [lname, kid] of kids) {
          if (seen.has(lname)) continue;
          if (isTomb((rel ? rel + '/' : '') + kid.n)) continue;   // deleted by the guest
          if (kid.e.kind === 'folder') { out.push({ n: kid.n, d: 1 }); continue; }
          out.push({ n: kid.n, s: kid.e.size | 0, m: kid.e.cloudMtime ? (Date.parse(kid.e.cloudMtime) || 0) : 0 });
          cloudOnly++;
        }
        // The scope root lists the home's .ssh too (it lives outside the folder; see S).
        if (scope && rel === scope && !out.some((e) => e.n === '.ssh')) {
          let hasSsh = false;
          try { await walkDir('.ssh'); hasSsh = true; } catch (_) { const ix = await loadIndex(); hasSsh = !!(ix.get('.ssh') || idxEntry('.ssh')); }
          if (hasSsh) out.push({ n: '.ssh', d: 1 });
        }
        // Not local and nothing indexed under it -- but if the index KNOWS it as a folder
        // (a cloud folder with no local copy and no indexed files, e.g. an empty one),
        // it is an empty directory, not a missing one. The parent listing showed it, so
        // ENOENT here read as "errno 2 -- this directory will look empty but may not be".
        const selfEntry = idxEntry(rel);
        const knownFolder = (selfEntry && selfEntry.kind === 'folder') || (idxByDir && idxByDir.has(rel.toLowerCase()));
        if (!d && !out.length && !knownFolder) throw Object.assign(new Error('no such dir'), { name: 'NotFoundError' });
        // Stored modes ride along as `p`; entries without one get the kernel's default.
        await loadModes();
        if (modes.size) for (const e of out) { const pm = modes.get((rel ? rel + '/' : '') + e.n); if (pm !== undefined) e.p = pm; }
        // aux carries how many entries are cloud-only AND unreadable right now, so
        // the kernel can warn once instead of the guest meeting an EIO per file.
        out.sort((x, y) => x.n < y.n ? -1 : x.n > y.n ? 1 : 0);   // Promise.all filled `out` in completion order: ls shuffled between calls
        const b = te.encode(JSON.stringify(out));
        if (b.length > data.length) return finish(EINVAL, 0);
        data.set(b, 0); return finish(b.length, cloud() ? 0 : cloudOnly);
      }
      case OP.OPEN: {                        // in: path, a1=create — out: res=id, aux=size
        const rel = S(td.decode(data.slice(0, a0)));
        closeByRel(rel);                     // self-heal a handle leaked by a terminated OS worker
        // Cloud-only file: fetch the bytes before handing out a handle. Also on
        // create -- opening a dehydrated file for writing must not start from an
        // empty one and silently discard what is in the cloud.
        try { await hydrate(rel); } catch (err) { return finish(EIO, 0); }
        const { d, name } = await parentOf(rel, a1);
        const fh = await d.getFileHandle(name, { create: !!a1 });
        const sh = await fh.createSyncAccessHandle();
        const id = nextId++; handles.set(id, { sh, rel });
        if (a1) { tombs.delete(String(rel).replace(/^\/+/, '').toLowerCase()); reportChange(rel); }
        return finish(id, sh.getSize());
      }
      case OP.READ: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        const b = new Uint8Array(a2);          // scratch: handle IO on SAB views is engine-dependent
        const n = h.sh.read(b, { at: a1 }); data.set(b.subarray(0, n), 0); return finish(n, 0); }
      case OP.WRITE: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        reportChange(h.rel);
        return finish(h.sh.write(data.slice(0, a2), { at: a1 }), 0); }
      case OP.TRUNC: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        h.sh.truncate(a1 >>> 0); reportChange(h.rel); return finish(0, 0); }
      case OP.CLOSE: { const h = handles.get(a0);
        if (h) { try { h.sh.flush(); h.sh.close(); } catch {} handles.delete(a0); } return finish(0, 0); }
      case OP.UNLINK: case OP.RMDIR: {       // in: path
        const rel = S(td.decode(data.slice(0, a0)));
        closeByRel(rel);
        // Deleting used to hydrate first ("removeEntry needs a real entry"), so `rm`
        // on a cloud-only file failed with the DOWNLOAD's error -- ENOENT if there was
        // no token -- and the file stayed in the listing. A delete needs no bytes:
        // drop the local copy if there is one, tombstone the path either way, and let
        // the page propagate the remote delete.
        if (op === OP.UNLINK) {
          tombs.add(String(rel).replace(/^\/+/, '').toLowerCase());
          let hadLocal = false;
          try { const { d, name } = await parentOf(rel); await d.removeEntry(name, { recursive: false }); hadLocal = true; }
          catch (e) { if (!(e && e.name === 'NotFoundError')) throw e; }
          if (!hadLocal) await loadIndex();          // so a cloud-only path is still "known"
          const known = hadLocal || !!idxEntry(rel);
          reportRemoved(rel);
          await loadModes(); dropModes(rel);
          return finish(known ? 0 : ENOENT, 0);
        }
        const { d, name } = await parentOf(rel);
        await d.removeEntry(name, { recursive: false });
        // Tombstone the dir AND everything the cloud index still knows under it --
        // otherwise the next listing resurrects the (now deleted) directory populated
        // with cloud-only children, the same lie UNLINK's tombstone already fixes for
        // plain files.
        await loadIndex();
        const lr = String(rel).replace(/^\/+/, '').toLowerCase();
        tombs.add(lr);
        for (const k of (idxByPath ? [...idxByPath.keys()] : []))
          if (k === lr || k.startsWith(lr + '/')) tombs.add(k);
        reportRemoved(rel);
        await loadModes(); dropModes(rel);
        return finish(0, 0);
      }
      case OP.SETMODE: {                     // in: path, a1 = mode bits (or -1 to forget)
        const rel = S(td.decode(data.slice(0, a0)));
        await loadModes(); setMode(rel, a1);
        return finish(0, 0);
      }
      case OP.MKDIR: {                       // in: path
        const mrel = S(td.decode(data.slice(0, a0)));
        // A segment that exists as a FILE made getDirectoryHandle(create:true) throw
        // TypeMismatchError, which the catch-all labelled EACCES ("Operation not
        // permitted") with no clue why. Name it: mkdir over an existing FILE is EEXIST.
        const segs = mrel.split('/').filter(Boolean);
        let md = root;
        for (let i = 0; i < segs.length; i++) {
          try { md = await md.getDirectoryHandle(segs[i]); }
          catch (e) {
            if (e && e.name === 'TypeMismatchError') return finish(EEXIST, 0);
            if (e && e.name === 'NotFoundError') {         // missing: create the rest
              for (let j = i; j < segs.length; j++) md = await md.getDirectoryHandle(segs[j], { create: true });
              return finish(0, 0);
            }
            throw e;
          }
        }
        return finish(0, 0);                 // already a directory: mkdir -p semantics
      }
      case OP.RENAME: {                      // in: old \0 new
        const [oldRel, newRel] = td.decode(data.slice(0, a0)).split('\0').map(S);
        closeByRel(oldRel); closeByRel(newRel);
        try { await hydrate(oldRel); } catch {}   // cannot move bytes that are still in the cloud
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
        if (typeof oh.move === 'function') {
          try { if (nd === od || (await nd.isSameEntry(od))) await oh.move(nn); else await oh.move(nd, nn); moved = true; } catch {}
        }
        if (!moved) {
          const buf = new Uint8Array(await (await oh.getFile()).arrayBuffer());
          const sh = await (await nd.getFileHandle(nn, { create: true })).createSyncAccessHandle();
          sh.truncate(0); sh.write(buf, { at: 0 }); sh.flush(); sh.close();   // flush: a run killed between write and removeEntry lost the copy
          await od.removeEntry(on);
        }
        reportChange(newRel); reportRemoved(oldRel);
        await loadModes(); moveModes(oldRel, newRel);
        return finish(0, 0);
      }
      case OP.RELEASE: {                     // end of run: flush + drop every lock
        for (const h of handles.values()) { try { h.sh.flush(); h.sh.close(); } catch {} }
        handles.clear(); return finish(0, 0);
      }
    }
    finish(EINVAL, 0);
  } catch (e) {
    // NEVER swallow silently: an unmapped exception used to become EACCES, which
    // busybox prints as "Operation not permitted" with zero clue about the cause.
    console.error('[opfs-worker] op', op, 'failed:', e);
    const n = e && e.name;
    // NoModificationAllowedError/InvalidStateError = another sync access handle holds
    // this file. In practice that is a PREVIOUS bridge worker the host abandoned (a
    // run killed on timeout: the kernel that would have sent RELEASE is dead, the
    // bridge is not) -- an EBUSY the kernel can name, not a generic EACCES.
    finish(n === 'NoModificationAllowedError' || n === 'InvalidStateError' ? EBUSY :
           n === 'NotFoundError' ? ENOENT :
           n === 'TypeMismatchError' ? EEXIST :      // a path segment exists as a FILE
           n === 'InvalidModificationError' ? ENOTEMPTY :
           n === 'QuotaExceededError' ? ENOSPC :
           EACCES, 0);
  }
}

self.onmessage = async (ev) => {
  // The cloud provider config for hydrating cloud-only files. Sent before the
  // initial 'sab' message and re-sendable at any time (an access token lives ~4h;
  // the app refreshes it and pushes the new config).
  if (ev.data.t === 'tombstones') {          // replayed by the page at boot
    for (const r of ev.data.rels || []) tombs.add(String(r).replace(/^\/+/, '').toLowerCase());
    return;
  }
  if (ev.data.t === 'cloud') { setCloud(ev.data.provider); return; }
  // Fire the pending change batch NOW instead of waiting out the 250ms debounce,
  // then ack. The walios() tool sends this on the guest's exit so every write is
  // reported (and attributed to the finishing run) before the tool result resolves.
  if (ev.data.t === 'flush') {
    if (changeTimer) { clearTimeout(changeTimer); changeTimer = null; }
    if (changed.size) { const rels = [...changed]; changed = new Set();
      try { self.postMessage({ t: 'opfs-changed', rels }); } catch {} }
    flushRemoved();
    try { self.postMessage({ t: 'flushed' }); } catch {}
    return;
  }
  if (ev.data.t !== 'sab') return;
  if (ev.data.provider) setCloud(ev.data.provider);
  scope = String(ev.data.scope || '').replace(/^\/+|\/+$/g, '');
  // No SharedArrayBuffer on the page (no cross-origin isolation): the kernel runs its
  // in-process engine and talks to this worker over a MessagePort instead (see
  // servePort); ctl/data are then private scratch the same handle() code writes to.
  const port = ev.data.port || null;
  if (!port) { ctl = new Int32Array(ev.data.sab, 0, 8); data = new Uint8Array(ev.data.sab, 32); }
  // No OPFS here (a browser without it, or a context that lacks it): say so and keep
  // serving -- every request is answered EIO -- rather than never answering. The kernel
  // parks on the SAB waiting for us; an unanswered request used to hang the guest forever.
  try { root = await navigator.storage.getDirectory(); }
  catch (e) { root = null; try { self.postMessage({ ready: false, error: 'OPFS unavailable: ' + ((e && e.message) || e) }); } catch {} }
  // Optional isolation: scope this mount to an OPFS subdir so a shell can't see or
  // delete the host app's OPFS data (same origin). terminal.html passes subdir.
  if (!root) { /* no store: fall through to the serve loop, which answers EIO */ }
  else if (ev.data.subdir) { for (const s of ev.data.subdir.split('/').filter(Boolean)) root = await root.getDirectoryHandle(s, { create: true }); }
  // (The legacy full-root mount used to plant a demo hello-from-opfs.txt at the workspace
  // root on every boot. It was clutter in the user's home, synced to their cloud; the
  // workspace check (organize.js) removes any left behind.)
  self.postMessage({ ready: true });
  if (port) { servePort(port); return; }
  let last = 0;
  // waitAsync, not the blocking wait: a blocking Atomics.wait parks this thread
  // between requests, and queued message events (notably a refreshed the cloud
  // token) would then never be dispatched -- the loop's own microtask
  // continuation always beats them to the thread. The guest is blocked on its own
  // Atomics.wait either way, so yielding here costs nothing.
  const canAsync = typeof Atomics.waitAsync === 'function';
  while (true) {
    if (canAsync) { const r = Atomics.waitAsync(ctl, 0, last); if (r.async) await r.value; }
    else Atomics.wait(ctl, 0, last);
    const seq = Atomics.load(ctl, 0); if (seq === last) continue; last = seq;
    await handle(ctl[2]);
  }
};
