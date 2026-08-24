// OPFS bridge worker: owns ALL OPFS handles so the (synchronous) OS worker can
// fault the tree in lazily over a SharedArrayBuffer — the riscv-vm ?p9lazy model.
// Spawned by the PAGE as a sibling of wali-worker (a nested worker would starve
// under its blocked parent). Sync access handles are exclusive locks, so one is
// opened only when a file is actually read/written, and released on unlink,
// RELEASE (end of run), or self-healed on a stale re-OPEN.
// SAB layout (same shape as the wisp bridge): Int32Array ctl at 0 —
// [0]=req seq, [1]=done seq, [2]=op, [3..5]=args, [6]=res, [7]=aux; data at 32.
'use strict';
const OP = { READDIR: 1, OPEN: 2, READ: 3, WRITE: 4, TRUNC: 5, CLOSE: 6, UNLINK: 7, MKDIR: 8, RMDIR: 9, RENAME: 10, RELEASE: 11 };
const ENOENT = -2, EBADF = -9, EACCES = -13, EINVAL = -22, ENOTEMPTY = -39;
const te = new TextEncoder(), td = new TextDecoder();
let ctl, data, root;
const handles = new Map(); let nextId = 1;   // id -> { sh, rel }

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

async function handle(op) {
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  try {
    switch (op) {
      case OP.READDIR: {                     // in: path — out: JSON [{n, d?} | {n, s, m}]
        const d = await walkDir(td.decode(data.slice(0, a0)));
        const out = [];
        for await (const [name, h] of d.entries()) {
          if (h.kind === 'directory') { out.push({ n: name, d: 1 }); continue; }
          // getFile() throws while another handle (the host app / Pyodide) holds an
          // exclusive sync-access lock on the file. Still list it (size unknown)
          // rather than aborting the whole directory on one locked entry.
          try { const f = await h.getFile(); out.push({ n: name, s: f.size, m: f.lastModified }); }
          catch { out.push({ n: name, s: 0, m: 0 }); }
        }
        const b = te.encode(JSON.stringify(out));
        if (b.length > data.length) return finish(EINVAL, 0);
        data.set(b, 0); return finish(b.length, 0);
      }
      case OP.OPEN: {                        // in: path, a1=create — out: res=id, aux=size
        const rel = td.decode(data.slice(0, a0));
        closeByRel(rel);                     // self-heal a handle leaked by a terminated OS worker
        const { d, name } = await parentOf(rel, a1);
        const fh = await d.getFileHandle(name, { create: !!a1 });
        const sh = await fh.createSyncAccessHandle();
        const id = nextId++; handles.set(id, { sh, rel });
        return finish(id, sh.getSize());
      }
      case OP.READ: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        const b = new Uint8Array(a2);          // scratch: handle IO on SAB views is engine-dependent
        const n = h.sh.read(b, { at: a1 }); data.set(b.subarray(0, n), 0); return finish(n, 0); }
      case OP.WRITE: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        return finish(h.sh.write(data.slice(0, a2), { at: a1 }), 0); }
      case OP.TRUNC: { const h = handles.get(a0); if (!h) return finish(EBADF, 0);
        h.sh.truncate(a1 >>> 0); return finish(0, 0); }
      case OP.CLOSE: { const h = handles.get(a0);
        if (h) { try { h.sh.flush(); h.sh.close(); } catch {} handles.delete(a0); } return finish(0, 0); }
      case OP.UNLINK: case OP.RMDIR: {       // in: path
        const rel = td.decode(data.slice(0, a0));
        closeByRel(rel);
        const { d, name } = await parentOf(rel);
        await d.removeEntry(name, { recursive: false });
        return finish(0, 0);
      }
      case OP.MKDIR: {                       // in: path
        await walkDir(td.decode(data.slice(0, a0)), true);
        return finish(0, 0);
      }
      case OP.RENAME: {                      // in: old \0 new (copy + delete: portable, unlike move())
        const [oldRel, newRel] = td.decode(data.slice(0, a0)).split('\0');
        closeByRel(oldRel); closeByRel(newRel);
        const { d: od, name: on } = await parentOf(oldRel);
        const buf = new Uint8Array(await (await (await od.getFileHandle(on)).getFile()).arrayBuffer());
        const { d: nd, name: nn } = await parentOf(newRel, 1);
        const sh = await (await nd.getFileHandle(nn, { create: true })).createSyncAccessHandle();
        sh.truncate(0); sh.write(buf, { at: 0 }); sh.close();
        await od.removeEntry(on);
        return finish(0, 0);
      }
      case OP.RELEASE: {                     // end of run: flush + drop every lock
        for (const h of handles.values()) { try { h.sh.flush(); h.sh.close(); } catch {} }
        handles.clear(); return finish(0, 0);
      }
    }
    finish(EINVAL, 0);
  } catch (e) {
    finish(e && e.name === 'NotFoundError' ? ENOENT :
           e && e.name === 'InvalidModificationError' ? ENOTEMPTY : EACCES, 0);
  }
}

self.onmessage = async (ev) => {
  if (ev.data.t !== 'sab') return;
  ctl = new Int32Array(ev.data.sab, 0, 8); data = new Uint8Array(ev.data.sab, 32);
  root = await navigator.storage.getDirectory();
  // Optional isolation: scope this mount to an OPFS subdir so a shell can't see or
  // delete the host app's OPFS data (same origin). terminal.html passes subdir.
  if (ev.data.subdir) { for (const s of ev.data.subdir.split('/').filter(Boolean)) root = await root.getDirectoryHandle(s, { create: true }); }
  else try { // legacy full-root mount: keep the demo seed the eager mount used to plant
    const sh = await (await root.getFileHandle('hello-from-opfs.txt', { create: true })).createSyncAccessHandle();
    if (sh.getSize() === 0) sh.write(te.encode('greetings from real OPFS storage\n'), { at: 0 });
    sh.close();
  } catch {}
  self.postMessage({ ready: true });
  let last = 0;
  while (true) {
    Atomics.wait(ctl, 0, last);
    const seq = Atomics.load(ctl, 0); if (seq === last) continue; last = seq;
    await handle(ctl[2]);
  }
};
