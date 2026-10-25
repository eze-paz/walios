// One walios process, running on its own thread.
//
// This is the guest half of the worker-per-process model. The kernel (wali-worker.js)
// keeps every syscall implementation, the VFS, the process table and the ptys; this file
// only instantiates the module and turns each host import into a synchronous request on
// a SharedArrayBuffer: store the args, flip the state word, Atomics.wait for the reply.
//
// Why this exists: the kernel used to run a forked child INLINE, depth-first, so two
// processes could never interleave. `busybox yes hello | busybox head -c 1000000` hung
// forever because the producer had to finish before the consumer started, and pipes are
// unbounded so it never did. Parking the guest on its OWN thread means a blocked process
// blocks nothing else, and processes run in parallel instead of interleaving on a single
// thread.
//
// The kernel can read and write this process's linear memory directly because every
// guest is built with a SHARED memory: WALI binaries export one (busybox initial=129,
// python initial=311, max 32768 pages), wasm32-wasi-threads binaries (qjs, rustc) import
// one the kernel creates. Either way `memory.buffer` is a SharedArrayBuffer that travels
// to the kernel by postMessage. A module with a private memory is refused: the kernel
// could not see a single pointer argument. This is the ONLY process model; the older
// in-kernel engines and the separate wasi-threads proxy are gone.
//
// Control block layout (ctl), matching KCTL in wali-worker.js:
//   i32[0]  state: 0 idle, 1 request pending, 2 reply ready, 3 guest finished
//   i32[1]  import index into `names`
//   i32[2]  argc
//   i32[3]  exit code, when state is 3
//   i64[ARGS/8 + k]  argument k  (byte offset 64, 16 slots -- WASI path_open takes 9)
//   i64[RET/8]       return value (byte offset 192)
'use strict';

const ARGS = 64, RET = 192, MAXARGS = 16;
const ST_IDLE = 0, ST_REQ = 1, ST_REPLY = 2, ST_DONE = 3, ST_DIE = 4, ST_FORKED = 5;
const ST_SIGNAL = 6, ST_SIGDONE = 7;
const ASYNC_PAGES = 16, PAGE = 65536;   // 1MB Asyncify unwind buffer, as in the kernel

let inst = null, ctl = null, i32 = null, i64 = null, names = null, sigs = null;
let forkIdx = -1;                  // index of wali.SYS_fork, handled entirely in here
let bulk = null, bulkOp = -1;      // staging buffer + kernel op for reading a .so
let waliBag = null;                // the proxy imports, re-offered to side modules
const dlHandles = [];
let forkState = 'none', forkRet = 0n, asyncifyBuf = 0;

// Thrown when the kernel says this process is finished; unwinds the guest out of _start.
class ProcExit { constructor(code) { this.code = code; } }

// A host call. The kernel is on another thread with its own event loop, so it can serve
// this while other processes run; we just block until the reply lands.
function hostCall(idx, args) {
  const n = Math.min(args.length, MAXARGS);
  // Loud, not silent: a dropped argument is a pointer the kernel never sees.
  if (args.length > MAXARGS && !warned.has('argc:' + idx)) { warned.add('argc:' + idx); warn('import ' + names[idx] + ' passes ' + args.length + ' args; only ' + MAXARGS + ' fit the control block'); }
  for (let k = 0; k < n; k++) {
    const a = args[k];
    i64[(ARGS >> 3) + k] = (typeof a === 'bigint') ? a : BigInt(Math.trunc(a));
  }
  Atomics.store(i32, 2, n);
  Atomics.store(i32, 1, idx);
  Atomics.store(i32, 0, ST_REQ);
  Atomics.notify(i32, 0);
  for (;;) {
    const st = Atomics.load(i32, 0);
    if (st === ST_REPLY) break;
    // The kernel answers DIE for exit/exit_group/__proc_exit: those calls must never
    // return to the guest, and the kernel can no longer unwind our stack for us.
    if (st === ST_DIE) throw new ProcExit(Atomics.load(i32, 3) & 0xff);
    // SIGNAL: run a signal handler here, because the indirect function table is ours.
    // The handler makes its OWN host calls, which reuse this control block -- so the
    // in-flight request has to be saved and put back before we resume waiting for it.
    if (st === ST_SIGNAL) {
      const sPtr = Atomics.load(i32, 4), sNo = Atomics.load(i32, 5);
      const sIdx = Atomics.load(i32, 1), sArgc = Atomics.load(i32, 2);
      const saved = []; for (let k = 0; k < MAXARGS; k++) saved.push(i64[(ARGS >> 3) + k]);
      try {
        const table = inst.exports.__indirect_function_table;
        if (table) table.get(sPtr)(sNo);
        else if (!warned.has('notable')) { warned.add('notable'); warn('signal ' + sNo + ' handler requested but this binary has no __indirect_function_table export (link with -Wl,--export-table)'); }
      } finally {
        for (let k = 0; k < MAXARGS; k++) i64[(ARGS >> 3) + k] = saved[k];
        Atomics.store(i32, 2, sArgc);
        Atomics.store(i32, 1, sIdx);
        // The handler may not RETURN at all: busybox ping's SIGINT handler prints its
        // statistics and calls exit(), and the kernel answers that exit with DIE, which
        // unwinds us through here. Storing SIGDONE over it told the kernel the handler
        // had simply come back, so the process's death was lost -- the kernel went on
        // serving a guest that was already unwinding, the parent's wait4 was never
        // satisfied, and an interactive shell never printed another prompt after ^C.
        // `sleep` hid it: with no handler the signal takes the default action and never
        // comes through this path at all.
        if (Atomics.load(i32, 0) !== ST_DIE) Atomics.store(i32, 0, ST_SIGDONE);
        Atomics.notify(i32, 0);
      }
      continue;
    }
    Atomics.wait(i32, 0, st);
  }
  const ret = i64[RET >> 3];
  Atomics.store(i32, 0, ST_IDLE);
  return ret;
}

// dlopen has to run HERE. It reaches into the instance for the memory, the indirect
// function table, __stack_pointer and every symbol the main module exports, and links a
// side module against them -- none of which the kernel can see any more. Only the two
// things it does NOT have travel over the wire: the .so bytes (staged into a shared
// buffer by the kernel, because a parked thread cannot receive a postMessage) and the
// path resolution, which is the kernel's VFS.

function parseDylink(mod) {                       // dylink.0 MEM_INFO: memsize/align/tablesize
  const info = { memsize: 0, memalign: 0, tablesize: 0, tablealign: 0 };
  const secs = WebAssembly.Module.customSections(mod, 'dylink.0');
  if (!secs.length) return info;
  const b = new Uint8Array(secs[0]); let p = 0;
  const uleb = () => { let r = 0, s = 0, x; do { x = b[p++]; r |= (x & 0x7f) << s; s += 7; } while (x & 0x80); return r >>> 0; };
  while (p < b.length) {
    const id = b[p++], len = uleb(), end = p + len;
    if (id === 1) { info.memsize = uleb(); info.memalign = uleb(); info.tablesize = uleb(); info.tablealign = uleb(); }
    p = end;
  }
  return info;
}

function cstr(ptr) {
  const u8 = new Uint8Array(inst.exports.memory.buffer);
  let e = ptr; while (u8[e]) e++;
  return new TextDecoder().decode(u8.slice(ptr, e));
}

function funcIdx(fn) {
  if (typeof fn !== 'function') return 0;
  const table = inst.exports.__indirect_function_table;
  const idx = table.length; table.grow(1); table.set(idx, fn); return idx;
}

function warn(msg) { try { self.postMessage({ t: 'warn', s: msg }); } catch (_) {} }
const warned = new Set();

function dlopen(pathPtr) {
  let ph = 'read';
  const guestPath = cstr(pathPtr);
  try {
    // The kernel resolves the path, faults it in from OPFS if needed, and stages the
    // bytes in the shared staging buffer. It grows that buffer to fit, so read its
    // length back rather than assuming.
    const size = Number(hostCall(bulkOp, [pathPtr]));
    if (size < 0) throw new Error('not found: ' + guestPath);
    ph = 'compile';
    // WebAssembly.Module refuses a SharedArrayBuffer-backed view (same refusal as
    // TextDecoder), so copy into a plain one first.
    const bytes = new Uint8Array(size);
    bytes.set(new Uint8Array(bulk, 0, size));
    const mod = new WebAssembly.Module(bytes);
    const info = parseDylink(mod);
    const exp = inst.exports, table = exp.__indirect_function_table;
    let memBase = 0;
    if (info.memsize > 0) {
      // Take the region by growing linear memory, exactly as the host's mmap does, and
      // honour the module's data alignment (malloc only guarantees 16B, SIMD statics want more).
      ph = 'grow';
      const align = 1 << (info.memalign || 0);
      const raw = exp.memory.buffer.byteLength;
      exp.memory.grow(Math.ceil((info.memsize + align) / PAGE));
      memBase = align > 1 ? ((raw + align - 1) & ~(align - 1)) : raw;
      new Uint8Array(exp.memory.buffer).fill(0, memBase, memBase + info.memsize);
    }
    const tableBase = table.length;
    if (info.tablesize > 0) table.grow(info.tablesize);
    const Gi = (v) => new WebAssembly.Global({ value: 'i32', mutable: false }, v >>> 0);
    const BASE = new Set(['memory', '__indirect_function_table', '__stack_pointer', '__memory_base', '__table_base']);
    const env = { memory: exp.memory, __indirect_function_table: table, __stack_pointer: exp.__stack_pointer,
                  __memory_base: Gi(memBase), __table_base: Gi(tableBase) };
    const gotMem = {}, gotFunc = {};
    let sideInst = null;
    for (const im of WebAssembly.Module.imports(mod)) {
      if (im.module === 'env') {
        if (BASE.has(im.name)) continue;
        const sym = exp[im.name];
        if (sym === undefined && !warned.has(im.name)) { warned.add(im.name); warn('dlopen: unresolved env.' + im.name); }
        // Self-resolving trampoline: a symbol the main does not export may still be
        // DEFINED BY THIS .so (libc++ weak template instantiations are imported AND
        // exported by the same module). Resolve at call time to this module's export,
        // then any other loaded one, else throw loudly -- binding ()=>0 corrupts silently.
        env[im.name] = (sym !== undefined) ? sym : ((...a) => {
          const own = sideInst && sideInst.exports[im.name];
          if (typeof own === 'function') return own(...a);
          const alt = dlHandles.map((h) => h.inst.exports[im.name]).find((f) => typeof f === 'function');
          if (alt) return alt(...a);
          throw new Error('unresolved dynamic fn: ' + im.name);
        });
      } else if (im.module === 'GOT.mem') {
        const sym = exp[im.name];
        gotMem[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true },
                                                 (sym && sym.value !== undefined) ? sym.value : Number(sym || 0));
      } else if (im.module === 'GOT.func') {
        gotFunc[im.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, funcIdx(exp[im.name]));
      }
    }
    const waliProxy = new Proxy(waliBag || {}, { get: (t, n) => t[n] || (typeof n !== 'string' ? undefined
                                : (() => { throw new Error('unresolved wali import from side module: ' + n); })) });
    ph = 'instantiate';
    sideInst = new WebAssembly.Instance(mod, { env, wali: waliProxy, 'GOT.mem': gotMem, 'GOT.func': gotFunc });
    // GOT back-fill BEFORE the relocs: __wasm_apply_data_relocs bakes GOT values into
    // memory (PyMethodDef ml_meth pointers, type slots), so a 0 left here becomes a
    // permanent null function pointer and the first call_indirect traps.
    for (const k in gotMem) { const e = sideInst.exports[k]; if (e && e.value !== undefined) gotMem[k].value = memBase + e.value; }
    for (const k in gotFunc) { if (gotFunc[k].value === 0) { const e = sideInst.exports[k]; if (typeof e === 'function') gotFunc[k].value = funcIdx(e); } }
    ph = 'apply_data_relocs';
    if (sideInst.exports.__wasm_apply_data_relocs) sideInst.exports.__wasm_apply_data_relocs();
    ph = 'call_ctors';
    if (sideInst.exports.__wasm_call_ctors) sideInst.exports.__wasm_call_ctors();
    dlHandles.push({ inst: sideInst, symCache: new Map() });
    return dlHandles.length - 1;
  } catch (e) {
    warn('dlopen(' + guestPath + ') failed at [' + ph + ']: ' + ((e && e.message) || e));
    return -1;
  }
}

function dlsym(handle, symPtr) {
  const h = dlHandles[handle]; if (!h) return -1;
  const sym = cstr(symPtr);
  if (h.symCache.has(sym)) return h.symCache.get(sym);
  const fn = h.inst.exports[sym]; if (typeof fn !== 'function') return -1;
  const idx = funcIdx(fn); h.symCache.set(sym, idx); return idx;
}

self.onmessage = async (ev) => {
  const m = ev.data;

  if (m.t === 'init') {
    ctl = m.ctl; names = m.names; sigs = m.sigs; bulk = m.bulk;
    bulkOp = names.indexOf('@.dlbytes');
    i32 = new Int32Array(ctl);
    i64 = new BigInt64Array(ctl);
    const imports = {};
    for (let i = 0; i < names.length; i++) {
      const full = names[i], dot = full.indexOf('.');
      const mod = full.slice(0, dot), nm = full.slice(dot + 1), idx = i;
      const sig = sigs[i];                       // 0 = returns i32/void, 1 = returns i64
      imports[mod] = imports[mod] || {};
      // The result type MUST match what the module declared: an i64 result needs a
      // BigInt back and an i32 result needs a Number, or the call traps at the
      // boundary. WALI is not uniform about this (SYS_* return i64, __cl_get_argc and
      // friends return i32), which is why the kernel ships a per-import signature.
      if (full === 'env.__wali_dlopen') { imports[mod][nm] = (p) => dlopen(Number(p)); continue; }
      if (full === 'env.__wali_dlsym') { imports[mod][nm] = (h, sp) => dlsym(Number(h), Number(sp)); continue; }
      if (full.startsWith('@.')) continue;             // kernel-only op, not a wasm import
      if (nm === 'SYS_fork' && WebAssembly.Module.exports(m.mod).some((e) => e.name === 'asyncify_start_unwind')) {
        // fork() has to unwind the calling stack, and the stack lives here now -- so the
        // Asyncify half runs locally and the kernel is only asked for a pid once the
        // unwind is complete (see the ST_FORKED handshake in run()). A binary WITHOUT
        // Asyncify falls through to the ordinary host call: its libc fork() is the
        // vfork protocol (child branch runs here, execve answers CHILD_DONE and longjmps
        // back), which the kernel serves like any other syscall. Before this check every
        // such binary trapped on asyncify_start_unwind -- python's subprocess exited 139
        // and git could not start its remote helper.
        forkIdx = idx;
        imports[mod][nm] = () => {
          if (forkState === 'rewinding') { inst.exports.asyncify_stop_rewind(); forkState = 'none'; return forkRet; }
          if (!asyncifyBuf) { const old = inst.exports.memory.buffer.byteLength; inst.exports.memory.grow(ASYNC_PAGES); asyncifyBuf = old; }
          const d = new DataView(inst.exports.memory.buffer);
          d.setUint32(asyncifyBuf, asyncifyBuf + 8, true);
          d.setUint32(asyncifyBuf + 4, asyncifyBuf + ASYNC_PAGES * PAGE, true);
          inst.exports.asyncify_start_unwind(asyncifyBuf);
          forkState = 'unwinding';
          return 0n;
        };
        continue;
      }
      if (nm === '__proc_exit') {
        imports[mod][nm] = (code) => { hostCall(idx, [code]); throw new ProcExit(Number(code) & 0xff); };
      } else if (sig === 1) {
        imports[mod][nm] = (...a) => hostCall(idx, a);
      } else {
        imports[mod][nm] = (...a) => Number(hostCall(idx, a));
      }
    }
    waliBag = imports.wali || (imports.wali = {});
    // C99 floating-point environment. numpy's _multiarray_umath/_simd/_umath_linalg
    // import these but the MAIN does not, so they arrive ONLY through the side-module
    // proxy and are absent from the import list this stub was given. wasm exposes no FP
    // status register, so 0 is the correct answer, not a stub: fetestexcept -> no flags
    // raised, feraiseexcept -> nothing to raise. (Same reasoning as the kernel's copy.)
    if (!waliBag.fetestexcept) waliBag.fetestexcept = () => 0;
    if (!waliBag.feraiseexcept) waliBag.feraiseexcept = () => 0;
    // A wasm32-wasi-threads build (qjs, rustc) IMPORTS its memory; the kernel created the
    // shared memory and sent it along. (Its `wasi.thread-spawn` import needs nothing
    // special here: it is proxied like every other import, and the kernel answers it by
    // starting another worker of this same script in thread mode -- see 'run' below.)
    if (m.memory) (imports.env = imports.env || {}).memory = m.memory;
    try {
      inst = await WebAssembly.instantiate(m.mod, imports);
    } catch (e) {
      self.postMessage({ t: 'ready', ok: false, error: String((e && e.stack) || e) });
      return;
    }
    const memory = inst.exports.memory || m.memory;
    if (!memory || !(memory.buffer instanceof SharedArrayBuffer)) {
      // Without a shared memory the kernel cannot see this process at all, and every
      // pointer argument would be meaningless. Fail loudly rather than corrupt.
      self.postMessage({ t: 'ready', ok: false,
                         error: 'module memory is not shared; the kernel cannot map it' });
      return;
    }
    self.postMessage({ t: 'ready', ok: true, memory });
    return;
  }

  if (m.t === 'rewind') {
    // We are a forked child: our memory is a byte copy of the parent's, taken while it
    // was unwound, so replaying from its Asyncify buffer lands us right after its fork().
    asyncifyBuf = m.asyncifyBuf; forkRet = 0n; forkState = 'rewinding';
    if (m.sp >= 0 && inst.exports.__stack_pointer) inst.exports.__stack_pointer.value = m.sp;   // see the ST_FORKED handshake in drive()
    if (m.tls >= 0 && inst.exports.__tls_base) inst.exports.__tls_base.value = m.tls;
    else if (m.sp >= 0 && !inst.exports.__stack_pointer && !warned.has('nosp')) { warned.add('nosp'); warn('fork: this binary does not export __stack_pointer; the child runs with the initial stack pointer (relink with -Wl,--export=__stack_pointer)'); }
    inst.exports.asyncify_start_rewind(asyncifyBuf);
    drive();
    return;
  }

  if (m.t === 'run') { if (m.mode === 'thread') driveThread(m.entry || 'wasi_thread_start', m.tid, m.startArg); else drive(); }
};

// This worker is ONE THREAD of a process whose main thread runs on another worker over
// the same shared memory. `entry` is the module's thread trampoline -- wasi-threads
// exports wasi_thread_start, wali-musl exports __wasm_thread_start_libc; both take
// (tid, start_arg), set up __stack_pointer/__tls_base from start_arg and run the user
// function. Run it to completion; fork/exec from a thread is not a thing, so none of
// drive()'s protocol applies.
function driveThread(entry, tid, startArg) {
  let code = 0;
  try { inst.exports[entry](tid, startArg); }
  catch (e) {
    if (e instanceof ProcExit) code = e.code;
    else { code = 139; self.postMessage({ t: 'trap', error: String((e && e.stack) || e).slice(0, 400) }); }
  }
  finish(code);
}

// Run the guest until it exits, servicing every fork() unwind on the way.
function drive() {
  let code = 0;
  try {
    for (;;) {
      inst.exports._start();
      if (forkState !== 'unwinding') break;
      inst.exports.asyncify_stop_unwind();
      // Ask the kernel to build the child. It replies with the pid once the child worker
      // is up and our memory has been copied into it -- so the snapshot is taken while
      // we are still unwound, which is what makes it a fork rather than a race.
      i64[RET >> 3] = BigInt(asyncifyBuf);
      // The child rewinds on a FRESH instance whose __stack_pointer / __tls_base globals
      // hold their initial values (empty stack), while the memory copy it replays over has
      // our frames at OUR stack pointer. Rewinding skips prologues, so nothing in the child
      // would ever set them: its next call would allocate a frame at the top of the stack,
      // on top of the frames it inherited (busybox `timeout`: kill(parent) saw parent=0).
      // Hand the values over; the kernel forwards them in the 'rewind' message.
      const spg = inst.exports.__stack_pointer, tlsg = inst.exports.__tls_base;
      i64[(ARGS >> 3) + 0] = spg ? BigInt(spg.value) : -1n;
      i64[(ARGS >> 3) + 1] = tlsg ? BigInt(tlsg.value) : -1n;
      Atomics.store(i32, 0, ST_FORKED);
      Atomics.notify(i32, 0);
      for (;;) { const st = Atomics.load(i32, 0);
        if (st === ST_REPLY) break;
        if (st === ST_DIE) { code = Atomics.load(i32, 3) & 0xff; Atomics.store(i32, 0, ST_IDLE); return finish(code); }
        Atomics.wait(i32, 0, st); }
      forkRet = i64[RET >> 3];
      Atomics.store(i32, 0, ST_IDLE);
      forkState = 'rewinding';
      inst.exports.asyncify_start_rewind(asyncifyBuf);
    }
  } catch (e) {
    if (e instanceof ProcExit) code = e.code;
    else { code = 139; self.postMessage({ t: 'trap', error: String((e && e.stack) || e).slice(0, 400) }); }
  }
  finish(code);
}

function finish(code) {
  Atomics.store(i32, 3, code | 0);
  Atomics.store(i32, 0, ST_DONE);
  Atomics.notify(i32, 0);
  self.postMessage({ t: 'exit', code });
}
