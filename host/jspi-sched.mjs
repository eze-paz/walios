// Concurrent scheduler proof: two REAL WALI processes connected by a BOUNDED pipe,
// run concurrently via JSPI. The pipe is tiny (12 bytes) so the writer MUST block
// when it's full -> suspends -> scheduler runs the reader -> reader drains ->
// writer resumes. If they interleave without deadlock, the scheduler works.
//   node --experimental-wasm-jspi jspi-sched.mjs
import { readFileSync } from 'fs';

const CAP = 4;                        // < one line (7B): every write blocks partway => both suspend paths fire
const trace = [];

// ---- a bounded pipe with JSPI-suspending read/write ----
function makePipe() {
  let buf = [];                       // bytes in flight
  let closed = false;                 // write end closed
  let wReady = null, rReady = null;   // resolvers for space / data
  const spaceAvail = () => new Promise(r => (wReady = r));
  const dataAvail  = () => new Promise(r => (rReady = r));
  const wakeR = () => { if (rReady) { const r = rReady; rReady = null; r(); } };
  const wakeW = () => { if (wReady) { const w = wReady; wReady = null; w(); } };
  return {
    async write(bytes) {
      let off = 0;
      while (off < bytes.length) {
        while (buf.length >= CAP && !closed) { trace.push('W blocks (pipe full)'); await spaceAvail(); }
        const room = CAP - buf.length;
        const chunk = bytes.slice(off, off + room);
        for (const b of chunk) buf.push(b);
        off += chunk.length;
        wakeR();
      }
      return bytes.length;
    },
    async read(max) {
      while (buf.length === 0 && !closed) { trace.push('R blocks (pipe empty)'); await dataAvail(); }
      if (buf.length === 0 && closed) return [];          // EOF
      const out = buf.splice(0, Math.min(max, buf.length));
      wakeW();
      return out;
    },
    closeWrite() { closed = true; wakeR(); },
  };
}

// ---- minimal WALI host for one process; fd table maps to pipe ends / stdout ----
function runProc(wasmPath, name, fds) {
  const mod = new WebAssembly.Module(readFileSync(wasmPath));
  let memory, u8; const refresh = () => { u8 = new Uint8Array(memory.buffer); };
  let brk = 0;
  const argv0 = name;

  const enc = new TextEncoder();
  const wali = new Proxy({}, { get(_, n) {
    if (n === '__init' || n === '__deinit' || n === '__get_init_envfile') return () => 0;
    if (n === '__cl_get_argc') return () => 1;
    if (n === '__cl_get_argv_len') return () => argv0.length;
    if (n === '__cl_copy_argv') return (buf) => { refresh(); u8.set(enc.encode(argv0), buf); u8[buf + argv0.length] = 0; return argv0.length; };
    if (n === '__proc_exit' || n === 'SYS_exit' || n === 'SYS_exit_group') return () => { throw { exit: 0 }; };
    if (n === 'setjmp' || n === 'sigsetjmp' || n === '_setjmp') return () => 0;
    if (n === 'longjmp' || n === 'siglongjmp' || n === '_longjmp') return () => { throw new Error('longjmp'); };
    if (n === 'SYS_brk') return (a) => { refresh(); if (!brk) brk = memory.buffer.byteLength; return BigInt((a === 0 || a <= brk) ? brk : -12); };
    if (n === 'SYS_mmap') return (addr, len) => { const base = memory.buffer.byteLength; memory.grow(Math.ceil(Number(len) / 65536)); refresh(); return BigInt(base); };
    // WRITE: suspends if the target pipe is full
    if (n === 'SYS_write') return new WebAssembly.Suspending(async (fd, ptr, len) => {
      refresh(); const bytes = Array.from(u8.slice(Number(ptr), Number(ptr) + Number(len)));
      const dst = fds[Number(fd)];
      if (dst === 'stdout') { process.stdout.write('  [' + name + '] ' + Buffer.from(bytes).toString().trimEnd() + '\n'); return BigInt(len); }
      if (dst && dst.write) { await dst.write(bytes); await new Promise(r => setTimeout(r, 5)); return BigInt(len); } // yield: let reader outrun us -> it blocks on empty
      return BigInt(len);
    });
    // READ: suspends if the source pipe is empty (until data or EOF)
    if (n === 'SYS_read') return new WebAssembly.Suspending(async (fd, ptr, len) => {
      const src = fds[Number(fd)];
      if (src && src.read) { const got = await src.read(Number(len)); refresh(); u8.set(got, Number(ptr)); return BigInt(got.length); }
      return 0n;
    });
    if (typeof n === 'string' && n.startsWith('SYS_')) return () => 0n;
    return () => 0;
  }});

  const inst = new WebAssembly.Instance(mod, { wali });
  memory = inst.exports.memory; refresh();
  const start = WebAssembly.promising(inst.exports._start);
  return start().catch(e => { if (!e || e.exit === undefined) throw e; });
}

// ---- wire: writer.stdout(1) -> pipe -> reader.stdin(0); reader.stdout(1) -> real stdout ----
const pipe = makePipe();
console.log('running writer | reader  (pipe capacity =', CAP, 'bytes, forces interleave)\n');

const writerDone = runProc('/tmp/writer.wasm', 'writer', { 1: pipe }).then(() => { pipe.closeWrite(); trace.push('writer exited -> EOF'); });
const readerDone = runProc('/tmp/reader.wasm', 'reader', { 0: pipe, 1: 'stdout' });

await Promise.all([writerDone, readerDone]);

console.log('\n--- scheduler trace (proves both ran concurrently, neither deadlocked) ---');
for (const t of trace) console.log('  ' + t);
const blockedW = trace.some(t => t.startsWith('W blocks'));
const blockedR = trace.some(t => t.startsWith('R blocks'));
console.log('\nRESULT:', (blockedW && blockedR)
  ? 'CONCURRENT SCHEDULER WORKS — writer suspended on full pipe AND reader suspended on empty pipe; they interleaved to completion.'
  : 'ran but did not exercise both suspend paths');
