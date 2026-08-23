// JSPI proof: can a blocking syscall SUSPEND a WALI wasm process (yield to the
// event loop) and RESUME it when data arrives? If yes, we can build a concurrent
// scheduler where blocking processes let others run. Run:
//   node --experimental-wasm-jspi jspi-proto.mjs
import { readFileSync } from 'fs';
const mod = new WebAssembly.Module(readFileSync('/tmp/readln.wasm'));

let memory, u8;
const refresh = () => { u8 = new Uint8Array(memory.buffer); };
let brk = 0;
let otherRan = false;

// stdin that arrives late: read() suspends until this resolves
let deliver;
const stdinReady = new Promise(r => (deliver = r));

const wali = new Proxy({}, { get(_, name) {
  if (name === '__init' || name === '__deinit' || name === '__get_init_envfile') return () => 0;
  if (name === '__cl_get_argc') return () => 1;
  if (name === '__cl_get_argv_len') return () => 4;
  if (name === '__cl_copy_argv') return (buf) => { refresh(); u8.set(new TextEncoder().encode('prog'), buf); u8[buf + 4] = 0; return 4; };
  if (name === '__proc_exit') return () => { throw { exit: 0 }; };
  if (name === 'setjmp' || name === 'sigsetjmp' || name === '_setjmp') return () => 0;
  if (name === 'longjmp' || name === 'siglongjmp' || name === '_longjmp') return () => { throw new Error('longjmp'); };
  if (name === 'SYS_brk') return (a) => { refresh(); if (!brk) brk = memory.buffer.byteLength; return BigInt((a === 0 || a <= brk) ? brk : -12); };
  if (name === 'SYS_mmap') return (addr, len) => { refresh(); const base = memory.buffer.byteLength; memory.grow(Math.ceil(Number(len) / 65536)); refresh(); return BigInt(base); };
  if (name === 'SYS_write') return (fd, ptr, len) => { refresh(); process.stdout.write(Buffer.from(u8.slice(ptr, ptr + len))); return BigInt(len); };
  if (name === 'SYS_writev') return (fd, iov, n) => { refresh(); const dv = new DataView(memory.buffer); let tot = 0; for (let i = 0; i < n; i++) { const p = dv.getInt32(iov + i * 8, true), l = dv.getInt32(iov + i * 8 + 4, true); if (l) { process.stdout.write(Buffer.from(u8.slice(p, p + l))); tot += l; } } return BigInt(tot); };
  if (name === 'SYS_exit_group' || name === 'SYS_exit') return () => { throw { exit: 0 }; };
  // THE BLOCKING SYSCALL: read suspends (async import) until stdin arrives
  if (name === 'SYS_read') return new WebAssembly.Suspending(async (fd, ptr, len) => {
    if (fd !== 0) return -9n;
    console.log('  [read] no data yet -> SUSPENDING (yielding to event loop)');
    const data = await stdinReady;                // <-- wasm suspends here
    console.log('  [read] data arrived -> RESUMING');
    refresh(); const b = new TextEncoder().encode(data); const k = Math.min(b.length, Number(len)); u8.set(b.subarray(0, k), ptr); return BigInt(k);
  });
  if (typeof name === 'string' && name.startsWith('SYS_')) return () => 0n;
  return () => 0;
}});

const inst = new WebAssembly.Instance(mod, { wali });
memory = inst.exports.memory; refresh();

// prove the event loop ran WHILE the wasm was suspended in read()
setTimeout(() => { otherRan = true; console.log('  [scheduler] another task ran while process was suspended'); deliver('hello from the event loop\n'); }, 300);

const start = WebAssembly.promising(inst.exports._start);
try { await start(); } catch (e) { if (!e || e.exit === undefined) console.log('trap:', e); }
console.log(otherRan ? 'RESULT: concurrency works — process suspended, scheduler ran, then it resumed'
                     : 'RESULT: no suspension happened (ran straight through)');
