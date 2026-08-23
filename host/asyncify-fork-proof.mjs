// Proof: concurrent fork-WITHOUT-exec via Asyncify — the substrate the JSPI
// scheduler can't provide (JSPI can't clone a live stack). At fork we UNWIND the
// call stack into linear memory, COPY the whole memory into a fresh instance, then
// REWIND both instances back to the fork point (parent gets pid, child gets 0) and
// schedule them concurrently. A yield point interleaves them; each keeps its own
// `base` — proving the memories are independent copies, not shared.
//   node asyncify-fork-proof.mjs
import { readFileSync } from 'fs';
const bytes = readFileSync('/tmp/forkproof.async.wasm');
const mod = new WebAssembly.Module(bytes);

let BUF = 0;                   // asyncify stack buffer address (from the module's static asyncbuf)
const STACK = 0x40000 - 8;     // 256KB region minus the 8-byte control struct
const PAGES = 4194304 / 65536; // matches --initial/max-memory

let nextPid = 100;
const out = [];
const ready = [];              // scheduler run queue of processes

function newProc(tag, pid, memToCopy) {
  const proc = { tag, pid, phase: 'run', pendingOp: null, forkRet: 0, done: false };
  const armBuf = () => { const d = new DataView(proc.memory.buffer); d.setUint32(BUF, BUF + 8, true); d.setUint32(BUF + 4, BUF + 8 + STACK, true); };
  const imports = { env: {
    print_num: (x) => out.push(`${proc.tag}: ${x}`),
    sched_fork: () => {
      if (proc.phase === 'rewind') { proc.inst.exports.asyncify_stop_rewind(); proc.phase = 'run'; return proc.forkRet; }
      armBuf(); proc.inst.exports.asyncify_start_unwind(BUF); proc.phase = 'unwind'; proc.pendingOp = 'fork'; return 0;
    },
    sched_yield0: () => {
      if (proc.phase === 'rewind') { proc.inst.exports.asyncify_stop_rewind(); proc.phase = 'run'; return; }
      armBuf(); proc.inst.exports.asyncify_start_unwind(BUF); proc.phase = 'unwind'; proc.pendingOp = 'yield'; return;
    },
  }};
  proc.inst = new WebAssembly.Instance(mod, imports);
  proc.memory = proc.inst.exports.memory; // module defines+exports its own (independent) memory
  if (memToCopy) { new Uint8Array(proc.memory.buffer).set(new Uint8Array(memToCopy)); } // fork: inherit parent's memory
  if (!BUF) BUF = Number(proc.inst.exports.asyncbuf_addr());
  return proc;
}

function resume(proc) {
  // enter (or re-enter for rewind) the program
  proc.pendingOp = null;
  const r = proc.inst.exports.run();
  if (proc.phase === 'unwind') {
    proc.inst.exports.asyncify_stop_unwind();
    if (proc.pendingOp === 'fork') {
      // spawn child: fresh instance, copy this proc's memory, rewind child->0, parent->pid
      const childPid = nextPid++;
      const child = newProc(`child(pid ${childPid})`, childPid, proc.memory.buffer);
      child.forkRet = 0; child.phase = 'rewind'; child.inst.exports.asyncify_start_rewind(BUF);
      ready.push(child);
      proc.forkRet = childPid; proc.phase = 'rewind'; proc.inst.exports.asyncify_start_rewind(BUF);
      ready.push(proc);
    } else if (proc.pendingOp === 'yield') {
      proc.phase = 'rewind'; proc.inst.exports.asyncify_start_rewind(BUF);
      ready.push(proc);
    }
  } else {
    proc.done = true;
    out.push(`${proc.tag}: [exited ${r}]`);
  }
}

const root = newProc('parent(pid 100)', 100, null);
ready.push(root);
// round-robin scheduler
let steps = 0;
while (ready.length && steps++ < 1000) { const p = ready.shift(); resume(p); }

console.log(out.join('\n'));
const childLines = out.filter(l => l.startsWith('child')).length;
const parentBaseOk = out.some(l => l === 'parent(pid 100): 599');
const childBaseOk = out.some(l => l.includes(': 99'));
const interleaved = (() => { // did parent and child alternate rather than run to completion serially?
  let switches = 0, prev = null;
  for (const l of out) { const who = l.split(':')[0]; if (prev && who !== prev) switches++; prev = who; }
  return switches;
})();
console.log('\nRESULT:', (parentBaseOk && childBaseOk && childLines > 0 && interleaved >= 3)
  ? `CONCURRENT fork-without-exec WORKS — parent(base 500) & child(base 0) ran on INDEPENDENT copied memories, interleaved (${interleaved} context switches).`
  : `incomplete (parentBaseOk=${parentBaseOk} childBaseOk=${childBaseOk} switches=${interleaved})`);
