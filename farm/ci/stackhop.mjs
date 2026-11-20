// stackhop: let a WALI program recurse deeper than one browser stack.
//
//   node stackhop.mjs <in.wasm> <out.wasm> [--budget BYTES]
//   (STACKHOP_NAMES=1 keeps function names in the output, for readable traps)
//
// A browser runs wasm on the thread's native stack, about 1 MB (a worker's is smaller than a
// page's), where Linux gives a process 8 MB. git's fast-import writes a 4100-deep tree by
// recursion and overflowed it (t6700 "create big tree": RangeError, Maximum call stack size).
//
// The program keeps a running estimate of the native stack its recursion uses (__sh_used, a
// per-instance global, so per thread), counted where a recursion must pass:
//   - every function in a recursive SCC of the DIRECT-call graph is wrapped;
//   - every call_indirect goes through a helper per signature: a recursion through a function
//     pointer (git archive: read_tree -> callback -> read_tree) passes one on every level.
//     (Wrapping the targets instead would take most of the program: any call_indirect of a type
//     may reach every table function of that type -- 4073 of git's 5079 functions.)
// Past --budget, the next call goes through the kernel import wali.__stackhop, which re-enters
// the module on a FRESH stack (WebAssembly.promising: a call that never suspends runs to
// completion synchronously, on a new stack) and continues there from 0. Measured in Chrome (a
// worker): 3,168 levels -> 1,344,670.
//
// What the kernel sees: the arguments in __sh_<type>_<i> globals (a function pointer in
// __sh_ci_idx), the target in __sh_k; it calls the export __stackhop_enter(), which runs it and
// sets the exported global __stackhop_done to 1 when it returned normally (0: it trapped, exited
// or is unwinding for fork). A kernel without JSPI calls __stackhop_enter on the same stack: the
// program then behaves exactly as unwrapped. walios: wali-proc-worker.js stackHop and
// wali-worker.js _makeInProcImports.
//
// The estimate per frame is the baseline compiler's (the larger) frame: 96 + 16 bytes per
// param/local (calibrated in Chrome: a 6-local and a 3-local function pair took ~336 bytes);
// an indirect call counts CI_W. fork() inside a hopped segment works when asyncify-imports also
// lists wali.__stackhop -- run this pass BEFORE --asyncify: Asyncify then unwinds and rewinds
// through the hop like through any import.
import fs from 'node:fs';

const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); if (i < 0) return d; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const BUDGET = +opt('--budget', 196608);
const CI_W = 256;
const [IN, OUT] = argv;
if (!IN || !OUT) { console.error('usage: stackhop.mjs <in.wasm> <out.wasm> [--budget BYTES]'); process.exit(2); }
const binaryen = (await import('binaryen')).default;
const VT = new Set(['i32', 'i64', 'f32', 'f64']);

let mod = binaryen.readBinary(fs.readFileSync(IN));
mod.setFeatures(binaryen.Features.All);
const txt0 = mod.emitText();
const lines = txt0.split('\n');

// ---- types, direct calls, call_indirect sites (from the module's text) ----
const types = new Map();       // $T -> { ps: [...], rs: [...] }
for (const m of txt0.matchAll(/^ \(type \$(\S+) \(func((?: \(param [^)]*\))*)((?: \(result [^)]*\))*)\)\)$/gm)) {
  const grab = (s, kw) => [...s.matchAll(new RegExp('\\(' + kw + '([^)]*)\\)', 'g'))].flatMap((x) => x[1].trim().split(/\s+/).filter(Boolean));
  types.set(m[1], { ps: grab(m[2], 'param'), rs: grab(m[3], 'result') });
}
const edges = new Map();
const ciKinds = new Map();     // "table type" -> helper index
{
  let cur = null, set = null;
  for (const line of lines) {
    const fm = /^ \(func \$(\S+)/.exec(line);
    if (fm) { cur = fm[1]; set = new Set(); edges.set(cur, set); continue; }
    if (!cur) continue;
    const cm = /\((?:return_)?call \$([^\s)]+)/.exec(line);
    if (cm) set.add(cm[1]);
    const im = /\(call_indirect \$(\S+) \(type \$([^\s)]+)\)/.exec(line);
    if (im) {
      const t = types.get(im[2]);
      if (t && t.rs.length <= 1 && [...t.ps, ...t.rs].every((x) => VT.has(x)) && !ciKinds.has(im[1] + ' ' + im[2])) ciKinds.set(im[1] + ' ' + im[2], ciKinds.size);
    }
  }
}
const funcs = [];
for (let i = 0; i < mod.getNumFunctions(); i++) {
  const info = binaryen.getFunctionInfo(mod.getFunctionByIndex(i));
  if (!info.module) funcs.push(info);          // defined, not imported
}
const byName = new Map(funcs.map((f) => [f.name, f]));

// ---- Tarjan: functions in a recursive SCC of the direct-call graph ----
const recursive = new Set();
{
  let idx = 0; const st = [], on = new Set(), num = new Map(), low = new Map();
  const succ = (v) => [...(edges.get(v) || [])].filter((w) => byName.has(w));
  const strong = (v0) => {
    const work = [[v0, succ(v0), 0]];
    num.set(v0, idx); low.set(v0, idx); idx++; st.push(v0); on.add(v0);
    while (work.length) {
      const top = work[work.length - 1], [v, ws] = top;
      if (top[2] < ws.length) {
        const w = ws[top[2]++];
        if (!num.has(w)) { num.set(w, idx); low.set(w, idx); idx++; st.push(w); on.add(w); work.push([w, succ(w), 0]); }
        else if (on.has(w)) low.set(v, Math.min(low.get(v), num.get(w)));
      } else {
        work.pop();
        if (work.length) { const u = work[work.length - 1][0]; low.set(u, Math.min(low.get(u), low.get(v))); }
        if (low.get(v) === num.get(v)) {
          const comp = []; let w; do { w = st.pop(); on.delete(w); comp.push(w); } while (w !== v);
          if (comp.length > 1 || (edges.get(v) && edges.get(v).has(v))) comp.forEach((c) => recursive.add(c));
        }
      }
    }
  };
  for (const f of funcs) if (!num.has(f.name)) strong(f.name);
}
const T = (t) => binaryen.expandType(t);
const tname = (t) => ({ [binaryen.i32]: 'i32', [binaryen.i64]: 'i64', [binaryen.f32]: 'f32', [binaryen.f64]: 'f64' })[t];
const targets = [...recursive].map((n) => byName.get(n)).filter((f) => {
  const ps = T(f.params), rs = T(f.results);
  return rs.length <= 1 && [...ps, ...rs].every((t) => tname(t));
});
if (!targets.length && !ciKinds.size) { console.log('stackhop: nothing recursive; copied as is'); fs.copyFileSync(IN, OUT); process.exit(0); }

// argument slots: per type, as many as the widest target needs
const slotsNeeded = {};
const need = (ps) => { const c = {}; for (const n of ps) c[n] = (c[n] || 0) + 1; for (const n in c) slotsNeeded[n] = Math.max(slotsNeeded[n] || 0, c[n]); };
targets.forEach((f) => need(T(f.params).map(tname)));
for (const key of ciKinds.keys()) need(types.get(key.split(' ')[1]).ps);
const slotNames = (ps) => { const c = {}; return ps.map((n) => `__sh_${n}_${(c[n] = (c[n] || 0) + 1) - 1}`); };

// ---- text phase: helpers for the call_indirect sites, globals, the import ----
const ZERO = { i32: '(i32.const 0)', i64: '(i64.const 0)', f32: '(f32.const 0)', f64: '(f64.const 0)' };
const add = [];
for (const n in slotsNeeded) for (let i = 0; i < slotsNeeded[n]; i++) add.push(` (global $__sh_${n}_${i} (mut ${n}) ${ZERO[n]})`);
for (const n of VT) add.push(` (global $__sh_r_${n} (mut ${n}) ${ZERO[n]})`);
add.push(' (global $__sh_used (mut i32) (i32.const 0))', ' (global $__sh_k (mut i32) (i32.const 0))', ' (global $__sh_ci_idx (mut i32) (i32.const 0))',
  ' (global $__stackhop_done (mut i32) (i32.const 0))', ' (export "__stackhop_done" (global $__stackhop_done))');
for (const [key, k] of ciKinds) {
  const [tab, ty] = key.split(' '), { ps, rs } = types.get(ty), R = rs[0];
  const P = ps.map((t, i) => `(param $p${i} ${t})`).join(' ');
  const args = ps.map((_, i) => `(local.get $p${i})`).join(' ');
  const ci = `(call_indirect $${tab} (type $${ty}) ${args} (local.get $idx))`;
  const sets = slotNames(ps).map((g, i) => `(global.set $${g} (local.get $p${i}))`).join(' ');
  add.push(` (func $__sh_ci_${k} ${P} (param $idx i32)${R ? ` (result ${R})` : ''} (local $s i32)${R ? ` (local $r ${R})` : ''}
  (global.set $__sh_used (i32.add (global.get $__sh_used) (i32.const ${CI_W})))
  (if (i32.gt_u (global.get $__sh_used) (i32.const ${BUDGET}))
   (then (local.set $s (global.get $__sh_used)) (global.set $__sh_used (i32.const 0)) ${sets}
    (global.set $__sh_ci_idx (local.get $idx)) (global.set $__sh_k (i32.const ${k})) (call $__stackhop)
    ${R ? `(local.set $r (global.get $__sh_r_${R}))` : ''} (global.set $__sh_used (local.get $s)))
   (else ${R ? `(local.set $r ${ci})` : ci}))
  (global.set $__sh_used (i32.sub (global.get $__sh_used) (i32.const ${CI_W})))
  ${R ? '(local.get $r)' : ''})`);
}
let lastImport = -1, sites = 0;
{
  let inFunc = false;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^ \(import /.test(l)) lastImport = i;
    if (/^ \(func /.test(l)) inFunc = true; else if (/^ \((?!func )/.test(l)) inFunc = false;
    if (!inFunc) continue;
    lines[i] = l.replace(/\(call_indirect \$(\S+) \(type \$([^\s)]+)\)/, (all, tab, ty) => {
      const k = ciKinds.get(tab + ' ' + ty); if (k === undefined) return all; sites++; return `(call $__sh_ci_${k}`;
    });
  }
}
lines.splice(lastImport + 1, 0, ' (import "wali" "__stackhop" (func $__stackhop))');
const close = lines.lastIndexOf(')');
lines.splice(close, 0, ...add);
mod.dispose();
mod = binaryen.parseText(lines.join('\n'));
mod.setFeatures(binaryen.Features.All);

// ---- API phase: wrap the direct-recursive functions ----
const { i32 } = binaryen;
const G = (n, t) => mod.global.get(n, t);
const inner = [];
targets.forEach((f0, j) => {
  const f = binaryen.getFunctionInfo(mod.getFunction(f0.name));
  const ps = T(f.params), rs = T(f.results), vars = f.vars || [];
  const k = ciKinds.size + j;
  const W = Math.min(96 + 16 * (ps.length + vars.length), BUDGET >> 2);
  const innerName = f.name + '$sh';
  mod.addFunction(innerName, f.params, f.results, vars, f.body);
  mod.removeFunction(f.name);
  const R = rs.length ? rs[0] : binaryen.none;
  const sav = ps.length, rl = ps.length + 1;
  const callInner = mod.call(innerName, ps.map((t, i) => mod.local.get(i, t)), R);
  const slots = slotNames(ps.map(tname));
  const hopSeq = [
    mod.local.set(sav, G('__sh_used', i32)),
    mod.global.set('__sh_used', mod.i32.const(0)),
    ...slots.map((g, i) => mod.global.set(g, mod.local.get(i, ps[i]))),
    mod.global.set('__sh_k', mod.i32.const(k)),
    mod.call('__stackhop', [], binaryen.none),
    ...(R !== binaryen.none ? [mod.local.set(rl, G('__sh_r_' + tname(R), R))] : []),
    mod.global.set('__sh_used', mod.local.get(sav, i32)),
  ];
  const body = mod.block(null, [
    mod.global.set('__sh_used', mod.i32.add(G('__sh_used', i32), mod.i32.const(W))),
    mod.if(mod.i32.gt_u(G('__sh_used', i32), mod.i32.const(BUDGET)),
      mod.block(null, hopSeq, binaryen.none),
      R !== binaryen.none ? mod.local.set(rl, callInner) : callInner),
    mod.global.set('__sh_used', mod.i32.sub(G('__sh_used', i32), mod.i32.const(W))),
    ...(R !== binaryen.none ? [mod.return(mod.local.get(rl, R))] : []),
  ], binaryen.none);
  mod.addFunction(f.name, f.params, f.results, R !== binaryen.none ? [i32, R] : [i32], body);
  inner.push({ k, call: () => mod.call(innerName, slots.map((g, i) => G(g, ps[i])), R), R });
});

// __stackhop_enter: run target __sh_k with the slotted arguments on the current (fresh) stack.
{
  const cases = [];
  for (const [key, k] of ciKinds) {
    const [tab, ty] = key.split(' '), { ps, rs } = types.get(ty);
    const R = rs.length ? binaryen[rs[0]] : binaryen.none;
    const sl = slotNames(ps);
    cases[k] = { R, call: () => mod.call_indirect(tab, G('__sh_ci_idx', i32), sl.map((g, i) => G(g, binaryen[ps[i]])), binaryen.createType(ps.map((p) => binaryen[p])), R) };
  }
  for (const t of inner) cases[t.k] = t;
  const names = cases.map((_, i) => 'c' + i);
  let blk = mod.block(names[0], [mod.switch(names, 'out', G('__sh_k', i32))], binaryen.none);
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i], call = c.call();
    const kase = c.R !== binaryen.none ? mod.global.set('__sh_r_' + tname(c.R), call) : call;
    blk = mod.block(i + 1 < cases.length ? names[i + 1] : 'out', [blk, kase, mod.br('out')], binaryen.none);
  }
  mod.addFunction('__stackhop_enter', binaryen.none, binaryen.none, [], mod.block(null, [
    mod.global.set('__stackhop_done', mod.i32.const(0)),
    blk,
    mod.global.set('__stackhop_done', mod.i32.const(1)),
  ], binaryen.none));
  mod.addFunctionExport('__stackhop_enter', '__stackhop_enter');
}
if (!mod.validate()) { console.error('stackhop: the result does not validate'); process.exit(1); }
// binaryen drops custom sections on the way through; walios reads one (wali.abi says ILP32, and
// with it the kernel's struct layouts). Carry them over -- all but DWARF, stale after this pass.
{
  const seen = new Set();
  const bytes = fs.readFileSync(IN);
  let p = 8;
  const leb = () => { let n = 0, s = 0, x; do { x = bytes[p++]; n |= (x & 127) << s; s += 7; } while (x & 128); return n >>> 0; };
  while (p < bytes.length) {
    const id = bytes[p++], size = leb(), end = p + size;
    if (id === 0) {
      const nl = leb(), name = bytes.subarray(p, p + nl).toString(); p += nl;
      if (!name.startsWith('.debug') && name !== 'name' && !seen.has(name)) { seen.add(name); mod.addCustomSection(name, bytes.subarray(p, end)); }
    }
    p = end;
  }
}
binaryen.setDebugInfo(!!process.env.STACKHOP_NAMES);
fs.writeFileSync(OUT, mod.emitBinary());
console.log(`stackhop: ${targets.length} directly recursive functions wrapped, ${sites} indirect call sites through ${ciKinds.size} helpers; budget ${BUDGET} bytes`);
