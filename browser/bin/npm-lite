#!/bin/node
'use strict';
// npm-lite -- install a package from the real npm registry, inside walios.
//
// Not npm. npm itself is 1338 files of pure JS and would run here in principle, but
// it wants concurrency and a lot more of the fs/promises surface. This is the install
// path reduced to its essentials, which is what proves the pieces work:
//
//   registry metadata  -> https over fetch      (shim-http.js)
//   integrity check    -> sha512 of the tarball (shim-crypto.js)
//   decompress         -> DecompressionStream   (shim-zlib.js)
//   unpack             -> tar reader below
//   write              -> real SYS_open/write into the walios filesystem
//
// Usage:  node /usr/bin/npm-lite <pkg>[@version] [--prefix DIR]

const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const crypto = require('crypto');

const REGISTRY = 'https://registry.npmjs.org';

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) return reject(new Error(url + ' -> HTTP ' + res.statusCode));
      try { resolve(JSON.parse(new TextDecoder().decode(res.body))); }
      catch (e) { reject(e); }
    }).on('error', reject);
  });
}

function getBytes(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) return reject(new Error(url + ' -> HTTP ' + res.statusCode));
      resolve(res.body);
    }).on('error', reject);
  });
}

// ---- tar --------------------------------------------------------------------
// Only what an npm tarball contains: regular files, directories, and the long-name
// extensions ('L' and the PAX 'x' record) that real packages do hit.
function untar(buf) {
  const td = new TextDecoder();
  const out = [];
  let off = 0;
  let longName = null;
  const str = (o, n) => td.decode(buf.subarray(o, o + n)).replace(/\0.*$/, '').trim();
  while (off + 512 <= buf.length) {
    const hdr = buf.subarray(off, off + 512);
    if (hdr.every((b) => b === 0)) break;
    let name = str(off, 100);
    const prefix = str(off + 345, 155);
    if (prefix) name = prefix + '/' + name;
    const size = parseInt(str(off + 124, 12), 8) || 0;
    const type = String.fromCharCode(hdr[156] || 48);
    off += 512;
    const data = buf.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;

    if (type === 'L') { longName = td.decode(data).replace(/\0.*$/, ''); continue; }
    if (type === 'x' || type === 'g') {
      const rec = td.decode(data);
      const m = /\d+ path=([^\n]+)\n/.exec(rec);
      if (m) longName = m[1];
      continue;
    }
    if (longName) { name = longName; longName = null; }
    if (type === '0' || type === '\0') out.push({ name, data: data.slice() });
    else if (type === '5') out.push({ name, dir: true });
  }
  return out;
}

function mkdirp(p) {
  const parts = p.split('/').filter(Boolean);
  let cur = '';
  for (const part of parts) {
    cur += '/' + part;
    try { fs.mkdirSync(cur); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  }
}

// npm's integrity is "<algo>-<base64 digest>"
function verify(bytes, integrity) {
  if (!integrity) return 'no integrity field in the registry metadata';
  const [algo, expected] = String(integrity).split('-', 2);
  const got = crypto.createHash(algo).update(bytes).digest('base64');
  if (got !== expected) throw new Error('integrity mismatch: ' + algo + ' expected ' + expected.slice(0, 24) + '..., got ' + got.slice(0, 24) + '...');
  return algo + ' ok';
}


// ---- semver ------------------------------------------------------------------
// Enough of the grammar that real dependency ranges resolve: exact, x-ranges,
// caret, tilde, comparators, and ||-alternatives. Not a spec-complete
// implementation -- prerelease ordering in particular is simplified.
// Minor and patch are optional. Comparators are routinely written short ("< 3",
// ">= 2.1"), and demanding all three components made `<3` unparseable -- so the
// comparator returned false and express could not resolve safer-buffer.
function parseV(v) {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?/.exec(String(v).trim());
  return m ? { major: +m[1], minor: +(m[2] || 0), patch: +(m[3] || 0), pre: m[4] || null } : null;
}
function cmp(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.pre && !b.pre) return -1;          // 1.0.0-rc < 1.0.0
  if (!a.pre && b.pre) return 1;
  return 0;
}
function satisfiesOne(v, range) {
  range = range.trim();
  // An exact range with a prerelease tag ("0.0.0-nope") must match exactly. Without
  // this the numeric comparison below ignored the tag and happily installed 0.0.0.
  if (/^v?\d+\.\d+\.\d+-/.test(range)) return String(v).replace(/^v/, '') === range.replace(/^v/, '');
  if (!range || range === '*' || range === 'latest' || range === 'x') return true;
  if (/^(https?:|git|file:|npm:)/.test(range)) return false;      // not a version range
  const V = parseV(v);
  if (!V) return false;

  // A comparator may be written with a space after the operator (">= 2.1.2 < 3"),
  // so glue operators to their versions before splitting -- otherwise ">=" and
  // "2.1.2" became separate comparators and express failed to resolve safer-buffer.
  const parts = range.replace(/([<>]=?|=)\s+/g, '$1').split(/\s+/).filter(Boolean);
  if (parts.length > 1 && !/^[~^]/.test(range)) return parts.every((p) => satisfiesOne(v, p));

  let m;
  if ((m = /^([~^]?)v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?/.exec(range))) {
    const op = m[1];
    const maj = +m[2];
    const minS = m[3], patS = m[4];
    const minorAny = minS === undefined || minS === 'x' || minS === '*';
    const patchAny = patS === undefined || patS === 'x' || patS === '*';
    const min = minorAny ? 0 : +minS;
    const pat = patchAny ? 0 : +patS;
    const lo = { major: maj, minor: min, patch: pat, pre: null };
    if (cmp(V, lo) < 0) return false;
    if (op === '^') {
      // ^0.2.3 is >=0.2.3 <0.3.0; ^1.2.3 is >=1.2.3 <2.0.0
      if (maj > 0) return V.major === maj;
      if (min > 0 || !minorAny) return V.major === 0 && V.minor === min;
      return V.major === 0;
    }
    if (op === '~') return V.major === maj && (minorAny || V.minor === min);
    if (minorAny) return V.major === maj;
    if (patchAny) return V.major === maj && V.minor === min;
    return cmp(V, lo) === 0;
  }
  if ((m = /^(>=|<=|>|<|=)\s*v?(.+)$/.exec(range))) {
    const R = parseV(m[2]);
    if (!R) return false;
    const c = cmp(V, R);
    switch (m[1]) {
      case '>=': return c >= 0;
      case '<=': return c <= 0;
      case '>': return c > 0;
      case '<': return c < 0;
      default: return c === 0;
    }
  }
  return false;
}
function satisfies(v, range) {
  return String(range).split('||').some((r) => satisfiesOne(v, r));
}
function pickVersion(meta, range) {
  if (meta.versions[range]) return range;                       // exact pin
  const tag = meta['dist-tags'] && meta['dist-tags'][range];
  if (tag) return tag;
  const all = Object.keys(meta.versions).map(parseV).filter(Boolean);
  const ok = Object.keys(meta.versions).filter((v) => satisfies(v, range));
  if (!ok.length) return null;
  // highest satisfying version, which is what npm does
  return ok.sort((a, b) => cmp(parseV(a), parseV(b))).pop();
}

// Progress to a FILE when NPM_LITE_DEBUG is set. stdout is buffered and is lost if the
// process dies mid-install, which is exactly the case being investigated -- a file
// survives it and shows where it stopped.
const DBG = (typeof process !== 'undefined' && process.env && process.env.NPM_LITE_DEBUG) || '';
let dbgSeq = 0;
function dbg(msg) {
  if (!DBG) return;
  try { fs.appendFileSync(DBG, (++dbgSeq) + ' ' + Date.now() + ' ' + msg + String.fromCharCode(10)); } catch (_) {}
}

async function installOne(name, range, prefix) {
  dbg('installOne:enter ' + name + '@' + range);
  const meta = await getJSON(REGISTRY + '/' + name);
  const version = pickVersion(meta, range || 'latest');
  const v = version && meta.versions && meta.versions[version];
  if (!v) throw new Error('no version of ' + name + ' satisfies ' + JSON.stringify(range));

  const tgz = await getBytes(v.dist.tarball);
  const integrity = verify(tgz, v.dist.integrity || (v.dist.shasum && 'sha1-' + Buffer.from(v.dist.shasum, 'hex').toString('base64')));
  const tar = await zlib.promises.gunzip(tgz);
  const entries = untar(tar);

  const dest = path.join(prefix, name);
  let written = 0, bytes = 0;
  for (const e of entries) {
    // npm tarballs are rooted at "package/"
    const rel = e.name.replace(/^[^/]+\//, '');
    if (!rel) continue;
    const full = path.join(dest, rel);
    if (e.dir) { mkdirp(full); continue; }
    mkdirp(path.dirname(full));
    fs.writeFileSync(full, e.data);
    written++; bytes += e.data.length;
  }
  return { name, version, dest, written, bytes, tgz: tgz.length, integrity, deps: v.dependencies || {} };
}

// Walk the dependency graph breadth-first into a FLAT /node_modules, which is what
// npm has done since v3 and what node's resolver expects: every package sits at
// <prefix>/<name>, so a nested require finds it by walking up. A single version per
// name -- no conflict resolution, so a genuine diamond with incompatible ranges
// resolves to whichever was seen first, and says so.
async function installTree(specs, prefix, log) {
  const want = new Map();                 // name -> range
  for (const spec of specs) {
    const at = spec.lastIndexOf('@');
    if (at > 0) want.set(spec.slice(0, at), spec.slice(at + 1));
    else want.set(spec, 'latest');
  }
  const done = new Map();                 // name -> version installed
  const queue = [...want.entries()];
  const conflicts = [];
  let files = 0, bytes = 0;

  while (queue.length) {
    const [name, range] = queue.shift();
    if (done.has(name)) {
      if (!satisfies(done.get(name), range)) conflicts.push(name + '@' + done.get(name) + ' vs ' + range);
      continue;
    }
    const r = await installOne(name, range, prefix);
    dbg('installed ' + name + '@' + r.version + ' queue=' + queue.length + ' done=' + done.size);
    done.set(name, r.version);
    files += r.written; bytes += r.bytes;
    log('  ' + (name + '@' + r.version).padEnd(34) + r.written + ' files  ' + r.integrity);
    for (const [dep, depRange] of Object.entries(r.deps)) {
      if (!done.has(dep)) queue.push([dep, depRange]);
    }
  }
  return { count: done.size, files, bytes, conflicts, tree: done };
}

async function main() {
  const args = process.argv.slice(2);
  let prefix = '/node_modules';
  const specs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--prefix') { prefix = args[++i]; continue; }
    specs.push(args[i]);
  }
  if (!specs.length) {
    console.error('usage: npm-lite <pkg>[@range]... [--prefix DIR]');
    process.exitCode = 1;
    return;
  }
  const t0 = Date.now();
  // Hold the event loop for the WHOLE install. Every individual await here is
  // covered (the fetch shim and the zlib shim each register with the runtime's
  // pending count), but an install is a long chain of them and the process only has
  // to be judged idle ONCE, in a gap between two of them, to be retired mid-work --
  // which is what was happening: npm-lite exited 0 having written part of the tree,
  // and the failure only showed up later as "Cannot find module" from a package that
  // looked installed. A single explicit hold removes the whole class.
  const hold = setInterval(() => {}, 200);
  let r;
  dbg('main:start ' + specs.join(','));
  try { r = await installTree(specs, prefix, (s) => console.log(s)); }
  catch (e) { dbg('main:THREW ' + ((e && e.stack) || e)); throw e; }
  finally { clearInterval(hold); dbg('main:installTree returned'); }
  dbg('main:done count=' + r.count);
  console.log('installed ' + r.count + ' package(s), ' + r.files + ' files, '
    + r.bytes + ' bytes in ' + ((Date.now() - t0) / 1000).toFixed(1) + 's -> ' + prefix);
  if (r.conflicts.length) console.log('version conflicts (first wins): ' + r.conflicts.join('; '));
}

main().catch((e) => { console.error('npm-lite: ' + (e && e.message || e)); process.exitCode = 1; });
