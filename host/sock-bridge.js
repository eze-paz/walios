// Synchronous TCP bridge for the WALI host.
// Runs in a worker_thread; owns real net.Sockets. The main (guest) thread
// issues blocking socket ops by writing a request into a SharedArrayBuffer and
// Atomics.wait-ing for this worker to complete it. This is the node stand-in
// for the browser's WISP relay — same sync-guest / async-io contract.
'use strict';
const { parentPort, workerData } = require('worker_threads');
const net = require('net');
const dgram = require('dgram');
const dns = require('dns');

// Parse the QNAME from a DNS query (offset 12) and answer it via node's resolver,
// returning a synthetic DNS response. Reliable + browser-portable (a DoH relay
// would slot in here); avoids depending on raw UDP reaching a nameserver.
function parseQName(buf, off) {
  const labels = [];
  while (buf[off] !== 0) { const len = buf[off]; labels.push(buf.subarray(off + 1, off + 1 + len).toString('ascii')); off += 1 + len; }
  return { name: labels.join('.'), end: off + 1 };
}
async function answerDns(query) {
  const id = query.subarray(0, 2);
  const { name, end } = parseQName(query, 12);
  const qtype = query.readUInt16BE(end);
  const question = query.subarray(12, end + 4); // qname + qtype + qclass
  let ips = [];
  try { // DNS-over-HTTPS (rides TCP; system UDP resolver is unreachable here + no UDP in browsers)
    const t = qtype === 28 ? 'AAAA' : 'A';
    const r = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(name)}&type=${t}`, { headers: { accept: 'application/dns-json' } });
    const j = await r.json();
    ips = (j.Answer || []).filter(a => a.type === qtype).map(a => a.data);
    console.error(`[dns] ${name} type=${qtype} -> ${ips.join(',') || '(none)'}`);
  } catch (e) { console.error(`[dns] ${name} FAILED: ${e.message}`); }
  const header = Buffer.alloc(12);
  id.copy(header, 0);
  header.writeUInt16BE(0x8180, 2);   // response, recursion available
  header.writeUInt16BE(1, 4);        // qdcount
  header.writeUInt16BE(ips.length, 6); // ancount
  const answers = ips.map((ip) => {
    const isV6 = ip.includes(':');
    const rd = isV6 ? Buffer.from(ip.split(':').flatMap(h => { const n = parseInt(h || '0', 16); return [n >> 8, n & 0xff]; })) : Buffer.from(ip.split('.').map(Number));
    const a = Buffer.alloc(12 + rd.length);
    a.writeUInt16BE(0xC00C, 0);       // name -> pointer to offset 12
    a.writeUInt16BE(isV6 ? 28 : 1, 2); // type
    a.writeUInt16BE(1, 4);            // class IN
    a.writeUInt32BE(60, 6);           // ttl
    a.writeUInt16BE(rd.length, 10);   // rdlength
    rd.copy(a, 12);
    return a;
  });
  return Buffer.concat([header, question, ...answers]);
}

// SAB layout (Int32 indexed):
//  ctl[0] = request seq (main increments, then notifies)
//  ctl[1] = response seq (worker sets = request seq when done, then notifies)
//  ctl[2] = opcode
//  ctl[3] = a0  ctl[4] = a1  ctl[5] = a2   (op args)
//  ctl[6] = result (i32, negative = -errno)
//  data area (bytes) after header for payloads (host->worker request bytes and
//  worker->host response bytes share the region; big enough for one op)
const HDR = 32;                       // bytes reserved for ctl (8 int32)
const ctl = new Int32Array(workerData.sab, 0, 8);
const data = new Uint8Array(workerData.sab, HDR);

const OP = { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, LISTEN: 9, ACCEPT: 10 };
const EAGAIN = -11, ECONNREFUSED = -111, EPIPE = -32, EBADF = -9, EINVAL = -22;

// per-socket state living in the worker
const socks = new Map(); // id -> {sock, rxq:[Buffer], eof, connected, err}
let nextId = 1;

function finish(res) { Atomics.store(ctl, 6, res | 0); Atomics.store(ctl, 1, Atomics.load(ctl, 0)); Atomics.notify(ctl, 1); }

async function handle(op) {
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  if (op === OP.CONNECT) {
    // request bytes: "host:port"
    const spec = Buffer.from(data.subarray(0, a0)).toString('utf8');
    const [host, portStr] = spec.split('|');
    const id = nextId++;
    const st = { sock: null, rxq: [], eof: false, connected: false, err: 0 };
    socks.set(id, st);
    await new Promise((resolve) => {
      const s = net.connect({ host, port: +portStr }, () => { st.connected = true; resolve(); });
      st.sock = s;
      s.on('data', (b) => st.rxq.push(b));
      s.on('end', () => { st.eof = true; });
      s.on('close', () => { st.eof = true; });
      s.on('error', (e) => { st.err = e.code === 'ECONNREFUSED' ? ECONNREFUSED : EPIPE; resolve(); });
    });
    if (st.err) { socks.delete(id); return finish(st.err); }
    return finish(id);
  }
  if (op === OP.LISTEN) { // request bytes: "ip|port" -> listener id; ctl[7] = actual port
    const [ip, portStr] = Buffer.from(data.subarray(0, a0)).toString('utf8').split('|');
    const id = nextId++;
    const st = { server: null, pendq: [], rxq: [], eof: false, err: 0 };
    socks.set(id, st);
    await new Promise((resolve) => {
      const srv = net.createServer((s) => st.pendq.push(s));
      st.server = srv;
      srv.on('error', (e) => { st.err = e.code === 'EADDRINUSE' ? -98 : EINVAL; resolve(); });
      srv.listen(+portStr, ip === '0.0.0.0' ? undefined : ip, () => resolve());
    });
    if (st.err) { socks.delete(id); return finish(st.err); }
    ctl[7] = st.server.address().port;
    return finish(id);
  }
  if (op === OP.UDP) {
    const id = nextId++;
    const st = { udp: dgram.createSocket('udp4'), rxq: [], eof: false, err: 0 };
    st.udp.on('message', (m) => st.rxq.push(m));
    st.udp.on('error', () => { st.err = EPIPE; });
    socks.set(id, st);
    return finish(id);
  }
  const st = socks.get(a0);
  if (!st) return finish(EBADF);
  if (op === OP.SEND) {
    const buf = Buffer.from(data.subarray(0, a1));
    if (st.eof || !st.sock.writable) return finish(EPIPE);
    st.sock.write(buf);
    return finish(a1);
  }
  if (op === OP.RECV) {
    // block until data or EOF
    while (!st.rxq.length && !st.eof && !st.err) await new Promise(r => setTimeout(r, 1));
    if (st.err) return finish(st.err);
    if (!st.rxq.length) return finish(0); // EOF
    let out = Buffer.concat(st.rxq); st.rxq = [];
    const n = Math.min(out.length, a1);
    data.set(out.subarray(0, n), 0);
    if (n < out.length) st.rxq.push(out.subarray(n));
    return finish(n);
  }
  if (op === OP.SENDTO) { // a1=len; request bytes = "ip|port|<payload>" ... instead pass addr via data prefix
    // data layout: [0..a1) payload already; addr passed separately in a2 handled by host as "ip|port" appended after payload
    // simpler: host packs "ip|port\n" + payload; a1 = payload len, a2 = addrlen prefix
    const addr = Buffer.from(data.subarray(a1, a1 + a2)).toString('utf8');
    const [ip, portStr] = addr.split('|');
    const payload = Buffer.from(data.subarray(0, a1));
    if (+portStr === 53) { // DNS: resolve host-side (await so the reply is queued
      // before RECVFROM runs — the worker blocks in Atomics.wait between ops, so
      // a fire-and-forget fetch would never progress).
      try { const resp = await answerDns(payload); st.rxq.push(resp); } catch {}
      return finish(a1);
    }
    st.udp.send(payload, +portStr, ip);
    return finish(a1);
  }
  if (op === OP.RECVFROM) {
    while (!st.rxq.length && !st.err) await new Promise(r => setTimeout(r, 1));
    if (st.err) return finish(st.err);
    const msg = st.rxq.shift();
    const n = Math.min(msg.length, a1);
    data.set(msg.subarray(0, n), 0);
    return finish(n);
  }
  if (op === OP.ACCEPT) { // a0 = listener id, a1 = probe (1: EAGAIN instead of block)
    if (!st.server) return finish(EINVAL);
    while (!st.pendq.length && !st.err) {
      if (a1) return finish(EAGAIN);
      await new Promise(r => setTimeout(r, 5));
    }
    if (st.err) return finish(st.err);
    const s = st.pendq.shift();
    const id = nextId++;
    const cst = { sock: s, rxq: [], eof: false, connected: true, err: 0 };
    s.on('data', (b) => cst.rxq.push(b));
    s.on('end', () => { cst.eof = true; });
    s.on('close', () => { cst.eof = true; });
    s.on('error', () => { cst.err = EPIPE; });
    socks.set(id, cst);
    const peer = Buffer.from(`${s.remoteAddress || '0.0.0.0'}|${s.remotePort || 0}`, 'utf8');
    data.set(peer, 0); ctl[7] = peer.length;
    return finish(id);
  }
  if (op === OP.CLOSE) { if (st.sock) st.sock.destroy(); if (st.udp) st.udp.close(); if (st.server) st.server.close(); socks.delete(a0); return finish(0); }
  if (op === OP.POLL) { return finish((st.server ? st.pendq.length : st.rxq.length || st.eof) ? 1 : 0); }
  finish(EINVAL);
}

// worker loop: wait for a new request seq, run it
(async () => {
  let last = 0;
  parentPort.postMessage({ ready: true });
  while (true) {
    Atomics.wait(ctl, 0, last);
    const seq = Atomics.load(ctl, 0);
    if (seq === last) continue;
    last = seq;
    if (ctl[2] === 0) break; // opcode 0 = shutdown
    await handle(ctl[2]);
  }
})();
