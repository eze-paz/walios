// Synchronous TCP bridge for the WALI host.
// Runs in a worker_thread; owns real net.Sockets. The main (guest) thread
// issues blocking socket ops by writing a request into a SharedArrayBuffer and
// Atomics.wait-ing for this worker to complete it. This is the node stand-in
// for the browser's WISP relay — same sync-guest / async-io contract.
'use strict';
const { parentPort, workerData } = require('worker_threads');
const net = require('net');
const dgram = require('dgram');

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

const OP = { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8 };
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
  if (op === OP.CLOSE) { if (st.sock) st.sock.destroy(); if (st.udp) st.udp.close(); socks.delete(a0); return finish(0); }
  if (op === OP.POLL) { return finish(st.rxq.length || st.eof ? 1 : 0); }
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
