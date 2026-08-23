// Browser WISP bridge worker: owns a WebSocket to the WISP relay and gives the
// (synchronous) OS worker blocking TCP via a SharedArrayBuffer + Atomics.
// TCP -> WISP frames over the WebSocket; DNS -> DoH fetch. Mirrors the node
// sock-bridge op protocol so wali-worker.js uses the same call shape.
'use strict';
const OP = { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, PING: 9 };
const EAGAIN = -11, ECONNREFUSED = -111, EPIPE = -32, EBADF = -9, EINVAL = -22;
// WISP v1 + the riscv-vm's ICMP extension (see riscv-vm/web/wisp-egress.js)
const F = { CONNECT: 0x01, DATA: 0x02, CONTINUE: 0x03, CLOSE: 0x04, PING: 0xf1, PONG: 0xf2 };

let ctl, data, ws, wsReady = false, wsErr = false, RELAY;
const streams = new Map();        // wisp stream id -> {rxq:[Uint8Array], closed}
const udpSocks = new Map();       // our udp id -> {rxq:[Uint8Array]}
const pings = new Map();          // ping id -> {status|null}
let nextStream = 1, nextUdp = 1, nextPing = 1;
// default to the SAME relay the riscv-vm uses (this origin's /wisp); dev override
// via the 'sab' message's url (e.g. the local wisp-relay.js on :8790).
function defaultRelay() { return `${self.location.protocol === 'https:' ? 'wss' : 'ws'}://${self.location.host}/wisp`; }

function connectWS() {
  ws = new WebSocket(RELAY); ws.binaryType = 'arraybuffer';
  ws.onopen = () => { wsReady = true; };
  ws.onerror = () => { wsErr = true; };
  ws.onclose = () => { wsErr = true; for (const s of streams.values()) s.closed = true; };
  ws.onmessage = (ev) => {
    const b = new Uint8Array(ev.data); if (b.length < 5) return;
    const type = b[0], id = new DataView(b.buffer, b.byteOffset).getUint32(1, true), payload = b.subarray(5);
    if (type === F.PONG) { const p = pings.get(id); if (p) p.status = payload[0]; return; } // ICMP reply
    const s = streams.get(id);
    if (type === F.DATA) { if (s) s.rxq.push(payload.slice()); }         // DATA
    else if (type === F.CLOSE) { if (s) s.closed = true; }               // CLOSE
    // CONTINUE (flow control) — ignored (relay buffer is generous)
  };
}
function wispSend(type, id, payload) {
  const f = new Uint8Array(5 + (payload ? payload.length : 0));
  f[0] = type; new DataView(f.buffer).setUint32(1, id >>> 0, true); if (payload) f.set(payload, 5);
  ws.send(f);
}
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// synthetic DNS: hand out fake 10.x IPs and remember name<->ip, then hand the
// HOSTNAME to WISP CONNECT so the RELAY resolves it (avoids COEP-blocked DoH; this
// is how riscv-vm's fake_network + resolveName works).
const nameToIp = new Map(), ipToName = new Map(); let synth = (10 << 24) | 1;
function synthIp(name) {
  if (nameToIp.has(name)) return nameToIp.get(name);
  const n = synth++; const ip = `${(n>>>24)&255}.${(n>>>16)&255}.${(n>>>8)&255}.${n&255}`;
  nameToIp.set(name, ip); ipToName.set(ip, name); return ip;
}
async function answerDns(query) {  // -> DNS response carrying a synthetic A record
  const parseQ = (buf, off) => { const l = []; while (buf[off]) { const n = buf[off]; l.push(String.fromCharCode(...buf.subarray(off + 1, off + 1 + n))); off += 1 + n; } return { name: l.join('.'), end: off + 1 }; };
  const id = query.subarray(0, 2);
  const { name, end } = parseQ(query, 12);
  const qtype = (query[end] << 8) | query[end + 1];
  const question = query.subarray(12, end + 4);
  // only answer A (IPv4); AAAA -> empty so glibc/musl falls back to A
  const ips = qtype === 1 ? [synthIp(name)] : [];
  const hdr = new Uint8Array(12); hdr.set(id, 0); const dv = new DataView(hdr.buffer);
  dv.setUint16(2, 0x8180); dv.setUint16(4, 1); dv.setUint16(6, ips.length);
  const ans = ips.map(ip => { const v6 = ip.includes(':');
    const rd = v6 ? Uint8Array.from(ip.split(':').flatMap(h => { const n = parseInt(h || '0', 16); return [n >> 8, n & 255]; })) : Uint8Array.from(ip.split('.').map(Number));
    const a = new Uint8Array(12 + rd.length); const d = new DataView(a.buffer);
    d.setUint16(0, 0xC00C); d.setUint16(2, v6 ? 28 : 1); d.setUint16(4, 1); d.setUint32(6, 60); d.setUint16(10, rd.length); a.set(rd, 12); return a; });
  const total = 12 + question.length + ans.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total); let o = 0; out.set(hdr, o); o += 12; out.set(question, o); o += question.length;
  for (const a of ans) { out.set(a, o); o += a.length; }
  return out;
}

function finish(res) { Atomics.store(ctl, 6, res | 0); Atomics.store(ctl, 1, Atomics.load(ctl, 0)); Atomics.notify(ctl, 1); }

async function handle(op) {
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  if (op === OP.CONNECT) {
    while (!wsReady && !wsErr) await sleep(2);
    if (wsErr) return finish(ECONNREFUSED);
    const spec = new TextDecoder().decode(data.slice(0, a0));   // "ip|port"
    const [ip, portStr] = spec.split('|');
    const host = ipToName.get(ip) || ip;  // hand the hostname to the relay (it resolves)
    const id = nextStream++; streams.set(id, { rxq: [], closed: false });
    const hb = new TextEncoder().encode(host);
    const payload = new Uint8Array(3 + hb.length); payload[0] = 1; new DataView(payload.buffer).setUint16(1, +portStr, true); payload.set(hb, 3);
    wispSend(0x01, id, payload);
    return finish(id);
  }
  if (op === OP.PING) { // ICMP echo via the relay: a0 = dst IP as u32 (network order in data[0..4])
    while (!wsReady && !wsErr) await sleep(2); if (wsErr) return finish(EPIPE);
    const id = nextPing++; pings.set(id, { status: null });
    const p = new Uint8Array(6); p.set(data.subarray(0, 4), 0); new DataView(p.buffer).setUint16(4, 4000, true);
    wispSend(F.PING, id, p);
    let n = 0; while (pings.get(id).status === null && n++ < 4000) await sleep(2);
    const st = pings.get(id).status; pings.delete(id);
    return finish(st === 0 ? 0 : -1); // 0 = reachable
  }
  if (op === OP.UDP) { const id = nextUdp++; udpSocks.set(id, { rxq: [] }); return finish(id); }
  if (op === OP.SENDTO) { // DNS only (port 53); a1=payloadlen a2=addrlen
    const addr = new TextDecoder().decode(data.slice(a1, a1 + a2)); const [, portStr] = addr.split('|');
    const st = udpSocks.get(a0); if (!st) return finish(EBADF);
    if (+portStr === 53) { try { const resp = await answerDns(data.slice(0, a1)); st.rxq.push(resp); } catch {} }
    return finish(a1);
  }
  if (op === OP.RECVFROM) { const st = udpSocks.get(a0); if (!st) return finish(EBADF);
    let n = 0; while (!st.rxq.length) { await sleep(2); if (++n > 2500) return finish(0); }
    const msg = st.rxq.shift(); const k = Math.min(msg.length, a1); data.set(msg.subarray(0, k), 0); return finish(k); }
  const s = streams.get(a0);
  if (op === OP.SEND) { if (!s || s.closed) return finish(EPIPE); wispSend(0x02, a0, data.slice(0, a1)); return finish(a1); }
  if (op === OP.RECV) {
    while (!s.rxq.length && !s.closed) await sleep(1);
    if (!s.rxq.length) return finish(0);  // closed = EOF
    let out = s.rxq.shift(); const k = Math.min(out.length, a1);
    data.set(out.subarray(0, k), 0); if (k < out.length) s.rxq.unshift(out.subarray(k));
    return finish(k);
  }
  if (op === OP.POLL) { if (s) return finish(s.rxq.length || s.closed ? 1 : 0); const u = udpSocks.get(a0); return finish(u && u.rxq.length ? 1 : 0); }
  if (op === OP.CLOSE) { if (s) { wispSend(0x04, a0, new Uint8Array([0])); streams.delete(a0); } udpSocks.delete(a0); return finish(0); }
  finish(EINVAL);
}

self.onmessage = async (ev) => {
  if (ev.data.t !== 'sab') return;
  ctl = new Int32Array(ev.data.sab, 0, 8); data = new Uint8Array(ev.data.sab, 32);
  RELAY = ev.data.url || defaultRelay();
  connectWS();
  self.postMessage({ ready: true });
  let last = 0;
  while (true) {
    Atomics.wait(ctl, 0, last);
    const seq = Atomics.load(ctl, 0); if (seq === last) continue; last = seq;
    if (ctl[2] === 0) break;
    await handle(ctl[2]);
  }
};
