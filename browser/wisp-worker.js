// Browser WISP bridge worker: owns a WebSocket to the WISP relay and gives the
// (synchronous) OS worker blocking TCP via a SharedArrayBuffer + Atomics.
// TCP -> WISP frames over the WebSocket; DNS -> DoH fetch. Mirrors the node
// sock-bridge op protocol so wali-worker.js uses the same call shape.
'use strict';
const OP = { CONNECT: 1, SEND: 2, RECV: 3, CLOSE: 4, POLL: 5, UDP: 6, SENDTO: 7, RECVFROM: 8, PING: 9, LISTEN: 10, ACCEPT: 11, PINGPOLL: 12 };
const listenReqs = new Map();     // listen stream id -> {status, port} (0xf5 reply)
const listeners = new Map();      // listener id -> bound relay port
const acceptQs = new Map();       // relay port -> [{sid, ip, port}] pending inbound conns
const EAGAIN = -11, ECONNREFUSED = -111, EPIPE = -32, EBADF = -9, EINVAL = -22;
// WISP v1 + the riscv-vm's ICMP extension (see riscv-vm/web/wisp-egress.js)
const F = { CONNECT: 0x01, DATA: 0x02, CONTINUE: 0x03, CLOSE: 0x04, PING: 0xf1, PONG: 0xf2 };

let ctl, data, ws, wsReady = false, wsErr = false, RELAY;
const streams = new Map();        // wisp stream id -> {rxq:[Uint8Array], closed}
const udpSocks = new Map();       // our udp id -> {rxq:[Uint8Array]}
const pings = new Map();          // ping id -> {status|null}
const resolves = new Map();       // resolve id -> {ip|null, done} (0xf6 reply)
let nextStream = 1, nextUdp = 1, nextPing = 1, nextResolve = 1;
// default to the SAME relay the riscv-vm uses (this origin's /wisp); dev override
// via the 'sab' message's url (e.g. the local wisp-relay.js on :8790).
function defaultRelay() { return `${self.location.protocol === 'https:' ? 'wss' : 'ws'}://${self.location.host}/wisp`; }

let _reDelay = 500, _reTimer = null;
function _scheduleReconnect() {   // relay dropped (e.g. server restart): reconnect with backoff
  wsReady = false;
  if (_reTimer) return;           // one attempt in flight at a time
  _reTimer = setTimeout(() => { _reTimer = null; connectWS(); }, _reDelay);
  _reDelay = Math.min(_reDelay * 2, 10000);
}
function connectWS() {
  try { ws = new WebSocket(RELAY); } catch (_) { _scheduleReconnect(); return; }
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { wsReady = true; wsErr = false; _reDelay = 500; };
  ws.onerror = () => {};                       // onclose fires next → reconnect there
  // The relay went away (restart, proxy timeout): every stream is at EOF. Keep the entries,
  // marked closed, until the kernel closes each fd -- they used to be cleared here, and the
  // kernel's next RECV on a vanished id threw inside handle(), which ended the serve loop:
  // no reply ever again, the kernel parked in Atomics.wait for good.
  ws.onclose = () => { wsReady = false; for (const s of streams.values()) s.closed = true; _scheduleReconnect(); };
  ws.onmessage = (ev) => {
    const b = new Uint8Array(ev.data); if (b.length < 5) return;
    const type = b[0], id = new DataView(b.buffer, b.byteOffset).getUint32(1, true), payload = b.subarray(5);
    if (type === F.PONG) { const p = pings.get(id); if (p) p.status = payload[0]; return; } // ICMP reply
    if (type === 0xf6) { const r = resolves.get(id); if (r) { r.ip = (payload.length >= 4 && (payload[0] || payload[1] || payload[2] || payload[3])) ? `${payload[0]}.${payload[1]}.${payload[2]}.${payload[3]}` : null; r.done = true; } return; } // RESOLVE reply
    if (type === 0xf5) { const r = listenReqs.get(id); if (r) { r.status = payload[0]; r.port = payload[1] | (payload[2] << 8); } return; } // LISTEN reply
    if (type === 0xf4) { // relay-pushed inbound connection: [lport:u16][ip:4][pport:u16]
      const lport = payload[0] | (payload[1] << 8);
      streams.set(id, { rxq: [], closed: false });
      let q = acceptQs.get(lport); if (!q) { q = []; acceptQs.set(lport, q); }
      q.push({ sid: id, ip: `${payload[2]}.${payload[3]}.${payload[4]}.${payload[5]}`, port: payload[6] | (payload[7] << 8) });
      return; }
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

// DNS: ask the RELAY to resolve the name (browsers can't: DoH is COEP-blocked here)
// and hand back the REAL A record so `ping`/tools display the true IP. We still keep
// a name<->ip map so CONNECT/PING hand the HOSTNAME to the relay (lets it re-resolve
// / do SNI). If the relay can't resolve (offline/slow), fall back to a synthetic 10.x
// so name resolution still "works" the way it used to.
const nameToIp = new Map(), ipToName = new Map(); let synth = (10 << 24) | 1;
function synthIp(name) {
  if (nameToIp.has(name)) return nameToIp.get(name);
  const n = synth++; const ip = `${(n>>>24)&255}.${(n>>>16)&255}.${(n>>>8)&255}.${n&255}`;
  nameToIp.set(name, ip); ipToName.set(ip, name); return ip;
}
async function resolveViaRelay(name) {   // -> real dotted-quad, or null if the relay can't
  for (let i = 0; i < 100 && !wsReady; i++) await sleep(5);   // ride out a reconnect (~500ms)
  if (!wsReady) return null;
  const id = nextResolve++; const rec = { ip: null, done: false }; resolves.set(id, rec);
  wispSend(0xf6, id, new TextEncoder().encode(name));
  for (let i = 0; i < 200 && !rec.done; i++) await sleep(2);   // ~400ms budget
  resolves.delete(id); return rec.done ? rec.ip : null;
}
async function ipForName(name) {         // real IP if the relay resolves it, else synthetic
  if (nameToIp.has(name)) return nameToIp.get(name);
  const real = await resolveViaRelay(name);
  if (real) { nameToIp.set(name, real); ipToName.set(real, name); return real; }
  return synthIp(name);
}
async function answerDns(query) {  // -> DNS response carrying a synthetic A record
  const parseQ = (buf, off) => { const l = []; while (buf[off]) { const n = buf[off]; l.push(String.fromCharCode(...buf.subarray(off + 1, off + 1 + n))); off += 1 + n; } return { name: l.join('.'), end: off + 1 }; };
  const id = query.subarray(0, 2);
  const { name, end } = parseQ(query, 12);
  const qtype = (query[end] << 8) | query[end + 1];
  const question = query.subarray(12, end + 4);
  // only answer A (IPv4); AAAA -> empty so glibc/musl falls back to A
  const ips = qtype === 1 ? [await ipForName(name)] : [];
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

// Host policy (sandpie secrets): while a run that uses a secret is going, the host sets
// the hosts that secret may be sent to, {t:'policy', allow:[...]}; every other outbound
// connection and ping is refused. allow:null lifts it. "*.x.com" = any subdomain of x.com.
// DNS still answers (so the refusal is a clean ECONNREFUSED, not a lookup failure).
let POLICY = null;
self.addEventListener('message', (ev) => { const d = ev.data; if (d && d.t === 'policy') POLICY = Array.isArray(d.allow) && d.allow.length ? d.allow.map((h) => String(h).toLowerCase()) : null; });
function allowedHost(host) {
  if (!POLICY) return true;
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const ok = POLICY.some((p) => (p.startsWith('*.') ? h.endsWith(p.slice(1)) : h === p));
  if (!ok) { try { self.postMessage({ t: 'refused', host: h }); } catch (_) {} }   // the host says why in the tool result
  return ok;
}

async function handle(op) {
  const a0 = ctl[3], a1 = ctl[4], a2 = ctl[5];
  if (op === OP.CONNECT) {
    for (let i = 0; i < 4000 && !wsReady; i++) await sleep(2);   // wait for (re)connect, ~8s cap
    if (!wsReady) return finish(ECONNREFUSED);
    const spec = new TextDecoder().decode(data.slice(0, a0));   // "ip|port" or "ip|port|T" (T=TLS)
    const [ip, portStr, flag] = spec.split('|');
    const host = ipToName.get(ip) || ip;  // hand the hostname to the relay (it resolves)
    if (!allowedHost(host)) return finish(ECONNREFUSED);
    const id = nextStream++; streams.set(id, { rxq: [], closed: false });
    const hb = new TextEncoder().encode(host);
    const payload = new Uint8Array(3 + hb.length); payload[0] = flag === 'T' ? 3 : 1; new DataView(payload.buffer).setUint16(1, +portStr, true); payload.set(hb, 3);
    wispSend(0x01, id, payload);
    return finish(id);
  }
  if (op === OP.PING) { // ICMP kickoff: data = "ip[|port]" spec. Swap the synthetic IP
    // back to the hostname (like CONNECT) so the relay resolves + pings it. Returns a
    // ping id immediately; the OS worker polls PINGPOLL, so nothing blocks the worker.
    for (let i = 0; i < 250 && !wsReady; i++) await sleep(2);
    const spec = new TextDecoder().decode(data.slice(0, a0)).split('|')[0];
    const host = ipToName.get(spec) || spec;
    const id = nextPing++; const rec = { status: null }; pings.set(id, rec);
    if (!allowedHost(host)) rec.status = 1;   // host policy: unreachable
    else if (wsReady) {
      const hb = new TextEncoder().encode(host);
      const p = new Uint8Array(3 + hb.length); p[0] = 0xff; new DataView(p.buffer).setUint16(1, 4000, true); p.set(hb, 3);
      wispSend(F.PING, id, p);
      setTimeout(() => { if (rec.status === null) rec.status = 1; }, 6000); // no PONG -> unreachable
    } else rec.status = 1;
    return finish(id);
  }
  if (op === OP.PINGPOLL) { const rec = pings.get(a0); if (!rec) return finish(EBADF);
    if (rec.status === null) return finish(EAGAIN);         // still in flight
    const st = rec.status; pings.delete(a0); return finish(st === 0 ? 0 : 1); } // 0 = replied
  if (op === OP.LISTEN) { // a0 = wanted port -> res = listener id, ctl[7] = actual relay port
    for (let i = 0; i < 4000 && !wsReady; i++) await sleep(2);   // wait for (re)connect, ~8s cap
    if (!wsReady) return finish(ECONNREFUSED);
    const id = nextStream++;
    const req = { status: -1, port: 0 }; listenReqs.set(id, req);
    const pl = new Uint8Array(2); pl[0] = a0 & 0xff; pl[1] = (a0 >> 8) & 0xff;
    wispSend(0xf3, id, pl);
    for (let i = 0; i < 1500 && req.status === -1; i++) await sleep(2);
    listenReqs.delete(id);
    if (req.status !== 0) return finish(-98); // EADDRINUSE
    listeners.set(id, req.port);
    if (!acceptQs.has(req.port)) acceptQs.set(req.port, []);
    ctl[7] = req.port;
    return finish(id);
  }
  if (op === OP.ACCEPT) { // a0 = listener id, a1 = probe
    const lp = listeners.get(a0); if (lp === undefined) return finish(EINVAL);
    await sleep(0); // pump inbound-connection frames
    const q = acceptQs.get(lp);
    while (!q.length) { if (a1) return finish(EAGAIN); await sleep(5); }
    const c = q.shift();
    const peer = new TextEncoder().encode(`${c.ip}|${c.port}`);
    data.set(peer, 0); ctl[7] = peer.length;
    return finish(c.sid);
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
    if (!s) return finish(EBADF);
    while (!s.rxq.length && !s.closed) await sleep(1);
    if (!s.rxq.length) return finish(0);  // closed = EOF
    let out = s.rxq.shift(); const k = Math.min(out.length, a1, data.length);   // never past the SAB window
    data.set(out.subarray(0, k), 0); if (k < out.length) s.rxq.unshift(out.subarray(k));
    return finish(k);
  }
  if (op === OP.POLL) { await sleep(0); const lp = listeners.get(a0); // pump WS events (worker blocks in Atomics.wait between ops)
    if (lp !== undefined) { const q = acceptQs.get(lp); return finish(q && q.length ? 1 : 0); }
    if (s) return finish(s.rxq.length || s.closed ? 1 : 0); const u = udpSocks.get(a0); if (u) return finish(u.rxq.length ? 1 : 0);
    return finish(1); }   // unknown id: report readable so the read fails with EBADF instead of polling for ever
  if (op === OP.CLOSE) { if (s) { wispSend(0x04, a0, new Uint8Array([0])); streams.delete(a0); } udpSocks.delete(a0); return finish(0); }
  finish(EINVAL);
}

// Message bridge (kernel without SharedArrayBuffer, see opfs-worker.js servePort):
// {t:'call', id, op, a0, a1, a2, bytes} -> {t:'reply', id, res, aux, data}, one at a time.
function servePort(port) {
  const CTL = new Int32Array(8);
  let chain = Promise.resolve();
  port.onmessage = (ev) => {
    const m = ev.data; if (!m || m.t !== 'call') return;
    chain = chain.then(async () => {
      const inb = m.bytes ? new Uint8Array(m.bytes) : null;
      ctl = CTL; ctl.fill(0);
      data = new Uint8Array(Math.max(1 << 20, inb ? inb.length : 0, (m.op === OP.RECV || m.op === OP.RECVFROM) ? (m.a1 | 0) : 0));
      if (inb) data.set(inb, 0);
      ctl[2] = m.op; ctl[3] = m.a0 | 0; ctl[4] = m.a1 | 0; ctl[5] = m.a2 | 0;
      try { await handle(m.op); } catch (e) { try { finish(-5); } catch (_) {} }   // -5 = EIO
      let n = 0;
      if ((m.op === OP.RECV || m.op === OP.RECVFROM) && ctl[6] > 0) n = Math.min(ctl[6], data.length);
      else if (m.op === OP.ACCEPT && ctl[7] > 0) n = Math.min(ctl[7], data.length);
      const out = data.slice(0, n);
      port.postMessage({ t: 'reply', id: m.id, res: ctl[6], aux: ctl[7], data: out.buffer }, [out.buffer]);
    });
  };
}

self.onmessage = async (ev) => {
  if (ev.data.t !== 'sab') return;
  RELAY = ev.data.url || defaultRelay();
  connectWS();
  self.postMessage({ ready: true });
  if (ev.data.port) { servePort(ev.data.port); return; }
  ctl = new Int32Array(ev.data.sab, 0, 8); data = new Uint8Array(ev.data.sab, 32);
  let last = 0;
  while (true) {
    // waitAsync (not the blocking Atomics.wait) so this worker's event loop stays
    // live to deliver ws.onmessage — otherwise a blocked thread never processes
    // relay->browser frames (PONG/DATA) that arrive while we're parked, which broke
    // ping (the ICMP PONG was never delivered). One op is ever in flight (the OS
    // worker blocks on the reply), so this stays a clean request/response loop.
    const r = Atomics.waitAsync(ctl, 0, last);
    if (r.async) await r.value;
    const seq = Atomics.load(ctl, 0); if (seq === last) continue; last = seq;
    if (ctl[2] === 0) break;
    // A throw inside handle() must still answer, or the kernel waits for this reply for ever.
    try { await handle(ctl[2]); } catch (e) { try { finish(-5); } catch (_) {} }   // -5 = EIO
  }
};
