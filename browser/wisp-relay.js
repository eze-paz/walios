// Minimal WISP v1 relay: WebSocket <-> real TCP. Lets the browser OS open TCP
// (browsers can't do raw sockets). Frame = [type:u8][stream_id:u32le][payload].
//   CONNECT 0x01: payload [conntype:u8(1=TCP)][port:u16le][hostname utf8]
//   DATA    0x02: raw bytes (both directions)
//   CONTINUE0x03: [bufremaining:u32le]  (server->client flow control)
//   CLOSE   0x04: [reason:u8]
// Run:  node wisp-relay.js [port]   (default 8790)
'use strict';
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { execFile } = require('child_process');
const PORT = +process.argv[2] || 8790;

// tiny WebSocket server (RFC6455, no deps)
const server = http.createServer((_, res) => { res.writeHead(200); res.end('wisp-relay\n'); });
server.on('upgrade', (req, sock) => {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
  handleWisp(sock);
});
server.listen(PORT, () => console.log(`[wisp-relay] ws://localhost:${PORT}`));

// --- WebSocket framing (server side: send unmasked, recv masked) ---
function wsSend(sock, data) {
  const len = data.length; let hdr;
  if (len < 126) hdr = Buffer.from([0x82, len]);
  else if (len < 65536) { hdr = Buffer.alloc(4); hdr[0] = 0x82; hdr[1] = 126; hdr.writeUInt16BE(len, 2); }
  else { hdr = Buffer.alloc(10); hdr[0] = 0x82; hdr[1] = 127; hdr.writeBigUInt64BE(BigInt(len), 2); }
  sock.write(Buffer.concat([hdr, data]));
}
function wsFrames(buf, onMsg, state) {
  state.buf = Buffer.concat([state.buf, buf]);
  for (;;) {
    const b = state.buf; if (b.length < 2) return;
    const op = b[0] & 0x0f, masked = b[1] & 0x80; let len = b[1] & 0x7f, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    let mask; if (masked) { if (b.length < off + 4) return; mask = b.subarray(off, off + 4); off += 4; }
    if (b.length < off + len) return;
    let payload = b.subarray(off, off + len);
    if (masked) { payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3]; }
    state.buf = b.subarray(off + len);
    if (op === 0x8) { onMsg(null); return; } // close
    if (op === 0x1 || op === 0x2) onMsg(payload);
  }
}

// This box's system DNS is dead for node (EAI_AGAIN); resolve via DoH.
async function resolveHost(host) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
  try { const r = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: 'application/dns-json' } });
    const j = await r.json(); const a = (j.Answer || []).filter(x => x.type === 1); if (a.length) return a[0].data; } catch {}
  return host;
}

// --- WISP handling ---
function handleWisp(sock) {
  const streams = new Map();
  const listeners = new Map();       // listen-request id -> net.Server
  let serverStreamNext = 1;          // relay-owned (pushed) stream ids: high bit set
  const state = { buf: Buffer.alloc(0) };
  const sendFrame = (type, id, payload = Buffer.alloc(0)) => {
    const f = Buffer.alloc(5 + payload.length); f[0] = type; f.writeUInt32LE(id >>> 0, 1); payload.copy(f, 5); wsSend(sock, f);
  };
  // initial CONTINUE on stream 0 (advertise buffer)
  sendFrame(0x03, 0, (() => { const p = Buffer.alloc(4); p.writeUInt32LE(1024, 0); return p; })());
  sock.on('data', (d) => wsFrames(d, (msg) => {
    if (msg === null) { for (const s of streams.values()) if (s.sock) s.sock.destroy(); sock.end(); return; }
    const type = msg[0], id = msg.readUInt32LE(1), payload = msg.subarray(5);
    if (type === 0x01) { // CONNECT — resolve (DoH) then connect; buffer early DATA
      const conntype = payload[0], port = payload.readUInt16LE(1), host = payload.subarray(3).toString('utf8');
      if (conntype !== 1) { sendFrame(0x04, id, Buffer.from([0x41])); return; } // only TCP
      const st = { sock: null, pending: [], closed: false }; streams.set(id, st);
      resolveHost(host).then((ip) => {
        if (st.closed) return; console.error(`[relay] CONNECT ${id} -> ${host} (${ip}):${port}`);
        const s = net.connect({ host: ip, port }, () => { for (const b of st.pending) s.write(b); st.pending = []; });
        st.sock = s;
        s.on('data', (b) => sendFrame(0x02, id, b));
        s.on('close', () => { sendFrame(0x04, id, Buffer.from([0x02])); streams.delete(id); });
        s.on('error', (e) => { console.error(`[relay] ${id} error ${e.code}`); sendFrame(0x04, id, Buffer.from([0x03])); streams.delete(id); });
      });
    } else if (type === 0x02) { const st = streams.get(id); if (st) { if (st.sock && st.sock.writable) st.sock.write(payload); else st.pending.push(payload); } }
    else if (type === 0x04) { const st = streams.get(id); if (st) { st.closed = true; if (st.sock) st.sock.destroy(); } streams.delete(id); }
    else if (type === 0xf3) { // LISTEN (our extension): payload [port:u16le]. Inbound conns
      // become relay-pushed streams announced with 0xf4 (id = new stream id,
      // payload [lport:u16][ip:4][pport:u16]); reply here is 0xf5 [status][actualPort:u16].
      const wantPort = payload.readUInt16LE(0);
      const srv = net.createServer((c) => {
        const sid = (0x80000000 | (serverStreamNext++ & 0x7fffffff)) >>> 0;
        const st = { sock: c, pending: [], closed: false }; streams.set(sid, st);
        const ann = Buffer.alloc(8); ann.writeUInt16LE(srv.address().port, 0);
        const oct = (c.remoteAddress || '0.0.0.0').replace(/^::ffff:/, '').split('.').map(Number);
        for (let i = 0; i < 4; i++) ann[2 + i] = oct[i] | 0;
        ann.writeUInt16LE(c.remotePort || 0, 6);
        sendFrame(0xf4, sid, ann);
        c.on('data', (b) => sendFrame(0x02, sid, b));
        c.on('close', () => { sendFrame(0x04, sid, Buffer.from([0x02])); streams.delete(sid); });
        c.on('error', () => { sendFrame(0x04, sid, Buffer.from([0x03])); streams.delete(sid); });
      });
      srv.on('error', () => { const r = Buffer.alloc(3); r[0] = 1; sendFrame(0xf5, id, r); });
      srv.listen(wantPort, () => {
        console.error(`[relay] LISTEN ${id} on :${srv.address().port}`);
        listeners.set(id, srv);
        const r = Buffer.alloc(3); r[0] = 0; r.writeUInt16LE(srv.address().port, 1);
        sendFrame(0xf5, id, r);
      });
    }
    else if (type === 0xf1) { // PING (ICMP echo). Two payload shapes (mirror the prod relay):
      //   legacy   [dst:4][timeout:u16]              (v86 / riscv-vm)
      //   hostname [0xff][timeout:u16][host:utf8]    (walios — DNS resolved here)
      const pong = (status) => sendFrame(0xf2, id, Buffer.from([status]));
      const doPing = (ip, ms) => {
        const secs = Math.max(1, Math.round(ms / 1000));
        execFile('ping', ['-n', '-c', '1', '-W', String(secs), ip], { timeout: ms + 1000 }, (err) => {
          if (err && (err.code === 'ENOENT' || err.code === 'EACCES')) console.error(`[relay] ping unavailable (${err.code})`);
          pong(err ? 1 : 0);
        });
      };
      if (payload.length >= 4 && payload[0] === 0xff) {
        const ms = payload.readUInt16LE(1) || 1000, host = payload.subarray(3).toString('utf8');
        resolveHost(host).then((ip) => doPing(ip, ms)).catch(() => pong(2));
      } else if (payload.length >= 6) {
        doPing(`${payload[0]}.${payload[1]}.${payload[2]}.${payload[3]}`, payload.readUInt16LE(4) || 1000);
      } else pong(2);
    }
  }, state));
  sock.on('close', () => { for (const s of streams.values()) if (s.sock) s.sock.destroy(); for (const l of listeners.values()) l.close(); });
  sock.on('error', () => {});
}
