// WISP v1 relay — TCP over WebSocket, for browser VMs that need real sockets.
//
// A browser cannot open a TCP connection, so an emulated guest's network stack
// terminates TCP client-side and forwards the payload here. This end opens the
// real socket. That is the whole trick behind `apk` working inside an in-browser
// Linux VM.
//
// Protocol (WISP v1, little-endian, [type:u8][stream:u32][payload]):
//   0x01 CONNECT   c→s  [type:u8 (1=TCP)][port:u16][hostname:utf8]
//   0x02 DATA      both [bytes]
//   0x03 CONTINUE  s→c  [buffer_remaining:u32]   flow control
//   0x04 CLOSE     both [reason:u8]
// The server opens the window with a CONTINUE on stream 0; until that arrives
// the reference client (v86's wisp_network.js) buffers everything and sends
// nothing, which looks exactly like a hung relay. We never send PROTOEXT (0x05)
// — that is the v2 upgrade, and v1 clients ignore it.
//
// ── Who may use this, and to reach what ────────────────────────────────────
// The defaults are narrow because an UNAUTHENTICATED relay that connects
// anywhere on request will be found and abused. This one is not
// unauthenticated: `attachWisp` is handed a session verifier, browsers are held
// to same-origin on the handshake, and without a valid SSO session (or
// WISP_TOKEN) the upgrade is refused. Anonymous /guest visitors get no session
// cookie, so they cannot open a stream at all.
//
// So the destination allowlists are defence-in-depth against a compromised or
// careless signed-in account, not a defence against the internet. They can be
// opened deliberately:
//   * off unless WISP_ENABLED=1;
//   * destination host must match WISP_ALLOW_HOSTS (default: Alpine mirrors),
//     where a bare "*" means any host;
//   * destination port must be in WISP_ALLOW_PORTS (default: 80,443), where a
//     bare "*" means any port.
// Opening both makes this a general outbound TCP proxy for signed-in users —
// which is the point when the guest VM needs ssh, git or a mail port, and is a
// deliberate choice rather than an oversight. What it costs: connections egress
// from this host's IP, so misuse lands in someone else's abuse log as us.
//
// What does NOT relax with the allowlists, and is not env-configurable:
// `resolvePublicHost` from netguard.js resolves the name, refuses
// private/loopback/link-local addresses, and connects to the resolved IP so a
// name cannot pass the check and then re-resolve inward (DNS rebinding). The
// internal network stays unreachable however wide the allowlists are set.

// ── ICMP echo (private extension, types 0xF1/0xF2) ─────────────────────────
// A browser cannot emit ICMP, so a guest's ping has nowhere to go and the old
// answer was to fake a reply locally — which reported success for addresses
// that do not exist. Since every other packet already crosses this relay, the
// meaningful question is whether *this host* can reach the address, and that is
// the only thing these frames ask:
//   0xF1 PING  c→s  id in the stream field, payload [dst:4 bytes][timeout:u16]
//   0xF2 PONG  s→c  id in the stream field, payload [status:u8], 0 = replied
// The client owns the reply packet; we return one byte. Same gates as TCP: the
// address goes through isBlockedIp, so this cannot become an internal-network
// scanner, and concurrency is capped so it cannot become a flooder.
//
// A browser guest has no DNS of its own, so it cannot produce those four bytes
// in the first place — walios hands us the NAME and we resolve it here, exactly
// as CONNECT does. Hence a second PING payload shape, told apart by a leading
// 0xFF (never a valid first octet of a pingable address):
//   0xF1 PING  c→s  payload [0xff][timeout:u16][host:utf8]
// Without this branch the old parser read 0xff and the first bytes of the name
// as the address and pinged nonsense — `ping google.com` went to 255.160.15.103
// and every guest ping reported 100% loss.

// ── Name resolution (private extension, type 0xF6) ──────────────────────
// Same reason: the guest has no resolver and DoH is COEP-blocked in the page, so
// it asks us for the A record and falls back to a synthetic 10.x address when we
// do not answer. Every name therefore displayed as 10.0.0.x, which is a lie the
// moment anyone reads it back.
//   0xF6 RESOLVE  c→s  id in the stream field, payload [host:utf8]
//   0xF6 RESOLVE  s→c  id in the stream field, payload [a:4 bytes], all-zero = no answer
// It resolves through the same `resolvePublicHost`, so a name that resolves
// inward is refused here too and simply reports no answer.

const crypto = require('crypto');
const net = require('net');
const tls = require('tls');   // relay-side TLS termination for conntype 0x03
const { execFile } = require('child_process');
const { resolvePublicHost, isBlockedIp } = require('./netguard');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

// Per-stream credit, in DATA packets. The client decrements on send and stalls
// at zero until we replenish; we top it back up as we drain writes.
const WINDOW = 128;
const MAX_STREAMS = 32;
const MAX_FRAME = 1 << 20;

// Echoes in flight per connection. Each one is a process, so this is a much
// harder limit than the stream cap: a client that pings faster than replies
// arrive gets refusals, not an unbounded fork bomb.
const MAX_PINGS = 4;
const PING_TIMEOUT_MAX_MS = 5000;

const envList = (v, dflt) =>
  (v || dflt).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

function config() {
  return {
    enabled: process.env.WISP_ENABLED === '1',
    // Suffix match, so "alpinelinux.org" covers dl-cdn.alpinelinux.org.
    // A bare "*" in either list means "anything" — see hostAllowed/portAllowed.
    hosts: envList(process.env.WISP_ALLOW_HOSTS, 'alpinelinux.org'),
    ports: envList(process.env.WISP_ALLOW_PORTS, '80,443'),
    origins: envList(process.env.WISP_ALLOW_ORIGINS, ''),
    token: process.env.WISP_TOKEN || '',
  };
}

function hostAllowed(host, allow) {
  if (allow.includes('*')) return true;
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return allow.some(a => h === a || h.endsWith('.' + a));
}

// Ports stay as strings rather than being parsed up front, so that '*' can mean
// the same thing here as it does for hosts. Number() would have turned it into
// NaN and silently allowed nothing.
function portAllowed(port, allow) {
  return allow.includes('*') || allow.includes(String(port));
}

// ── Minimal RFC 6455 server framing ────────────────────────────────────────
// Hand-rolled rather than pulling in `ws`: this repo has no build step and
// deploys by copying files, so a new runtime dependency is a deploy hazard for
// one endpoint. Binary frames only, which is all WISP uses.

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

function encodeFrame(payload, opcode = 0x2) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode; // FIN
  return Buffer.concat([header, payload]);
}

/** Pull complete frames out of `buf`. Returns [frames, rest]. */
function decodeFrames(buf) {
  const out = [];
  let off = 0;
  for (;;) {
    if (buf.length - off < 2) break;
    const b0 = buf[off], b1 = buf[off + 1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let p = off + 2;
    if (len === 126) {
      if (buf.length - p < 2) break;
      len = buf.readUInt16BE(p);
      p += 2;
    } else if (len === 127) {
      if (buf.length - p < 8) break;
      const big = buf.readBigUInt64BE(p);
      if (big > BigInt(MAX_FRAME)) return [out, null]; // absurd: kill the socket
      len = Number(big);
      p += 8;
    }
    if (len > MAX_FRAME) return [out, null];
    let mask = null;
    if (masked) {
      if (buf.length - p < 4) break;
      mask = buf.subarray(p, p + 4);
      p += 4;
    }
    if (buf.length - p < len) break;
    const payload = Buffer.from(buf.subarray(p, p + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    out.push({ opcode, payload, fin: (b0 & 0x80) !== 0 });
    off = p + len;
  }
  return [out, buf.subarray(off)];
}

// ── The relay ──────────────────────────────────────────────────────────────

/**
 * @param server        the http.Server to hook `upgrade` on
 * @param log           console-like
 * @param verifySession optional `(req) => user|null`. When supplied, a valid
 *                      signed-in session is sufficient authorisation, which is
 *                      how this runs in sandpie: a WebSocket upgrade is an
 *                      ordinary HTTP request and carries the session cookie,
 *                      so the relay inherits SSO instead of needing a second,
 *                      separately-managed shared secret.
 */
function attachWisp(server, log = console, verifySession = null) {
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/wisp') return; // not ours; another handler may take it

    const cfg = config();
    const deny = reason => {
      log.warn?.(`[wisp] refused: ${reason}`);
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    };
    if (!cfg.enabled) return deny('WISP_ENABLED is not 1');

    // Cross-site WebSocket hijacking. Browsers attach cookies to cross-origin
    // WebSocket handshakes and there is no preflight, so authenticating by
    // session makes the Origin check MORE important, not less: without it any
    // page on the internet could open a relay stream carrying a signed-in
    // user's cookie. Hence the default below is same-origin, not "anything".
    const origin = (req.headers.origin || '').toLowerCase();
    if (cfg.origins.length) {
      if (!cfg.origins.includes(origin)) {
        return deny(`origin ${origin || '(none)'} not in WISP_ALLOW_ORIGINS`);
      }
    } else if (origin) {
      // No explicit allowlist: require the request to come from a page served
      // by this same host. An absent Origin is a non-browser client (curl, the
      // self-test) and falls through to the auth check below.
      let host;
      try { host = new URL(origin).host.toLowerCase(); } catch { host = null; }
      if (host !== (req.headers.host || '').toLowerCase()) {
        return deny(`cross-origin ${origin} (set WISP_ALLOW_ORIGINS to permit)`);
      }
    }

    // Authorisation. A valid SSO session is enough — the relay is for
    // signed-in users of this app, and reusing the session means there is no
    // second secret to distribute, rotate, or leak into a URL. WISP_TOKEN
    // stays as the escape hatch for clients that have no cookie (a VM page on
    // another origin, local development, the self-test).
    const user = verifySession ? verifySession(req) : null;
    const tokenOk = cfg.token && url.searchParams.get('token') === cfg.token;
    if (verifySession && !user && !tokenOk) {
      return deny(cfg.token ? 'no valid session and bad token' : 'no valid session');
    }
    if (!verifySession && cfg.token && !tokenOk) {
      return deny('bad or missing token');
    }
    if (user) log.log?.(`[wisp] session ${user.email || user.sub || '?'}`);
    const key = req.headers['sec-websocket-key'];
    if ((req.headers.upgrade || '').toLowerCase() !== 'websocket' || !key) {
      return socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    }

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`);
    socket.setNoDelay(true);

    const streams = new Map();
    let rx = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
    let closed = false;

    const sendFrame = buf => {
      if (!closed && socket.writable) socket.write(encodeFrame(buf));
    };
    const wisp = (type, stream, payload = Buffer.alloc(0)) => {
      const b = Buffer.alloc(5 + payload.length);
      b[0] = type;
      b.writeUInt32LE(stream >>> 0, 1);
      payload.copy(b, 5);
      sendFrame(b);
    };
    const close = (stream, reason) => wisp(0x04, stream, Buffer.from([reason]));

    const shutdown = () => {
      if (closed) return;
      closed = true;
      for (const s of streams.values()) s.sock?.destroy();
      streams.clear();
      socket.destroy();
    };

    // Open the window. Without this the client never transmits.
    wisp(0x03, 0, (() => { const b = Buffer.alloc(4); b.writeUInt32LE(WINDOW, 0); return b; })());

    async function onConnect(stream, payload) {
      if (streams.size >= MAX_STREAMS) return close(stream, 0x03);
      const kind = payload[0];
      const port = payload.readUInt16LE(1);
      const host = payload.subarray(3).toString('utf8');
      if (kind !== 0x01 && kind !== 0x03) return close(stream, 0x41); // 0x01=TCP 0x03=TLS; UDP unsupported
      if (!hostAllowed(host, cfg.hosts)) {
        log.warn?.(`[wisp] blocked host ${host}`);
        return close(stream, 0x48); // host blocked by policy
      }
      if (!portAllowed(port, cfg.ports)) {
        log.warn?.(`[wisp] blocked port ${port}`);
        return close(stream, 0x48);
      }

      // Register the stream NOW, before the DNS lookup below. A client sends
      // CONNECT and then its first DATA one round trip later, while resolving
      // the name takes however long it takes — so DATA routinely arrives while
      // this function is still awaiting, and the handler dropped it silently
      // because the stream was not in the map yet. The request was gone: the
      // guest waited out its timeout and the relay reported a connection that
      // carried nothing.
      //
      // It hid well. On a loopback relay the lookup is cached and effectively
      // instant, so the window never opens and everything works; over a real
      // network it loses every time.
      const entry = { sock: null, credit: WINDOW, rx: 0, tx: 0, pending: [] };
      streams.set(stream, entry);

      let ip;
      try {
        ip = await resolvePublicHost(host);
      } catch (e) {
        log.warn?.(`[wisp] ${host}: ${e.message}`);
        streams.delete(stream);
        return close(stream, e.blocked ? 0x48 : 0x42); // 0x42: unreachable
      }
      // Either side may have given up during the lookup.
      if (closed || !streams.has(stream)) return;

      const sock = kind === 0x03
        ? tls.connect({ host: ip, port, servername: host })   // SNI + system-CA validation, native speed
        : net.connect({ host: ip, port, servername: host });
      sock.setNoDelay(true);
      entry.sock = sock;
      // Anything that arrived while we were resolving. node buffers writes on
      // a socket that has not finished connecting, so this needs no further
      // sequencing.
      for (const chunk of entry.pending) sock.write(chunk);
      entry.pending = [];

      // Byte counters, because "connected" and "working" are different claims:
      // a stream can open cleanly and then carry nothing in either direction,
      // and from the guest that is indistinguishable from a dead network.
      // Logged on close so one failed request says which half stalled.
      sock.on('connect', () => log.log?.(`[wisp] ${stream} → ${host}:${port} (${ip})`));
      sock.on('data', d => {
        entry.rx += d.length;
        wisp(0x02, stream, d);
      });
      sock.on('error', () => {
        if (streams.delete(stream)) close(stream, 0x03);
      });
      sock.on('close', () => {
        log.log?.(`[wisp] ${stream} closed: ${entry.tx} B to host, ${entry.rx} B back`);
        if (streams.delete(stream)) close(stream, 0x02);
      });
    }

    // Echo requests currently out. Bounded by MAX_PINGS.
    let pingsInFlight = 0;

    async function onPing(id, payload) {
      const pong = status => wisp(0xf2, id, Buffer.from([status]));
      if (payload.length < 4) return pong(2);
      if (pingsInFlight >= MAX_PINGS) return pong(2);

      // Two payload shapes, and BOTH hand execFile a dotted quad by construction
      // — never a hostname, never anything that could be read as an option:
      //   legacy   [dst:4 bytes][timeout:u16]             (v86 / riscv-vm)
      //   hostname [0xff][timeout:u16][host:utf8]         (walios — no DNS in the
      //            browser, so the name is resolved HERE, like CONNECT, and only
      //            the resolved IP ever reaches ping)
      // (execFile takes an argv, so there is no shell either; belt and braces,
      // because this one is worth being sure about.)
      let ip, ms;
      if (payload[0] === 0xff) {
        ms = Math.min(payload.readUInt16LE(1) || 1000, PING_TIMEOUT_MAX_MS);
        const host = payload.subarray(3).toString('utf8');
        if (!host) return pong(2);
        try { ip = await resolvePublicHost(host); }
        catch (e) { log.warn?.(`[wisp] ping ${host}: ${e.message}`); return pong(2); }
      } else {
        if (payload.length < 6) return pong(2);
        ip = `${payload[0]}.${payload[1]}.${payload[2]}.${payload[3]}`;
        ms = Math.min(payload.readUInt16LE(4) || 1000, PING_TIMEOUT_MAX_MS);
      }
      if (isBlockedIp(ip)) {
        log.warn?.(`[wisp] blocked ping ${ip}`);
        return pong(2);
      }

      const secs = Math.max(1, Math.round(ms / 1000));

      pingsInFlight++;
      let done = false;
      execFile('ping', ['-n', '-c', '1', '-W', String(secs), ip],
        { timeout: ms + 1000 }, err => {
          if (done) return;          // guard: callback fires once, but cheap
          done = true;
          pingsInFlight--;
          // A non-zero exit is "no reply" and is a perfectly normal answer —
          // most of the internet does not respond to ping. But a missing or
          // unusable binary looks identical from here and would silently turn
          // every ping into a timeout, so say so out loud.
          if (err && (err.code === 'ENOENT' || err.code === 'EACCES')) {
            log.warn?.(`[wisp] ping unavailable (${err.code}); ICMP will always fail`);
          }
          pong(err ? 1 : 0);
        });
    }

    // Answer the guest's A-record lookup (0xF6). Same resolver, same gate as
    // CONNECT: a name that points inward throws and we answer 0.0.0.0, which the
    // client reads as "no answer" and falls back to its synthetic address.
    async function onResolve(id, payload) {
      const reply = ip => wisp(0xf6, id, ip ? Buffer.from(ip.split('.').map(Number)) : Buffer.alloc(4));
      const host = payload.toString('utf8');
      if (!host) return reply(null);
      try {
        const ip = await resolvePublicHost(host);
        // IPv6 has no place in a 4-byte A record; the client asks for A only.
        return reply(/^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip : null);
      } catch (e) {
        log.warn?.(`[wisp] resolve ${host}: ${e.message}`);
        return reply(null);
      }
    }

    function onWisp(frame) {
      const type = frame[0];
      const stream = frame.readUInt32LE(1);
      const payload = frame.subarray(5);
      switch (type) {
        case 0x01:
          onConnect(stream, payload).catch(() => close(stream, 0x03));
          break;
        case 0x02: {
          const e = streams.get(stream);
          if (!e) break;
          e.tx += payload.length;
          // The socket may not exist yet: CONNECT starts a DNS lookup and the
          // client's first DATA can beat it. Hold the bytes rather than
          // dropping them, which is what silently lost every request.
          if (e.sock) e.sock.write(payload);
          else e.pending.push(Buffer.from(payload));
          // Replenish as we consume, so a long download never stalls.
          if (--e.credit <= WINDOW / 2) {
            const b = Buffer.alloc(4);
            b.writeUInt32LE(WINDOW - e.credit, 0);
            wisp(0x03, stream, b);
            e.credit = WINDOW;
          }
          break;
        }
        case 0x04: {
          const e = streams.get(stream);
          // sock is null while the name is still resolving; deleting the entry
          // is what stops that lookup from going on to open a socket nobody
          // wants (see the `streams.has` check in onConnect).
          if (e) { streams.delete(stream); e.sock?.destroy(); }
          break;
        }
        case 0xf1:
          onPing(stream, payload).catch(() => {});
          break;
        case 0xf6:
          onResolve(stream, payload).catch(() => {});
          break;
        default:
          break; // CONTINUE/PROTOEXT from a client: not ours to act on
      }
    }

    socket.on('data', chunk => {
      rx = rx.length ? Buffer.concat([rx, chunk]) : chunk;
      const [frames, rest] = decodeFrames(rx);
      if (rest === null) return shutdown(); // oversized frame
      rx = rest;
      for (const f of frames) {
        if (f.opcode === 0x8) return shutdown();          // close
        if (f.opcode === 0x9) { sendFrame(f.payload, 0xA); continue; } // ping
        if (f.opcode !== 0x2 && f.opcode !== 0x0) continue; // binary/continuation only
        if (f.payload.length >= 5) onWisp(f.payload);
      }
    });
    socket.on('error', shutdown);
    socket.on('close', shutdown);
  });
}

module.exports = { attachWisp, decodeFrames, encodeFrame, acceptKey, hostAllowed };
