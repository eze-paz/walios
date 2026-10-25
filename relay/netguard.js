// Outbound-connection safety, shared by every feature that opens a socket on
// a user-supplied address: the SSH tool and the WISP relay.
//
// Its own module so neither has to require the other — the relay pulling in
// ssh2 just to reuse one function would be silly, and worse, a deployment
// that wants only the relay would still need the SSH dependency tree.

const dns = require('dns').promises;
const net = require('net');

// ── SSRF guard (rule 2) ─────────────────────────────────────────────────────
// Block RFC1918, loopback, link-local (incl. 169.254.169.254 cloud metadata),
// CGNAT, multicast/reserved, IPv6 ULA/link-local/loopback, and v4-mapped v6.
function isBlockedIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const o = ip.split('.').map(Number);
    if (o[0] === 0 || o[0] === 10 || o[0] === 127) return true;
    if (o[0] === 169 && o[1] === 254) return true;            // link-local + metadata
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true; // CGNAT
    if (o[0] >= 224) return true;                              // multicast / reserved
    return false;
  }
  if (v === 6) {
    const lo = ip.toLowerCase();
    if (lo === '::1' || lo === '::') return true;
    if (lo.startsWith('fe80')) return true;                   // link-local
    if (lo.startsWith('fc') || lo.startsWith('fd')) return true; // ULA
    if (lo.startsWith('::ffff:')) return isBlockedIp(lo.slice(7)); // v4-mapped
    return false;
  }
  return true; // unparseable → block
}

// Resolve a hostname to a concrete PUBLIC IP and return that IP. We connect by
// the resolved IP (not the name) so a name can't pass the check then re-resolve
// to a private address (DNS-rebinding). Throws { blocked:true } on a private hit.
async function resolvePublicHost(host) {
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw blocked(host);
    return host;
  }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); }
  catch (e) { throw Object.assign(new Error(`cannot resolve host "${host}"`), { dns: true }); }
  if (!addrs || !addrs.length) throw Object.assign(new Error(`cannot resolve host "${host}"`), { dns: true });
  for (const a of addrs) if (isBlockedIp(a.address)) throw blocked(`${host} → ${a.address}`);
  // Prefer IPv4. dns.lookup returns A and AAAA in no guaranteed order, so
  // taking the first address silently picks IPv6 some of the time — and on a
  // host without IPv6 egress the connection then dies with no useful error.
  // That is exactly how this presented: apk worked, then stopped, with nothing
  // changed but which record DNS happened to list first.
  const v4 = addrs.find(a => a.family === 4);
  return (v4 || addrs[0]).address;
}
function blocked(what) {
  return Object.assign(
    new Error(`refused: "${what}" is a private/loopback/link-local address (public hosts only)`),
    { blocked: true });
}

module.exports = { isBlockedIp, resolvePublicHost };
