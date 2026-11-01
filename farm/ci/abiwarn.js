// abiwarn.js <build.log> -- prints how many printf/scanf-format warnings in a build log pass an
// argument of a different WIDTH than the format reads. On LP64 Linux size_t and long are the
// same type, so "%lu" for a size_t is harmless there; on WALI (32-bit size_t, 64-bit long) the
// call reads 8 bytes where 4 were passed. Same-width mismatches (%llu vs uint64_t) are ignored.
const fs = require('fs');
let log = ''; try { log = fs.readFileSync(process.argv[2], 'utf8'); } catch {}
const width = (t) => /long long|int64|intmax|off_t|off64_t|time_t|\blong\b/.test(t) ? 8
  : /size_t|ptrdiff|\bint\b|unsigned|int32/.test(t) ? 4 : 0;
const seen = new Set();
for (const m of log.matchAll(/^(\S+:\d+:\d+): warning: format specifies type '([^']+)' but the argument has type '([^']+)'/gm)) {
  const a = width(m[2]), b = width(m[3]);
  if (a && b && a !== b) seen.add(m[1]);  // parallel make prints a warning more than once
}
console.log(seen.size);
