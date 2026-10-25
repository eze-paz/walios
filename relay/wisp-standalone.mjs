// Run the WISP relay on its own, without the rest of sandpie.
//
// app.js refuses to boot without SSO configured (deliberately — it must never
// come up unauthenticated), which makes it a poor way to exercise one endpoint.
// This mounts the same wisp.js on a bare http server so the relay can be
// developed and tested locally, and so a deployment that wants *only* the relay
// has a supported way to run it.
//
//   WISP_ENABLED=1 node scripts/wisp-standalone.mjs [port]
//
// Same env vars as the real thing: WISP_ALLOW_HOSTS, WISP_ALLOW_PORTS,
// WISP_ALLOW_ORIGINS, WISP_TOKEN.

import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { attachWisp } = require("./wisp.js");

const port = Number(process.argv[2] || process.env.PORT || 6970);
const server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("wisp relay: connect a WebSocket to /wisp\n");
});
attachWisp(server, console);
server.listen(port, "127.0.0.1", () => {
    console.log(`wisp relay on ws://127.0.0.1:${port}/wisp`);
    console.log(`  enabled: ${process.env.WISP_ENABLED === "1"}`);
    console.log(`  hosts:   ${process.env.WISP_ALLOW_HOSTS || "alpinelinux.org"}`);
    console.log(`  ports:   ${process.env.WISP_ALLOW_PORTS || "80,443"}`);
});
