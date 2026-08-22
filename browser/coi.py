#!/usr/bin/env python3
"""Static server with cross-origin-isolation headers (SAB needs COOP+COEP)."""
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

class H(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
ThreadingHTTPServer(('0.0.0.0', port), H).serve_forever()
