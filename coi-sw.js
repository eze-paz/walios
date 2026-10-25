// Cross-origin isolation for static hosts (GitHub Pages sends no COOP/COEP headers).
// SharedArrayBuffer -- which the kernel's worker-per-process engine needs -- is only
// available on a cross-origin-isolated page. This service worker re-serves every
// same-origin response with the two headers, and terminal.html reloads once after it
// takes control. Pages that already get the headers from their server never register it.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.cache === 'only-if-cached' && req.mode !== 'same-origin') return;
  e.respondWith(fetch(req).then((res) => {
    if (res.status === 0) return res;                       // opaque: cannot be rewritten
    const h = new Headers(res.headers);
    h.set('Cross-Origin-Embedder-Policy', 'require-corp');
    h.set('Cross-Origin-Opener-Policy', 'same-origin');
    h.set('Cross-Origin-Resource-Policy', 'same-origin');
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
  }));
});
