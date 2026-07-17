// FastNotes service worker — offline app shell.
// Static assets: cache-first with background refresh. API: network only
// (ciphertext data is cached in IndexedDB by the app itself, not here).
const CACHE = 'fastnotes-v3';
const SHELL = [
  '/', '/style.css', '/app.js', '/crypto.js',
  '/vendor/marked.min.js', '/vendor/purify.min.js',
  '/fonts/noto-sans-100.woff2', '/fonts/noto-serif-700.woff2',
  '/icons/icon.svg', '/manifest.webmanifest',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.startsWith('/api/')) return; // never cache ciphertext or auth traffic

  e.respondWith(
    caches.match(e.request).then(cached => {
      const refresh = fetch(e.request).then(resp => {
        if (resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return resp;
      }).catch(() => cached);
      return cached || refresh;
    })
  );
});
