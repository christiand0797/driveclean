const CACHE_NAME = 'driveclean-v2';
const urlsToCache = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const isAppShellRequest = event.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('/index.html');

  if (isAppShellRequest) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/index.html', copy)).catch(() => {});
          return response;
        })
        .catch(() => caches.match('/index.html'))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((response) => response || fetch(event.request))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(cacheNames.map((cacheName) => {
        if (cacheName !== CACHE_NAME) caches.delete(cacheName);
      }));
    })
  );
});
