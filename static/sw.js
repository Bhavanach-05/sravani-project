const CACHE_NAME = 'quantumshield-pwa-v1';
const ASSETS_TO_CACHE = [
  '/mobile',
  '/static/css/style.css',
  '/static/css/mobile.css',
  '/static/css/animations.css',
  '/static/js/web_nfc.js',
  '/static/js/ring_lwe_client.js',
  '/static/js/mobile_app.js',
  '/static/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE).catch(err => console.warn('PWA Cache non-critical fail:', err));
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Network first, fallback to cache
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
