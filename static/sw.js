const CACHE_VERSION = 'v1.1';
const CACHE_NAME = 'streetbook-v1';
const ASSETS_TO_CACHE = [
    '/static/streetbook_logo.png',
    '/static/sb.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE))
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
// --- OTA UPDATE OVERRIDE ---
// Listen for the signal from the frontend to hot-swap the active worker
self.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});
