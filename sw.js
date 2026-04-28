/**
 * Service Worker — TrafficPanel .0090
 * Strategy: Cache-First for static assets, Network-Only for dynamic pages
 */

const CACHE_NAME   = 'trafficpanel-v5';
const CACHE_ASSETS = [
    '/assets/vendor/tailwind-3.4.17.css',
    '/assets/vendor/chart-4.4.2.umd.js',
    '/assets/vendor/alpine-3.15.11.min.js',
    '/assets/style.css',
    '/favicon.ico',
    '/assets/favicon-16x16.png',
    '/assets/favicon-32x32.png',
    '/assets/apple-touch-icon.png',
    '/assets/android-chrome-192x192.png',
    '/assets/android-chrome-512x512.png',
    '/assets/maskable-icon-192x192.png'
];

// ── Install: pre-cache static assets (graceful, skip failing ones) ──
self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => Promise.all(
                CACHE_ASSETS.map(url =>
                    cache.add(url).catch(err => {
                        console.warn('[SW] skip cache:', url, err.message || err);
                    })
                )
            ))
            .then(() => self.skipWaiting())
    );
});

// ── Activate: clear old caches ──
self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys
                .filter(k => k !== CACHE_NAME)
                .map(k => caches.delete(k))
            )
        ).then(() => self.clients.claim())
    );
});

// ── Fetch: routing strategy ──
self.addEventListener('fetch', e => {
    const url = new URL(e.request.url);

    // Ignore: non-GET, chrome-extension, go.php (redirect engine)
    if (e.request.method !== 'GET') return;
    if (url.pathname === '/go.php')  return;
    if (url.pathname.startsWith('/go')) return;

    // POST API calls — bypass cache
    if (e.request.method === 'POST') return;

    // Skip cross-origin requests (CDN) — let the browser handle directly
    if (url.hostname !== self.location.hostname) return;

    // Static assets (css, js, ico, png) → Cache-First
    const isAsset = /\.(css|js|ico|png|jpg|svg|woff2?)(\?|$)/.test(url.pathname);
    if (isAsset) {
        e.respondWith(
            caches.match(e.request).then(cached => {
                return cached || fetch(e.request).then(res => {
                    if (res.ok) {
                        const clone = res.clone();
                        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
                    }
                    return res;
                }).catch(() => new Response('', { status: 503 }));
            })
        );
        return;
    }

    // Dynamic pages and PHP routes must stay fresh because they can embed session state and CSRF tokens.
    e.respondWith(
        fetch(e.request)
            .catch(() => new Response('', { status: 503 }))
    );
});
