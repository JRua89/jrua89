/* Service worker for johnrua.com
   - Precaches the app shell so the site is installable and works offline
   - Network-first for navigations, cache-first for static assets
   - Handles Web Push + notification clicks
*/

const VERSION = 'v1';
const PRECACHE = `jr-precache-${VERSION}`;
const RUNTIME = `jr-runtime-${VERSION}`;

const OFFLINE_URL = '/offline.html';

// Kept small on purpose: if any one of these 404s, install() rejects and the
// service worker never activates.
const PRECACHE_URLS = [
  '/',
  '/index.html',
  OFFLINE_URL,
  '/site.webmanifest',
  '/email.min.js',
  '/favicon.ico',
  '/favicon-32x32.png',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
  '/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(PRECACHE);
    // addAll() is all-or-nothing; add individually so one bad URL can't brick install.
    await Promise.all(PRECACHE_URLS.map((url) =>
      cache.add(new Request(url, { cache: 'reload' })).catch(() => {})
    ));
    // The offline page is the one entry we genuinely require.
    await cache.add(new Request(OFFLINE_URL, { cache: 'reload' }));
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    if (self.registration.navigationPreload) {
      await self.registration.navigationPreload.enable();
    }
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k !== PRECACHE && k !== RUNTIME).map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // let cross-origin go to the network

  // Navigations: network first, fall back to cached shell, then offline page.
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const preload = await event.preloadResponse;
        if (preload) return preload;

        const fresh = await fetch(req);
        const cache = await caches.open(RUNTIME);
        cache.put(req, fresh.clone());
        return fresh;
      } catch (err) {
        const cached = (await caches.match(req)) || (await caches.match('/index.html'));
        return cached || (await caches.match(OFFLINE_URL));
      }
    })());
    return;
  }

  // Static assets: cache first, refresh in the background.
  event.respondWith((async () => {
    const cached = await caches.match(req);
    if (cached) {
      event.waitUntil((async () => {
        try {
          const fresh = await fetch(req);
          if (fresh && fresh.status === 200) {
            const cache = await caches.open(RUNTIME);
            await cache.put(req, fresh);
          }
        } catch (err) { /* offline: keep the cached copy */ }
      })());
      return cached;
    }

    try {
      const fresh = await fetch(req);
      if (fresh && fresh.status === 200 && fresh.type === 'basic') {
        const cache = await caches.open(RUNTIME);
        cache.put(req, fresh.clone());
      }
      return fresh;
    } catch (err) {
      return Response.error();
    }
  })());
});

/* ---------------------------------------------------------------- Web Push */

self.addEventListener('push', (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch (err) {
      payload = { body: event.data.text() };
    }
  }

  const title = payload.title || 'John Rua';
  const options = {
    body: payload.body || '',
    icon: payload.icon || '/android-chrome-192x192.png',
    badge: payload.badge || '/favicon-32x32.png',
    image: payload.image,
    tag: payload.tag || 'jr-notification',
    renotify: Boolean(payload.tag),
    requireInteraction: Boolean(payload.requireInteraction),
    silent: Boolean(payload.silent),
    timestamp: payload.timestamp || Date.now(),
    data: { url: payload.url || '/', ...(payload.data || {}) },
    actions: payload.actions || []
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const target = new URL(
    (event.action && event.notification.data && event.notification.data[event.action]) ||
      (event.notification.data && event.notification.data.url) ||
      '/',
    self.location.origin
  ).href;

  event.waitUntil((async () => {
    const allClients = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    });

    for (const client of allClients) {
      if (client.url === target && 'focus' in client) return client.focus();
    }
    for (const client of allClients) {
      if ('navigate' in client && 'focus' in client) {
        await client.focus();
        return client.navigate(target);
      }
    }
    return self.clients.openWindow(target);
  })());
});

// Re-subscribe if the push service rotates the subscription out from under us.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil((async () => {
    const oldSub = event.oldSubscription || (await self.registration.pushManager.getSubscription());
    const appServerKey = (event.oldSubscription && event.oldSubscription.options.applicationServerKey) ||
      (oldSub && oldSub.options && oldSub.options.applicationServerKey);
    if (!appServerKey) return;

    const newSub = await self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: appServerKey
    });

    // Same-origin: the Cloudflare Worker is routed at /api/push/* on this host.
    try {
      await fetch('/api/push/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSub)
      });
    } catch (err) { /* backend not reachable; subscription still works locally */ }
  })());
});
