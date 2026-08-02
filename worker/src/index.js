/* Web Push backend for johnrua.com, running on Cloudflare Workers.
 *
 * Routes (same-origin, so no CORS needed from the site itself):
 *   POST /api/push/subscribe    - store a PushSubscription
 *   POST /api/push/unsubscribe  - remove one
 *   POST /api/push/send         - broadcast (Bearer PUSH_ADMIN_TOKEN)
 *
 * Workers has no Node crypto and can't run the `web-push` package, so VAPID
 * signing (RFC 8292) and payload encryption (RFC 8291, aes128gcm) are
 * implemented directly on WebCrypto below.
 */

const KEY_PREFIX = 'sub:';

/* ------------------------------------------------------------- encoding */

const utf8 = new TextEncoder();

function b64urlEncode(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

/* ----------------------------------------------------------------- HKDF */

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

// Single-block HKDF (RFC 5869) — every output we need is <= 32 bytes.
async function hkdf(salt, ikm, info, length) {
  const prk = await hmac(salt, ikm);
  const okm = await hmac(prk, concat(info, new Uint8Array([1])));
  return okm.slice(0, length);
}

/* ----------------------------------------------------------- VAPID (JWT) */

async function importVapidPrivateKey(publicKeyB64, privateKeyB64) {
  const pub = b64urlDecode(publicKeyB64);   // 65 bytes: 0x04 || X || Y
  const priv = b64urlDecode(privateKeyB64); // 32 bytes
  if (pub.length !== 65 || pub[0] !== 0x04) throw new Error('VAPID public key must be 65-byte uncompressed P-256');
  if (priv.length !== 32) throw new Error('VAPID private key must be 32 bytes');

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: b64urlEncode(pub.slice(1, 33)),
    y: b64urlEncode(pub.slice(33, 65)),
    d: b64urlEncode(priv),
    ext: true
  };
  return crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
}

async function createVapidToken(endpoint, subject, publicKeyB64, privateKeyB64) {
  const aud = new URL(endpoint).origin;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = {
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60, // 12h; spec caps at 24h
    sub: subject
  };

  const signingInput = utf8.encode(
    b64urlEncode(utf8.encode(JSON.stringify(header))) + '.' +
    b64urlEncode(utf8.encode(JSON.stringify(payload)))
  );

  const key = await importVapidPrivateKey(publicKeyB64, privateKeyB64);
  // WebCrypto emits P1363 (raw r||s), which is exactly what JWS ES256 wants.
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, signingInput
  );

  return new TextDecoder().decode(signingInput) + '.' + b64urlEncode(sig);
}

/* ------------------------------------------- payload encryption (RFC 8291) */

async function encryptPayload(plaintext, uaPublicB64, authSecretB64) {
  const uaPublic = b64urlDecode(uaPublicB64);   // 65 bytes
  const authSecret = b64urlDecode(authSecretB64); // 16 bytes

  // Ephemeral application-server ECDH keypair, fresh per message.
  const asKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));

  const uaKey = await crypto.subtle.importKey(
    'raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: uaKey }, asKeys.privateKey, 256
  ));

  // IKM: salt is the subscription's auth secret, info binds both public keys.
  const keyInfo = concat(
    utf8.encode('WebPush: info'), new Uint8Array([0]), uaPublic, asPublic
  );
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, concat(utf8.encode('Content-Encoding: aes128gcm'), new Uint8Array([0])), 16);
  const nonce = await hkdf(salt, ikm, concat(utf8.encode('Content-Encoding: nonce'), new Uint8Array([0])), 12);

  // 0x02 is the last-record delimiter for a single-record message.
  const padded = concat(utf8.encode(plaintext), new Uint8Array([2]));

  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, padded
  ));

  // aes128gcm header: salt(16) || rs(4, BE) || idlen(1) || keyid(=as_public)
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);

  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ciphertext);
}

/* ---------------------------------------------------------------- sending */

async function sendPush(subscription, payload, env, ttl = 86400) {
  const body = await encryptPayload(payload, subscription.keys.p256dh, subscription.keys.auth);
  const jwt = await createVapidToken(
    subscription.endpoint,
    env.VAPID_SUBJECT || 'mailto:jrua89@gmail.com',
    env.VAPID_PUBLIC_KEY,
    env.VAPID_PRIVATE_KEY
  );

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(body.length),
      TTL: String(ttl),
      Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body
  });
}

/* ------------------------------------------------------------------ utils */

async function subKey(endpoint) {
  const digest = await crypto.subtle.digest('SHA-256', utf8.encode(endpoint));
  return KEY_PREFIX + b64urlEncode(digest).slice(0, 32);
}

function isValidSubscription(sub) {
  return Boolean(
    sub && typeof sub.endpoint === 'string' && sub.endpoint.startsWith('https://') &&
    sub.keys && typeof sub.keys.p256dh === 'string' && typeof sub.keys.auth === 'string'
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

// Constant-time compare so the admin token can't be recovered by timing.
function safeEqual(a, b) {
  const ab = utf8.encode(a);
  const bb = utf8.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/* --------------------------------------------------------------- handlers */

async function handleSubscribe(request, env) {
  const sub = await request.json().catch(() => null);
  if (!isValidSubscription(sub)) return json({ error: 'Invalid subscription object' }, 400);

  await env.SUBSCRIPTIONS.put(await subKey(sub.endpoint), JSON.stringify({
    endpoint: sub.endpoint,
    keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
    userAgent: request.headers.get('user-agent') || null,
    updatedAt: new Date().toISOString()
  }));

  return json({ ok: true }, 201);
}

async function handleUnsubscribe(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.endpoint !== 'string') return json({ error: 'Missing endpoint' }, 400);

  await env.SUBSCRIPTIONS.delete(await subKey(body.endpoint));
  return json({ ok: true });
}

async function handleSend(request, env) {
  const auth = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!env.PUSH_ADMIN_TOKEN || !safeEqual(auth, env.PUSH_ADMIN_TOKEN)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json().catch(() => null);
  if (!body || !body.title) return json({ error: 'title is required' }, 400);

  const payload = JSON.stringify({
    title: body.title,
    body: body.body || '',
    url: body.url || '/',
    icon: body.icon || '/android-chrome-192x192.png',
    badge: body.badge || '/favicon-32x32.png',
    tag: body.tag || 'jr-notification',
    actions: body.actions || []
  });

  const listed = await env.SUBSCRIPTIONS.list({ prefix: KEY_PREFIX });
  let sent = 0, removed = 0, failed = 0;

  for (const entry of listed.keys) {
    const raw = await env.SUBSCRIPTIONS.get(entry.name);
    if (!raw) continue;
    const sub = JSON.parse(raw);

    try {
      const res = await sendPush(sub, payload, env);
      if (res.status >= 200 && res.status < 300) {
        sent++;
      } else if (res.status === 404 || res.status === 410) {
        // Browser dropped the subscription — prune it.
        await env.SUBSCRIPTIONS.delete(entry.name);
        removed++;
      } else {
        failed++;
        console.error('Push failed', res.status, await res.text().catch(() => ''));
      }
    } catch (err) {
      failed++;
      console.error('Push threw', err && err.message);
    }
  }

  return json({ sent, removed, failed });
}

/* ----------------------------------------------------------------- blog */

const MEDIUM_FEED = 'https://medium.com/feed/@Jrua89';
// How long the edge holds the feed. Short enough that a new Medium post shows
// up promptly; long enough that traffic never approaches the free-tier limits.
const FEED_TTL = 300; // 5 minutes

// Medium's RSS feed sends no CORS headers, so the browser can't fetch it
// directly. Proxying it here keeps the request same-origin (no CSP entry
// needed) and removes the dependency on a third-party CORS proxy.
async function handleBlog(request, env, ctx) {
  const cache = caches.default;
  const cacheKey = new Request(new URL('/api/blog', request.url).toString(), { method: 'GET' });

  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  const upstream = await fetch(MEDIUM_FEED, {
    headers: { 'User-Agent': 'johnrua.com feed reader' },
    cf: { cacheTtl: FEED_TTL, cacheEverything: true }
  });

  if (!upstream.ok) {
    return json({ error: 'Upstream feed unavailable', status: upstream.status }, 502);
  }

  const xml = await upstream.text();
  const res = new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=' + FEED_TTL
    }
  });

  if (ctx && ctx.waitUntil) ctx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

/* ------------------------------------------------------------------ entry */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      // Read-only feed proxy.
      if (url.pathname === '/api/blog') {
        if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
        return await handleBlog(request, env, ctx);
      }

      if (!url.pathname.startsWith('/api/push/')) {
        return json({ error: 'Not found' }, 404);
      }
      if (request.method !== 'POST') {
        return json({ error: 'Method not allowed' }, 405);
      }

      switch (url.pathname) {
        case '/api/push/subscribe':   return await handleSubscribe(request, env);
        case '/api/push/unsubscribe': return await handleUnsubscribe(request, env);
        case '/api/push/send':        return await handleSend(request, env);
        default:                      return json({ error: 'Not found' }, 404);
      }
    } catch (err) {
      console.error('Unhandled error', err && err.stack);
      return json({ error: 'Internal error' }, 500);
    }
  }
};
