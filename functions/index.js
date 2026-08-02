/* Web Push backend for johnrua.com
 *
 * Endpoints (wired to /api/push/* by the rewrites in firebase.json):
 *   POST /api/push/subscribe    - store a PushSubscription
 *   POST /api/push/unsubscribe  - remove one
 *   POST /api/push/send         - fan out a notification (admin token required)
 *
 * Secrets are read from Secret Manager in production and from
 * functions/.env.local under the emulator. Nothing key-shaped is hardcoded.
 */

const crypto = require('crypto');
const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { setGlobalOptions } = require('firebase-functions/v2');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const webpush = require('web-push');

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({ region: 'us-central1', maxInstances: 10 });

const VAPID_PUBLIC_KEY = defineSecret('VAPID_PUBLIC_KEY');
const VAPID_PRIVATE_KEY = defineSecret('VAPID_PRIVATE_KEY');
// Shared bearer token so only you can trigger a broadcast.
const PUSH_ADMIN_TOKEN = defineSecret('PUSH_ADMIN_TOKEN');

const COLLECTION = 'pushSubscriptions';
const ALLOWED_ORIGINS = ['https://johnrua.com', 'https://www.johnrua.com'];

/* ------------------------------------------------------------------ helpers */

function applyCors(req, res) {
  const origin = req.get('origin');
  // Allow the production origins, plus localhost during development.
  if (ALLOWED_ORIGINS.includes(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin || '')) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.set('Access-Control-Max-Age', '3600');
}

// Firestore document IDs can't contain '/', and push endpoints are long URLs,
// so key documents by a hash of the endpoint instead.
function docIdFor(endpoint) {
  return crypto.createHash('sha256').update(endpoint).digest('hex').slice(0, 40);
}

function isValidSubscription(sub) {
  return Boolean(
    sub &&
    typeof sub.endpoint === 'string' &&
    /^https:\/\//.test(sub.endpoint) &&
    sub.keys &&
    typeof sub.keys.p256dh === 'string' &&
    typeof sub.keys.auth === 'string'
  );
}

function configureWebPush() {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:jrua89@gmail.com',
    VAPID_PUBLIC_KEY.value(),
    VAPID_PRIVATE_KEY.value()
  );
}

/* --------------------------------------------------------------- subscribe */

exports.pushSubscribe = onRequest(
  { secrets: [VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY], cors: false },
  async (req, res) => {
    applyCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).send('');
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const sub = req.body;
    if (!isValidSubscription(sub)) {
      return res.status(400).json({ error: 'Invalid subscription object' });
    }

    try {
      const id = docIdFor(sub.endpoint);
      await db.collection(COLLECTION).doc(id).set(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
          expirationTime: sub.expirationTime || null,
          userAgent: req.get('user-agent') || null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

      logger.info('Subscription stored', { id });
      return res.status(201).json({ ok: true, id });
    } catch (err) {
      logger.error('Failed to store subscription', err);
      return res.status(500).json({ error: 'Could not store subscription' });
    }
  }
);

/* ------------------------------------------------------------- unsubscribe */

exports.pushUnsubscribe = onRequest({ cors: false }, async (req, res) => {
  applyCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).send('');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const endpoint = req.body && req.body.endpoint;
  if (!endpoint || typeof endpoint !== 'string') {
    return res.status(400).json({ error: 'Missing endpoint' });
  }

  try {
    await db.collection(COLLECTION).doc(docIdFor(endpoint)).delete();
    return res.status(200).json({ ok: true });
  } catch (err) {
    logger.error('Failed to delete subscription', err);
    return res.status(500).json({ error: 'Could not remove subscription' });
  }
});

/* --------------------------------------------------------------------- send */

exports.pushSend = onRequest(
  { secrets: [VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, PUSH_ADMIN_TOKEN], cors: false },
  async (req, res) => {
    applyCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).send('');
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // Constant-time comparison so the token can't be guessed by timing.
    const provided = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const expected = PUSH_ADMIN_TOKEN.value();
    const providedBuf = Buffer.from(provided);
    const expectedBuf = Buffer.from(expected);
    const authorized =
      providedBuf.length === expectedBuf.length &&
      crypto.timingSafeEqual(providedBuf, expectedBuf);

    if (!authorized) {
      logger.warn('Rejected unauthorized send attempt');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { title, body, url, icon, badge, tag, actions } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title is required' });

    configureWebPush();

    const payload = JSON.stringify({
      title,
      body: body || '',
      url: url || '/',
      icon: icon || '/android-chrome-192x192.png',
      badge: badge || '/favicon-32x32.png',
      tag: tag || 'jr-notification',
      actions: actions || []
    });

    const snapshot = await db.collection(COLLECTION).get();
    if (snapshot.empty) return res.status(200).json({ sent: 0, removed: 0 });

    let sent = 0;
    const stale = [];

    await Promise.all(
      snapshot.docs.map(async (doc) => {
        const data = doc.data();
        const subscription = {
          endpoint: data.endpoint,
          keys: data.keys
        };

        try {
          await webpush.sendNotification(subscription, payload, { TTL: 60 * 60 * 24 });
          sent++;
        } catch (err) {
          // 404/410 mean the browser dropped the subscription — prune it so the
          // list doesn't fill up with dead endpoints.
          if (err.statusCode === 404 || err.statusCode === 410) {
            stale.push(doc.ref.delete());
          } else {
            logger.error('Send failed', { status: err.statusCode, body: err.body });
          }
        }
      })
    );

    await Promise.all(stale);

    logger.info('Broadcast complete', { sent, removed: stale.length });
    return res.status(200).json({ sent, removed: stale.length });
  }
);
