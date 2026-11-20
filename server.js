import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const baseUrl = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const secret = process.env.SESSION_SECRET || '';
const merchantId = process.env.ZARINPAL_MERCHANT_ID || '';
const sandbox = String(process.env.ZARINPAL_SANDBOX || 'true').toLowerCase() === 'true';
const monthlyPrice = Number(process.env.WALTRIX_MONTHLY_PRICE_TOMAN || 0);
const yearlyPrice = Number(process.env.WALTRIX_YEARLY_PRICE_TOMAN || 0);
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'waltrix.sqlite');
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, plan TEXT NOT NULL,
 amount_rial INTEGER NOT NULL, status TEXT NOT NULL,
 authority TEXT UNIQUE, ref_id TEXT, created_at INTEGER NOT NULL, paid_at INTEGER
);
CREATE TABLE IF NOT EXISTS subscriptions (
 session_id TEXT PRIMARY KEY, plan TEXT NOT NULL, expires_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

function sign(value) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function getSession(req, res) {
  const raw = req.headers.cookie || '';
  const part = raw.split(';').map(x => x.trim()).find(x => x.startsWith('wx_session='));
  if (part) {
    const token = decodeURIComponent(part.slice('wx_session='.length));
    const [id, sig] = token.split('.');
    if (id && sig && safeEqual(sig, sign(id)) && db.prepare('SELECT id FROM sessions WHERE id=?').get(id)) return id;
  }
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO sessions(id,created_at) VALUES(?,?)').run(id, Date.now());
  res.cookie('wx_session', `${id}.${sign(id)}`, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 365, path: '/'
  });
  return id;
}
function originAllowed(req) {
  const origin = req.get('origin');
  return !origin || (baseUrl && origin === baseUrl);
}
function paymentApi(pathname) {
  return sandbox ? `https://sandbox.zarinpal.com/pg/v4${pathname}` : `https://api.zarinpal.com/pg/v4${pathname}`;
}
function payUrl(authority) {
  const host = sandbox ? 'https://sandbox.zarinpal.com' : 'https://www.zarinpal.com';
  return `${host}/pg/StartPay/${encodeURIComponent(authority)}`;
}
function publicConfig() {
  return {
    provider: 'zarinpal', sandbox,
    monthly: { enabled: monthlyPrice > 0, priceToman: monthlyPrice },
    yearly: { enabled: yearlyPrice > 0, priceToman: yearlyPrice },
    cryptoEnabled: false
  };
}
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'WALTRIX payments', mode: sandbox ? 'sandbox' : 'live' }));
app.get('/api/payment/config', (_req, res) => res.json(publicConfig()));

app.post('/api/payment/zarinpal/create', async (req, res) => {
  try {
    if (!originAllowed(req)) return res.status(403).json({ error: 'درخواست از مبدأ غیرمجاز رد شد.' });
    if (!baseUrl || !/^https:\/\//i.test(baseUrl)) return res.status(503).json({ error: 'نشانی HTTPS سایت هنوز تنظیم نشده است.' });
    if (!merchantId) return res.status(503).json({ error: 'شناسه پذیرنده زرین‌پال هنوز در تنظیمات سرور ثبت نشده است.' });
    const plan = req.body?.plan;
    const amountToman = plan === 'monthly' ? monthlyPrice : plan === 'yearly' ? yearlyPrice : 0;
    if (!Number.isSafeInteger(amountToman) || amountToman <= 0) return res.status(400).json({ error: 'این پلن هنوز قیمت‌گذاری و فعال نشده است.' });
    const amountRial = amountToman * 10;
    if (!Number.isSafeInteger(amountRial) || amountRial < 1000) return res.status(400).json({ error: 'مبلغ پرداخت معتبر نیست.' });
    const sessionId = getSession(req, res);
    const orderId = crypto.randomUUID();
    db.prepare('INSERT INTO orders(id,session_id,plan,amount_rial,status,created_at) VALUES(?,?,?,?,?,?)')
      .run(orderId, sessionId, plan, amountRial, 'pending', Date.now());
    const callback = `${baseUrl}/api/payment/zarinpal/callback?order=${encodeURIComponent(orderId)}`;
    const response = await fetch(paymentApi('/payment/request.json'), {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ merchant_id: merchantId, amount: amountRial, callback_url: callback,
        description: `WALTRIX subscription ${plan} order ${orderId}` })
    });
    const data = await response.json();
    const authority = data?.data?.authority;
    if (!response.ok || data?.data?.code !== 100 || !authority) {
      db.prepare('UPDATE orders SET status=? WHERE id=?').run('failed', orderId);
      return res.status(502).json({ error: 'درخواست ساخت پرداخت از درگاه ناموفق بود.' });
    }
    db.prepare('UPDATE orders SET authority=? WHERE id=?').run(authority, orderId);
    return res.json({ redirectUrl: payUrl(authority) });
  } catch (err) {
    console.error('payment create error:', err?.message || err);
    return res.status(500).json({ error: 'خطای داخلی هنگام ساخت پرداخت.' });
  }
});

app.get('/api/payment/zarinpal/callback', async (req, res) => {
  const orderId = String(req.query.order || '');
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(orderId);
  if (!order) return res.status(404).send('سفارش پیدا نشد.');
  if (order.status === 'paid') return res.redirect(`${baseUrl}/?payment=success`);
  if (String(req.query.Status || '').toUpperCase() !== 'OK' || !req.query.Authority || req.query.Authority !== order.authority) {
    db.prepare("UPDATE orders SET status='failed' WHERE id=? AND status='pending'").run(orderId);
    return res.redirect(`${baseUrl}/?payment=failed`);
  }
  try {
    const response = await fetch(paymentApi('/payment/verify.json'), {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ merchant_id: merchantId, amount: order.amount_rial, authority: order.authority })
    });
    const data = await response.json();
    if (!response.ok || data?.data?.code !== 100) {
      db.prepare("UPDATE orders SET status='failed' WHERE id=? AND status='pending'").run(orderId);
      return res.redirect(`${baseUrl}/?payment=failed`);
    }
    const now = Date.now();
    const days = order.plan === 'yearly' ? 365 : 30;
    const current = db.prepare('SELECT expires_at FROM subscriptions WHERE session_id=?').get(order.session_id);
    const start = Math.max(now, current?.expires_at || 0);
    const expiresAt = start + days * 24 * 60 * 60 * 1000;
    const commit = db.transaction(() => {
      const changed = db.prepare("UPDATE orders SET status='paid',ref_id=?,paid_at=? WHERE id=? AND status='pending'")
        .run(String(data.data.ref_id || ''), now, orderId).changes;
      if (!changed) return false;
      db.prepare(`INSERT INTO subscriptions(session_id,plan,expires_at,updated_at) VALUES(?,?,?,?)
        ON CONFLICT(session_id) DO UPDATE SET plan=excluded.plan,expires_at=excluded.expires_at,updated_at=excluded.updated_at`)
        .run(order.session_id, order.plan, expiresAt, now);
      return true;
    });
    commit();
    return res.redirect(`${baseUrl}/?payment=success`);
  } catch (err) {
    console.error('payment verify error:', err?.message || err);
    return res.redirect(`${baseUrl}/?payment=pending`);
  }
});

app.get('/api/subscription/me', (req, res) => {
  const sessionId = getSession(req, res);
  const sub = db.prepare('SELECT plan,expires_at FROM subscriptions WHERE session_id=?').get(sessionId);
  res.json({ active: Boolean(sub && sub.expires_at > Date.now()), plan: sub?.plan || null, expiresAt: sub?.expires_at || null });
});

app.use('/server', (_req, res) => res.sendStatus(404));
app.use(express.static(path.resolve(__dirname, '..'), { index: 'index.html', dotfiles: 'deny', etag: true }));
app.listen(port, () => {
  console.log(`WALTRIX server listening on ${port}; provider=zarinpal; sandbox=${sandbox}`);
  if (secret.length < 32) console.warn('WARNING: SESSION_SECRET must be at least 32 characters before production.');
  if (!baseUrl) console.warn('WARNING: PUBLIC_BASE_URL is not configured.');
});
