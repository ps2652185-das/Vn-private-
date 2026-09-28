import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';
import twilio from 'twilio';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { TwilioProvider } from './providers/twilio.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
const DB_FILE = path.join(DATA, 'db.json');
const BAK_FILE = path.join(DATA, 'db.bak');

const PORT = Number(process.env.PORT) || 8080;
const JWT_SECRET = process.env.JWT_SECRET || '';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const MAX_NUMBERS = Number(process.env.MAX_NUMBERS) || 25;
const PROVIDER_NAME = (process.env.PROVIDER || 'twilio').toLowerCase();
const TOKEN_TTL_SEC = Number(process.env.TOKEN_TTL_SEC) || 60 * 60 * 24 * 7;
const BCRYPT_ROUNDS = 12;

const bootWarnings = [];
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  bootWarnings.push('JWT_SECRET missing or shorter than 32 chars — auth will fail until set');
}
if (PROVIDER_NAME === 'twilio' && !PUBLIC_BASE_URL.startsWith('https://')) {
  bootWarnings.push('PUBLIC_BASE_URL must be HTTPS for Twilio webhooks — set after Railway domain is generated');
}
if (PROVIDER_NAME !== 'twilio') {
  bootWarnings.push('Only twilio provider is supported');
}

let provider = null;
function getProvider() {
  if (PROVIDER_NAME !== 'twilio') throw new Error('Only the real Twilio provider is enabled');
  if (!provider) provider = new TwilioProvider();
  return provider;
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));

const allowedOrigin = process.env.CORS_ORIGIN || '';
app.use(cors({
  origin: allowedOrigin || false,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type']
}));

const globalLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many auth attempts. Try again later.' } });
const expensiveLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

app.use((req, res, next) => {
  if (req.path.startsWith('/webhooks/')) return next();
  return globalLimiter(req, res, next);
});
app.use(express.json({ limit: '64kb' }));

function emptyDb() { return { users: [], numbers: [], calls: [], messages: [], sessions: [], audit: [] }; }
function normalize(db) {
  const d = db || emptyDb();
  for (const k of ['users', 'numbers', 'calls', 'messages', 'sessions', 'audit']) {
    if (!Array.isArray(d[k])) d[k] = [];
  }
  return d;
}
function loadSync() {
  try { return normalize(JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); }
  catch {
    try { return normalize(JSON.parse(fs.readFileSync(BAK_FILE, 'utf8'))); }
    catch { return emptyDb(); }
  }
}
function saveSync(db) {
  const tmp = DB_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  if (fs.existsSync(DB_FILE)) {
    try { fs.copyFileSync(DB_FILE, BAK_FILE); } catch { /* ignore */ }
  }
  fs.renameSync(tmp, DB_FILE);
}
let writeChain = Promise.resolve();
function load() { return loadSync(); }
function save(db) {
  writeChain = writeChain.then(() => {
    try { saveSync(db); } catch (e) { console.error('db save failed', e.message); }
  }).catch(() => {});
  return writeChain;
}
function audit(db, userId, action, meta) {
  db.audit.push({ id: uuid(), userId: userId || null, action, meta: meta || null, at: Date.now() });
  if (db.audit.length > 2000) db.audit = db.audit.slice(-1500);
}

function validUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(u); }
function validPassword(p) { return typeof p === 'string' && p.length >= 8 && p.length <= 128; }
function validPhone(p) { return typeof p === 'string' && /^\+[1-9]\d{6,14}$/.test(p); }
function validLabel(l) { return typeof l === 'string' && l.length <= 64; }
function webhookUrl(pathSuffix) {
  if (!PUBLIC_BASE_URL.startsWith('https://')) {
    throw new Error('PUBLIC_BASE_URL must be set to your HTTPS Railway URL');
  }
  return PUBLIC_BASE_URL + pathSuffix;
}
function requireJwtConfigured(res) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    res.status(503).json({ error: 'Server not configured: JWT_SECRET' });
    return false;
  }
  return true;
}
function issueToken(user, sessionId) {
  return jwt.sign({ sub: user.id, username: user.username, sid: sessionId }, JWT_SECRET, { expiresIn: TOKEN_TTL_SEC, algorithm: 'HS256' });
}
function auth(req, res, next) {
  if (!requireJwtConfigured(res)) return;
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
    const db = load();
    const session = db.sessions.find(s => s.id === payload.sid && s.userId === payload.sub);
    if (!session || session.revokedAt) return res.status(401).json({ error: 'Session revoked' });
    if (session.expiresAt && session.expiresAt < Date.now()) return res.status(401).json({ error: 'Session expired' });
    const now = Date.now();
    if (!session.lastUsedAt || (now - session.lastUsedAt) > 60000) {
      session.lastUsedAt = now;
      save(db);
    }
    req.user = payload;
    req.sessionId = payload.sid;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
function requireTwilioWebhook(req, res, next) {
  try {
    const signature = req.headers['x-twilio-signature'];
    if (!process.env.TWILIO_AUTH_TOKEN) return res.status(503).send('Twilio not configured');
    if (!PUBLIC_BASE_URL.startsWith('https://')) return res.status(503).send('PUBLIC_BASE_URL not set');
    const url = PUBLIC_BASE_URL + req.originalUrl.split('?')[0];
    const valid = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN, signature, url, req.body);
    if (!valid) return res.status(403).send('Invalid signature');
    next();
  } catch {
    return res.status(403).send('Invalid signature');
  }
}
function ownNumber(db, userId, numberId) {
  return db.numbers.find(n => n.id === numberId && n.userId === userId && n.status === 'active');
}

app.get('/', (_req, res) => res.json({ name: 'PrivateVN', version: 3, provider: PROVIDER_NAME, warnings: bootWarnings }));
app.get('/health', (_req, res) => res.json({
  ok: true, ts: Date.now(),
  configured: {
    jwt: !!(JWT_SECRET && JWT_SECRET.length >= 32),
    publicUrl: PUBLIC_BASE_URL.startsWith('https://'),
    twilio: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
  },
  warnings: bootWarnings
}));

app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    if (!requireJwtConfigured(res)) return;
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!validUsername(username)) return res.status(400).json({ error: 'Username 3-32 chars, alphanumeric/underscore' });
    if (!validPassword(password)) return res.status(400).json({ error: 'Password must be 8-128 characters' });
    const db = load();
    if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username taken' });
    const user = { id: uuid(), username, passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS), createdAt: Date.now() };
    const sessionId = uuid();
    const expiresAt = Date.now() + TOKEN_TTL_SEC * 1000;
    db.users.push(user);
    db.sessions.push({ id: sessionId, userId: user.id, label: String(req.body.deviceLabel || 'Android').slice(0, 64), createdAt: Date.now(), lastUsedAt: Date.now(), expiresAt, revokedAt: null });
    audit(db, user.id, 'register', null);
    await save(db);
    res.status(201).json({ token: issueToken(user, sessionId), userId: user.id, username: user.username, sessionId });
  } catch { res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    if (!requireJwtConfigured(res)) return;
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Credentials required' });
    const db = load();
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
    const sessionId = uuid();
    const expiresAt = Date.now() + TOKEN_TTL_SEC * 1000;
    db.sessions.push({ id: sessionId, userId: user.id, label: String(req.body.deviceLabel || 'Android').slice(0, 64), createdAt: Date.now(), lastUsedAt: Date.now(), expiresAt, revokedAt: null });
    audit(db, user.id, 'login', null);
    await save(db);
    res.json({ token: issueToken(user, sessionId), userId: user.id, username: user.username, sessionId });
  } catch { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/auth/logout', auth, async (req, res) => {
  const db = load();
  const s = db.sessions.find(x => x.id === req.sessionId && x.userId === req.user.sub);
  if (s) s.revokedAt = Date.now();
  audit(db, req.user.sub, 'logout', { sessionId: req.sessionId });
  await save(db);
  res.json({ ok: true });
});

app.post('/auth/revoke-all', auth, async (req, res) => {
  const db = load();
  const now = Date.now();
  for (const s of db.sessions) { if (s.userId === req.user.sub && !s.revokedAt) s.revokedAt = now; }
  audit(db, req.user.sub, 'revoke_all', null);
  await save(db);
  res.json({ ok: true });
});

app.get('/auth/sessions', auth, (req, res) => {
  const db = load();
  res.json(db.sessions.filter(s => s.userId === req.user.sub).map(s => ({
    id: s.id, label: s.label, createdAt: s.createdAt, lastUsedAt: s.lastUsedAt, expiresAt: s.expiresAt, revoked: !!s.revokedAt, current: s.id === req.sessionId
  })).sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0)));
});

app.post('/auth/sessions/:id/revoke', auth, async (req, res) => {
  const db = load();
  const s = db.sessions.find(x => x.id === req.params.id && x.userId === req.user.sub);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  if (!s.revokedAt) s.revokedAt = Date.now();
  audit(db, req.user.sub, 'revoke_session', { sessionId: s.id });
  await save(db);
  res.json({ ok: true });
});

app.get('/numbers', auth, (req, res) => {
  const db = load();
  res.json(db.numbers.filter(n => n.userId === req.user.sub && n.status !== 'released').sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)));
});

app.get('/numbers/available', auth, expensiveLimiter, async (req, res) => {
  try { res.json(await getProvider().listAvailableNumbers()); }
  catch (e) { res.status(502).json({ error: e.message || 'Provider unavailable' }); }
});

app.post('/numbers', auth, expensiveLimiter, async (req, res) => {
  try {
    const phoneNumber = String(req.body.phoneNumber || '').trim();
    const label = String(req.body.label || 'Number').trim().slice(0, 64);
    if (!validPhone(phoneNumber)) return res.status(400).json({ error: 'Valid E.164 phone required' });
    const db = load();
    if (db.numbers.filter(n => n.userId === req.user.sub && n.status === 'active').length >= MAX_NUMBERS) return res.status(403).json({ error: `Maximum ${MAX_NUMBERS} active numbers` });
    if (db.numbers.some(n => n.phoneNumber === phoneNumber && n.status === 'active')) return res.status(409).json({ error: 'Number already assigned' });
    const p = getProvider();
    const assigned = await p.assignNumber(phoneNumber);
    try {
      await p.configureNumber(assigned.providerNumberId, webhookUrl('/webhooks/twilio/voice/incoming'), webhookUrl('/webhooks/twilio/sms/incoming'));
    } catch (cfgErr) {
      try { await p.releaseNumber(assigned.providerNumberId); } catch { /* best effort */ }
      throw cfgErr;
    }
    const row = {
      id: uuid(), userId: req.user.sub, phoneNumber: assigned.phoneNumber, country: assigned.country || null,
      providerNumberId: assigned.providerNumberId, label, callMode: 'OUTGOING_ONLY', incomingCallsEnabled: false,
      incomingSmsEnabled: true, outgoingSmsEnabled: true, notificationsEnabled: true, status: 'active', createdAt: Date.now()
    };
    db.numbers.push(row);
    audit(db, req.user.sub, 'assign_number', { phoneNumber: row.phoneNumber });
    await save(db);
    res.status(201).json(row);
  } catch (e) { res.status(400).json({ error: e.message || 'Assign failed' }); }
});

function applyNumberPatch(n, patch) {
  if (patch.label !== undefined) {
    const l = String(patch.label).trim().slice(0, 64);
    if (!validLabel(l)) throw new Error('Invalid label');
    n.label = l;
  }
  if (patch.callMode !== undefined) {
    const m = String(patch.callMode);
    if (m !== 'OUTGOING_ONLY' && m !== 'TWO_WAY') throw new Error('callMode must be OUTGOING_ONLY or TWO_WAY');
    n.callMode = m;
    n.incomingCallsEnabled = (m === 'TWO_WAY');
  }
  if (patch.incomingCallsEnabled !== undefined) {
    n.incomingCallsEnabled = !!patch.incomingCallsEnabled;
    n.callMode = n.incomingCallsEnabled ? 'TWO_WAY' : 'OUTGOING_ONLY';
  }
  if (patch.incomingSmsEnabled !== undefined) n.incomingSmsEnabled = !!patch.incomingSmsEnabled;
  if (patch.outgoingSmsEnabled !== undefined) n.outgoingSmsEnabled = !!patch.outgoingSmsEnabled;
  if (patch.notificationsEnabled !== undefined) n.notificationsEnabled = !!patch.notificationsEnabled;
  n.updatedAt = Date.now();
}

app.post('/numbers/:id/update', auth, async (req, res) => {
  try {
    const db = load();
    const n = ownNumber(db, req.user.sub, req.params.id);
    if (!n) return res.status(404).json({ error: 'Number not found' });
    applyNumberPatch(n, req.body || {});
    audit(db, req.user.sub, 'update_number', { id: n.id });
    await save(db);
    res.json(n);
  } catch (e) { res.status(400).json({ error: e.message || 'Update failed' }); }
});
app.patch('/numbers/:id', auth, async (req, res) => {
  try {
    const db = load();
    const n = ownNumber(db, req.user.sub, req.params.id);
    if (!n) return res.status(404).json({ error: 'Number not found' });
    applyNumberPatch(n, req.body || {});
    audit(db, req.user.sub, 'update_number', { id: n.id });
    await save(db);
    res.json(n);
  } catch (e) { res.status(400).json({ error: e.message || 'Update failed' }); }
});

async function releaseNumberHandler(req, res) {
  try {
    const db = load();
    const n = db.numbers.find(x => x.id === req.params.id && x.userId === req.user.sub && x.status === 'active');
    if (!n) return res.status(404).json({ error: 'Number not found' });
    if (n.providerNumberId) {
      try { await getProvider().releaseNumber(n.providerNumberId); }
      catch (e) { return res.status(502).json({ error: e.message || 'Provider release failed' }); }
    }
    n.status = 'released'; n.releasedAt = Date.now();
    audit(db, req.user.sub, 'release_number', { phoneNumber: n.phoneNumber });
    await save(db);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message || 'Release failed' }); }
}
app.post('/numbers/:id/delete', auth, expensiveLimiter, releaseNumberHandler);
app.delete('/numbers/:id', auth, expensiveLimiter, releaseNumberHandler);

app.post('/calls', auth, expensiveLimiter, async (req, res) => {
  try {
    const virtualNumberId = String(req.body.virtualNumberId || '');
    const destination = String(req.body.destination || '').trim();
    if (!virtualNumberId || !validPhone(destination)) return res.status(400).json({ error: 'Valid destination required (E.164)' });
    const db = load();
    const n = ownNumber(db, req.user.sub, virtualNumberId);
    if (!n) return res.status(404).json({ error: 'Number not found' });
    const result = await getProvider().makeCall(n.phoneNumber, destination, webhookUrl('/webhooks/twilio/voice/status'), webhookUrl('/webhooks/twilio/voice/outbound'));
    const row = { id: uuid(), userId: req.user.sub, virtualNumberId: n.id, from: n.phoneNumber, to: destination, direction: 'out', status: result.status || 'initiated', providerCallId: result.providerCallId || null, mock: !!result.mock, createdAt: Date.now() };
    db.calls.push(row);
    audit(db, req.user.sub, 'start_call', { to: destination });
    await save(db);
    res.status(201).json(row);
  } catch (e) { res.status(400).json({ error: e.message || 'Call failed' }); }
});

app.get('/calls', auth, (req, res) => {
  const db = load();
  let list = db.calls.filter(c => c.userId === req.user.sub);
  const vid = req.query.virtualNumberId ? String(req.query.virtualNumberId) : null;
  if (vid) list = list.filter(c => c.virtualNumberId === vid);
  list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json(list.slice(0, 200));
});

app.get('/calls/:id', auth, (req, res) => {
  const db = load();
  const c = db.calls.find(x => x.id === req.params.id && x.userId === req.user.sub);
  if (!c) return res.status(404).json({ error: 'Call not found' });
  res.json(c);
});

app.delete('/calls/:id', auth, async (req, res) => {
  const db = load();
  const idx = db.calls.findIndex(x => x.id === req.params.id && x.userId === req.user.sub);
  if (idx < 0) return res.status(404).json({ error: 'Call not found' });
  db.calls.splice(idx, 1);
  await save(db);
  res.json({ ok: true });
});

app.post('/messages', auth, expensiveLimiter, async (req, res) => {
  try {
    const virtualNumberId = String(req.body.virtualNumberId || '');
    const to = String(req.body.to || '').trim();
    const body = String(req.body.body || '');
    if (!virtualNumberId || !validPhone(to) || !body) return res.status(400).json({ error: 'Valid number and message required' });
    if (body.length > 1600) return res.status(400).json({ error: 'Message too long (max 1600)' });
    const db = load();
    const n = ownNumber(db, req.user.sub, virtualNumberId);
    if (!n) return res.status(404).json({ error: 'Number not found' });
    if (n.outgoingSmsEnabled === false) return res.status(403).json({ error: 'Outgoing SMS disabled' });
    const result = await getProvider().sendSms(n.phoneNumber, to, body, webhookUrl('/webhooks/twilio/sms/status'));
    const row = { id: uuid(), userId: req.user.sub, virtualNumberId: n.id, from: n.phoneNumber, to, body, direction: 'out', status: result.status || 'queued', providerMessageId: result.providerMessageId || null, mock: !!result.mock, createdAt: Date.now() };
    db.messages.push(row);
    audit(db, req.user.sub, 'send_sms', { to });
    await save(db);
    res.status(201).json(row);
  } catch (e) { res.status(400).json({ error: e.message || 'SMS failed' }); }
});

app.get('/messages', auth, (req, res) => {
  const db = load();
  let list = db.messages.filter(m => m.userId === req.user.sub);
  const vid = req.query.virtualNumberId ? String(req.query.virtualNumberId) : null;
  if (vid) list = list.filter(m => m.virtualNumberId === vid);
  list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json(list.slice(0, 300));
});

app.delete('/messages/:id', auth, async (req, res) => {
  const db = load();
  const idx = db.messages.findIndex(x => x.id === req.params.id && x.userId === req.user.sub);
  if (idx < 0) return res.status(404).json({ error: 'Message not found' });
  db.messages.splice(idx, 1);
  await save(db);
  res.json({ ok: true });
});

app.get('/voice/token', auth, (req, res) => {
  try {
    if (PROVIDER_NAME !== 'twilio') return res.status(400).json({ error: 'Voice SDK token requires Twilio' });
    const AccessToken = twilio.jwt.AccessToken;
  
