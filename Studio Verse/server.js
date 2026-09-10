import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDirectory = path.join(root, 'data');
const usersFile = path.join(dataDirectory, 'users.json');
const submissionsFile = path.join(dataDirectory, 'submissions.json');
const app = express();
const port = Number(process.env.PORT || 3000);
const sessions = new Map();
const adminSessions = new Map();
const sessionDuration = 1000 * 60 * 60 * 24 * 30;
const adminSessionDuration = 1000 * 60 * 60 * 8;
const ownerHash = process.env.OWNER_PASSWORD_HASH || 'ad98f59a44425cfc03cd12554b893f26b98a73ef7435e5e01d75478559a6fe84';

app.use(express.json({ limit: '32kb' }));
app.use((request, response, next) => {
  if (/^\/(data|server\.js|server\.py|server\.ps1|package\.json|\.env)/i.test(request.path)) return response.status(404).json({ error: 'Not found' });
  next();
});
app.use(express.static(root));

async function ensureUserStore() {
  await fs.mkdir(dataDirectory, { recursive: true });
  try { await fs.access(usersFile); } catch { await fs.writeFile(usersFile, '[]\n', 'utf8'); }
  try { await fs.access(submissionsFile); } catch { await fs.writeFile(submissionsFile, '[]\n', 'utf8'); }
}

async function readUsers() {
  return JSON.parse(await fs.readFile(usersFile, 'utf8'));
}

async function writeUsers(users) {
  const temporaryFile = `${usersFile}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(users, null, 2), 'utf8');
  await fs.rename(temporaryFile, usersFile);
}

async function readSubmissions() {
  return JSON.parse(await fs.readFile(submissionsFile, 'utf8'));
}

async function writeSubmissions(submissions) {
  const temporaryFile = `${submissionsFile}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(submissions, null, 2), 'utf8');
  await fs.rename(temporaryFile, submissionsFile);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}

function passwordMatches(password, user) {
  const stored = Buffer.from(user.passwordHash, 'hex');
  const supplied = Buffer.from(hashPassword(password, user.passwordSalt).hash, 'hex');
  return stored.length === supplied.length && crypto.timingSafeEqual(stored, supplied);
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map(cookie => {
    const separator = cookie.indexOf('=');
    return [cookie.slice(0, separator).trim(), decodeURIComponent(cookie.slice(separator + 1))];
  }));
}

function setSessionCookie(response, sessionId, maxAge = sessionDuration, name = 'orbit_session') {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  response.setHeader('Set-Cookie', `${name}=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(maxAge / 1000)}${secure}`);
}

function publicUser(user) {
  return { id: user.id, username: user.username, createdAt: user.createdAt };
}

function validCredentials(username, password) {
  return typeof username === 'string' && /^[a-zA-Z0-9_]{3,24}$/.test(username) && typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function startSession(user) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, { userId: user.id, expiresAt: Date.now() + sessionDuration });
  return sessionId;
}

function startAdminSession() {
  const sessionId = crypto.randomBytes(32).toString('hex');
  adminSessions.set(sessionId, { expiresAt: Date.now() + adminSessionDuration });
  return sessionId;
}

function isAdmin(request) {
  const sessionId = parseCookies(request).studioverse_admin;
  const session = adminSessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    if (sessionId) adminSessions.delete(sessionId);
    return false;
  }
  return true;
}

function requireAdmin(request, response, next) {
  if (!isAdmin(request)) return response.status(401).json({ error: 'Admin access required.' });
  next();
}

async function currentUser(request) {
  const sessionId = parseCookies(request).orbit_session;
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    if (sessionId) sessions.delete(sessionId);
    return null;
  }
  const users = await readUsers();
  return users.find(user => user.id === session.userId) || null;
}

app.post('/api/auth/signup', async (request, response) => {
  const { username, password } = request.body || {};
  if (!validCredentials(username, password)) return response.status(400).json({ error: 'Use a username with 3–24 letters, numbers, or underscores and a password with at least 8 characters.' });
  const normalizedUsername = username.toLowerCase();
  const users = await readUsers();
  if (users.some(user => user.username === normalizedUsername)) return response.status(409).json({ error: 'That username is already taken.' });
  const passwordData = hashPassword(password);
  const user = { id: crypto.randomUUID(), username: normalizedUsername, passwordSalt: passwordData.salt, passwordHash: passwordData.hash, createdAt: new Date().toISOString() };
  await writeUsers([...users, user]);
  setSessionCookie(response, startSession(user));
  response.status(201).json({ user: publicUser(user) });
});

app.post('/api/auth/login', async (request, response) => {
  const { username, password } = request.body || {};
  const users = await readUsers();
  const user = users.find(candidate => candidate.username === String(username || '').toLowerCase());
  if (!user || !passwordMatches(String(password || ''), user)) return response.status(401).json({ error: 'Username or password is incorrect.' });
  setSessionCookie(response, startSession(user));
  response.json({ user: publicUser(user) });
});

app.get('/api/session', async (request, response) => {
  const user = await currentUser(request);
  if (!user) return response.status(401).json({ authenticated: false });
  response.json({ authenticated: true, user: publicUser(user) });
});

app.post('/api/auth/logout', (request, response) => {
  const sessionId = parseCookies(request).orbit_session;
  if (sessionId) sessions.delete(sessionId);
  setSessionCookie(response, '', 0);
  response.status(204).end();
});

app.post('/api/admin/session', (request, response) => {
  const suppliedHash = crypto.createHash('sha256').update(String(request.body?.password || '')).digest('hex');
  if (suppliedHash !== ownerHash) return response.status(401).json({ error: 'That passcode is not correct.' });
  setSessionCookie(response, startAdminSession(), adminSessionDuration, 'studioverse_admin');
  response.status(204).end();
});

app.post('/api/submissions', async (request, response) => {
  const { email, discord, details, paypal, additionalInfo, termsAccepted } = request.body || {};
  const cleanEmail = String(email || '').trim();
  const cleanDiscord = String(discord || '').trim();
  const cleanDetails = String(details || '').trim();
  const cleanPaypal = String(paypal || '').trim();
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if ((!cleanEmail && !cleanDiscord) || (cleanEmail && !emailPattern.test(cleanEmail)) || !cleanDetails || !cleanPaypal || !emailPattern.test(cleanPaypal) || termsAccepted !== true || cleanEmail.length > 160 || cleanDiscord.length > 120 || cleanDetails.length > 5000 || cleanPaypal.length > 160 || String(additionalInfo || '').length > 2000) {
    return response.status(400).json({ error: 'Email or Discord, sale details, PayPal, and TOS agreement are required.' });
  }
  const submissions = await readSubmissions();
  const submission = {
    id: crypto.randomUUID(),
    ticketNumber: submissions.reduce((highest, item) => Math.max(highest, Number(item.ticketNumber) || 0), 0) + 1,
    email: cleanEmail,
    discord: cleanDiscord,
    details: cleanDetails,
    paypal: cleanPaypal,
    additionalInfo: String(additionalInfo || '').trim(),
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  await writeSubmissions([submission, ...submissions]);
  response.status(201).json({ id: submission.id, ticketNumber: submission.ticketNumber });
});

app.get('/api/submissions', requireAdmin, async (request, response) => {
  response.json(await readSubmissions());
});

app.patch('/api/submissions/:id', requireAdmin, async (request, response) => {
  const status = request.body?.status;
  if (!['approved', 'rejected', 'pending'].includes(status)) return response.status(400).json({ error: 'Invalid submission status.' });
  const submissions = await readSubmissions();
  const index = submissions.findIndex(submission => submission.id === request.params.id);
  if (index < 0) return response.status(404).json({ error: 'Submission not found.' });
  submissions[index] = { ...submissions[index], status, reviewedAt: new Date().toISOString() };
  await writeSubmissions(submissions);
  response.json(submissions[index]);
});

app.use('/api', (request, response) => response.status(404).json({ error: 'API route not found.' }));
app.get('*', (request, response) => response.sendFile(path.join(root, 'index.html')));

ensureUserStore().then(() => app.listen(port, () => console.log(`Orbit is running at http://localhost:${port}`))).catch(error => {
  console.error('Could not initialize the user store:', error);
  process.exit(1);
});
