require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');

const { DISCORD_TOKEN, PORT = 3000, NODE_ENV } = process.env;
const SITE_NAME = process.env.SITE_NAME || 'My Site';
if (!DISCORD_TOKEN) {
  console.error('Missing DISCORD_TOKEN. Copy .env.example to .env and fill it in.');
  process.exit(1);
}

const CODE_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 5;

// ---------- Database ----------
const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    discord_id TEXT PRIMARY KEY,
    username TEXT,
    avatar TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS codes (
    discord_id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    mode TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    discord_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

const q = {
  getUser: db.prepare('SELECT * FROM users WHERE discord_id = ?'),
  upsertUser: db.prepare(`
    INSERT INTO users (discord_id, username, avatar, created_at) VALUES (@id, @username, @avatar, @now)
    ON CONFLICT(discord_id) DO UPDATE SET username = @username, avatar = @avatar`),
  getCode: db.prepare('SELECT * FROM codes WHERE discord_id = ?'),
  upsertCode: db.prepare(`
    INSERT INTO codes (discord_id, code_hash, mode, attempts, created_at, expires_at)
    VALUES (@id, @hash, @mode, 0, @now, @exp)
    ON CONFLICT(discord_id) DO UPDATE SET code_hash = @hash, mode = @mode, attempts = 0, created_at = @now, expires_at = @exp`),
  delCode: db.prepare('DELETE FROM codes WHERE discord_id = ?'),
  addAttempt: db.prepare('UPDATE codes SET attempts = attempts + 1 WHERE discord_id = ?'),
  addSession: db.prepare('INSERT INTO sessions (token_hash, discord_id, expires_at) VALUES (?, ?, ?)'),
  getSession: db.prepare(`
    SELECT u.discord_id AS id, u.username, u.avatar, u.created_at
    FROM sessions s JOIN users u ON u.discord_id = s.discord_id
    WHERE s.token_hash = ? AND s.expires_at > ?`),
  delSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  cleanCodes: db.prepare('DELETE FROM codes WHERE expires_at < ?'),
  cleanSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
};

setInterval(() => {
  const now = Date.now();
  q.cleanCodes.run(now);
  q.cleanSessions.run(now);
}, 10 * 60 * 1000).unref();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hashCode = (id, code) => sha256(`${id}:${code}`);

// ---------- Discord bot ----------
const bot = new Client({ intents: [GatewayIntentBits.Guilds] });
bot.once('ready', () => console.log(`Bot online as ${bot.user.tag}`));
bot.login(DISCORD_TOKEN).catch((e) => {
  console.error('Bot login failed:', e.message);
  process.exit(1);
});

// ---------- Web server ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1kb' }));
app.use(cookieParser());

const requestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, limit: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests. Try again in a few minutes.' },
});
const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, limit: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
});

app.post('/api/request-code', requestLimiter, async (req, res) => {
  const userId = String(req.body.userId || '').trim();
  const mode = req.body.mode === 'register' ? 'register' : 'login';

  if (!/^\d{17,20}$/.test(userId)) {
    return res.status(400).json({ error: 'Enter a valid Discord User ID (17 to 20 digits).' });
  }
  const existing = q.getUser.get(userId);
  if (mode === 'register' && existing) {
    return res.status(409).json({ error: 'This ID is already registered. Use Login instead.' });
  }
  if (mode === 'login' && !existing) {
    return res.status(404).json({ error: 'No account found for this ID. Register first.' });
  }

  const prev = q.getCode.get(userId);
  if (prev && Date.now() - prev.created_at < RESEND_COOLDOWN_MS) {
    const wait = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - prev.created_at)) / 1000);
    return res.status(429).json({ error: `Wait ${wait}s before requesting another code.` });
  }

  let user;
  try {
    user = await bot.users.fetch(userId);
  } catch {
    return res.status(404).json({ error: 'Discord could not find a user with that ID.' });
  }
  if (user.bot) return res.status(400).json({ error: 'Bots cannot have accounts.' });

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  try {
    await user.send({
      embeds: [
        new EmbedBuilder()
          .setColor(0x7c83ff)
          .setTitle(`${SITE_NAME} verification code`)
          .setDescription(`Your code is:\n# \`${code}\`\nIt expires in 5 minutes. Never share it with anyone.`)
          .setFooter({ text: "If you didn't request this, ignore this message." }),
      ],
    });
  } catch {
    return res.status(403).json({
      error: "The bot couldn't DM you. Join a server with the bot and allow DMs from server members, then try again.",
    });
  }

  const now = Date.now();
  q.upsertCode.run({ id: userId, hash: hashCode(userId, code), mode, now, exp: now + CODE_TTL_MS });
  res.json({ ok: true });
});

app.post('/api/verify', verifyLimiter, async (req, res) => {
  const userId = String(req.body.userId || '').trim();
  const code = String(req.body.code || '').trim();
  if (!/^\d{17,20}$/.test(userId) || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Enter the 6-digit code from your DMs.' });
  }

  const row = q.getCode.get(userId);
  if (!row || row.expires_at < Date.now()) {
    if (row) q.delCode.run(userId);
    return res.status(400).json({ error: 'This code expired. Request a new one.' });
  }
  if (row.attempts >= MAX_ATTEMPTS) {
    q.delCode.run(userId);
    return res.status(429).json({ error: 'Too many wrong attempts. Request a new code.' });
  }

  const a = Buffer.from(hashCode(userId, code));
  const b = Buffer.from(row.code_hash);
  if (!crypto.timingSafeEqual(a, b)) {
    q.addAttempt.run(userId);
    const left = MAX_ATTEMPTS - (row.attempts + 1);
    return res.status(400).json({ error: `Wrong code. ${left} attempt${left === 1 ? '' : 's'} left.` });
  }

  q.delCode.run(userId); // single use

  let username = null, avatar = null;
  try {
    const u = await bot.users.fetch(userId);
    username = u.username;
    avatar = u.displayAvatarURL({ extension: 'png', size: 128 });
  } catch { /* profile is optional */ }
  q.upsertUser.run({ id: userId, username, avatar, now: Date.now() });

  const token = crypto.randomBytes(32).toString('hex');
  q.addSession.run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
  res.cookie('sid', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    maxAge: SESSION_TTL_MS,
  });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.sid;
  const me = token && q.getSession.get(sha256(token), Date.now());
  if (!me) return res.status(401).json({ error: 'Not logged in.' });
  res.json(me);
});

app.post('/api/logout', (req, res) => {
  if (req.cookies.sid) q.delSession.run(sha256(req.cookies.sid));
  res.clearCookie('sid');
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`Website running on http://localhost:${PORT}`));
