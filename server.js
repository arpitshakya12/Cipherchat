const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const tls = require('node:tls');
const zlib = require('node:zlib');
const { DatabaseSync } = require('node:sqlite');

// ==========================================
// 1. GMAIL & ADMINISTRATOR CONFIGURATION
// ==========================================
const SENDER_EMAIL = process.env.SENDER_EMAIL || '';
const SENDER_APP_PASSWORD = process.env.SENDER_APP_PASSWORD || '';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const PORT = process.env.PORT || 3000;

// ==========================================
// 2. SQLITE DATABASE & SAFE SCHEMA MIGRATION
// ==========================================
const db = new DatabaseSync(path.join(__dirname, 'cipherchat.db'));
db.exec('PRAGMA journal_mode = WAL;');

const cols = db.prepare('PRAGMA table_info(users)').all();
if (cols.length > 0 && !cols.some((c) => c.name === 'username')) {
  db.exec(`
    DROP TABLE IF EXISTS messages;
    DROP TABLE IF EXISTS friend_requests;
    DROP TABLE IF EXISTS otps;
    DROP TABLE IF EXISTS users;
  `);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    public_key TEXT,
    encrypted_priv_key TEXT DEFAULT '',
    pin_salt TEXT DEFAULT '',
    pin_iv TEXT DEFAULT '',
    bio TEXT DEFAULT 'Hey there! Using CipherChat E2EE.',
    last_seen INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    device_name TEXT NOT NULL,
    last_active INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS otps (
    email TEXT PRIMARY KEY,
    otp TEXT NOT NULL,
    purpose TEXT NOT NULL,
    pending_data TEXT,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(sender_id, receiver_id)
  );

  CREATE TABLE IF NOT EXISTS invite_tokens (
    token TEXT PRIMARY KEY,
    creator_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (blocker_id, blocked_id)
  );

  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_group_key TEXT NOT NULL,
    key_iv TEXT NOT NULL,
    added_by INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    group_id INTEGER DEFAULT NULL,
    msg_type TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    file_name TEXT,
    reply_to_id INTEGER DEFAULT NULL,
    is_view_once INTEGER DEFAULT 0,
    is_sealed INTEGER DEFAULT 0,
    is_edited INTEGER DEFAULT 0,
    poll_votes TEXT DEFAULT '{}',
    expires_at INTEGER DEFAULT NULL,
    is_read INTEGER DEFAULT 0,
    reactions TEXT DEFAULT '{}',
    is_deleted INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS deletion_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    reason TEXT DEFAULT '',
    accepted_terms INTEGER NOT NULL DEFAULT 1,
    terms_accepted_at TEXT NOT NULL,
    device_info TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS deletion_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    username TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    reason TEXT DEFAULT '',
    terms_accepted_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const safeAlters = [
  "ALTER TABLE users ADD COLUMN encrypted_priv_key TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN pin_salt TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN pin_iv TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN bio TEXT DEFAULT 'Hey there! Using CipherChat E2EE.'",
  "ALTER TABLE users ADD COLUMN last_seen INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN group_id INTEGER DEFAULT NULL",
  "ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL",
  "ALTER TABLE messages ADD COLUMN is_view_once INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN is_sealed INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN is_edited INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN poll_votes TEXT DEFAULT '{}'",
  "ALTER TABLE messages ADD COLUMN expires_at INTEGER DEFAULT NULL",
  "ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN reactions TEXT DEFAULT '{}'",
  "ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0"
];
for (const sql of safeAlters) {
  try { db.exec(sql); } catch {}
}

const typingStatus = new Map();
const callSignals = new Map();
let signalSeq = 1;

setInterval(() => {
  const now = Date.now();
  try {
    db.prepare('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?').run(now);
    db.prepare('DELETE FROM invite_tokens WHERE expires_at <= ?').run(now);
  } catch {}
  for (const [uid, queue] of callSignals.entries()) {
    const fresh = queue.filter((s) => now - s.ts < 60000);
    if (fresh.length === 0) callSignals.delete(uid);
    else callSignals.set(uid, fresh);
  }
}, 5000);

// ==========================================
// 3. HELPERS (ADMIN CHECK, DEVICE, PHONE, SMTP)
// ==========================================
function isAdminUser(user) {
  return Boolean(user && user.email && user.email.toLowerCase() === ADMIN_EMAIL);
}

function permanentlyDeleteUserAccount(targetUserId, reason, termsAcceptedAt, approvedByEmail) {
  const target = db.prepare('SELECT id, name, username, phone, email FROM users WHERE id = ?').get(targetUserId);
  if (!target) return false;

  db.prepare(`
    INSERT INTO deletion_audit_logs (user_name, username, phone, email, reason, terms_accepted_at, approved_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    target.name,
    target.username,
    target.phone,
    target.email,
    reason || 'User requested deletion',
    termsAcceptedAt || new Date().toISOString(),
    approvedByEmail
  );

  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(targetUserId);
  db.prepare('DELETE FROM friend_requests WHERE sender_id = ? OR receiver_id = ?').run(targetUserId, targetUserId);
  db.prepare('DELETE FROM blocks WHERE blocker_id = ? OR blocked_id = ?').run(targetUserId, targetUserId);
  db.prepare('DELETE FROM invite_tokens WHERE creator_id = ?').run(targetUserId);
  db.prepare('DELETE FROM group_members WHERE user_id = ?').run(targetUserId);
  db.prepare('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?').run(targetUserId, targetUserId);
  db.prepare('DELETE FROM deletion_requests WHERE user_id = ?').run(targetUserId);
  db.prepare('DELETE FROM users WHERE id = ?').run(targetUserId);
  return true;
}

function parseDeviceName(ua = '') {
  let browser = 'Browser';
  if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('Chrome/')) browser = 'Chrome';
  else if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Safari/') && !ua.includes('Chrome/')) browser = 'Safari';

  let os = 'Unknown OS';
  if (ua.includes('Windows')) os = 'Windows PC';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else if (ua.includes('Mac OS')) os = 'Mac';
  else if (ua.includes('Linux')) os = 'Linux';

  return `${browser} on ${os}`;
}

function normalizePhone(raw) {
  const cleaned = String(raw || '').replace(/[\s\-()]/g, '');
  const digits = cleaned.replace(/\D/g, '');
  if (digits.length === 10) return '+91' + digits;
  if (digits.length === 12 && digits.startsWith('91')) return '+' + digits;
  if (cleaned.startsWith('+') && digits.length >= 10) return '+' + digits;
  return digits.length >= 10 ? '+' + digits : '';
}

function maskEmail(email) {
  const [user, domain] = email.split('@');
  if (!domain) return email;
  return `${user.slice(0, 2)}***@${domain}`;
}

function isBlockedBetween(u1, u2) {
  const row = db.prepare(`
    SELECT 1 FROM blocks
    WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
  `).get(u1, u2, u2, u1);
  return Boolean(row);
}

function areFriends(id1, id2) {
  if (Number(id1) === Number(id2)) return true;
  if (isBlockedBetween(id1, id2)) return false;
  const row = db.prepare(`
    SELECT id FROM friend_requests
    WHERE status = 'accepted'
      AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
  `).get(id1, id2, id2, id1);
  return Boolean(row);
}

function isGroupMember(groupId, userId) {
  const row = db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?').get(groupId, userId);
  return Boolean(row);
}

async function sendGmailOtp(toEmail, otp, purposeLabel) {
  if (!SENDER_EMAIL) {
    throw new Error('Render Environment me SENDER_EMAIL missing hai.');
  }

  const html = `
    <div style="font-family:sans-serif;max-width:440px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;">
      <h2 style="color:#0f172a;margin-top:0;">CipherChat ${purposeLabel}</h2>
      <p style="color:#475569;">Aapka 6-digit verification OTP (5 minute ke liye valid):</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:6px;background:#f1f5f9;padding:16px;text-align:center;border-radius:8px;color:#059669;">
        ${otp}
      </div>
    </div>`;

  // Cloud / Render ke liye Brevo HTTPS API (Port 443)
  if (BREVO_API_KEY) {
    const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'CipherChat Security', email: SENDER_EMAIL },
        to: [{ email: toEmail }],
        subject: `${otp} is your CipherChat ${purposeLabel} OTP`,
        htmlContent: html
      })
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Brevo API Error (${resp.status}): ${errText}`);
    }
    return;
  }

  // Local PC ke liye Gmail SMTP Fallback
  if (!SENDER_APP_PASSWORD) {
    throw new Error('BREVO_API_KEY ya SENDER_APP_PASSWORD set karein.');
  }

  return new Promise((resolve, reject) => {
    const cleanPass = SENDER_APP_PASSWORD.replace(/\s+/g, '');
    const socket = tls.connect(465, 'smtp.gmail.com', { rejectUnauthorized: true });
    let buffer = '';
    let step = 0;

    const commands = [
      () => `EHLO localhost\r\n`,
      () => `AUTH LOGIN\r\n`,
      () => `${Buffer.from(SENDER_EMAIL).toString('base64')}\r\n`,
      () => `${Buffer.from(cleanPass).toString('base64')}\r\n`,
      () => `MAIL FROM:<${SENDER_EMAIL}>\r\n`,
      () => `RCPT TO:<${toEmail}>\r\n`,
      () => `DATA\r\n`,
      () => [
        `From: "CipherChat Security" <${SENDER_EMAIL}>`,
        `To: <${toEmail}>`,
        `Subject: ${otp} is your CipherChat ${purposeLabel} OTP`,
        `MIME-Version: 1.0`,
        `Content-Type: text/html; charset=UTF-8`,
        ``,
        html,
        `.`
      ].join('\r\n') + '\r\n',
      () => `QUIT\r\n`
    ];

    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buffer += chunk;
      const lines = buffer.split('\r\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line) continue;
        if (/^\d{3} /.test(line)) {
          const code = parseInt(line.slice(0, 3), 10);
          if (code >= 400) {
            socket.destroy();
            return reject(new Error(`Gmail SMTP Error: ${line}`));
          }
          if (step < commands.length) {
            socket.write(commands[step]());
            step++;
          } else {
            socket.end();
            resolve();
          }
        }
      }
    });
    socket.on('error', (err) => reject(err));
  });
}

function generatePngIcon(size) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  const pad = Math.floor(size * 0.24);
  const inner = size - pad;
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0;
    for (let x = 0; x < size; x++) {
      const idx = rowStart + 1 + x * 4;
      const isEmblem = x >= pad && x <= inner && y >= pad && y <= inner &&
        !((x > pad + size * 0.14 && x < inner - size * 0.14) && (y > pad + size * 0.14 && y < inner - size * 0.14));
      if (isEmblem) {
        raw[idx] = 16; raw[idx + 1] = 185; raw[idx + 2] = 129; raw[idx + 3] = 255;
      } else {
        raw[idx] = 6; raw[idx + 1] = 9; raw[idx + 2] = 19; raw[idx + 3] = 255;
      }
    }
  }
  const crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    crcTable[n] = c;
  }
  const makeChunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
    const t = Buffer.from(type, 'ascii');
    const body = Buffer.concat([t, data]);
    let crc = 0xffffffff;
    for (let i = 0; i < body.length; i++) crc = crcTable[(crc ^ body[i]) & 0xff] ^ (crc >>> 8);
    const cBuf = Buffer.alloc(4); cBuf.writeUInt32BE((crc ^ 0xffffffff) >>> 0, 0);
    return Buffer.concat([len, body, cBuf]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', zlib.deflateSync(raw)),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 50 * 1024 * 1024) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(payload));
}

// ==========================================
// 4. API ROUTES
// ==========================================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  try {
    // 1. SIGNUP: LINK EMAIL + PHONE + USERNAME & SEND OTP
    if (req.method === 'POST' && url.pathname === '/api/signup/send-otp') {
      const { name, username, phone, email } = await readJsonBody(req);
      const cleanName = (name || '').trim();
      const cleanUsername = (username || '').trim().toLowerCase().replace(/^@+/, '');
      const cleanPhone = normalizePhone(phone);
      const cleanEmail = (email || '').trim().toLowerCase();

      if (!cleanName || cleanName.length < 2) return sendJson(res, 400, { error: 'Apna poora naam daalein.' });
      if (!/^[a-z0-9_]{3,20}$/.test(cleanUsername)) {
        return sendJson(res, 400, { error: 'Username 3-20 characters ka hona chahiye (sirf a-z, 0-9, _).' });
      }
      if (!cleanPhone) return sendJson(res, 400, { error: 'Sahi 10-digit mobile number daalein.' });
      if (!cleanEmail || !cleanEmail.includes('@')) return sendJson(res, 400, { error: 'Sahi email address daalein.' });

      if (db.prepare('SELECT id FROM users WHERE username = ?').get(cleanUsername)) {
        return sendJson(res, 400, { error: `Username "@${cleanUsername}" pehle se liya ja chuka hai.` });
      }
      if (db.prepare('SELECT id FROM users WHERE phone = ?').get(cleanPhone)) {
        return sendJson(res, 400, { error: 'Is mobile number se pehle se ek account linked hai!' });
      }
      if (db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail)) {
        return sendJson(res, 400, { error: 'Is email se pehle se account bana hai. Login tab use karein.' });
      }

      const otp = crypto.randomInt(100000, 999999).toString();
      const expiresAt = Date.now() + 5 * 60 * 1000;
      const pendingData = JSON.stringify({ name: cleanName, username: cleanUsername, phone: cleanPhone, email: cleanEmail });

      db.prepare(`
        INSERT INTO otps (email, otp, purpose, pending_data, expires_at)
        VALUES (?, ?, 'signup', ?, ?)
        ON CONFLICT(email) DO UPDATE SET
          otp = excluded.otp, purpose = 'signup', pending_data = excluded.pending_data, expires_at = excluded.expires_at
      `).run(cleanEmail, otp, pendingData, expiresAt);

      await sendGmailOtp(cleanEmail, otp, 'Account Registration');
      return sendJson(res, 200, {
        success: true,
        targetEmail: cleanEmail,
        message: `Verification OTP aapke email (${cleanEmail}) par bhej diya gaya hai!`
      });
    }

    // 2. LOGIN: ACCEPT EMAIL OR PHONE -> SEND OTP TO LINKED EMAIL
    if (req.method === 'POST' && url.pathname === '/api/login/send-otp') {
      const { identifier } = await readJsonBody(req);
      const rawId = (identifier || '').trim().toLowerCase();
      if (!rawId) return sendJson(res, 400, { error: 'Registered Email ya Mobile number daalein.' });

      let user = null;
      if (rawId.includes('@') && rawId.includes('.')) {
        user = db.prepare('SELECT * FROM users WHERE email = ?').get(rawId);
      } else {
        const cleanPhone = normalizePhone(rawId);
        const cleanUser = rawId.replace(/^@+/, '');
        user = db.prepare('SELECT * FROM users WHERE phone = ? OR username = ?').get(cleanPhone, cleanUser);
      }

      if (!user) {
        return sendJson(res, 404, { error: 'Is Email ya Mobile se koi account nahi mila. Pehle Create Account karein.' });
      }

      const otp = crypto.randomInt(100000, 999999).toString();
      const expiresAt = Date.now() + 5 * 60 * 1000;

      db.prepare(`
        INSERT INTO otps (email, otp, purpose, pending_data, expires_at)
        VALUES (?, ?, 'login', NULL, ?)
        ON CONFLICT(email) DO UPDATE SET
          otp = excluded.otp, purpose = 'login', pending_data = NULL, expires_at = excluded.expires_at
      `).run(user.email, otp, expiresAt);

      await sendGmailOtp(user.email, otp, 'Login');
      return sendJson(res, 200, {
        success: true,
        targetEmail: user.email,
        message: `Login OTP aapke linked email (${maskEmail(user.email)}) par bhej diya gaya hai!`
      });
    }

    // 3. VERIFY OTP & CREATE DEVICE SESSION
    if (req.method === 'POST' && url.pathname === '/api/verify-otp') {
      const { targetEmail, otp, publicKey, encryptedPrivKey, pinSalt, pinIv } = await readJsonBody(req);
      const cleanEmail = (targetEmail || '').trim().toLowerCase();

      const record = db.prepare('SELECT * FROM otps WHERE email = ?').get(cleanEmail);
      if (!record) return sendJson(res, 400, { error: 'Pehle OTP request karein.' });
      if (Date.now() > record.expires_at) return sendJson(res, 400, { error: 'OTP expire ho gaya hai.' });
      if (record.otp !== (otp || '').trim()) return sendJson(res, 400, { error: 'Galat OTP hai!' });

      db.prepare('DELETE FROM otps WHERE email = ?').run(cleanEmail);

      let user = null;
      if (record.purpose === 'signup') {
        const data = JSON.parse(record.pending_data);
        if (db.prepare('SELECT id FROM users WHERE username = ? OR phone = ? OR email = ?').get(data.username, data.phone, data.email)) {
          return sendJson(res, 400, { error: 'Ye details abhi-abhi register ho chuki hain.' });
        }
        const info = db.prepare(`
          INSERT INTO users (name, username, phone, email, public_key, encrypted_priv_key, pin_salt, pin_iv, last_seen)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(data.name, data.username, data.phone, data.email, publicKey || '', encryptedPrivKey || '', pinSalt || '', pinIv || '', Date.now());

        user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(info.lastInsertRowid));
      } else {
        user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
        if (!user) return sendJson(res, 404, { error: 'User account nahi mila.' });
        db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), user.id);
        if (!user.public_key && publicKey) {
          db.prepare('UPDATE users SET public_key = ?, encrypted_priv_key = ?, pin_salt = ?, pin_iv = ? WHERE id = ?')
            .run(publicKey, encryptedPrivKey || '', pinSalt || '', pinIv || '', user.id);
          user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
        }
      }

      const sessionToken = crypto.randomBytes(24).toString('hex');
      const deviceName = parseDeviceName(req.headers['user-agent'] || '');
      db.prepare('INSERT INTO sessions (user_id, token, device_name, last_active) VALUES (?, ?, ?, ?)')
        .run(user.id, sessionToken, deviceName, Date.now());

      return sendJson(res, 200, {
        success: true,
        user: { ...user, is_admin: isAdminUser(user) },
        sessionToken
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/keys/backup') {
      const { userId, publicKey, encryptedPrivKey, pinSalt, pinIv } = await readJsonBody(req);
      db.prepare('UPDATE users SET public_key = ?, encrypted_priv_key = ?, pin_salt = ?, pin_iv = ? WHERE id = ?')
        .run(publicKey, encryptedPrivKey, pinSalt, pinIv, userId);
      return sendJson(res, 200, { success: true });
    }

    // 4. USER ACCOUNT DELETION REQUEST (WITH MANDATORY TERMS & CONDITIONS CONSENT)
    if (req.method === 'POST' && url.pathname === '/api/account/request-delete') {
      const { userId, reason, acceptedTerms } = await readJsonBody(req);
      if (!acceptedTerms) {
        return sendJson(res, 400, { error: 'Account delete request ke liye Terms & Conditions par tick karna zaroori hai.' });
      }
      const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(userId);
      if (!user) return sendJson(res, 404, { error: 'User nahi mila.' });
      if (isAdminUser(user)) {
        return sendJson(res, 400, { error: 'Primary Administrator account delete nahi kiya ja sakta.' });
      }

      const acceptedAt = new Date().toISOString();
      const deviceInfo = parseDeviceName(req.headers['user-agent'] || '');
      const cleanReason = (reason || '').trim().slice(0, 250);

      db.prepare(`
        INSERT INTO deletion_requests (user_id, reason, accepted_terms, terms_accepted_at, device_info, status)
        VALUES (?, ?, 1, ?, ?, 'pending')
        ON CONFLICT(user_id) DO UPDATE SET
          reason = excluded.reason,
          accepted_terms = 1,
          terms_accepted_at = excluded.terms_accepted_at,
          device_info = excluded.device_info,
          status = 'pending',
          created_at = CURRENT_TIMESTAMP
      `).run(userId, cleanReason, acceptedAt, deviceInfo);

      return sendJson(res, 200, {
        success: true,
        message: 'Aapki Account Deletion Request submit ho gayi hai. Admin review ke baad account permanently delete ho jayega.'
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/account/cancel-delete') {
      const { userId } = await readJsonBody(req);
      db.prepare("DELETE FROM deletion_requests WHERE user_id = ? AND status = 'pending'").run(userId);
      return sendJson(res, 200, { success: true });
    }

    // 5. ADMINISTRATOR PANEL APIs (OVERVIEW + REVIEW DELETION)
    if (req.method === 'GET' && url.pathname === '/api/admin/overview') {
      const adminId = Number(url.searchParams.get('adminId') || 0);
      const adminUser = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
      if (!isAdminUser(adminUser)) {
        return sendJson(res, 403, { error: 'Unauthorized: Sirf Administrator hi ye panel dekh sakta hai.' });
      }

      const now = Date.now();
      const users = db.prepare(`
        SELECT u.id, u.name, u.username, u.phone, u.email, u.last_seen, u.created_at,
               dr.status AS deletion_status, dr.terms_accepted_at
        FROM users u
        LEFT JOIN deletion_requests dr ON dr.user_id = u.id
        ORDER BY u.id DESC
      `).all().map((u) => ({
        ...u,
        is_online: now - (u.last_seen || 0) < 12000,
        is_admin: u.email.toLowerCase() === ADMIN_EMAIL
      }));

      const deletionRequests = db.prepare(`
        SELECT dr.id AS request_id, dr.user_id, dr.reason, dr.accepted_terms, dr.terms_accepted_at,
               dr.device_info, dr.status, dr.created_at,
               u.name, u.username, u.phone, u.email
        FROM deletion_requests dr
        JOIN users u ON u.id = dr.user_id
        WHERE dr.status = 'pending'
        ORDER BY dr.id ASC
      `).all();

      const auditLogs = db.prepare(`
        SELECT * FROM deletion_audit_logs
        ORDER BY id DESC
        LIMIT 50
      `).all();

      const groupCount = db.prepare('SELECT COUNT(*) AS c FROM groups').get().c;
      const msgCount = db.prepare('SELECT COUNT(*) AS c FROM messages').get().c;

      return sendJson(res, 200, {
        stats: {
          totalUsers: users.length,
          pendingDeletions: deletionRequests.length,
          totalGroups: groupCount,
          totalMessages: msgCount
        },
        users,
        deletionRequests,
        auditLogs
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/review-delete') {
      const { adminId, targetUserId, action } = await readJsonBody(req);
      const adminUser = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
      if (!isAdminUser(adminUser)) {
        return sendJson(res, 403, { error: 'Unauthorized: Administrator access required.' });
      }

      const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);
      if (!targetUser) return sendJson(res, 404, { error: 'User account nahi mila.' });
      if (isAdminUser(targetUser)) {
        return sendJson(res, 400, { error: 'Admin account delete nahi ho sakta.' });
      }

      const reqRow = db.prepare('SELECT * FROM deletion_requests WHERE user_id = ?').get(targetUserId);

      if (action === 'approve') {
        if (!reqRow || !reqRow.accepted_terms) {
          return sendJson(res, 400, { error: 'User ne abhi tak Terms & Conditions accept nahi ki hain.' });
        }
        permanentlyDeleteUserAccount(targetUserId, reqRow.reason, reqRow.terms_accepted_at, adminUser.email);
        return sendJson(res, 200, {
          success: true,
          message: `@${targetUser.username} (${targetUser.name}) ka account review ke baad permanently delete kar diya gaya hai.`
        });
      }

      if (action === 'reject') {
        db.prepare("UPDATE deletion_requests SET status = 'rejected' WHERE user_id = ?").run(targetUserId);
        return sendJson(res, 200, {
          success: true,
          message: `@${targetUser.username} ki deletion request reject kar di gayi hai.`
        });
      }

      return sendJson(res, 400, { error: 'Invalid action' });
    }

    // 6. PROFILE SETTINGS & REMOTE SESSION LOGOUT
    if (req.method === 'POST' && url.pathname === '/api/profile/update') {
      const { userId, name, bio } = await readJsonBody(req);
      const cleanName = (name || '').trim();
      const cleanBio = (bio || '').trim().slice(0, 140);
      if (cleanName.length < 2) return sendJson(res, 400, { error: 'Naam kam se kam 2 letters ka hona chahiye.' });

      db.prepare('UPDATE users SET name = ?, bio = ? WHERE id = ?').run(cleanName, cleanBio, userId);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      return sendJson(res, 200, { success: true, user: { ...user, is_admin: isAdminUser(user) } });
    }

    if (req.method === 'POST' && url.pathname === '/api/sessions/revoke') {
      const { userId, sessionId } = await readJsonBody(req);
      db.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').run(sessionId, userId);
      return sendJson(res, 200, { success: true });
    }

    // 7. EXPIRING INVITE LINKS & QR CODES
    if (req.method === 'POST' && url.pathname === '/api/invites/create') {
      const { userId, ttlMs } = await readJsonBody(req);
      const token = 'CC-' + crypto.randomBytes(4).toString('hex').toUpperCase();
      const expiresAt = Date.now() + (Number(ttlMs) || 3600000);
      db.prepare('INSERT INTO invite_tokens (token, creator_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt);
      return sendJson(res, 200, { success: true, token, expiresAt });
    }

    if (req.method === 'POST' && url.pathname === '/api/invites/redeem') {
      const { userId, token } = await readJsonBody(req);
      const cleanToken = (token || '').trim().toUpperCase();
      const inv = db.prepare('SELECT * FROM invite_tokens WHERE token = ?').get(cleanToken);
      if (!inv) return sendJson(res, 404, { error: 'Invalid invite code.' });
      if (Date.now() > inv.expires_at) {
        db.prepare('DELETE FROM invite_tokens WHERE token = ?').run(cleanToken);
        return sendJson(res, 400, { error: 'Invite link/code expire ho chuka hai.' });
      }
      if (Number(inv.creator_id) === Number(userId)) {
        return sendJson(res, 400, { error: 'Ye aapka khud ka invite code hai.' });
      }
      if (isBlockedBetween(userId, inv.creator_id)) {
        return sendJson(res, 403, { error: 'Cannot connect with this user.' });
      }

      const creator = db.prepare('SELECT id, name, username FROM users WHERE id = ?').get(inv.creator_id);
      if (!creator) return sendJson(res, 404, { error: 'Creator account nahi mila.' });

      const existing = db.prepare(`
        SELECT * FROM friend_requests
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
      `).get(userId, creator.id, creator.id, userId);

      if (existing) {
        db.prepare("UPDATE friend_requests SET status = 'accepted' WHERE id = ?").run(existing.id);
      } else {
        db.prepare("INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, 'accepted')").run(creator.id, userId);
      }

      return sendJson(res, 200, {
        success: true,
        message: `Invite verified! Ab aap aur @${creator.username} (${creator.name}) direct E2EE friends hain!`
      });
    }

    // 8. EXPORT ENCRYPTED VAULT DATA (.cipher)
    if (req.method === 'GET' && url.pathname === '/api/vault/export') {
      const userId = Number(url.searchParams.get('userId') || 0);
      const user = db.prepare('SELECT id, name, username, phone, email, bio, public_key FROM users WHERE id = ?').get(userId);
      if (!user) return sendJson(res, 404, { error: 'User not found' });

      const messages = db.prepare(`
        SELECT id, sender_id, receiver_id, group_id, msg_type, ciphertext, iv, file_name, is_sealed, created_at
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
        ORDER BY id ASC
      `).all(userId, userId);

      return sendJson(res, 200, { user, messages, exportedAt: new Date().toISOString() });
    }

    // 9. SEARCH & FRIEND REQUESTS
    if (req.method === 'GET' && url.pathname === '/api/friends/search') {
      const q = (url.searchParams.get('q') || '').trim().toLowerCase();
      const myId = Number(url.searchParams.get('myId') || 0);
      if (!q) return sendJson(res, 400, { error: 'Search query required' });

      let target = null;
      if (q.includes('@') && q.includes('.')) {
        target = db.prepare('SELECT id, name, username, phone, email, bio FROM users WHERE email = ?').get(q);
      } else {
        const cleanUser = q.replace(/^@+/, '');
        const cleanPhone = normalizePhone(q);
        target = db.prepare('SELECT id, name, username, phone, email, bio FROM users WHERE username = ? OR phone = ?').get(cleanUser, cleanPhone);
      }

      if (!target || Number(target.id) === myId) return sendJson(res, 404, { error: 'Koi matching user nahi mila.' });
      if (isBlockedBetween(myId, target.id)) return sendJson(res, 403, { error: 'Ye user available nahi hai (Blocked).' });

      return sendJson(res, 200, { user: target });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/request') {
      const { senderId, query } = await readJsonBody(req);
      const q = (query || '').trim().toLowerCase();
      if (!senderId || !q) return sendJson(res, 400, { error: 'Username, Mobile ya Email daalein.' });

      let target = null;
      if (q.includes('@') && q.includes('.')) {
        target = db.prepare('SELECT id, name, username FROM users WHERE email = ?').get(q);
      } else {
        const cleanUser = q.replace(/^@+/, '');
        const cleanPhone = normalizePhone(q);
        target = db.prepare('SELECT id, name, username FROM users WHERE username = ? OR phone = ?').get(cleanUser, cleanPhone);
      }

      if (!target) return sendJson(res, 404, { error: 'Is Username, Mobile ya Email se koi account nahi mila.' });
      if (Number(target.id) === Number(senderId)) return sendJson(res, 400, { error: 'Khud ko request nahi bhej sakte.' });
      if (isBlockedBetween(senderId, target.id)) return sendJson(res, 403, { error: 'Aap is user ko request nahi bhej sakte.' });

      const existing = db.prepare(`
        SELECT * FROM friend_requests
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
      `).get(senderId, target.id, target.id, senderId);

      if (existing) {
        if (existing.status === 'accepted') return sendJson(res, 400, { error: `@${target.username} pehle se aapke friend hain!` });
        if (existing.status === 'pending') {
          if (Number(existing.receiver_id) === Number(senderId)) {
            db.prepare("UPDATE friend_requests SET status = 'accepted' WHERE id = ?").run(existing.id);
            return sendJson(res, 200, { success: true, message: `@${target.username} ki request accept ho gayi!` });
          }
          return sendJson(res, 400, { error: `@${target.username} ko request pehle se bheji ja chuki hai.` });
        }
        db.prepare("UPDATE friend_requests SET sender_id = ?, receiver_id = ?, status = 'pending' WHERE id = ?").run(senderId, target.id, existing.id);
        return sendJson(res, 200, { success: true, message: `@${target.username} ko friend request bhej di gayi!` });
      }

      db.prepare('INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, ?)').run(senderId, target.id, 'pending');
      return sendJson(res, 200, { success: true, message: `@${target.username} (${target.name}) ko friend request bhej di gayi!` });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/respond') {
      const { requestId, userId, action } = await readJsonBody(req);
      const reqRow = db.prepare('SELECT * FROM friend_requests WHERE id = ? AND receiver_id = ?').get(requestId, userId);
      if (!reqRow) return sendJson(res, 404, { error: 'Request nahi mili.' });

      const newStatus = action === 'accept' ? 'accepted' : 'rejected';
      db.prepare('UPDATE friend_requests SET status = ? WHERE id = ?').run(newStatus, requestId);
      return sendJson(res, 200, { success: true, status: newStatus });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/unfriend') {
      const { userId, targetId } = await readJsonBody(req);
      db.prepare('DELETE FROM friend_requests WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)')
        .run(userId, targetId, targetId, userId);
      return sendJson(res, 200, { success: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/block') {
      const { userId, targetId } = await readJsonBody(req);
      db.prepare('DELETE FROM friend_requests WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)')
        .run(userId, targetId, targetId, userId);
      db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)').run(userId, targetId);
      return sendJson(res, 200, { success: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/unblock') {
      const { userId, targetId } = await readJsonBody(req);
      db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(userId, targetId);
      return sendJson(res, 200, { success: true });
    }

    // 10. CREATE ENCRYPTED GROUP
    if (req.method === 'POST' && url.pathname === '/api/groups/create') {
      const { name, creatorId, members } = await readJsonBody(req);
      const cleanName = (name || '').trim();
      if (!cleanName) return sendJson(res, 400, { error: 'Group name daalein.' });
      if (!Array.isArray(members) || members.length < 2) {
        return sendJson(res, 400, { error: 'Group me kam se kam 1 friend select karein.' });
      }

      const info = db.prepare('INSERT INTO groups (name, created_by) VALUES (?, ?)').run(cleanName, creatorId);
      const groupId = Number(info.lastInsertRowid);

      const insertMember = db.prepare(`
        INSERT INTO group_members (group_id, user_id, encrypted_group_key, key_iv, added_by)
        VALUES (?, ?, ?, ?, ?)
      `);
      for (const m of members) {
        insertMember.run(groupId, m.userId, m.encryptedGroupKey, m.keyIv, creatorId);
      }

      return sendJson(res, 200, { success: true, groupId });
    }

    // 11. SYNC DASHBOARD & VALIDATE ACCOUNT/SESSION
    if (req.method === 'GET' && url.pathname === '/api/dashboard') {
      const userId = Number(url.searchParams.get('userId') || 0);
      const sessionToken = url.searchParams.get('sessionToken') || '';
      if (!userId) return sendJson(res, 400, { error: 'userId required' });

      const userRow = db.prepare('SELECT id, email FROM users WHERE id = ?').get(userId);
      if (!userRow) {
        return sendJson(res, 401, { revoked: true, error: 'Aapka account Admin review ke baad permanently delete kar diya gaya hai.' });
      }

      const now = Date.now();
      if (sessionToken) {
        const sess = db.prepare('SELECT id FROM sessions WHERE user_id = ? AND token = ?').get(userId, sessionToken);
        if (!sess) return sendJson(res, 401, { revoked: true, error: 'Session revoked from another device.' });
        db.prepare('UPDATE sessions SET last_active = ? WHERE id = ?').run(now, sess.id);
      }

      db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now, userId);

      const friends = db.prepare(`
        SELECT u.id, u.name, u.username, u.phone, u.email, u.bio, u.public_key, u.last_seen,
               (SELECT COUNT(*) FROM messages m
                WHERE m.group_id IS NULL AND m.sender_id = u.id AND m.receiver_id = ? AND m.is_read = 0 AND m.is_deleted = 0) AS unread_count
        FROM friend_requests fr
        JOIN users u ON u.id = CASE WHEN fr.sender_id = ? THEN fr.receiver_id ELSE fr.sender_id END
        WHERE fr.status = 'accepted' AND (fr.sender_id = ? OR fr.receiver_id = ?)
        ORDER BY u.name ASC
      `).all(userId, userId, userId, userId).map((f) => ({
        ...f,
        is_online: now - (f.last_seen || 0) < 12000
      }));

      const incoming = db.prepare(`
        SELECT fr.id AS request_id, u.id AS user_id, u.name, u.username, u.email
        FROM friend_requests fr
        JOIN users u ON u.id = fr.sender_id
        WHERE fr.receiver_id = ? AND fr.status = 'pending'
        ORDER BY fr.id DESC
      `).all(userId);

      const outgoing = db.prepare(`
        SELECT fr.id AS request_id, u.id AS user_id, u.name, u.username
        FROM friend_requests fr
        JOIN users u ON u.id = fr.receiver_id
        WHERE fr.sender_id = ? AND fr.status = 'pending'
        ORDER BY fr.id DESC
      `).all(userId);

      const groups = db.prepare(`
        SELECT g.id, g.name, g.created_by, gm.encrypted_group_key, gm.key_iv,
               u_adder.public_key AS adder_public_key,
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count
        FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        JOIN users u_adder ON u_adder.id = gm.added_by
        WHERE gm.user_id = ?
        ORDER BY g.id DESC
      `).all(userId);

      const blocked = db.prepare(`
        SELECT u.id, u.name, u.username
        FROM blocks b
        JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = ?
      `).all(userId);

      const sessions = db.prepare(`
        SELECT id, token, device_name, last_active
        FROM sessions
        WHERE user_id = ?
        ORDER BY last_active DESC
      `).all(userId);

      const deletionRequest = db.prepare(`
        SELECT status, reason, terms_accepted_at, created_at
        FROM deletion_requests
        WHERE user_id = ?
      `).get(userId) || null;

      return sendJson(res, 200, {
        friends,
        incoming,
        outgoing,
        groups,
        blocked,
        sessions,
        deletionRequest,
        isAdmin: isAdminUser(userRow)
      });
    }

    // 12. WEBRTC AUDIO/VIDEO/SCREEN CALL SIGNALING
    if (req.method === 'POST' && url.pathname === '/api/call/signal') {
      const { fromUserId, toUserId, type, payload } = await readJsonBody(req);
      if (!areFriends(fromUserId, toUserId)) return sendJson(res, 403, { error: 'Not friends' });

      const sender = db.prepare('SELECT id, name, username FROM users WHERE id = ?').get(fromUserId);
      if (!sender) return sendJson(res, 404, { error: 'Sender not found' });

      const targetId = Number(toUserId);
      if (!callSignals.has(targetId)) callSignals.set(targetId, []);
      callSignals.get(targetId).push({
        id: signalSeq++,
        fromUser: sender,
        type,
        payload,
        ts: Date.now()
      });
      return sendJson(res, 200, { success: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/call/poll') {
      const userId = Number(url.searchParams.get('userId') || 0);
      const afterId = Number(url.searchParams.get('afterId') || 0);
      const queue = callSignals.get(userId) || [];
      const fresh = queue.filter((s) => s.id > afterId);
      return sendJson(res, 200, { signals: fresh });
    }

    // 13. LIVE TYPING STATUS
    if (req.method === 'POST' && url.pathname === '/api/typing') {
      const { senderId, targetKey } = await readJsonBody(req);
      typingStatus.set(`${senderId}->${targetKey}`, Date.now());
      return sendJson(res, 200, { success: true });
    }

    // 14. ENCRYPTED MESSAGES (SEALED SENDER, STEGO, POLLS, EDITING)
    if (req.method === 'GET' && url.pathname === '/api/messages') {
      const userId = Number(url.searchParams.get('userId') || 0);
      const peerId = Number(url.searchParams.get('peerId') || 0);
      const groupId = Number(url.searchParams.get('groupId') || 0);
      const now = Date.now();

      db.prepare('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?').run(now);

      if (groupId) {
        if (!isGroupMember(groupId, userId)) return sendJson(res, 403, { error: 'Not a group member' });
        const rows = db.prepare(`
          SELECT m.*, u.name AS sender_name, u.username AS sender_username
          FROM messages m
          LEFT JOIN users u ON u.id = m.sender_id
          WHERE m.group_id = ?
          ORDER BY m.id ASC
        `).all(groupId);

        let typingUser = null;
        for (const [k, ts] of typingStatus.entries()) {
          if (k.endsWith(`->group:${groupId}`) && now - ts < 3500) {
            const typerId = Number(k.split('->')[0]);
            if (typerId !== userId) {
              const u = db.prepare('SELECT name FROM users WHERE id = ?').get(typerId);
              if (u) typingUser = u.name;
            }
          }
        }
        return sendJson(res, 200, { messages: rows, typingUser });
      }

      if (!areFriends(userId, peerId)) return sendJson(res, 403, { error: 'Friend request accept honi zaroori hai.' });

      db.prepare('UPDATE messages SET is_read = 1 WHERE group_id IS NULL AND sender_id = ? AND receiver_id = ? AND is_read = 0')
        .run(peerId, userId);

      const rows = db.prepare(`
        SELECT m.*, u.name AS sender_name, u.username AS sender_username
        FROM messages m
        LEFT JOIN users u ON u.id = m.sender_id
        WHERE m.group_id IS NULL
          AND (
            (m.sender_id = ? AND m.receiver_id = ?)
            OR (m.sender_id = ? AND m.receiver_id = ?)
            OR (m.is_sealed = 1 AND m.sender_id = 0 AND (m.receiver_id = ? OR m.receiver_id = ?))
          )
        ORDER BY m.id ASC
      `).all(userId, peerId, peerId, userId, userId, peerId);

      const peerTypingTs = typingStatus.get(`${peerId}->user:${userId}`) || 0;
      const typingUser = now - peerTypingTs < 3500 ? 'typing' : null;

      return sendJson(res, 200, { messages: rows, typingUser });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages') {
      const { senderId, receiverId, groupId, msgType, ciphertext, iv, fileName, replyToId, isViewOnce, isSealed, ttlMs } = await readJsonBody(req);
      if (!senderId || !ciphertext || !iv) return sendJson(res, 400, { error: 'Incomplete encrypted payload' });

      if (groupId) {
        if (!isGroupMember(groupId, senderId)) return sendJson(res, 403, { error: 'Not a group member.' });
      } else {
        if (!receiverId || !areFriends(senderId, receiverId)) {
          return sendJson(res, 403, { error: 'Sirf accepted friends ko hi message bhej sakte hain.' });
        }
      }

      const storedSenderId = !groupId && isSealed ? 0 : senderId;
      const expiresAt = ttlMs && Number(ttlMs) > 0 ? Date.now() + Number(ttlMs) : null;

      const info = db.prepare(`
        INSERT INTO messages (sender_id, receiver_id, group_id, msg_type, ciphertext, iv, file_name, reply_to_id, is_view_once, is_sealed, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        storedSenderId,
        groupId ? 0 : receiverId,
        groupId || null,
        msgType || 'text',
        ciphertext,
        iv,
        fileName || null,
        replyToId || null,
        isViewOnce ? 1 : 0,
        !groupId && isSealed ? 1 : 0,
        expiresAt
      );

      return sendJson(res, 200, { success: true, id: Number(info.lastInsertRowid) });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages/edit') {
      const { messageId, userId, ciphertext, iv } = await readJsonBody(req);
      const msg = db.prepare('SELECT sender_id, is_sealed FROM messages WHERE id = ?').get(messageId);
      if (!msg) return sendJson(res, 404, { error: 'Message not found' });
      if (!msg.is_sealed && Number(msg.sender_id) !== Number(userId)) {
        return sendJson(res, 403, { error: 'Sirf aap apne bheje messages edit kar sakte hain.' });
      }
      db.prepare('UPDATE messages SET ciphertext = ?, iv = ?, is_edited = 1 WHERE id = ?').run(ciphertext, iv, messageId);
      return sendJson(res, 200, { success: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages/vote') {
      const { messageId, userId, optionIndex } = await readJsonBody(req);
      const msg = db.prepare('SELECT poll_votes FROM messages WHERE id = ?').get(messageId);
      if (!msg) return sendJson(res, 404, { error: 'Poll not found' });

      let votes = {};
      try { votes = JSON.parse(msg.poll_votes || '{}'); } catch {}
      const uid = Number(userId);
      const optKey = String(optionIndex);
      const alreadyVotedThis = Array.isArray(votes[optKey]) && votes[optKey].includes(uid);

      for (const k of Object.keys(votes)) {
        votes[k] = (votes[k] || []).filter((id) => id !== uid);
        if (votes[k].length === 0) delete votes[k];
      }

      if (!alreadyVotedThis) {
        if (!votes[optKey]) votes[optKey] = [];
        votes[optKey].push(uid);
      }

      db.prepare('UPDATE messages SET poll_votes = ? WHERE id = ?').run(JSON.stringify(votes), messageId);
      return sendJson(res, 200, { success: true, votes });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages/view-once') {
      const { messageId, userId } = await readJsonBody(req);
      const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
      if (!msg) return sendJson(res, 404, { error: 'Message already destroyed' });
      if (Number(msg.receiver_id) === Number(userId) || msg.group_id) {
        db.prepare("UPDATE messages SET ciphertext = '', is_deleted = 1 WHERE id = ?").run(messageId);
      }
      return sendJson(res, 200, { success: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages/react') {
      const { messageId, userId, emoji } = await readJsonBody(req);
      const msg = db.prepare('SELECT reactions FROM messages WHERE id = ?').get(messageId);
      if (!msg) return sendJson(res, 404, { error: 'Message not found' });

      let reactions = {};
      try { reactions = JSON.parse(msg.reactions || '{}'); } catch {}
      if (!reactions[emoji]) reactions[emoji] = [];

      const idx = reactions[emoji].indexOf(Number(userId));
      if (idx >= 0) {
        reactions[emoji].splice(idx, 1);
        if (reactions[emoji].length === 0) delete reactions[emoji];
      } else {
        reactions[emoji].push(Number(userId));
      }

      db.prepare('UPDATE messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), messageId);
      return sendJson(res, 200, { success: true, reactions });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages/delete') {
      const { messageId, userId } = await readJsonBody(req);
      const msg = db.prepare('SELECT sender_id, is_sealed FROM messages WHERE id = ?').get(messageId);
      if (!msg) return sendJson(res, 404, { error: 'Message not found' });
      if (!msg.is_sealed && Number(msg.sender_id) !== Number(userId)) {
        return sendJson(res, 403, { error: 'Sirf aap apne bheje gaye messages delete kar sakte hain.' });
      }
      db.prepare("UPDATE messages SET ciphertext = '', is_deleted = 1, reactions = '{}' WHERE id = ?").run(messageId);
      return sendJson(res, 200, { success: true });
    }

    // 15. BUILT-IN PWA PNG ICONS, MANIFEST & SERVICE WORKER
    if (req.method === 'GET' && (url.pathname === '/icon-192.png' || url.pathname === '/icon-512.png')) {
      const size = url.pathname === '/icon-192.png' ? 192 : 512;
      const png = generatePngIcon(size);
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
      return res.end(png);
    }

    if (req.method === 'GET' && url.pathname === '/manifest.json') {
      return sendJson(res, 200, {
        id: '/',
        name: 'CipherChat Ultimate',
        short_name: 'CipherChat',
        description: 'End-to-End Encrypted Messenger',
        start_url: '/',
        scope: '/',
        display: 'standalone',
        background_color: '#060913',
        theme_color: '#060913',
        icons: [
          { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
          { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
        ]
      });
    }

    if (req.method === 'GET' && url.pathname === '/sw.js') {
      res.writeHead(200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });
      return res.end(`
        self.addEventListener('install', () => self.skipWaiting());
        self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
        self.addEventListener('fetch', (e) => {
          e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
        });
      `);
    }

    // 16. SERVE FRONTEND
    const reqPath = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\/+/, '');
    const filePath = path.join(__dirname, 'public', reqPath);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      const mimeTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.svg': 'image/svg+xml'
      };
      res.writeHead(200, {
        'Content-Type': mimeTypes[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });
      return fs.createReadStream(filePath).pipe(res);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
  } catch (err) {
    console.error('Server Error:', err);
    sendJson(res, 500, { error: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`\nCipherChat Ultimate Server running at: http://localhost:${PORT}`);
  console.log(`Configured Administrator Email: ${ADMIN_EMAIL}`);

});
