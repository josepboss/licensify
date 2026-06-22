const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// ─── Configuration ─────────────────────────────────────────────
const PORT = process.env.PORT || 7008;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const API_KEY = process.env.API_KEY || crypto.randomBytes(32).toString('hex');

// ─── App Setup ─────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiting ────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const validateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  message: { error: 'Too many validation requests, please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// ─── Database Initialization ───────────────────────────────────
const dbPath = path.join(__dirname, 'licenses.db');
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    user_email TEXT DEFAULT '',
    user_name TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    is_permanent INTEGER DEFAULT 0,
    duration_minutes INTEGER DEFAULT 0,
    duration_hours INTEGER DEFAULT 0,
    duration_days INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT,
    last_validated_at TEXT,
    notes TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}'
  );

  CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
  CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(is_active);
  CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at);
`);

// Create default admin user if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get(ADMIN_USERNAME);
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, hash);
  console.log('✓ Default admin user created');
}

// Save API key to a file for reference
const apiKeyPath = path.join(__dirname, '.api_key');
if (!fs.existsSync(apiKeyPath)) {
  fs.writeFileSync(apiKeyPath, API_KEY);
  console.log(`✓ API key saved to .api_key`);
}

// ─── Helper Functions ──────────────────────────────────────────

function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const randomBlock = () => {
    let block = '';
    for (let i = 0; i < 4; i++) {
      block += chars[crypto.randomInt(chars.length)];
    }
    return block;
  };
  return `${randomBlock()}-${randomBlock()}-${randomBlock()}-${randomBlock()}`;
}

function calculateExpiry(minutes, hours, days, isPermanent) {
  if (isPermanent) return null;
  const now = new Date();
  const totalMs = (minutes || 0) * 60 * 1000 +
                  (hours || 0) * 60 * 60 * 1000 +
                  (days || 0) * 24 * 60 * 60 * 1000;
  if (totalMs <= 0) return null;
  return new Date(now.getTime() + totalMs).toISOString();
}

function isLicenseExpired(license) {
  if (license.is_permanent) return false;
  if (!license.expires_at) return false;
  return new Date(license.expires_at) < new Date();
}

function formatDuration(license) {
  const parts = [];
  if (license.duration_days > 0) parts.push(`${license.duration_days}d`);
  if (license.duration_hours > 0) parts.push(`${license.duration_hours}h`);
  if (license.duration_minutes > 0) parts.push(`${license.duration_minutes}m`);
  if (license.is_permanent) return 'Permanent';
  return parts.join(' ') || 'Custom';
}

// ─── Middleware ────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function apiKeyMiddleware(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!key) {
    return res.status(401).json({ error: 'API key required.' });
  }
  // Accept both the system API key and admin-generated keys
  if (key !== API_KEY) {
    return res.status(403).json({ error: 'Invalid API key.' });
  }
  next();
}

// ─── Auth Routes ───────────────────────────────────────────────

app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    token,
    user: { id: user.id, username: user.username },
    api_key: API_KEY,
  });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  res.json({ message: 'Logged out successfully.' });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user });
});

// ─── License Routes ────────────────────────────────────────────

// List all licenses with search, filter, pagination
app.get('/api/licenses', authMiddleware, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  const status = req.query.status || 'all';
  const sortBy = req.query.sort_by || 'created_at';
  const sortOrder = req.query.sort_order === 'asc' ? 'ASC' : 'DESC';

  // Whitelist sort columns to prevent SQL injection
  const validSorts = ['created_at', 'expires_at', 'license_key', 'id'];
  const sortCol = validSorts.includes(sortBy) ? sortBy : 'created_at';

  let whereClauses = [];
  let params = [];

  if (search) {
    whereClauses.push('(license_key LIKE ? OR user_email LIKE ? OR user_name LIKE ? OR notes LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (status === 'active') {
    whereClauses.push('is_active = 1 AND (is_permanent = 1 OR expires_at IS NULL OR expires_at > datetime(\'now\'))');
  } else if (status === 'expired') {
    whereClauses.push('is_active = 1 AND is_permanent = 0 AND expires_at IS NOT NULL AND expires_at <= datetime(\'now\')');
  } else if (status === 'revoked') {
    whereClauses.push('is_active = 0');
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM licenses ${whereSQL}`).get(...params);
  const total = countRow.total;

  const rows = db.prepare(
    `SELECT * FROM licenses ${whereSQL} ORDER BY ${sortCol} ${sortOrder} LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);

  // Add computed status to each row
  const licenses = rows.map(row => ({
    ...row,
    status: row.is_active === 0 ? 'revoked' :
            isLicenseExpired(row) ? 'expired' : 'active',
    duration_display: formatDuration(row),
  }));

  res.json({
    licenses,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
});

// Generate new license
app.post('/api/licenses', authMiddleware, (req, res) => {
  const {
    duration_minutes = 0,
    duration_hours = 0,
    duration_days = 0,
    is_permanent = false,
    user_email = '',
    user_name = '',
    notes = '',
    metadata = {},
  } = req.body;

  // Validate duration
  const mins = parseInt(duration_minutes) || 0;
  const hours = parseInt(duration_hours) || 0;
  const days = parseInt(duration_days) || 0;
  const permanent = Boolean(is_permanent);

  if (mins < 0 || mins > 59) return res.status(400).json({ error: 'Minutes must be between 0 and 59.' });
  if (hours < 0 || hours > 23) return res.status(400).json({ error: 'Hours must be between 0 and 23.' });
  if (days < 0 || days > 3650) return res.status(400).json({ error: 'Days must be between 0 and 3650.' });
  if (!permanent && mins === 0 && hours === 0 && days === 0) {
    return res.status(400).json({ error: 'Set a duration or mark as permanent.' });
  }

  // Generate unique key
  let license_key;
  let attempts = 0;
  do {
    license_key = generateLicenseKey();
    attempts++;
    if (attempts > 10) return res.status(500).json({ error: 'Failed to generate unique key.' });
  } while (db.prepare('SELECT id FROM licenses WHERE license_key = ?').get(license_key));

  const expiresAt = calculateExpiry(mins, hours, days, permanent);
  const metadataStr = typeof metadata === 'object' ? JSON.stringify(metadata) : metadata;

  const result = db.prepare(`
    INSERT INTO licenses (license_key, user_email, user_name, is_active, is_permanent,
                          duration_minutes, duration_hours, duration_days, expires_at, notes, metadata)
    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
  `).run(license_key, user_email, user_name, permanent ? 1 : 0,
         mins, hours, days, expiresAt, notes, metadataStr);

  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(result.lastInsertRowid);

  res.status(201).json({
    ...license,
    status: 'active',
    duration_display: formatDuration(license),
  });
});

// Get single license
app.get('/api/licenses/:id', authMiddleware, (req, res) => {
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  res.json({
    ...license,
    status: license.is_active === 0 ? 'revoked' :
            isLicenseExpired(license) ? 'expired' : 'active',
    duration_display: formatDuration(license),
  });
});

// Update license (revoke/reactivate/edit)
app.put('/api/licenses/:id', authMiddleware, (req, res) => {
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  const { is_active, user_email, user_name, notes } = req.body;

  const updates = [];
  const params = [];

  if (is_active !== undefined) {
    const newActive = is_active ? 1 : 0;
    updates.push('is_active = ?');
    params.push(newActive);
    if (!is_active) {
      updates.push('revoked_at = datetime(\'now\')');
    } else {
      updates.push('revoked_at = NULL');
    }
  }
  if (user_email !== undefined) {
    updates.push('user_email = ?');
    params.push(user_email);
  }
  if (user_name !== undefined) {
    updates.push('user_name = ?');
    params.push(user_name);
  }
  if (notes !== undefined) {
    updates.push('notes = ?');
    params.push(notes);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }

  params.push(req.params.id);
  db.prepare(`UPDATE licenses SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  const updated = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  res.json({
    ...updated,
    status: updated.is_active === 0 ? 'revoked' :
            isLicenseExpired(updated) ? 'expired' : 'active',
    duration_display: formatDuration(updated),
  });
});

// Delete license
app.delete('/api/licenses/:id', authMiddleware, (req, res) => {
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  db.prepare('DELETE FROM licenses WHERE id = ?').run(req.params.id);
  res.json({ message: 'License deleted successfully.' });
});

// ─── Validation Route (Public with API Key) ────────────────────

app.post('/api/validate', validateLimiter, apiKeyMiddleware, (req, res) => {
  const { license_key, ip_address, device_info } = req.body;
  if (!license_key) {
    return res.status(400).json({ error: 'License key is required.' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!license) {
    return res.status(404).json({
      valid: false,
      error: 'License key not found.',
    });
  }

  // Track validation
  const meta = license.metadata ? JSON.parse(license.metadata) : {};
  const validations = meta.validations || [];
  validations.push({
    ip: ip_address || req.ip,
    device: device_info || 'unknown',
    timestamp: new Date().toISOString(),
  });
  // Keep last 100 validations
  const trimmed = validations.slice(-100);
  const updatedMeta = { ...meta, validations: trimmed, last_ip: ip_address || req.ip };

  const now = new Date();
  const expired = !license.is_permanent && license.expires_at && new Date(license.expires_at) < now;

  let status = { valid: true };
  if (!license.is_active) {
    status = { valid: false, error: 'License has been revoked.', revoked_at: license.revoked_at };
  } else if (expired) {
    status = { valid: false, error: 'License has expired.', expires_at: license.expires_at };
  } else {
    // Update last validated timestamp
    db.prepare('UPDATE licenses SET last_validated_at = datetime(\'now\'), metadata = ? WHERE id = ?')
      .run(JSON.stringify(updatedMeta), license.id);
  }

  res.json({
    ...status,
    license_key: license.license_key,
    is_permanent: !!license.is_permanent,
    expires_at: license.expires_at,
    created_at: license.created_at,
    validations_remaining: !license.expires_at ? null :
      Math.max(0, Math.floor((new Date(license.expires_at) - now) / (1000 * 60 * 60 * 24))),
  });
});

// ─── Stats Route ───────────────────────────────────────────────

app.get('/api/stats', authMiddleware, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count FROM licenses').get().count;
  const active = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND (is_permanent = 1 OR expires_at IS NULL OR expires_at > datetime('now'))`
  ).get().count;
  const expired = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND is_permanent = 0 AND expires_at IS NOT NULL AND expires_at <= datetime('now')`
  ).get().count;
  const revoked = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_active = 0').get().count;
  const expiredSoon = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND is_permanent = 0 AND expires_at IS NOT NULL
     AND expires_at > datetime('now')
     AND expires_at <= datetime('now', '+7 days')`
  ).get().count;
  const permanent = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_permanent = 1 AND is_active = 1').get().count;

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayCount = db.prepare(
    `SELECT COUNT(*) as count FROM licenses WHERE created_at >= ?`
  ).get(todayStart.toISOString()).count;

  // Recent licenses
  const recent = db.prepare(
    'SELECT id, license_key, created_at, is_active, expires_at, is_permanent FROM licenses ORDER BY created_at DESC LIMIT 5'
  ).all().map(r => ({
    ...r,
    status: r.is_active === 0 ? 'revoked' :
            !r.is_permanent && r.expires_at && new Date(r.expires_at) < new Date() ? 'expired' : 'active',
  }));

  res.json({
    total,
    active,
    expired,
    revoked,
    expired_soon: expiredSoon,
    permanent,
    created_today: todayCount,
    recent_licenses: recent,
  });
});

// ─── Export CSV ────────────────────────────────────────────────

app.get('/api/licenses/export/csv', authMiddleware, (req, res) => {
  const licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();

  const headers = ['ID', 'License Key', 'User Email', 'User Name', 'Status', 'Duration', 'Created At', 'Expires At', 'Notes'];
  const rows = licenses.map(l => [
    l.id,
    l.license_key,
    l.user_email,
    l.user_name,
    l.is_active === 0 ? 'Revoked' : isLicenseExpired(l) ? 'Expired' : 'Active',
    formatDuration(l),
    l.created_at,
    l.expires_at || (l.is_permanent ? 'Permanent' : 'N/A'),
    `"${(l.notes || '').replace(/"/g, '""')}"`,
  ]);

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename=licenses_${new Date().toISOString().split('T')[0]}.csv`);
  res.send(csv);
});

// ─── Serve SPA (all unmatched routes go to index.html) ─────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found.' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server ──────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║          🔑 Licensify v1.0                   ║');
  console.log('  ║  License Management System                   ║');
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log(`  ║  Server:     http://0.0.0.0:${PORT}                 ║`);
      console.log(`  ║  Dashboard:  http://localhost:${PORT}                ║`);
  console.log('  ║  API Key:    ' + API_KEY.substring(0, 16) + '...          ║');
  console.log('  ║  Database:   SQLite (licenses.db)            ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
});
