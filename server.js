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

  CREATE TABLE IF NOT EXISTS sub_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    max_daily_licenses INTEGER DEFAULT 10,
    licenses_today INTEGER DEFAULT 0,
    last_reset_date TEXT,
    is_active INTEGER DEFAULT 1,
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
      activated_at TEXT DEFAULT NULL,
      expires_at TEXT,
      revoked_at TEXT,
      last_validated_at TEXT,
      notes TEXT DEFAULT '',
      metadata TEXT DEFAULT '{}',
      created_by_admin_id INTEGER DEFAULT NULL,
      created_by_sub_admin_id INTEGER DEFAULT NULL
    );

  CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
  CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(is_active);
  CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at);
  `);
  
  // --- Migration: add columns if missing (for existing databases) ---
  const tableInfo = db.prepare("PRAGMA table_info('licenses')").all();
  const existingCols = tableInfo.map(r => r.name);
  if (!existingCols.includes('created_by_admin_id')) {
    db.exec("ALTER TABLE licenses ADD COLUMN created_by_admin_id INTEGER DEFAULT NULL");
  }
  if (!existingCols.includes('created_by_sub_admin_id')) {
    db.exec("ALTER TABLE licenses ADD COLUMN created_by_sub_admin_id INTEGER DEFAULT NULL");
  }
  if (!existingCols.includes('activated_at')) {
    db.exec("ALTER TABLE licenses ADD COLUMN activated_at TEXT DEFAULT NULL");
  }
  // Create index on new column (must happen AFTER the ALTER TABLE)
  db.exec("CREATE INDEX IF NOT EXISTS idx_licenses_sub_admin ON licenses(created_by_sub_admin_id)");

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
  if (!license.activated_at) return false; // not yet activated = pending, not expired
  if (!license.expires_at) return false;
  return new Date(license.expires_at) < new Date();
}

function getLicenseStatus(license) {
  if (license.is_active === 0) return 'revoked';
  if (!license.activated_at) return 'pending';
  return isLicenseExpired(license) ? 'expired' : 'active';
}

function formatDuration(license) {
  const parts = [];
  if (license.duration_days > 0) parts.push(`${license.duration_days}d`);
  if (license.duration_hours > 0) parts.push(`${license.duration_hours}h`);
  if (license.duration_minutes > 0) parts.push(`${license.duration_minutes}m`);
  if (license.is_permanent) return 'Permanent';
  return parts.join(' ') || 'Custom';
}

function formatDateStr(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function resetDailyCounts() {
  const today = new Date().toISOString().split('T')[0];
  db.prepare(`
    UPDATE sub_admins 
    SET licenses_today = 0, last_reset_date = ?
    WHERE last_reset_date IS NULL OR last_reset_date != ?
  `).run(today, today);
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

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

function apiKeyMiddleware(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!key) {
    return res.status(401).json({ error: 'API key required.' });
  }
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
    { id: user.id, username: user.username, role: 'admin' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    token,
    user: { id: user.id, username: user.username, role: 'admin' },
    api_key: API_KEY,
  });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  res.json({ message: 'Logged out successfully.' });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  if (req.user.role === 'admin') {
    const user = db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: { ...user, role: 'admin' } });
  }
  // Sub-admin
  const sub = db.prepare('SELECT id, username, max_daily_licenses, licenses_today, is_active, created_at FROM sub_admins WHERE id = ?').get(req.user.id);
  if (!sub) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: { ...sub, role: 'sub_admin' } });
});

// ─── Change Password ───────────────────────────────────────────

app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  if (req.user.role === 'admin') {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user || !bcrypt.compareSync(current_password, user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    const hash = bcrypt.hashSync(new_password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  } else {
    const sub = db.prepare('SELECT * FROM sub_admins WHERE id = ?').get(req.user.id);
    if (!sub || !bcrypt.compareSync(current_password, sub.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    const hash = bcrypt.hashSync(new_password, 12);
    db.prepare('UPDATE sub_admins SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  }

  res.json({ message: 'Password updated successfully.' });
});

// ─── Sub-Admin Auth ────────────────────────────────────────────

app.post('/api/sub-admin/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const sub = db.prepare('SELECT * FROM sub_admins WHERE username = ?').get(username);
  if (!sub) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  if (!sub.is_active) {
    return res.status(403).json({ error: 'Account has been deactivated.' });
  }

  const valid = bcrypt.compareSync(password, sub.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  // Reset daily count if needed
  resetDailyCounts();

  const token = jwt.sign(
    { id: sub.id, username: sub.username, role: 'sub_admin' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    token,
    user: { id: sub.id, username: sub.username, role: 'sub_admin', max_daily_licenses: sub.max_daily_licenses },
  });
});

// ─── Sub-Admin Management (Admin Only) ─────────────────────────

app.get('/api/sub-admins', authMiddleware, adminOnly, (req, res) => {
  resetDailyCounts();
  const subs = db.prepare('SELECT id, username, max_daily_licenses, licenses_today, is_active, created_at FROM sub_admins ORDER BY created_at DESC').all();

  // Add today's actual count from licenses table
  const today = new Date().toISOString().split('T')[0];
  const todayStart = today + 'T00:00:00';
  const enriched = subs.map(s => {
    const actualToday = db.prepare(
      `SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND created_at >= ?`
    ).get(s.id, todayStart).count;
    return { ...s, licenses_today: actualToday, remaining: s.max_daily_licenses - actualToday };
  });

  res.json(enriched);
});

app.post('/api/sub-admins', authMiddleware, adminOnly, (req, res) => {
  const { username, password, max_daily_licenses = 10 } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  if (max_daily_licenses < 1 || max_daily_licenses > 1000) {
    return res.status(400).json({ error: 'Daily license limit must be between 1 and 1000.' });
  }

  const existing = db.prepare('SELECT id FROM sub_admins WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already exists.' });
  }

  const hash = bcrypt.hashSync(password, 12);
  const result = db.prepare(
    'INSERT INTO sub_admins (username, password_hash, max_daily_licenses) VALUES (?, ?, ?)'
  ).run(username, hash, max_daily_licenses);

  const sub = db.prepare('SELECT id, username, max_daily_licenses, is_active, created_at FROM sub_admins WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(sub);
});

app.put('/api/sub-admins/:id', authMiddleware, adminOnly, (req, res) => {
  const sub = db.prepare('SELECT * FROM sub_admins WHERE id = ?').get(req.params.id);
  if (!sub) return res.status(404).json({ error: 'Sub-admin not found.' });

  const { max_daily_licenses, is_active, password } = req.body;
  const updates = [];
  const params = [];

  if (max_daily_licenses !== undefined) {
    if (max_daily_licenses < 1 || max_daily_licenses > 1000) {
      return res.status(400).json({ error: 'Daily license limit must be between 1 and 1000.' });
    }
    updates.push('max_daily_licenses = ?');
    params.push(max_daily_licenses);
  }
  if (is_active !== undefined) {
    updates.push('is_active = ?');
    params.push(is_active ? 1 : 0);
  }
  if (password) {
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    updates.push('password_hash = ?');
    params.push(bcrypt.hashSync(password, 12));
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }

  params.push(req.params.id);
  db.prepare(`UPDATE sub_admins SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  const updated = db.prepare('SELECT id, username, max_daily_licenses, is_active, created_at FROM sub_admins WHERE id = ?').get(req.params.id);
  res.json(updated);
});

app.delete('/api/sub-admins/:id', authMiddleware, adminOnly, (req, res) => {
  const sub = db.prepare('SELECT id FROM sub_admins WHERE id = ?').get(req.params.id);
  if (!sub) return res.status(404).json({ error: 'Sub-admin not found.' });

  db.prepare('DELETE FROM sub_admins WHERE id = ?').run(req.params.id);
  res.json({ message: 'Sub-admin deleted successfully.' });
});

// ─── Sub-Admin License Creation (Restricted) ───────────────────

app.post('/api/sub-admin/licenses', authMiddleware, (req, res) => {
  if (req.user.role !== 'sub_admin') {
    return res.status(403).json({ error: 'Sub-admin access required.' });
  }

  const sub = db.prepare('SELECT * FROM sub_admins WHERE id = ?').get(req.user.id);
  if (!sub || !sub.is_active) {
    return res.status(403).json({ error: 'Account is inactive.' });
  }

  // Reset daily count if needed
  resetDailyCounts();

  // Check daily limit using actual license count
  const todayStart = new Date().toISOString().split('T')[0] + 'T00:00:00';
  const todayCount = db.prepare(
    `SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND created_at >= ?`
  ).get(sub.id, todayStart).count;

  if (todayCount >= sub.max_daily_licenses) {
    return res.status(429).json({
      error: `Daily license limit reached (${sub.max_daily_licenses}). Try again tomorrow.`,
      limit: sub.max_daily_licenses,
      used: todayCount,
    });
  }

  const {
    duration_minutes = 0,
    duration_hours = 0,
    duration_days = 0,
    user_email = '',
    user_name = '',
    notes = '',
    metadata = {},
  } = req.body;

  // Enforce sub-admin restrictions: max 15 minutes total
  const mins = parseInt(duration_minutes) || 0;
  const hours = parseInt(duration_hours) || 0;
  const days = parseInt(duration_days) || 0;

  if (days > 0 || hours > 0) {
    return res.status(400).json({ error: 'Sub-admins can only create licenses with minute-based duration (max 15 min).' });
  }
  if (mins < 1 || mins > 15) {
    return res.status(400).json({ error: 'Duration must be between 1 and 15 minutes.' });
  }

  // Generate unique key
  let license_key;
  let attempts = 0;
  do {
    license_key = generateLicenseKey();
    attempts++;
    if (attempts > 10) return res.status(500).json({ error: 'Failed to generate unique key.' });
  } while (db.prepare('SELECT id FROM licenses WHERE license_key = ?').get(license_key));

  const metadataStr = typeof metadata === 'object' ? JSON.stringify(metadata) : metadata;

  // expires_at starts NULL — clock starts ticking on first activation
  const result = db.prepare(`
    INSERT INTO licenses (license_key, user_email, user_name, is_active, is_permanent,
                          duration_minutes, duration_hours, duration_days, expires_at, notes, metadata, created_by_sub_admin_id)
    VALUES (?, ?, ?, 1, 0, ?, 0, 0, NULL, ?, ?, ?)
  `).run(license_key, user_email, user_name, mins, notes, metadataStr, sub.id);

  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(result.lastInsertRowid);

  res.status(201).json({
      ...license,
      status: 'pending',
      duration_display: formatDuration(license),
      daily_usage: { used: todayCount + 1, limit: sub.max_daily_licenses },
      message: 'License created. Clock will start on first activation.',
    });
});

// ─── Sub-Admin Stats ───────────────────────────────────────────

app.get('/api/sub-admin/stats', authMiddleware, (req, res) => {
  if (req.user.role !== 'sub_admin') {
    return res.status(403).json({ error: 'Sub-admin access required.' });
  }

  resetDailyCounts();
  const todayStart = new Date().toISOString().split('T')[0] + 'T00:00:00';

  const sub = db.prepare('SELECT max_daily_licenses FROM sub_admins WHERE id = ?').get(req.user.id);
  const todayCount = db.prepare(
    `SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND created_at >= ?`
  ).get(req.user.id, todayStart).count;

  const totalByMe = db.prepare(
    'SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ?'
  ).get(req.user.id).count;

  const activeByMe = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE created_by_sub_admin_id = ? AND is_active = 1 AND activated_at IS NOT NULL
     AND (is_permanent = 1 OR expires_at > datetime('now'))`
  ).get(req.user.id).count;
  const pendingByMe = db.prepare(
    'SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND is_active = 1 AND activated_at IS NULL'
  ).get(req.user.id).count;

  res.json({
    max_daily_licenses: sub.max_daily_licenses,
    used_today: todayCount,
    remaining_today: Math.max(0, sub.max_daily_licenses - todayCount),
    total_created: totalByMe,
    active: activeByMe,
    pending: pendingByMe,
  });
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

  const validSorts = ['created_at', 'expires_at', 'license_key', 'id'];
  const sortCol = validSorts.includes(sortBy) ? sortBy : 'created_at';

  let whereClauses = [];
  let params = [];

  if (search) {
    whereClauses.push('(license_key LIKE ? OR user_email LIKE ? OR user_name LIKE ? OR notes LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (status === 'active') {
    whereClauses.push("is_active = 1 AND activated_at IS NOT NULL AND (is_permanent = 1 OR expires_at > datetime('now'))");
  } else if (status === 'pending') {
    whereClauses.push("is_active = 1 AND activated_at IS NULL");
  } else if (status === 'expired') {
    whereClauses.push("is_active = 1 AND is_permanent = 0 AND activated_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at <= datetime('now')");
  } else if (status === 'revoked') {
    whereClauses.push('is_active = 0');
  }

  // Sub-admins can only see their own licenses
  if (req.user.role === 'sub_admin') {
    whereClauses.push('created_by_sub_admin_id = ?');
    params.push(req.user.id);
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM licenses ${whereSQL}`).get(...params);
  const total = countRow.total;

  const rows = db.prepare(
    `SELECT * FROM licenses ${whereSQL} ORDER BY ${sortCol} ${sortOrder} LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);

  const licenses = rows.map(row => ({
      ...row,
      status: getLicenseStatus(row),
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

// Generate new license (admin)
app.post('/api/licenses', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

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

  let license_key;
  let attempts = 0;
  do {
    license_key = generateLicenseKey();
    attempts++;
    if (attempts > 10) return res.status(500).json({ error: 'Failed to generate unique key.' });
  } while (db.prepare('SELECT id FROM licenses WHERE license_key = ?').get(license_key));

  const metadataStr = typeof metadata === 'object' ? JSON.stringify(metadata) : metadata;
  
    // expires_at starts NULL — clock starts ticking on first activation (via /api/validate)
    const result = db.prepare(`
      INSERT INTO licenses (license_key, user_email, user_name, is_active, is_permanent,
                            duration_minutes, duration_hours, duration_days, expires_at, notes, metadata, created_by_admin_id)
      VALUES (?, ?, ?, 1, ?, ?, ?, ?, NULL, ?, ?, ?)
    `).run(license_key, user_email, user_name, permanent ? 1 : 0,
           mins, hours, days, notes, metadataStr, req.user.id);

  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(result.lastInsertRowid);

  res.status(201).json({
      ...license,
      status: 'pending',
      duration_display: formatDuration(license),
      message: 'License created. Clock will start on first activation.',
    });
});

// Get single license
app.get('/api/licenses/:id', authMiddleware, (req, res) => {
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  // Sub-admins can only view their own
  if (req.user.role === 'sub_admin' && license.created_by_sub_admin_id !== req.user.id) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  res.json({
    ...license,
    status: getLicenseStatus(license),
    duration_display: formatDuration(license),
  });
});

// Update license (revoke/reactivate/edit)
app.put('/api/licenses/:id', authMiddleware, (req, res) => {
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  // Sub-admins can only update their own and can only revoke
  if (req.user.role === 'sub_admin') {
    if (license.created_by_sub_admin_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied.' });
    }
    if (req.body.is_active === undefined) {
      return res.status(403).json({ error: 'Sub-admins can only revoke/reactivate licenses.' });
    }
  }

  const { is_active, user_email, user_name, notes } = req.body;

  const updates = [];
  const params = [];

  if (is_active !== undefined) {
    const newActive = is_active ? 1 : 0;
    updates.push('is_active = ?');
    params.push(newActive);
    if (!is_active) {
      updates.push("revoked_at = datetime('now')");
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
    status: getLicenseStatus(updated),
    duration_display: formatDuration(updated),
  });
});

// Extend license duration (admin only)
app.post('/api/licenses/:id/extend', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });
  if (!license.is_active) return res.status(400).json({ error: 'Cannot extend a revoked license. Reactivate it first.' });

  const { minutes, hours, days } = req.body;
  const addMins = parseInt(minutes) || 0;
  const addHours = parseInt(hours) || 0;
  const addDays = parseInt(days) || 0;

  if (addMins <= 0 && addHours <= 0 && addDays <= 0) {
    return res.status(400).json({ error: 'At least one duration field (minutes/hours/days) with a positive value is required.' });
  }

  const now = new Date();

  // ─── If license was never activated, activate it now ───
  if (!license.activated_at) {
    const expiresAt = calculateExpiry(addMins, addHours, addDays, false);
    db.prepare("UPDATE licenses SET activated_at = ?, expires_at = ?, duration_minutes = ?, duration_hours = ?, duration_days = ?, notes = CASE WHEN notes IS NULL OR notes = '' THEN ? ELSE notes || '\n' || ? END WHERE id = ?")
      .run(now.toISOString(), expiresAt, addMins, addHours, addDays, `Extended: +${addMins}m ${addHours}h ${addDays}d (activated on extend)`, `Extended: +${addMins}m ${addHours}h ${addDays}d (activated on extend)`, license.id);
    const updated = db.prepare('SELECT * FROM licenses WHERE id = ?').get(license.id);
    return res.json({
      ...updated,
      status: getLicenseStatus(updated),
      duration_display: formatDuration(updated),
      message: `License activated and extended by ${addMins}m ${addHours}h ${addDays}d. Expires ${formatDateStr(expiresAt)}`,
    });
  }

  // ─── License was activated — add time ───
  // If already expired, start from now; otherwise add to current expires_at
  const baseTime = isLicenseExpired(license) ? now : new Date(license.expires_at);
  const newExpires = new Date(baseTime);
  newExpires.setMinutes(newExpires.getMinutes() + addMins);
  newExpires.setHours(newExpires.getHours() + addHours);
  newExpires.setDate(newExpires.getDate() + addDays);
  const newExpiresStr = newExpires.toISOString();

  const note = `Extended: +${addMins}m ${addHours}h ${addDays}d (new expiry: ${newExpiresStr.slice(0, 10)})`;
  db.prepare("UPDATE licenses SET expires_at = ?, duration_minutes = duration_minutes + ?, duration_hours = duration_hours + ?, duration_days = duration_days + ?, notes = CASE WHEN notes IS NULL OR notes = '' THEN ? ELSE notes || '\n' || ? END WHERE id = ?")
    .run(newExpiresStr, addMins, addHours, addDays, note, note, license.id);

  const updated = db.prepare('SELECT * FROM licenses WHERE id = ?').get(license.id);
  res.json({
    ...updated,
    status: getLicenseStatus(updated),
    duration_display: formatDuration(updated),
    message: `License extended by ${addMins}m ${addHours}h ${addDays}d. New expiry: ${formatDateStr(newExpiresStr)}`,
  });
});

// Delete license (admin only)
app.delete('/api/licenses/:id', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!license) return res.status(404).json({ error: 'License not found.' });

  db.prepare('DELETE FROM licenses WHERE id = ?').run(license.id);
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

  const meta = license.metadata ? JSON.parse(license.metadata) : {};
  const validations = meta.validations || [];
  validations.push({
    ip: ip_address || req.ip,
    device: device_info || 'unknown',
    timestamp: new Date().toISOString(),
  });
  const trimmed = validations.slice(-100);
  const updatedMeta = { ...meta, validations: trimmed, last_ip: ip_address || req.ip };

  if (!license.is_active) {
    const meta2 = JSON.stringify(updatedMeta);
    db.prepare("UPDATE licenses SET last_validated_at = datetime('now'), metadata = ? WHERE id = ?")
      .run(meta2, license.id);
    return res.json({
      valid: false, error: 'License has been revoked.', revoked_at: license.revoked_at,
      license_key: license.license_key, is_permanent: !!license.is_permanent,
      expires_at: null, created_at: license.created_at,
    });
  }

  const now = new Date();

  // ─── First activation? Set activated_at and calculate expires_at ───
  if (!license.activated_at) {
    const activatedAt = now.toISOString();
    const expiresAt = calculateExpiry(
      license.duration_minutes, license.duration_hours, license.duration_days,
      !!license.is_permanent
    );
    db.prepare("UPDATE licenses SET activated_at = ?, expires_at = ?, last_validated_at = datetime('now'), metadata = ? WHERE id = ?")
      .run(activatedAt, expiresAt, JSON.stringify(updatedMeta), license.id);
    license.activated_at = activatedAt;
    license.expires_at = expiresAt;
  } else {
    db.prepare("UPDATE licenses SET last_validated_at = datetime('now'), metadata = ? WHERE id = ?")
      .run(JSON.stringify(updatedMeta), license.id);
  }

  // Check if expired now (post-activation)
  const expired = !license.is_permanent && license.expires_at && new Date(license.expires_at) < now;

  if (expired) {
    return res.json({
      valid: false, error: 'License has expired.', expires_at: license.expires_at,
      license_key: license.license_key, is_permanent: !!license.is_permanent,
      created_at: license.created_at,
    });
  }

  const msRemaining = license.expires_at ? new Date(license.expires_at) - now : null;
  const daysRemaining = msRemaining !== null ? Math.max(0, Math.floor(msRemaining / (1000 * 60 * 60 * 24))) : null;
  const hoursRemaining = msRemaining !== null ? Math.max(0, Math.floor((msRemaining % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))) : null;
  const minsRemaining = msRemaining !== null ? Math.max(0, Math.floor((msRemaining % (1000 * 60 * 60)) / (1000 * 60))) : null;

  res.json({
    valid: true,
    license_key: license.license_key,
    is_permanent: !!license.is_permanent,
    activated_at: license.activated_at,
    expires_at: license.expires_at,
    created_at: license.created_at,
    time_remaining: msRemaining !== null ? { days: daysRemaining, hours: hoursRemaining, minutes: minsRemaining } : null,
  });
});

// ─── Stats Route ───────────────────────────────────────────────

app.get('/api/stats', authMiddleware, (req, res) => {
  // Sub-admins get their own stats
  if (req.user.role === 'sub_admin') {
    const todayStart = new Date().toISOString().split('T')[0] + 'T00:00:00';
    const sub = db.prepare('SELECT max_daily_licenses FROM sub_admins WHERE id = ?').get(req.user.id);
    const total = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ?').get(req.user.id).count;
        const active = db.prepare(
          `SELECT COUNT(*) as count FROM licenses
           WHERE created_by_sub_admin_id = ? AND is_active = 1 AND activated_at IS NOT NULL
           AND (is_permanent = 1 OR expires_at > datetime('now'))`
        ).get(req.user.id).count;
        const pending = db.prepare(
          'SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND is_active = 1 AND activated_at IS NULL'
        ).get(req.user.id).count;
        const expired = db.prepare(
          `SELECT COUNT(*) as count FROM licenses
           WHERE created_by_sub_admin_id = ? AND is_active = 1 AND is_permanent = 0
           AND activated_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at <= datetime('now')`
        ).get(req.user.id).count;
        const revoked = db.prepare(
          'SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND is_active = 0'
        ).get(req.user.id).count;
    const todayCount = db.prepare(
      'SELECT COUNT(*) as count FROM licenses WHERE created_by_sub_admin_id = ? AND created_at >= ?'
    ).get(req.user.id, todayStart).count;

    const recent = db.prepare(
          'SELECT id, license_key, created_at, is_active, expires_at, is_permanent, activated_at FROM licenses WHERE created_by_sub_admin_id = ? ORDER BY created_at DESC LIMIT 5'
        ).all(req.user.id).map(r => ({
          ...r,
          status: getLicenseStatus(r),
        }));
    
        return res.json({
          total, active, pending, expired, revoked,
          expired_soon: 0, permanent: 0,
          created_today: todayCount,
          recent_licenses: recent,
      sub_admin_stats: {
        max_daily: sub.max_daily_licenses,
        used_today: todayCount,
        remaining: Math.max(0, sub.max_daily_licenses - todayCount),
      },
    });
  }

  // Admin stats
  const total = db.prepare('SELECT COUNT(*) as count FROM licenses').get().count;
  const active = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND activated_at IS NOT NULL AND (is_permanent = 1 OR expires_at > datetime('now'))`
  ).get().count;
  const pending = db.prepare(
    `SELECT COUNT(*) as count FROM licenses WHERE is_active = 1 AND activated_at IS NULL`
  ).get().count;
  const expired = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND is_permanent = 0 AND activated_at IS NOT NULL
     AND expires_at IS NOT NULL AND expires_at <= datetime('now')`
  ).get().count;
  const revoked = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_active = 0').get().count;
  const expiredSoon = db.prepare(
    `SELECT COUNT(*) as count FROM licenses
     WHERE is_active = 1 AND is_permanent = 0 AND activated_at IS NOT NULL AND expires_at IS NOT NULL
     AND expires_at > datetime('now')
     AND expires_at <= datetime('now', '+7 days')`
  ).get().count;
  const permanent = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_permanent = 1 AND is_active = 1 AND activated_at IS NOT NULL').get().count;

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayCount = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE created_at >= ?').get(todayStart.toISOString()).count;

  const recent = db.prepare(
    'SELECT id, license_key, created_at, is_active, expires_at, is_permanent, activated_at FROM licenses ORDER BY created_at DESC LIMIT 5'
  ).all().map(r => ({
    ...r,
    status: getLicenseStatus(r),
  }));

  res.json({
    total, active, pending, expired, revoked,
    expired_soon: expiredSoon, permanent,
    created_today: todayCount,
    recent_licenses: recent,
  });
});

// ─── Export CSV ────────────────────────────────────────────────

app.get('/api/licenses/export/csv', authMiddleware, (req, res) => {
  let licenses;
  if (req.user.role === 'sub_admin') {
    licenses = db.prepare('SELECT * FROM licenses WHERE created_by_sub_admin_id = ? ORDER BY created_at DESC').all(req.user.id);
  } else {
    licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  }

  const headers = ['ID', 'License Key', 'User Email', 'User Name', 'Status', 'Duration', 'Created At', 'Expires At', 'Notes'];
  const rows = licenses.map(l => [
    l.id,
    l.license_key,
    l.user_email,
    l.user_name,
    l.is_active === 0 ? 'Revoked' : !l.activated_at ? 'Pending' : isLicenseExpired(l) ? 'Expired' : 'Active',
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

// ─── Serve SPA ─────────────────────────────────────────────────
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