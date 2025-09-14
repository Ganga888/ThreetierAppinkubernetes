require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'please_change';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || 'change_me',
  database: process.env.DB_NAME || 'myapp',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

async function ensureSchema() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    console.log("Ensured users table exists");
  } finally {
    client.release();
  }
}

const app = express();
app.use(bodyParser.json());
app.use(cors({ origin: true, credentials: true }));

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const q = 'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at';
    const r = await pool.query(q, [username, hash]);
    const user = r.rows[0];
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ success: false, message: 'username already exists' });
    console.error(err);
    res.status(500).json({ success: false, message: 'internal error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });

  try {
    const q = 'SELECT id, username, password_hash FROM users WHERE username = $1';
    const r = await pool.query(q, [username]);
    if (r.rowCount === 0) return res.status(401).json({ success: false, message: 'invalid credentials' });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'invalid credentials' });

    const token = jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'internal error' });
  }
});

// Protected example
app.get('/api/profile', async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'missing token' });
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    const q = 'SELECT id, username, created_at FROM users WHERE id = $1';
    const r = await pool.query(q, [payload.sub]);
    if (r.rowCount === 0) return res.status(404).json({ success: false, message: 'user not found' });
    res.json({ success: true, user: r.rows[0] });
  } catch (err) {
    console.error('auth error', err);
    return res.status(401).json({ success: false, message: 'invalid token' });
  }
});

// Start server after ensuring schema
ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Backend started on ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to ensure schema', err);
    process.exit(1);
  });