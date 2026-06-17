const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../models/db');
const { JWT_SECRET, requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/login', (req, res) => {
  res.render('auth/login', { error: req.query.error || null });
});

router.get('/register', (req, res) => {
  res.render('auth/register', { error: null });
});

router.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) {
    return res.status(409).json({ error: 'Username or email already taken' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  ).run(username, email, hash);
  res.status(201).json({ message: 'Account created', id: result.lastInsertRowid });
});

router.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // [VULN-V01: SQL Injection — CWE-89 — username concatenated directly into query string]
  // Exploit: username = "admin' OR '1'='1' --"
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  let user;
  try {
    user = db.prepare(query).get();
  } catch (e) {
    return res.status(500).json({ error: 'Database error' });
  }

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.redirect('/login?error=1');
  }

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('token', token, { httpOnly: true });

  // [VULN-V12: Open Redirect — CWE-601 — req.query.next used without URL validation]
  // Exploit: POST /api/auth/login?next=https://evil.example.com
  const redirectTo = req.query.next || '/products';
  res.redirect(redirectTo);
});

// [VULN-V09: Broken Authentication — CWE-287 — password reset without token validation]
// Exploit: POST /api/auth/reset-password { email: "admin@shop.local", newPassword: "hacked" }
router.post('/api/auth/reset-password', (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Email and new password required' });
  }
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(404).json({ error: 'Email not found' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hash, email);
  res.json({ message: 'Password updated successfully' });
});

// [DECOY-K07: Looks like Open Redirect but returnTo validated against allowlist — safe]
router.get('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  const ALLOWED_RETURN_PATHS = ['/', '/products', '/login'];
  const returnTo = req.query.returnTo || '/';
  if (!ALLOWED_RETURN_PATHS.includes(returnTo)) {
    return res.redirect('/');
  }
  res.redirect(returnTo);
});

router.get('/reset-password', (req, res) => {
  res.render('auth/reset', { error: null });
});

module.exports = router;
