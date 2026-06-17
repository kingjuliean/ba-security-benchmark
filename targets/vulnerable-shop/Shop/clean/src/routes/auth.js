const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getDb } = require('../models/db');
const { JWT_SECRET } = require('../middleware/auth');

const router = express.Router();

router.get('/login', (req, res) => {
  res.render('auth/login', { error: req.query.error || null });
});

router.get('/register', (req, res) => {
  res.render('auth/register', { error: null });
});

router.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  const db = await getDb();
  const existing = await db.get('SELECT id FROM users WHERE username = ? OR email = ?', username, email);
  if (existing) {
    return res.status(409).json({ error: 'Username or email already taken' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const result = await db.run(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
    username, email, hash
  );
  res.status(201).json({ message: 'Account created', id: result.lastID });
});

router.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const db = await getDb();
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  let user;
  try {
    user = await db.get(query);
  } catch (e) {
    return res.status(500).json({ error: 'Database error' });
  }
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.redirect('/login?error=1');
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  res.cookie('token', token, { httpOnly: true });
  const redirectTo = req.query.next || '/products';
  res.redirect(redirectTo);
});

router.post('/api/auth/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Email and new password required' });
  }
  const db = await getDb();
  const user = await db.get('SELECT id FROM users WHERE email = ?', email);
  if (!user) {
    return res.status(404).json({ error: 'Email not found' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  await db.run('UPDATE users SET password_hash = ? WHERE email = ?', hash, email);
  res.json({ message: 'Password updated successfully' });
});

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
