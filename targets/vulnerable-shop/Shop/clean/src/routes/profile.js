const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const _ = require('lodash');
const { getDb } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '../../../../public/uploads/avatars');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${req.user.id}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 } });

router.get('/', requireAuth, async (req, res) => {
  const db = await getDb();
  const user = await db.get(
    'SELECT id, username, email, role, avatar, created_at FROM users WHERE id = ?',
    req.user.id
  );
  res.render('profile', { user });
});

router.post('/update', requireAuth, async (req, res) => {
  const { email, username } = req.body;
  const defaultSettings = { newsletter: false, theme: 'default', language: 'en' };
  const userSettings = _.merge({}, defaultSettings, req.body.settings || {});
  const db = await getDb();
  await db.run(
    'UPDATE users SET email = ?, username = ? WHERE id = ?',
    email || req.user.email, username || req.user.username, req.user.id
  );
  res.json({ message: 'Profile updated', settings: userSettings });
});

router.post('/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const db = await getDb();
  await db.run('UPDATE users SET avatar = ? WHERE id = ?', req.file.filename, req.user.id);
  res.json({ message: 'Avatar updated', filename: req.file.filename });
});

router.get('/:filename', (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

router.get('/themes/:name', (req, res) => {
  const ALLOWED_THEMES = ['default', 'dark', 'light', 'contrast'];
  const themeName = req.params.name;
  if (!ALLOWED_THEMES.includes(themeName)) {
    return res.status(400).json({ error: 'Invalid theme name' });
  }
  const themePath = path.join(__dirname, '../../../../public/themes', `${themeName}.css`);
  fs.readFile(themePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'Theme not found' });
    res.type('text/css').send(data);
  });
});

module.exports = router;
