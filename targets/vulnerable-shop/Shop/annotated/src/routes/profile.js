const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const _ = require('lodash');
const { db } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '../../../../public/uploads/avatars');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${req.user.id}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 } });

router.get('/', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, role, avatar, created_at FROM users WHERE id = ?').get(req.user.id);
  res.render('profile', { user });
});

// [VULN-V13: CSRF — CWE-352 — state-changing endpoint with no CSRF token, session cookie has no SameSite]
// [VULN-V16: SCA — lodash@4.17.20 — _.merge() vulnerable to prototype pollution via settings[__proto__][isAdmin]=true]
router.post('/update', requireAuth, (req, res) => {
  const { email, username } = req.body;
  const defaultSettings = { newsletter: false, theme: 'default', language: 'en' };
  const userSettings = _.merge({}, defaultSettings, req.body.settings || {});

  db.prepare('UPDATE users SET email = ?, username = ? WHERE id = ?').run(
    email || req.user.email,
    username || req.user.username,
    req.user.id
  );
  res.json({ message: 'Profile updated', settings: userSettings });
});

router.post('/avatar', requireAuth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(req.file.filename, req.user.id);
  res.json({ message: 'Avatar updated', filename: req.file.filename });
});

// [VULN-V06: Path Traversal — CWE-22 — req.params.filename used directly in path.join without normalization]
// Exploit: GET /api/avatar/../../../etc/passwd
router.get('/:filename', (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

// [DECOY-K06: fs.readFile with req.params — but ALLOWED_THEMES whitelist prevents path traversal — safe]
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
