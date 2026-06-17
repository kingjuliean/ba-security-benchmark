const express = require('express');
const { db } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get().count;
  const revenue = db.prepare("SELECT COALESCE(SUM(total),0) as total FROM orders WHERE status != 'cancelled'").get().total;
  res.render('admin/index', { userCount, orderCount, revenue });
});

// [VULN-V11: Missing Authorization — CWE-862 — requireAdmin middleware absent, any logged-in user can access]
// [VULN-V15: Sensitive Data Exposure — CWE-200 — SELECT * returns password_hash field in response]
router.get('/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
  if (req.xhr || req.headers.accept === 'application/json') {
    return res.json(users);
  }
  res.render('admin/users', { users });
});

// [VULN-V11: Missing Authorization — same issue on /admin/orders]
router.get('/orders', requireAuth, (req, res) => {
  const orders = db.prepare(
    'SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC'
  ).all();
  if (req.xhr || req.headers.accept === 'application/json') {
    return res.json(orders);
  }
  res.render('admin/orders', { orders });
});

// [DECOY-K10: JSON.parse on request body — but endpoint is behind requireAuth + only admin should reach here]
// JSON.parse() does not execute code; max impact is malformed config, not RCE
router.post('/settings', requireAuth, (req, res) => {
  const config = JSON.parse(req.body.configJson);
  res.json({ message: 'Settings updated', applied: config });
});

module.exports = router;
