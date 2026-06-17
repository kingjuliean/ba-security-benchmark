const express = require('express');
const { getDb } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  const db = await getDb();
  const { count: userCount } = await db.get('SELECT COUNT(*) as count FROM users');
  const { count: orderCount } = await db.get('SELECT COUNT(*) as count FROM orders');
  const { total: revenue } = await db.get("SELECT COALESCE(SUM(total),0) as total FROM orders WHERE status != 'cancelled'");
  res.render('admin/index', { userCount, orderCount, revenue });
});

router.get('/users', requireAuth, async (req, res) => {
  const db = await getDb();
  const users = await db.all('SELECT * FROM users ORDER BY created_at DESC');
  if (req.xhr || (req.headers.accept || '').includes('application/json')) {
    return res.json(users);
  }
  res.render('admin/users', { users });
});

router.get('/orders', requireAuth, async (req, res) => {
  const db = await getDb();
  const orders = await db.all(
    'SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC'
  );
  if (req.xhr || (req.headers.accept || '').includes('application/json')) {
    return res.json(orders);
  }
  res.render('admin/orders', { orders });
});

router.post('/settings', requireAuth, (req, res) => {
  const config = JSON.parse(req.body.configJson);
  res.json({ message: 'Settings updated', applied: config });
});

module.exports = router;
