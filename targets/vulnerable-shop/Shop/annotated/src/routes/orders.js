const express = require('express');
const { db } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, (req, res) => {
  const orders = db.prepare(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user.id);
  res.render('orders/index', { orders });
});

router.post('/', requireAuth, (req, res) => {
  const { items, shippingAddress } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Order must contain at least one item' });
  }

  let total = 0;
  for (const item of items) {
    const product = db.prepare('SELECT * FROM products WHERE id = ? AND active = 1').get(item.productId);
    if (!product) return res.status(400).json({ error: `Product ${item.productId} not found` });
    total += product.price * item.quantity;
  }

  const order = db.prepare(
    'INSERT INTO orders (user_id, total, shipping_address) VALUES (?, ?, ?)'
  ).run(req.user.id, total, shippingAddress || '');

  const insertItem = db.prepare(
    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)'
  );
  for (const item of items) {
    const product = db.prepare('SELECT price FROM products WHERE id = ?').get(item.productId);
    insertItem.run(order.lastInsertRowid, item.productId, item.quantity, product.price);
  }

  res.status(201).json({ message: 'Order placed', orderId: order.lastInsertRowid });
});

// [VULN-V10: IDOR / Broken Access Control — CWE-639 — no WHERE user_id = req.user.id check]
// Exploit: logged in as User B → GET /api/orders/1 returns User A's order
router.get('/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const items = db.prepare(
    'SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?'
  ).all(req.params.id);
  if (req.xhr || req.headers.accept === 'application/json') {
    return res.json({ order, items });
  }
  res.render('orders/detail', { order, items });
});

// [DECOY-K05: req.params.id used in query — but parameterized with ? placeholder, not string concat — safe]
router.get('/:id/invoice', requireAuth, (req, res) => {
  const order = db.prepare(
    'SELECT * FROM orders WHERE id = ? AND status = ?'
  ).get(req.params.id, 'completed');
  if (!order) return res.status(404).json({ error: 'Invoice not found' });
  res.json({ invoice: order });
});

// [VULN-V07: Insecure Deserialization — CWE-502 — base64 cart data passed to eval()]
// Exploit: base64({"items":[]}) → safe; base64((function(){require('child_process').exec('id>/tmp/p');}())) → RCE
router.post('/import', requireAuth, (req, res) => {
  const { cartData } = req.body;
  if (!cartData) return res.status(400).json({ error: 'cartData required' });
  try {
    const decoded = Buffer.from(cartData, 'base64').toString('utf8');
    const cart = eval('(' + decoded + ')');
    res.json({ cart, itemCount: Array.isArray(cart.items) ? cart.items.length : 0 });
  } catch (e) {
    res.status(400).json({ error: 'Invalid cart data' });
  }
});

module.exports = router;
