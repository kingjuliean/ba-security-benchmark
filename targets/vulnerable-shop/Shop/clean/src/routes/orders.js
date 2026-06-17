const express = require('express');
const { getDb } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  const db = await getDb();
  const orders = await db.all(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
    req.user.id
  );
  res.render('orders/index', { orders });
});

router.post('/', requireAuth, async (req, res) => {
  const { items, shippingAddress } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Order must contain at least one item' });
  }
  const db = await getDb();
  let total = 0;
  for (const item of items) {
    const product = await db.get('SELECT * FROM products WHERE id = ? AND active = 1', item.productId);
    if (!product) return res.status(400).json({ error: `Product ${item.productId} not found` });
    total += product.price * item.quantity;
  }
  const order = await db.run(
    'INSERT INTO orders (user_id, total, shipping_address) VALUES (?, ?, ?)',
    req.user.id, total, shippingAddress || ''
  );
  for (const item of items) {
    const product = await db.get('SELECT price FROM products WHERE id = ?', item.productId);
    await db.run(
      'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
      order.lastID, item.productId, item.quantity, product.price
    );
  }
  res.status(201).json({ message: 'Order placed', orderId: order.lastID });
});

router.get('/:id', requireAuth, async (req, res) => {
  const db = await getDb();
  const order = await db.get('SELECT * FROM orders WHERE id = ?', req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const items = await db.all(
    'SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
    req.params.id
  );
  if (req.xhr || (req.headers.accept || '').includes('application/json')) {
    return res.json({ order, items });
  }
  res.render('orders/detail', { order, items });
});

router.get('/:id/invoice', requireAuth, async (req, res) => {
  const db = await getDb();
  const order = await db.get(
    'SELECT * FROM orders WHERE id = ? AND status = ?',
    req.params.id, 'completed'
  );
  if (!order) return res.status(404).json({ error: 'Invoice not found' });
  res.json({ invoice: order });
});

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
