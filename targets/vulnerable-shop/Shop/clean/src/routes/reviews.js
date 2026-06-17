const express = require('express');
const { getDb } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/:productId', async (req, res) => {
  const db = await getDb();
  const reviews = await db.all(
    'SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC',
    req.params.productId
  );
  res.json(reviews);
});

router.post('/', requireAuth, async (req, res) => {
  const { productId, content, rating } = req.body;
  if (!productId || !content) {
    return res.status(400).json({ error: 'productId and content required' });
  }
  const db = await getDb();
  const product = await db.get('SELECT id FROM products WHERE id = ?', productId);
  if (!product) return res.status(404).json({ error: 'Product not found' });

  await db.run(
    'INSERT INTO reviews (product_id, user_id, username, content, rating) VALUES (?, ?, ?, ?, ?)',
    productId, req.user.id, req.user.username, content, rating || 5
  );

  if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
    return res.status(201).json({ message: 'Review posted' });
  }
  res.redirect('/products/' + productId);
});

module.exports = router;
