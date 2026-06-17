const express = require('express');
const marked = require('marked');
const axios = require('axios');
const { db, buildSearchQuery } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// [DECOY-K01: Looks like SQL Injection but FEATURED_CATEGORY is a hardcoded constant — no user input]
const FEATURED_CATEGORY = 'electronics';

router.get('/', (req, res) => {
  const featuredQuery = `SELECT * FROM products WHERE category = '${FEATURED_CATEGORY}' AND active = 1`;
  const featured = db.prepare(featuredQuery).all();
  const all = db.prepare('SELECT * FROM products WHERE active = 1').all();
  // [DECOY-K09: Math.random() used for HTML element ID — not security-relevant, no crypto use]
  const carouselId = 'carousel-' + Math.floor(Math.random() * 10000);
  res.render('products/index', { products: all, featured, carouselId });
});

// [VULN-V02: SQL Injection (distributed) — CWE-89 — taint sink: buildSearchQuery(q) in db.js]
// [VULN-V04: Reflected XSS — CWE-79 — searchTerm passed unescaped to template via <%- %>]
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  let results = [];
  if (q) {
    try {
      const sql = buildSearchQuery(q);
      results = db.prepare(sql).all();
    } catch (e) {
      results = [];
    }
  }
  res.render('products/search', { results, searchTerm: q, query: req.query });
});

// [VULN-V20: SCA — axios@0.21.0 — CVE-2021-3749 SSRF via open redirect following]
router.get('/image-proxy', requireAuth, async (req, res) => {
  const imageUrl = req.query.imageUrl;
  if (!imageUrl) return res.status(400).json({ error: 'imageUrl required' });
  try {
    const response = await axios.get(imageUrl, { responseType: 'stream' });
    response.data.pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch image' });
  }
});

// [VULN-V19: SCA — marked@0.3.6 — CVE-2022-21680/21681 ReDoS + XSS in old version]
router.get('/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ? AND active = 1').get(req.params.id);
  if (!product) return res.status(404).render('error', { message: 'Product not found' });
  const reviews = db.prepare('SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC').all(req.params.id);
  const descriptionHtml = marked(product.description || '');
  res.render('products/detail', { product, reviews, descriptionHtml });
});

module.exports = router;
