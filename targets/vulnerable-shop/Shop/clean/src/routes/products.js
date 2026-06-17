const express = require('express');
const marked = require('marked');
const axios = require('axios');
const { getDb, buildSearchQuery } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const FEATURED_CATEGORY = 'electronics';

router.get('/', async (req, res) => {
  const db = await getDb();
  const featuredQuery = `SELECT * FROM products WHERE category = '${FEATURED_CATEGORY}' AND active = 1`;
  const featured = await db.all(featuredQuery);
  const all = await db.all('SELECT * FROM products WHERE active = 1');
  const carouselId = 'carousel-' + Math.floor(Math.random() * 10000);
  res.render('products/index', { products: all, featured, carouselId });
});

router.get('/search', async (req, res) => {
  const q = req.query.q || '';
  let results = [];
  if (q) {
    const db = await getDb();
    try {
      const sql = buildSearchQuery(q);
      results = await db.all(sql);
    } catch (e) {
      results = [];
    }
  }
  res.render('products/search', { results, searchTerm: q, query: req.query });
});

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

router.get('/:id', async (req, res) => {
  const db = await getDb();
  const product = await db.get('SELECT * FROM products WHERE id = ? AND active = 1', req.params.id);
  if (!product) return res.status(404).render('error', { message: 'Product not found' });
  const reviews = await db.all(
    'SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC',
    req.params.id
  );
  const descriptionHtml = marked(product.description || '');
  res.render('products/detail', { product, reviews, descriptionHtml });
});

module.exports = router;
