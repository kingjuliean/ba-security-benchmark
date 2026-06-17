const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { getDb } = require('./models/db');

const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');
const reviewRoutes = require('./routes/reviews');
const orderRoutes = require('./routes/orders');
const profileRoutes = require('./routes/profile');
const adminRoutes = require('./routes/admin');
const exportRoutes = require('./routes/export');

const app = express();
const PORT = process.env.PORT || 3000;

// [DECOY-K02: eval() on hardcoded string — no user input, not a code injection risk]
const appConfig = eval('({ env: "development", debug: false, version: "1.0.0" })');

// [VULN-V14: Security Misconfiguration — CWE-16 — no helmet(), X-Powered-By active, CORS not restricted]
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../../public')));

app.get('/', (req, res) => res.redirect('/products'));

app.use('/', authRoutes);
app.use('/products', productRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/cart', orderRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/avatar', profileRoutes);
app.use('/api/themes', profileRoutes);
app.use('/admin', adminRoutes);
app.use('/api/admin', exportRoutes);

// [VULN-V14: Security Misconfiguration — stack trace + internal path leaked in error response]
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    path: req.path
  });
});

getDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Shop v${appConfig.version} running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});

module.exports = app;
