const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../../data/shop.db');

let db;

async function getDb() {
  if (db) return db;
  db = await open({ filename: DB_PATH, driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      avatar TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      category TEXT,
      stock INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      shipping_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      price REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      rating INTEGER DEFAULT 5,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await seed(db);
  return db;
}

async function seed(db) {
  const adminExists = await db.get('SELECT id FROM users WHERE username = ?', 'admin');
  if (!adminExists) {
    const adminHash = bcrypt.hashSync('admin123', 10);
    await db.run(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      'admin', 'admin@shop.local', adminHash, 'admin'
    );
    const userHash = bcrypt.hashSync('user123', 10);
    await db.run(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      'testuser', 'user@shop.local', userHash, 'user'
    );
  }
  const productsExist = await db.get('SELECT id FROM products LIMIT 1');
  if (!productsExist) {
    const ps = [
      ['Wireless Headphones', 'Premium noise-cancelling wireless headphones with 30h battery life and foldable design.', 89.99, 'electronics', 50],
      ['Mechanical Keyboard', 'Compact TKL mechanical keyboard with Cherry MX Brown switches and RGB backlight.', 129.99, 'electronics', 30],
      ['Leather Wallet', 'Slim genuine leather bifold wallet with RFID blocking and 6 card slots.', 34.99, 'accessories', 100],
      ['Running Shoes', 'Lightweight performance running shoes for road and trail. Available in sizes 38-47.', 79.99, 'footwear', 45],
      ['Coffee Grinder', 'Burr coffee grinder with 18 grind settings, 200g capacity, for the perfect brew every time.', 59.99, 'kitchen', 25],
    ];
    for (const p of ps) {
      await db.run('INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)', ...p);
    }
  }
}

// [VULN-V02: SQL Injection (distributed) — CWE-89 — user input flows from products.js into this function]
// [VULN-V02: taint source: req.query.q → buildSearchQuery(term) → template literal → SQL execution]
function buildSearchQuery(term) {
  return `SELECT * FROM products WHERE active = 1 AND (name LIKE '%${term}%' OR description LIKE '%${term}%')`;
}

module.exports = { getDb, buildSearchQuery };
