const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { getDb } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const EXPORT_DIR = '/tmp/exports';

function cleanupOldExports() {
  exec('find /tmp/exports -name "*.zip" -mtime +7 -delete', (err) => {
    if (err) console.error('Cleanup error:', err.message);
  });
}

router.post('/export', requireAuth, async (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'filename required' });

  const db = await getDb();
  const orders = await db.all('SELECT * FROM orders');
  const outFile = path.join(EXPORT_DIR, `${filename}.json`);

  try {
    fs.mkdirSync(EXPORT_DIR, { recursive: true });
    fs.writeFileSync(outFile, JSON.stringify(orders, null, 2));
  } catch (e) {
    return res.status(500).json({ error: 'Failed to write export file' });
  }

  const zipCmd = `zip ${EXPORT_DIR}/${filename}.zip ${EXPORT_DIR}/${filename}.json`;
  exec(zipCmd, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: 'Export failed', detail: stderr });
    cleanupOldExports();
    res.json({ message: 'Export complete', file: `${filename}.zip` });
  });
});

module.exports = router;
