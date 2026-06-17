const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { db } = require('../models/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const EXPORT_DIR = '/tmp/exports';

// [DECOY-K03: child_process.exec() — but command is fully hardcoded, no user input — safe]
function cleanupOldExports() {
  exec('find /tmp/exports -name "*.zip" -mtime +7 -delete', (err) => {
    if (err) console.error('Cleanup error:', err.message);
  });
}

// [VULN-V05: Command Injection — CWE-78 — filename from req.body inserted unsanitized into shell command]
// Exploit: filename = "report; cat /etc/passwd > /tmp/exports/out.txt"
router.post('/export', requireAuth, (req, res) => {
  const { filename, format } = req.body;
  if (!filename) return res.status(400).json({ error: 'filename required' });

  const orders = db.prepare('SELECT * FROM orders').all();
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
