const jwt = require('jsonwebtoken');

// [VULN-V08: Hardcoded Secret — CWE-798 — JWT_SECRET as string literal instead of process.env]
const JWT_SECRET = 'sh0pS3cr3t!2024';

// [DECOY-K08: Looks like a secret but is a labeled test fixture — not a real key]
const TEST_PUBLIC_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' +
  'test_fixture_not_a_real_key_do_not_use_in_production_00000000000000';

function requireAuth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) {
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }
  try {
    // [VULN-V17: SCA — jsonwebtoken@8.5.1 vulnerable to CVE-2022-23529 / CVE-2022-23540 / CVE-2022-23541]
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    res.clearCookie('token');
    res.redirect('/login');
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

module.exports = { JWT_SECRET, requireAuth, requireAdmin, TEST_PUBLIC_KEY };
