const http = require('http');

function req(method, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const body = data ? JSON.stringify(data) : null;
    const opts = {
      hostname: 'localhost', port: 3000, path, method,
      headers: body
        ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers }
        : headers
    };
    const r = http.request(opts, resp => {
      let b = '';
      resp.on('data', d => b += d);
      resp.on('end', () => resolve({
        s: resp.statusCode,
        loc: resp.headers.location,
        cook: (resp.headers['set-cookie'] || [''])[0].split(';')[0],
        b,
        headers: resp.headers
      }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

let passed = 0, failed = 0;
function pass(label, ok, detail = '') {
  if (ok) { passed++; console.log('  \x1b[32mPASS\x1b[0m', label, detail ? '\x1b[90m' + detail + '\x1b[0m' : ''); }
  else    { failed++; console.log('  \x1b[31mFAIL\x1b[0m', label, detail ? '\x1b[90m' + detail + '\x1b[0m' : ''); }
}

(async () => {
  let r, adminCook, userCook, newAdminCook;

  // ─── Pre-test setup ────────────────────────────────────────────────
  // Reset admin password to known value (uses V09 itself — no token needed)
  await req('POST', '/api/auth/reset-password', { email: 'admin@shop.local', newPassword: 'admin123' });

  // ─── Infrastructure ─────────────────────────────────────────────────
  console.log('\n\x1b[1m=== Infrastructure ===\x1b[0m');
  r = await req('GET', '/');
  pass('GET / → 302 /products', r.s === 302 && r.loc === '/products');

  r = await req('GET', '/login');
  pass('Login page renders', r.s === 200 && r.b.includes('Sign In'));

  r = await req('GET', '/products');
  pass('Products page', r.s === 200 && r.b.includes('VulnShop'));

  r = await req('GET', '/products/1');
  pass('Product detail (id=1)', r.s === 200 && r.b.includes('Headphone'));

  r = await req('GET', '/products/search?q=keyboard');
  pass('Search', r.s === 200 && r.b.includes('Keyboard'));

  // ─── Auth setup ─────────────────────────────────────────────────────
  console.log('\n\x1b[1m=== Authentication setup ===\x1b[0m');
  const ts = Date.now();
  r = await req('POST', '/api/auth/register', { username: 'user' + ts, email: ts + '@test.com', password: 'pass123' });
  pass('Register new user', r.s === 201);

  r = await req('POST', '/api/auth/login', { username: 'admin', password: 'admin123' });
  adminCook = r.cook;
  pass('Admin login', r.s === 302 && r.loc === '/products', 'cookie: ' + adminCook.substring(0, 40) + '...');

  r = await req('POST', '/api/auth/login', { username: 'testuser', password: 'user123' });
  userCook = r.cook;
  pass('Testuser login', r.s === 302 && r.loc === '/products');

  // ─── SAST Vulnerabilities ────────────────────────────────────────────
  console.log('\n\x1b[1m=== SAST Vulnerabilities ===\x1b[0m');

  // V01 — error-based detection
  r = await req('POST', '/api/auth/login', { username: "'", password: 'x' });
  pass("V01 SQLi (klassisch) — broken quote → 500", r.s === 500 && r.b.includes('Database error'));

  // V01 — OR bypass: unknown username + known password
  r = await req('POST', '/api/auth/login', { username: "nonexistent' OR '1'='1' --", password: 'admin123' });
  pass("V01 SQLi (klassisch) — OR bypass login", r.s === 302 && r.loc === '/products', '-> ' + r.loc);

  // V02 — interprocedural: UNION SELECT via search (URL-encoded)
  const unionPayload = encodeURIComponent("' UNION SELECT 1,'injected','injected-desc',0.01,'electronics',99,1 --");
  r = await req('GET', '/products/search?q=' + unionPayload);
  pass("V02 SQLi (verteilt) — UNION inject in search", r.s === 200 && r.b.includes('injected'));

  // V03 — stored XSS
  const xssPayload = '<script>alert(document.cookie)</script>';
  r = await req('POST', '/api/reviews', { productId: 1, content: xssPayload, rating: 5 }, { Cookie: userCook });
  pass("V03 Stored XSS — review accepted", r.s === 201);
  r = await req('GET', '/products/1');
  pass("V03 Stored XSS — payload unescaped in HTML", r.b.includes(xssPayload));

  // V04 — reflected XSS
  r = await req('GET', '/products/search?q=<script>alert(1)</script>');
  pass("V04 Reflected XSS — payload unescaped in response", r.b.includes('<script>alert(1)</script>'));

  // V05 — command injection endpoint
  r = await req('POST', '/api/admin/export', { filename: 'test-report' }, { Cookie: adminCook });
  pass("V05 Cmd injection — export endpoint reachable", r.s === 200 || r.s === 500, '(status ' + r.s + ')');

  // V06 — path traversal endpoint exists
  r = await req('GET', '/api/avatar/nonexistent.jpg');
  pass("V06 Path traversal — endpoint reachable (no auth required)", r.s === 404);

  // V07 — insecure deserialization: eval executes code
  const malCart = Buffer.from('({items:[],nodeType:typeof process})').toString('base64');
  r = await req('POST', '/api/cart/import', { cartData: malCart }, { Cookie: userCook });
  pass("V07 Insecure deserialization — eval exposes process object", r.s === 200 && r.b.includes('"object"'));

  // V08 — hardcoded secret: JWT payload readable without verification
  const jwtB64 = adminCook.replace('token=', '').split('.')[1];
  const padded = jwtB64 + '='.repeat((4 - jwtB64.length % 4) % 4);
  const decoded = JSON.parse(Buffer.from(padded, 'base64').toString());
  pass("V08 Hardcoded secret — JWT role readable", decoded && decoded.role === 'admin', 'id=' + (decoded||{}).id + ' role=' + (decoded||{}).role);

  // ─── DAST Vulnerabilities ────────────────────────────────────────────
  console.log('\n\x1b[1m=== DAST Vulnerabilities ===\x1b[0m');

  // V09 — password reset without token
  r = await req('POST', '/api/auth/reset-password', { email: 'admin@shop.local', newPassword: 'hacked123' });
  pass("V09 Broken Auth — reset without token (200)", r.s === 200 && r.b.includes('updated'));
  r = await req('POST', '/api/auth/login', { username: 'admin', password: 'hacked123' });
  newAdminCook = r.cook;
  pass("V09 — hacked password now works", r.s === 302 && r.loc === '/products');

  // V10 — IDOR: create order as testuser, read as admin (no ownership check)
  r = await req('POST', '/api/orders', { items: [{ productId: 2, quantity: 1 }], shippingAddress: 'Street 1' }, { Cookie: userCook });
  const orderId = (r.b.match(/"orderId":(\d+)/) || [])[1] || '1';
  pass("Order created", r.s === 201, 'orderId=' + orderId);
  r = await req('GET', '/api/orders/' + orderId, {}, { Cookie: newAdminCook });
  pass("V10 IDOR — admin reads testuser order (no 403)", r.s === 200, 'no ownership check applied');

  // V11 — missing authorization: non-admin accesses admin panel
  r = await req('GET', '/admin/users', {}, { Cookie: userCook });
  pass("V11 Missing AuthZ — /admin/users as testuser", r.s === 200, 'no role check');

  // V15 — sensitive data: bcrypt hash in response
  pass("V15 Sensitive data — password_hash in HTML", r.b.includes('$2b$') || r.b.includes('$2a$'));

  // V12 — open redirect
  r = await req('POST', '/api/auth/login?next=https://evil.example.com', { username: 'testuser', password: 'user123' });
  pass("V12 Open Redirect — next= external URL followed", r.s === 302 && r.loc === 'https://evil.example.com', '-> ' + r.loc);

  // V13 — CSRF: profile update without token
  r = await req('POST', '/api/profile/update', { email: 'csrf@evil.com' }, { Cookie: userCook });
  pass("V13 CSRF — profile update accepted without CSRF token", r.s === 200);

  // V14 — stack trace in error response
  r = await req('POST', '/admin/settings', { configJson: 'INVALID_JSON{{' }, { Cookie: newAdminCook });
  pass("V14 Misconfig — stack trace in 500 response", r.s === 500 && r.b.includes('stack'));

  // V14 — X-Powered-By header
  r = await req('GET', '/products');
  pass("V14 Misconfig — X-Powered-By: Express present", (r.headers['x-powered-by'] || '').includes('Express'));

  // ─── False Positive Decoys ────────────────────────────────────────────
  console.log('\n\x1b[1m=== False Positive Decoys (should be SAFE) ===\x1b[0m');

  // K07 — allowlist redirect blocks external URLs
  r = await req('GET', '/api/auth/logout?returnTo=https://evil.com');
  pass("K07 Allowlist — evil URL blocked (redirects to /)", r.loc === '/' || (r.loc || '').includes('login'));

  // K07 — allowlist redirect allows /products
  r = await req('GET', '/api/auth/logout?returnTo=/products');
  pass("K07 Allowlist — /products URL allowed", r.loc === '/products');

  // K05 — parameterized query (SQLi attempt in order ID fails gracefully)
  r = await req('GET', '/api/orders/999999', {}, { Cookie: userCook });
  pass("K05 Parameterized — non-existent ID → 404 (no injection)", r.s === 404);

  // ─── Summary ─────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(50));
  console.log('\x1b[1mResults: ' + passed + ' passed, ' + failed + ' failed\x1b[0m');
  if (failed > 0) process.exit(1);
})().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
