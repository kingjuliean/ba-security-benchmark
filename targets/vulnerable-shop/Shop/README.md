# VulnShop — Deliberately Vulnerable E-Commerce Application

> **WARNING: DO NOT DEPLOY TO A PUBLIC INTERNET SERVER**  
> This application contains intentional security vulnerabilities for academic research purposes only.  
> Use exclusively in isolated lab environments (Docker, local VM, air-gapped network).

## Purpose

VulnShop is a controlled-vulnerability Node.js/Express e-commerce application built for benchmarking SAST, DAST, and SCA security scanning tools as part of a Bachelor's thesis. It contains **20 real vulnerabilities** and **10 false-positive decoys**, fully documented in [GROUND_TRUTH.md](GROUND_TRUTH.md).

## Quick Start

### Docker (Recommended)

```bash
docker-compose up --build
```

App available at: **http://localhost:3000**

### Local

```bash
npm install
mkdir -p data public/uploads/avatars /tmp/exports
npm start
```

## Default Credentials

| Role  | Username   | Password   |
|-------|-----------|------------|
| Admin | `admin`    | `admin123` |
| User  | `testuser` | `user123`  |

## Application Features

| Route                      | Description                          |
|---------------------------|--------------------------------------|
| `/products`               | Product listing                      |
| `/products/search?q=`     | Product search                       |
| `/products/:id`           | Product detail + reviews             |
| `/login`, `/register`     | Authentication                       |
| `/reset-password`         | Password reset (no token — V09)      |
| `/api/orders`             | Order management                     |
| `/api/profile`            | User profile + avatar upload         |
| `/admin`                  | Admin dashboard (no role check — V11)|
| `/admin/users`            | User list with password hashes (V15) |
| `/api/admin/export`       | Order export (command injection — V05)|

## Repository Structure

```
vulnerable-shop/
├── GROUND_TRUTH.md          # Complete vulnerability documentation
├── docker-compose.yml
├── Dockerfile
├── package.json             # Contains 5 vulnerable SCA dependencies
├── .env.example
├── .zap/
│   └── automation.yml       # ZAP Automation Framework starter config
├── clean/                   # Scan target — production-style code, NO markers
│   └── src/
│       ├── app.js
│       ├── middleware/auth.js
│       ├── models/db.js
│       ├── routes/
│       └── views/
├── annotated/               # Reference copy — identical code WITH marker comments
│   └── src/ [same structure]
└── public/                  # Static assets (CSS, JS, themes, uploads)
```

## Scanning the App

Always scan the **`clean/`** version (what Docker runs). Use `annotated/` only for ground-truth verification.

### SAST

```bash
# Semgrep
semgrep --config=auto clean/src/

# CodeQL
codeql database create vuln-shop-db --language=javascript --source-root=clean/
codeql database analyze vuln-shop-db javascript-code-scanning.qls

# SonarQube
sonar-scanner -Dsonar.projectBaseDir=clean/
```

### DAST — ZAP

```bash
docker run -v $(pwd)/.zap:/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/automation.yml
```

### SCA

```bash
npm audit
snyk test
dependency-check --project vulnerable-shop --scan .
```

## Vulnerable SCA Dependencies

| Package              | Version  | CVE(s)                                      |
|---------------------|----------|---------------------------------------------|
| `lodash`            | 4.17.20  | CVE-2021-23337, GHSA-p6mc-m468-83gw         |
| `jsonwebtoken`      | 8.5.1    | CVE-2022-23529, CVE-2022-23540, CVE-2022-23541 |
| `express`           | 4.16.0   | CVE-2022-24999 (transitive qs), CVE-2024-45296 (transitive path-to-regexp) |
| `marked`            | 0.3.6    | CVE-2022-21680, CVE-2022-21681              |
| `axios`             | 0.21.0   | CVE-2021-3749                               |

## Ground Truth

See [GROUND_TRUTH.md](GROUND_TRUTH.md) for the complete list of all 30 security-relevant code locations, including:
- CWE classification
- Expected detection by tool category (SAST/DAST/SCA)
- Exploit examples
- False-positive decoy explanations

---

*Built for academic security tool evaluation — Bachelor's Thesis 2024/2025*
