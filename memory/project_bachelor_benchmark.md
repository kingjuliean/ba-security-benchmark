---
name: project-bachelor-benchmark
description: Bachelorthesis — quantitative Evaluation von 9 Application-Security-Testing-Tools (SAST/DAST/SCA)
metadata:
  type: project
---

Bachelorthesis: quantitatives Benchmark-Setup für 9 AST-Tools.

**Why:** Drei Forschungsfragen — FF1 Detektionsqualität (Recall/Precision/F1/Youden), FF2 Integrationsaufwand, FF3 Wirtschaftlichkeit (TCO, 27 Toolchain-Kombinationen).

**Tools:**
- SAST: Semgrep, CodeQL, SonarQube Community
- DAST: OWASP ZAP, Nuclei, Burp Dastardly
- SCA: OWASP Dependency-Check, Snyk (Free), npm audit

**Targets:**
- `targets/vulnerable-shop/Shop/` — Express.js-App, 20 echte Schwachstellen (V01–V20) + 10 FP-Köder (K01–K10), Ground Truth in `GROUND_TRUTH.md`
- `targets/juice-shop/` — nur docker-compose.yml; Quellcode muss geklont werden

**Ports:** vulnerable-shop → 3001, juice-shop → 3000

**Output-Format:** SARIF v2.1.0. Native SARIF: Semgrep, CodeQL, ZAP, Dependency-Check (optional). Konvertierung nötig: SonarQube (JSON), Nuclei (JSON), npm audit (JSON), Snyk (JSON), Dastardly (XML).

**Matching-Logik (FF1):**
- SAST: CWE-ID + Datei + Zeile (±5)
- DAST: CWE-ID + URL-Endpoint
- SCA: CWE-ID + Package-Name + Version

**Setup 1 (lokal, FF1):** `benchmark/run_benchmark.ps1` — alle 9 Tools × 2 Targets × 3 Runs, Output unter `benchmark/results/<tool>/<target>/run_<n>.<ext>`, Timing in `benchmark/results/timing.csv`

**Setup 2 (CI, FF2):** `pipeline/github-actions.yml` — Build → SAST (parallel) → SCA (parallel) → Deploy → DAST (parallel)

**Platform:** Windows 11 + Docker Desktop. DAST-Container nutzen `host.docker.internal` statt `localhost`.

**How to apply:** Beim Schreiben von Docker-Befehlen immer `host.docker.internal` für DAST-Targets verwenden (kein `--network host` auf Windows).
