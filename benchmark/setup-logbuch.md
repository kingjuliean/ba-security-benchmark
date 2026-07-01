# Setup-Logbuch — FF2: Integrationsaufwand

Dokumentation der Setup-Zeit pro Tool in Schritten von 0,25 h.
Eingeschlossen: Account-Anlage, Token-Generierung, YAML-Konfiguration, Debugging bis zum ersten erfolgreichen Durchlauf.
Nicht eingeschlossen: reine Lese-/Recherchezeit.

---

## Semgrep

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| Account-Anlage / Login        |          |         |
| Token-Generierung             |          |         |
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## CodeQL

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| GitHub-Permissions konfigurieren |       |         |
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## SonarQube (SonarCloud)

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| Account-Anlage / Projekt anlegen |        |         |
| Token-Generierung (SONAR_TOKEN) |         |         |
| YAML-Konfiguration            |          |         |
| Automatic Analysis deaktivieren |         |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## npm audit

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## Snyk

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| Account-Anlage / Login        |          |         |
| Token-Generierung (SNYK_TOKEN) |         |         |
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## OWASP Dependency-Check

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| NVD API-Key beantragen        |          |         |
| YAML-Konfiguration            |          |         |
| Debugging / NVD-Download-Problem |        | CI/CD nicht einsetzbar wegen NVD-API-Ratenlimitierung |
| **Gesamt**                    |          |         |

---

## OWASP ZAP

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## Nuclei

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## Burp Dastardly

| Schritt                        | Zeit (h) | Notizen |
|-------------------------------|----------|---------|
| YAML-Konfiguration            |          |         |
| Debugging / erster grüner Run |          |         |
| **Gesamt**                    |          |         |

---

## Zusammenfassung

| Tool                    | Setup-Zeit (h) |
|------------------------|---------------|
| Semgrep                |               |
| CodeQL                 |               |
| SonarQube              |               |
| npm audit              |               |
| Snyk                   |               |
| OWASP Dependency-Check |               |
| OWASP ZAP              |               |
| Nuclei                 |               |
| Burp Dastardly         |               |
| **Gesamt**             |               |
