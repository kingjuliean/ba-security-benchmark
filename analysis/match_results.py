#!/usr/bin/env python3
"""
analysis/match_results.py — Ground-Truth-Matching (FF1)

Liest alle Tool-Outputs aus benchmark/results/,
matched gegen targets/vulnerable-shop/Shop/GROUND_TRUTH.md,
gibt TP/FP/FN/TN pro Tool/Target/Run aus.

Usage:
    python analysis/match_results.py
    python analysis/match_results.py --tool semgrep --target vulnerable-shop --run 1
    python analysis/match_results.py --verbose
"""

import argparse
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

# ── Konfiguration ─────────────────────────────────────────────────────────────

REPO_ROOT       = Path(__file__).parent.parent
RESULTS_DIR     = REPO_ROOT / "benchmark" / "results"
GROUND_TRUTH_MD = REPO_ROOT / "targets" / "vulnerable-shop" / "Shop" / "GROUND_TRUTH.md"
OUTPUT_JSON     = RESULTS_DIR / "match_results.json"

LINE_TOLERANCE = 5  # ±5 Zeilen für SAST-Matching

# Ground Truth existiert nur für vulnerable-shop — juice-shop wird nicht gematcht
GROUND_TRUTH_TARGET = "vulnerable-shop"

TOOL_TYPE = {
    "semgrep":           "SAST",
    "codeql":            "SAST",
    "sonarqube":         "SAST",
    "zap":               "DAST",
    "nuclei":            "DAST",
    "dastardly":         "DAST",
    "dependency-check":  "SCA",
    "snyk":              "SCA",
    "npm-audit":         "SCA",
}

# Manuelle DAST-Endpunkt-Zuordnung — abgeleitet aus GROUND_TRUTH.md-Beschreibungen
# Für jede echte DAST-Schwachstelle und DAST-relevante Köder
DAST_ENDPOINTS = {
    "V01": ["/api/auth/login"],
    "V02": ["/products/search", "/api/products/search"],
    "V03": ["/api/reviews", "/products/"],
    "V04": ["/products/search"],
    "V05": ["/api/admin/export"],
    "V06": ["/api/avatar/"],
    "V09": ["/api/auth/reset-password", "/api/auth/reset"],
    "V10": ["/api/orders/"],
    "V11": ["/admin/users", "/admin/orders", "/admin/"],
    "V12": ["/api/auth/login"],
    "V13": ["/api/profile/update", "/api/profile"],
    "V14": ["/"],
    "V15": ["/admin/users"],
    "K07": ["/api/auth/logout"],
    "K10": ["/admin/settings"],
}

# SonarQube-Regel-ID → CWE-Mapping (Community Edition, JS/TS-Regeln)
SONARQUBE_RULE_CWE = {
    "javascript:S3649":  ["CWE-89"],
    "javascript:S5334":  ["CWE-89"],
    "javascript:S2631":  ["CWE-79"],
    "javascript:S5247":  ["CWE-79"],
    "javascript:S4036":  ["CWE-78"],
    "javascript:S2083":  ["CWE-22"],
    "javascript:S1523":  ["CWE-502"],
    "javascript:S2068":  ["CWE-798"],
    "javascript:S5725":  ["CWE-601"],
    "javascript:S4423":  ["CWE-327"],
    "javascript:S5542":  ["CWE-327"],
    "Web:S5122":         ["CWE-16"],
    "javascript:S5256":  ["CWE-862"],
    "javascript:S5304":  ["CWE-200"],
    "javascript:S5131":  ["CWE-79"],
    "javascript:S6096":  ["CWE-22"],
}

# Docker-Mount-Prefixes, die aus Dateipfaden entfernt werden
_STRIP_PREFIXES = ["/src/", "/project/", "/usr/src/", "/home/user/", "/code/", "/app/"]


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class GTEntry:
    """Eine Zeile aus der Ground-Truth-Tabelle."""
    id:           str
    typ:          str
    cwe_ids:      List[str]
    files:        List[str]                   # normalisierte Pfade
    line_ranges:  List[Tuple[int, int]]       # (start, end) pro Datei-Eintrag
    categories:   Set[str]                    # {"SAST"}, {"DAST"}, {"SCA"}, ...
    is_decoy:     bool
    sca_packages: List[Tuple[str, str]]       # [(name, version)] für SCA-Einträge

    def relevant_for(self, tool_type: str) -> bool:
        return tool_type in self.categories

    def dast_endpoints(self) -> List[str]:
        return DAST_ENDPOINTS.get(self.id, [])


@dataclass
class Finding:
    """Ein normalisiertes Tool-Finding."""
    tool:       str
    target:     str
    run:        int
    cwe_ids:    List[str]
    file_uri:   str        # normalisierter Pfad, z.B. "src/routes/auth.js"
    start_line: int        # 0 wenn unbekannt
    endpoint:   str        # URL-Pfad für DAST
    package:    str        # Paketname für SCA
    version:    str        # Version für SCA
    rule_id:    str        # Original-Regel-ID zur Nachverfolgung


@dataclass
class MatchResult:
    """TP/FP/FN/TN-Ergebnis für eine (Tool, Target, Run)-Kombination."""
    tool:         str
    target:       str
    run:          int
    tp_ids:       List[str] = field(default_factory=list)   # gematchte echte Vuln-IDs
    fp_details:   List[str] = field(default_factory=list)   # Köder-Treffer (FP)
    fn_ids:       List[str] = field(default_factory=list)   # verpasste Vuln-IDs
    tn_ids:       List[str] = field(default_factory=list)   # korrekt ignorierte Köder
    bonus_finds:  int = 0                                   # Findings außerhalb Ground Truth

    @property
    def tp(self) -> int: return len(self.tp_ids)
    @property
    def fp(self) -> int: return len(self.fp_details)
    @property
    def fn(self) -> int: return len(self.fn_ids)
    @property
    def tn(self) -> int: return len(self.tn_ids)


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def normalize_path(uri: str) -> str:
    """Entfernt Docker-Mount-Prefixes und normalisiert Pfadtrennzeichen."""
    if not uri:
        return ""
    p = uri.replace("\\", "/")
    for prefix in _STRIP_PREFIXES:
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    # Absoluter Pfad ohne bekannten Prefix: ab "src/" kürzen
    if "src/" in p and not p.startswith("src/"):
        p = p[p.index("src/"):]
    return p.lstrip("./")


def _parse_line_field(raw: str) -> List[Tuple[int, int]]:
    """Parst Zeilen-Angaben: '41', '61–73', '26 / 90–91', '—' → [(start, end)]."""
    raw = raw.strip().replace("–", "-").replace("—", "").replace("—", "")
    if not raw:
        return []
    result = []
    for part in re.split(r"\s*/\s*", raw):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"(\d+)\s*[-]\s*(\d+)", part)
        if m:
            result.append((int(m.group(1)), int(m.group(2))))
        elif re.match(r"^\d+$", part):
            n = int(part)
            result.append((n, n))
    return result


def _parse_cwe_field(raw: str) -> List[str]:
    """Extrahiert CWE-IDs aus 'CWE-89', 'CWE-400/1321' etc."""
    found = re.findall(r"CWE-\d+", raw, re.IGNORECASE)
    if not found:
        # Slash-getrennte Nummern: "CWE-400/1321"
        m = re.match(r"CWE-(\d+(?:/\d+)+)", raw, re.IGNORECASE)
        if m:
            found = [f"CWE-{n}" for n in m.group(1).split("/")]
    return [c.upper() for c in found]


def _parse_files_field(raw: str) -> List[str]:
    """Extrahiert Pfade aus Backtick-Feldern: '`src/routes/auth.js`'."""
    files = re.findall(r"`([^`]+)`", raw)
    result = []
    for f in files:
        f = f.split(":")[0].strip()  # "src/file.js:30" → "src/file.js"
        if any(f.endswith(ext) for ext in (".js", ".json", ".ts", ".ejs", ".html")):
            result.append(normalize_path(f))
        elif "/" in f and not f.startswith("http"):
            result.append(normalize_path(f))
    return result


def _parse_sca_packages(typ: str) -> List[Tuple[str, str]]:
    """Extrahiert (name, version) aus 'SCA: lodash@4.17.20'."""
    return re.findall(r"([a-z@][a-z0-9\-_./@]*)@(\d[\d.]+)", typ, re.IGNORECASE)


# ── Ground-Truth-Parser ───────────────────────────────────────────────────────

def parse_ground_truth(path: Path) -> List[GTEntry]:
    """
    Parst die tabellarische Übersicht aus GROUND_TRUTH.md.
    Erwartet Zeilen im Format:
    | V01 | Typ | CWE-89 | A03 | `src/routes/auth.js` | 41 | SAST+DAST | Echt |
    """
    text = path.read_text(encoding="utf-8-sig")

    row_re = re.compile(
        r"^\|\s*(V\d+|K\d+)\s*\|"   # ID
        r"\s*([^|]+?)\s*\|"          # Typ
        r"\s*([^|]*?)\s*\|"          # CWE
        r"\s*[^|]*?\s*\|"            # OWASP (ignoriert)
        r"\s*([^|]*?)\s*\|"          # Datei
        r"\s*([^|]*?)\s*\|"          # Zeile
        r"\s*([^|]*?)\s*\|"          # Tool-Kategorie
        r"\s*(Echt|Köder)\s*\|",  # Status (Echt | Köder)
        re.MULTILINE,
    )

    entries = []
    for m in row_re.finditer(text):
        vid      = m.group(1)
        typ      = m.group(2).strip()
        cwe_raw  = m.group(3).strip()
        file_raw = m.group(4).strip()
        line_raw = m.group(5).strip()
        cat_raw  = m.group(6).strip()
        status   = m.group(7).strip()

        cwe_ids     = _parse_cwe_field(cwe_raw)
        files       = _parse_files_field(file_raw)
        line_ranges = _parse_line_field(line_raw)
        is_decoy    = (status == "Köder")
        cats        = {c.strip() for c in re.split(r"[+,]", cat_raw) if c.strip()}
        sca_pkgs    = _parse_sca_packages(typ) if "SCA" in cats else []

        entries.append(GTEntry(
            id=vid, typ=typ, cwe_ids=cwe_ids,
            files=files, line_ranges=line_ranges,
            categories=cats, is_decoy=is_decoy,
            sca_packages=sca_pkgs,
        ))

    return entries


# ── CWE-Extraktion aus SARIF ──────────────────────────────────────────────────

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _sarif_rule_index(sarif_run: dict) -> dict:
    """Baut einen {ruleId: rule_dict}-Index für einen SARIF-Run."""
    rules = {}
    driver = sarif_run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []):
        rules[rule.get("id", "")] = rule
    # Extensions (z.B. CodeQL-Packs)
    for ext in sarif_run.get("tool", {}).get("extensions", []):
        for rule in ext.get("rules", []):
            rules[rule.get("id", "")] = rule
    return rules


def _extract_cwes(result: dict, rules: dict) -> List[str]:
    """Extrahiert alle CWE-IDs aus einem SARIF-Result-Objekt."""
    cwes: Set[str] = set()

    # 1. result.taxa (CodeQL-Stil: direkte CWE-Referenzen)
    for taxon in result.get("taxa", []):
        tid = taxon.get("id", "")
        if _CWE_RE.match(tid):
            cwes.add(tid.upper())

    # 2. Rule-Properties (Semgrep-Stil: tags, cwe)
    rule_id = result.get("ruleId", "")
    rule = rules.get(rule_id, {})
    props = rule.get("properties", {})

    for tag in props.get("tags", []):
        for m in _CWE_RE.finditer(str(tag)):
            cwes.add(m.group().upper())

    for cwe_val in props.get("cwe", []):
        for m in _CWE_RE.finditer(str(cwe_val)):
            cwes.add(m.group().upper())

    # 3. Relationships-Array
    for rel in rule.get("relationships", []):
        for m in _CWE_RE.finditer(json.dumps(rel)):
            cwes.add(m.group().upper())

    # 4. Rule-ID selbst (z.B. "js/sql-injection" → kein CWE, aber CodeQL taxa deckt das)
    for m in _CWE_RE.finditer(rule_id):
        cwes.add(m.group().upper())

    # 5. Ergebnis-Nachricht (letzter Ausweg)
    msg = result.get("message", {}).get("text", "")
    for m in _CWE_RE.finditer(msg):
        cwes.add(m.group().upper())

    return sorted(cwes)


# ── Format-spezifische Parser ─────────────────────────────────────────────────

def parse_sarif(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] SARIF-Parse-Fehler: {exc}")
        return []

    findings = []
    for sarif_run in data.get("runs", []):
        rules = _sarif_rule_index(sarif_run)
        for result in sarif_run.get("results", []):
            cwes = _extract_cwes(result, rules)
            file_uri, start_line = "", 0
            for loc in result.get("locations", [])[:1]:
                phys = loc.get("physicalLocation", {})
                file_uri   = normalize_path(phys.get("artifactLocation", {}).get("uri", ""))
                start_line = phys.get("region", {}).get("startLine", 0)
            findings.append(Finding(
                tool=tool, target=target, run=run,
                cwe_ids=cwes, file_uri=file_uri, start_line=start_line,
                endpoint="", package="", version="",
                rule_id=result.get("ruleId", ""),
            ))
    return findings


def parse_sonarqube_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] SonarQube-Parse-Fehler: {exc}")
        return []

    findings = []
    for issue in data.get("issues", []):
        rule_id  = issue.get("rule", "")
        cwes     = SONARQUBE_RULE_CWE.get(rule_id, [])
        # "benchmark-vulnerableshop:src/routes/auth.js" → "src/routes/auth.js"
        component = issue.get("component", "")
        file_uri  = normalize_path(component.split(":")[-1] if ":" in component else component)
        line      = issue.get("line") or 0
        findings.append(Finding(
            tool=tool, target=target, run=run,
            cwe_ids=cwes, file_uri=file_uri, start_line=int(line),
            endpoint="", package="", version="",
            rule_id=rule_id,
        ))
    return findings


def parse_zap_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] ZAP-Parse-Fehler: {exc}")
        return []

    alerts = data.get("alerts", [])
    if not alerts:
        for site in data.get("site", []):
            alerts.extend(site.get("alerts", []))

    findings = []
    for alert in alerts:
        cweid_raw = str(alert.get("cweid", alert.get("cweId", "")))
        cwes = [f"CWE-{cweid_raw}"] if cweid_raw.isdigit() else []

        instances = alert.get("instances", [{"uri": alert.get("url", "")}])
        for instance in instances:
            url      = instance.get("uri", instance.get("url", ""))
            endpoint = urlparse(url).path if url else ""
            findings.append(Finding(
                tool=tool, target=target, run=run,
                cwe_ids=cwes, file_uri="", start_line=0,
                endpoint=endpoint, package="", version="",
                rule_id=str(alert.get("alertRef", alert.get("alert", ""))),
            ))
    return findings


def parse_nuclei_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8-sig").strip()
    except OSError as exc:
        print(f"    [WARN] Nuclei-Parse-Fehler: {exc}")
        return []

    if not text or text in ("[]", "{}"):
        return []

    findings = []
    # Nuclei schreibt NDJSON (eine JSON-Zeile pro Finding)
    for line in text.splitlines():
        line = line.strip()
        if not line or line in ("[", "]"):
            continue
        line = line.rstrip(",")
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        cwe_raw = item.get("classification", {}).get("cwe-id", [])
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwes = [c.upper() for c in cwe_raw if c]

        url      = item.get("matched-at", item.get("host", ""))
        endpoint = urlparse(url).path if url else ""
        findings.append(Finding(
            tool=tool, target=target, run=run,
            cwe_ids=cwes, file_uri="", start_line=0,
            endpoint=endpoint, package="", version="",
            rule_id=item.get("template-id", ""),
        ))
    return findings


def parse_npm_audit_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] npm-audit-Parse-Fehler: {exc}")
        return []

    findings = []
    for pkg_name, vuln in data.get("vulnerabilities", {}).items():
        for entry in vuln.get("via", []):
            if isinstance(entry, str):
                continue  # Transitiv-Referenz ohne eigene Metadaten
            cwes = [c.upper() for c in entry.get("cwe", []) if c]
            findings.append(Finding(
                tool=tool, target=target, run=run,
                cwe_ids=cwes, file_uri="package.json", start_line=0,
                endpoint="", package=pkg_name, version=vuln.get("range", ""),
                rule_id=str(entry.get("url", entry.get("source", ""))),
            ))
    return findings


def parse_snyk_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] Snyk-Parse-Fehler: {exc}")
        return []

    findings = []
    for v in data.get("vulnerabilities", []):
        cwes = [c.upper() for c in v.get("identifiers", {}).get("CWE", []) if c]
        findings.append(Finding(
            tool=tool, target=target, run=run,
            cwe_ids=cwes, file_uri="package.json", start_line=0,
            endpoint="",
            package=v.get("packageName", ""),
            version=v.get("version", ""),
            rule_id=v.get("id", ""),
        ))
    return findings


def parse_dependency_check_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"    [WARN] DepCheck-Parse-Fehler: {exc}")
        return []

    findings = []
    for dep in data.get("dependencies", []):
        pkg_name, version = "", ""
        for pkg in dep.get("packages", []):
            pid = pkg.get("id", "")
            if "npm/" in pid:
                parts = pid.split("npm/")[-1].lstrip("/").split("@")
                pkg_name = parts[0]
                version  = parts[1] if len(parts) > 1 else ""
                break

        for vuln in dep.get("vulnerabilities", []):
            cwes = [c.upper() for c in vuln.get("cwes", []) if c]
            findings.append(Finding(
                tool=tool, target=target, run=run,
                cwe_ids=cwes, file_uri="package.json", start_line=0,
                endpoint="", package=pkg_name, version=version,
                rule_id=vuln.get("name", ""),
            ))
    return findings


def parse_dastardly_xml(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    try:
        # Strip invalid XML character references (e.g. &#x1F; &#0;) before parsing
        content = path.read_text(encoding="utf-8-sig", errors="replace")
        content = re.sub(r"&#(?:x[0-9A-Fa-f]+|\d+);", "", content)
        tree = ET.fromstring(content)
        tree = ET.ElementTree(tree)
    except ET.ParseError as exc:
        print(f"    [WARN] Dastardly-XML-Parse-Fehler: {exc}")
        return []

    findings = []
    for tc in tree.iter("testcase"):
        for failure in tc.iter("failure"):
            text = failure.text or ""
            cwes = [m.group().upper() for m in _CWE_RE.finditer(text)]
            url_m = re.search(r"https?://[^\s<]+", text)
            endpoint = urlparse(url_m.group()).path if url_m else ""
            findings.append(Finding(
                tool=tool, target=target, run=run,
                cwe_ids=cwes, file_uri="", start_line=0,
                endpoint=endpoint, package="", version="",
                rule_id=tc.get("name", ""),
            ))
    return findings


# ── Finding-Loader ─────────────────────────────────────────────────────────────

def _dispatch_json(path: Path, tool: str, target: str, run: int) -> List[Finding]:
    dispatch = {
        "sonarqube":        parse_sonarqube_json,
        "zap":              parse_zap_json,
        "nuclei":           parse_nuclei_json,
        "npm-audit":        parse_npm_audit_json,
        "snyk":             parse_snyk_json,
        "dependency-check": parse_dependency_check_json,
    }
    parser = dispatch.get(tool)
    if parser:
        return parser(path, tool, target, run)
    print(f"    [WARN] Kein JSON-Parser für Tool '{tool}'.")
    return []


_JSON_PREFERRED_TOOLS = {"sonarqube", "zap", "nuclei", "npm-audit", "snyk", "dependency-check"}
_XML_ONLY_TOOLS       = {"dastardly"}


def load_findings(
    results_dir: Path,
    filter_tool:   str = "",
    filter_target: str = "",
    filter_run:    int = 0,
) -> List[Finding]:
    """Lädt alle Findings aus benchmark/results/<tool>/<target>/run_<n>.*"""
    all_findings: List[Finding] = []

    for tool_dir in sorted(results_dir.iterdir()):
        if not tool_dir.is_dir():
            continue
        tool = tool_dir.name
        if filter_tool and tool != filter_tool:
            continue
        if tool not in TOOL_TYPE:
            continue

        for target_dir in sorted(tool_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            target = target_dir.name
            if filter_target and target != filter_target:
                continue

            for result_file in sorted(target_dir.iterdir()):
                m = re.match(r"run_(\d+)\.(sarif|json|xml)$", result_file.name)
                if not m:
                    continue
                run = int(m.group(1))
                if filter_run and run != filter_run:
                    continue

                ext = result_file.suffix.lower()

                # Avoid double-parsing: tools with JSON parser skip .sarif/.xml duplicates
                if ext == ".sarif" and tool in _JSON_PREFERRED_TOOLS:
                    continue
                if ext == ".xml" and tool not in _XML_ONLY_TOOLS:
                    continue

                print(f"  Lade {result_file.relative_to(results_dir)}", end="")

                if ext == ".sarif":
                    findings = parse_sarif(result_file, tool, target, run)
                elif ext == ".json":
                    findings = _dispatch_json(result_file, tool, target, run)
                elif ext == ".xml":
                    findings = parse_dastardly_xml(result_file, tool, target, run)
                else:
                    findings = []

                print(f"  → {len(findings)} Findings")
                all_findings.extend(findings)

    return all_findings


def discover_all_combos(
    results_dir: Path,
    filter_tool:   str = "",
    filter_target: str = "",
    filter_run:    int = 0,
) -> set:
    """Gibt alle (tool, target, run)-Tupel zurück, für die Ergebnisdateien existieren."""
    combos = set()
    for tool_dir in sorted(results_dir.iterdir()):
        if not tool_dir.is_dir():
            continue
        tool = tool_dir.name
        if filter_tool and tool != filter_tool:
            continue
        if tool not in TOOL_TYPE:
            continue
        for target_dir in sorted(tool_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            target = target_dir.name
            if filter_target and target != filter_target:
                continue
            for result_file in sorted(target_dir.iterdir()):
                m = re.match(r"run_(\d+)\.(sarif|json|xml)$", result_file.name)
                if not m:
                    continue
                ext = result_file.suffix.lower()
                # Use same skip logic as load_findings
                if ext == ".sarif" and tool in _JSON_PREFERRED_TOOLS:
                    continue
                if ext == ".xml" and tool not in _XML_ONLY_TOOLS:
                    continue
                run = int(m.group(1))
                if filter_run and run != filter_run:
                    continue
                combos.add((tool, target, run))
    return combos


# ── Matching-Logik ─────────────────────────────────────────────────────────────

def _cwe_match(finding_cwes: List[str], gt_cwes: List[str]) -> bool:
    """True wenn die CWE-Sets sich überschneiden."""
    if not gt_cwes or not finding_cwes:
        return False
    return bool(set(finding_cwes) & set(gt_cwes))


def _sast_match(f: Finding, gt: GTEntry) -> bool:
    """CWE + Datei (Suffix-Match) + Zeile (±LINE_TOLERANCE)."""
    if not _cwe_match(f.cwe_ids, gt.cwe_ids):
        return False
    if not gt.files:
        return False
    for i, gt_file in enumerate(gt.files):
        if not f.file_uri or not gt_file:
            continue
        # Suffix-Match: "src/routes/auth.js" passt auf "/src/routes/auth.js"
        if not (f.file_uri.endswith(gt_file) or gt_file.endswith(f.file_uri)):
            continue
        # Zeilen-Check
        if i < len(gt.line_ranges):
            lo, hi = gt.line_ranges[i]
            if lo - LINE_TOLERANCE <= f.start_line <= hi + LINE_TOLERANCE:
                return True
        else:
            return True  # Kein Zeilen-Constraint → Datei-Match reicht
    return False


def _dast_match(f: Finding, gt: GTEntry) -> bool:
    """CWE + URL-Endpoint-Übereinstimmung."""
    if not _cwe_match(f.cwe_ids, gt.cwe_ids):
        return False
    endpoints = gt.dast_endpoints()
    if not endpoints:
        # Kein Endpoint-Constraint — CWE-Match allein reicht (z.B. V14 Security Headers)
        return True
    if not f.endpoint:
        # Tool hat keinen Endpoint gemeldet — CWE allein als Fallback
        return True
    for ep in endpoints:
        if f.endpoint.startswith(ep) or ep in f.endpoint:
            return True
    return False


def _sca_match(f: Finding, gt: GTEntry) -> bool:
    """CWE + Paketname (Version ist informativ, kein hartes Kriterium)."""
    if not _cwe_match(f.cwe_ids, gt.cwe_ids):
        return False
    if not gt.sca_packages:
        return False
    for pkg_name, _ in gt.sca_packages:
        if f.package and pkg_name.lower() in f.package.lower():
            return True
    return False


def match_findings(
    findings:     List[Finding],
    ground_truth: List[GTEntry],
    tool:         str,
    target:       str,
    run:          int,
) -> MatchResult:
    """Klassifiziert alle Findings einer (Tool, Target, Run)-Kombination."""

    tool_type = TOOL_TYPE.get(tool, "")
    result    = MatchResult(tool=tool, target=target, run=run)

    relevant_gt = [gt for gt in ground_truth if gt.relevant_for(tool_type)]
    if not relevant_gt:
        return result

    real_vulns = {gt.id: gt for gt in relevant_gt if not gt.is_decoy}
    decoys     = {gt.id: gt for gt in relevant_gt if gt.is_decoy}

    matched_vuln_ids:  Set[str] = set()
    matched_decoy_ids: Set[str] = set()

    run_findings = [f for f in findings if f.tool == tool and f.target == target and f.run == run]

    for finding in run_findings:
        matched_any = False

        # Echte Schwachstellen prüfen
        for vid, gt in real_vulns.items():
            if vid in matched_vuln_ids:
                continue  # Deduplizierung: jede GT-Schwachstelle zählt max. 1× als TP
            hit = (
                _sast_match(finding, gt) if tool_type == "SAST" else
                _dast_match(finding, gt) if tool_type == "DAST" else
                _sca_match(finding, gt)
            )
            if hit:
                matched_vuln_ids.add(vid)
                matched_any = True

        # Köder prüfen (FP-Erkennung)
        for kid, gt in decoys.items():
            if kid in matched_decoy_ids:
                continue
            hit = (
                _sast_match(finding, gt) if tool_type == "SAST" else
                _dast_match(finding, gt) if tool_type == "DAST" else
                False  # SCA hat keine Köder
            )
            if hit:
                matched_decoy_ids.add(kid)
                matched_any = True
                result.fp_details.append(
                    f"Köder {kid} ausgelöst (rule={finding.rule_id}, "
                    f"file={finding.file_uri}:{finding.start_line})"
                )

        # Finding ohne jeglichen GT-Treffer → Bonus Find (kein FP)
        # FP zählt nur für Köder-Treffer; Findings außerhalb der Ground Truth
        # werden nicht bestraft, da die Ground Truth möglicherweise unvollständig ist.
        if not matched_any:
            result.bonus_finds += 1

    result.tp_ids  = sorted(matched_vuln_ids)
    result.fn_ids  = sorted(set(real_vulns) - matched_vuln_ids)
    result.tn_ids  = sorted(set(decoys) - matched_decoy_ids)

    return result


# ── Ausgabe ───────────────────────────────────────────────────────────────────

def print_result(r: MatchResult, verbose: bool = False) -> None:
    bar = "─" * 58
    print(f"\n  {bar}")
    print(f"  {r.tool:22s}  {r.target:18s}  Run {r.run}")
    print(f"  {bar}")
    print(f"  TP={r.tp:3d}  FP={r.fp:3d}  FN={r.fn:3d}  TN={r.tn:3d}  Bonus={r.bonus_finds:3d}")
    if r.tp_ids:
        print(f"  TP : {', '.join(r.tp_ids)}")
    if r.fn_ids:
        print(f"  FN : {', '.join(r.fn_ids)}")
    if r.tn_ids:
        print(f"  TN : {', '.join(r.tn_ids)}")
    if verbose and r.fp_details:
        shown = r.fp_details[:10]
        for fp in shown:
            print(f"  FP : {fp}")
        if len(r.fp_details) > 10:
            print(f"       … +{len(r.fp_details) - 10} weitere FPs")


def results_to_dict(results: List[MatchResult]) -> List[dict]:
    return [
        {
            "tool":         r.tool,
            "target":       r.target,
            "run":          r.run,
            "TP":           r.tp,
            "FP":           r.fp,
            "FN":           r.fn,
            "TN":           r.tn,
            "bonus_finds":  r.bonus_finds,
            "tp_ids":       r.tp_ids,
            "fn_ids":       r.fn_ids,
            "tn_ids":       r.tn_ids,
            "fp_details":   r.fp_details,
        }
        for r in results
    ]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Ground-Truth-Matching — BA-Security-Benchmark (FF1)")
    ap.add_argument("--tool",    default="", help="Nur dieses Tool auswerten (z.B. semgrep)")
    ap.add_argument("--target",  default="", help="Nur dieses Target (z.B. vulnerable-shop)")
    ap.add_argument("--run",     type=int, default=0, help="Nur Run N (0 = alle)")
    ap.add_argument("--verbose", action="store_true", help="Alle FP-Details ausgeben")
    args = ap.parse_args()

    print("\n══════════════════════════════════════════════════════════════")
    print("  BA Security Benchmark — Ground-Truth-Matching (FF1)")
    print("══════════════════════════════════════════════════════════════")

    # Ground Truth laden
    if not GROUND_TRUTH_MD.exists():
        print(f"  [ERROR] Ground-Truth-Datei nicht gefunden: {GROUND_TRUTH_MD}")
        raise SystemExit(1)

    print(f"\n  Ground Truth: {GROUND_TRUTH_MD}")
    gt_entries = parse_ground_truth(GROUND_TRUTH_MD)
    real_count  = sum(1 for g in gt_entries if not g.is_decoy)
    decoy_count = sum(1 for g in gt_entries if g.is_decoy)
    print(f"  → {real_count} echte Schwachstellen (V01–V20), {decoy_count} Köder (K01–K10)")

    # Findings laden
    print(f"\n  Tool-Outputs: {RESULTS_DIR}")
    if not RESULTS_DIR.exists():
        print("  [ERROR] benchmark/results/ nicht gefunden. Bitte zuerst run_benchmark.ps1 ausführen.")
        raise SystemExit(1)

    findings = load_findings(
        RESULTS_DIR,
        filter_tool=args.tool,
        filter_target=args.target,
        filter_run=args.run,
    )

    # Alle (Tool, Target, Run)-Kombinationen: aus Findings PLUS alle Ergebnisdateien
    # (Tools mit 0 Findings werden sonst stillschweigend übergangen)
    # Nur GROUND_TRUTH_TARGET — juice-shop hat keine Ground Truth und wird nicht gematcht.
    combos_from_findings = {(f.tool, f.target, f.run) for f in findings
                            if f.target == GROUND_TRUTH_TARGET}
    combos_from_files    = discover_all_combos(
        RESULTS_DIR,
        filter_tool=args.tool,
        filter_target=args.target or GROUND_TRUTH_TARGET,
        filter_run=args.run,
    )
    all_combos = sorted(combos_from_findings | combos_from_files)
    print(f"  → {len(findings)} Findings insgesamt, {len(all_combos)} Kombinationen")

    # Alle (Tool, Target, Run)-Kombinationen matchen
    print("\n  Matching...")
    results: List[MatchResult] = []

    for tool, target, run in all_combos:
        mr = match_findings(findings, gt_entries, tool, target, run)
        results.append(mr)
        print_result(mr, verbose=args.verbose)

    # JSON-Export
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(results_to_dict(results), indent=2, ensure_ascii=False),
        encoding="utf-8-sig",
    )

    print(f"\n  Ergebnisse gespeichert: {OUTPUT_JSON}")
    print("  Nächster Schritt: python analysis/calculate_metrics.py\n")


if __name__ == "__main__":
    main()
