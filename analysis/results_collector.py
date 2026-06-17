#!/usr/bin/env python3
"""
analysis/results_collector.py — Konsolidierter Ergebnis-Collector (FF1 + FF2)

Liest alle verfügbaren Quellen ein:
  1. benchmark/results/match_results.json    → TP/FP/FN/TN (aus match_results.py)
  2. benchmark/results/metrics.json          → Recall/Precision/F1/Youden (aus calculate_metrics.py)
  3. benchmark/results/timing.csv            → lokale Scan-Dauern (aus run_benchmark.ps1)
  4. benchmark/results/timing_ci.csv         → CI-Scan-Dauern (aus github-actions.yml)

Schreibt:
  benchmark/results/results_summary.csv     → eine Zeile pro (Tool, Target, Run)

CSV-Spalten:
  Tool, Target, Run, TP, FP, FN, TN,
  Recall, Precision, F1, Youden,
  Scan_Duration_Local_s, Scan_Duration_CI_s,
  Source_File

Usage:
    python analysis/results_collector.py
    python analysis/results_collector.py --output my_summary.csv
"""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Pfade ─────────────────────────────────────────────────────────────────────

REPO_ROOT    = Path(__file__).parent.parent
RESULTS_DIR  = REPO_ROOT / "benchmark" / "results"

MATCH_JSON   = RESULTS_DIR / "match_results.json"
METRICS_JSON = RESULTS_DIR / "metrics.json"
TIMING_LOCAL = RESULTS_DIR / "timing.csv"
TIMING_CI    = RESULTS_DIR / "timing_ci.csv"
OUTPUT_CSV   = RESULTS_DIR / "results_summary.csv"

CSV_COLUMNS = [
    "Tool",
    "Target",
    "Run",
    "TP",
    "FP",
    "FN",
    "TN",
    "Recall",
    "Precision",
    "F1",
    "Youden",
    "Scan_Duration_Local_s",
    "Scan_Duration_CI_s",
    "Source_File",
]

# ── Lade-Funktionen ───────────────────────────────────────────────────────────

def _load_json(path: Path) -> Optional[object]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"  [WARN] JSON-Parse-Fehler in {path}: {e}")
        return None


def load_match_results(path: Path) -> Dict[Tuple[str, str, int], Dict]:
    """Lädt match_results.json → {(tool, target, run): {TP, FP, FN, TN, ...}}"""
    data = _load_json(path)
    if not data:
        return {}
    index = {}
    for entry in data:
        key = (entry["tool"], entry["target"], int(entry["run"]))
        index[key] = entry
    return index


def load_metrics(path: Path) -> Dict[Tuple[str, str, int], Dict]:
    """
    Lädt metrics.json → {(tool, target, run): {recall, precision, f1, youden, ...}}
    metrics.json hat verschachtelte Struktur: entries[].runs[].
    """
    data = _load_json(path)
    if not data:
        return {}
    index = {}
    for entry in data:
        tool   = entry["tool"]
        target = entry["target"]
        for run_data in entry.get("runs", []):
            key = (tool, target, int(run_data["run"]))
            index[key] = run_data
    return index


def _load_timing_csv(path: Path) -> Dict[Tuple[str, str, int], float]:
    """
    Lädt eine Timing-CSV → {(tool, target, run): duration_seconds}
    Erwartet Header: tool,target,run,duration_seconds,[status],[timestamp]
    """
    if not path.exists():
        return {}
    timings: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
    try:
        with path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                tool   = row.get("tool", "").strip()
                target = row.get("target", "").strip()
                run    = row.get("run", "0").strip()
                dur    = row.get("duration_seconds", "0").strip()
                if not tool or not run or not dur:
                    continue
                try:
                    timings[(tool, target, int(run))].append(float(dur))
                except ValueError:
                    pass
    except OSError as e:
        print(f"  [WARN] Timing-CSV nicht lesbar {path}: {e}")
    # Bei mehreren Einträgen pro Key: Mittelwert
    return {k: sum(v) / len(v) for k, v in timings.items()}


def _fmt(val: Optional[float], digits: int = 4) -> str:
    """Formatiert float oder gibt leer zurück."""
    if val is None:
        return ""
    return f"{round(val, digits)}"


# ── Discover: alle Result-Dateien auffinden ───────────────────────────────────

def discover_result_files(results_dir: Path) -> List[Tuple[str, str, int, str]]:
    """
    Durchsucht benchmark/results/<tool>/<target>/run_<n>.* und gibt alle
    gefundenen (tool, target, run, filepath)-Tupel zurück.
    Dient als Fallback wenn match_results.json noch nicht existiert.
    """
    found = []
    if not results_dir.exists():
        return found
    for tool_dir in sorted(results_dir.iterdir()):
        if not tool_dir.is_dir() or tool_dir.name.startswith("."):
            continue
        for target_dir in sorted(tool_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            import re
            for f in sorted(target_dir.iterdir()):
                m = re.match(r"run_(\d+)\.(sarif|json|xml)$", f.name)
                if m:
                    found.append((tool_dir.name, target_dir.name, int(m.group(1)), str(f)))
    return found


# ── Rows zusammenbauen ────────────────────────────────────────────────────────

def build_rows(
    match_index:  Dict[Tuple[str, str, int], Dict],
    metrics_index: Dict[Tuple[str, str, int], Dict],
    local_timing:  Dict[Tuple[str, str, int], float],
    ci_timing:     Dict[Tuple[str, str, int], float],
    result_files:  List[Tuple[str, str, int, str]],
) -> List[Dict]:
    """Baut eine Liste von Zeilen für die CSV auf."""

    # Alle bekannten (tool, target, run)-Kombinationen aus allen Quellen sammeln
    all_keys: set = set()
    all_keys.update(match_index.keys())
    all_keys.update(metrics_index.keys())
    all_keys.update(local_timing.keys())
    all_keys.update(ci_timing.keys())
    all_keys.update((tool, target, run) for tool, target, run, _ in result_files)

    # Nicht relevante Einträge (Timing-Hilfszeilen aus CI) herausfiltern
    skip_tools = {"deploy", "build_baseline", "sast_sca_overhead"}
    all_keys = {k for k in all_keys if k[0] not in skip_tools}

    rows = []
    for key in sorted(all_keys):
        tool, target, run = key

        match  = match_index.get(key, {})
        metric = metrics_index.get(key, {})

        # Source-Datei ermitteln
        src_file = next(
            (fp for t, tgt, r, fp in result_files if (t, tgt, r) == key),
            "",
        )

        row = {
            "Tool":                  tool,
            "Target":                target,
            "Run":                   run,
            "TP":                    match.get("TP", ""),
            "FP":                    match.get("FP", ""),
            "FN":                    match.get("FN", ""),
            "TN":                    match.get("TN", ""),
            "Recall":                _fmt(metric.get("recall")),
            "Precision":             _fmt(metric.get("precision")),
            "F1":                    _fmt(metric.get("f1")),
            "Youden":                _fmt(metric.get("youden")),
            "Scan_Duration_Local_s": _fmt(local_timing.get(key)),
            "Scan_Duration_CI_s":    _fmt(ci_timing.get(key)),
            "Source_File":           src_file,
        }
        rows.append(row)

    return rows


# ── Konsolen-Zusammenfassung ──────────────────────────────────────────────────

def print_summary(rows: List[Dict]) -> None:
    if not rows:
        print("  Keine Daten zum Anzeigen.")
        return

    header = (
        f"{'Tool':<22} {'Target':<18} {'Run':>3}  "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}  "
        f"{'Recall':>7} {'Prec':>7} {'F1':>7} {'Youden':>7}  "
        f"{'Local(s)':>9} {'CI(s)':>7}"
    )
    sep = "─" * len(header)

    print(f"\n  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    prev_tool = None
    for r in rows:
        if r["Tool"] != prev_tool and prev_tool is not None:
            print(f"  {'·' * (len(sep) - 2)}")
        prev_tool = r["Tool"]

        recall  = r["Recall"]  or "  —  "
        prec    = r["Precision"] or "  —  "
        f1      = r["F1"]      or "  —  "
        youden  = r["Youden"]  or "  —  "
        local_s = r["Scan_Duration_Local_s"] or "  —  "
        ci_s    = r["Scan_Duration_CI_s"]    or "  —  "

        print(
            f"  {r['Tool']:<22} {r['Target']:<18} {r['Run']:>3}  "
            f"{str(r['TP']):>4} {str(r['FP']):>4} {str(r['FN']):>4} {str(r['TN']):>4}  "
            f"{recall:>7} {prec:>7} {f1:>7} {youden:>7}  "
            f"{local_s:>9} {ci_s:>7}"
        )

    print(f"  {sep}")
    print(f"  {len(rows)} Zeilen gesamt.\n")


# ── CSV schreiben ─────────────────────────────────────────────────────────────

def write_csv(rows: List[Dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ergebnis-Collector — BA Security Benchmark"
    )
    ap.add_argument(
        "--output", default=str(OUTPUT_CSV),
        help=f"Ausgabe-CSV (Default: {OUTPUT_CSV})",
    )
    ap.add_argument(
        "--results-dir", default=str(RESULTS_DIR),
        help="Verzeichnis mit Tool-Outputs (Default: benchmark/results/)",
    )
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    output_path = Path(args.output)

    print("\n══════════════════════════════════════════════════════════════")
    print("  BA Security Benchmark — Ergebnis-Collector (FF1 + FF2)")
    print("══════════════════════════════════════════════════════════════")

    # Quellen laden
    print(f"\n  Lade Quellen aus: {results_dir}")

    match_index  = load_match_results(MATCH_JSON)
    metrics_index = load_metrics(METRICS_JSON)
    local_timing = _load_timing_csv(TIMING_LOCAL)
    ci_timing    = _load_timing_csv(TIMING_CI)
    result_files = discover_result_files(results_dir)

    print(f"  match_results.json:  {len(match_index)} Einträge")
    print(f"  metrics.json:        {len(metrics_index)} Einträge")
    print(f"  timing.csv (lokal):  {len(local_timing)} Einträge")
    print(f"  timing_ci.csv (CI):  {len(ci_timing)} Einträge")
    print(f"  Gefundene Dateien:   {len(result_files)}")

    if not any([match_index, metrics_index, local_timing, ci_timing, result_files]):
        print("\n  [INFO] Keine Daten gefunden.")
        print("  Workflow: run_benchmark.ps1 → match_results.py → calculate_metrics.py → results_collector.py")
        raise SystemExit(0)

    # Zeilen aufbauen
    rows = build_rows(match_index, metrics_index, local_timing, ci_timing, result_files)

    # Zusammenfassung ausgeben
    print_summary(rows)

    # CSV schreiben
    write_csv(rows, output_path)
    print(f"  Gespeichert: {output_path}")
    print(f"  Spalten: {', '.join(CSV_COLUMNS)}")
    print(f"\n  Hinweis: Leere Zellen = Quelle noch nicht vorhanden.")
    print(f"  Vollständiger Workflow:")
    print(f"    1. .\\benchmark\\run_benchmark.ps1 -Tool all -Target all")
    print(f"    2. python analysis/match_results.py")
    print(f"    3. python analysis/calculate_metrics.py")
    print(f"    4. python analysis/results_collector.py\n")


if __name__ == "__main__":
    main()
