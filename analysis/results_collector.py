#!/usr/bin/env python3
"""
analysis/results_collector.py — Konsolidierter Ergebnis-Collector (FF1 + FF2)

Kombinations-Logik für die Bachelorarbeit:
  - Detektionsqualität (Recall/Precision/F1/Youden): aus vulnerable-shop Runs
  - Timing (Scandauer):                              aus juice-shop Runs

Schreibt:
  benchmark/results/results_summary.csv         → eine Zeile pro (Tool, Run)
  benchmark/results/results_summary_agg.csv     → eine Zeile pro Tool (Mittelwert ± SD)

Usage:
    python analysis/results_collector.py
    python analysis/results_collector.py --output my_summary.csv
"""

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Pfade ─────────────────────────────────────────────────────────────────────

REPO_ROOT    = Path(__file__).parent.parent
RESULTS_DIR  = REPO_ROOT / "benchmark" / "results"

MATCH_JSON   = RESULTS_DIR / "match_results.json"
METRICS_JSON = RESULTS_DIR / "metrics.json"
TIMING_LOCAL = RESULTS_DIR / "timing.csv"

OUTPUT_CSV     = RESULTS_DIR / "results_summary.csv"
OUTPUT_AGG_CSV = RESULTS_DIR / "results_summary_agg.csv"

# Metriken kommen von diesem Target (Ground Truth)
METRIC_TARGET = "vulnerable-shop"
# Timing kommt von diesem Target (reale App ohne Ground-Truth-Verzerrung)
TIMING_TARGET = "juice-shop"

CSV_COLUMNS = [
    "Tool",
    "Run",
    "TP", "FP", "FN", "TN", "Bonus_Finds",
    "Recall", "Precision", "F1", "Youden",
    "Timing_s",
]

CSV_AGG_COLUMNS = [
    "Tool",
    "Runs",
    "Recall_mean", "Recall_std",
    "Precision_mean", "Precision_std",
    "F1_mean", "F1_std",
    "Youden_mean", "Youden_std",
    "Timing_mean_s", "Timing_std_s",
    "TP_total", "FP_total", "FN_total", "TN_total", "Bonus_total",
]

# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _fmt(val: Optional[float], digits: int = 4) -> str:
    if val is None:
        return ""
    return f"{round(val, digits)}"


def _mean(vals: List[Optional[float]]) -> Optional[float]:
    v = [x for x in vals if x is not None]
    return sum(v) / len(v) if v else None


def _std(vals: List[Optional[float]]) -> Optional[float]:
    v = [x for x in vals if x is not None]
    if len(v) < 2:
        return None
    m = sum(v) / len(v)
    return math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1))


# ── Lade-Funktionen ───────────────────────────────────────────────────────────

def _load_json(path: Path) -> Optional[object]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        print(f"  [WARN] JSON-Parse-Fehler in {path}: {e}")
        return None


def load_match_results(path: Path) -> Dict[Tuple[str, int], Dict]:
    """
    Lädt match_results.json (nur METRIC_TARGET).
    Gibt {(tool, run): entry} zurück.
    """
    data = _load_json(path)
    if not data:
        return {}
    index = {}
    for entry in data:
        if entry.get("target") != METRIC_TARGET:
            continue
        key = (entry["tool"], int(entry["run"]))
        index[key] = entry
    return index


def load_metrics(path: Path) -> Dict[Tuple[str, int], Dict]:
    """
    Lädt metrics.json (nur METRIC_TARGET).
    Gibt {(tool, run): run_data} zurück.
    """
    data = _load_json(path)
    if not data:
        return {}
    index = {}
    for entry in data:
        if entry.get("target") != METRIC_TARGET:
            continue
        tool = entry["tool"]
        for run_data in entry.get("runs", []):
            key = (tool, int(run_data["run"]))
            index[key] = run_data
    return index


def load_timing(path: Path) -> Dict[Tuple[str, int], float]:
    """
    Lädt timing.csv (nur TIMING_TARGET, nur OK-Status).
    Bei mehreren Einträgen für denselben (tool, run) gewinnt der letzte.
    Gibt {(tool, run): duration_seconds} zurück.
    """
    if not path.exists():
        return {}
    timings: Dict[Tuple[str, int], float] = {}
    try:
        with path.open(encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                tool   = row.get("tool", "").strip().lstrip("﻿")
                target = row.get("target", "").strip()
                run    = row.get("run", "").strip()
                dur    = row.get("duration_seconds", "").strip()
                status = row.get("status", "OK").strip()
                if target != TIMING_TARGET:
                    continue
                if status and status != "OK":
                    continue
                if not tool or not run or not dur:
                    continue
                try:
                    timings[(tool, int(run))] = float(dur)
                except ValueError:
                    pass
    except OSError as e:
        print(f"  [WARN] Timing-CSV nicht lesbar {path}: {e}")
    return timings


# ── Zeilen zusammenbauen ─────────────────────────────────────────────────────

def build_rows(
    match_index:   Dict[Tuple[str, int], Dict],
    metrics_index: Dict[Tuple[str, int], Dict],
    timing_index:  Dict[Tuple[str, int], float],
) -> List[Dict]:
    """Eine Zeile pro (Tool, Run): Metriken aus vulnerable-shop, Timing aus juice-shop."""

    all_keys: set = set()
    all_keys.update(match_index.keys())
    all_keys.update(metrics_index.keys())
    all_keys.update(timing_index.keys())

    rows = []
    for key in sorted(all_keys):
        tool, run = key
        match  = match_index.get(key, {})
        metric = metrics_index.get(key, {})
        timing = timing_index.get(key)

        rows.append({
            "Tool":        tool,
            "Run":         run,
            "TP":          match.get("TP", ""),
            "FP":          match.get("FP", ""),
            "FN":          match.get("FN", ""),
            "TN":          match.get("TN", ""),
            "Bonus_Finds": match.get("bonus_finds", ""),
            "Recall":      _fmt(metric.get("recall")),
            "Precision":   _fmt(metric.get("precision")),
            "F1":          _fmt(metric.get("f1")),
            "Youden":      _fmt(metric.get("youden")),
            "Timing_s":    _fmt(timing),
        })
    return rows


def build_agg_rows(rows: List[Dict]) -> List[Dict]:
    """Eine Zeile pro Tool: Mittelwert ± Standardabweichung über alle Runs."""
    by_tool: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        by_tool[r["Tool"]].append(r)

    agg_rows = []
    for tool in sorted(by_tool):
        tool_rows = by_tool[tool]

        def vals(col):
            return [float(r[col]) for r in tool_rows if r.get(col) not in ("", None)]

        recall_v    = vals("Recall")
        prec_v      = vals("Precision")
        f1_v        = vals("F1")
        youden_v    = vals("Youden")
        timing_v    = vals("Timing_s")

        agg_rows.append({
            "Tool":           tool,
            "Runs":           len(tool_rows),
            "Recall_mean":    _fmt(_mean(recall_v)),
            "Recall_std":     _fmt(_std(recall_v)),
            "Precision_mean": _fmt(_mean(prec_v)),
            "Precision_std":  _fmt(_std(prec_v)),
            "F1_mean":        _fmt(_mean(f1_v)),
            "F1_std":         _fmt(_std(f1_v)),
            "Youden_mean":    _fmt(_mean(youden_v)),
            "Youden_std":     _fmt(_std(youden_v)),
            "Timing_mean_s":  _fmt(_mean(timing_v)),
            "Timing_std_s":   _fmt(_std(timing_v)),
            "TP_total":       sum(int(r["TP"]) for r in tool_rows if r.get("TP") not in ("", None)),
            "FP_total":       sum(int(r["FP"]) for r in tool_rows if r.get("FP") not in ("", None)),
            "FN_total":       sum(int(r["FN"]) for r in tool_rows if r.get("FN") not in ("", None)),
            "TN_total":       sum(int(r["TN"]) for r in tool_rows if r.get("TN") not in ("", None)),
            "Bonus_total":    sum(int(r["Bonus_Finds"]) for r in tool_rows if r.get("Bonus_Finds") not in ("", None)),
        })
    return agg_rows


# ── Konsolen-Ausgabe ──────────────────────────────────────────────────────────

def print_detail_table(rows: List[Dict]) -> None:
    header = (
        f"{'Tool':<22} {'Run':>3}  "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Bonus':>5}  "
        f"{'Recall':>7} {'Prec':>7} {'F1':>7} {'Youden':>7}  "
        f"{'Timing(s)':>10}"
    )
    sep = "─" * len(header)
    print(f"\n  Detail: Metriken=vulnerable-shop | Timing=juice-shop")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    prev_tool = None
    for r in rows:
        if r["Tool"] != prev_tool and prev_tool is not None:
            print(f"  {'·' * (len(sep) - 2)}")
        prev_tool = r["Tool"]
        print(
            f"  {r['Tool']:<22} {r['Run']:>3}  "
            f"{str(r['TP']):>4} {str(r['FP']):>4} {str(r['FN']):>4} "
            f"{str(r['TN']):>4} {str(r['Bonus_Finds']):>5}  "
            f"{(r['Recall'] or '—'):>7} {(r['Precision'] or '—'):>7} "
            f"{(r['F1'] or '—'):>7} {(r['Youden'] or '—'):>7}  "
            f"{(r['Timing_s'] or '—'):>10}"
        )
    print(f"  {sep}")


def print_agg_table(agg_rows: List[Dict]) -> None:
    header = (
        f"{'Tool':<22} {'Runs':>4}  "
        f"{'Recall':>13} {'Precision':>13} {'F1':>13} {'Youden':>13}  "
        f"{'Timing(s)':>14}"
    )
    sep = "─" * len(header)
    print(f"\n  Aggregiert (Mittelwert ± SD über Runs):")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    for r in agg_rows:
        def pm(m, s):
            if not m:
                return "—".center(13)
            return f"{m} ±{s or '0'}"

        print(
            f"  {r['Tool']:<22} {r['Runs']:>4}  "
            f"{pm(r['Recall_mean'], r['Recall_std']):>13} "
            f"{pm(r['Precision_mean'], r['Precision_std']):>13} "
            f"{pm(r['F1_mean'], r['F1_std']):>13} "
            f"{pm(r['Youden_mean'], r['Youden_std']):>13}  "
            f"{pm(r['Timing_mean_s'], r['Timing_std_s']):>14}"
        )
    print(f"  {sep}")
    print("  Metriken: vulnerable-shop (Ground Truth) | Timing: juice-shop\n")


# ── CSV schreiben ─────────────────────────────────────────────────────────────

def write_csv(rows: List[Dict], path: Path, columns: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ergebnis-Collector — BA Security Benchmark"
    )
    ap.add_argument("--output", default=str(OUTPUT_CSV),
                    help=f"Ausgabe-CSV Detail (Default: {OUTPUT_CSV})")
    ap.add_argument("--output-agg", default=str(OUTPUT_AGG_CSV),
                    help=f"Ausgabe-CSV Aggregiert (Default: {OUTPUT_AGG_CSV})")
    args = ap.parse_args()

    print("\n══════════════════════════════════════════════════════════════")
    print("  BA Security Benchmark — Ergebnis-Collector")
    print(f"  Metriken: {METRIC_TARGET} | Timing: {TIMING_TARGET}")
    print("══════════════════════════════════════════════════════════════")

    print(f"\n  Lade Quellen aus: {RESULTS_DIR}")

    match_index   = load_match_results(MATCH_JSON)
    metrics_index = load_metrics(METRICS_JSON)
    timing_index  = load_timing(TIMING_LOCAL)

    print(f"  match_results.json ({METRIC_TARGET}):  {len(match_index)} Einträge")
    print(f"  metrics.json ({METRIC_TARGET}):        {len(metrics_index)} Einträge")
    print(f"  timing.csv ({TIMING_TARGET}):          {len(timing_index)} Einträge")

    if not any([match_index, metrics_index, timing_index]):
        print("\n  [INFO] Keine Daten gefunden.")
        print("  Workflow: run_benchmark.ps1 → match_results.py → calculate_metrics.py → results_collector.py")
        raise SystemExit(0)

    rows     = build_rows(match_index, metrics_index, timing_index)
    agg_rows = build_agg_rows(rows)

    print_detail_table(rows)
    print_agg_table(agg_rows)

    write_csv(rows, Path(args.output), CSV_COLUMNS)
    print(f"  Detail-CSV:      {args.output}")

    write_csv(agg_rows, Path(args.output_agg), CSV_AGG_COLUMNS)
    print(f"  Aggregiert-CSV:  {args.output_agg}")

    print(f"\n  Workflow:")
    print(f"    1. .\\benchmark\\run_benchmark.ps1 -Tool all -Target all")
    print(f"    2. py -3 analysis/match_results.py")
    print(f"    3. py -3 analysis/calculate_metrics.py")
    print(f"    4. py -3 analysis/results_collector.py\n")


if __name__ == "__main__":
    main()
