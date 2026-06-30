#!/usr/bin/env python3
"""
analysis/calculate_metrics.py — Metriken (FF1)

Liest benchmark/results/match_results.json ein (Ausgabe von match_results.py)
und berechnet pro Tool und Target:
  - Recall    = TP / (TP + FN)
  - Precision = TP / (TP + FP)
  - F1        = 2 · Precision · Recall / (Precision + Recall)
  - Youden's Index = Recall − FP / (FP + TN)

Über mehrere Runs wird gemittelt (Mean ± SD).

Ausgabe:
  - Konsole: formatierte Tabelle
  - benchmark/results/metrics.json
  - benchmark/results/metrics.csv  (für Weiterverarbeitung in results_collector.py)

Usage:
    python analysis/calculate_metrics.py
    python analysis/calculate_metrics.py --input benchmark/results/match_results.json
"""

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Pfade ─────────────────────────────────────────────────────────────────────

REPO_ROOT       = Path(__file__).parent.parent
RESULTS_DIR     = REPO_ROOT / "benchmark" / "results"
DEFAULT_INPUT   = RESULTS_DIR / "match_results.json"
OUTPUT_JSON     = RESULTS_DIR / "metrics.json"
OUTPUT_CSV      = RESULTS_DIR / "metrics.csv"


# ── Metriken-Berechnung ───────────────────────────────────────────────────────

def _safe_div(numerator: float, denominator: float) -> Optional[float]:
    """Division mit None-Fallback statt ZeroDivisionError."""
    if denominator == 0:
        return None
    return numerator / denominator


def calculate_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Optional[float]]:
    """
    Berechnet alle vier Metriken aus der Confusion Matrix.

    Youden's Index = Sensitivity + Specificity − 1
                   = Recall − FP / (FP + TN)
    Bei TN = 0 ist Specificity undefiniert → Youden ebenfalls None.
    """
    recall    = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)

    if recall is not None and precision is not None and (recall + precision) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None

    specificity = _safe_div(tn, fp + tn)
    if recall is not None and specificity is not None:
        youden = recall + specificity - 1.0
    else:
        youden = None

    return {
        "recall":     recall,
        "precision":  precision,
        "f1":         f1,
        "youden":     youden,
        "specificity": specificity,
    }


def _mean(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def _std(values: List[float], mean: Optional[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2 or mean is None:
        return None
    variance = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(variance)


def aggregate_runs(run_metrics: List[Dict]) -> Dict:
    """
    Aggregiert mehrere Runs zu Mittelwert ± Standardabweichung.
    Gibt auch die rohen Confusion-Matrix-Summen zurück.
    """
    keys = ["recall", "precision", "f1", "youden", "specificity"]

    # Rohe Confusion-Matrix über alle Runs summieren
    agg = {
        "tp_total": sum(r["TP"] for r in run_metrics),
        "fp_total": sum(r["FP"] for r in run_metrics),
        "fn_total": sum(r["FN"] for r in run_metrics),
        "tn_total": sum(r["TN"] for r in run_metrics),
        "run_count": len(run_metrics),
    }

    # Metriken über Runs mitteln
    for key in keys:
        vals = [r["metrics"].get(key) for r in run_metrics]
        m = _mean(vals)
        s = _std(vals, m)
        agg[f"{key}_mean"] = m
        agg[f"{key}_std"]  = s
        agg[f"{key}_runs"] = [v for v in vals]  # Raw-Werte pro Run

    # Pooled-Metrik: berechnet auf den summierten TP/FP/FN/TN
    pooled = calculate_metrics(agg["tp_total"], agg["fp_total"], agg["fn_total"], agg["tn_total"])
    agg["pooled_metrics"] = pooled

    return agg


# ── Formatierungs-Hilfsfunktionen ─────────────────────────────────────────────

def _fmt(val: Optional[float], digits: int = 3) -> str:
    if val is None:
        return "  —  "
    return f"{val:.{digits}f}"


def _fmt_pm(mean: Optional[float], std: Optional[float]) -> str:
    if mean is None:
        return "    —    "
    if std is None or std == 0.0:
        return f"{mean:.3f}      "
    return f"{mean:.3f} ±{std:.3f}"


# ── Tabellen-Ausgabe ──────────────────────────────────────────────────────────

def print_metrics_table(all_results: List[Dict]) -> None:
    """Gibt eine formatierte Tabelle pro Tool/Target aus."""

    # Gruppieren nach (tool, target)
    groups: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for r in all_results:
        groups[(r["tool"], r["target"])].append(r)

    header = (
        f"{'Tool':<22} {'Target':<18} {'Runs':>4}  "
        f"{'Recall':>12}  {'Precision':>12}  {'F1':>12}  {'Youden':>12}  "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
    )
    sep = "─" * len(header)

    print(f"\n  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    for (tool, target), runs in sorted(groups.items()):
        run_metrics = []
        for r in runs:
            m = calculate_metrics(r["TP"], r["FP"], r["FN"], r["TN"])
            run_metrics.append({**r, "metrics": m})

        agg = aggregate_runs(run_metrics)
        p = agg["pooled_metrics"]
        n = agg["run_count"]

        print(
            f"  {tool:<22} {target:<18} {n:>4}  "
            f"{_fmt_pm(agg['recall_mean'],    agg['recall_std'])!s:>12}  "
            f"{_fmt_pm(agg['precision_mean'], agg['precision_std'])!s:>12}  "
            f"{_fmt_pm(agg['f1_mean'],        agg['f1_std'])!s:>12}  "
            f"{_fmt_pm(agg['youden_mean'],    agg['youden_std'])!s:>12}  "
            f"{agg['tp_total']:>4} {agg['fp_total']:>4} {agg['fn_total']:>4} {agg['tn_total']:>4}"
        )

    print(f"  {sep}")
    print("  Werte: Mittelwert ±Std über alle Runs. Youden = Recall + Specificity − 1.")
    print("  Youden '—' bedeutet TN=0 (keine relevanten Köder für diesen Tool-Typ).\n")


def print_run_details(all_results: List[Dict]) -> None:
    """Gibt Metriken pro einzelnem Run aus."""
    print("\n  Detailansicht pro Run:")
    print(f"  {'Tool':<22} {'Target':<18} {'Run':>4}  "
          f"{'Recall':>8} {'Prec':>8} {'F1':>8} {'Youden':>8}  "
          f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}")
    print("  " + "─" * 90)

    for r in sorted(all_results, key=lambda x: (x["tool"], x["target"], x["run"])):
        m = calculate_metrics(r["TP"], r["FP"], r["FN"], r["TN"])
        print(
            f"  {r['tool']:<22} {r['target']:<18} {r['run']:>4}  "
            f"{_fmt(m['recall']):>8} {_fmt(m['precision']):>8} "
            f"{_fmt(m['f1']):>8} {_fmt(m['youden']):>8}  "
            f"{r['TP']:>4} {r['FP']:>4} {r['FN']:>4} {r['TN']:>4}"
        )


# ── JSON/CSV-Export ───────────────────────────────────────────────────────────

def build_output(all_results: List[Dict]) -> List[Dict]:
    """Baut die vollständige Ausgabestruktur auf (für JSON und CSV)."""
    groups: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for r in all_results:
        groups[(r["tool"], r["target"])].append(r)

    output = []
    for (tool, target), runs in sorted(groups.items()):
        run_details = []
        for r in runs:
            m = calculate_metrics(r["TP"], r["FP"], r["FN"], r["TN"])
            run_details.append({
                "run":         r["run"],
                "TP":          r["TP"],
                "FP":          r["FP"],
                "FN":          r["FN"],
                "TN":          r["TN"],
                "bonus_finds": r.get("bonus_finds", 0),
                "recall":      m["recall"],
                "precision":   m["precision"],
                "f1":          m["f1"],
                "youden":      m["youden"],
                "specificity": m["specificity"],
            })

        agg = aggregate_runs([{**r, "metrics": calculate_metrics(r["TP"], r["FP"], r["FN"], r["TN"])} for r in runs])

        output.append({
            "tool":   tool,
            "target": target,
            "runs":   run_details,
            "aggregated": {
                "run_count":      agg["run_count"],
                "tp_total":       agg["tp_total"],
                "fp_total":       agg["fp_total"],
                "fn_total":       agg["fn_total"],
                "tn_total":       agg["tn_total"],
                "recall_mean":    agg["recall_mean"],
                "recall_std":     agg["recall_std"],
                "precision_mean": agg["precision_mean"],
                "precision_std":  agg["precision_std"],
                "f1_mean":        agg["f1_mean"],
                "f1_std":         agg["f1_std"],
                "youden_mean":    agg["youden_mean"],
                "youden_std":     agg["youden_std"],
                "pooled_recall":    agg["pooled_metrics"]["recall"],
                "pooled_precision": agg["pooled_metrics"]["precision"],
                "pooled_f1":        agg["pooled_metrics"]["f1"],
                "pooled_youden":    agg["pooled_metrics"]["youden"],
            },
        })
    return output


def write_csv(output: List[Dict], path: Path) -> None:
    """
    Schreibt eine flache CSV-Datei — eine Zeile pro Run.
    Kompatibel mit results_collector.py.
    """
    fieldnames = [
        "tool", "target", "run",
        "TP", "FP", "FN", "TN", "bonus_finds",
        "recall", "precision", "f1", "youden", "specificity",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry in output:
            for run in entry["runs"]:
                writer.writerow({
                    "tool":        entry["tool"],
                    "target":      entry["target"],
                    "run":         run["run"],
                    "TP":          run["TP"],
                    "FP":          run["FP"],
                    "FN":          run["FN"],
                    "TN":          run["TN"],
                    "bonus_finds": run.get("bonus_finds", ""),
                    "recall":      _fmt(run["recall"]) if run["recall"] is not None else "",
                    "precision":   _fmt(run["precision"]) if run["precision"] is not None else "",
                    "f1":          _fmt(run["f1"]) if run["f1"] is not None else "",
                    "youden":      _fmt(run["youden"]) if run["youden"] is not None else "",
                    "specificity": _fmt(run["specificity"]) if run["specificity"] is not None else "",
                })


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Metriken-Berechnung — BA-Security-Benchmark (FF1)")
    ap.add_argument("--input",    default=str(DEFAULT_INPUT),
                    help="Pfad zu match_results.json")
    ap.add_argument("--details",  action="store_true",
                    help="Metriken pro einzelnem Run ausgeben")
    ap.add_argument("--no-csv",   action="store_true",
                    help="Keine CSV-Datei schreiben")
    args = ap.parse_args()

    input_path = Path(args.input)

    print("\n══════════════════════════════════════════════════════════════")
    print("  BA Security Benchmark — Metriken-Berechnung (FF1)")
    print("══════════════════════════════════════════════════════════════")

    if not input_path.exists():
        print(f"  [ERROR] Input nicht gefunden: {input_path}")
        print("  Bitte zuerst: python analysis/match_results.py")
        raise SystemExit(1)

    all_results: List[Dict] = json.loads(input_path.read_text(encoding="utf-8-sig"))
    # Nur vulnerable-shop: Ground Truth existiert nur für dieses Target.
    # Timing für juice-shop wird separat in results_collector.py berücksichtigt.
    all_results = [r for r in all_results if r.get("target") == "vulnerable-shop"]
    print(f"\n  Input: {input_path} ({len(all_results)} Einträge, nur vulnerable-shop)")

    # Haupttabelle
    print_metrics_table(all_results)

    # Optional: Detailansicht pro Run
    if args.details:
        print_run_details(all_results)

    # Ausgabe bauen
    output = build_output(all_results)

    # JSON speichern
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(output, indent=2, ensure_ascii=False, default=lambda x: None),
        encoding="utf-8-sig",
    )
    print(f"  Metriken (JSON):  {OUTPUT_JSON}")

    # CSV speichern
    if not args.no_csv:
        write_csv(output, OUTPUT_CSV)
        print(f"  Metriken (CSV):   {OUTPUT_CSV}")

    print(f"\n  Nächster Schritt: python analysis/results_collector.py\n")


if __name__ == "__main__":
    main()
