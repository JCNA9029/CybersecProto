# eval_harness.py — CyberSentinel Quantitative Evaluation Engine
#
# Implements the full methodology §3.2.1 / §3.5.2 / §3.6 quantitative pipeline:
#
#   ┌─────────────────────────────────────────────────────────────────────┐
#   │  1. Persistent SQLite score retention  (v2_predictions.db)         │
#   │  2. Fault-tolerant execution loop      (try/except, error logging)  │
#   │  3. Temporal stratification            (Pre-2020 / Post-2020)       │
#   │  4. Stealth/UPX adversarial dataset    (separate subdirectory)      │
#   │  5. Threshold sweep                    (θ = 0.4 → 0.8, step 0.05)  │
#   │  6. Confusion matrix per threshold     (TP/FP/TN/FN)               │
#   │  7. Metrics: Precision, Recall, F1, FPR, FNR, Accuracy             │
#   │  8. Per-sample raw score log           (for post-hoc analysis)      │
#   │  9. Tier 1 cloud consensus evaluation  (optional, --tier1 flag)     │
#   │ 10. JSON + TXT forensic report export                               │
#   └─────────────────────────────────────────────────────────────────────┘
#
# Expected directory structure:
#
#   samples/
#     pre2020/
#       malware/     ← Pre-2020 malicious PE files
#       clean/       ← Pre-2020 benign files (Windows system DLLs, etc.)
#     post2020/
#       malware/     ← Post-2020 malicious PE files
#       clean/       ← Post-2020 benign files
#     stealth/
#       malware/     ← UPX-packed malicious PE files (adversarial set)
#       clean/       ← UPX-packed benign files (optional)
#
# Flat layout also accepted:
#   python eval_harness.py --malware ./mal --clean ./clean
#
# Usage:
#   python eval_harness.py --samples ./samples          (full temporal + stealth)
#   python eval_harness.py --malware ./mal --clean ./ok (flat layout)
#   python eval_harness.py --samples ./samples --tier1  (also benchmark cloud)
#   python eval_harness.py --resume                     (resume interrupted run)

import argparse
import os
import sys
import time
import json
import sqlite3
import datetime
import traceback
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ml_engine import LocalScanner
from modules import utils

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

PRED_DB     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v2_predictions.db")
THRESHOLDS  = [round(t, 2) for t in [x * 0.05 + 0.40 for x in range(9)]]  # 0.40 … 0.80
PE_EXTS     = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}
DEFAULT_θ   = 0.50   # standard operating threshold

# ─────────────────────────────────────────────────────────────────────────────
#  PERSISTENT SCORE DATABASE  (v2_predictions.db)
# ─────────────────────────────────────────────────────────────────────────────

def init_pred_db():
    """
    Creates or verifies the persistent prediction database.
    Stores every raw ML score so metrics can be re-derived at any threshold
    without re-running inference — the 'single-pass synthesis' described in §3.5.2.
    """
    with sqlite3.connect(PRED_DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                sha256      TEXT PRIMARY KEY,
                filename    TEXT,
                raw_score   REAL,
                ground_truth INTEGER,   -- 1 = malicious, 0 = benign
                stratum     TEXT,       -- 'pre2020' | 'post2020' | 'stealth' | 'flat'
                error_msg   TEXT,       -- NULL if scan succeeded
                scan_time_ms REAL,
                scanned_at  TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS eval_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT,
                finished_at TEXT,
                config_json TEXT,
                status      TEXT        -- 'running' | 'complete' | 'interrupted'
            )
        """)


def upsert_prediction(sha256, filename, raw_score, ground_truth, stratum, error_msg, scan_ms):
    """Persist one sample's raw score. Uses INSERT OR REPLACE for idempotency."""
    with sqlite3.connect(PRED_DB) as c:
        c.execute(
            """INSERT OR REPLACE INTO predictions
               (sha256, filename, raw_score, ground_truth, stratum, error_msg, scan_time_ms, scanned_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (sha256, filename, raw_score, ground_truth, stratum,
             error_msg, scan_ms, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )


def load_predictions(stratum: Optional[str] = None) -> list:
    """Load all stored predictions, optionally filtered by stratum."""
    with sqlite3.connect(PRED_DB) as c:
        if stratum:
            rows = c.execute(
                "SELECT sha256, filename, raw_score, ground_truth, stratum, error_msg "
                "FROM predictions WHERE stratum=? AND error_msg IS NULL", (stratum,)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT sha256, filename, raw_score, ground_truth, stratum, error_msg "
                "FROM predictions WHERE error_msg IS NULL"
            ).fetchall()
    return [{"sha256": r[0], "filename": r[1], "raw_score": r[2],
             "ground_truth": r[3], "stratum": r[4]} for r in rows]


def already_scanned(sha256: str) -> bool:
    """Resume support: check if this file was already processed in a previous run."""
    with sqlite3.connect(PRED_DB) as c:
        row = c.execute(
            "SELECT 1 FROM predictions WHERE sha256=?", (sha256,)
        ).fetchone()
    return row is not None


# ─────────────────────────────────────────────────────────────────────────────
#  SCANNING ENGINE  (fault-tolerant, persistent)
# ─────────────────────────────────────────────────────────────────────────────

def scan_directory(
    scanner: LocalScanner,
    directory: str,
    ground_truth: int,       # 1 = malicious, 0 = benign
    stratum: str,
    resume: bool = False,
    progress_cb=None,        # optional callback(filename, score, error)
) -> dict:
    """
    Scans all PE files in a directory.

    - Fault-tolerant: exceptions are caught per-file, logged to DB, and skipped.
    - Resume-aware: files already in v2_predictions.db are skipped if resume=True.
    - Returns summary counts for this directory batch.
    """
    counts = {"scanned": 0, "skipped": 0, "errors": 0}

    files = [
        os.path.join(directory, f)
        for f in sorted(os.listdir(directory))
        if os.path.isfile(os.path.join(directory, f))
        and os.path.splitext(f)[1].lower() in PE_EXTS
    ]

    label = "malicious" if ground_truth == 1 else "benign"
    print(f"\n  [*] {stratum} / {label}: {len(files)} PE files in {directory}")

    for fp in files:
        fname = os.path.basename(fp)
        sha256 = utils.get_sha256(fp)
        if not sha256:
            counts["errors"] += 1
            upsert_prediction(fp, fname, None, ground_truth, stratum,
                              "SHA256 read failed", 0)
            if progress_cb:
                progress_cb(fname, None, "SHA256 read failed")
            continue

        if resume and already_scanned(sha256):
            counts["skipped"] += 1
            continue

        t0 = time.perf_counter()
        try:
            result = scanner.scan_stage1(fp)
            elapsed = (time.perf_counter() - t0) * 1000

            if result is None:
                # Invalid PE / extraction error — logged but not counted as error
                upsert_prediction(sha256, fname, None, ground_truth, stratum,
                                  "ML engine returned None (invalid PE)", elapsed)
                counts["errors"] += 1
                if progress_cb:
                    progress_cb(fname, None, "invalid PE")
            else:
                raw_score = float(result.get("score", 0.0))
                upsert_prediction(sha256, fname, raw_score, ground_truth, stratum, None, elapsed)
                counts["scanned"] += 1
                if progress_cb:
                    progress_cb(fname, raw_score, None)

        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            err_msg = f"{type(e).__name__}: {str(e)[:200]}"
            upsert_prediction(sha256, fname, None, ground_truth, stratum, err_msg, elapsed)
            counts["errors"] += 1
            if progress_cb:
                progress_cb(fname, None, err_msg)

    return counts


# ─────────────────────────────────────────────────────────────────────────────
#  THRESHOLD SWEEP + METRICS
# ─────────────────────────────────────────────────────────────────────────────

def compute_confusion(predictions: list, threshold: float) -> dict:
    """Build confusion matrix for a given decision threshold θ."""
    TP = FP = TN = FN = 0
    fp_files = []
    fn_files = []

    for p in predictions:
        score    = p["raw_score"]
        label    = p["ground_truth"]
        detected = score >= threshold

        if label == 1 and detected:
            TP += 1
        elif label == 1 and not detected:
            FN += 1
            fn_files.append(f"{p['filename']} (score={score:.4f})")
        elif label == 0 and detected:
            FP += 1
            fp_files.append(f"{p['filename']} (score={score:.4f})")
        else:
            TN += 1

    total = TP + FP + TN + FN
    precision = TP / (TP + FP)  if (TP + FP)  > 0 else 0.0
    recall    = TP / (TP + FN)  if (TP + FN)  > 0 else 0.0   # Detection Rate
    fpr       = FP / (FP + TN)  if (FP + TN)  > 0 else 0.0
    fnr       = FN / (FN + TP)  if (FN + TP)  > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy  = (TP + TN) / total if total > 0 else 0.0

    return {
        "threshold":    threshold,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "total":        total,
        "precision":    round(precision, 4),
        "recall":       round(recall,    4),
        "f1_score":     round(f1,        4),
        "fpr":          round(fpr,       4),
        "fnr":          round(fnr,       4),
        "accuracy":     round(accuracy,  4),
        "fp_files":     fp_files,
        "fn_files":     fn_files,
    }


def sweep_thresholds(predictions: list) -> list:
    """
    Runs compute_confusion across all thresholds in THRESHOLDS list.
    Returns list of metric dicts sorted by threshold.
    """
    return [compute_confusion(predictions, θ) for θ in THRESHOLDS]


def best_threshold(sweep: list, metric: str = "f1_score") -> dict:
    """Returns the sweep row with the highest value for the given metric."""
    return max(sweep, key=lambda r: r[metric])


# ─────────────────────────────────────────────────────────────────────────────
#  TIER 1 CLOUD EVALUATION
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_tier1(directories: list, logic) -> dict:
    """
    Evaluates Tier 1 cloud consensus against labelled file hashes.
    directories: list of (path, ground_truth_int, stratum_label)
    """
    records = []

    for dirpath, ground_truth, stratum in directories:
        if not os.path.isdir(dirpath):
            continue
        label = "malicious" if ground_truth == 1 else "benign"
        print(f"\n  [*] Tier 1 — {stratum}/{label}: {dirpath}")

        for f in sorted(os.listdir(dirpath)):
            fp = os.path.join(dirpath, f)
            if not os.path.isfile(fp):
                continue
            sha = utils.get_sha256(fp)
            if not sha:
                continue
            t0 = time.perf_counter()
            try:
                result  = logic._run_tier1_concurrent(sha)
                elapsed = (time.perf_counter() - t0) * 1000
                detected = (result.get("verdict") == "MALICIOUS")
                records.append({
                    "filename":     f,
                    "sha256":       sha,
                    "ground_truth": ground_truth,
                    "detected":     detected,
                    "stratum":      stratum,
                    "elapsed_ms":   elapsed,
                })
            except Exception as e:
                print(f"    [-] Error on {f}: {e}")

    TP = sum(1 for r in records if r["ground_truth"] == 1 and r["detected"])
    FP = sum(1 for r in records if r["ground_truth"] == 0 and r["detected"])
    TN = sum(1 for r in records if r["ground_truth"] == 0 and not r["detected"])
    FN = sum(1 for r in records if r["ground_truth"] == 1 and not r["detected"])
    total = TP + FP + TN + FN

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    fnr       = FN / (FN + TP) if (FN + TP) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy  = (TP + TN) / total if total > 0 else 0.0
    avg_ms    = sum(r["elapsed_ms"] for r in records) / len(records) if records else 0.0

    return {
        "total":      total,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "precision":  round(precision, 4),
        "recall":     round(recall,    4),
        "f1_score":   round(f1,        4),
        "fpr":        round(fpr,       4),
        "fnr":        round(fnr,       4),
        "accuracy":   round(accuracy,  4),
        "avg_latency_ms": round(avg_ms, 2),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  REPORT FORMATTING
# ─────────────────────────────────────────────────────────────────────────────

def _bar(value: float, width: int = 30) -> str:
    """Renders a simple ASCII progress bar for a 0-1 metric."""
    filled = round(value * width)
    return "[" + "█" * filled + "░" * (width - filled) + f"] {value:.2%}"


def print_sweep_table(sweep: list, highlight_θ: float = DEFAULT_θ):
    """Prints the full threshold sweep as an aligned table."""
    print(f"\n{'─'*80}")
    print(f"  {'θ':>5}  {'Prec':>6}  {'Recall':>7}  {'F1':>6}  {'FPR':>6}  {'FNR':>6}  "
          f"{'Acc':>6}  {'TP':>5}  {'FP':>5}  {'TN':>5}  {'FN':>5}")
    print(f"{'─'*80}")
    for r in sweep:
        marker = " ◄" if abs(r["threshold"] - highlight_θ) < 0.001 else ""
        print(
            f"  {r['threshold']:>5.2f}  "
            f"{r['precision']:>6.2%}  {r['recall']:>7.2%}  {r['f1_score']:>6.4f}  "
            f"{r['fpr']:>6.2%}  {r['fnr']:>6.2%}  {r['accuracy']:>6.2%}  "
            f"{r['TP']:>5}  {r['FP']:>5}  {r['TN']:>5}  {r['FN']:>5}{marker}"
        )
    print(f"{'─'*80}")


def print_metrics_block(title: str, m: dict, fp_files=None, fn_files=None):
    """Prints a formatted metrics block for a single threshold."""
    print(f"\n{'='*64}")
    print(f"  CYBERSENTINEL EVALUATION — {title}")
    print(f"{'='*64}")
    print(f"  Total Samples    : {m.get('total', m.get('TP',0)+m.get('FP',0)+m.get('TN',0)+m.get('FN',0))}")
    print(f"  True Positives   : {m['TP']}")
    print(f"  False Positives  : {m['FP']}")
    print(f"  True Negatives   : {m['TN']}")
    print(f"  False Negatives  : {m['FN']}")
    print(f"{'─'*64}")
    print(f"  Precision   {_bar(m['precision'])}")
    print(f"  Recall (DR) {_bar(m['recall'])}")
    print(f"  F1 Score         : {m['f1_score']:.4f}")
    print(f"  Accuracy    {_bar(m['accuracy'])}")
    print(f"  FPR              : {m['fpr']:.2%}  (alert fatigue risk)")
    print(f"  FNR              : {m['fnr']:.2%}  (missed malware risk)")
    if "avg_latency_ms" in m:
        print(f"  Avg Latency/file : {m['avg_latency_ms']:.1f} ms")
    print(f"{'='*64}")

    if fp_files:
        print(f"\n  ⚠  False Positives — clean files incorrectly flagged:")
        for f in fp_files[:15]:
            print(f"       ✗  {f}")
        if len(fp_files) > 15:
            print(f"       ... and {len(fp_files)-15} more")

    if fn_files:
        print(f"\n  ⚠  False Negatives — malware that evaded detection:")
        for f in fn_files[:15]:
            print(f"       ✗  {f}")
        if len(fn_files) > 15:
            print(f"       ... and {len(fn_files)-15} more")


def save_reports(report: dict, base_path: str = "eval_report"):
    """Saves JSON and human-readable TXT forensic reports."""
    json_path = base_path + ".json"
    txt_path  = base_path + ".txt"

    # JSON
    try:
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  [+] JSON report saved : {os.path.abspath(json_path)}")
    except Exception as e:
        print(f"  [-] JSON save failed  : {e}")

    # Human-readable TXT
    try:
        lines = [
            "=" * 70,
            " CYBERSENTINEL v2 — QUANTITATIVE EVALUATION REPORT",
            f" Generated : {report.get('generated', 'N/A')}",
            f" Pred DB   : {PRED_DB}",
            "=" * 70,
        ]
        for stratum, data in report.get("strata", {}).items():
            m = data.get("metrics_at_default_theta", {})
            lines += [
                f"\n  [{stratum.upper()}]",
                f"  Precision: {m.get('precision',0):.2%}  Recall: {m.get('recall',0):.2%}  "
                f"F1: {m.get('f1_score',0):.4f}  FPR: {m.get('fpr',0):.2%}  "
                f"FNR: {m.get('fnr',0):.2%}",
            ]
        if "tier1" in report:
            t1 = report["tier1"]
            lines += [
                "\n  [TIER 1 — CLOUD CONSENSUS]",
                f"  Precision: {t1.get('precision',0):.2%}  Recall: {t1.get('recall',0):.2%}  "
                f"F1: {t1.get('f1_score',0):.4f}  FPR: {t1.get('fpr',0):.2%}",
            ]
        lines += ["", "=" * 70, " END OF REPORT", "=" * 70]
        with open(txt_path, "w") as f:
            f.write("\n".join(lines))
        print(f"  [+] TXT report saved  : {os.path.abspath(txt_path)}")
    except Exception as e:
        print(f"  [-] TXT save failed   : {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  DATASET DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def discover_strata(samples_root: str) -> dict:
    """
    Discovers the temporal + stealth dataset layout under samples_root.
    Returns: { stratum_name: {"malware": path, "clean": path} }

    Expected layout:
        samples/pre2020/malware/  samples/pre2020/clean/
        samples/post2020/malware/ samples/post2020/clean/
        samples/stealth/malware/  samples/stealth/clean/  (optional)

    Falls back to flat layout (samples/malware, samples/clean) if temporal
    subdirectories are not found.
    """
    strata = {}
    for name in ("pre2020", "post2020", "stealth"):
        mal  = os.path.join(samples_root, name, "malware")
        cln  = os.path.join(samples_root, name, "clean")
        if os.path.isdir(mal) or os.path.isdir(cln):
            strata[name] = {
                "malware": mal if os.path.isdir(mal) else None,
                "clean":   cln if os.path.isdir(cln) else None,
            }
    if not strata:
        # Flat layout
        mal = os.path.join(samples_root, "malware")
        cln = os.path.join(samples_root, "clean")
        if os.path.isdir(mal) or os.path.isdir(cln):
            strata["flat"] = {
                "malware": mal if os.path.isdir(mal) else None,
                "clean":   cln if os.path.isdir(cln) else None,
            }
    return strata


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────

def run_evaluation(args) -> dict:
    """
    Full evaluation pipeline. Returns the complete report dict.
    This function is called both from CLI (main) and from the GUI page.
    """
    init_pred_db()
    scanner   = LocalScanner()
    utils.init_db()
    report    = {
        "generated":    datetime.datetime.now().isoformat(),
        "pred_db":      PRED_DB,
        "strata":       {},
        "combined":     {},
    }

    # ── Discover dataset layout ───────────────────────────────────────────────
    if args.samples:
        strata = discover_strata(args.samples)
        if not strata:
            print(f"[-] No recognised dataset layout found in: {args.samples}")
            print("    Expected: samples/pre2020/malware, samples/post2020/malware, etc.")
            return report
    else:
        strata = {"flat": {"malware": args.malware, "clean": args.clean}}

    print(f"\n{'='*64}")
    print(f"  CYBERSENTINEL — EVALUATION HARNESS")
    print(f"  Threshold sweep : {THRESHOLDS[0]:.2f} → {THRESHOLDS[-1]:.2f} (step 0.05)")
    print(f"  Default θ       : {DEFAULT_θ:.2f}")
    print(f"  Resume mode     : {'ON' if args.resume else 'OFF'}")
    print(f"  Strata found    : {', '.join(strata.keys())}")
    print(f"{'='*64}")

    # ── Scan each stratum ─────────────────────────────────────────────────────
    all_predictions = []

    for stratum, paths in strata.items():
        print(f"\n  ── Stratum: {stratum.upper()} ──")
        stratum_counts = {"scanned": 0, "skipped": 0, "errors": 0}

        if paths.get("malware"):
            c = scan_directory(scanner, paths["malware"], ground_truth=1,
                               stratum=stratum, resume=args.resume,
                               progress_cb=lambda n, s, e: _cli_progress(n, s, e))
            for k in stratum_counts:
                stratum_counts[k] += c[k]

        if paths.get("clean"):
            c = scan_directory(scanner, paths["clean"], ground_truth=0,
                               stratum=stratum, resume=args.resume,
                               progress_cb=lambda n, s, e: _cli_progress(n, s, e))
            for k in stratum_counts:
                stratum_counts[k] += c[k]

        print(f"\n  {stratum}: {stratum_counts['scanned']} scanned, "
              f"{stratum_counts['skipped']} resumed/skipped, "
              f"{stratum_counts['errors']} errors")

        # Load this stratum's predictions and compute metrics
        preds = load_predictions(stratum)
        if not preds:
            print(f"  [!] No valid predictions for stratum '{stratum}' — skipping metrics.")
            continue

        all_predictions.extend(preds)

        # Threshold sweep for this stratum
        sweep = sweep_thresholds(preds)
        best  = best_threshold(sweep, "f1_score")
        at_default = compute_confusion(preds, DEFAULT_θ)

        print_metrics_block(
            f"TIER 2 — {stratum.upper()} (θ={DEFAULT_θ:.2f})",
            at_default,
            at_default["fp_files"],
            at_default["fn_files"]
        )
        print(f"\n  Threshold sweep for {stratum}:")
        print_sweep_table(sweep, highlight_θ=DEFAULT_θ)
        print(f"\n  Best threshold by F1: θ={best['threshold']:.2f}  "
              f"(F1={best['f1_score']:.4f}, Prec={best['precision']:.2%}, "
              f"Recall={best['recall']:.2%})")

        report["strata"][stratum] = {
            "sample_counts":            stratum_counts,
            "metrics_at_default_theta": {k: v for k, v in at_default.items()
                                         if k not in ("fp_files", "fn_files")},
            "best_threshold":           {k: v for k, v in best.items()
                                         if k not in ("fp_files", "fn_files")},
            "threshold_sweep":          [{k: v for k, v in r.items()
                                          if k not in ("fp_files", "fn_files")}
                                         for r in sweep],
        }

    # ── Combined metrics (all strata together) ────────────────────────────────
    if all_predictions:
        print(f"\n{'─'*64}")
        print(f"  COMBINED METRICS (all strata, N={len(all_predictions)})")
        combined_sweep   = sweep_thresholds(all_predictions)
        combined_default = compute_confusion(all_predictions, DEFAULT_θ)
        combined_best    = best_threshold(combined_sweep, "f1_score")
        avg_ms = 0.0
        try:
            with sqlite3.connect(PRED_DB) as c:
                row = c.execute("SELECT AVG(scan_time_ms) FROM predictions WHERE error_msg IS NULL").fetchone()
                avg_ms = row[0] or 0.0
        except Exception:
            pass

        combined_default["avg_latency_ms"] = round(avg_ms, 2)
        print_metrics_block(
            f"TIER 2 COMBINED (θ={DEFAULT_θ:.2f})",
            combined_default,
            combined_default["fp_files"],
            combined_default["fn_files"]
        )
        print(f"\n  Full combined threshold sweep:")
        print_sweep_table(combined_sweep, highlight_θ=DEFAULT_θ)
        print(f"\n  Optimal threshold by F1: θ={combined_best['threshold']:.2f}  "
              f"(F1={combined_best['f1_score']:.4f})")

        report["combined"] = {
            "total_samples":            len(all_predictions),
            "metrics_at_default_theta": {k: v for k, v in combined_default.items()
                                         if k not in ("fp_files", "fn_files")},
            "best_threshold":           {k: v for k, v in combined_best.items()
                                         if k not in ("fp_files", "fn_files")},
            "threshold_sweep":          [{k: v for k, v in r.items()
                                          if k not in ("fp_files", "fn_files")}
                                         for r in combined_sweep],
            "avg_latency_ms":           round(avg_ms, 2),
        }

    # ── Tier 1 cloud (optional) ───────────────────────────────────────────────
    if getattr(args, "tier1", False):
        print(f"\n{'─'*64}")
        print("  TIER 1 — CLOUD CONSENSUS EVALUATION")
        try:
            from modules.analysis_manager import ScannerLogic
            logic = ScannerLogic()
            if not logic.api_keys:
                print("  [!] No API keys configured — Tier 1 skipped.")
            else:
                dirs = []
                for stratum, paths in strata.items():
                    if paths.get("malware"):
                        dirs.append((paths["malware"], 1, stratum))
                    if paths.get("clean"):
                        dirs.append((paths["clean"], 0, stratum))
                t1_metrics = evaluate_tier1(dirs, logic)
                print_metrics_block("TIER 1 — CLOUD CONSENSUS", t1_metrics)
                report["tier1"] = t1_metrics
        except Exception as e:
            print(f"  [-] Tier 1 evaluation error: {e}")

    return report


def _cli_progress(filename: str, score, error: Optional[str]):
    """Minimal per-file progress indicator for CLI mode."""
    if error:
        print(f"    [ERR] {filename[:55]:<55}  {error[:40]}")
    else:
        marker = "MALICIOUS" if score >= DEFAULT_θ else "safe     "
        print(f"    [{marker}] {filename[:55]:<55}  score={score:.4f}")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Entry point for the ML benchmarking harness — runs batch evaluation on the dataset."""
    parser = argparse.ArgumentParser(
        description="CyberSentinel v1 — Quantitative Evaluation Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full temporal + stealth evaluation:
  python eval_harness.py --samples ./samples

  # Flat layout (no temporal split):
  python eval_harness.py --malware ./mal --clean ./clean

  # Also benchmark Tier 1 cloud:
  python eval_harness.py --samples ./samples --tier1

  # Resume an interrupted run (skips already-scanned files):
  python eval_harness.py --samples ./samples --resume

  # Re-derive metrics from existing scores (no re-scanning):
  python eval_harness.py --metrics-only
        """
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--samples",      metavar="DIR",
                       help="Root of temporal dataset (pre2020/post2020/stealth subdirs).")
    group.add_argument("--malware",      metavar="DIR",
                       help="Directory of known-malicious PE files (flat layout).")
    parser.add_argument("--clean",       metavar="DIR",
                        help="Directory of known-benign PE files (required with --malware).")
    parser.add_argument("--tier1",       action="store_true",
                        help="Also evaluate Tier 1 cloud consensus (requires API keys).")
    parser.add_argument("--resume",      action="store_true",
                        help="Skip files already in v2_predictions.db (resume interrupted run).")
    parser.add_argument("--metrics-only",action="store_true",
                        help="Re-derive metrics from existing v2_predictions.db without re-scanning.")
    parser.add_argument("--output",      default="eval_report",
                        help="Base path for output files (default: eval_report → .json + .txt).")
    args = parser.parse_args()

    # Metrics-only mode: reload DB, re-compute, print, save
    if args.metrics_only:
        init_pred_db()
        preds = load_predictions()
        if not preds:
            print("[-] No predictions in v2_predictions.db. Run a scan first.")
            sys.exit(1)
        sweep   = sweep_thresholds(preds)
        default = compute_confusion(preds, DEFAULT_θ)
        best    = best_threshold(sweep, "f1_score")
        print_metrics_block(f"TIER 2 — ALL STRATA (θ={DEFAULT_θ:.2f})", default,
                            default["fp_files"], default["fn_files"])
        print_sweep_table(sweep, DEFAULT_θ)
        print(f"\n  Best θ by F1: {best['threshold']:.2f}  (F1={best['f1_score']:.4f})")
        save_reports({"generated": datetime.datetime.now().isoformat(),
                      "combined": {"metrics_at_default_theta": default,
                                   "threshold_sweep": sweep}}, args.output)
        return

    if args.malware and not args.clean:
        parser.error("--clean is required when using --malware")
    if not args.samples and not args.malware:
        parser.error("Provide either --samples DIR or --malware DIR --clean DIR")
    if args.malware and not os.path.isdir(args.malware):
        print(f"[-] Malware directory not found: {args.malware}")
        sys.exit(1)
    if args.clean and not os.path.isdir(args.clean):
        print(f"[-] Clean directory not found: {args.clean}")
        sys.exit(1)
    if args.samples and not os.path.isdir(args.samples):
        print(f"[-] Samples directory not found: {args.samples}")
        sys.exit(1)

    report = run_evaluation(args)
    save_reports(report, args.output)


if __name__ == "__main__":
    main()
