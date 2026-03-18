# modules/feedback.py — Analyst Feedback & Self-Correcting Learning Loop
#
# UPGRADE: Now integrated with adaptive_learner.py.
# When an analyst marks FALSE_POSITIVE or FALSE_NEGATIVE, the correction is
# automatically queued for incremental model retraining via AdaptiveLearner.

import sqlite3
import datetime
import os
from . import utils
from . import colors


# ─────────────────────────────────────────────
#  SECTION 1: INTERACTIVE FEEDBACK PROMPT (CLI)
# ─────────────────────────────────────────────

def prompt_analyst_feedback(
    sha256:                   str,
    filename:                 str,
    original_verdict:         str,
    file_path:                str = "",
    prefetched_features_json: str | None = None,
) -> str | None:
    """
    Post-scan review prompt for CLI mode.

    prefetched_features_json: compressed feature vector pre-extracted before
    quarantine ran (Scenario 3 fix). When provided, adaptive learning works
    even if the original file has been quarantined or deleted by this point.

    Returns:
        'CONFIRMED'      — analyst agrees with the verdict
        'FALSE_POSITIVE' — analyst marks it as a false alarm  → queues ML correction
        'FALSE_NEGATIVE' — analyst marks a missed threat      → queues ML correction
        None             — analyst skipped the review
    """
    print("\n" + "─" * 55)
    print(f"  [ANALYST REVIEW]  Verdict was: {original_verdict}")
    print("─" * 55)
    print("  Y  →  Confirm verdict (True Positive)")
    print("  F  →  False Positive (file is safe — add to exclusions + queue ML fix)")
    print("  N  →  False Negative (file IS malicious — queue ML fix)")
    print("  S  →  Skip review")
    print("─" * 55)
    choice = input("  [?] Your review (Y/F/N/S): ").strip().upper()

    if choice not in ("Y", "F", "N"):
        print("  [*] Review skipped.")
        return None

    notes = ""
    if choice == "Y":
        analyst_verdict = "CONFIRMED"
        print("  [+] Verdict confirmed. Logged.")
        _register_anchor(sha256, filename, file_path, original_verdict,
                         prefetched_features_json)

    elif choice == "F":
        analyst_verdict = "FALSE_POSITIVE"
        notes = input("  [?] Reason / notes (optional, Enter to skip): ").strip()
        _add_to_exclusions(filename)
        colors.success(f"  [+] Marked as False Positive. '{filename}' added to exclusion list.")
        _queue_ml_correction(sha256, filename, file_path, "FALSE_POSITIVE",
                             original_verdict, notes, prefetched_features_json)

    else:  # N — False Negative
        analyst_verdict = "FALSE_NEGATIVE"
        notes = input("  [?] Reason / notes (optional, Enter to skip): ").strip()
        colors.warning(f"  [!] Marked as False Negative. Queuing ML correction for '{filename}'.")
        _queue_ml_correction(sha256, filename, file_path, "FALSE_NEGATIVE",
                             original_verdict, notes, prefetched_features_json)

    _save_feedback(sha256, filename, original_verdict, analyst_verdict, notes)
    return analyst_verdict


# ─────────────────────────────────────────────
#  SECTION 2: ML CORRECTION DISPATCHER
# ─────────────────────────────────────────────

def _queue_ml_correction(
    sha256:                   str,
    filename:                 str,
    file_path:                str,
    correction_type:          str,
    original_verdict:         str,
    analyst_notes:            str = "",
    prefetched_features_json: str | None = None,
):
    """
    Dispatches a correction to the AdaptiveLearner queue.

    prefetched_features_json: compressed feature vector captured before
    quarantine ran (Scenario 3 fix). When provided, schedule_correction
    uses it directly instead of attempting to re-read the (now missing) file.
    Wrapped in try/except so a learner failure never crashes the feedback flow.
    """
    try:
        from .adaptive_learner import get_learner
        learner = get_learner()
        learner.schedule_correction(
            sha256=sha256,
            filename=filename,
            file_path=file_path,
            correction_type=correction_type,
            original_verdict=original_verdict,
            analyst_notes=analyst_notes,
            prefetched_features_json=prefetched_features_json,
        )
    except Exception as e:
        colors.warning(f"[!] AdaptiveLearner queue error (non-fatal): {e}")


def _register_anchor(
    sha256:                   str,
    filename:                 str,
    file_path:                str,
    original_verdict:         str,
    prefetched_features_json: str | None = None,
):
    """
    Registers a CONFIRMED verdict as an anchor sample in the adaptive learner.

    prefetched_features_json: compressed feature vector captured before
    quarantine ran (Scenario 3 fix). When provided, register_anchor uses it
    directly so confirmed verdicts work even after the file is quarantined.
    """
    try:
        from .adaptive_learner import get_learner, LABEL_MALICIOUS, LABEL_BENIGN
        verdict_upper = (original_verdict or "").upper()
        if any(v in verdict_upper for v in ("MALICIOUS", "CRITICAL")):
            true_label = LABEL_MALICIOUS
            source     = "CONFIRMED_TP"
        else:
            true_label = LABEL_BENIGN
            source     = "CONFIRMED_SAFE"

        learner = get_learner()
        ok = learner.register_anchor(
            sha256=sha256,
            filename=filename,
            file_path=file_path,
            true_label=true_label,
            source=source,
            prefetched_features_json=prefetched_features_json,
        )
        if ok:
            colors.success(
                f"[+] Anchor registered: '{filename}' "
                f"({'MALICIOUS' if true_label == LABEL_MALICIOUS else 'BENIGN'}) "
                f"— will stabilize future retraining batches."
            )
    except Exception as e:
        colors.warning(f"[!] Anchor registration error (non-fatal): {e}")


def submit_gui_correction(
    sha256:                   str,
    filename:                 str,
    file_path:                str,
    analyst_verdict:          str,   # 'FALSE_POSITIVE' | 'FALSE_NEGATIVE' | 'CONFIRMED'
    original_verdict:         str,
    notes:                    str = "",
    prefetched_features_json: str | None = None,
):
    """
    GUI entry point — called when the analyst submits a review from the
    inline post-scan dialog or the Analyst Feedback page.

    prefetched_features_json: compressed feature vector captured in Step 0.5
    of _prompt_quarantine before the file was quarantined (Scenario 3 fix).
    When provided, adaptive learning works even if the original file is gone.

    CONFIRMED verdicts register as anchors to stabilize future retraining batches.
    FALSE_POSITIVE/NEGATIVE verdicts queue ML corrections for incremental retraining.
    """
    _save_feedback(sha256, filename, original_verdict, analyst_verdict, notes)

    if analyst_verdict in ("FALSE_POSITIVE", "FALSE_NEGATIVE"):
        if analyst_verdict == "FALSE_POSITIVE":
            _add_to_exclusions(filename)
        _queue_ml_correction(
            sha256, filename, file_path,
            analyst_verdict, original_verdict, notes,
            prefetched_features_json,
        )

    elif analyst_verdict == "CONFIRMED":
        _register_anchor(
            sha256, filename, file_path, original_verdict,
            prefetched_features_json,
        )


# ─────────────────────────────────────────────
#  SECTION 3: DATABASE OPERATIONS
# ─────────────────────────────────────────────

def _save_feedback(
    sha256: str,
    filename: str,
    original_verdict: str,
    analyst_verdict: str,
    notes: str,
):
    """Persists analyst feedback to the SQLite analyst_feedback table."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(
                """
                INSERT INTO analyst_feedback
                    (sha256, filename, original_verdict, analyst_verdict, notes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256, filename, original_verdict, analyst_verdict, notes,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
    except sqlite3.Error as e:
        print(f"[-] Feedback save error: {e}")


def save_feedback(
    sha256: str,
    filename: str,
    original_verdict: str,
    analyst_verdict: str,
    notes: str = "",
):
    """Public alias for backward compatibility with analysis_manager."""
    _save_feedback(sha256, filename, original_verdict, analyst_verdict, notes)


def get_feedback_stats() -> dict:
    """Returns aggregate feedback statistics for the dashboard."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            rows = conn.execute(
                "SELECT analyst_verdict, COUNT(*) FROM analyst_feedback GROUP BY analyst_verdict"
            ).fetchall()
            return {row[0]: row[1] for row in rows}
    except sqlite3.Error:
        return {}


def get_all_feedback(limit: int = 100) -> list:
    """Returns recent feedback records for display."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            rows = conn.execute(
                """
                SELECT sha256, filename, original_verdict, analyst_verdict, notes, timestamp
                FROM analyst_feedback
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "sha256":           r[0],
                    "filename":         r[1],
                    "original_verdict": r[2],
                    "analyst_verdict":  r[3],
                    "notes":            r[4],
                    "timestamp":        r[5],
                }
                for r in rows
            ]
    except sqlite3.Error:
        return []


# ─────────────────────────────────────────────
#  SECTION 4: EXCLUSION LIST MANAGEMENT
# ─────────────────────────────────────────────

def _add_to_exclusions(filename: str):
    """
    Appends a filename to exclusions.txt when an analyst marks it as a FP.
    Skips generic or placeholder names that would create overly broad exclusions.
    """
    if not filename or filename in ("Unknown", "Manual Hash", "Fleet Sync"):
        return

    exclusion_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "exclusions.txt"
    )

    if os.path.exists(exclusion_file):
        try:
            with open(exclusion_file, "r") as f:
                if filename.lower() in f.read().lower():
                    return
        except Exception:
            pass  # Non-critical: operation continues regardless

    try:
        with open(exclusion_file, "a") as f:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            f.write(f"\n{filename}  # Auto-added by analyst review on {ts}\n")
    except Exception:
        pass  # Non-critical: operation continues regardless


# ─────────────────────────────────────────────
#  SECTION 5: CLI DISPLAY
# ─────────────────────────────────────────────

def display_feedback_history():
    """Prints a formatted feedback history table to the terminal."""
    records = get_all_feedback(limit=50)
    if not records:
        print("[*] No analyst feedback recorded yet.")
        return

    print("\n" + "=" * 110)
    print(
        f"  {'SHA-256 (Short)':<22}  {'File':<25}  "
        f"{'System Verdict':<17}  {'Analyst':<15}  {'Notes':<20}  Timestamp"
    )
    print("─" * 110)
    for r in records:
        sha_short = (r["sha256"][:20] + "..") if r["sha256"] else "N/A"
        fname     = (r["filename"][:23] + "..") if r["filename"] and len(r["filename"]) > 25 else str(r["filename"])
        notes     = (r["notes"][:18] + "..") if r["notes"] and len(r["notes"]) > 20 else str(r["notes"] or "")
        print(
            f"  {sha_short:<22}  {fname:<25}  "
            f"{r['original_verdict']:<17}  {r['analyst_verdict'] or 'N/A':<15}  "
            f"{notes:<20}  {r['timestamp']}"
        )
    print("=" * 110)

    stats     = get_feedback_stats()
    confirmed = stats.get("CONFIRMED", 0)
    fps       = stats.get("FALSE_POSITIVE", 0)
    fns       = stats.get("FALSE_NEGATIVE", 0)
    total     = confirmed + fps + fns
    fpr       = (fps / total * 100) if total > 0 else 0
    print(
        f"\n  Totals — Confirmed: {confirmed}  |  "
        f"False Positives: {fps}  |  False Negatives: {fns}  |  "
        f"Observed FP Rate: {fpr:.1f}%"
    )

    # Show learning queue status
    try:
        from .adaptive_learner import get_learner
        summary = get_learner().get_queue_summary()
        pending = summary.get("pending_fp", 0) + summary.get("pending_fn", 0)
        trained = summary.get("trained", 0)
        print(f"  Learning Queue — Pending: {pending}  |  Already Trained: {trained}")
    except Exception:
        pass  # Non-critical: operation continues regardless
