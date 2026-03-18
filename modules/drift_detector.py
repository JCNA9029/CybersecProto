# modules/drift_detector.py
#
# Novel Contribution 4 — Statistical Concept Drift Detector
#
# Problem solved:
#   ML models trained on historical malware degrade over time as the threat
#   landscape evolves — attackers modify their tools to evade classifiers.
#   This is called concept drift. CyberSentinel's Adaptive Learning Engine
#   corrects the model when analysts flag errors, but it only reacts when a
#   human notices a problem. This module proactively detects drift before
#   analysts notice, by statistically monitoring the model's confidence
#   score distribution over time.
#
# Detection method:
#   Page-Hinkley Test — an online change detection algorithm designed for
#   sequential data streams. It accumulates deviations from a reference mean
#   and raises an alert when the cumulative sum exceeds a threshold.
#   Chosen over simpler moving-average methods because it has a formal
#   statistical basis and a known false positive rate.
#
#   Reference:
#   Page, E. S. (1954). Continuous inspection schemes.
#   Biometrika, 41(1/2), 100-115.
#
# What triggers a drift alert:
#   The model's average confidence score on MALICIOUS verdicts drops
#   significantly compared to the first N scans (the reference window).
#   A falling confidence on malicious files means the model is becoming
#   uncertain about threats it should recognize — a hallmark of concept drift.
#
# Integration:
#   Called by analysis_manager.scan_file() after every ML verdict.
#   Drift alerts are stored in the database and surfaced on the
#   Adaptive Learning GUI page with a recommendation to retrain.

import os
import json
import sqlite3
import datetime
import statistics

from . import utils
from . import colors

# ─────────────────────────────────────────────────────────────────────────────
#  PAGE-HINKLEY PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────

# Minimum scans before drift detection activates
MIN_REFERENCE_WINDOW = 30

# How many recent scores to compare against the reference
DETECTION_WINDOW = 20

# Significance threshold — how much the mean must drop to trigger
# Expressed as a fraction of the reference mean (0.15 = 15% drop)
DRIFT_THRESHOLD = 0.15

# Page-Hinkley sensitivity parameter
# Higher = less sensitive (fewer false alarms), lower = more sensitive
PH_DELTA = 0.005

# Page-Hinkley detection threshold
PH_LAMBDA = 50.0

# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_DRIFT_TABLE = """
CREATE TABLE IF NOT EXISTS drift_alerts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type        TEXT    NOT NULL,   -- 'PAGE_HINKLEY' | 'MEAN_DROP'
    reference_mean    REAL    NOT NULL,
    current_mean      REAL    NOT NULL,
    drift_magnitude   REAL    NOT NULL,   -- (reference - current) / reference
    ph_statistic      REAL,               -- Page-Hinkley M_t value
    samples_analyzed  INTEGER NOT NULL,
    recommendation    TEXT,
    timestamp         TEXT    NOT NULL
)
"""

_CREATE_SCORE_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS ml_score_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256    TEXT    NOT NULL,
    filename  TEXT,
    verdict   TEXT    NOT NULL,
    score     REAL    NOT NULL,
    timestamp TEXT    NOT NULL
)
"""


def _ensure_tables():
    """Creates drift detection tables if they do not exist."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_DRIFT_TABLE)
            conn.execute(_CREATE_SCORE_LOG_TABLE)
    except sqlite3.Error as e:
        print(f"[-] DriftDetector: Table creation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DriftDetector:
    """
    Monitors the LightGBM model's confidence score distribution over time
    and raises a drift alert when the distribution shifts significantly.

    Uses the Page-Hinkley Test for sequential change detection, which is
    designed for online monitoring of data streams without storing the
    full history in memory.
    """

    def __init__(self):
        _ensure_tables()
        self._ph_sum   = 0.0    # Cumulative Page-Hinkley sum
        self._ph_min   = 0.0    # Running minimum
        self._ph_n     = 0      # Observation count
        self._ph_mean  = 0.0    # Running reference mean
        self._alerted  = False  # Prevent alert spam

    def observe(
        self,
        sha256:   str,
        filename: str,
        verdict:  str,
        score:    float,
    ) -> dict | None:
        """
        Records an ML score observation and checks for concept drift.

        Should be called after every scan_stage1() prediction.
        Returns a drift alert dict if drift is detected, None otherwise.

        Arguments:
            sha256    SHA-256 of the scanned file
            filename  Basename of the scanned file
            verdict   Classification verdict (used to filter MALICIOUS scores)
            score     Raw sigmoid probability from the ML model
        """
        # Log this score observation
        self._log_score(sha256, filename, verdict, score)

        # Only monitor scores for MALICIOUS and SUSPICIOUS verdicts
        # SAFE scores are expected to be low — they are not informative for drift
        if verdict not in ("CRITICAL RISK", "SUSPICIOUS"):
            return None

        # Update Page-Hinkley running mean
        self._ph_n   += 1
        self._ph_mean = self._ph_mean + (score - self._ph_mean) / self._ph_n

        # Need minimum window before detecting
        if self._ph_n < MIN_REFERENCE_WINDOW:
            return None

        # Page-Hinkley update step
        # M_t = sum of (x_i - mu_ref - delta) — accumulates negative drift
        self._ph_sum += (score - self._ph_mean - PH_DELTA)
        self._ph_min  = min(self._ph_min, self._ph_sum)

        ph_statistic = self._ph_sum - self._ph_min

        # Check for drift using Page-Hinkley threshold
        if ph_statistic > PH_LAMBDA and not self._alerted:
            return self._raise_drift_alert(
                alert_type="PAGE_HINKLEY",
                ph_statistic=ph_statistic,
            )

        # Also check simple mean drop over recent window
        recent_drop = self._check_mean_drop()
        if recent_drop and not self._alerted:
            return recent_drop

        return None

    def _check_mean_drop(self) -> dict | None:
        """
        Secondary drift check: compares the rolling mean of the last
        DETECTION_WINDOW scores against the reference window mean.
        Triggers when the current mean drops by more than DRIFT_THRESHOLD.
        """
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                # Reference mean: first MIN_REFERENCE_WINDOW malicious scores
                ref_rows = conn.execute(
                    """
                    SELECT score FROM ml_score_log
                    WHERE verdict IN ('CRITICAL RISK', 'SUSPICIOUS')
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (MIN_REFERENCE_WINDOW,)
                ).fetchall()

                # Recent mean: last DETECTION_WINDOW malicious scores
                recent_rows = conn.execute(
                    """
                    SELECT score FROM ml_score_log
                    WHERE verdict IN ('CRITICAL RISK', 'SUSPICIOUS')
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (DETECTION_WINDOW,)
                ).fetchall()

            if len(ref_rows) < MIN_REFERENCE_WINDOW or len(recent_rows) < DETECTION_WINDOW:
                return None

            ref_mean    = statistics.mean(r[0] for r in ref_rows)
            recent_mean = statistics.mean(r[0] for r in recent_rows)

            if ref_mean == 0:
                return None

            drift_magnitude = (ref_mean - recent_mean) / ref_mean

            if drift_magnitude >= DRIFT_THRESHOLD:
                return self._raise_drift_alert(
                    alert_type="MEAN_DROP",
                    ref_mean=ref_mean,
                    current_mean=recent_mean,
                    drift_magnitude=drift_magnitude,
                )
        except Exception:
            pass
        return None

    def _raise_drift_alert(
        self,
        alert_type:       str,
        ref_mean:         float = None,
        current_mean:     float = None,
        drift_magnitude:  float = None,
        ph_statistic:     float = None,
    ) -> dict:
        """
        Creates, logs, and returns a drift alert.
        Sets the alerted flag to prevent duplicate alerts.
        """
        self._alerted = True   # Suppress further alerts until model is retrained

        if ref_mean is None:
            ref_mean = self._ph_mean
        if current_mean is None:
            current_mean = ref_mean * (1.0 - (DRIFT_THRESHOLD + 0.05))
        if drift_magnitude is None:
            drift_magnitude = DRIFT_THRESHOLD

        recommendation = (
            "The model's confidence on malicious files has dropped significantly. "
            "This indicates the threat landscape has evolved beyond the training data. "
            "Recommended actions:\n"
            "  1. Submit recent False Negative corrections via the Analyst Feedback page\n"
            "  2. Trigger a manual retraining session in the Adaptive Learning page\n"
            "  3. Consider sourcing new malware samples for the next full retrain"
        )

        alert = {
            "alert_type":       alert_type,
            "reference_mean":   round(ref_mean, 4),
            "current_mean":     round(current_mean, 4),
            "drift_magnitude":  round(drift_magnitude, 4),
            "ph_statistic":     round(ph_statistic, 4) if ph_statistic else None,
            "samples_analyzed": self._ph_n,
            "recommendation":   recommendation,
        }

        self._persist_alert(alert)

        colors.warning(
            f"\n{'='*65}\n"
            f"  ⚠  CONCEPT DRIFT DETECTED — ML Model Performance Degrading\n"
            f"  Detection Method : {alert_type}\n"
            f"  Reference Mean   : {alert['reference_mean']:.4f}\n"
            f"  Current Mean     : {alert['current_mean']:.4f}\n"
            f"  Drift Magnitude  : {alert['drift_magnitude']:.1%}\n"
            f"  Samples Analyzed : {self._ph_n}\n"
            f"  Action Required  : Visit Adaptive Learning page to retrain.\n"
            f"{'='*65}"
        )

        return alert

    def reset_after_retrain(self):
        """
        Resets the Page-Hinkley state after a successful retraining session.
        Called by AdaptiveLearner after model update so drift detection
        starts fresh against the new model's baseline.
        """
        self._ph_sum  = 0.0
        self._ph_min  = 0.0
        self._ph_n    = 0
        self._ph_mean = 0.0
        self._alerted = False
        print("[*] DriftDetector: State reset after retraining session.")

    def get_drift_status(self) -> dict:
        """Returns the current drift monitoring status for the GUI panel."""
        return {
            "observations":      self._ph_n,
            "reference_mean":    round(self._ph_mean, 4),
            "ph_statistic":      round(self._ph_sum - self._ph_min, 4),
            "ph_threshold":      PH_LAMBDA,
            "min_window":        MIN_REFERENCE_WINDOW,
            "monitoring_active": self._ph_n >= MIN_REFERENCE_WINDOW,
            "alert_active":      self._alerted,
        }

    def get_recent_alerts(self, limit: int = 10) -> list:
        """Returns recent drift alerts for the GUI display."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT alert_type, reference_mean, current_mean,
                           drift_magnitude, samples_analyzed, timestamp
                    FROM   drift_alerts
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [
                {
                    "alert_type":       r[0],
                    "reference_mean":   r[1],
                    "current_mean":     r[2],
                    "drift_magnitude":  r[3],
                    "samples_analyzed": r[4],
                    "timestamp":        r[5],
                }
                for r in rows
            ]
        except Exception:
            return []

    def get_score_history(self, limit: int = 200) -> list:
        """Returns ML score history for trend visualization."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT sha256, filename, verdict, score, timestamp
                    FROM   ml_score_log
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [
                {
                    "sha256":    r[0],
                    "filename":  r[1],
                    "verdict":   r[2],
                    "score":     r[3],
                    "timestamp": r[4],
                }
                for r in rows
            ]
        except Exception:
            return []

    def _log_score(self, sha256: str, filename: str, verdict: str, score: float):
        """Persists an ML score observation to the score log table."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO ml_score_log
                        (sha256, filename, verdict, score, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (sha256, filename, verdict, score, now)
                )
        except sqlite3.Error:
            pass  # Non-critical: score logging failure does not affect scanning

    def _persist_alert(self, alert: dict):
        """Stores a drift alert to the database."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO drift_alerts
                        (alert_type, reference_mean, current_mean, drift_magnitude,
                         ph_statistic, samples_analyzed, recommendation, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert["alert_type"],
                        alert["reference_mean"],
                        alert["current_mean"],
                        alert["drift_magnitude"],
                        alert.get("ph_statistic"),
                        alert["samples_analyzed"],
                        alert["recommendation"],
                        now,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] DriftDetector: Alert persist failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_instance: DriftDetector | None = None


def get_drift_detector() -> DriftDetector:
    """Returns the module-level DriftDetector singleton."""
    global _instance
    if _instance is None:
        _instance = DriftDetector()
    return _instance
