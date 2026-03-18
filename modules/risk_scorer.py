# modules/risk_scorer.py
#
# Novel Contribution 3 — Dynamic Context-Aware Risk Scoring Engine
#
# Problem solved:
#   Every existing EDR tool assigns a static severity score based solely on
#   the file being scanned. This ignores the host context — whether the machine
#   is currently under attack, what time it is, what other threats are active.
#   The result is alert fatigue: every detection looks equally urgent regardless
#   of circumstances.
#
# What this module does:
#   Computes a composite Dynamic Risk Score (DRS) from 0.0 to 1.0 by combining:
#     1. ML/Cloud verdict weight   — the base probability of maliciousness
#     2. Temporal anomaly weight   — scans at unusual hours score higher
#     3. Active threat context     — concurrent detections amplify individual scores
#     4. Attack chain presence     — if a chain is active, everything scores higher
#     5. Network activity          — active outbound connections increase risk
#     6. Baseline deviation        — unknown processes in baseline score higher
#
#   The DRS replaces the raw ML score for display and prioritization purposes.
#   It does NOT change the binary verdict — SAFE stays SAFE even with a high DRS.
#   It answers: "How urgent is this alert right now, on this machine, at this moment?"
#
# Academic grounding:
#   Prioritization-based alert triage is documented in:
#   Axelsson, S. (2000). The base-rate fallacy and the difficulty of intrusion
#   detection. ACM Transactions on Information and System Security, 3(3), 186-205.

import os
import sqlite3
import datetime
import json

from . import utils
from . import colors

# ─────────────────────────────────────────────────────────────────────────────
#  SCORING WEIGHTS
#
#  All weights sum to 1.0. Each component contributes proportionally.
#  Weights were chosen conservatively — no single non-verdict factor
#  can override a SAFE verdict into a CRITICAL classification.
# ─────────────────────────────────────────────────────────────────────────────

WEIGHTS = {
    "verdict":          0.45,   # ML/cloud probability is the dominant signal
    "temporal":         0.10,   # Time-of-day anomaly
    "active_threats":   0.15,   # Other concurrent detections on this machine
    "chain_active":     0.15,   # Attack chain currently firing
    "network_activity": 0.10,   # Outbound connections from new process
    "baseline_miss":    0.05,   # Process not in behavioral baseline
}

# ─────────────────────────────────────────────────────────────────────────────
#  TEMPORAL RISK PROFILE
#
#  Business hours (8AM–6PM weekdays) = low temporal risk.
#  After hours and weekends = elevated temporal risk.
#  Rationale: Legitimate software installations happen during business hours.
#  Malware typically executes during off-hours to avoid analyst detection.
# ─────────────────────────────────────────────────────────────────────────────

def _temporal_risk_score(dt: datetime.datetime) -> float:
    """
    Returns a temporal anomaly score from 0.0 to 1.0.

    Business hours (Mon-Fri, 08:00-18:00) return 0.1 (low anomaly).
    Nights and weekends return progressively higher scores up to 1.0.
    """
    hour    = dt.hour
    weekday = dt.weekday()   # 0=Monday, 6=Sunday

    # Weekend — any hour
    if weekday >= 5:
        return 0.8

    # Weekday business hours (08:00–18:00)
    if 8 <= hour < 18:
        return 0.1

    # Early morning (00:00–06:00) — highest anomaly
    if 0 <= hour < 6:
        return 1.0

    # Evening (18:00–22:00)
    if 18 <= hour < 22:
        return 0.6

    # Late night (22:00–00:00)
    return 0.9


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_RISK_TABLE = """
CREATE TABLE IF NOT EXISTS risk_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL,
    filename        TEXT,
    base_verdict    TEXT,
    base_score      REAL,
    dynamic_score   REAL,
    risk_level      TEXT,
    components      TEXT,   -- JSON breakdown of each weight component
    timestamp       TEXT    NOT NULL
)
"""


def _ensure_table():
    """Creates the risk_scores table if it does not exist."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_RISK_TABLE)
    except sqlite3.Error as e:
        print(f"[-] RiskScorer: Table creation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DynamicRiskScorer:
    """
    Computes a context-aware Dynamic Risk Score (DRS) for every detected threat.

    The DRS combines the file's inherent maliciousness probability with real-time
    host context signals to produce a prioritized urgency score. Analysts can use
    the DRS to triage which alerts require immediate attention versus which can
    wait for the next shift.
    """

    def __init__(self):
        _ensure_table()

    def compute(
        self,
        sha256:          str,
        filename:        str,
        verdict:         str,
        base_score:      float,
        file_path:       str = "",
        scan_time:       datetime.datetime = None,
    ) -> dict:
        """
        Computes the Dynamic Risk Score for a scan result.

        Arguments:
            sha256       SHA-256 of the scanned file
            filename     Basename of the scanned file
            verdict      Classification verdict string
            base_score   Raw ML probability or 1.0 for confirmed cloud detections
            file_path    Full path (used for baseline check)
            scan_time    Datetime of scan (defaults to now)

        Returns a dict with keys:
            dynamic_score  float [0.0, 1.0] — composite risk score
            risk_level     str — CRITICAL / HIGH / MEDIUM / LOW
            components     dict — per-component scores for transparency
            narrative      str — plain-English explanation of the score
        """
        if scan_time is None:
            scan_time = datetime.datetime.now()

        # ── Component 1: Verdict weight ───────────────────────────────────────
        # Normalize verdict to a 0.0–1.0 score
        verdict_upper = verdict.upper()
        if "CRITICAL" in verdict_upper or "MALICIOUS" in verdict_upper:
            verdict_score = min(1.0, base_score if base_score > 0 else 1.0)
        elif "SUSPICIOUS" in verdict_upper:
            verdict_score = min(0.7, base_score)
        else:
            verdict_score = max(0.0, base_score)

        # ── Component 2: Temporal anomaly ─────────────────────────────────────
        temporal_score = _temporal_risk_score(scan_time)

        # ── Component 3: Active threat context ───────────────────────────────
        # Count other MALICIOUS verdicts in the last 60 minutes
        active_threats = self._count_recent_malicious(minutes=60)
        # Normalize: 0 threats=0.0, 1=0.3, 3+=1.0
        active_score = min(1.0, active_threats * 0.33)

        # ── Component 4: Attack chain presence ───────────────────────────────
        chain_score = 1.0 if self._has_active_chain(minutes=10) else 0.0

        # ── Component 5: Network activity ─────────────────────────────────────
        network_score = self._check_network_activity(file_path)

        # ── Component 6: Baseline deviation ──────────────────────────────────
        baseline_score = self._check_baseline_miss(sha256)

        # ── Composite DRS ─────────────────────────────────────────────────────
        components = {
            "verdict":          round(verdict_score   * WEIGHTS["verdict"],          4),
            "temporal":         round(temporal_score  * WEIGHTS["temporal"],         4),
            "active_threats":   round(active_score    * WEIGHTS["active_threats"],   4),
            "chain_active":     round(chain_score     * WEIGHTS["chain_active"],     4),
            "network_activity": round(network_score   * WEIGHTS["network_activity"], 4),
            "baseline_miss":    round(baseline_score  * WEIGHTS["baseline_miss"],    4),
        }

        dynamic_score = round(sum(components.values()), 4)
        dynamic_score = min(1.0, dynamic_score)   # Cap at 1.0

        # ── Risk level classification ─────────────────────────────────────────
        if dynamic_score >= 0.75:
            risk_level = "CRITICAL"
        elif dynamic_score >= 0.55:
            risk_level = "HIGH"
        elif dynamic_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        narrative = self._build_narrative(
            verdict, dynamic_score, risk_level, components,
            scan_time, active_threats
        )

        result = {
            "dynamic_score": dynamic_score,
            "risk_level":    risk_level,
            "components":    components,
            "narrative":     narrative,
        }

        # Persist to database
        self._persist(sha256, filename, verdict, base_score, dynamic_score,
                      risk_level, components)

        return result

    # ── Context signal collectors ─────────────────────────────────────────────

    def _count_recent_malicious(self, minutes: int = 60) -> int:
        """
        Counts MALICIOUS verdicts in the scan cache from the last N minutes.
        Represents concurrent threat activity on this host.
        """
        try:
            cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=minutes)
                      ).strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    """
                    SELECT COUNT(*) FROM scan_cache
                    WHERE (verdict LIKE '%MALICIOUS%' OR verdict LIKE '%CRITICAL%')
                      AND timestamp >= ?
                    """,
                    (cutoff,)
                ).fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def _has_active_chain(self, minutes: int = 10) -> bool:
        """
        Returns True if an attack chain alert fired within the last N minutes.
        A chain in progress dramatically elevates the risk of any new detection.
        """
        try:
            cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=minutes)
                      ).strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM chain_alerts WHERE timestamp >= ?",
                    (cutoff,)
                ).fetchone()
            return (row[0] if row else 0) > 0
        except Exception:
            return False

    def _check_network_activity(self, file_path: str) -> float:
        """
        Returns 1.0 if the process has active outbound connections, 0.0 otherwise.
        Requires psutil and only works on actively-running processes.
        """
        if not file_path or not os.path.isfile(file_path):
            return 0.0
        try:
            import psutil
            for proc in psutil.process_iter(["exe", "connections"]):
                try:
                    if proc.info["exe"] == file_path:
                        conns = proc.net_connections(kind="inet")
                        if any(c.status == "ESTABLISHED" for c in conns):
                            return 1.0
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception:
            pass
        return 0.0

    def _check_baseline_miss(self, sha256: str) -> float:
        """
        Returns 1.0 if the file is not in the behavioral baseline profile,
        0.0 if it is a known process. Unknown processes score higher.
        """
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT seen_count FROM baseline_profiles WHERE sha256 = ?",
                    (sha256,)
                ).fetchone()
            # Not in baseline at all = 1.0, seen rarely = 0.5, well-known = 0.0
            if not row:
                return 1.0
            seen = row[0]
            if seen >= 10:
                return 0.0
            return max(0.0, 1.0 - (seen / 10.0))
        except Exception:
            return 0.5   # Unknown state — moderate score

    # ── Narrative builder ─────────────────────────────────────────────────────

    def _build_narrative(
        self,
        verdict: str,
        dynamic_score: float,
        risk_level: str,
        components: dict,
        scan_time: datetime.datetime,
        active_threats: int,
    ) -> str:
        """Builds a plain-English explanation of why the DRS is what it is."""
        lines = [
            f"Dynamic Risk Score: {dynamic_score:.2f} / 1.00 — {risk_level}",
            "Contributing factors:",
        ]

        # Verdict contribution
        v_contrib = components["verdict"]
        lines.append(f"  • Verdict maliciousness:    {v_contrib:.3f} (weight 45%)")

        # Temporal
        t_contrib = components["temporal"]
        hour = scan_time.hour
        day  = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][scan_time.weekday()]
        lines.append(
            f"  • Time-of-day anomaly:      {t_contrib:.3f} "
            f"(scanned at {hour:02d}:00 on {day})"
        )

        # Active threats
        a_contrib = components["active_threats"]
        lines.append(
            f"  • Concurrent threat count:  {a_contrib:.3f} "
            f"({active_threats} MALICIOUS verdict(s) in last 60 min)"
        )

        # Chain
        c_contrib = components["chain_active"]
        chain_str = "YES — attack chain active" if c_contrib > 0 else "No active chains"
        lines.append(f"  • Attack chain presence:    {c_contrib:.3f} ({chain_str})")

        # Network
        n_contrib = components["network_activity"]
        net_str = "Active outbound connections detected" if n_contrib > 0 else "No active connections"
        lines.append(f"  • Network activity:         {n_contrib:.3f} ({net_str})")

        # Baseline
        b_contrib = components["baseline_miss"]
        base_str = "Not in baseline profile" if b_contrib > 0.5 else "Known process"
        lines.append(f"  • Baseline deviation:       {b_contrib:.3f} ({base_str})")

        return "\n".join(lines)

    # ── Database operations ───────────────────────────────────────────────────

    def _persist(
        self,
        sha256: str,
        filename: str,
        verdict: str,
        base_score: float,
        dynamic_score: float,
        risk_level: str,
        components: dict,
    ):
        """Stores the computed DRS to the database."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO risk_scores
                        (sha256, filename, base_verdict, base_score,
                         dynamic_score, risk_level, components, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256, filename, verdict, base_score,
                        dynamic_score, risk_level,
                        json.dumps(components), now,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] RiskScorer: Persist failed: {e}")

    def get_recent_scores(self, limit: int = 50) -> list:
        """Returns recent DRS records for the GUI display."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT sha256, filename, base_verdict, base_score,
                           dynamic_score, risk_level, components, timestamp
                    FROM   risk_scores
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [
                {
                    "sha256":        r[0],
                    "filename":      r[1],
                    "base_verdict":  r[2],
                    "base_score":    r[3],
                    "dynamic_score": r[4],
                    "risk_level":    r[5],
                    "components":    json.loads(r[6]),
                    "timestamp":     r[7],
                }
                for r in rows
            ]
        except Exception:
            return []

    def get_risk_trend(self, hours: int = 24) -> list:
        """
        Returns hourly average DRS for trend visualization in the GUI.
        Used to show whether the host's overall risk level is increasing or decreasing.
        """
        try:
            cutoff = (datetime.datetime.now() - datetime.timedelta(hours=hours)
                      ).strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                           AVG(dynamic_score) as avg_score,
                           COUNT(*) as scan_count
                    FROM   risk_scores
                    WHERE  timestamp >= ?
                    GROUP BY hour
                    ORDER BY hour ASC
                    """,
                    (cutoff,)
                ).fetchall()
            return [
                {"hour": r[0], "avg_score": round(r[1], 3), "scan_count": r[2]}
                for r in rows
            ]
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_instance: DynamicRiskScorer | None = None


def get_risk_scorer() -> DynamicRiskScorer:
    """Returns the module-level DynamicRiskScorer singleton."""
    global _instance
    if _instance is None:
        _instance = DynamicRiskScorer()
    return _instance
