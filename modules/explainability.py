# modules/explainability.py
#
# Novel Contribution 2 — SHAP-Based ML Explainability Engine
#
# Provides mathematically rigorous, per-scan feature attribution for every
# LightGBM verdict using SHAP (SHapley Additive exPlanations).
#
# Problem solved:
#   LightGBM outputs a probability score (e.g. 0.87) but cannot tell the analyst
#   which specific file characteristics drove that decision. This is the
#   "black box" problem. SHAP solves it by computing each feature's individual
#   contribution to the final score using cooperative game theory (Shapley values).
#
# Academic grounding:
#   Lundberg, S. M., & Lee, S. I. (2017). A unified approach to interpreting model
#   predictions. Advances in Neural Information Processing Systems, 30.
#
# Output:
#   A ranked list of the top N features that most influenced the verdict,
#   with human-readable labels mapped from EMBER2024 feature group definitions.
#
# Design note:
#   Feature count is determined dynamically from the SHAP output rather than
#   hardcoded. Different thrember versions may produce different feature
#   dimensions (2381, 2568, etc.). The label map and group ranges scale
#   proportionally so the explanation is always valid regardless of version.

import os
import json
import sqlite3
import datetime
import warnings
import numpy as np

from . import utils
from . import colors

# ─────────────────────────────────────────────────────────────────────────────
#  SHAP availability guard
# ─────────────────────────────────────────────────────────────────────────────

try:
    import shap as _shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  DYNAMIC FEATURE LABEL BUILDER
#
#  Generates human-readable labels for any feature vector length.
#  The EMBER2024 feature groups are reproduced proportionally so the
#  explanation is meaningful regardless of which thrember version is installed.
#
#  Known dimensions:
#    thrember 0.x  →  2381 features  (original EMBER2024)
#    thrember 1.x  →  2568 features  (extended with DataDirectories group)
# ─────────────────────────────────────────────────────────────────────────────

def _build_feature_labels(n_features: int) -> list[str]:
    """
    Generates human-readable feature labels for a feature vector of length n_features.
    Labels are built from EMBER2024 group definitions and padded/truncated to match
    the actual feature count produced by the installed thrember version.
    """
    labels = []

    # Group 1: Byte Histogram (256 features — always present)
    for i in range(256):
        labels.append(f"Byte frequency 0x{i:02X}")

    # Group 2: Byte Entropy Histogram (256 features — always present)
    for i in range(256):
        labels.append(f"Entropy bucket {i} (local byte entropy)")

    # Group 3: String Features (~104 features)
    for i in range(96):
        labels.append(f"String count (length {i+1})")
    labels += [
        "URL strings count", "Registry path strings count",
        "File path strings count", "MZ-header strings count",
        "Average string length", "Printable char ratio",
        "IP address strings count", "Crypto address strings count",
    ]

    # Group 4: General File Info (~10 features)
    labels += [
        "File size", "Virtual size", "Has debug info",
        "Has relocations", "Has resources", "Has digital signature",
        "Has TLS section", "Import count", "Export count", "Section count",
    ]

    # Group 5: PE Header Features (~62 features)
    for i in range(62):
        labels.append(f"PE header field {i}")

    # Group 6: Section Features (~255 features — 51 sections × 5 fields)
    for s in range(51):
        for field in ("name hash", "raw size", "virtual size", "entropy", "characteristics"):
            labels.append(f"Section {s}: {field}")

    # Group 7: Import Features (~1280 features — 256 DLL + 1024 function hashes)
    for i in range(256):
        labels.append(f"Imported DLL hash bucket {i}")
    for i in range(1024):
        labels.append(f"Imported function hash bucket {i}")

    # Group 8: Export Features (~128 features)
    for i in range(128):
        labels.append(f"Exported function hash bucket {i}")

    # Group 9: Data Directories — present in newer thrember versions (~186+ features)
    for i in range(max(0, n_features - len(labels))):
        labels.append(f"Data directory feature {i}")

    # Pad if still short (should not happen, but defensive)
    while len(labels) < n_features:
        labels.append(f"Feature {len(labels)}")

    return labels[:n_features]


def _build_group_ranges(n_features: int) -> dict:
    """
    Builds feature group boundary ranges proportional to the actual feature count.
    Groups are defined by their known starting positions in the EMBER feature vector.
    Any features beyond the known groups are collected into an 'Extended Features' group.
    """
    # These boundaries are fixed by the EMBER2024 spec regardless of total count
    known_groups = {
        "Byte Frequency Distribution":   (0,    255),
        "Entropy / Packing Indicators":  (256,  511),
        "String Content Analysis":       (512,  615),
        "General File Properties":       (616,  625),
        "PE Header Fields":              (626,  687),
        "Section Structure":             (688,  942),
        "Import Table (DLLs)":           (943,  1198),
        "Import Table (Functions)":      (1199, 2222),
        "Export Table":                  (2223, 2350),
    }

    ranges = {}
    last_end = 0
    for name, (start, end) in known_groups.items():
        if start >= n_features:
            break
        actual_end = min(end, n_features - 1)
        ranges[name] = (start, actual_end)
        last_end = actual_end + 1

    # Any features beyond the known EMBER groups go into Extended Features
    if last_end < n_features:
        ranges["Extended Features"] = (last_end, n_features - 1)

    return ranges


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_SHAP_TABLE = """
CREATE TABLE IF NOT EXISTS shap_explanations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL,
    filename        TEXT,
    verdict         TEXT,
    score           REAL,
    n_features      INTEGER,
    top_features    TEXT,
    group_summary   TEXT,
    timestamp       TEXT    NOT NULL
)
"""


def _ensure_table():
    """Creates the SHAP explanations table if it does not exist."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_SHAP_TABLE)
            # Add n_features column to existing tables if missing
            cols = {r[1] for r in conn.execute(
                "PRAGMA table_info(shap_explanations)"
            ).fetchall()}
            if "n_features" not in cols:
                conn.execute(
                    "ALTER TABLE shap_explanations ADD COLUMN n_features INTEGER"
                )
    except sqlite3.Error as e:
        print(f"[-] Explainability: Table creation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SHAPExplainer:
    """
    Computes and stores SHAP feature attributions for every LightGBM verdict.

    Uses TreeExplainer which is exact (not approximate) for tree-based models.
    Dynamically adapts to the feature vector dimension produced by the installed
    thrember version — no hardcoded feature count assumptions.
    """

    def __init__(self):
        self._explainer   = None
        self._n_features  = None   # detected on first explain() call
        self._feat_labels = None   # built lazily after n_features is known
        self._grp_ranges  = None   # built lazily after n_features is known
        _ensure_table()

    def _get_explainer(self, model) -> object | None:
        """
        Lazily initializes the SHAP TreeExplainer on first use.
        Suppresses the SHAP UserWarning about binary classifier output format
        changes — handled explicitly in the explain() method.
        """
        if not _SHAP_AVAILABLE:
            return None
        if self._explainer is None:
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message=".*LightGBM binary classifier.*",
                        category=UserWarning,
                    )
                    self._explainer = _shap.TreeExplainer(model)
            except Exception as e:
                print(f"[-] SHAP: Explainer initialization failed: {e}")
                return None
        return self._explainer

    def _init_labels(self, n_features: int):
        """
        Builds the feature label map and group ranges for the detected feature count.
        Called once on first explain() and cached for subsequent scans.
        """
        if self._n_features == n_features:
            return   # Already initialized for this dimension
        self._n_features  = n_features
        self._feat_labels = _build_feature_labels(n_features)
        self._grp_ranges  = _build_group_ranges(n_features)
        print(f"[*] SHAP: Initialized for {n_features}-dimensional feature vectors.")

    def explain(
        self,
        model,
        features:  np.ndarray,
        sha256:    str,
        filename:  str,
        verdict:   str,
        score:     float,
        top_n:     int = 10,
    ) -> dict | None:
        """
        Computes SHAP values for one feature vector and returns a ranked
        explanation of the top N features that most influenced the verdict.

        Dynamically detects the feature dimension from the SHAP output so
        it works with any thrember version (2381, 2568, or future dimensions).

        Returns a dict with keys: top_features, group_summary, narrative, n_features
        Returns None if SHAP is unavailable or computation fails.
        """
        if not _SHAP_AVAILABLE:
            return None

        explainer = self._get_explainer(model)
        if explainer is None:
            return None

        try:
            # Compute SHAP values — suppress version-change warning
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=".*LightGBM binary classifier.*",
                    category=UserWarning,
                )
                shap_values = explainer.shap_values(features)

            # ── Normalise output to a flat 1D array ──────────────────────────
            # SHAP >= 0.46 with binary LightGBM returns a list of one ndarray.
            # Older versions return a list of two ndarrays [benign, malicious].
            # Some versions return an Explanation object with a .values attribute.
            if isinstance(shap_values, list):
                if len(shap_values) == 2:
                    sv = np.array(shap_values[1]).flatten()
                else:
                    sv = np.array(shap_values[0]).flatten()
            elif hasattr(shap_values, "values"):
                sv = np.array(shap_values.values).flatten()
            else:
                sv = np.array(shap_values).flatten()

            # If still 2D after flattening, take the first sample row
            if sv.ndim > 1:
                sv = sv[0]

            n_features = len(sv)

            # ── Initialize label map for this feature dimension ───────────────
            # This replaces the old hardcoded 2381 check.
            # Any valid non-zero feature count is accepted.
            if n_features < 100:
                print(f"[-] SHAP: Feature vector too short ({n_features}) — skipping.")
                return None

            self._init_labels(n_features)

            # ── Rank features by absolute SHAP value ─────────────────────────
            abs_sv  = np.abs(sv)
            top_idx = np.argsort(abs_sv)[::-1][:top_n]

            top_features = []
            for idx in top_idx:
                shap_val = float(sv[idx])
                top_features.append({
                    "feature":     self._feat_labels[idx],
                    "feature_idx": int(idx),
                    "shap_value":  round(shap_val, 4),
                    "direction":   "toward malicious" if shap_val > 0 else "toward safe",
                    "magnitude":   round(float(abs_sv[idx]), 4),
                })

            # ── Aggregate by feature group ────────────────────────────────────
            group_summary = {}
            for group_name, (start, end) in self._grp_ranges.items():
                contribution = float(np.sum(np.abs(sv[start:end + 1])))
                group_summary[group_name] = round(contribution, 4)

            group_summary = dict(
                sorted(group_summary.items(), key=lambda x: x[1], reverse=True)
            )

            narrative = self._build_narrative(top_features[:3], verdict, score)

            result = {
                "top_features":  top_features,
                "group_summary": group_summary,
                "narrative":     narrative,
                "n_features":    n_features,
            }

            self._persist(sha256, filename, verdict, score,
                          n_features, top_features, group_summary)

            return result

        except Exception as e:
            print(f"[-] SHAP: Explanation failed: {e}")
            return None

    def _build_narrative(
        self,
        top_features: list,
        verdict:      str,
        score:        float,
    ) -> str:
        """Builds a concise plain-English explanation of the top 3 SHAP drivers."""
        if not top_features:
            return "No SHAP explanation available."

        lines = [
            f"Verdict: {verdict} (confidence: {score:.2%})",
            "Primary factors driving this verdict:",
        ]
        for i, feat in enumerate(top_features, 1):
            direction = "increased" if feat["shap_value"] > 0 else "decreased"
            lines.append(
                f"  {i}. {feat['feature']} "
                f"({direction} malicious probability by {feat['magnitude']:.3f})"
            )
        return "\n".join(lines)

    def _persist(
        self,
        sha256:        str,
        filename:      str,
        verdict:       str,
        score:         float,
        n_features:    int,
        top_features:  list,
        group_summary: dict,
    ):
        """Stores the SHAP explanation in the database for later retrieval."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO shap_explanations
                        (sha256, filename, verdict, score, n_features,
                         top_features, group_summary, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256, filename, verdict, score, n_features,
                        json.dumps(top_features),
                        json.dumps(group_summary),
                        now,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] SHAP: Persist failed: {e}")

    def get_explanation(self, sha256: str) -> dict | None:
        """Retrieves a previously computed SHAP explanation from the database."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    """
                    SELECT sha256, filename, verdict, score,
                           top_features, group_summary, timestamp
                    FROM   shap_explanations
                    WHERE  sha256 = ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (sha256,)
                ).fetchone()
            if not row:
                return None
            return {
                "sha256":        row[0],
                "filename":      row[1],
                "verdict":       row[2],
                "score":         row[3],
                "top_features":  json.loads(row[4]),
                "group_summary": json.loads(row[5]),
                "timestamp":     row[6],
            }
        except Exception:
            return None

    def get_recent_explanations(self, limit: int = 50) -> list:
        """Returns recent SHAP explanations for the GUI history table."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT sha256, filename, verdict, score,
                           top_features, group_summary, timestamp
                    FROM   shap_explanations
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [
                {
                    "sha256":        r[0],
                    "filename":      r[1],
                    "verdict":       r[2],
                    "score":         r[3],
                    "top_features":  json.loads(r[4]),
                    "group_summary": json.loads(r[5]),
                    "timestamp":     r[6],
                }
                for r in rows
            ]
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_instance: SHAPExplainer | None = None


def get_explainer() -> SHAPExplainer:
    """Returns the module-level SHAPExplainer singleton."""
    global _instance
    if _instance is None:
        _instance = SHAPExplainer()
    return _instance
