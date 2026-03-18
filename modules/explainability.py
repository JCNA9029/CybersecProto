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
# Integration:
#   Called by ml_engine.scan_stage1() after every successful prediction.
#   Results are attached to the ml_result dict as "shap_explanation".

import os
import json
import sqlite3
import datetime
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
#  EMBER2024 FEATURE LABEL MAP
#
#  Maps flat feature indices (0–2380) to human-readable descriptions.
#  Built from the EMBER2024 feature group specifications.
#  Groups: ByteHistogram(0-255), ByteEntropyHistogram(256-511),
#          StringFeatures(512-615), GeneralInfo(616-625),
#          HeaderFeatures(626-687), SectionFeatures(688-942),
#          ImportFeatures(943-2222), ExportFeatures(2223-2350),
#          DataDirectories(2351-2380)
# ─────────────────────────────────────────────────────────────────────────────

def _build_feature_labels() -> list[str]:
    """
    Generates the 2,381 human-readable feature labels matching EMBER2024 groups.
    Used to translate raw SHAP feature indices into analyst-readable descriptions.
    """
    labels = []

    # Group 1: Byte Histogram (256 features)
    for i in range(256):
        labels.append(f"Byte frequency 0x{i:02X}")

    # Group 2: Byte Entropy Histogram (256 features)
    for i in range(256):
        labels.append(f"Entropy bucket {i} (local byte entropy distribution)")

    # Group 3: String Features (104 features)
    string_labels = [
        "Number of strings (length 1)", "Number of strings (length 2)",
        "Number of strings (length 3)", "Number of strings (length 4)",
        "Number of strings (length 5)", "Number of strings (length 6)",
        "Number of strings (length 7)", "Number of strings (length 8)",
        "Number of strings (length 9)", "Number of strings (length 10)",
    ]
    for i in range(10, 96):
        string_labels.append(f"Number of strings (length {i+1})")
    string_labels += [
        "URLs detected in strings",
        "Registry key paths in strings",
        "File paths in strings",
        "MZ headers embedded in strings",
        "Average string length",
        "Printable character ratio",
        "IP addresses in strings",
        "Cryptocurrency addresses in strings",
    ]
    labels.extend(string_labels[:104])

    # Group 4: General File Info (10 features)
    labels += [
        "File size (bytes)",
        "Virtual size",
        "Has debug info",
        "Has relocations",
        "Has resources",
        "Has digital signature",
        "Has TLS section",
        "Number of imports",
        "Number of exports",
        "Number of sections",
    ]

    # Group 5: Header Features (62 features)
    for i in range(62):
        labels.append(f"PE header field {i} (COFF/Optional header)")

    # Group 6: Section Features (255 features — 51 sections × 5 fields)
    section_fields = ["name hash", "raw size", "virtual size", "entropy", "characteristics"]
    for s in range(51):
        for field in section_fields:
            labels.append(f"Section {s}: {field}")

    # Group 7: Import Features (1280 features — 256 DLL + 1024 function hashes)
    for i in range(256):
        labels.append(f"Imported DLL hash bucket {i}")
    for i in range(1024):
        labels.append(f"Imported function hash bucket {i}")

    # Group 8: Export Features (128 features)
    for i in range(128):
        labels.append(f"Exported function hash bucket {i}")

    # Pad to exactly 2381 if needed
    while len(labels) < 2381:
        labels.append(f"Feature {len(labels)}")

    return labels[:2381]


_FEATURE_LABELS = _build_feature_labels()

# High-risk feature group names for summary reporting
_GROUP_RANGES = {
    "Byte Frequency Distribution":   (0,   255),
    "Entropy / Packing Indicators":  (256, 511),
    "String Content Analysis":       (512, 615),
    "General File Properties":       (616, 625),
    "PE Header Fields":              (626, 687),
    "Section Structure":             (688, 942),
    "Import Table (DLLs)":           (943, 1198),
    "Import Table (Functions)":      (1199, 2222),
    "Export Table":                  (2223, 2350),
    "Data Directories":              (2351, 2380),
}


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
    top_features    TEXT,   -- JSON: [{feature, shap_value, direction}, ...]
    group_summary   TEXT,   -- JSON: {group_name: total_shap_contribution}
    timestamp       TEXT    NOT NULL
)
"""


def _ensure_table():
    """Creates the SHAP explanations table if it does not exist."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_SHAP_TABLE)
    except sqlite3.Error as e:
        print(f"[-] Explainability: Table creation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SHAPExplainer:
    """
    Computes and stores SHAP feature attributions for every LightGBM verdict.

    Uses TreeExplainer which is exact (not approximate) for tree-based models
    and runs in O(TLD) time where T=trees, L=leaves, D=depth — fast enough
    for real-time use in the scan pipeline.
    """

    def __init__(self):
        self._explainer = None
        _ensure_table()

    def _get_explainer(self, model) -> object | None:
        """
        Lazily initializes the SHAP TreeExplainer on first use.
        Caches the explainer so it is not rebuilt on every scan.
        """
        if not _SHAP_AVAILABLE:
            return None
        if self._explainer is None:
            try:
                self._explainer = _shap.TreeExplainer(model)
            except Exception as e:
                print(f"[-] SHAP: Explainer initialization failed: {e}")
                return None
        return self._explainer

    def explain(
        self,
        model,
        features: np.ndarray,
        sha256: str,
        filename: str,
        verdict: str,
        score: float,
        top_n: int = 10,
    ) -> dict | None:
        """
        Computes SHAP values for one feature vector and returns a ranked
        explanation of the top N features that most influenced the verdict.

        Arguments:
            model     LightGBM Booster used for prediction
            features  Feature vector of shape (1, 2381)
            sha256    SHA-256 of the scanned file
            filename  Basename of the scanned file
            verdict   Classification result (CRITICAL RISK / SUSPICIOUS / SAFE)
            score     Raw sigmoid probability from Stage 1
            top_n     Number of top features to include in the explanation

        Returns:
            A dict with keys: top_features, group_summary, narrative
            Returns None if SHAP is unavailable or computation fails.
        """
        if not _SHAP_AVAILABLE:
            return None

        explainer = self._get_explainer(model)
        if explainer is None:
            return None

        try:
            # Compute exact SHAP values for the feature vector
            # Output shape: (1, 2381) — one value per feature
            shap_values = explainer.shap_values(features)

            # For binary classification, shap_values may be a list [benign, malicious]
            # We want the values for the malicious class
            if isinstance(shap_values, list):
                sv = shap_values[1][0]   # malicious class, first (only) sample
            else:
                sv = shap_values[0]      # single output

            # Rank features by absolute SHAP value (most influential first)
            abs_sv   = np.abs(sv)
            top_idx  = np.argsort(abs_sv)[::-1][:top_n]

            top_features = []
            for idx in top_idx:
                shap_val = float(sv[idx])
                top_features.append({
                    "feature":     _FEATURE_LABELS[idx],
                    "feature_idx": int(idx),
                    "shap_value":  round(shap_val, 4),
                    "direction":   "toward malicious" if shap_val > 0 else "toward safe",
                    "magnitude":   round(float(abs_sv[idx]), 4),
                })

            # Aggregate SHAP contributions by feature group
            group_summary = {}
            for group_name, (start, end) in _GROUP_RANGES.items():
                group_contribution = float(np.sum(np.abs(sv[start:end+1])))
                group_summary[group_name] = round(group_contribution, 4)

            # Sort groups by contribution
            group_summary = dict(
                sorted(group_summary.items(), key=lambda x: x[1], reverse=True)
            )

            # Build a plain-English narrative for the top 3 features
            narrative = self._build_narrative(top_features[:3], verdict, score)

            result = {
                "top_features":  top_features,
                "group_summary": group_summary,
                "narrative":     narrative,
            }

            # Persist to database
            self._persist(sha256, filename, verdict, score, top_features, group_summary)

            return result

        except Exception as e:
            print(f"[-] SHAP: Explanation failed: {e}")
            return None

    def _build_narrative(
        self,
        top_features: list,
        verdict: str,
        score: float,
    ) -> str:
        """
        Builds a concise plain-English explanation of the top 3 SHAP drivers.
        Suitable for display in the GUI console and AI triage context.
        """
        if not top_features:
            return "No SHAP explanation available."

        lines = [
            f"Verdict: {verdict} (confidence: {score:.1%})",
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
        sha256: str,
        filename: str,
        verdict: str,
        score: float,
        top_features: list,
        group_summary: dict,
    ):
        """Stores the SHAP explanation in the database for later retrieval."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO shap_explanations
                        (sha256, filename, verdict, score,
                         top_features, group_summary, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256, filename, verdict, score,
                        json.dumps(top_features),
                        json.dumps(group_summary),
                        now,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] SHAP: Persist failed: {e}")

    def get_explanation(self, sha256: str) -> dict | None:
        """
        Retrieves a previously computed SHAP explanation from the database.
        Used by the GUI Explainability page to display historical results.
        """
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
        """
        Returns recent SHAP explanations for the GUI history table.
        """
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
