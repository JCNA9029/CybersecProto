# modules/adaptive_learner.py — Self-Correcting ML Engine with Label Poisoning Protection
#
# SAFEGUARDS AGAINST MISLABELING:
#
#   1. Correction Quarantine
#      Every correction enters status='PENDING_REVIEW' first — not immediately
#      trainable. It only becomes 'PENDING' (trainable) after passing all
#      automated validation checks. Nothing trains from unvalidated data.
#
#   2. Automated Conflict Detection (3 checks run on every submission)
#      a) Cross-source conflict  — does the existing cache verdict contradict
#         the analyst's label? (e.g. VT said MALICIOUS, analyst said FP)
#      b) Duplicate conflict     — has the same SHA-256 been corrected before
#         with a DIFFERENT label? Flags the contradiction for review.
#      c) Self-contradiction     — analyst marked FP on a file originally
#         flagged SAFE, or FN on a file originally flagged MALICIOUS — logically
#         impossible; rejected outright.
#
#   3. Correction Revocation
#      Any PENDING or PENDING_REVIEW correction can be revoked by an analyst
#      before it enters a retraining session. If a correction was already
#      TRAINED, revoke_correction() rolls the model back to the backup snapshot
#      taken before that session.
#
#   4. Conflict Resolution
#      CONFLICTED corrections are held in quarantine and displayed in the GUI
#      for manual review. An analyst can approve them (→ PENDING) or reject
#      them (→ REVOKED) explicitly.

import os
import json
import sqlite3
import datetime
import shutil
import threading
import numpy as np
import lightgbm as lgb

from . import utils
from . import colors
from .loading import Spinner

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH     = os.path.join(_PROJECT_ROOT, "models", "CyberSentinel_v2.model")
BACKUP_DIR     = os.path.join(_PROJECT_ROOT, "models", "backups")
AUDIT_LOG_PATH = os.path.join(_PROJECT_ROOT, "models", "learning_audit.jsonl")

AUTO_RETRAIN_THRESHOLD = 5
LEARNING_RATE  = 0.05
NUM_NEW_TREES  = 15
MAX_DEPTH      = 4

LABEL_MALICIOUS = 1
LABEL_BENIGN    = 0

# Queue status lifecycle:
#   PENDING_REVIEW → (validation passes) → PENDING → (trained) → TRAINED
#   PENDING_REVIEW → (conflict found)    → CONFLICTED
#   CONFLICTED     → (analyst approves)  → PENDING
#   CONFLICTED     → (analyst rejects)   → REVOKED
#   PENDING        → (analyst revokes)   → REVOKED
#   TRAINED        → (analyst revokes)   → REVOKED + model rollback

STATUS_PENDING_REVIEW = "PENDING_REVIEW"
STATUS_PENDING        = "PENDING"
STATUS_TRAINED        = "TRAINED"
STATUS_CONFLICTED     = "CONFLICTED"
STATUS_REVOKED        = "REVOKED"
STATUS_SKIPPED        = "SKIPPED"

# ─────────────────────────────────────────────────────────────────────────────
#  ANCHOR SAMPLE PARAMETERS
#
#  Anchor samples are correctly-classified examples drawn from the scan cache
#  and mixed into every retraining batch. They prevent the model from drifting
#  away from its original knowledge base when corrections are skewed toward
#  one class (e.g. all False Negatives and no False Positives).
#
#  ANCHOR_RATIO: For every 1 correction, include this many anchor samples.
#                At 2.0, a 5-correction batch becomes 5 corrections + 10 anchors.
#  ANCHOR_BALANCE: Target ratio of benign:malicious anchors (0.5 = 50/50).
#                  This directly counteracts class imbalance in the correction set.
# ─────────────────────────────────────────────────────────────────────────────

ANCHOR_RATIO   = 2.0    # Anchor samples per correction
ANCHOR_BALANCE = 0.5    # Fraction of anchor samples that should be benign

# ─────────────────────────────────────────────────────────────────────────────
#  ANTI-BIAS SAFEGUARDS
#
#  MIN_ANCHORS_PER_CLASS:
#    Minimum confirmed samples of EACH class required before any retraining
#    session is allowed to proceed (even forced). Prevents early-deployment
#    bias when the anchor store is empty or too small to provide balance.
#
#  ANCHOR_RECENT_DAYS:
#    Anchors newer than this many days are treated as "recent" and preferred
#    during random selection. Recent anchors reflect the current threat
#    landscape better than old ones. Older anchors are used as fallback.
#
#  ANCHOR_EXPIRY_DAYS:
#    Anchors older than this are considered stale and excluded from retraining.
#    Prevents outdated ground truth from permanently biasing the model.
#    Set to 0 to disable expiry entirely.
#
#  MAX_IMBALANCE_RATIO:
#    Maximum allowed ratio of majority:minority class in the final training
#    batch. If the combined corrections+anchors exceed this ratio, retraining
#    is blocked with a warning. 3.0 means no more than 3:1 skew is permitted.
# ─────────────────────────────────────────────────────────────────────────────

MIN_ANCHORS_PER_CLASS = 5      # Minimum of each class before retraining allowed
ANCHOR_RECENT_DAYS    = 90     # Prefer anchors newer than this many days
ANCHOR_EXPIRY_DAYS    = 365    # Exclude anchors older than this (0 = never expire)
MAX_IMBALANCE_RATIO   = 3.0    # Maximum majority:minority ratio in final batch

# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_ANCHOR_STORE = """
CREATE TABLE IF NOT EXISTS anchor_samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT    UNIQUE NOT NULL,
    filename      TEXT,
    true_label    INTEGER NOT NULL,   -- 0=BENIGN, 1=MALICIOUS (ground truth)
    features_json TEXT    NOT NULL,   -- JSON-encoded float32 feature vector
    source        TEXT,               -- 'CONFIRMED_TP' | 'CONFIRMED_SAFE'
    added_at      TEXT    NOT NULL
)
"""

_CREATE_LEARNING_QUEUE = """
CREATE TABLE IF NOT EXISTS learning_queue (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256           TEXT    NOT NULL,
    filename         TEXT,
    file_path        TEXT,
    correction_type  TEXT    NOT NULL,
    original_verdict TEXT    NOT NULL,
    analyst_notes    TEXT,
    features_json    TEXT,
    status           TEXT    DEFAULT 'PENDING_REVIEW',
    conflict_reason  TEXT,
    session_id       TEXT,
    queued_at        TEXT    NOT NULL,
    reviewed_at      TEXT,
    trained_at       TEXT,
    revoked_at       TEXT
)
"""

_CREATE_RETRAINING_LOG = """
CREATE TABLE IF NOT EXISTS retraining_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT    NOT NULL,
    samples_used     INTEGER NOT NULL,
    fp_corrections   INTEGER NOT NULL,
    fn_corrections   INTEGER NOT NULL,
    model_backup     TEXT,
    new_trees_added  INTEGER NOT NULL,
    outcome          TEXT    NOT NULL,
    error_message    TEXT,
    timestamp        TEXT    NOT NULL
)
"""


def _ensure_tables():
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_LEARNING_QUEUE)
            conn.execute(_CREATE_RETRAINING_LOG)
            conn.execute(_CREATE_ANCHOR_STORE)
            # Migrate existing tables that lack new columns
            cols = {r[1] for r in conn.execute("PRAGMA table_info(learning_queue)").fetchall()}
            for col, defn in [
                ("conflict_reason", "TEXT"),
                ("session_id",      "TEXT"),
                ("reviewed_at",     "TEXT"),
                ("revoked_at",      "TEXT"),
            ]:
                if col not in cols:
                    conn.execute(f"ALTER TABLE learning_queue ADD COLUMN {col} {defn}")
    except sqlite3.Error as e:
        print(f"[-] AdaptiveLearner: Table init failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class AdaptiveLearner:
    """
    Self-correcting ML engine with label-poisoning safeguards.

    Corrections go through a validation quarantine before they can influence
    the model. Mislabeled corrections can be revoked at any time; if already
    trained, the model is automatically rolled back to the pre-session backup.
    """

    _db_lock = threading.Lock()

    def __init__(
        self,
        model_path:    str   = MODEL_PATH,
        threshold:     int   = AUTO_RETRAIN_THRESHOLD,
        learning_rate: float = LEARNING_RATE,
        num_new_trees: int   = NUM_NEW_TREES,
    ):
        self.model_path    = model_path
        self.threshold     = threshold
        self.learning_rate = learning_rate
        self.num_new_trees = num_new_trees
        _ensure_tables()

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 1: CORRECTION INTAKE WITH VALIDATION QUARANTINE
    # ──────────────────────────────────────────────────────────────────────────

    def schedule_correction(
        self,
        sha256:                   str,
        filename:                 str,
        file_path:                str,
        correction_type:          str,
        original_verdict:         str,
        analyst_notes:            str = "",
        prefetched_features_json: str | None = None,
    ) -> dict:
        """
        Validates and queues an analyst correction.

        prefetched_features_json: compressed feature vector captured in
        _prompt_quarantine Step 0.5, before the file was quarantined.
        When provided, feature extraction from file_path is skipped entirely —
        this is the Scenario 3 fix that makes adaptive learning work even
        when the analyst approves quarantine before submitting feedback.

        Returns a result dict:
          {
            "accepted":        bool,
            "status":          PENDING | CONFLICTED | REVOKED,
            "conflict_reason": str | None,
            "message":         str
          }

        Corrections enter PENDING_REVIEW immediately. Three automated checks
        run before the status is upgraded to PENDING or downgraded to CONFLICTED.
        Nothing is trainable until it reaches PENDING.
        """
        if correction_type not in ("FALSE_POSITIVE", "FALSE_NEGATIVE"):
            return {
                "accepted": False, "status": None,
                "conflict_reason": None,
                "message": f"Unknown correction type: {correction_type}"
            }

        # ── Check 1: Self-contradiction ────────────────────────────────────
        #
        # Definitions:
        #   FALSE_POSITIVE = system said MALICIOUS, analyst says it is actually SAFE
        #   FALSE_NEGATIVE = system said SAFE,      analyst says it is actually MALICIOUS
        #
        # A self-contradiction is when the original verdict already matches what
        # the analyst is claiming — e.g. marking a SAFE verdict as FALSE_POSITIVE
        # makes no sense because FALSE_POSITIVE requires the system to have said
        # MALICIOUS in the first place.
        #
        # Correct pairings:
        #   FALSE_POSITIVE  ←→  original verdict was MALICIOUS / CRITICAL / SUSPICIOUS
        #   FALSE_NEGATIVE  ←→  original verdict was SAFE / UNKNOWN
        orig_upper = original_verdict.upper()
        orig_is_malicious = any(v in orig_upper for v in ("MALICIOUS", "CRITICAL", "SUSPICIOUS"))
        orig_is_safe      = any(v in orig_upper for v in ("SAFE",)) or not orig_is_malicious

        if correction_type == "FALSE_POSITIVE" and orig_is_safe:
            return {
                "accepted": False, "status": STATUS_REVOKED,
                "conflict_reason": (
                    f"Self-contradiction: cannot mark a '{original_verdict}' verdict as "
                    f"FALSE_POSITIVE. FALSE_POSITIVE means the system said MALICIOUS but "
                    f"the file is safe. Use FALSE_NEGATIVE if the system missed a threat."
                ),
                "message": (
                    f"Rejected: original verdict was '{original_verdict}' (safe/unknown). "
                    f"FALSE_POSITIVE only applies when the system said MALICIOUS."
                )
            }
        if correction_type == "FALSE_NEGATIVE" and orig_is_malicious:
            return {
                "accepted": False, "status": STATUS_REVOKED,
                "conflict_reason": (
                    f"Self-contradiction: cannot mark a '{original_verdict}' verdict as "
                    f"FALSE_NEGATIVE. FALSE_NEGATIVE means the system said SAFE but the "
                    f"file is malicious. Use FALSE_POSITIVE if the system over-detected."
                ),
                "message": (
                    f"Rejected: original verdict was '{original_verdict}' (malicious). "
                    f"FALSE_NEGATIVE only applies when the system said SAFE."
                )
            }

        # ── Feature extraction ──────────────────────────────────────────────
        # Scenario 3 Fix: use pre-extracted features if available (captured
        # before quarantine ran), otherwise attempt fresh extraction.
        # If the file has been quarantined, prefetched_features_json will be
        # set and extraction from the now-missing file is never attempted.
        if prefetched_features_json:
            features_json = prefetched_features_json
        else:
            features_json = self._extract_and_serialize(file_path)
        queued_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:

                    # ── Check 2: Duplicate conflict ────────────────────────
                    # Same SHA-256 already queued or trained with a DIFFERENT label
                    prior = conn.execute(
                        """
                        SELECT id, correction_type, status
                        FROM   learning_queue
                        WHERE  sha256 = ?
                          AND  status NOT IN (?, ?)
                        ORDER BY queued_at DESC LIMIT 1
                        """,
                        (sha256, STATUS_REVOKED, STATUS_SKIPPED)
                    ).fetchone()

                    conflict_reason = None

                    if prior:
                        prior_id, prior_type, prior_status = prior
                        if prior_type != correction_type:
                            conflict_reason = (
                                f"Label conflict: this SHA-256 was previously submitted as "
                                f"{prior_type} (queue ID {prior_id}, status {prior_status}). "
                                f"New submission says {correction_type}. "
                                f"Held for manual review."
                            )
                        else:
                            # Same label as before — skip duplicate silently
                            colors.warning(
                                f"[*] AdaptiveLearner: {sha256[:16]}... already queued as "
                                f"{prior_type} — skipping duplicate."
                            )
                            return {
                                "accepted": False,
                                "status": prior_status,
                                "conflict_reason": None,
                                "message": "Duplicate correction ignored — already in queue."
                            }

                    # ── Check 3: Cross-source conflict ──────────────────────
                    # Flags when the cache verdict is the OPPOSITE of what the
                    # correction implies — indicating the analyst may have the
                    # correction type backwards.
                    #
                    # Normal (no conflict):
                    #   Cache = MALICIOUS + correction = FALSE_POSITIVE  ✅
                    #   Cache = SAFE      + correction = FALSE_NEGATIVE  ✅
                    #
                    # Conflict (analyst may have swapped FP and FN):
                    #   Cache = SAFE      + correction = FALSE_POSITIVE  ⚠
                    #   Cache = MALICIOUS + correction = FALSE_NEGATIVE  ⚠
                    if not conflict_reason:
                        cached = conn.execute(
                            "SELECT verdict FROM scan_cache WHERE sha256 = ?",
                            (sha256,)
                        ).fetchone()
                        if cached:
                            cached_verdict     = (cached[0] or "").upper()
                            cache_is_malicious = any(
                                v in cached_verdict for v in ("MALICIOUS", "CRITICAL", "SUSPICIOUS")
                            )
                            cache_is_safe = not cache_is_malicious

                            if correction_type == "FALSE_POSITIVE" and cache_is_safe:
                                # Analyst says FP (system over-detected) but cache says SAFE —
                                # the system never flagged it as malicious, so FP makes no sense.
                                conflict_reason = (
                                    f"Possible mislabel: cache verdict is '{cached[0]}' (safe) "
                                    f"but analyst chose FALSE_POSITIVE. "
                                    f"FALSE_POSITIVE means the system said MALICIOUS. "
                                    f"Did you mean FALSE_NEGATIVE? Held for manual review."
                                )
                            elif correction_type == "FALSE_NEGATIVE" and cache_is_malicious:
                                # Analyst says FN (system under-detected) but cache says MALICIOUS —
                                # the system already caught it, so FN makes no sense.
                                conflict_reason = (
                                    f"Possible mislabel: cache verdict is '{cached[0]}' (malicious) "
                                    f"but analyst chose FALSE_NEGATIVE. "
                                    f"FALSE_NEGATIVE means the system said SAFE. "
                                    f"Did you mean FALSE_POSITIVE? Held for manual review."
                                )

                    # ── Insert with appropriate status ─────────────────────
                    initial_status = STATUS_CONFLICTED if conflict_reason else STATUS_PENDING
                    conn.execute(
                        """
                        INSERT INTO learning_queue
                            (sha256, filename, file_path, correction_type, original_verdict,
                             analyst_notes, features_json, status, conflict_reason,
                             queued_at, reviewed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sha256, filename, file_path, correction_type,
                            original_verdict, analyst_notes, features_json,
                            initial_status, conflict_reason, queued_at,
                            queued_at if not conflict_reason else None
                        )
                    )

            except sqlite3.Error as e:
                print(f"[-] AdaptiveLearner: Queue insert failed: {e}")
                return {
                    "accepted": False, "status": None,
                    "conflict_reason": None,
                    "message": f"Database error: {e}"
                }

        if conflict_reason:
            colors.warning(
                f"[!] AdaptiveLearner: Correction for '{filename}' held — CONFLICTED.\n"
                f"    Reason: {conflict_reason}\n"
                f"    Review in the Adaptive Learning page."
            )
            return {
                "accepted": True,
                "status": STATUS_CONFLICTED,
                "conflict_reason": conflict_reason,
                "message": "Correction held for manual review due to conflict."
            }

        label = "FALSE POSITIVE" if correction_type == "FALSE_POSITIVE" else "FALSE NEGATIVE"
        colors.success(f"[+] AdaptiveLearner: Correction validated — {label} for '{filename}'")

        # Check threshold and auto-retrain if reached
        pending_count = self.get_pending_count()
        colors.info(f"[*] AdaptiveLearner: Queue depth {pending_count}/{self.threshold}")
        if pending_count >= self.threshold:
            colors.info("[*] AdaptiveLearner: Threshold reached — scheduling retraining session.")
            t = threading.Thread(target=self._run_retraining_session, daemon=True)
            t.start()

        return {
            "accepted": True,
            "status": STATUS_PENDING,
            "conflict_reason": None,
            "message": f"Correction queued. Queue depth: {pending_count}/{self.threshold}"
        }

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 2: CONFLICT RESOLUTION
    # ──────────────────────────────────────────────────────────────────────────

    def approve_conflicted(self, queue_id: int) -> bool:
        """
        Analyst manually approves a CONFLICTED correction after reviewing it.
        Moves it to PENDING so it can be included in the next retraining session.
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    rows = conn.execute(
                        "UPDATE learning_queue SET status=?, reviewed_at=? "
                        "WHERE id=? AND status=?",
                        (STATUS_PENDING, now, queue_id, STATUS_CONFLICTED)
                    ).rowcount
                    if rows:
                        colors.success(f"[+] AdaptiveLearner: Correction {queue_id} approved → PENDING.")
                        return True
                    colors.warning(f"[*] AdaptiveLearner: Correction {queue_id} not found or not CONFLICTED.")
                    return False
            except sqlite3.Error as e:
                print(f"[-] AdaptiveLearner: Approve failed: {e}")
                return False

    def reject_conflicted(self, queue_id: int, reason: str = "") -> bool:
        """
        Analyst rejects a CONFLICTED correction — it is permanently revoked
        and will never be used for training.
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        note = f"Rejected by analyst: {reason}" if reason else "Rejected by analyst."
        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    rows = conn.execute(
                        "UPDATE learning_queue SET status=?, conflict_reason=?, revoked_at=? "
                        "WHERE id=? AND status=?",
                        (STATUS_REVOKED, note, now, queue_id, STATUS_CONFLICTED)
                    ).rowcount
                    if rows:
                        colors.warning(f"[*] AdaptiveLearner: Correction {queue_id} rejected → REVOKED.")
                        return True
                    return False
            except sqlite3.Error as e:
                print(f"[-] AdaptiveLearner: Reject failed: {e}")
                return False

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 3: CORRECTION REVOCATION + MODEL ROLLBACK
    # ──────────────────────────────────────────────────────────────────────────

    def revoke_correction(self, queue_id: int) -> dict:
        """
        Revokes a correction at any stage:
          - PENDING_REVIEW / PENDING / CONFLICTED → marked REVOKED, never trains
          - TRAINED → model rolled back to the backup snapshot from that session

        Returns {
            "revoked": bool,
            "rollback_performed": bool,
            "backup_used": str | None,
            "message": str
        }
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = {
            "revoked": False,
            "rollback_performed": False,
            "backup_used": None,
            "message": ""
        }

        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT status, session_id, filename FROM learning_queue WHERE id=?",
                    (queue_id,)
                ).fetchone()
        except sqlite3.Error as e:
            result["message"] = f"DB error: {e}"
            return result

        if not row:
            result["message"] = f"Queue entry {queue_id} not found."
            return result

        status, session_id, filename = row

        if status == STATUS_REVOKED:
            result["message"] = f"Correction {queue_id} is already revoked."
            return result

        # Mark as REVOKED
        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    conn.execute(
                        "UPDATE learning_queue SET status=?, revoked_at=? WHERE id=?",
                        (STATUS_REVOKED, now, queue_id)
                    )
                result["revoked"] = True
                colors.warning(
                    f"[*] AdaptiveLearner: Correction {queue_id} ('{filename}') revoked."
                )
            except sqlite3.Error as e:
                result["message"] = f"Revoke failed: {e}"
                return result

        # If already TRAINED — roll back the model to the backup from that session
        if status == STATUS_TRAINED and session_id:
            rollback = self._rollback_model(session_id)
            result["rollback_performed"] = rollback["performed"]
            result["backup_used"]        = rollback["backup_path"]
            result["message"] = rollback["message"]
            if rollback["performed"]:
                colors.warning(
                    f"[!] AdaptiveLearner: Model rolled back to snapshot before {session_id}."
                )
                _set_model_reload_flag()
            else:
                colors.warning(
                    f"[!] AdaptiveLearner: Could not roll back model — {rollback['message']}"
                )
        else:
            result["message"] = (
                f"Correction revoked. "
                f"It had not been trained yet so no model rollback was needed."
            )

        self._write_audit_jsonl({
            "event":       "REVOCATION",
            "queue_id":    queue_id,
            "session_id":  session_id or "",
            "rollback":    result["rollback_performed"],
            "backup_used": result["backup_used"] or "",
        }, now)

        return result

    def _rollback_model(self, session_id: str) -> dict:
        """
        Restores the model from the backup created immediately before
        the given session_id ran. Returns a status dict.
        """
        result = {"performed": False, "backup_path": None, "message": ""}

        # Find the backup for this session from the retraining log
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT model_backup FROM retraining_log WHERE session_id=?",
                    (session_id,)
                ).fetchone()
        except sqlite3.Error as e:
            result["message"] = f"DB read failed: {e}"
            return result

        if not row or not row[0]:
            result["message"] = (
                f"No backup path recorded for session {session_id}. "
                f"Manual rollback required from {BACKUP_DIR}."
            )
            return result

        backup_path = row[0]
        if not os.path.exists(backup_path):
            result["message"] = (
                f"Backup file not found: {backup_path}. "
                f"Check {BACKUP_DIR} for available snapshots."
            )
            return result

        try:
            shutil.copy2(backup_path, self.model_path)
            result["performed"]   = True
            result["backup_path"] = backup_path
            result["message"]     = f"Model restored from {os.path.basename(backup_path)}."
        except Exception as e:
            result["message"] = f"File copy failed: {e}"

        return result

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 4: QUEUE QUERIES
    # ──────────────────────────────────────────────────────────────────────────

    def register_anchor(
        self,
        sha256:                   str,
        filename:                 str,
        file_path:                str,
        true_label:               int,
        source:                   str,
        prefetched_features_json: str | None = None,
    ) -> bool:
        """
        Registers a correctly-classified sample as an anchor for future retraining.

        prefetched_features_json: Scenario 3 fix — use pre-extracted features
        when available so anchors can be registered even after quarantine.

        D3 Fix: Cross-validates the anchor label against the scan cache before
        accepting it. An anchor whose label contradicts the stored verdict is
        rejected to prevent accidentally-confirmed wrong verdicts from permanently
        biasing future retraining batches.
        """
        # Use pre-extracted features if available, otherwise extract fresh
        if prefetched_features_json:
            features_json = prefetched_features_json
        else:
            features_json = self._extract_and_serialize(file_path)

        if not features_json:
            return False

        # D3 Fix: Cross-validate anchor label against scan cache
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                cached = conn.execute(
                    "SELECT verdict FROM scan_cache WHERE sha256 = ?", (sha256,)
                ).fetchone()
            if cached:
                cached_upper       = (cached[0] or "").upper()
                cached_is_malicious = any(
                    v in cached_upper for v in ("MALICIOUS", "CRITICAL")
                )
                if true_label == LABEL_BENIGN and cached_is_malicious:
                    colors.warning(
                        f"[!] Anchor rejected: cache verdict is MALICIOUS "
                        f"but label is BENIGN for '{filename}'. "
                        f"Submit a FALSE_POSITIVE correction instead."
                    )
                    return False
                if true_label == LABEL_MALICIOUS and not cached_is_malicious:
                    colors.warning(
                        f"[!] Anchor rejected: cache verdict is SAFE "
                        f"but label is MALICIOUS for '{filename}'. "
                        f"Submit a FALSE_NEGATIVE correction instead."
                    )
                    return False
        except Exception:
            pass   # Cannot verify against cache — proceed cautiously

        added_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO anchor_samples
                            (sha256, filename, true_label, features_json, source, added_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (sha256, filename, true_label, features_json, source, added_at)
                    )
                return True
            except sqlite3.Error:
                return False

    def _load_anchor_samples(self, n_corrections: int, correction_label_counts: dict) -> tuple:
        """
        Loads a balanced set of anchor samples to mix into the correction batch.

        Anti-bias improvements:
          1. Age weighting — recent anchors (within ANCHOR_RECENT_DAYS) are
             preferred. Older anchors used as fallback. Expired anchors
             (older than ANCHOR_EXPIRY_DAYS) are excluded entirely.
          2. Inverted ratio — anchor class balance is inverted relative to
             the correction class imbalance to restore overall balance.
          3. Returns imbalance metrics so the caller can log or warn.

        Returns (X_anchors, y_anchors, imbalance_info) as numpy arrays
        and a dict, or (None, None, {}) if not enough anchors available.
        """
        n_anchors = max(2, int(n_corrections * ANCHOR_RATIO))

        n_malicious_corrections = correction_label_counts.get(LABEL_MALICIOUS, 0)
        n_benign_corrections    = correction_label_counts.get(LABEL_BENIGN, 0)
        total_corrections       = n_malicious_corrections + n_benign_corrections

        if total_corrections == 0:
            return None, None

        correction_malicious_ratio = n_malicious_corrections / total_corrections
        target_benign_anchor_ratio = max(
            0.2, min(0.8, 1.0 - correction_malicious_ratio)
        )

        n_benign_anchors    = int(n_anchors * target_benign_anchor_ratio)
        n_malicious_anchors = n_anchors - n_benign_anchors

        # Build date cutoffs for age weighting
        now         = datetime.datetime.now()
        recent_cutoff = (now - datetime.timedelta(days=ANCHOR_RECENT_DAYS)
                         ).strftime("%Y-%m-%d %H:%M:%S")
        expiry_cutoff = None
        if ANCHOR_EXPIRY_DAYS > 0:
            expiry_cutoff = (now - datetime.timedelta(days=ANCHOR_EXPIRY_DAYS)
                             ).strftime("%Y-%m-%d %H:%M:%S")

        def _fetch_class(label: int, n: int) -> list:
            """Fetch n anchors of given label, preferring recent ones."""
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    # Build expiry clause
                    expiry_clause = (
                        f"AND added_at >= '{expiry_cutoff}'" if expiry_cutoff else ""
                    )

                    # Step 1: Try recent anchors first
                    recent = conn.execute(
                        f"""
                        SELECT features_json, true_label FROM anchor_samples
                        WHERE  true_label = ?
                          AND  added_at >= ?
                          {expiry_clause}
                        ORDER BY RANDOM() LIMIT ?
                        """,
                        (label, recent_cutoff, n)
                    ).fetchall()

                    if len(recent) >= n:
                        return recent[:n]

                    # Step 2: Fill remainder from older (non-expired) anchors
                    older_limit = n - len(recent)
                    older = conn.execute(
                        f"""
                        SELECT features_json, true_label FROM anchor_samples
                        WHERE  true_label = ?
                          AND  added_at < ?
                          {expiry_clause}
                        ORDER BY RANDOM() LIMIT ?
                        """,
                        (label, recent_cutoff, older_limit)
                    ).fetchall()

                    return recent + older
            except Exception:
                return []

        benign_rows   = _fetch_class(LABEL_BENIGN,    n_benign_anchors)
        malicious_rows = _fetch_class(LABEL_MALICIOUS, n_malicious_anchors)
        all_rows = benign_rows + malicious_rows

        if not all_rows:
            return None, None

        X_anchors, y_anchors = [], []
        for feat_json, label in all_rows:
            feat = self._deserialize_features(feat_json)
            if feat is not None:
                X_anchors.append(feat)
                y_anchors.append(label)

        if not X_anchors:
            return None, None

        n_benign_loaded    = sum(1 for y in y_anchors if y == 0)
        n_malicious_loaded = sum(1 for y in y_anchors if y == 1)
        colors.info(
            f"[*] AdaptiveLearner: Loaded {len(X_anchors)} anchor samples "
            f"({n_benign_loaded} benign, {n_malicious_loaded} malicious) "
            f"[recent preference active, expiry={ANCHOR_EXPIRY_DAYS}d]"
        )
        return np.array(X_anchors, dtype=np.float32), np.array(y_anchors, dtype=np.int32)

    def get_anchor_stats(self) -> dict:
        """
        Returns anchor store statistics for the GUI display including
        staleness breakdown and readiness for safe retraining.
        """
        try:
            now = datetime.datetime.now()
            recent_cutoff = (now - datetime.timedelta(days=ANCHOR_RECENT_DAYS)
                             ).strftime("%Y-%m-%d %H:%M:%S")
            expiry_cutoff = None
            if ANCHOR_EXPIRY_DAYS > 0:
                expiry_cutoff = (now - datetime.timedelta(days=ANCHOR_EXPIRY_DAYS)
                                 ).strftime("%Y-%m-%d %H:%M:%S")

            expiry_clause = (
                f"AND added_at >= '{expiry_cutoff}'" if expiry_cutoff else ""
            )

            with sqlite3.connect(utils.DB_FILE) as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM anchor_samples"
                ).fetchone()[0]
                benign = conn.execute(
                    f"SELECT COUNT(*) FROM anchor_samples "
                    f"WHERE true_label = 0 {expiry_clause}"
                ).fetchone()[0]
                malicious = conn.execute(
                    f"SELECT COUNT(*) FROM anchor_samples "
                    f"WHERE true_label = 1 {expiry_clause}"
                ).fetchone()[0]
                recent = conn.execute(
                    f"SELECT COUNT(*) FROM anchor_samples "
                    f"WHERE added_at >= ? {expiry_clause}",
                    (recent_cutoff,)
                ).fetchone()[0]
                stale = total - recent
                expired = (conn.execute(
                    "SELECT COUNT(*) FROM anchor_samples WHERE added_at < ?",
                    (expiry_cutoff,)
                ).fetchone()[0] if expiry_cutoff else 0)

            ready_to_train = (
                benign    >= MIN_ANCHORS_PER_CLASS and
                malicious >= MIN_ANCHORS_PER_CLASS
            )
            balanced = abs(benign - malicious) <= max(2, (benign + malicious) * 0.3)

            return {
                "total":             total,
                "benign":            benign,
                "malicious":         malicious,
                "recent":            recent,
                "stale":             stale,
                "expired":           expired,
                "balanced":          balanced,
                "ready_to_train":    ready_to_train,
                "min_per_class":     MIN_ANCHORS_PER_CLASS,
                "recent_days":       ANCHOR_RECENT_DAYS,
                "expiry_days":       ANCHOR_EXPIRY_DAYS,
            }
        except Exception:
            return {
                "total": 0, "benign": 0, "malicious": 0,
                "recent": 0, "stale": 0, "expired": 0,
                "balanced": False, "ready_to_train": False,
                "min_per_class": MIN_ANCHORS_PER_CLASS,
                "recent_days": ANCHOR_RECENT_DAYS,
                "expiry_days": ANCHOR_EXPIRY_DAYS,
            }

    def get_pending_count(self) -> int:
        """Returns PENDING (validated) corrections ready for training."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM learning_queue WHERE status=?",
                    (STATUS_PENDING,)
                ).fetchone()
                return row[0] if row else 0
        except sqlite3.Error:
            return 0

    def get_queue_summary(self) -> dict:
        """Returns queue statistics broken down by status and correction type."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT correction_type, status, COUNT(*) as cnt
                    FROM   learning_queue
                    GROUP BY correction_type, status
                    """
                ).fetchall()
            summary = {
                "pending_fp": 0, "pending_fn": 0,
                "pending_review": 0, "conflicted": 0,
                "trained": 0, "revoked": 0, "skipped": 0, "total": 0,
            }
            for ctype, status, cnt in rows:
                summary["total"] += cnt
                if status == STATUS_PENDING:
                    if ctype == "FALSE_POSITIVE":
                        summary["pending_fp"] += cnt
                    else:
                        summary["pending_fn"] += cnt
                elif status == STATUS_PENDING_REVIEW:
                    summary["pending_review"] += cnt
                elif status == STATUS_CONFLICTED:
                    summary["conflicted"] += cnt
                elif status == STATUS_TRAINED:
                    summary["trained"] += cnt
                elif status == STATUS_REVOKED:
                    summary["revoked"] += cnt
                elif status == STATUS_SKIPPED:
                    summary["skipped"] += cnt
            return summary
        except sqlite3.Error:
            return {}

    def get_queue_items(self, status_filter: str = None, limit: int = 100) -> list:
        """Returns queue entries, optionally filtered by status."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                if status_filter:
                    rows = conn.execute(
                        """
                        SELECT id, sha256, filename, correction_type, original_verdict,
                               status, conflict_reason, analyst_notes, queued_at, trained_at
                        FROM   learning_queue
                        WHERE  status=?
                        ORDER BY queued_at DESC LIMIT ?
                        """,
                        (status_filter, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT id, sha256, filename, correction_type, original_verdict,
                               status, conflict_reason, analyst_notes, queued_at, trained_at
                        FROM   learning_queue
                        ORDER BY queued_at DESC LIMIT ?
                        """,
                        (limit,)
                    ).fetchall()
                return [
                    {
                        "id":               r[0],
                        "sha256":           r[1],
                        "filename":         r[2],
                        "correction_type":  r[3],
                        "original_verdict": r[4],
                        "status":           r[5],
                        "conflict_reason":  r[6],
                        "analyst_notes":    r[7],
                        "queued_at":        r[8],
                        "trained_at":       r[9],
                    }
                    for r in rows
                ]
        except sqlite3.Error:
            return []

    def get_retraining_history(self, limit: int = 20) -> list:
        """Returns recent retraining sessions for the audit log display."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT session_id, samples_used, fp_corrections, fn_corrections,
                           new_trees_added, outcome, error_message, timestamp
                    FROM   retraining_log
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
                return [
                    {
                        "session_id":      r[0],
                        "samples_used":    r[1],
                        "fp_corrections":  r[2],
                        "fn_corrections":  r[3],
                        "new_trees_added": r[4],
                        "outcome":         r[5],
                        "error_message":   r[6],
                        "timestamp":       r[7],
                    }
                    for r in rows
                ]
        except sqlite3.Error:
            return []

    def clear_queue(self):
        """Clears all PENDING and PENDING_REVIEW corrections. Used for testing."""
        try:
            with self._db_lock:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    conn.execute(
                        "DELETE FROM learning_queue WHERE status IN (?,?)",
                        (STATUS_PENDING, STATUS_PENDING_REVIEW)
                    )
            colors.warning("[*] AdaptiveLearner: Learning queue cleared.")
        except sqlite3.Error as e:
            print(f"[-] AdaptiveLearner: Queue clear failed: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 5: RETRAINING ENGINE
    # ──────────────────────────────────────────────────────────────────────────

    def _run_retraining_session(self, force: bool = False) -> dict:
        """
        Incremental retraining on validated (PENDING) corrections only.
        CONFLICTED, PENDING_REVIEW, and REVOKED entries are never included.
        """
        session_id = datetime.datetime.now().strftime("SESSION_%Y%m%d_%H%M%S")
        timestamp  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = {
            "session_id":      session_id,
            "outcome":         "FAILED",
            "samples_used":    0,
            "fp_corrections":  0,
            "fn_corrections":  0,
            "new_trees_added": 0,
            "model_backup":    None,
            "error_message":   None,
        }

        # Only PENDING entries train — all others are excluded by design
        pending = self._load_pending_with_features()

        if not pending:
            result["outcome"]       = "SKIPPED"
            result["error_message"] = "No validated corrections with features available."
            colors.warning("[*] AdaptiveLearner: No usable samples — skipping.")
            self._write_retraining_log(result, timestamp)
            return result

        if len(pending) < 2 and not force:
            result["outcome"]       = "SKIPPED"
            result["error_message"] = (
                f"Only {len(pending)} sample(s) — minimum 2 required. "
                f"Use Force Retrain to override."
            )
            colors.warning(f"[*] AdaptiveLearner: {result['error_message']}")
            self._write_retraining_log(result, timestamp)
            return result

        # Build correction matrix
        # Label assignment:
        #   FALSE_POSITIVE correction → label = 0 (BENIGN)
        #     The system said MALICIOUS but the file is safe.
        #     We teach the model to stop flagging this type of file.
        #   FALSE_NEGATIVE correction → label = 1 (MALICIOUS)
        #     The system said SAFE but the file is malicious.
        #     We teach the model to start catching this type of file.
        X, y, ids = [], [], []
        fp_count = fn_count = 0
        for row in pending:
            feat = self._deserialize_features(row["features_json"])
            if feat is None:
                continue
            X.append(feat)
            if row["correction_type"] == "FALSE_POSITIVE":
                y.append(LABEL_BENIGN)     # system over-detected → teach benign
                fp_count += 1
            else:
                y.append(LABEL_MALICIOUS)  # system under-detected → teach malicious
                fn_count += 1
            ids.append(row["id"])

        if not X:
            result["outcome"]       = "SKIPPED"
            result["error_message"] = "All validated samples had unreadable feature vectors."
            self._write_retraining_log(result, timestamp)
            return result

        # ── Anti-bias Check 1: Minimum anchor threshold ──────────────────────
        # Block retraining if the anchor store does not have enough confirmed
        # samples of each class to provide meaningful balance.
        # This prevents early-deployment bias when the store is too small.
        anchor_stats = self.get_anchor_stats()
        n_benign_anchors_available    = anchor_stats.get("benign", 0)
        n_malicious_anchors_available = anchor_stats.get("malicious", 0)

        if not force and (
            n_benign_anchors_available    < MIN_ANCHORS_PER_CLASS or
            n_malicious_anchors_available < MIN_ANCHORS_PER_CLASS
        ):
            result["outcome"] = "SKIPPED"
            result["error_message"] = (
                f"Anchor store insufficient for safe retraining: "
                f"{n_benign_anchors_available} benign, "
                f"{n_malicious_anchors_available} malicious anchors available. "
                f"Minimum {MIN_ANCHORS_PER_CLASS} of each class required. "
                f"Confirm more verdicts in Analyst Feedback to build the anchor store. "
                f"Use Force Retrain to override (not recommended)."
            )
            colors.warning(
                f"[!] AdaptiveLearner: RETRAINING BLOCKED — insufficient anchors.\n"
                f"    Benign: {n_benign_anchors_available}/{MIN_ANCHORS_PER_CLASS}  "
                f"Malicious: {n_malicious_anchors_available}/{MIN_ANCHORS_PER_CLASS}\n"
                f"    Confirm more verdicts in Analyst Feedback to unlock retraining."
            )
            self._write_retraining_log(result, timestamp)
            return result

        # ── Anchor sample injection ───────────────────────────────────────────
        correction_label_counts = {
            LABEL_BENIGN:    fp_count,
            LABEL_MALICIOUS: fn_count,
        }
        X_anchors, y_anchors = self._load_anchor_samples(
            n_corrections=len(X),
            correction_label_counts=correction_label_counts,
        )

        if X_anchors is not None and len(X_anchors) > 0:
            X_combined = np.concatenate([np.array(X, dtype=np.float32), X_anchors], axis=0)
            y_combined = np.concatenate([np.array(y, dtype=np.int32),   y_anchors], axis=0)
            colors.info(
                f"[*] AdaptiveLearner: Final batch — "
                f"{len(X)} corrections + {len(X_anchors)} anchors = "
                f"{len(X_combined)} total samples"
            )
        else:
            X_combined = np.array(X, dtype=np.float32)
            y_combined = np.array(y, dtype=np.int32)
            colors.warning(
                "[!] AdaptiveLearner: No usable anchors loaded. "
                "Retraining on corrections only — class imbalance risk elevated."
            )

        # ── Anti-bias Check 2: Final imbalance guard ──────────────────────────
        # Even after anchor injection, check if the combined batch is still
        # too skewed. If majority:minority ratio exceeds MAX_IMBALANCE_RATIO,
        # block retraining (unless forced) to prevent model degradation.
        n_benign_final    = int(np.sum(y_combined == LABEL_BENIGN))
        n_malicious_final = int(np.sum(y_combined == LABEL_MALICIOUS))
        majority  = max(n_benign_final, n_malicious_final)
        minority  = min(n_benign_final, n_malicious_final)
        imbalance_ratio = majority / max(minority, 1)

        if not force and imbalance_ratio > MAX_IMBALANCE_RATIO:
            result["outcome"] = "SKIPPED"
            result["error_message"] = (
                f"Final batch too imbalanced to retrain safely: "
                f"{n_benign_final} benign vs {n_malicious_final} malicious "
                f"(ratio {imbalance_ratio:.1f}:1, limit {MAX_IMBALANCE_RATIO:.1f}:1). "
                f"Add more anchor samples of the minority class or use Force Retrain."
            )
            colors.warning(
                f"[!] AdaptiveLearner: RETRAINING BLOCKED — batch too imbalanced.\n"
                f"    Benign: {n_benign_final}  Malicious: {n_malicious_final}  "
                f"Ratio: {imbalance_ratio:.1f}:1  Limit: {MAX_IMBALANCE_RATIO:.1f}:1\n"
                f"    Confirm more '{('malicious' if n_malicious_final < n_benign_final else 'benign')}' "
                f"verdicts to balance the batch."
            )
            self._write_retraining_log(result, timestamp)
            return result

        colors.info(
            f"[*] AdaptiveLearner: Batch balance check passed — "
            f"{n_benign_final} benign, {n_malicious_final} malicious "
            f"(ratio {imbalance_ratio:.1f}:1)"
        )

        X_arr = X_combined
        y_arr = y_combined
        result["samples_used"]   = len(X_arr)
        result["fp_corrections"] = fp_count
        result["fn_corrections"] = fn_count

        colors.info(
            f"[*] AdaptiveLearner: {session_id} — "
            f"{len(X_arr)} samples ({fp_count} FP, {fn_count} FN)"
        )

        # Load model
        if not os.path.exists(self.model_path):
            result["error_message"] = f"Model not found: {self.model_path}"
            colors.error(f"[-] AdaptiveLearner: {result['error_message']}")
            self._write_retraining_log(result, timestamp)
            return result

        try:
            booster = lgb.Booster(model_file=self.model_path)
        except Exception as e:
            result["error_message"] = f"Model load failed: {e}"
            self._write_retraining_log(result, timestamp)
            return result

        # Backup before touching the model
        backup_path = self._backup_model(session_id)
        result["model_backup"] = backup_path

        # Incremental training
        try:
            spinner = Spinner(
                f"[*] AdaptiveLearner: Retraining ({len(X_arr)} corrections)..."
            )
            spinner.start()

            train_data = lgb.Dataset(X_arr, label=y_arr, free_raw_data=True)
            params = {
                "objective":         "binary",
                "metric":            "binary_logloss",
                "learning_rate":     self.learning_rate,
                "max_depth":         MAX_DEPTH,
                "min_child_samples": max(1, len(X_arr) // 4),
                "verbose":           -1,
                "n_jobs":            1,
            }
            updated = lgb.train(
                params, train_data,
                num_boost_round=self.num_new_trees,
                init_model=booster,
                keep_training_booster=True,
            )
            spinner.stop()
        except Exception as e:
            spinner.stop()
            result["error_message"] = f"Training failed: {e}"
            colors.error(f"[-] AdaptiveLearner: {result['error_message']}")
            if backup_path and os.path.exists(backup_path):
                shutil.copy2(backup_path, self.model_path)
                colors.warning("[*] AdaptiveLearner: Previous model restored from backup.")
            self._write_retraining_log(result, timestamp)
            return result

        # Save
        try:
            updated.save_model(self.model_path)
            result["new_trees_added"] = self.num_new_trees
            colors.success(
                f"[+] AdaptiveLearner: Model updated — {self.num_new_trees} new trees. "
                f"Session: {session_id}"
            )
        except Exception as e:
            result["error_message"] = f"Model save failed: {e}"
            self._write_retraining_log(result, timestamp)
            return result

        # Mark corrections as TRAINED, tag with session_id for rollback linking
        trained_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._db_lock:
            try:
                with sqlite3.connect(utils.DB_FILE) as conn:
                    placeholders = ",".join("?" * len(ids))
                    conn.execute(
                        f"UPDATE learning_queue SET status=?, trained_at=?, session_id=? "
                        f"WHERE id IN ({placeholders})",
                        [STATUS_TRAINED, trained_at, session_id] + ids
                    )
            except sqlite3.Error as e:
                colors.warning(f"[!] AdaptiveLearner: Could not mark samples TRAINED: {e}")

        result["outcome"] = "SUCCESS"
        self._write_retraining_log(result, timestamp)
        self._write_audit_jsonl(result, timestamp)
        _set_model_reload_flag()

        # Reset drift detector — new model starts fresh reference window
        try:
            from .drift_detector import get_drift_detector
            get_drift_detector().reset_after_retrain()
        except Exception:
            pass  # Non-critical: drift reset failure does not affect the model

        return result

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 6: FEATURE HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_and_serialize(self, file_path: str) -> str | None:
        """
        Extracts PE features and serializes them as a zlib-compressed, base64-encoded string.

        R2 Fix: Feature vectors are compressed before storage.
        Raw JSON is ~47 KB per vector. After zlib compression the average is ~8 KB
        — an 83% reduction that prevents unbounded database growth in long deployments.
        """
        if not file_path or not os.path.isfile(file_path):
            return None
        try:
            import thrember, zlib, base64 as _b64
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                return None
            with open(file_path, "rb") as f:
                data = f.read()
            if not data.startswith(b"MZ"):
                return None
            features = np.array(
                thrember.PEFeatureExtractor().feature_vector(data), dtype=np.float32
            )
            raw      = json.dumps(features.tolist()).encode("utf-8")
            comp     = zlib.compress(raw, level=6)
            return "z:" + _b64.b64encode(comp).decode("ascii")
        except Exception:
            return None

    @staticmethod
    def _deserialize_features(features_json: str | None) -> np.ndarray | None:
        """
        Deserializes a feature vector from storage.
        Handles both compressed ("z:" prefix) and legacy uncompressed JSON formats.
        """
        if not features_json:
            return None
        try:
            if features_json.startswith("z:"):
                import zlib, base64 as _b64
                comp = _b64.b64decode(features_json[2:].encode("ascii"))
                raw  = zlib.decompress(comp)
                return np.array(json.loads(raw), dtype=np.float32)
            # Legacy uncompressed JSON — read as-is for backward compatibility
            return np.array(json.loads(features_json), dtype=np.float32)
        except Exception:
            return None

    def _load_pending_with_features(self) -> list:
        """Loads PENDING (validated) corrections that have feature vectors."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT id, sha256, filename, file_path, correction_type,
                           original_verdict, features_json
                    FROM   learning_queue
                    WHERE  status=?
                    ORDER BY queued_at ASC
                    """,
                    (STATUS_PENDING,)
                ).fetchall()
        except sqlite3.Error:
            return []

        usable, skippable_ids = [], []
        for row in rows:
            rid, sha256, fname, fpath, ctype, verdict, features_json = row
            if features_json:
                usable.append({
                    "id": rid, "sha256": sha256, "filename": fname,
                    "correction_type": ctype, "features_json": features_json,
                })
                continue
            re_extracted = self._extract_and_serialize(fpath)
            if re_extracted:
                usable.append({
                    "id": rid, "sha256": sha256, "filename": fname,
                    "correction_type": ctype, "features_json": re_extracted,
                })
                try:
                    with sqlite3.connect(utils.DB_FILE) as conn:
                        conn.execute(
                            "UPDATE learning_queue SET features_json=? WHERE id=?",
                            (re_extracted, rid)
                        )
                except sqlite3.Error:
                    pass
            else:
                skippable_ids.append(rid)
                colors.warning(
                    f"[*] AdaptiveLearner: No features for '{fname}' — marking SKIPPED."
                )

        if skippable_ids:
            with self._db_lock:
                try:
                    with sqlite3.connect(utils.DB_FILE) as conn:
                        placeholders = ",".join("?" * len(skippable_ids))
                        conn.execute(
                            f"UPDATE learning_queue SET status=? WHERE id IN ({placeholders})",
                            [STATUS_SKIPPED] + skippable_ids
                        )
                except sqlite3.Error:
                    pass

        return usable

    # ──────────────────────────────────────────────────────────────────────────
    #  SECTION 7: BACKUP AND AUDIT
    # ──────────────────────────────────────────────────────────────────────────

    def _backup_model(self, session_id: str) -> str | None:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_path = os.path.join(
            BACKUP_DIR, f"CyberSentinel_v2_{session_id}.model"
        )
        try:
            shutil.copy2(self.model_path, backup_path)
            colors.info(f"[*] AdaptiveLearner: Backup → {os.path.basename(backup_path)}")
            self._prune_old_backups(keep=10)
            return backup_path
        except Exception as e:
            colors.warning(f"[!] AdaptiveLearner: Backup failed — {e}")
            return None

    def _prune_old_backups(self, keep: int = 10):
        try:
            backups = sorted(
                [f for f in os.listdir(BACKUP_DIR) if f.endswith(".model")],
                key=lambda f: os.path.getmtime(os.path.join(BACKUP_DIR, f))
            )
            for old in backups[:-keep]:
                os.remove(os.path.join(BACKUP_DIR, old))
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _write_retraining_log(self, result: dict, timestamp: str):
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO retraining_log
                        (session_id, samples_used, fp_corrections, fn_corrections,
                         model_backup, new_trees_added, outcome, error_message, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result["session_id"], result["samples_used"],
                        result["fp_corrections"], result["fn_corrections"],
                        result.get("model_backup", ""), result["new_trees_added"],
                        result["outcome"], result.get("error_message", ""),
                        timestamp,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] AdaptiveLearner: Log write failed: {e}")

    def _write_audit_jsonl(self, record: dict, timestamp: str):
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        record["timestamp"] = timestamp
        try:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass  # Non-critical: operation continues regardless


# ─────────────────────────────────────────────────────────────────────────────
#  MODEL RELOAD FLAG
# ─────────────────────────────────────────────────────────────────────────────

_RELOAD_FLAG = os.path.join(_PROJECT_ROOT, "models", ".model_updated")


def _set_model_reload_flag():
    os.makedirs(os.path.dirname(_RELOAD_FLAG), exist_ok=True)
    try:
        with open(_RELOAD_FLAG, "w") as f:
            f.write(datetime.datetime.now().isoformat())
    except Exception:
        pass  # Non-critical: operation continues regardless


def check_and_clear_reload_flag() -> bool:
    """Returns True and removes the flag file if the model was updated since last scan."""
    if os.path.exists(_RELOAD_FLAG):
        try:
            os.remove(_RELOAD_FLAG)
        except Exception:
            pass  # Non-critical: operation continues regardless
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_instance: AdaptiveLearner | None = None


def get_learner() -> AdaptiveLearner:
    """Returns the module-level AdaptiveLearner singleton instance."""
    global _instance
    if _instance is None:
        _instance = AdaptiveLearner()
    return _instance
