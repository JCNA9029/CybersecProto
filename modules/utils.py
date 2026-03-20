# modules/utils.py
#
# Shared utility library used by all CyberSentinel modules.
#
# Sections:
#   1. Hardware-bound Fernet encryption  (AES-128-CBC + HMAC-SHA256, PBKDF2 key)
#   2. Configuration persistence         (encrypted API keys, webhook URL)
#   3. SOC webhook dispatcher            (Discord, Slack, Teams compatible)
#   4. Network and file utilities        (connectivity check, SHA-256 hashing)
#   5. SQLite database management        (schema init, cache read/write)
#
# Security model:
#   API keys are encrypted with a key derived from the machine's hardware MAC address
#   via PBKDF2-HMAC-SHA256 (100,000 iterations). The encrypted config.json file
#   cannot be decrypted on any other machine.

import hashlib
import socket
import json
import os
import base64
import binascii
import uuid
import sqlite3
import datetime
import requests
from typing import Optional

# Resolve all data file paths relative to the project root (modules/../)
# so they work regardless of which directory Python is launched from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(_PROJECT_ROOT, "config.json")
DB_FILE     = os.path.join(_PROJECT_ROOT, "threat_cache.db")


# ─────────────────────────────────────────────
#  SECTION 1: HARDWARE-BOUND FERNET ENCRYPTION
# ─────────────────────────────────────────────

def _get_fernet():
    """
    Derives a hardware-bound Fernet cipher using PBKDF2-HMAC-SHA256.
    The MAC address acts as the password, making config files non-portable.
    Returns None if the cryptography package is missing (graceful degradation).
    """
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        hardware_id = str(uuid.getnode()).encode()
        # Fixed salt is acceptable here: the security goal is hardware binding,
        # not password hashing. The salt prevents offline dictionary attacks on
        # the tiny MAC address space.
        salt = b"CyberSentinel_HW_Salt_v2"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(hardware_id))
        return Fernet(key)
    except ImportError:
        return None


def _legacy_get_machine_key() -> bytes:
    """Retained ONLY for migrating old XOR-encrypted configs. Do not use for new data."""
    return hashlib.sha256(str(uuid.getnode()).encode()).digest()


def _legacy_decrypt(encrypted_key: str) -> str:
    """Decrypts a config saved by the old XOR+Base64 scheme for one-time migration."""
    if not encrypted_key:
        return ""
    try:
        enc_bytes = base64.b64decode(encrypted_key)
        dynamic_key = _legacy_get_machine_key()
        xored = bytes(
            a ^ b
            for a, b in zip(enc_bytes, dynamic_key * (len(enc_bytes) // len(dynamic_key) + 1))
        )
        return xored.decode("utf-8")
    except Exception:
        return ""


def encrypt_key(api_key: str) -> str:
    """
    Encrypts an API key with Fernet (AES-128-CBC + HMAC).
    Output is prefixed 'v1:' so decrypt_key can identify the scheme.
    Falls back to the legacy XOR scheme if cryptography is not installed.
    """
    if not api_key:
        return ""

    f = _get_fernet()
    if f:
        try:
            return "v2:" + f.encrypt(api_key.encode()).decode()
        except Exception:
            pass  # Non-critical: operation continues regardless

    # Fallback: legacy XOR (warn user to install cryptography)
    print("[!] Warning: 'cryptography' package missing. Using weak XOR fallback. Run: pip install cryptography")
    dynamic_key = _legacy_get_machine_key()
    api_bytes = api_key.encode("utf-8")
    xored = bytes(
        a ^ b
        for a, b in zip(api_bytes, dynamic_key * (len(api_bytes) // len(dynamic_key) + 1))
    )
    return base64.b64encode(xored).decode("utf-8")


def decrypt_key(encrypted_key: str) -> str:
    """
    Decrypts a key, automatically handling both v2 (Fernet) and legacy (XOR) formats.
    Old configs are transparently readable — the next save() call will upgrade them.
    """
    if not encrypted_key:
        return ""

    if encrypted_key.startswith("v2:"):
        f = _get_fernet()
        if f:
            try:
                return f.decrypt(encrypted_key[3:].encode()).decode()
            except Exception:
                # SECURITY: Token invalid = tampered or different hardware.
                print("[-] Security Warning: Config decryption failed. File may be tampered or copied from another machine.")
                return ""
        print("[-] Cannot decrypt v2 config: 'cryptography' package not installed.")
        return ""

    # Legacy XOR path — migrate silently
    return _legacy_decrypt(encrypted_key)


# ─────────────────────────────────────────────
#  SECTION 2: CONFIG PERSISTENCE
# ─────────────────────────────────────────────

def load_config() -> dict:
    """Reads and decrypts all API keys, webhook URL, and LLM model from disk."""
    config_data = {"api_keys": {}, "webhook_url": "", "llm_model": "qwen2.5:3b"}
    if not os.path.exists(CONFIG_FILE):
        return config_data

    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)

        keys = data.get("api_keys", {})

        # Backward compatibility: single VT key from original format
        if "api_key" in data and not keys:
            keys["virustotal"] = data.get("api_key", "")

        config_data["api_keys"]   = {k: decrypt_key(v) for k, v in keys.items() if v}
        config_data["webhook_url"] = decrypt_key(data.get("webhook_url", ""))
        # LLM model is stored in plain text — not sensitive
        config_data["llm_model"]   = data.get("llm_model", "qwen2.5:3b") or "qwen2.5:3b"
    except Exception:
        pass  # Non-critical: operation continues regardless

    return config_data


def save_config(
    api_keys:   dict,
    webhook_url: str = "",
    llm_model:  str = "qwen2.5:3b",
) -> bool:
    """Encrypts all API keys with Fernet and writes them + LLM model to disk."""
    try:
        encrypted_keys = {k: encrypt_key(v) for k, v in api_keys.items() if v}
        with open(CONFIG_FILE, "w") as f:
            json.dump(
                {
                    "api_keys":   encrypted_keys,
                    "webhook_url": encrypt_key(webhook_url),
                    "llm_model":  llm_model or "qwen2.5:3b",
                },
                f,
                indent=2,
            )
        return True
    except Exception as e:
        print(f"[-] Failed to save configuration: {e}")
        return False


def ollama_list_models() -> list[str]:
    """
    Returns a sorted list of locally available Ollama model names by
    calling `ollama list` as a subprocess.

    Returns an empty list if Ollama is not installed or not running.
    Each entry is the model tag exactly as Ollama reports it,
    e.g. ['deepseek-r1:8b', 'qwen2.5:3b', 'qwen2.5:7b'].
    """
    import subprocess
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        models = []
        for line in result.stdout.splitlines()[1:]:   # skip header row
            parts = line.split()
            if parts:
                models.append(parts[0])              # first column is NAME:TAG
        return sorted(models)
    except Exception:
        return []


# ─────────────────────────────────────────────
#  SECTION 3: SOC WEBHOOK
# ─────────────────────────────────────────────

def send_webhook_alert(webhook_url: str, title: str, details: dict) -> bool:
    """
    Dispatches a JSON telemetry payload to a Discord/Slack/Teams SOC webhook.
    Returns True on HTTP 2xx success, False on any failure.
    Capped at 5-second timeout so it never blocks the EDR pipeline.

    Security:
        - Only HTTPS URLs are accepted (prevents plaintext credential leakage)
        - Private/loopback/metadata IP ranges are blocked (SSRF protection)
    """
    if not webhook_url:
        return False

    # Fix: SSRF protection — only allow HTTPS to public addresses
    if not webhook_url.startswith("https://"):
        print("[-] Webhook rejected: only HTTPS URLs are permitted.")
        return False
    try:
        import urllib.parse
        host = urllib.parse.urlparse(webhook_url).hostname or ""
        blocked_prefixes = (
            "localhost", "127.", "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "169.254.",   # Link-local / AWS metadata endpoint
            "0.0.0.0",
        )
        blocked_hosts = {"localhost", "::1", "[::1]"}
        if host in blocked_hosts or any(host.startswith(p) for p in blocked_prefixes):
            print(f"[-] Webhook rejected: private/loopback address blocked ({host}).")
            return False
    except Exception:
        print("[-] Webhook rejected: URL parsing failed.")
        return False

    # Discord expects "embeds"; Slack/Teams/generic expect "text" or "body".
    # We send both so the payload works across all three platforms.
    fields = [
        {"name": str(k), "value": str(v)[:1024], "inline": False}
        for k, v in details.items()
    ]
    payload = {
        # Discord / Slack legacy webhook
        "content": f"🚨 **{title}**",
        "embeds": [
            {
                "title": title,
                "color": 16711680,  # red
                "fields": fields,
                "footer": {"text": "CyberSentinel EDR"},
            }
        ],
        # Slack Block Kit / Teams fallback
        "text": title + "\n" + "\n".join(f"{k}: {v}" for k, v in details.items()),
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        # Discord returns 204, Slack returns "ok", Teams returns 1
        return resp.status_code in (200, 204)
    except requests.exceptions.ConnectionError:
        print("[-] Webhook: Connection refused — is the URL reachable?")
        return False
    except requests.exceptions.Timeout:
        print("[-] Webhook: Request timed out after 5 s.")
        return False
    except Exception as e:
        print(f"[-] Webhook: Unexpected error — {e}")
        return False


# ─────────────────────────────────────────────
#  SECTION 4: NETWORK & FILE UTILITIES
# ─────────────────────────────────────────────

def check_internet(host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
    """Pings Google DNS to verify external network routing."""
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
        return True
    except socket.error:
        return False


def get_sha256(file_path: str) -> Optional[str]:
    """
    Generates SHA-256 via 4096-byte chunked reading.
    Chunking ensures large files don't spike RAM. Returns None on I/O error.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def sanitize_path(path: str) -> str:
    """Strips hidden characters and quotes from terminal drag-and-drop operations."""
    if not path:
        return ""
    return path.strip().lstrip("& ").strip("'\"").strip()


# ─────────────────────────────────────────────
#  SECTION 5: SQLITE DATABASE MANAGEMENT
# ─────────────────────────────────────────────

def init_db():
    """
    Initialises all SQLite tables on startup.
    Uses CREATE TABLE IF NOT EXISTS so it is idempotent and safe to call repeatedly.
    Adds analyst_feedback table for the feedback loop module.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_cache (
                    sha256    TEXT PRIMARY KEY,
                    filename  TEXT,
                    verdict   TEXT,
                    timestamp TEXT,
                    apis      TEXT
                )
            """)
            # Analyst feedback table — powers the learning loop
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256           TEXT    NOT NULL,
                    filename         TEXT,
                    original_verdict TEXT,
                    analyst_verdict  TEXT,
                    notes            TEXT,
                    timestamp        TEXT
                )
            """)
            # Feature 1+2: LolBin and BYOVD driver alerts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS driver_alerts (
                    sha256       TEXT PRIMARY KEY,
                    driver_name  TEXT,
                    path         TEXT,
                    cve          TEXT,
                    description  TEXT,
                    timestamp    TEXT
                )
            """)
            # Feature 3: C2 fingerprinting alerts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS c2_alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_type  TEXT,
                    indicator       TEXT,
                    malware_family  TEXT,
                    details         TEXT,
                    timestamp       TEXT
                )
            """)
            # Feature 4: Behavioral chain correlation
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_timeline (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    detail     TEXT,
                    pid        INTEGER,
                    timestamp  TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_name   TEXT,
                    mitre        TEXT,
                    severity     TEXT,
                    description  TEXT,
                    window_start TEXT,
                    timestamp    TEXT
                )
            """)
            # Feature 5: Environment baseline
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baseline_profiles (
                    sha256       TEXT PRIMARY KEY,
                    process_name TEXT,
                    seen_count   INTEGER DEFAULT 1,
                    paths_json   TEXT,
                    last_seen    TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baseline_network (
                    process_sha256 TEXT,
                    dest_ip        TEXT,
                    PRIMARY KEY (process_sha256, dest_ip)
                )
            """)
            # Feature 6: Fileless/AMSI alerts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fileless_alerts (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    source    TEXT,
                    findings  TEXT,
                    pid       INTEGER,
                    timestamp TEXT
                )
            """)
            # Anchor samples — balanced ground truth for retraining stability
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anchor_samples (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256        TEXT    UNIQUE NOT NULL,
                    filename      TEXT,
                    true_label    INTEGER NOT NULL,
                    features_json TEXT    NOT NULL,
                    source        TEXT,
                    added_at      TEXT    NOT NULL
                )
            """)
            # Novel Feature 2: SHAP explainability results
            conn.execute("""
                CREATE TABLE IF NOT EXISTS shap_explanations (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256          TEXT    NOT NULL,
                    filename        TEXT,
                    verdict         TEXT,
                    score           REAL,
                    top_features    TEXT,
                    group_summary   TEXT,
                    timestamp       TEXT    NOT NULL
                )
            """)
            # Novel Feature 3: Dynamic Risk Score history
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_scores (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256          TEXT    NOT NULL,
                    filename        TEXT,
                    base_verdict    TEXT,
                    base_score      REAL,
                    dynamic_score   REAL,
                    risk_level      TEXT,
                    components      TEXT,
                    timestamp       TEXT    NOT NULL
                )
            """)
            # Novel Feature 4: Concept drift alerts and ML score log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS drift_alerts (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type        TEXT    NOT NULL,
                    reference_mean    REAL    NOT NULL,
                    current_mean      REAL    NOT NULL,
                    drift_magnitude   REAL    NOT NULL,
                    ph_statistic      REAL,
                    samples_analyzed  INTEGER NOT NULL,
                    recommendation    TEXT,
                    timestamp         TEXT    NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ml_score_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256    TEXT    NOT NULL,
                    filename  TEXT,
                    verdict   TEXT    NOT NULL,
                    score     REAL    NOT NULL,
                    timestamp TEXT    NOT NULL
                )
            """)
            # Feature 7: Adaptive learning — correction queue and retraining audit log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learning_queue (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256           TEXT    NOT NULL,
                    filename         TEXT,
                    file_path        TEXT,
                    correction_type  TEXT    NOT NULL,
                    original_verdict TEXT    NOT NULL,
                    analyst_notes    TEXT,
                    features_json    TEXT,
                    status           TEXT    DEFAULT 'PENDING',
                    queued_at        TEXT    NOT NULL,
                    trained_at       TEXT
                )
            """)
            conn.execute("""
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
            """)
    except sqlite3.Error as e:
        print(f"[-] Threat Cache Initialization Failed: {e}")


def save_cached_result(
    sha256:        str,
    verdict:       str,
    filename:      str = "Unknown",
    detected_apis: list | None = None,
):
    """
    Commits a scan verdict to the local SQLite cache.

    detected_apis: list of high-risk Windows API names found in the IAT
    (from ml_engine.get_suspicious_apis). Persisted so the AI analyst report
    can reference them on cache-hit re-scans without re-running the ML engine.
    """
    apis_json = json.dumps(detected_apis or [])
    try:
        with sqlite3.connect(DB_FILE) as conn:
            # Migrate existing table if apis column is missing
            cols = {r[1] for r in conn.execute(
                "PRAGMA table_info(scan_cache)"
            ).fetchall()}
            if "apis" not in cols:
                conn.execute("ALTER TABLE scan_cache ADD COLUMN apis TEXT")
            conn.execute(
                """INSERT OR REPLACE INTO scan_cache
                   (sha256, filename, verdict, timestamp, apis)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    sha256, filename, verdict,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    apis_json,
                ),
            )
    except sqlite3.Error:
        pass


def get_cached_result(sha256: str) -> Optional[dict]:
    """
    Retrieves a cached scan verdict with full forensic context including
    any detected API calls stored from the original ML scan.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute(
                "SELECT verdict, filename, timestamp, apis FROM scan_cache WHERE sha256 = ?",
                (sha256,)
            ).fetchone()
            if row:
                try:
                    apis = json.loads(row[3]) if row[3] else []
                except Exception:
                    apis = []
                return {
                    "verdict":       row[0],
                    "source":        row[1],
                    "timestamp":     row[2],
                    "detected_apis": apis,
                }
    except sqlite3.Error as e:
        print(f"[-] Cache Read Error: {e}")
    return None


def get_all_cached_results() -> list:
    """Returns all cached scan records for the dashboard and cache viewer."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            rows = conn.execute(
                "SELECT sha256, filename, verdict, timestamp FROM scan_cache ORDER BY timestamp DESC"
            ).fetchall()
            return [{"sha256": r[0], "filename": r[1], "verdict": r[2], "timestamp": r[3]} for r in rows]
    except sqlite3.Error:
        return []


def is_excluded(file_path: str) -> bool:
    """
    Checks whether the target path matches any administrator-defined allowlist entry.
    Auto-creates an exclusions.txt template on first run.
    """
    exclusion_file = "exclusions.txt"

    if not os.path.exists(exclusion_file):
        try:
            with open(exclusion_file, "w") as f:
                f.write("# CyberSentinel Enterprise Exclusion List\n")
                f.write("# Add directory or file paths below to bypass scanning.\n")
                f.write("# Example: C:\\Program Files\\MySafeCompany\\\n")
        except Exception:
            pass  # Non-critical: operation continues regardless
        return False

    try:
        with open(exclusion_file, "r") as f:
            exclusions = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        target_path = file_path.lower()
        return any(exc in target_path for exc in exclusions)
    except Exception:
        return False

def prune_old_records(days: int = 90):
    """
    Removes records older than N days from high-volume tables to prevent
    unbounded database growth in long-running daemon deployments.

    Tables pruned: ml_score_log, shap_explanations, risk_scores, event_timeline.
    Tables preserved: scan_cache, analyst_feedback, learning_queue, anchor_samples,
                      chain_alerts, driver_alerts (audit trail — never auto-pruned).
    Calls VACUUM after pruning to reclaim disk space.
    """
    cutoff = (
        datetime.datetime.now() - datetime.timedelta(days=days)
    ).strftime("%Y-%m-%d %H:%M:%S")

    HIGH_VOLUME_TABLES = [
        ("ml_score_log",      "timestamp"),
        ("shap_explanations", "timestamp"),
        ("risk_scores",       "timestamp"),
        ("event_timeline",    "timestamp"),
        ("retraining_log",    "timestamp"),
    ]
    try:
        with sqlite3.connect(DB_FILE) as conn:
            total_deleted = 0
            for table, col in HIGH_VOLUME_TABLES:
                try:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)
                    )
                    total_deleted += cursor.rowcount
                except sqlite3.OperationalError:
                    pass  # Table may not exist yet — skip
            if total_deleted > 0:
                conn.execute("VACUUM")
                print(f"[+] DB pruning: removed {total_deleted} records older than {days} days.")
    except sqlite3.Error as e:
        print(f"[-] DB pruning failed: {e}")

