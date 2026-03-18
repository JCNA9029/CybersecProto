# modules/intel_updater.py — Threat Intelligence Feed Manager
#
# Downloads and caches four open-source threat intelligence datasets:
#   1. LOLBAS Project  — Living-off-the-Land binary abuse patterns
#   2. LOLDrivers      — Known-vulnerable signed Windows drivers
#   3. Abuse.ch JA3    — Malicious TLS client fingerprints
#   4. Feodo Tracker   — Active C2 botnet IP blocklist
#
# All feeds are cached as local JSON/CSV files under ./intel/
# so the app operates fully offline after first update.

import os
import json
import datetime
import requests

INTEL_DIR = "intel"
LOLBAS_PATH    = os.path.join(INTEL_DIR, "lolbas.json")
LOLDRIVERS_PATH = os.path.join(INTEL_DIR, "loldrivers.json")
JA3_PATH       = os.path.join(INTEL_DIR, "ja3_blocklist.csv")
FEODO_PATH     = os.path.join(INTEL_DIR, "feodo_blocklist.json")
META_PATH      = os.path.join(INTEL_DIR, "update_meta.json")

FEEDS = {
    "lolbas":    "https://lolbas-project.github.io/api/lolbas.json",
    "loldrivers":"https://www.loldrivers.io/api/drivers.json",
    "ja3":       "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "feodo":     "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}

TIMEOUT = 15   # seconds per feed download

# Minimum acceptable response sizes (bytes) — responses smaller than this
# indicate a compromised, empty, or error response and are rejected.
MIN_FEED_SIZES = {
    "lolbas":     10_000,
    "loldrivers": 50_000,
    "ja3":         1_000,
    "feodo":       5_000,
}

# Feed content types — used to validate the response is parseable
# before overwriting the cached copy.
_JSON_FEEDS = {"lolbas", "loldrivers", "feodo"}
_CSV_FEEDS  = {"ja3"}


def _ensure_intel_dir():
    os.makedirs(INTEL_DIR, exist_ok=True)


def _load_meta() -> dict:
    if os.path.exists(META_PATH):
        try:
            with open(META_PATH) as f:
                return json.load(f)
        except Exception:
            pass  # Non-critical: operation continues regardless
    return {}


def _save_meta(meta: dict):
    try:
        with open(META_PATH, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass  # Non-critical: operation continues regardless


def _needs_update(meta: dict, feed_name: str, max_age_hours: int = 24) -> bool:
    last = meta.get(feed_name)
    if not last:
        return True
    try:
        delta = datetime.datetime.now() - datetime.datetime.fromisoformat(last)
        return delta.total_seconds() > max_age_hours * 3600
    except Exception:
        return True


def update_feed(feed_name: str, force: bool = False) -> bool:
    """Downloads a single feed. Returns True on success."""
    _ensure_intel_dir()
    meta = _load_meta()

    if not force and not _needs_update(meta, feed_name):
        return True   # Already fresh

    url = FEEDS.get(feed_name)
    if not url:
        print(f"[-] Unknown feed: {feed_name}")
        return False

    path_map = {
        "lolbas":     LOLBAS_PATH,
        "loldrivers": LOLDRIVERS_PATH,
        "ja3":        JA3_PATH,
        "feodo":      FEODO_PATH,
    }
    dest = path_map[feed_name]

    try:
        print(f"[*] Updating {feed_name} feed from {url} ...")
        resp = requests.get(url, timeout=TIMEOUT, verify=True)
        resp.raise_for_status()

        # V3 Fix: Integrity check 1 — minimum size guard
        # A response smaller than the minimum indicates an error page,
        # a compromised feed, or a DNS hijack returning a stub response.
        min_size = MIN_FEED_SIZES.get(feed_name, 1000)
        if len(resp.content) < min_size:
            print(
                f"[-] {feed_name}: Response too small "
                f"({len(resp.content)} bytes, minimum {min_size}) — rejecting update."
            )
            return False

        # V3 Fix: Integrity check 2 — content parseability validation
        # Validate the response is actually the expected format before
        # overwriting the cached copy. A corrupted or spoofed response
        # that cannot be parsed is rejected and the old cache is kept.
        if feed_name in _JSON_FEEDS:
            try:
                json.loads(resp.content)
            except json.JSONDecodeError as e:
                print(f"[-] {feed_name}: Invalid JSON in response ({e}) — rejecting update.")
                return False
        elif feed_name in _CSV_FEEDS:
            # CSV: verify at least one non-comment line with expected format
            lines = resp.text.splitlines()
            data_lines = [l for l in lines if l.strip() and not l.startswith("#")]
            if not data_lines:
                print(f"[-] {feed_name}: No data lines in CSV response — rejecting update.")
                return False

        with open(dest, "wb") as f:
            f.write(resp.content)
        meta[feed_name] = datetime.datetime.now().isoformat()
        _save_meta(meta)
        size_kb = os.path.getsize(dest) / 1024
        print(f"[+] {feed_name} updated — {size_kb:.1f} KB saved to {dest}")
        return True
    except Exception as e:
        print(f"[-] Failed to update {feed_name}: {e}")
        return False


def update_all(force: bool = False):
    """Updates all four intelligence feeds."""
    print("\n[*] Updating CyberSentinel Threat Intelligence Feeds...")
    results = {}
    for name in FEEDS:
        results[name] = update_feed(name, force=force)
    ok = sum(results.values())
    print(f"[+] Intel update complete: {ok}/{len(FEEDS)} feeds refreshed.\n")
    return results


def feed_status() -> dict:
    """Returns the last-updated timestamp for each feed."""
    meta = _load_meta()
    status = {}
    for name, path in {
        "lolbas": LOLBAS_PATH, "loldrivers": LOLDRIVERS_PATH,
        "ja3": JA3_PATH, "feodo": FEODO_PATH,
    }.items():
        status[name] = {
            "last_update": meta.get(name, "Never"),
            "cached":      os.path.exists(path),
            "size_kb":     round(os.path.getsize(path) / 1024, 1) if os.path.exists(path) else 0,
        }
    return status


# ─── Convenience loaders used by detector modules ─────────────────────────────

def load_lolbas() -> list:
    """Returns LOLBAS entries as a list of dicts. Auto-updates if missing."""
    if not os.path.exists(LOLBAS_PATH):
        update_feed("lolbas")
    if not os.path.exists(LOLBAS_PATH):
        return []
    try:
        with open(LOLBAS_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def load_loldrivers() -> list:
    """Returns LOLDrivers entries as a list of dicts. Auto-updates if missing."""
    if not os.path.exists(LOLDRIVERS_PATH):
        update_feed("loldrivers")
    if not os.path.exists(LOLDRIVERS_PATH):
        return []
    try:
        with open(LOLDRIVERS_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def load_ja3_blocklist() -> set:
    """Returns a set of malicious JA3 fingerprint hex strings."""
    if not os.path.exists(JA3_PATH):
        update_feed("ja3")
    if not os.path.exists(JA3_PATH):
        return set()
    hashes = set()
    try:
        with open(JA3_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split(",")
                if parts:
                    hashes.add(parts[0].strip())
    except Exception:
        pass  # Non-critical: operation continues regardless
    return hashes


def load_feodo_blocklist() -> set:
    """Returns a set of active C2 IP address strings."""
    if not os.path.exists(FEODO_PATH):
        update_feed("feodo")
    if not os.path.exists(FEODO_PATH):
        return set()
    try:
        with open(FEODO_PATH) as f:
            data = json.load(f)
        # Feodo format: list of {"ip_address": "...", "malware": "...", ...}
        return {entry.get("ip_address", "") for entry in data if entry.get("ip_address")}
    except Exception:
        return set()
