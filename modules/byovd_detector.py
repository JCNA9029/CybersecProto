# modules/byovd_detector.py — Bring Your Own Vulnerable Driver (BYOVD) Detector
#
# Solves: Attackers load legitimate, Microsoft-signed drivers that contain known
# vulnerabilities to gain kernel-level code execution and kill EDR processes.
# This module monitors driver load events via WMI and cross-references each
# driver's SHA256 hash against the LOLDrivers community database.
#
# Data source: LOLDrivers Project (https://www.loldrivers.io/)
# Real-world threat: CSA Singapore Advisory AD-2025-018 explicitly flags BYOVD
# as the primary EDR-killer mechanism used in ransomware pre-deployment.

import os
import json
import sqlite3
import datetime
import hashlib
from . import utils
from .intel_updater import load_loldrivers


class ByovdDetector:
    """
    Cross-references loaded drivers against the LOLDrivers vulnerable driver database.
    Lookup is O(1) via a pre-built hash set — zero performance impact on the daemon.
    """

    def __init__(self):
        # Primary lookup: SHA256 → driver metadata
        self._sha256_map: dict[str, dict] = {}
        # Secondary lookup: lowercase filename → metadata (for when hash unavailable)
        self._name_map: dict[str, dict] = {}
        self._load_loldrivers_feed()

    # ─────────────────────────────────────────────
    #  DATABASE LOADING
    # ─────────────────────────────────────────────

    def _load_loldrivers_feed(self):
        """
        Parses the LOLDrivers JSON feed into O(1) hash and name lookup structures.
        LOLDrivers format: list of driver objects, each with KnownVulnerableSamples
        containing hash arrays.
        """
        raw = load_loldrivers()
        loaded = 0

        for driver in raw:
            name       = (driver.get("Tags") or [""])[0] if driver.get("Tags") else ""
            category   = driver.get("Category", "")
            cve_list   = driver.get("CVE") or []
            cves       = ", ".join(cve_list) if isinstance(cve_list, list) else str(cve_list)
            description= driver.get("Commands", [{}])[0].get("Description", "Known vulnerable driver")
            filename   = (driver.get("KnownFilenames") or [""])[0] if driver.get("KnownFilenames") else name

            metadata = {
                "name":        name or filename,
                "filename":    filename,
                "category":    category,
                "cves":        cves,
                "description": description,
            }

            # Index every known hash for this driver
            for sample in driver.get("KnownVulnerableSamples") or []:
                sha256 = (sample.get("SHA256") or "").lower().strip()
                if sha256 and len(sha256) == 64:
                    self._sha256_map[sha256] = metadata
                    loaded += 1

            # Index by filename for fallback matching
            if filename:
                self._name_map[filename.lower()] = metadata

        if loaded:
            print(f"[*] BYOVD: Loaded {loaded} vulnerable driver hashes from LOLDrivers.")

    # ─────────────────────────────────────────────
    #  DETECTION
    # ─────────────────────────────────────────────

    def check_driver(self, driver_path: str) -> dict | None:
        """
        Checks a newly loaded driver file for known vulnerabilities.

        Strategy:
          1. Hash the driver file (SHA256) → exact match against LOLDrivers
          2. If unreadable, fall back to filename match (lower confidence)

        Args:
            driver_path: Full filesystem path to the .sys driver file

        Returns:
            Finding dict if vulnerable driver detected, None if clean.
        """
        finding = None

        # Step 1: Hash-based exact match (highest confidence)
        sha256 = self._hash_file(driver_path)
        if sha256:
            meta = self._sha256_map.get(sha256)
            if meta:
                finding = self._build_finding(driver_path, sha256, meta, "SHA256-exact")

        # Step 2: Filename fallback (medium confidence — driver may be a variant)
        if finding is None:
            fname = os.path.basename(driver_path).lower()
            meta = self._name_map.get(fname)
            if meta:
                finding = self._build_finding(driver_path, sha256 or "N/A", meta, "filename-match")

        if finding:
            self._save_alert(finding)

        return finding

    def _build_finding(self, path: str, sha256: str, meta: dict, match_type: str) -> dict:
        return {
            "type":        "BYOVD",
            "driver_path": path,
            "driver_name": meta.get("name", os.path.basename(path)),
            "sha256":      sha256,
            "cves":        meta.get("cves", "N/A"),
            "category":    meta.get("category", ""),
            "description": meta.get("description", ""),
            "match_type":  match_type,
        }

    # ─────────────────────────────────────────────
    #  UTILITIES
    # ─────────────────────────────────────────────

    def _hash_file(self, path: str) -> str | None:
        """SHA256 hash via chunked read. Returns None on any I/O error."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest().lower()
        except Exception:
            return None

    def _save_alert(self, finding: dict):
        """Persists a BYOVD alert to both driver_alerts and event_timeline tables."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                # Dedicated driver alert table
                conn.execute(
                    """INSERT OR REPLACE INTO driver_alerts
                       (sha256, driver_name, path, cve, description, timestamp)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        finding["sha256"],
                        finding["driver_name"],
                        finding["driver_path"],
                        finding["cves"],
                        finding["description"],
                        now,
                    ),
                )
                # Also push to event_timeline for chain correlation
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    (
                        "BYOVD_LOAD",
                        json.dumps({
                            "driver": finding["driver_name"],
                            "cves":   finding["cves"],
                        }),
                        0,
                        now,
                    ),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def format_alert(self, finding: dict) -> str:
        """Formats a BYOVD finding dict into a human-readable alert string."""
        confidence = "HIGH" if finding["match_type"] == "SHA256-exact" else "MEDIUM"
        return (
            f"\n{'='*60}\n"
            f"  🔴  BYOVD — VULNERABLE DRIVER LOADED  [{confidence} CONFIDENCE]\n"
            f"  Driver   : {finding['driver_name']}\n"
            f"  Path     : {finding['driver_path']}\n"
            f"  CVE(s)   : {finding['cves']}\n"
            f"  Category : {finding['category']}\n"
            f"  Details  : {finding['description']}\n"
            f"  SHA256   : {finding['sha256'][:32]}...\n"
            f"  Match    : {finding['match_type']}\n"
            f"  ACTION   : Investigate immediately — kernel-level EDR bypass risk\n"
            f"{'='*60}"
        )

    # ─────────────────────────────────────────────
    #  ACTIVE SYSTEM DRIVER SCAN
    # ─────────────────────────────────────────────

    def scan_loaded_drivers(self) -> list[dict]:
        """
        One-shot scan of all currently loaded kernel drivers.
        Enumerates drivers from the Windows drivers directory and checks each.
        Called on-demand from the CLI menu.
        """
        findings = []
        drivers_dir = r"C:\Windows\System32\drivers"
        if not os.path.exists(drivers_dir):
            return findings

        print(f"[*] Scanning loaded drivers in {drivers_dir} ...")
        for fname in os.listdir(drivers_dir):
            if fname.lower().endswith(".sys"):
                path = os.path.join(drivers_dir, fname)
                result = self.check_driver(path)
                if result:
                    findings.append(result)

        return findings
