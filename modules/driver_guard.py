# modules/driver_guard.py — Feature 2: BYOVD (Bring Your Own Vulnerable Driver) Detection
#
# Monitors driver load events via WMI Win32_SystemDriver and cross-references
# every loaded .sys file hash against the LOLDrivers database (loldrivers.io).
# A hash match means a known-vulnerable signed driver just loaded into kernel space —
# this is the exact pattern used by LockBit, BlackCat, and Scattered Spider to
# kill AV/EDR processes before deploying ransomware.
#
# Detection is purely a local hash lookup: no network calls, no false positives
# on legitimate driver loads, and runs on a background thread.

import os
import json
import hashlib
import threading
import sqlite3
import datetime
from . import colors, utils

_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "loldrivers.json")


def _sha256_file(path: str) -> str | None:
    """SHA-256 hash a file in 4096-byte chunks. Returns None on I/O error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class DriverGuard:
    """
    Loads the LOLDrivers hash index once at startup.
    Exposes check_driver(path) for both real-time WMI monitoring
    and on-demand manual checks from the CLI menu.
    """

    def __init__(self, webhook_url: str = "", headless: bool = False):
        self.webhook_url = webhook_url
        self.headless    = headless
        self._index: dict[str, dict] = {}   # sha256_lower → driver entry
        self._load()

    # ── Database load ────────────────────────────────────────────────────────

    def _load(self):
        if not os.path.exists(_DATA_PATH):
            print(f"[!] DriverGuard: LOLDrivers database not found at {_DATA_PATH}")
            return
        try:
            with open(_DATA_PATH, "r") as f:
                data = json.load(f)
            for entry in data.get("drivers", []):
                key = entry["sha256"].lower()
                self._index[key] = entry
            print(f"[+] DriverGuard: {len(self._index)} vulnerable driver signatures loaded.")
        except Exception as e:
            print(f"[!] DriverGuard: failed to load LOLDrivers database — {e}")

    # ── Core detection ───────────────────────────────────────────────────────

    def check_driver(self, driver_path: str) -> dict | None:
        """
        Hashes the given .sys file and looks it up in the LOLDrivers index.

        Returns the matching driver entry dict on detection, None if clean.
        """
        if not driver_path or not os.path.exists(driver_path):
            return None

        sha = _sha256_file(driver_path)
        if not sha:
            return None

        match = self._index.get(sha.lower())
        if match:
            self._handle_detection(driver_path, sha, match)
            return match
        return None

    def _handle_detection(self, path: str, sha256: str, entry: dict):
        """Fires alerts on a BYOVD match — screen, SQLite, and webhook."""
        name        = entry.get("name", os.path.basename(path))
        cve         = entry.get("cve", "N/A")
        vendor      = entry.get("vendor", "Unknown")
        description = entry.get("description", "")
        tools       = ", ".join(entry.get("known_tools", []))

        colors.critical(f"\n{'='*64}")
        colors.critical(f"  [BYOVD ALERT] Vulnerable Kernel Driver Loaded!")
        colors.critical(f"{'='*64}")
        colors.warning(f"  Driver    : {name}")
        colors.warning(f"  Path      : {path}")
        colors.warning(f"  SHA-256   : {sha256}")
        colors.warning(f"  CVE       : {cve}   Vendor: {vendor}")
        print(        f"  Risk      : {description}")
        print(        f"  Used by   : {tools}")
        colors.critical(f"  ACTION    : IMMEDIATELY audit running security processes.")
        colors.critical(f"{'='*64}\n")

        # Persist to SQLite for dashboard and audit trail
        self._log_to_db(path, sha256, name, cve, description)

        # SOC webhook alert
        if self.webhook_url:
            utils.send_webhook_alert(
                self.webhook_url,
                title="BYOVD — Vulnerable Driver Loaded",
                details={
                    "Driver": name,
                    "Path": path,
                    "SHA-256": sha256,
                    "CVE": cve,
                    "Vendor": vendor,
                    "Known malware": tools,
                    "Risk": description,
                },
            )

    def _log_to_db(self, path: str, sha256: str, name: str, cve: str, description: str):
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO driver_alerts
                       (sha256, driver_name, path, cve, description, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (sha256, name, path, cve, description,
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except sqlite3.Error:
            pass

    # ── WMI real-time monitor (background thread) ────────────────────────────

    def start_realtime_monitor(self):
        """
        Launches a background thread that polls Win32_SystemDriver every 10 s
        and checks any newly loaded .sys file.
        Complements the process-creation WMI hook already in daemon_monitor.py.
        """
        t = threading.Thread(target=self._poll_drivers, daemon=True)
        t.start()

    def _poll_drivers(self):
        seen: set[str] = set()

        # Seed with already-loaded drivers so we only alert on NEW loads
        try:
            import wmi, pythoncom
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for drv in c.Win32_SystemDriver():
                if drv.PathName:
                    seen.add(drv.PathName.lower())
        except Exception:
            pass

        import time
        while True:
            time.sleep(10)
            try:
                import wmi, pythoncom
                c = wmi.WMI()
                for drv in c.Win32_SystemDriver():
                    path = drv.PathName or ""
                    if path.lower() not in seen:
                        seen.add(path.lower())
                        # Resolve \\SystemRoot\\ to full path
                        resolved = path.replace("\\SystemRoot\\",
                                                os.environ.get("SystemRoot", "C:\\Windows") + "\\")
                        self.check_driver(resolved)
            except Exception:
                pass
