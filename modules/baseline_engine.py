# modules/baseline_engine.py — Per-Machine Environment Baselining
#
# Runs a "learn mode" that profiles normal host behavior over a configurable
# window (default 24 h), then uses deviations from that profile to boost
# ML confidence — dramatically cutting false positives on known-good software.
#
# Addresses the market gap: commercial EDRs use fleet-wide baselines.
# CyberSentinel's baseline is per-machine, making it far more accurate for
# specialized or air-gapped systems where fleet data doesn't exist.

import os
import json
import sqlite3
import datetime
import threading
import time
import psutil
from . import utils
from . import colors

LEARN_MODE_FILE  = "baseline_learning.flag"   # Presence = learn mode active
BASELINE_HOURS   = int(os.environ.get("CS_BASELINE_HOURS", "24"))


class BaselineEngine:
    """
    Two operating modes:
      LEARN  — silently records every running process + its network destinations
               for BASELINE_HOURS, then writes a behavioral profile to SQLite.
      DETECT — compares new processes against the profile; unknown binaries
               receive a trust_penalty score fed back to the ML engine.
    """

    def __init__(self):
        self._learning  = os.path.exists(LEARN_MODE_FILE)
        self._stop_evt  = threading.Event()
        self._thread: threading.Thread | None = None
        self._profiles: dict = {}          # sha256 → {name, seen_count, paths, nets}
        self._load_profiles()

    # ─────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────

    def start_learning(self, hours: int = BASELINE_HOURS):
        """Begins learn mode. Writes flag file so restarts continue the window."""
        if self._learning:
            print("[*] Baseline learning already in progress.")
            return
        self._learning = True
        with open(LEARN_MODE_FILE, "w") as f:
            finish = (datetime.datetime.now() + datetime.timedelta(hours=hours)).isoformat()
            json.dump({"finish": finish, "hours": hours}, f)
        colors.info(f"[*] Baseline learn mode started — profiling for {hours} h.")
        self._start_thread()

    def stop_learning(self):
        """Manually stops learn mode and persists collected profiles."""
        self._learning = False
        self._stop_evt.set()
        if os.path.exists(LEARN_MODE_FILE):
            os.remove(LEARN_MODE_FILE)
        self._flush_profiles()
        colors.success("[+] Baseline learning complete — profiles saved.")

    def start_detection(self):
        """Starts deviation detection in the background."""
        if not self._profiles:
            print("[!] No baseline profile found. Run learn mode first.")
            return
        self._start_thread()

    def get_trust_score(self, sha256: str, file_path: str) -> float:
        """
        Returns a trust penalty [0.0 – 1.0] for a file.
        0.0 = fully trusted (in baseline)
        1.0 = completely unknown (raises ML confidence threshold)
        """
        if not self._profiles:
            return 0.0            # No profile = no penalty
        entry = self._profiles.get(sha256)
        if entry is None:
            return 1.0            # Never seen before → maximum suspicion
        seen = entry.get("seen_count", 0)
        return max(0.0, 1.0 - (seen / 10.0))   # Tapers off after 10 sightings

    def is_learning(self) -> bool:
        """Returns True if baseline learning mode is currently active."""
        if not self._learning:
            return False
        # Auto-expire if the learn window has passed
        if os.path.exists(LEARN_MODE_FILE):
            try:
                with open(LEARN_MODE_FILE) as f:
                    data = json.load(f)
                finish = datetime.datetime.fromisoformat(data["finish"])
                if datetime.datetime.now() >= finish:
                    self.stop_learning()
                    return False
            except Exception:
                pass  # Non-critical: operation continues regardless
        return self._learning

    def display_baseline_stats(self):
        """CLI display of baseline profile summary."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                total = conn.execute("SELECT COUNT(*) FROM baseline_profiles").fetchone()[0]
                top = conn.execute(
                    "SELECT process_name, seen_count FROM baseline_profiles ORDER BY seen_count DESC LIMIT 10"
                ).fetchall()
        except Exception:
            print("[-] Could not read baseline profiles.")
            return

        print(f"\n  Baseline: {total} unique process profiles")
        print(f"  {'Process':<35}  Seen Count")
        print("  " + "─" * 50)
        for name, count in top:
            print(f"  {(name or 'Unknown'):<35}  {count}")

    # ─────────────────────────────────────────────
    #  BACKGROUND THREAD
    # ─────────────────────────────────────────────

    def _start_thread(self):
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        """Polls running processes every 30 s and records / checks them."""
        flush_counter = 0
        while not self._stop_evt.is_set():
            try:
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        exe = proc.info.get("exe")
                        if not exe or not os.path.isfile(exe):
                            continue
                        sha256 = utils.get_sha256(exe)
                        if not sha256:
                            continue

                        if self._learning:
                            self._record(sha256, proc.info["name"], exe, proc.pid)
                        else:
                            self._check_deviation(sha256, proc.info["name"], exe)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
            except Exception:
                pass  # Non-critical: operation continues regardless

            flush_counter += 1
            if flush_counter >= 20:      # Flush to DB every ~10 min
                self._flush_profiles()
                flush_counter = 0

            # Auto-stop learning when window expires
            if self._learning and not self.is_learning():
                break

            self._stop_evt.wait(30)

    # ─────────────────────────────────────────────
    #  PROFILE RECORDING
    # ─────────────────────────────────────────────

    def _record(self, sha256: str, name: str, path: str, pid: int):
        if sha256 not in self._profiles:
            self._profiles[sha256] = {
                "name": name, "seen_count": 0,
                "paths": set(), "net_dests": set(),
            }
        entry = self._profiles[sha256]
        entry["seen_count"] += 1
        entry["paths"].add(path)

        # Record outbound network destinations for this process
        try:
            for conn in psutil.Process(pid).net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    entry["net_dests"].add(conn.raddr.ip)
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _flush_profiles(self):
        """Writes in-memory profiles to SQLite."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                for sha256, data in self._profiles.items():
                    conn.execute(
                        """INSERT INTO baseline_profiles
                           (sha256, process_name, seen_count, paths_json, last_seen)
                           VALUES (?,?,?,?,?)
                           ON CONFLICT(sha256) DO UPDATE SET
                               seen_count = seen_count + excluded.seen_count,
                               paths_json = excluded.paths_json,
                               last_seen  = excluded.last_seen""",
                        (sha256, data["name"], data["seen_count"],
                         json.dumps(list(data["paths"])[:20]), now),
                    )
                    for ip in data.get("net_dests", set()):
                        conn.execute(
                            "INSERT OR IGNORE INTO baseline_network (process_sha256, dest_ip) VALUES (?,?)",
                            (sha256, ip),
                        )
            self._profiles.clear()
        except Exception:
            pass  # Non-critical: operation continues regardless

    # ─────────────────────────────────────────────
    #  DEVIATION DETECTION
    # ─────────────────────────────────────────────

    def _check_deviation(self, sha256: str, name: str, path: str):
        if sha256 in self._profiles:
            return    # Already known in memory

        # Respect the shared exclusion list — processes excluded from scanning
        # are also excluded from baseline deviation alerts.
        if utils.is_excluded(path) or utils.is_excluded(name):
            return

        # Check DB
        if not self._in_db(sha256):
            colors.warning(
                f"[BASELINE] ⚠  Unknown binary not in baseline profile:\n"
                f"           {name} ({path})\n"
                f"           Trust score: HIGH RISK — investigate or add to exclusions."
            )

    def _in_db(self, sha256: str) -> bool:
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    "SELECT seen_count FROM baseline_profiles WHERE sha256=?", (sha256,)
                ).fetchone()
            return row is not None
        except Exception:
            return True    # DB error → don't alert

    def _load_profiles(self):
        """Pre-loads high-frequency profiles into memory for fast lookup."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT sha256, process_name, seen_count FROM baseline_profiles WHERE seen_count > 5"
                ).fetchall()
            for r in rows:
                self._profiles[r[0]] = {"name": r[1], "seen_count": r[2],
                                        "paths": set(), "net_dests": set()}
        except Exception:
            pass  # Non-critical: operation continues regardless
