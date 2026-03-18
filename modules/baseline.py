# modules/baseline.py — Feature 5: Per-Machine Environment Baselining
#
# Runs a "learn mode" that profiles the host's normal behavior over a
# configurable window (default 24 h), then raises the ML confidence threshold
# for processes that match the established baseline — dramatically reducing
# false positives on legitimate software specific to this host.
#
# Unlike commercial EDRs that use fleet-wide baselines, CyberSentinel's
# baseline is per-machine, making it accurate for air-gapped or specialized
# hosts where standard enterprise tools produce constant noise.
#
# Tables used: baseline_profiles, baseline_network

import os
import sqlite3
import datetime
import threading
import time
import json
import hashlib
from . import colors, utils


class BaselineManager:
    """
    Learn mode: observes running processes, their hashes, and network destinations
    for a configurable learning period, then persists the profile to SQLite.

    Scoring mode: given a new process/network event, returns a float [0.0, 1.0]
    deviation score — 0 = fully expected, 1 = never-before-seen.
    """

    LEARN_DURATION_HOURS = 24   # How long learn mode runs

    def __init__(self):
        self._learning    = False
        self._learn_end: datetime.datetime | None = None
        self._profiles: dict = {}   # sha256 → {name, seen_count, first_seen, paths}
        self._net_dests: set = set()   # (process_sha256, dest_ip) pairs
        self._lock = threading.Lock()
        self._load_from_db()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load_from_db(self):
        """Loads existing baseline profiles into memory for fast deviation checks."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT sha256, process_name, seen_count, paths_json FROM baseline_profiles"
                ).fetchall()
                for r in rows:
                    self._profiles[r[0]] = {
                        "name":       r[1],
                        "seen_count": r[2],
                        "paths":      json.loads(r[3] or "[]"),
                    }
                net_rows = conn.execute(
                    "SELECT process_sha256, dest_ip FROM baseline_network"
                ).fetchall()
                for r in net_rows:
                    self._net_dests.add((r[0], r[1]))
        except sqlite3.Error:
            pass

    def _save_profile(self, sha256: str, name: str, path: str):
        paths_json = json.dumps(list({path} | set(self._profiles.get(sha256, {}).get("paths", []))))
        count      = self._profiles.get(sha256, {}).get("seen_count", 0) + 1
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """INSERT INTO baseline_profiles (sha256, process_name, seen_count, paths_json, last_seen)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(sha256) DO UPDATE SET
                           seen_count = excluded.seen_count,
                           paths_json = excluded.paths_json,
                           last_seen  = excluded.last_seen""",
                    (sha256, name, count, paths_json, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except sqlite3.Error:
            pass
        with self._lock:
            self._profiles[sha256] = {"name": name, "seen_count": count, "paths": json.loads(paths_json)}

    def _save_network(self, process_sha256: str, dest_ip: str):
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO baseline_network (process_sha256, dest_ip) VALUES (?, ?)",
                    (process_sha256, dest_ip),
                )
        except sqlite3.Error:
            pass
        with self._lock:
            self._net_dests.add((process_sha256, dest_ip))

    # ── Learn mode ───────────────────────────────────────────────────────────

    def start_learn_mode(self, duration_hours: int = None):
        """
        Starts the background learning thread.
        Observes all running processes and hashes them into the baseline.
        """
        hours = duration_hours or self.LEARN_DURATION_HOURS
        self._learn_end = datetime.datetime.now() + datetime.timedelta(hours=hours)
        self._learning  = True

        colors.info(f"[BASELINE] Learn mode started — profiling for {hours} hours.")
        colors.info(f"[BASELINE] Learning ends at: {self._learn_end.strftime('%Y-%m-%d %H:%M:%S')}")

        t = threading.Thread(target=self._learn_loop, daemon=True)
        t.start()

    def _learn_loop(self):
        import psutil
        while self._learning and datetime.datetime.now() < self._learn_end:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    exe = proc.info.get("exe")
                    name = proc.info.get("name", "")
                    if exe and os.path.isfile(exe):
                        sha = utils.get_sha256(exe)
                        if sha:
                            self._save_profile(sha, name, exe)
                except (Exception,):
                    pass
            time.sleep(60)  # Re-sample every 60 seconds

        self._learning = False
        count = len(self._profiles)
        colors.success(f"[BASELINE] Learning complete — {count} process profiles recorded.")

    def observe_process(self, sha256: str, name: str, path: str):
        """
        Called by the daemon for every new process event during learn mode.
        Also callable outside learn mode to continuously update the profile.
        """
        if sha256:
            self._save_profile(sha256, name, path)

    def observe_network(self, process_sha256: str, dest_ip: str):
        """Records a (process, destination) pair as normal network behavior."""
        if process_sha256 and dest_ip:
            self._save_network(process_sha256, dest_ip)

    # ── Deviation scoring ────────────────────────────────────────────────────

    def deviation_score(self, sha256: str) -> float:
        """
        Returns a float [0.0, 1.0]:
          0.0  = process is in baseline (well-known, seen many times)
          0.5  = process is not in baseline (new)
          1.0  = reserved for future anomaly scoring (call frequency, parent chain)

        The caller (analysis_manager) uses this to adjust the effective ML
        confidence threshold: a baselined process needs a higher ML score
        before triggering an alert.
        """
        if not sha256:
            return 0.5

        with self._lock:
            profile = self._profiles.get(sha256)

        if not profile:
            return 0.5   # Unknown process

        seen = profile.get("seen_count", 0)
        if seen >= 10:
            return 0.0   # Very well-established baseline entry
        # Linear scale: 1–9 sightings → 0.45 to 0.05
        return max(0.0, 0.5 - (seen * 0.05))

    def network_deviation(self, process_sha256: str, dest_ip: str) -> bool:
        """Returns True if this (process, destination) pair has never been seen before."""
        with self._lock:
            return (process_sha256, dest_ip) not in self._net_dests

    # ── Status & CLI display ─────────────────────────────────────────────────

    @property
    def is_learning(self) -> bool:
        return self._learning

    @property
    def profile_count(self) -> int:
        return len(self._profiles)

    def display_status(self):
        print("\n─── Baseline Status ─────────────────────────────────")
        if self._learning and self._learn_end:
            remaining = self._learn_end - datetime.datetime.now()
            h, rem    = divmod(int(remaining.total_seconds()), 3600)
            m         = rem // 60
            colors.warning(f"  Mode         : LEARNING ({h}h {m}m remaining)")
        elif self._profiles:
            colors.success(f"  Mode         : ACTIVE (deviation scoring enabled)")
        else:
            colors.warning(f"  Mode         : INACTIVE (run learn mode first)")

        print(f"  Profiles     : {self.profile_count} processes baselined")
        print(f"  Network pairs: {len(self._net_dests)} (process, destination) pairs")
        print("─────────────────────────────────────────────────────\n")

    def display_top_profiles(self, limit: int = 20):
        """Displays the most frequently seen baselined processes."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """SELECT process_name, sha256, seen_count, last_seen
                       FROM baseline_profiles ORDER BY seen_count DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
        except sqlite3.Error:
            rows = []

        if not rows:
            print("[*] No baseline profiles recorded yet. Run learn mode first.")
            return

        print(f"\n  {'Process Name':<30}  {'SHA-256 (short)':<22}  {'Seen':<6}  Last Seen")
        print("─" * 85)
        for r in rows:
            sha_short = (r[1][:20] + "..") if r[1] else "N/A"
            print(f"  {r[0]:<30}  {sha_short:<22}  {r[2]:<6}  {r[3]}")
