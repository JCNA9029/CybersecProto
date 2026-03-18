# modules/chain_correlator.py — Behavioral Attack Chain Correlator
#
# Reads events from the shared event_timeline SQLite table (populated by all
# detectors) and matches their sequence against multi-step attack chain definitions.
# A single consolidated CRITICAL alert fires when a full chain completes within
# the correlation window — replacing N fragmented low-signal alerts.
# MITRE reference: https://attack.mitre.org/

import json
import sqlite3
import datetime
from . import utils
from . import colors

WINDOW_MINUTES = 10

ATTACK_CHAINS = [
    {
        "name":       "Process Injection → C2",
        "events":     ["LOLBIN_ABUSE", "C2_CONNECTION"],
        "mitre":      "T1055 — Process Injection",
        "severity":   "CRITICAL",
        "description": "LoLBin abuse followed by outbound C2 — shellcode injected into trusted process to establish remote shell.",
    },
    {
        "name":       "BYOVD → EDR Kill",
        "events":     ["BYOVD_LOAD", "LOLBIN_ABUSE"],
        "mitre":      "T1562.001 — Impair Defenses",
        "severity":   "CRITICAL",
        "description": "Vulnerable kernel driver loaded then LoLBin abused — classic EDR-kill pre-stage enabling payload deployment.",
    },
    {
        "name":       "DGA Beacon → C2 Resolve",
        "events":     ["DGA_BEACON", "C2_CONNECTION"],
        "mitre":      "T1568.002 — Dynamic Resolution: DGA",
        "severity":   "HIGH",
        "description": "DGA cycling detected then outbound C2 connection established — malware successfully resolved active C2 IP.",
    },
    {
        "name":       "Credential Dump Chain",
        "events":     ["LOLBIN_ABUSE", "LOLBIN_ABUSE", "C2_CONNECTION"],
        "mitre":      "T1003 — OS Credential Dumping",
        "severity":   "HIGH",
        "description": "Multiple LoLBin events then C2 connection — consistent with LSASS dump + encode + exfiltration chain.",
    },
    {
        "name":       "Fileless Execution → C2",
        "events":     ["FILELESS_AMSI", "C2_CONNECTION"],
        "mitre":      "T1059.001 — PowerShell",
        "severity":   "CRITICAL",
        "description": "Obfuscated in-memory script intercepted then C2 established — fileless backdoor executed without touching disk.",
    },
    {
        "name":       "Driver + DGA Dual-Stage",
        "events":     ["BYOVD_LOAD", "DGA_BEACON"],
        "mitre":      "T1562.001 + T1568.002",
        "severity":   "CRITICAL",
        "description": "Vulnerable driver loaded then DGA beaconing started — sophisticated actor disabling defenses while seeking new C2.",
    },
    {
        "name":       "Persistence Install",
        "events":     ["LOLBIN_ABUSE", "LOLBIN_ABUSE"],
        "mitre":      "T1547 — Boot/Logon Autostart",
        "severity":   "MEDIUM",
        "description": "Two sequential LoLBin events — consistent with scheduled task creation + dropper download for persistence.",
    },
]


class ChainCorrelator:
    """Correlates event sequences into high-confidence attack chain alerts."""

    def __init__(self):
        self._alerted: set[str] = set()

    def run_correlation(self) -> list[dict]:
        """Pull recent events and match against all chain definitions."""
        events = self._fetch_recent()
        if not events:
            return []

        seq       = [e["event_type"] for e in events]
        triggered = []

        for chain in ATTACK_CHAINS:
            if not self._sequence_present(seq, chain["events"]):
                continue
            key = f"{chain['name']}_{datetime.datetime.now().strftime('%Y-%m-%d_%H:%M')}"
            if key in self._alerted:
                continue
            self._alerted.add(key)
            finding = {
                "chain_name":  chain["name"],
                "mitre":       chain["mitre"],
                "severity":    chain["severity"],
                "description": chain["description"],
                "window_start": events[0]["timestamp"] if events else "",
            }
            self._persist(finding)
            self._print_alert(finding)
            triggered.append(finding)

        return triggered

    # ── helpers ──────────────────────────────────────────────────────────────

    def _fetch_recent(self) -> list[dict]:
        cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=WINDOW_MINUTES)
                  ).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT event_type, detail, pid, timestamp FROM event_timeline "
                    "WHERE timestamp >= ? ORDER BY timestamp ASC", (cutoff,)
                ).fetchall()
            return [{"event_type": r[0], "detail": r[1], "pid": r[2], "timestamp": r[3]} for r in rows]
        except Exception:
            return []

    @staticmethod
    def _sequence_present(haystack: list[str], needle: list[str]) -> bool:
        idx = 0
        for item in haystack:
            if item == needle[idx]:
                idx += 1
                if idx == len(needle):
                    return True
        return False

    def _persist(self, f: dict):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO chain_alerts (chain_name,mitre,severity,description,window_start,timestamp) VALUES (?,?,?,?,?,?)",
                    (f["chain_name"], f["mitre"], f["severity"], f["description"], f["window_start"], now),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _print_alert(self, f: dict):
        icon = "🔴" if f["severity"] == "CRITICAL" else "🟠"
        colors.critical(
            f"\n{'='*65}\n"
            f"  {icon}  ATTACK CHAIN: {f['chain_name']}\n"
            f"  Severity : {f['severity']}\n"
            f"  MITRE    : {f['mitre']}\n"
            f"  Details  : {f['description']}\n"
            f"  Window   : {f['window_start']} → now\n"
            f"{'='*65}"
        )

    def display_chain_alerts(self, limit: int = 20):
        """CLI display of recent chain alerts."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT chain_name,mitre,severity,description,window_start,timestamp "
                    "FROM chain_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        except Exception:
            rows = []

        if not rows:
            print("[*] No attack chains detected yet.")
            return

        print(f"\n{'='*100}")
        print(f"  {'Timestamp':<20}  {'Severity':<10}  {'Chain':<35}  MITRE")
        print(f"{'─'*100}")
        for r in rows:
            chain_name, mitre, severity, _, _, ts = r
            sev = f"\033[91m{severity}\033[0m" if severity == "CRITICAL" else f"\033[93m{severity}\033[0m"
            print(f"  {ts:<20}  {sev:<10}  {chain_name:<35}  {mitre}")
        print(f"{'='*100}")
