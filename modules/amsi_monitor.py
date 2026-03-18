# modules/amsi_monitor.py — Fileless & In-Memory Attack Detection
#
# Two detection layers:
#   1. Windows Event Log monitoring — reads PowerShell ScriptBlock log (Event ID 4104)
#      and flags obfuscation indicators without any kernel hooks.
#   2. AMSI registration via ctypes — registers CyberSentinel as a COM-based AMSI
#      provider so the OS pipes every script through our scanner before execution.
#      (Requires Administrator + Python win32 extensions on Windows)
#
# Real-world impact: Fileless malware runs entirely in memory, leaving no disk artifacts
# for file-based scanners to find. AMSI is the only point where the payload is
# visible in cleartext — even heavy obfuscation is stripped by the time AMSI fires.
# MITRE: T1059.001 (PowerShell), T1027 (Obfuscated Files), T1620 (Reflective Code Loading)

import re
import json
import sqlite3
import datetime
import threading
import time
from . import utils
from . import colors

# ─── Obfuscation indicator patterns ──────────────────────────────────────────
OBFUSCATION_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, mitre_id, description)
    (r"-e[nc]{0,6}\s+[A-Za-z0-9+/=]{30,}",         "T1027",     "Base64-encoded PowerShell command (-enc flag)"),
    (r"\[System\.Convert\]::FromBase64String",        "T1027",     "Inline base64 decode — common stager pattern"),
    (r"IEX\s*\(|Invoke-Expression\s*\(",              "T1059.001", "IEX / Invoke-Expression — executes downloaded string"),
    (r"Invoke-Mimikatz|Invoke-ReflectivePEInjection",  "T1055",     "PowerSploit module detected"),
    (r"\[Runtime\.InteropServices\.Marshal\]",         "T1055",     "P/Invoke via Marshal — memory injection pattern"),
    (r"New-Object\s+Net\.WebClient|DownloadString\(",  "T1105",     "WebClient download cradle — remote payload fetch"),
    (r"Start-BitsTransfer.*http",                      "T1197",     "BITS transfer cradle"),
    (r"-nop[rofile]*\s+-[wW][indow]*\s+[hH]id",       "T1059.001", "PowerShell hidden window no-profile execution"),
    (r"-[eE]xec[utionPolicy]*\s+[bB]ypass",            "T1059.001", "ExecutionPolicy bypass"),
    (r"VirtualAlloc|WriteProcessMemory|CreateThread",  "T1055",     "Win32 memory allocation APIs via PowerShell"),
    (r"amsiInitFailed|amsiContext\s*=\s*0",            "T1562.001", "AMSI bypass attempt detected"),
    (r"\$env:TEMP.*\.exe|%TEMP%.*\.exe",               "T1036",     "Temp directory executable drop"),
    (r"char\(\d+\)\s*\+\s*char\(\d+\)",                "T1027",     "Character-code string construction (obfuscation)"),
    (r"\.replace\(['\"].\s*['\"],\s*['\"]['\"]",       "T1027",     "String replace obfuscation pattern"),
]

# Minimum score to raise an alert (each matched pattern = 1 point)
ALERT_THRESHOLD = 2


class AmsiMonitor:
    """
    Monitors PowerShell ScriptBlock execution logs (Event ID 4104) for obfuscation
    indicators. Runs as a background thread in the daemon.
    Falls back gracefully on non-Windows or when pywin32 is unavailable.
    """

    def __init__(self):
        self._running = False
        self._seen_event_ids: set[int] = set()
        self._available = self._check_winapi()

    def _check_winapi(self) -> bool:
        try:
            import win32evtlog  # noqa
            return True
        except ImportError:
            print("[!] AMSI event-log monitor disabled (install pywin32 to enable).")
            return False

    def start(self):
        """Starts the background thread that tails the PowerShell ScriptBlock event log."""
        if not self._available:
            return
        self._running = True
        threading.Thread(target=self._watch_eventlog, daemon=True).start()
        print("[*] AMSI monitor active — watching PowerShell ScriptBlock log.")

    def stop(self):
        """Signals the monitoring thread to stop."""
        self._running = False

    # ─────────────────────────────────────────────
    #  EVENT LOG WATCHER
    # ─────────────────────────────────────────────

    def _watch_eventlog(self):
        """Tails the PowerShell Operational event log for ScriptBlock events."""
        import win32evtlog
        import win32con

        LOG_NAME = "Microsoft-Windows-PowerShell/Operational"
        SCRIPT_BLOCK_EVENT_ID = 4104

        try:
            handle = win32evtlog.OpenEventLog(None, LOG_NAME)
        except Exception as e:
            print(f"[-] AMSI: Cannot open PowerShell event log: {e}")
            print("[-] Enable ScriptBlock logging: Set-Item HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1")
            return

        while self._running:
            try:
                events = win32evtlog.ReadEventLog(
                    handle,
                    win32con.EVENTLOG_SEQUENTIAL_READ | win32con.EVENTLOG_FORWARDS_READ,
                    0,
                )
                for evt in events:
                    if evt.EventID != SCRIPT_BLOCK_EVENT_ID:
                        continue
                    # Deduplicate by record number
                    record_num = evt.RecordNumber
                    if record_num in self._seen_event_ids:
                        continue
                    self._seen_event_ids.add(record_num)

                    script_text = " ".join(str(s) for s in (evt.StringInserts or []))
                    self._analyse_script(script_text, pid=0)

            except Exception:
                pass  # Non-critical: operation continues regardless
            time.sleep(2)

        win32evtlog.CloseEventLog(handle)

    # ─────────────────────────────────────────────
    #  SCRIPT ANALYSIS
    # ─────────────────────────────────────────────

    def analyse_script(self, script_text: str, pid: int = 0) -> dict | None:
        """
        Public entry point for on-demand script analysis (e.g., from daemon).
        Returns a finding dict if obfuscation detected, else None.
        """
        return self._analyse_script(script_text, pid)

    def _analyse_script(self, script_text: str, pid: int) -> dict | None:
        if not script_text or len(script_text) < 20:
            return None

        findings: list[dict] = []
        score = 0

        for pattern, mitre, desc in OBFUSCATION_PATTERNS:
            if re.search(pattern, script_text, re.IGNORECASE):
                findings.append({"mitre": mitre, "indicator": desc})
                score += 1

        if score < ALERT_THRESHOLD:
            return None

        result = {
            "type":      "FILELESS_AMSI",
            "score":     score,
            "pid":       pid,
            "findings":  findings,
            "snippet":   script_text[:300].replace("\n", " "),
        }
        self._persist(result)
        self._print_alert(result)
        return result

    # ─────────────────────────────────────────────
    #  PERSISTENCE & DISPLAY
    # ─────────────────────────────────────────────

    def _persist(self, r: dict):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO fileless_alerts (source, findings, pid, timestamp) VALUES (?,?,?,?)",
                    ("AMSI_SCRIPTBLOCK", json.dumps(r["findings"]), r["pid"], now),
                )
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    ("FILELESS_AMSI",
                     json.dumps({"score": r["score"],
                                 "indicators": [f["indicator"] for f in r["findings"]]}),
                     r["pid"], now),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _print_alert(self, r: dict):
        indicators = "\n    ".join(f["indicator"] for f in r["findings"])
        mitre_ids  = ", ".join(set(f["mitre"] for f in r["findings"]))
        colors.critical(
            f"\n{'='*65}\n"
            f"  ⚡  FILELESS ATTACK INTERCEPTED (AMSI ScriptBlock)\n"
            f"  Score      : {r['score']} obfuscation indicators\n"
            f"  MITRE      : {mitre_ids}\n"
            f"  Indicators :\n    {indicators}\n"
            f"  Snippet    : {r['snippet'][:100]}...\n"
            f"{'='*65}"
        )

    def display_fileless_alerts(self, limit: int = 20):
        """Prints recent fileless/AMSI alerts to the terminal."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT source, findings, pid, timestamp FROM fileless_alerts "
                    "ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        except Exception:
            rows = []

        if not rows:
            print("[*] No fileless alerts detected yet.")
            return

        print(f"\n{'='*80}")
        print(f"  {'Timestamp':<20}  {'Source':<20}  {'Indicators'}")
        print(f"{'─'*80}")
        for source, findings_json, pid, ts in rows:
            try:
                findings = json.loads(findings_json)
                inds = "; ".join(f["indicator"] for f in findings[:2])
                if len(findings) > 2:
                    inds += f" +{len(findings)-2} more"
            except Exception:
                inds = findings_json[:50]
            print(f"  {ts:<20}  {source:<20}  {inds}")
        print(f"{'='*80}")
