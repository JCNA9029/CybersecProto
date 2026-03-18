# modules/lolbas_detector.py — Living-off-the-Land Binary (LoLBin) Abuse Detector
#
# Solves: CyberSentinel's WMI daemon previously skipped ALL Windows binaries with
# `"c:\\windows" not in exe_path` — leaving the entire LoLBin attack surface unmonitored.
# This module reverses that blind spot by specifically watching system binaries and
# matching their command-line arguments against known abuse patterns.
#
# Data source: LOLBAS Project (https://lolbas-project.github.io/)
# Real-world threat: 79% of targeted attacks in 2023 used LoLBins (Picus Blue Report 2025)

import os
import re
import sqlite3
import datetime
import json
from . import utils
from .intel_updater import load_lolbas

# ─── Built-in high-confidence abuse patterns ─────────────────────────────────
# These are hardcoded as a reliable fallback even when the LOLBAS feed is unavailable.
# Each entry: (binary_name, regex_pattern, mitre_technique, description)
BUILTIN_PATTERNS: list[tuple] = [
    # Execution / Download
    ("certutil.exe",     r"-urlcache|-decode|-encode|-f\s+http",          "T1105 / T1140", "CertUtil download or decode — common dropper technique"),
    ("mshta.exe",        r"https?://|vbscript:|javascript:",               "T1218.005",     "MSHTA remote script execution (Squiblydoo variant)"),
    ("regsvr32.exe",     r"/i:https?://|scrobj\.dll|/s\s+/n\s+/u\s+/i",  "T1218.010",     "Regsvr32 COM scriptlet execution (Squiblydoo)"),
    ("rundll32.exe",     r"javascript:|vbscript:|pcwrun|advpack",          "T1218.011",     "Rundll32 arbitrary code execution via JS/VBS"),
    ("msbuild.exe",      r"\.proj|\.targets|\.xml",                        "T1127.001",     "MSBuild inline task execution — bypasses AppLocker"),
    ("installutil.exe",  r".*",                                             "T1218.004",     "InstallUtil execution — commonly abused for AppLocker bypass"),
    ("ieexec.exe",       r"https?://",                                      "T1218",         "IEExec remote binary download and execute"),
    ("cmstp.exe",        r"/s\s+/ns|\.inf",                                 "T1218.003",     "CMSTP INF-based code execution and UAC bypass"),
    ("odbcconf.exe",     r"/a\s+\{|regsvr|dll",                             "T1218.008",     "OdbcConf DLL registration abuse"),
    ("mavinject.exe",    r"/injectrunning|/injectall",                      "T1055.001",     "MavInject process injection utility"),
    # Persistence
    ("schtasks.exe",     r"/create.*(/sc|/tr|/tn)",                         "T1053.005",     "Scheduled task creation for persistence"),
    ("reg.exe",          r"add.*run|add.*currentversion\\run",              "T1547.001",     "Registry run key persistence"),
    ("at.exe",           r"\d{1,2}:\d{2}",                                  "T1053.002",     "AT job scheduling (legacy persistence)"),
    # Discovery / Lateral Movement
    ("wmic.exe",         r"process\s+call\s+create|/node:",                 "T1047 / T1021", "WMIC remote process execution or WMI lateral movement"),
    ("bitsadmin.exe",    r"/transfer|/download|/create",                    "T1197",         "BITS job for stealthy download or persistence"),
    # Defense Evasion
    ("forfiles.exe",     r"/c\s+cmd|/c\s+powershell|/p\s+c:\\",            "T1202",         "Forfiles indirect command execution"),
    ("pcalua.exe",       r"-a\s+",                                           "T1202",         "PcaLua indirect program execution"),
    # Credential Access
    ("procdump.exe",     r"-ma\s+lsass|lsass\.exe",                         "T1003.001",     "ProcDump LSASS memory dump — credential harvesting"),
    ("ntdsutil.exe",     r"ifm|ac\s+instance\s+ntds",                       "T1003.003",     "NTDSUtil NTDS.dit extraction"),
    # PowerShell obfuscation (child of any process)
    ("powershell.exe",   r"-e[nc]*\s+[A-Za-z0-9+/=]{20,}|-nop.*-w.*hidden|-exec.*bypass|-enc|-command.*\[convert\]",
                          "T1059.001",     "PowerShell encoded/obfuscated command execution"),
    ("pwsh.exe",         r"-e[nc]*\s+[A-Za-z0-9+/=]{20,}|-nop.*-w.*hidden",
                          "T1059.001",     "PowerShell Core obfuscated execution"),
]


class LolbasDetector:
    """
    Matches process creation events against the LOLBAS Project database
    and built-in high-confidence abuse patterns.
    """

    def __init__(self):
        self._lolbas_patterns: list[dict] = []
        self._load_lolbas_feed()

    def _load_lolbas_feed(self):
        """Parses the LOLBAS JSON feed into a fast-lookup structure."""
        raw = load_lolbas()
        for entry in raw:
            name = (entry.get("Name") or "").lower()
            if not name:
                continue
            commands = entry.get("Commands") or []
            for cmd in commands:
                usecase   = cmd.get("Usecase", "")
                mitre     = cmd.get("MitreID", "")
                cat       = cmd.get("Category", "")
                full_cmd  = cmd.get("Command", "")
                self._lolbas_patterns.append({
                    "name":     name,
                    "usecase":  usecase,
                    "mitre":    mitre,
                    "category": cat,
                    "command":  full_cmd,
                })

    def check_process(
        self,
        process_name: str,
        cmdline: str = "",
        from_daemon: bool = False,
    ) -> dict | None:
        """
        Checks a process name + command line against all LoLBin abuse patterns.

        Args:
            process_name: Name of the new process (e.g. 'certutil.exe')
            cmdline:      Full command line string
            from_daemon:  If True, a confirmed hit is written to event_timeline
                          for attack chain correlation. Set False (default) for
                          manual UI checks so test inputs don't pollute the timeline.

        Returns:
            A finding dict if abuse is detected, None if clean.
        """
        name_lower = process_name.lower()
        cmd_lower  = (cmdline or "").lower()

        # 1. Check built-in high-confidence patterns first (fastest path)
        for binary, pattern, mitre, desc in BUILTIN_PATTERNS:
            if name_lower == binary.lower():
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    finding = {
                        "type":        "LOLBIN_ABUSE",
                        "binary":      process_name,
                        "mitre":       mitre,
                        "description": desc,
                        "cmdline":     cmdline,
                        "source":      "built-in",
                    }
                    if from_daemon:
                        self._save_alert(finding)
                    return finding

        # 2. Fall back to live LOLBAS feed for broader coverage
        for entry in self._lolbas_patterns:
            if name_lower == entry["name"]:
                feed_cmd_tokens = entry["command"].lower().split()
                suspicious_tokens = [t for t in feed_cmd_tokens
                                     if len(t) > 3 and t in cmd_lower]
                if len(suspicious_tokens) >= 2:
                    finding = {
                        "type":        "LOLBIN_ABUSE",
                        "binary":      process_name,
                        "mitre":       entry["mitre"],
                        "description": entry["usecase"],
                        "cmdline":     cmdline,
                        "source":      "LOLBAS-feed",
                    }
                    if from_daemon:
                        self._save_alert(finding)
                    return finding

        return None

    def _save_alert(self, finding: dict):
        """Persists a LoLBin alert to the event_timeline table for chain correlation."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    (
                        "LOLBIN_ABUSE",
                        json.dumps({
                            "binary":      finding["binary"],
                            "mitre":       finding["mitre"],
                            "description": finding["description"],
                        }),
                        0,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def format_alert(self, finding: dict) -> str:
        """Returns a formatted terminal alert string."""
        return (
            f"\n{'='*60}\n"
            f"  ⚠️  LOLBIN ABUSE DETECTED\n"
            f"  Binary  : {finding['binary']}\n"
            f"  MITRE   : {finding['mitre']}\n"
            f"  Details : {finding['description']}\n"
            f"  CmdLine : {finding['cmdline'][:120]}\n"
            f"{'='*60}"
        )
