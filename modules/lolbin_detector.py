# modules/lolbin_detector.py — Feature 1: Living-off-the-Land Binary Abuse Detection
#
# Closes the most critical blind spot in the WMI daemon: CyberSentinel previously
# excluded ALL c:\windows binaries. Attackers leverage this exclusion intentionally —
# 79% of targeted attacks in 2023 used LOLBins (Picus Blue Report 2025).
#
# This module loads the LOLBAS project pattern database (data/lolbas_patterns.json)
# and checks every new process name + command line against known abuse argument patterns.
# It is purely a static lookup — zero network calls, negligible CPU cost.

import json
import os
import re
from dataclasses import dataclass, field
from . import colors

_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "lolbas_patterns.json")

@dataclass
class LolbinAlert:
    binary:       str
    mitre:        str
    tactic:       str
    matched_args: list[str]
    description:  str
    command_line: str
    pid:          int = 0


class LolbinDetector:
    """
    Loads LOLBAS abuse patterns once at startup and provides O(1) binary-name
    lookups for every process creation event in the WMI daemon.
    """

    def __init__(self):
        self._patterns: dict[str, dict] = {}   # binary_name_lower → pattern entry
        self._load()

    def _load(self):
        if not os.path.exists(_DATA_PATH):
            print(f"[!] LolbinDetector: pattern database not found at {_DATA_PATH}")
            return
        try:
            with open(_DATA_PATH, "r") as f:
                data = json.load(f)
            for entry in data.get("binaries", []):
                key = entry["name"].lower()
                self._patterns[key] = entry
            print(f"[+] LolbinDetector: {len(self._patterns)} LOLBAS patterns loaded.")
        except Exception as e:
            print(f"[!] LolbinDetector: failed to load patterns — {e}")

    def check(self, process_name: str, command_line: str, pid: int = 0) -> LolbinAlert | None:
        """
        Checks a process name + command line against the LOLBAS database.

        Parameters
        ----------
        process_name : str  e.g. "certutil.exe"
        command_line : str  full command line string from WMI Win32_Process
        pid          : int  for reporting context

        Returns
        -------
        LolbinAlert if a match is found, None otherwise.
        """
        if not process_name:
            return None

        key = process_name.lower().strip()
        entry = self._patterns.get(key)
        if not entry:
            return None

        # Case-insensitive pattern match on the command line
        cmd_lower = (command_line or "").lower()
        matched = [p for p in entry.get("patterns", []) if p.lower() in cmd_lower]

        if matched:
            return LolbinAlert(
                binary=process_name,
                mitre=entry["mitre"],
                tactic=entry["tactic"],
                matched_args=matched,
                description=entry["description"],
                command_line=command_line or "",
                pid=pid,
            )
        return None

    def print_alert(self, alert: LolbinAlert):
        colors.critical(f"\n{'='*62}")
        colors.critical(f"  [LOLBIN ALERT] Living-off-the-Land Abuse Detected!")
        colors.critical(f"{'='*62}")
        colors.warning(f"  Binary     : {alert.binary}  (PID: {alert.pid})")
        colors.warning(f"  MITRE      : {alert.mitre}  —  {alert.tactic}")
        print(        f"  Description: {alert.description}")
        print(        f"  Matched Args: {', '.join(alert.matched_args)}")
        print(        f"  Command Line: {alert.command_line[:200]}")
        colors.critical(f"{'='*62}\n")
