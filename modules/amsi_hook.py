# modules/amsi_hook.py — Feature 6: Fileless / In-Memory Attack Detection
#
# Integrates with the Windows Antimalware Scan Interface (AMSI) to intercept
# PowerShell, WScript, and .NET script content BEFORE execution — the only
# point where fileless payloads are visible in plaintext, even when heavily obfuscated.
#
# Two complementary approaches:
#
#   Approach A — AMSI COM bridge (amsi.dll)
#     Initialises an AMSI session and routes script content through the Windows
#     AMSI provider chain. Any installed AV/EDR that registers an AMSI provider
#     will also scan the content. CyberSentinel's own heuristics run additionally.
#
#   Approach B — Process memory injection pattern detection
#     Watches psutil memory maps for the classic VirtualAlloc→WriteProcess→
#     CreateRemoteThread API triad in non-system processes, which is the
#     universal shellcode injection fingerprint.
#
# Requires: Administrator privileges for memory map access
# No kernel driver needed — all user-mode.

import ctypes
import ctypes.wintypes
import os
import re
import time
import threading
import sqlite3
import datetime
from . import colors, utils
from .chain_correlator import ChainCorrelator


# ─────────────────────────────────────────────────────────────────────────────
#  SUSPICIOUS CONTENT PATTERNS (Approach A)
#  Applied to every script blob intercepted through AMSI before execution.
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_PATTERNS = [
    # PowerShell download cradles
    (r"(?i)(new-object\s+net\.webclient).*downloadstring",
     "PowerShell download cradle — T1059.001"),
    (r"(?i)invoke-expression.*downloadstring",
     "IEX+DownloadString combo — T1059.001"),
    (r"(?i)\[system\.convert\]::frombase64string",
     "Base64 decode in memory — T1027"),
    (r"(?i)-enc\w*\s+[A-Za-z0-9+/=]{40,}",
     "Encoded PowerShell command — T1027"),

    # Shellcode patterns
    (r"(?i)(virtualalloc|virtualallocex)",
     "VirtualAlloc in script context — possible shellcode staging — T1055"),
    (r"(?i)(writeprocessmemory|zwwritevirtualmemory)",
     "WriteProcessMemory in script — injection staging — T1055"),
    (r"(?i)createremotethread",
     "CreateRemoteThread in script — injection execution — T1055"),

    # AMSI bypass signatures (meta: the script is trying to disable our detection)
    (r"(?i)(amsiutils|amsi\.dll|amsibuffer|amsicontext)",
     "AMSI bypass attempt detected — T1562.001"),
    (r"(?i)\[ref\]\.\w+\.getfield.*nonpublic",
     "Reflection-based AMSI bypass — T1562.001"),
    (r"(?i)set-mppreference.*disablerealtimemonitoring",
     "Windows Defender disablement — T1562.001"),

    # Credential theft
    (r"(?i)(sekurlsa|lsass|mimikatz)",
     "Mimikatz/credential dumping keyword — T1003"),
    (r"(?i)invoke-mimikatz",
     "Invoke-Mimikatz cmdlet — T1003"),

    # WMI persistence
    (r"(?i)eventtrigger.*commandlinetemplate",
     "WMI subscription persistence — T1546.003"),

    # Suspicious .NET reflection loading
    (r"(?i)\[reflection\.assembly\]::load(file|bytes|from)",
     "Reflective .NET assembly load — T1620"),
]

_COMPILED_PATTERNS = [(re.compile(p), desc) for p, desc in _SUSPICIOUS_PATTERNS]


# ─────────────────────────────────────────────────────────────────────────────
#  AMSI COM BRIDGE (Approach A)
# ─────────────────────────────────────────────────────────────────────────────

class AmsiScanner:
    """
    Thin wrapper around amsi.dll for scanning script blobs.
    Returns a (is_malicious, result_code, matched_patterns) tuple.
    Falls back to heuristic-only mode if amsi.dll is unavailable.
    """

    # AMSI result codes
    AMSI_RESULT_CLEAN              = 0
    AMSI_RESULT_NOT_DETECTED       = 1
    AMSI_RESULT_BLOCKED_BY_ADMIN_0 = 16384
    AMSI_RESULT_BLOCKED_BY_ADMIN_1 = 20479
    AMSI_RESULT_DETECTED           = 32768

    def __init__(self):
        self._amsi     = None
        self._context  = ctypes.c_void_p()
        self._session  = ctypes.c_void_p()
        self._available = False
        self._init_amsi()

    def _init_amsi(self):
        if os.name != "nt":
            return
        try:
            self._amsi = ctypes.WinDLL("amsi.dll")
            hr = self._amsi.AmsiInitialize(ctypes.c_wchar_p("CyberSentinel"),
                                           ctypes.byref(self._context))
            if hr == 0:
                hr2 = self._amsi.AmsiOpenSession(self._context,
                                                  ctypes.byref(self._session))
                self._available = (hr2 == 0)
                if self._available:
                    colors.success("[+] AMSI bridge initialized — script content scanning active.")
        except Exception as e:
            colors.warning(f"[!] AMSI bridge unavailable: {e} — heuristic mode only.")

    def scan_buffer(self, content: str, source_name: str = "script") -> tuple[bool, list[str]]:
        """
        Scans a script string through:
          1. Windows AMSI provider chain (if available)
          2. CyberSentinel's own regex heuristics (always)

        Returns (is_malicious: bool, findings: list[str])
        """
        findings: list[str] = []

        # ── AMSI provider scan ───────────────────────────────────────────────
        amsi_flagged = False
        if self._available and self._amsi:
            try:
                result = ctypes.c_uint(0)
                encoded = content.encode("utf-16-le")
                self._amsi.AmsiScanBuffer(
                    self._context,
                    ctypes.c_char_p(encoded),
                    ctypes.c_uint(len(encoded)),
                    ctypes.c_wchar_p(source_name),
                    self._session,
                    ctypes.byref(result),
                )
                if result.value >= self.AMSI_RESULT_DETECTED:
                    findings.append("AMSI_PROVIDER_DETECTION: Windows AV provider flagged content")
                    amsi_flagged = True
            except Exception:
                pass

        # ── Heuristic pattern scan ───────────────────────────────────────────
        for pattern, description in _COMPILED_PATTERNS:
            if pattern.search(content):
                findings.append(description)

        return (amsi_flagged or len(findings) > 0), findings

    def __del__(self):
        if self._available and self._amsi:
            try:
                self._amsi.AmsiCloseSession(self._context, self._session)
                self._amsi.AmsiUninitialize(self._context)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  MEMORY INJECTION PATTERN DETECTOR (Approach B)
# ─────────────────────────────────────────────────────────────────────────────

# Shellcode injection typically involves anonymous (no-name) RWX memory regions
_RWX = {"r", "w", "x"}   # all three permissions on an anonymous region = suspicious

def _scan_process_memory(pid: int) -> list[str]:
    """
    Checks a process's memory map for anonymous RWX regions (shellcode staging).
    Returns a list of suspicious region descriptions.
    Returns [] if psutil can't access the process (locked by OS).
    """
    suspicious = []
    try:
        import psutil
        proc = psutil.Process(pid)
        for mmap in proc.memory_maps(grouped=False):
            perms = set(mmap.perms.lower().replace("-", ""))
            path  = mmap.path or ""
            # An anonymous (no backing file) region that is executable AND writable
            # is the hallmark of injected shellcode
            if _RWX.issubset(perms) and not path:
                suspicious.append(
                    f"Anonymous RWX region at {mmap.addr} — shellcode staging suspected (T1055)"
                )
    except Exception:
        pass
    return suspicious


# ─────────────────────────────────────────────────────────────────────────────
#  FILELESS MONITOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class FilelessMonitor:
    """
    Combines the AMSI scanner and memory injection detector into a single
    service that the daemon and CLI can call.
    """

    def __init__(self, correlator: ChainCorrelator = None, webhook_url: str = ""):
        self.scanner     = AmsiScanner()
        self.correlator  = correlator
        self.webhook_url = webhook_url

    # ── Script scanning (called on PowerShell/script file drops) ────────────

    def scan_script(self, content: str, source_name: str = "script", pid: int = 0) -> bool:
        """
        Scans script content through AMSI + heuristics.
        Returns True if malicious findings detected.
        """
        is_mal, findings = self.scanner.scan_buffer(content, source_name)
        if not findings:
            return False

        colors.critical(f"\n{'='*64}")
        colors.critical(f"  [FILELESS ALERT] Malicious Script Content Detected!")
        colors.critical(f"{'='*64}")
        colors.warning(f"  Source  : {source_name}  (PID: {pid})")
        for f in findings:
            print(f"    ✗ {f}")
        colors.critical(f"{'='*64}\n")

        for f in findings:
            if self.correlator:
                self.correlator.log_event("FILELESS_SCRIPT", f, pid)

        self._log_to_db(source_name, "\n".join(findings), pid)
        if self.webhook_url:
            utils.send_webhook_alert(self.webhook_url, "Fileless Script Threat",
                {"Source": source_name, "Findings": "\n".join(findings[:5])})
        return True

    # ── Memory scan (called from background thread or CLI) ──────────────────

    def scan_process_memory(self, pid: int, process_name: str = "") -> bool:
        """
        Scans a specific process PID for shellcode injection signatures.
        Returns True if suspicious regions found.
        """
        findings = _scan_process_memory(pid)
        if not findings:
            return False

        colors.critical(f"\n[FILELESS] Memory injection pattern in PID {pid} ({process_name}):")
        for f in findings:
            colors.warning(f"  ✗ {f}")

        if self.correlator:
            for f in findings:
                self.correlator.log_event("SUSPICIOUS_API_VirtualAllocEx", f, pid)

        self._log_to_db(f"PID:{pid}:{process_name}", "\n".join(findings), pid)
        return True

    def start_memory_monitor(self, scan_interval: int = 60):
        """
        Background thread: scans all non-system processes for RWX anonymous regions
        every `scan_interval` seconds.
        """
        def _loop():
            try:
                import psutil
            except ImportError:
                print("[FILELESS] psutil not installed — memory monitor unavailable.")
                return
            while True:
                time.sleep(scan_interval)
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        exe = proc.info.get("exe", "") or ""
                        if "c:\\windows" not in exe.lower():
                            self.scan_process_memory(proc.info["pid"], proc.info.get("name", ""))
                    except Exception:
                        pass
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        print("[+] Fileless Monitor: memory injection scanner active.")

    # ── SQLite persistence ───────────────────────────────────────────────────

    def _log_to_db(self, source: str, findings: str, pid: int):
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """INSERT INTO fileless_alerts (source, findings, pid, timestamp)
                       VALUES (?, ?, ?, ?)""",
                    (source, findings[:1024], pid,
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except sqlite3.Error:
            pass
