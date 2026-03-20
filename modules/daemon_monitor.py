# modules/daemon_monitor.py — Headless Daemon: WMI hook + watchdog + all 6 new detectors
#
# Thread map:
#   Thread 1 (main)    — watchdog folder observer
#   Thread 2 (daemon)  — WMI process/driver hook (LoLBin + BYOVD + baseline)
#   Thread 3 (daemon)  — Feodo C2 IP monitor
#   Thread 4 (daemon)  — JA3 TLS sniffer (optional, scapy)
#   Thread 5 (daemon)  — AMSI ScriptBlock event-log monitor (optional, pywin32)
#   Thread 6 (daemon)  — Chain correlator sweep every 60 s

import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .analysis_manager import ScannerLogic
from .lolbas_detector  import LolbasDetector
from .byovd_detector   import ByovdDetector
from .c2_fingerprint   import FeodoMonitor, DgaMonitor, Ja3Monitor
from .chain_correlator import ChainCorrelator, ATTACK_CHAINS
from .baseline_engine  import BaselineEngine
from .amsi_monitor     import AmsiMonitor
from . import colors, utils

WATCHED_EXTENSIONS = (".exe",".dll",".sys",".apk",".elf",".pdf",".bat",".ps1",".vbs",".hta")


class ThreatHandler(FileSystemEventHandler):
    def __init__(self, logic: ScannerLogic):
        self.logic = logic

    def on_created(self, event):
        """Watchdog callback — triggered when a new file is created in the monitored folder."""
        if event.is_directory or not event.src_path.lower().endswith(WATCHED_EXTENSIONS):
            return
        print(f"\n[DAEMON] 🚨 File drop intercepted: {event.src_path}")
        time.sleep(2)
        try:
            self.logic.scan_file(event.src_path)
        except Exception as e:
            print(f"[DAEMON] ⚠  Scanner error on {os.path.basename(event.src_path)}: {e}")


def _monitor_processes(logic, lolbas, byovd, baseline, dga):
    try:
        import wmi, pythoncom
        pythoncom.CoInitialize()
        watcher = wmi.WMI().Win32_Process.watch_for("creation")
        while True:
            proc     = watcher()
            exe_path = proc.ExecutablePath or ""
            cmdline  = proc.CommandLine   or ""
            name     = proc.Name          or ""
            pid      = proc.ProcessId     or 0

            # Resolve parent process name for kill-chain context
            parent_name = ""
            parent_pid  = proc.ParentProcessId or 0
            if parent_pid:
                try:
                    parent_list = wmi.WMI().Win32_Process(ProcessId=parent_pid)
                    if parent_list:
                        parent_name = parent_list[0].Name or ""
                except Exception:
                    pass

            # LoLBin check — includes parent context for confidence scoring
            hit = lolbas.check_process(
                name,
                cmdline,
                from_daemon  = True,
                parent_name  = parent_name,
                parent_pid   = parent_pid,
                exe_path     = exe_path,
            )
            if hit:
                colors.critical(lolbas.format_alert(hit))

            # BYOVD check for driver loads
            if exe_path.lower().endswith(".sys"):
                hit = byovd.check_driver(exe_path)
                if hit:
                    colors.critical(byovd.format_alert(hit))

            # Baseline deviation — skip processes on the exclusion list
            if not baseline.is_learning() and exe_path:
                if not utils.is_excluded(exe_path) and not utils.is_excluded(name):
                    sha = utils.get_sha256(exe_path) or ""
                    if baseline.get_trust_score(sha, exe_path) >= 1.0:
                        colors.warning(f"[BASELINE] ⚠  Unknown binary: {name} ({exe_path})")

            # Standard PE scanner for non-Windows binaries
            if exe_path and "c:\\windows" not in exe_path.lower():
                try:
                    logic.scan_file(exe_path)
                except Exception as e:
                    print(f"[DAEMON] ⚠  Scanner skipped {name}: {e}")

    except ImportError:
        print("[DAEMON] ⚠  WMI unavailable — install wmi + pywin32.")
    except Exception as e:
        print(f"[DAEMON] ✖  WMI hook terminated: {e}")


def _run_correlator(correlator):
    while True:
        time.sleep(60)
        try:
            correlator.run_correlation()
        except Exception:
            pass  # Non-critical: operation continues regardless


def start_daemon(target_dir: str):
    """Starts the headless daemon monitor on the specified folder path."""
    if not os.path.exists(target_dir):
        print(f"\n[-] CRITICAL: Folder '{target_dir}' does not exist.")
        time.sleep(5)
        return

    logic = ScannerLogic()
    logic.headless_mode = True

    lolbas     = LolbasDetector()
    byovd      = ByovdDetector()
    feodo      = FeodoMonitor()
    dga        = DgaMonitor()
    ja3        = Ja3Monitor()
    correlator = ChainCorrelator()
    baseline   = BaselineEngine()
    amsi       = AmsiMonitor()

    print(f"\n[+] CyberSentinel Daemon v1 Active")
    print(f"[*] 📂  Watching : {os.path.abspath(target_dir)}")
    print(f"[*] ⚙️   WMI      : process + driver interception")
    print(f"[*] 🌐  Feodo    : {len(feodo._blocklist)} C2 IPs loaded")
    print(f"[*] 🔁  DGA      : entropy analysis active")
    print(f"[*] 🔗  Chains   : {len(ATTACK_CHAINS)} signatures loaded")

    feodo.start()
    ja3.start()
    amsi.start()
    if not baseline.is_learning():
        baseline.start_detection()

    threading.Thread(target=_monitor_processes,
                     args=(logic, lolbas, byovd, baseline, dga), daemon=True).start()
    threading.Thread(target=_run_correlator, args=(correlator,), daemon=True).start()

    handler  = ThreatHandler(logic)
    observer = Observer()
    observer.schedule(handler, target_dir, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        feodo.stop(); ja3.stop(); amsi.stop()
        print("\n[*] Daemon shutdown complete.")
    observer.join()
