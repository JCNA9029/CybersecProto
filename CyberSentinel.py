# CyberSentinel.py — Main CLI v1: all 6 new feature modules integrated

import argparse, os, ctypes
import tkinter as tk
from tkinter import filedialog

from modules import ScannerLogic, utils
from modules import colors, feedback as fb
from modules.live_edr          import get_target_process_path
from modules.network_isolation import isolate_network, restore_network
from modules.lolbas_detector   import LolbasDetector
from modules.byovd_detector    import ByovdDetector
from modules.chain_correlator  import ChainCorrelator
from modules.baseline_engine   import BaselineEngine
from modules.amsi_monitor      import AmsiMonitor
from modules.intel_updater     import update_all, feed_status


class CyberSentinelUI:
    def __init__(self):
        self.logic      = ScannerLogic()
        self.byovd      = ByovdDetector()
        self.lolbas     = LolbasDetector()
        self.correlator = ChainCorrelator()
        self.baseline   = BaselineEngine()
        self.amsi       = AmsiMonitor()

    def print_banner(self):
        """Prints the ASCII art CyberSentinel banner to the terminal."""
        colors.header(r"""
  ____ _   _ ____  _____ ____  ____  _____ _   _ _____ ___ _   _ _____ _
 / ___| \ | | __ )| ____|  _ \/ ___|| ____| \ | |_   _|_ _| \ | | ____| |
| |   | \ | |  _ \|  _| | |_) \___ \|  _| |  \| | | |  | ||  \| |  _| | |
| |___| |_| | |_) | |___|  _ < ___) | |___| |\  | | |  | || |\  | |___| |___
 \____|\__, |____/|_____|_| \_\____/|_____|_| \_| |_| |___|_| \_|_____|_____|
       |___/   v1 — 11-Tier Detection Engine
        """)

    def setup_api(self):
        """Loads saved configuration or prompts for initial API key setup."""
        config = utils.load_config()
        self.logic.api_keys    = config.get("api_keys", {})
        self.logic.webhook_url = config.get("webhook_url", "")
        self.logic.llm_model   = config.get("llm_model", "qwen2.5:3b")
        if self.logic.api_keys:
            colors.success(f"[+] Configuration loaded.  LLM: {self.logic.llm_model}")
        else:
            print("\n--- First Time Setup ---")
            key = input("VirusTotal API key (blank to skip): ").strip()
            if key:
                self.logic.api_keys["virustotal"] = key
                utils.save_config(
                    self.logic.api_keys,
                    self.logic.webhook_url,
                    self.logic.llm_model,
                )

    # ── existing menu actions (unchanged) ──────────────────────────────────

    def _menu_analyze_path(self):
        print("\n" + "="*50)
        target = input("File/directory path (Enter = file picker): ").strip().strip('"\'')
        if not target:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except AttributeError:
                is_admin = False
            if is_admin:
                root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
                target = filedialog.askopenfilename(title="Select File")
                if not target: return
            else:
                print("[-] No path provided."); return

        if os.path.isdir(target):
            count = 0
            for root, _, files in os.walk(target):
                for f in files:
                    fp = os.path.join(root, f)
                    if fp.lower().endswith((".exe",".dll",".sys",".scr",".cpl",".ocx",".bin",".tmp")):
                        self.logic.scan_file(fp); count += 1
            colors.success(f"[+] Batch complete — {count} files analyzed.")
        elif os.path.isfile(target):
            self.logic.scan_file(target)
        else:
            colors.error(f"[-] '{target}' is not a valid path.")

    def _menu_analyze_hash(self):
        print("\n" + "="*50)
        user_input = input("Hash or .txt IoC file (Enter to cancel): ").strip().strip('"\'')
        if not user_input: return
        if os.path.isfile(user_input) and user_input.endswith(".txt"):
            try:
                with open(user_input, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                valid = [h for h in lines if len(h) in (32,40,64)]
                if not valid: colors.error("[-] No valid hashes found."); return
                for h in valid: print("\n"+"─"*30); self.logic.scan_hash(h)
            except Exception as e: colors.error(f"[-] {e}")
        else:
            if len(user_input) not in (32,40,64):
                colors.error("[-] Must be a .txt path or 32/40/64-char hash."); return
            self.logic.scan_hash(user_input)

    def _menu_live_edr(self):
        path = get_target_process_path()
        if path:
            colors.info(f"[*] Routing live process → pipeline...")
            self.logic.scan_file(path)

    def _menu_network_containment(self):
        print("\n1. ISOLATE HOST\n2. RESTORE NETWORK\n3. Cancel")
        c = input("Select (1-3): ").strip()
        if c == "1": isolate_network()
        elif c == "2": restore_network()

    def update_settings(self):
        """Interactive settings editor for API keys, webhook URL, and LLM model."""
        if not isinstance(self.logic.api_keys, dict):
            self.logic.api_keys = {}

        # ── API Keys ────────────────────────────────────────────────────────
        print("\n--- Cloud API Keys ---")
        for eng in ("virustotal", "alienvault", "metadefender", "malwarebazaar"):
            status = "Active" if self.logic.api_keys.get(eng) else "Not Set"
            print(f"[*] {eng.capitalize()}: {status}")
            k = input(f"  New key (CLEAR to remove / Enter to keep): ").strip()
            if k.upper() == "CLEAR":
                self.logic.api_keys.pop(eng, None)
            elif k:
                self.logic.api_keys[eng] = k

        # ── Webhook ─────────────────────────────────────────────────────────
        print("\n--- SOC Webhook ---")
        print(f"[*] Current: {self.logic.webhook_url or 'Not configured'}")
        wh = input("  New URL (CLEAR to remove / Enter to keep): ").strip()
        if wh.upper() == "CLEAR":
            self.logic.webhook_url = ""
        elif wh:
            self.logic.webhook_url = wh

        # ── LLM Model Selection ─────────────────────────────────────────────
        print("\n--- Local AI Model (Ollama) ---")
        print(f"[*] Current model: {self.logic.llm_model}")
        print("[*] Scanning for installed Ollama models...")

        installed = utils.ollama_list_models()

        # Recommended models with RAM hints
        RECOMMENDED = {
            "deepseek-r1:8b": "~8 GB RAM — best quality reports",
            "qwen2.5:7b":     "~4.7 GB RAM — good balance",
            "qwen2.5:3b":     "~2.0 GB RAM — recommended default, fastest",
        }

        if installed:
            colors.success(f"[+] Found {len(installed)} installed model(s):\n")
            options = {}
            idx = 1
            for m in installed:
                hint = RECOMMENDED.get(m, "")
                rec  = " ✓ RECOMMENDED" if m in RECOMMENDED else ""
                hint_str = f"  ({hint})" if hint else ""
                print(f"  {idx}. {m}{hint_str}{rec}")
                options[str(idx)] = m
                idx += 1
            print(f"  {idx}. Keep current ({self.logic.llm_model})")
            print(f"  {idx+1}. Enter model name manually")

            choice = input(f"\n  Select [1-{idx+1}]: ").strip()
            if choice in options:
                self.logic.llm_model = options[choice]
                colors.success(f"[+] LLM model set to: {self.logic.llm_model}")
            elif choice == str(idx):
                colors.info(f"[*] Keeping current model: {self.logic.llm_model}")
            elif choice == str(idx + 1):
                manual = input("  Model name (e.g. llama3.2:latest): ").strip()
                if manual:
                    self.logic.llm_model = manual
                    colors.success(f"[+] LLM model set to: {self.logic.llm_model}")
            else:
                colors.warning("[-] Invalid choice — keeping current model.")
        else:
            colors.warning(
                "[!] Ollama not detected or no models installed.\n"
                "    Install a model with:  ollama pull qwen2.5:3b\n"
                "    Recommended options:\n"
            )
            for m, hint in RECOMMENDED.items():
                marker = " ← current" if m == self.logic.llm_model else ""
                print(f"    • {m}  ({hint}){marker}")

            manual = input(
                f"\n  Enter model name to set (Enter to keep '{self.logic.llm_model}'): "
            ).strip()
            if manual:
                self.logic.llm_model = manual
                colors.success(f"[+] LLM model set to: {self.logic.llm_model}")
            else:
                colors.info(f"[*] Keeping current model: {self.logic.llm_model}")

        # ── Save all ────────────────────────────────────────────────────────
        utils.save_config(
            self.logic.api_keys,
            self.logic.webhook_url,
            self.logic.llm_model,
        )
        colors.success(
            f"[+] Settings saved — "
            f"APIs: {sum(1 for v in self.logic.api_keys.values() if v)} configured  |  "
            f"LLM: {self.logic.llm_model}"
        )

    def _menu_view_cache(self):
        rows = utils.get_all_cached_results()
        if not rows: print("[*] Cache empty."); return
        print(f"\n  {'SHA-256':<64}  {'File':<22}  {'Verdict':<17}  Timestamp")
        print("─"*120)
        for r in rows:
            fname = (r["filename"][:20]+"..") if r["filename"] and len(r["filename"])>22 else str(r["filename"])
            print(f"  {r['sha256']:<64}  {fname:<22}  {colors.verdict_color(r['verdict']):<17}  {r['timestamp']}")

    # ── NEW FEATURE MENUS ──────────────────────────────────────────────────

    def _menu_lolbas_scan(self):
        """Interactive LoLBin abuse check on a user-supplied process name + cmdline."""
        print("\n--- LoLBin Abuse Checker ---")
        name = input("[?] Process name (e.g. certutil.exe): ").strip()
        cmd  = input("[?] Full command line             : ").strip()
        if not name: return
        hit = self.lolbas.check_process(name, cmd)
        if hit:
            colors.critical(self.lolbas.format_alert(hit))
        else:
            colors.success(f"[+] No known LoLBin abuse pattern matched for '{name}'.")

    def _menu_byovd_scan(self):
        """Scans all loaded drivers in System32\\drivers against LOLDrivers database."""
        print("\n--- BYOVD Vulnerable Driver Scanner ---")
        findings = self.byovd.scan_loaded_drivers()
        if not findings:
            colors.success("[+] No known-vulnerable drivers found in System32\\drivers.")
        else:
            colors.critical(f"[!] {len(findings)} vulnerable driver(s) detected:")
            for f in findings:
                colors.critical(self.byovd.format_alert(f))

    def _menu_chain_alerts(self):
        """Displays detected attack chains."""
        print("\n--- Attack Chain Correlation Alerts ---")
        self.correlator.run_correlation()   # Run a fresh sweep first
        self.correlator.display_chain_alerts()

    def _menu_baseline(self):
        """Baseline mode management."""
        print("\n--- Environment Baseline Manager ---")
        print("1. Start learn mode (profile this host)")
        print("2. Stop learn mode and save profile")
        print("3. Show baseline statistics")
        print("4. Cancel")
        c = input("Select (1-4): ").strip()
        if c == "1":
            h = input("  Learn duration in hours (default 24): ").strip()
            hours = int(h) if h.isdigit() else 24
            self.baseline.start_learning(hours)
        elif c == "2":
            self.baseline.stop_learning()
        elif c == "3":
            self.baseline.display_baseline_stats()

    def _menu_fileless_alerts(self):
        """Displays AMSI/fileless detection history."""
        print("\n--- Fileless / AMSI Alert History ---")
        self.amsi.display_fileless_alerts()

    def _menu_intel_update(self):
        """Updates all threat intelligence feeds."""
        print("\n--- Threat Intel Feed Manager ---")
        status = feed_status()
        for name, info in status.items():
            cached = "✓" if info["cached"] else "✗"
            print(f"  [{cached}] {name:<12}  Last: {info['last_update']:<25}  {info['size_kb']} KB")
        ans = input("\n[?] Update all feeds now? (Y/N): ").strip().upper()
        if ans == "Y":
            update_all(force=True)

    def _menu_feedback_history(self):
        print("\n--- Analyst Feedback History ---")
        fb.display_feedback_history()

    # ── MAIN LOOP ──────────────────────────────────────────────────────────

    def run(self):
        """Main application loop — displays the menu and dispatches selections."""
        self.print_banner()
        self.setup_api()

        while True:
            print("\n" + "="*50)
            colors.header("  CyberSentinel v1 — Detection Console")
            print("="*50)
            print("  ── Core Scanning ──────────────────")
            print("   1. Scan Local File or Directory")
            print("   2. Scan Hash or IoC Batch List")
            print("   3. Analyze Active Memory (Live EDR)")
            print("  ── Detectors ──────────────────────")
            print("   4. LoLBin Abuse Checker")
            print("   5. BYOVD Vulnerable Driver Scan")
            print("   6. Attack Chain Correlation Alerts")
            print("   7. Baseline Environment Manager")
            print("   8. Fileless / AMSI Alerts")
            print("  ── Management ─────────────────────")
            print("   9. Network Containment Control")
            print("  10. Update Threat Intelligence Feeds")
            print(f"  11. Configure Settings  [LLM: {self.logic.llm_model}]")
            print("  12. View Threat Cache")
            print("  13. View Analyst Feedback History")
            print("  14. Generate Report & Exit")
            print("="*50)

            choice = input("\nSelect [1-14]: ").strip()
            handlers = {
                "1":  self._menu_analyze_path,
                "2":  self._menu_analyze_hash,
                "3":  self._menu_live_edr,
                "4":  self._menu_lolbas_scan,
                "5":  self._menu_byovd_scan,
                "6":  self._menu_chain_alerts,
                "7":  self._menu_baseline,
                "8":  self._menu_fileless_alerts,
                "9":  self._menu_network_containment,
                "10": self._menu_intel_update,
                "11": self.update_settings,
                "12": self._menu_view_cache,
                "13": self._menu_feedback_history,
                "14": None,
            }
            if choice == "14":
                self.logic.save_session_log()
                colors.info("[*] Terminating CyberSentinel...")
                break
            elif choice in handlers:
                handlers[choice]()
                input("\nPress Enter to return to menu...")
            else:
                colors.warning("[-] Unrecognized command.")


# ── ENTRY POINT ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel v1 EDR")
    parser.add_argument("--daemon",    metavar="PATH", help="Run headless daemon on a folder.")
    parser.add_argument("--sync",      metavar="URL",  help="Pull enterprise threat hashes (HTTPS only).")
    parser.add_argument("--dashboard", action="store_true", help="Launch SOC dashboard.")
    parser.add_argument("--evaluate",  action="store_true", help="Run evaluation harness.")
    parser.add_argument("--update-intel", action="store_true", help="Update all threat intel feeds and exit.")
    args = parser.parse_args()

    if args.update_intel:
        update_all(force=True)

    elif args.sync:
        if not args.sync.startswith("https://"):
            colors.error("[-] SYNC REJECTED: HTTPS required.")
        else:
            import requests
            try:
                r = requests.get(args.sync, timeout=10); r.raise_for_status()
                count = 0
                for h in r.text.splitlines():
                    h = h.strip()
                    if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
                        utils.save_cached_result(h, "CRITICAL RISK", "Fleet Sync"); count += 1
                colors.success(f"[+] Sync complete: {count} hashes added.")
            except Exception as e:
                colors.error(f"[-] Sync error: {e}")

    elif args.daemon:
        from modules.daemon_monitor import start_daemon
        start_daemon(args.daemon)

    elif args.dashboard:
        import subprocess, sys
        subprocess.run([sys.executable, "dashboard.py"])

    elif args.evaluate:
        import subprocess, sys
        subprocess.run([sys.executable, "eval_harness.py"])

    else:
        CyberSentinelUI().run()
