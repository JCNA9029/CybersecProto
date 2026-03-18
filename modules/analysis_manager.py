# modules/analysis_manager.py
#
# Pipeline orchestrator for the CyberSentinel multi-tier EDR framework.
#
# Responsibilities:
#   - Routes files and hashes through the full detection pipeline:
#     Allowlist -> Cache -> Cloud Consensus -> ML Engine -> AI Triage -> Containment
#   - Manages GUI callback registration for thread-safe dialog interaction
#   - Fires SOC webhook alerts on every confirmed malicious verdict
#   - Coordinates the analyst feedback and adaptive learning pipeline
#
# Detection tiers:
#   Tier 0    Allowlist / exclusion check
#   Tier 0.5  SQLite cache (instant repeat-detection)
#   Tier 1    Concurrent cloud consensus (VirusTotal, OTX, MetaDefender, MalwareBazaar)
#   Tier 2    Offline LightGBM ML classifier (EMBER2024 PE features)
#   Tier 3    Local Ollama LLM triage report (MITRE mapping, YARA rule generation)
#   Tier 4    Containment (encrypted quarantine, Windows Firewall host isolation)

import os
import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import ollama

from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
from .scanner_api import VirusTotalAPI, AlienVaultAPI, MetaDefenderAPI, MalwareBazaarAPI
from .feedback import prompt_analyst_feedback
from .chain_correlator import ChainCorrelator
from .baseline_engine import BaselineEngine
from . import network_isolation
from . import utils
from . import colors


class ScannerLogic:
    """Orchestrates the Multi-Tier Pipeline: Cache → Cloud → ML → LLM → Containment."""

    def __init__(self):
        config = utils.load_config()
        self.api_keys      = config.get("api_keys", {})
        self.webhook_url   = config.get("webhook_url", "")
        self.ml_scanner    = LocalScanner()
        self.session_log: list[str] = []
        self.headless_mode = False
        # Daemon overwrites these references with its shared instances.
        # In CLI mode they still function independently.
        self.correlator    = ChainCorrelator()
        self.baseline      = BaselineEngine()
        utils.init_db()
        # R1 Fix: Prune records older than 90 days at startup to prevent
        # unbounded database growth in long-running daemon deployments.
        try:
            utils.prune_old_records(days=90)
        except Exception:
            pass   # Non-critical — startup continues regardless

        # Scenario 3 Fix: Pre-extracted feature cache.
        # Stores compressed feature vectors keyed by sha256, extracted BEFORE
        # quarantine runs so feedback/adaptive-learning has them even after the
        # original file has been moved or encrypted.
        # Entries are removed immediately after the feedback dialog consumes them.
        self._prefetch_features_cache: dict = {}

    # ─────────────────────────────────────────────
    #  LOGGING
    # ─────────────────────────────────────────────

    def log_event(self, message: str, print_to_screen: bool = True):
        """Appends a message to the session log and optionally prints it."""
        if print_to_screen:
            print(message)
        self.session_log.append(message)

    # ─────────────────────────────────────────────
    #  TIER 1: CONCURRENT CLOUD CONSENSUS
    # ─────────────────────────────────────────────

    def _run_tier1_concurrent(self, file_hash: str) -> dict:
        """
        Queries all configured cloud engines CONCURRENTLY using a thread pool.
        Previously sequential (up to 20 s); now completes in the time of the
        slowest single API call (~5 s max).

        Returns a dict with 'verdict', 'context', and 'sources'.
        """
        # Build a dict of {engine_name: callable}
        engine_map = {}
        if self.api_keys.get("malwarebazaar"):
            engine_map["MalwareBazaar"] = lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash)
        if self.api_keys.get("virustotal"):
            engine_map["VirusTotal"] = lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash)
        if self.api_keys.get("alienvault"):
            engine_map["AlienVault"] = lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash)
        if self.api_keys.get("metadefender"):
            engine_map["MetaDefender"] = lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash)

        if not engine_map:
            self.log_event("[!] No API keys configured — Tier 1 skipped.")
            return {"verdict": None, "context": "No APIs configured", "sources": []}

        malicious_sources: list[str] = []
        unknown_sources: list[str] = []

        with ThreadPoolExecutor(max_workers=len(engine_map)) as pool:
            futures = {pool.submit(fn): name for name, fn in engine_map.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if result is None:
                        self.log_event(f"    -> {name}: UNKNOWN (No record / API error)")
                        unknown_sources.append(name)
                    elif result.get("verdict") == "MALICIOUS":
                        hits = result.get("engines_detected", 0)
                        colors.critical(f"    -> {name}: MALICIOUS (Hits: {hits})")
                        self.session_log.append(f"    -> {name}: MALICIOUS (Hits: {hits})")
                        malicious_sources.append(name)
                    else:
                        hits = result.get("engines_detected", 0)
                        colors.success(f"    -> {name}: SAFE (Hits: {hits})")
                        self.session_log.append(f"    -> {name}: SAFE (Hits: {hits})")
                except Exception as e:
                    self.log_event(f"    -> {name}: ERROR ({e})")

        if malicious_sources:
            verdict = "MALICIOUS"
            context = f"Consensus ({', '.join(malicious_sources)})"
        else:
            verdict = "SAFE"
            context = "Consensus (All Clean)" if not unknown_sources else f"Consensus (Clean — {len(unknown_sources)} unknown)"

        return {"verdict": verdict, "context": context, "sources": malicious_sources}

    def _run_tier1_single(self, file_hash: str, engine_name: str) -> dict | None:
        """Queries a single cloud engine and returns its result dict."""
        key_map = {
            "virustotal":    lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash),
            "alienvault":    lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash),
            "metadefender":  lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash),
            "malwarebazaar": lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash),
        }
        if engine_name not in key_map:
            return None
        # Warn and fall back to consensus if the selected engine has no API key configured.
        if not self.api_keys.get(engine_name):
            self.log_event(f"[-] '{engine_name}' API key is not configured. Falling back to consensus.")
            return self._run_tier1_concurrent(file_hash)
        return key_map[engine_name]()

    # ─────────────────────────────────────────────
    #  TIER 3: LLM ANALYST
    # ─────────────────────────────────────────────

    def generate_llm_report(
        self,
        family_name: str,
        detected_apis: list,
        file_path: str,
        confidence_score: float,
        sha256: str,
        file_size_mb: float,
    ) -> str:
        """Queries the local Ollama LLM and returns a formatted triage report."""
        max_apis = 50
        if detected_apis:
            api_context = "\n".join([f"- {api}" for api in detected_apis[:max_apis]])
            if len(detected_apis) > max_apis:
                api_context += f"\n- ... and {len(detected_apis) - max_apis} more."
        else:
            api_context = "None extracted. Likely API hashing, dynamic loading, or UPX packing."

        family_context = family_name + (
            " (Heuristic match — focus on behavioral APIs.)"
            if "Family ID #" in family_name
            else ""
        )

        prompt = f"""
[SYSTEM: EDR TRIAGE REPORT GENERATION]
Target File: {os.path.basename(file_path)}
Target SHA256: {sha256}
File Size: {file_size_mb:.2f} MB
Malware Classification: {family_context}
AI Confidence Score: {confidence_score:.2f}%
Extracted Windows APIs:
{api_context}

TASK: Generate a highly technical malware triage report for a Tier 2 SOC Analyst.
If specific APIs are listed, explain EXACTLY how they are chained to perform malicious actions.
Map APIs to MITRE ATT&CK tactics (e.g., Process Injection, Credential Access).
Do not use conversational filler. Do not introduce yourself.

Format output EXACTLY using these four headers:

### 🔴 Threat Classification
(1-2 sentences explaining the core threat and mechanism.)

### ⚙️ API Behavioral Analysis
(Explain the technical intent behind each API detected. If none, explain evasion tactics.)

### ⚠️ System Impact & Risk
(Concrete impact: data exfiltration, persistence, lateral movement potential.)

### 🛡️ Recommended Mitigation
(Actionable, technical isolation steps beyond standard quarantine.)

### 🎯 Generated YARA Rule
(Valid YARA rule. Condition section MUST check PE magic byte: `uint16(0) == 0x5A4D`.)
"""


        try:
            response = ollama.chat(
                model="qwen2.5:3b",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a strictly analytical, automated Endpoint Detection and Response (EDR) triage engine.",
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2},
            )
            return response["message"]["content"]
        except Exception as e:
            return f"[-] LLM Analyst Offline: {e}"

    # ─────────────────────────────────────────────
    #  TIER 4: CONTAINMENT & QUARANTINE
    # ─────────────────────────────────────────────

    def _prompt_quarantine(self, file_path, sha256, threat_source, verdict,
                           filename="", ai_already_done=False):
        """
        Tier 4 containment — called for every malicious verdict.
        Modes:
          headless_mode=True  : auto-quarantine + isolate (daemon)
          gui_callbacks set   : Qt dialogs instead of input() (GUI)
          neither             : standard CLI input() prompts
        gui_callbacks keys: "ask" (str)->bool, "ai_report" (str)->None,
                            "feedback" (sha256,fname,file_path,verdict)->None

        Scenario 3 Fix:
          Step 0.5 pre-extracts PE features BEFORE Step 4 quarantine runs,
          so adaptive learning has valid feature vectors even when the analyst
          approves quarantine and the original file is moved/encrypted.
          For ML-detected threats the already-computed features are reused
          from _prefetch_features_cache (populated by _handle_critical_ml_threat)
          so no double extraction occurs.
        """
        fname = filename or (os.path.basename(file_path) if file_path else sha256)
        gui   = getattr(self, "gui_callbacks", None)

        # ── Step 0.5: Pre-extract features BEFORE quarantine ─────────────────
        # This is the Scenario 3 fix. If features are not already cached
        # (Path B: ML engine pre-cached them in _handle_critical_ml_threat),
        # extract them now while the file is guaranteed to still be on disk.
        # This runs silently — it never blocks or changes the user-visible flow.
        if sha256 not in self._prefetch_features_cache:
            if file_path and os.path.isfile(file_path):
                try:
                    from .adaptive_learner import get_learner
                    fj = get_learner()._extract_and_serialize(file_path)
                    if fj:
                        self._prefetch_features_cache[sha256] = fj
                        self.log_event("[*] Features cached for adaptive learning.")
                except Exception:
                    pass  # Non-critical — learning degrades gracefully without features

        # Step 1: Webhook — always fires first
        if self.webhook_url:
            import socket as _sock
            import datetime as _dt
            ok = utils.send_webhook_alert(
                self.webhook_url,
                title="Threat Detected on Endpoint",
                details={
                    "File":    fname,
                    "SHA256":  sha256,
                    "Source":  threat_source,
                    "Verdict": verdict,
                    "Host":    _sock.gethostname(),
                    "Time":    _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
            status = "OK" if ok else "FAILED"
            colors.success(f"[+] Webhook {status}.") if ok else colors.warning(f"[!] Webhook {status}.")
            self.session_log.append(f"[WEBHOOK] {status}")
        else:
            colors.warning("[!] No webhook configured.")

        # Step 2: Threat banner
        sep = "=" * 60
        self.log_event(sep)
        self.log_event("  THREAT CONFIRMED")
        self.log_event(f"  Verdict : {verdict}")
        self.log_event(f"  Source  : {threat_source}")
        self.log_event(f"  File    : {fname}")
        self.log_event(f"  SHA-256 : {sha256[:32]}...")
        self.log_event(sep)

        # Step 3: Headless daemon — auto-act, no prompts
        if self.headless_mode:
            self.log_event("[!] HEADLESS: Auto-quarantining.")
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
            self.log_event("[!] HEADLESS: Isolating network.")
            network_isolation.isolate_network()
            return

        # Step 4: Quarantine
        if gui:
            msg = ("THREAT CONFIRMED: " + verdict + "\n\n"
                   "File: " + fname + "\nSource: " + threat_source
                   + "\n\nQuarantine this file?")
            q = gui["ask"](msg)
        else:
            q = input("\n[?] Quarantine this file? (Y/N): ").strip().upper() == "Y"
        if q:
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
                colors.success("[+] File quarantined.")
            else:
                colors.warning("[!] No file path — hash-only scan.")
        else:
            colors.warning("[*] Quarantine skipped.")
            self.session_log.append("[*] Quarantine skipped.")

        # Step 5: Network isolation
        if gui:
            n = gui["ask"]("Isolate this host from the network?\n\nBlocks ALL traffic until restored.")
        else:
            n = input("[?] Isolate host network? (Y/N): ").strip().upper() == "Y"
        if n:
            # R4 Fix: Check return value — isolation can fail silently
            # if the Windows Firewall service is disabled or lacks privileges.
            isolated = network_isolation.isolate_network()
            if isolated:
                colors.critical("[!] Network isolated — restore via Network page when safe.")
                self.session_log.append("[!] NETWORK ISOLATED")
            else:
                colors.warning(
                    "[!] Network isolation FAILED — machine may still be connected. "
                    "Check Administrator privileges and Firewall service status."
                )
                self.session_log.append("[!] ISOLATION FAILED")
        else:
            colors.warning("[*] Network isolation skipped.")

        # Step 6: AI Analyst Report — skip if ML handler already ran it
        if ai_already_done:
            self.log_event("[*] AI report already generated above.")
        else:
            if gui:
                run_ai = gui["ask"](
                    "Generate AI analyst report for:\n" + fname
                    + "\n\nUses your local Ollama model.\nMay take 30-60 seconds."
                )
            else:
                run_ai = input("\n[?] Generate AI analyst report? (Y/N): ").strip().lower() == "y"

            if run_ai:
                self.log_event("[*] Generating AI report...")
                spinner = Spinner("[*] Generating AI threat report...")
                spinner.start()
                report = self.generate_llm_report(
                    family_name="Unknown - Cloud/Signature Detection",
                    detected_apis=[],
                    file_path=file_path or "",
                    confidence_score=100.0,
                    sha256=sha256,
                    file_size_mb=0.0,
                )
                spinner.stop()
                self.log_event("--- AI Analyst Report ---")
                self.log_event(report)
                if gui and "ai_report" in gui:
                    gui["ai_report"](report)
            else:
                self.log_event("[*] AI report skipped.")

        # Step 7: Analyst Feedback
        # Retrieve pre-extracted features from cache — these were captured in
        # Step 0.5 before quarantine ran, so they are available even if the
        # file no longer exists on disk.
        prefetched_fj = self._prefetch_features_cache.pop(sha256, None)

        if gui:
            if "feedback" in gui:
                gui["feedback"](sha256, fname, file_path or "", verdict,
                                prefetched_fj)
            else:
                self.log_event(
                    f"[*] Verdict logged: {verdict}. "
                    f"Review in Analyst Feedback tab."
                )
        else:
            prompt_analyst_feedback(sha256, fname, verdict,
                                    file_path=file_path or "",
                                    prefetched_features_json=prefetched_fj)

    # ─────────────────────────────────────────────
    #  ML THREAT HANDLER
    # ─────────────────────────────────────────────

    def _handle_critical_ml_threat(
        self,
        file_path: str,
        sha256: str,
        file_size_mb: float,
        ml_result: dict,
    ):
        """Orchestrates Stage 2 classification and LLM reporting for ML-detected threats.
        Supports three modes: headless (auto), GUI (callbacks), CLI (input()).
        """
        fam_name = "Unknown"
        features = ml_result.get("features")
        gui = getattr(self, "gui_callbacks", None)

        # Stage 2 family classification
        if self.headless_mode:
            run_stage2 = True
        elif gui:
            run_stage2 = gui["ask"](
                "CRITICAL RISK detected by ML engine.\n\n"
                "Run Stage 2 malware family classification?\n"
                "(Uses local model — no internet required)"
            )
        else:
            run_stage2 = input("\n[?] Run Stage 2 family analysis? (Y/N): ").strip().lower() == "y"

        if run_stage2 and features is not None:
            self.log_event("[*] Running Stage 2 classification...")
            fam_result = self.ml_scanner.scan_stage2(features)
            if fam_result:
                fam_name = fam_result.get("family_name", "Unknown")
                conf = fam_result.get("family_confidence", 0.0)
                self.log_event(f"[*] STAGE 2: {fam_name} ({conf:.2%} confidence)")
        else:
            self.log_event("[*] Stage 2 skipped.")

        # Scenario 3 Fix (Path B):
        # The ML engine already extracted the feature vector during scan_stage1().
        # Serialize and cache it NOW before deleting it from memory, so
        # _prompt_quarantine Step 0.5 finds it pre-populated and skips
        # re-extraction entirely. This avoids double I/O on the file.
        if features is not None and sha256 not in self._prefetch_features_cache:
            try:
                import json as _json, zlib as _zlib, base64 as _b64
                raw  = _json.dumps(features.tolist()).encode("utf-8")
                comp = _zlib.compress(raw, level=6)
                self._prefetch_features_cache[sha256] = (
                    "z:" + _b64.b64encode(comp).decode("ascii")
                )
            except Exception:
                pass  # Non-critical — Step 0.5 will attempt fresh extraction

        # Release the feature array immediately to prevent memory growth in long-running daemon mode.
        if features is not None:
            del ml_result["features"]

        # AI Analyst report
        if self.headless_mode:
            run_ai = True
        elif gui:
            run_ai = gui["ask"](
                f"Malware family: {fam_name}\n\n"
                "Generate AI analyst report via Ollama?\n"
                "Includes API behavioral analysis, MITRE mapping, and YARA rule.\n"
                "May take 30-60 seconds."
            )
        else:
            run_ai = input("\n[?] Generate local AI analyst report via Ollama? (Y/N): ").strip().lower() == "y"

        if run_ai:
            self.log_event("[*] Generating AI report...")
            spinner = Spinner("[*] Generating AI threat report (this may take a moment)...")
            spinner.start()
            report = self.generate_llm_report(
                fam_name,
                ml_result.get("detected_apis", []),
                file_path,
                ml_result["score"] * 100,
                sha256,
                file_size_mb,
            )
            spinner.stop()
            self.log_event("\n--- AI Analyst Report ---")
            self.log_event(report)
            if gui and "ai_report" in gui:
                gui["ai_report"](report)
        else:
            self.log_event("[*] AI report skipped.")

        self._prompt_quarantine(
            file_path, sha256, "Local ML Engine", "CRITICAL RISK",
            ai_already_done=True
        )

    # ─────────────────────────────────────────────
    #  PUBLIC: SCAN FILE
    # ─────────────────────────────────────────────

    def scan_file(self, file_path: str):
        """Main routing pipeline for physical file scans (Tiers 0.5 → 1 → 2 → 3 → 4)."""

        # ── Tier 0: Exclusion list ──────────────────────────────────────────
        if utils.is_excluded(file_path):
            self.log_event(f"[*] ALLOWLISTED: {os.path.basename(file_path)} — bypassed per policy.")
            return

        sha256 = utils.get_sha256(file_path)
        if not sha256:
            colors.error("[-] Cannot read file — OS may have locked it.")
            return

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            colors.error("[-] File was moved/deleted before scanning could begin.")
            return

        filename = os.path.basename(file_path)
        self.log_event("─" * 60)
        colors.info(f"[*] Target   : {filename}")
        self.session_log.append(f"[*] Target   : {filename}")
        self.log_event(f"[*] SHA-256  : {sha256}")
        self.log_event(f"[*] Size     : {file_size_mb:.2f} MB")

        # ── Tier 0.5: Local cache ───────────────────────────────────────────
        cached = utils.get_cached_result(sha256)
        if cached:
            colors.warning("[*] CACHE HIT — Bypassing API/ML engines")
            self.session_log.append("[*] CACHE HIT")
            self.log_event(f"    Verdict    : {cached['verdict']}")
            self.log_event(f"    Cached On  : {cached['timestamp']}")
            self.log_event(f"    Source     : {cached['source']}")
            # Malicious cache hits must still trigger webhook and quarantine — not silently return.
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                self._prompt_quarantine(
                    file_path, sha256,
                    f"Cache Hit ({cached['source']})",
                    cached['verdict'],
                    filename,
                )
            return

        # ── Tier 1: Cloud Intelligence ──────────────────────────────────────
        self.log_event("\n[*] Initializing Cloud Intelligence...")

        gui = getattr(self, "gui_callbacks", None)

        selected_engine = "consensus"
        if not self.headless_mode and not gui:
            # CLI only — GUI uses the engine combo box pre-selected before scan
            print("[?] Select cloud engine:")
            print("  1. VirusTotal        2. AlienVault OTX")
            print("  3. MetaDefender      4. MalwareBazaar")
            print("  5. Smart Consensus (all active APIs) [recommended]")
            mapping = {"1": "virustotal", "2": "alienvault", "3": "metadefender",
                       "4": "malwarebazaar", "5": "consensus"}
            selected_engine = mapping.get(input("  Choice (1-5): ").strip(), "consensus")
        elif gui and "engine" in gui:
            # GUI pre-selected engine via the combo box on the Scan File page
            selected_engine = gui["engine"]()

        cloud_verdict = None
        cloud_context = "N/A"

        if selected_engine == "consensus":
            self.log_event("[*] Running Smart Consensus (concurrent)...")
            result = self._run_tier1_concurrent(sha256)
            cloud_verdict = result["verdict"]
            cloud_context = result["context"]
        else:
            result = self._run_tier1_single(sha256, selected_engine)
            if result:
                cloud_verdict = result.get("verdict")
                cloud_context = selected_engine.capitalize()
                self.log_event(f"[*] {cloud_context}: {cloud_verdict} (Hits: {result.get('engines_detected', 0)})")

        if cloud_verdict:
            intel_context = f"{filename} | Tier 1: {cloud_context}"
            utils.save_cached_result(sha256, cloud_verdict, intel_context)

            if cloud_verdict == "MALICIOUS":
                colors.critical(f"\n[!] TIER 1 VERDICT: MALICIOUS — detected by {cloud_context}")
                self.session_log.append(f"[!] TIER 1 VERDICT: MALICIOUS — {cloud_context}")

                if file_size_mb > 50.0:
                    self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML limit — skipping Tier 2.")
                # Quarantine fires for all cloud MALICIOUS verdicts regardless of file size.
                self._prompt_quarantine(file_path, sha256, cloud_context, "MALICIOUS", filename)
                return
            else:
                colors.success(f"\n[+] TIER 1 VERDICT: SAFE — {cloud_context}")
                self.session_log.append(f"[+] TIER 1 VERDICT: SAFE")

        # ── Tier 2: Local ML ────────────────────────────────────────────────
        if file_size_mb > 50.0:
            self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML extraction limit. Tier 2 skipped.")
            return

        self.log_event("\n[*] Proceeding to Tier 2: Offline ML...")
        ml_result = self.ml_scanner.scan_stage1(file_path)

        if ml_result is None:
            self.log_event("[-] ML engine could not process file (invalid PE or extraction error).")
            return

        ml_verdict = ml_result["verdict"]
        score_pct = ml_result["score"]

        if ml_verdict == "CRITICAL RISK":
            colors.critical(f"[!] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")
        elif ml_verdict == "SUSPICIOUS":
            colors.warning(f"[!] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")
        else:
            colors.success(f"[+] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")

        self.session_log.append(f"[*] TIER 2: {ml_verdict} ({score_pct:.2%})")
        ml_context = f"{filename} | Tier 2: Local ML ({score_pct:.2%})"
        utils.save_cached_result(sha256, ml_verdict, ml_context)

        # ── Novel Feature: Dynamic Risk Scoring ──────────────────────────────
        # Compute context-aware composite risk score combining ML verdict,
        # time-of-day, active threats, chain presence, and baseline deviation.
        try:
            from .risk_scorer import get_risk_scorer
            drs = get_risk_scorer().compute(
                sha256     = sha256,
                filename   = filename,
                verdict    = ml_verdict,
                base_score = score_pct,
                file_path  = file_path,
            )
            self.log_event(
                f"[*] DYNAMIC RISK SCORE: {drs['dynamic_score']:.2f} / 1.00 "
                f"— {drs['risk_level']}"
            )
            self.session_log.append(f"[*] DRS: {drs['dynamic_score']:.2f} ({drs['risk_level']})")
        except Exception as e:
            self.log_event(f"[-] Risk Scorer: Non-critical error: {e}")

        # ── Novel Feature: SHAP Explanation output ───────────────────────────
        shap_expl = ml_result.get("shap_explanation")
        if shap_expl:
            self.log_event("[*] SHAP Feature Attribution (top factors):")
            for feat in shap_expl["top_features"][:5]:
                arrow = "↑" if feat["shap_value"] > 0 else "↓"
                self.log_event(
                    f"    {arrow} {feat['feature'][:55]:<55} "
                    f"({feat['shap_value']:+.4f})"
                )
            # Most influential feature group
            top_group = next(iter(shap_expl["group_summary"]))
            self.log_event(f"    Primary driver group: {top_group}")

        # ── Novel Feature: Drift Alert propagation ───────────────────────────
        drift = ml_result.get("drift_alert")
        if drift:
            colors.warning(
                f"[!] CONCEPT DRIFT: Model confidence dropped {drift['drift_magnitude']:.1%}. "
                f"Retraining recommended — see Adaptive Learning page."
            )
            self.session_log.append(f"[!] DRIFT ALERT: {drift['drift_magnitude']:.1%} degradation")

        # ── Feed findings into chain correlator ─────────────────────────────
        import sqlite3 as _sq, datetime as _dt
        _now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with _sq.connect(utils.DB_FILE) as _c:
                for api in ml_result.get("detected_apis", []):
                    _c.execute(
                        "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
                        ("SUSPICIOUS_API", f"{api} — {filename}", 0, _now),
                    )
        except Exception:
            pass  # Non-critical: operation continues regardless

        if ml_verdict == "CRITICAL RISK":
            self._handle_critical_ml_threat(file_path, sha256, file_size_mb, ml_result)
        elif ml_verdict == "SUSPICIOUS":
            colors.warning("[!] Anomalies detected but below isolation threshold. Sandbox testing advised.")
        else:
            colors.success("[+] File structure aligns with safe parameters.")

    # ─────────────────────────────────────────────
    #  PUBLIC: SCAN HASH
    # ─────────────────────────────────────────────

    def scan_hash(self, file_hash: str):
        """Hash-only pipeline: Cache → concurrent Tier 1 cloud consensus."""
        # V4 Fix: Validate hash format before any API call.
        # Accepts only hex strings of exactly 32 (MD5), 40 (SHA-1), or 64 (SHA-256) chars.
        # Rejects anything that could be used for URL injection into the API endpoint paths.
        import re as _re
        if not _re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", file_hash.strip()):
            short = file_hash[:32]
            colors.error(
                f"[-] Invalid hash rejected: '{short}...'. "
                "Must be a hex string of 32 (MD5), 40 (SHA-1), or 64 (SHA-256) chars."
            )
            return
        file_hash = file_hash.strip().lower()

        self.log_event("─" * 60)
        colors.info(f"[*] Manual Hash Scan: {file_hash}")
        self.session_log.append(f"[*] Manual Hash Scan: {file_hash}")

        cached = utils.get_cached_result(file_hash)
        if cached:
            colors.warning("[*] CACHE HIT — Local Threat DB")
            self.session_log.append("[*] CACHE HIT")
            self.log_event(f"    Verdict  : {cached['verdict']}")
            self.log_event(f"    Cached On: {cached['timestamp']}")
            self.log_event(f"    Source   : {cached['source']}")
            # Cached malicious hash scans still require webhook and quarantine.
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                self._prompt_quarantine(
                    "",          # no file path for hash-only scans
                    file_hash,
                    f"Cache Hit ({cached['source']})",
                    cached['verdict'],
                    file_hash[:16] + "...",
                )
            return

        self.log_event("[*] Running Smart Consensus (concurrent)...")
        result = self._run_tier1_concurrent(file_hash)
        cloud_verdict = result["verdict"]
        cloud_context = result["context"]

        if cloud_verdict == "MALICIOUS":
            colors.critical(f"\n[!] FINAL VERDICT: MALICIOUS — {cloud_context}")
            self.session_log.append(f"[!] HASH VERDICT: MALICIOUS — {cloud_context}")
        else:
            colors.success(f"\n[+] FINAL VERDICT: SAFE — {cloud_context}")
            self.session_log.append(f"[+] HASH VERDICT: SAFE")

        if cloud_verdict:
            utils.save_cached_result(file_hash, cloud_verdict, f"Cloud Consensus ({cloud_context})")
            # Trigger containment flow for new malicious hash verdicts
            if cloud_verdict == "MALICIOUS":
                self._prompt_quarantine(
                    "",           # no file path for hash-only scans
                    file_hash,
                    cloud_context,
                    "MALICIOUS",
                    file_hash[:16] + "...",
                )

    # ─────────────────────────────────────────────
    #  SESSION LOG
    # ─────────────────────────────────────────────

    def save_session_log(self):
        """
        Writes the session log to a timestamped .txt file.
        GUI mode: auto-saves without prompting.
        CLI mode: interactive filename prompt.
        """
        if not self.session_log:
            return

        gui = getattr(self, "gui_callbacks", None)
        analysis_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "Analysis Files"
        )
        os.makedirs(analysis_dir, exist_ok=True)

        if gui:
            # Auto-save with timestamp — no blocking prompt in GUI mode
            ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{ts}.txt"
            filepath = os.path.join(analysis_dir, filename)
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "=" * 60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "=" * 60 + "\n END OF REPORT\n" + "=" * 60 + "\n")
                self.log_event(f"[+] Session report auto-saved: {filename}")
            except Exception as e:
                self.log_event(f"[-] Report save error: {e}")
            return

        # CLI interactive path
        print("\n" + "=" * 50)
        ans = input("[?] Save session results to a forensic .txt log? (Y/N): ").strip().lower()
        if ans != "y":
            return

        while True:
            filename = input("[>] Filename (e.g., my_report): ").strip() or "scan_results"
            if not filename.endswith(".txt"):
                filename += ".txt"

            filepath = os.path.join(analysis_dir, filename)

            if os.path.exists(filepath):
                overwrite = input(f"[!] '{filename}' already exists. Overwrite? (Y/N): ").strip().lower()
                if overwrite != "y":
                    print("[*] Enter a different filename.")
                    continue

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "=" * 60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "=" * 60 + "\n END OF REPORT\n" + "=" * 60 + "\n")
                colors.success(f"\n[+] Report saved: {os.path.abspath(filepath)}")
                break
            except Exception as e:
                colors.error(f"[-] Save error: {e}")
                break
