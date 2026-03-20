<div align="center">

# 🛡️ CyberSentinel v1

**A Multi-Tiered Endpoint Detection & Response (EDR) Framework**

*Built for under-resourced SOCs — Python-native, offline-capable, AI-assisted*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

</div>

---

## Overview

CyberSentinel v1 is a modular, multi-tiered EDR framework that chains cloud reputation scanning, offline machine learning, local AI analysis, behavioral detection, and four novel research contributions into a single deployable pipeline. It includes a CLI, a full PyQt6 desktop GUI (18 pages), a SOC web dashboard (Flask), and a headless daemon for real-time process monitoring.

Designed as a thesis project for cybersecurity programs and SOC teams that cannot afford commercial EDR licensing. Fully functional on consumer-grade hardware with no GPU required.

---

## Detection Architecture

```
File / Process / Network Event
         │
    ┌────▼──────────────────────────────────────────────────────────┐
    │  Tier 0      Exclusion / Allowlist check                      │
    │  Tier 0.5    Local SQLite cache (instant repeat-detection)    │
    │  Tier 1      Cloud Consensus: VirusTotal + OTX +              │
    │              MetaDefender + MalwareBazaar (concurrent)        │
    │  Tier 2      Offline LightGBM ML — EMBER2024 2568-dim PE      │
    │              features (thrember extractor)                    │
    │  Tier 3      Local Ollama LLM — YARA + MITRE triage report    │
    │  Tier 4      Containment: AES-128 Quarantine + Net Isolation  │
    │                                                               │
    │  ── Novel Intelligence Layer ─────────────────────────────    │
    │  NC-1        Adaptive Learning Engine (label-poison-safe)     │
    │  NC-2        SHAP Explainability (real-time per-scan)         │
    │  NC-3        Dynamic Risk Scoring (6-signal composite)        │
    │  NC-4        Page-Hinkley Concept Drift Detector              │
    └───────────────────────────────────────────────────────────────┘
```

---

## Novel Contributions (v1)

| # | Contribution | Description |
|---|---|---|
| NC-1 | **Adaptive Learning with Label Poisoning Protection** | Incremental LightGBM retraining from analyst corrections. Five-stage validation pipeline (self-contradiction, conflict detection, cross-source check, anchor cross-validation, imbalance guard) prevents poisoned labels from corrupting the model. |
| NC-2 | **Real-Time SHAP Explainability** | SHAP TreeExplainer runs after every Tier 2 scan and presents the top-10 PE feature attributions to the analyst at scan time. First integration of SHAP into a live EDR scan pipeline rather than post-hoc analysis. |
| NC-3 | **Dynamic Risk Scoring (DRS)** | Six-signal composite urgency score: ML verdict (45%), temporal context (10%), active threat count (15%), attack chain presence (15%), network status (10%), baseline deviation (5%). Maps to LOW / MEDIUM / HIGH / CRITICAL. |
| NC-4 | **Concept Drift Detection + Closed Retraining Loop** | Page-Hinkley sequential test monitors ML confidence score distribution. Triggers analyst prompt and retraining when drift is detected. First closed detection-to-retraining loop in a deployable open-source EDR. |

---

## Features

| Category | Feature |
|----------|---------|
| **Scanning** | File, directory, hash, IoC batch list, live process |
| **Cloud Intel** | VirusTotal, AlienVault OTX, MetaDefender, MalwareBazaar — concurrent Smart Consensus |
| **ML Detection** | LightGBM Stage 1 (malicious/safe) + Stage 2 (family classification), θ = 0.60, 100 MB limit |
| **AI Reports** | Ollama LLM (qwen2.5:3b) triage reports with MITRE ATT&CK mapping, API behavioral analysis, and YARA rules |
| **SHAP Explainability** | Real-time per-scan TreeExplainer attributions — top-10 features ranked by Shapley value magnitude |
| **Dynamic Risk Scoring** | Six-signal composite urgency score computed at scan time, fully offline |
| **Adaptive Learning** | Analyst-feedback-driven incremental retraining with 5-stage label poisoning protection and anchor sample anti-bias system |
| **Concept Drift** | Page-Hinkley drift detection with closed analyst-to-model retraining loop |
| **LoLBin Detection** | 5-layer production engine: cmd normalization (caret/quote stripping), path normalization, 22 built-in regex patterns + LOLBAS feed, Shannon entropy scoring (threshold 4.2), parent process context scoring |
| **BYOVD Detection** | Vulnerable driver detection via LOLDrivers SHA-256 exact match + filename fallback |
| **C2 Fingerprinting** | Feodo IP blocklist + DGA entropy analysis + JA3 TLS fingerprinting (requires Npcap) |
| **Attack Chains** | Multi-event temporal correlation across shared event timeline — 7 predefined kill-chain patterns |
| **Baselining** | Per-machine behavioral baselining — flags statistical deviations from established host profile |
| **Fileless / AMSI** | PowerShell ScriptBlock obfuscation detection via Windows Event Log ID 4104 |
| **Quarantine** | Fernet AES-128 encrypted quarantine with analyst-authorization dialog |
| **Network Isolation** | Windows Firewall emergency host isolation + one-click restore |
| **SOC Dashboard** | Flask web dashboard — 7 tabs, live stats, auto-refresh |
| **Desktop GUI** | Full PyQt6 GUI — 18 pages, screen-adaptive responsive layout, colored console |
| **Daemon Mode** | Headless real-time WMI process hook with auto-quarantine and parent process context |
| **Webhook Alerts** | Discord / Slack / Teams webhook on every malicious verdict (SSRF-protected) |
| **Analyst Feedback** | Inline post-scan feedback dialog — TP / FP / FN with adaptive learning integration |
| **Session Reports** | Analyst-prompted save dialog — exports full session log as timestamped .txt report |
| **Intel Feeds** | Auto-updating LOLBAS, LOLDrivers, Feodo, JA3 feeds with integrity validation |
| **Evaluation Harness** | Quantitative benchmarking: Precision, Recall, F1, FPR — threshold sweep 0.40→0.80, temporal stratification, stealth (UPX) dataset |

---

## Requirements

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Windows 10 | Windows 10/11 64-bit |
| Python | 3.10 | 3.11 or 3.12 |
| RAM | 4 GB | 8 GB (16 GB for large LLM) |
| Disk | 2 GB | 5 GB (for ML models + intel feeds) |
| Privileges | Standard user | Administrator (daemon + network isolation) |

> The 100 MB ML file size limit keeps peak memory under ~950 MB on 8 GB hardware.
> No GPU required — all inference runs on CPU.

### External Tools Required

| Tool | Purpose | Download |
|------|---------|----------|
| **Ollama** | Local LLM for AI triage reports | https://ollama.com |
| **Npcap** | JA3 TLS fingerprinting (optional) | https://npcap.com |

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/JCNA9029/CybersentinelModularized.git
cd CybersentinelModularized
```

### Step 2 — Create a Virtual Environment (Recommended)

```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Install Windows-Only Dependencies

```bash
pip install pywin32
pip install wmi
```

> `pywin32` is required for the AMSI monitor and WMI daemon.
> `wmi` is required for the Tier 0 kernel-bridge process hook.

### Step 5 — Install Ollama and Pull a Model

1. Download and install Ollama from https://ollama.com
2. Pull the recommended model:

```bash
ollama pull qwen2.5:3b
```

Other options by RAM requirement:

```bash
ollama pull qwen2.5:7b       # 4.7 GB RAM
ollama pull deepseek-r1:8b   # 8 GB RAM — higher quality reports
```

Ollama must be running in the background when using the AI triage report feature.

### Step 6 — Install EMBER2024 ML Features

The ML engine uses thrember for PE feature extraction (produces a 2568-dimensional feature vector):

```bash
git clone https://github.com/FutureComputing4AI/EMBER2024
cd EMBER2024
pip install .
cd ..
```

Without this, Tier 2 ML scanning and SHAP explainability are disabled. Cloud and AI tiers still function.

### Step 7 — Install SHAP for Explainability (Novel Contribution 2)

```bash
pip install shap
```

Without SHAP, the explainability engine is silently skipped. All other tiers continue normally.

### Step 8 — Download the Local Machine Learning Models

Due to GitHub size limitations, the compiled LightGBM models are hosted externally.

Download the `models/` directory from [Google Drive](https://drive.google.com/drive/folders/1dtVVH4Oo5RhoAiMPhqsB4T1X2dGX0v5N?usp=drive_link).

Place the entire `models/` directory directly into your root `CybersentinelModularized/` folder.

### Step 9 — (Optional) Install Npcap for JA3 Monitor

Download and install from https://npcap.com/

Then install Scapy:

```bash
pip install scapy
```

### Step 10 — Enable PowerShell ScriptBlock Logging for AMSI Monitor

Run PowerShell as Administrator:

```powershell
$path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $path)) { New-Item $path -Force }
Set-ItemProperty $path -Name "EnableScriptBlockLogging" -Value 1
```

---

## Running CyberSentinel

### Desktop GUI (Recommended)

```bash
python gui.py
```

Full PyQt6 GUI with 18 pages, colored console, screen-adaptive layout.

### CLI Interactive Mode

```bash
python CyberSentinel.py
```

14-option menu covering all features.

### SOC Web Dashboard

```bash
python dashboard.py
```

Opens at http://127.0.0.1:5000 — run alongside the CLI or GUI in a separate terminal.

### Headless Daemon (Real-Time Protection)

Run as Administrator:

```bash
python CyberSentinel.py --daemon "C:\Path\To\Watch"
```

Monitors all new process creations via WMI. Auto-quarantines threats. Fires webhook alerts. Includes parent process context for LoLBin confidence scoring.

### Other Flags

```bash
# Update all threat intelligence feeds
python CyberSentinel.py --update-intel

# Pull enterprise threat hashes from a remote HTTPS source
python CyberSentinel.py --sync https://your-server.com/hashes.txt

# Launch the SOC dashboard via main script
python CyberSentinel.py --dashboard

# Run the ML evaluation harness
python CyberSentinel.py --evaluate
```

---

## First-Time Configuration

On first run, CyberSentinel will prompt for a VirusTotal API key.

To configure all keys and the webhook at any time:
- **GUI:** Settings page (⚙️ sidebar)
- **CLI:** Option 11 — Configure Cloud Integrations

### Getting Free API Keys

| Service | Free Tier | URL |
|---------|-----------|-----|
| VirusTotal | 4 requests/min, 500/day | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |
| MetaDefender | 5000 requests/day | https://metadefender.opswat.com |
| MalwareBazaar | Free | https://bazaar.abuse.ch |

All API keys are encrypted at rest using Fernet AES-128 with PBKDF2-HMAC-SHA256 key derivation. Plain-text credentials are never written to disk.

### Setting Up a Discord Webhook Alert

1. **Server Settings → Integrations → Webhooks → New Webhook**
2. Copy the webhook URL
3. Paste it into CyberSentinel Settings

Format: `https://discord.com/api/webhooks/XXXXXXXXXX/XXXXXXXXXX`

Webhook requests are SSRF-protected — only HTTPS URLs targeting non-private IP ranges are accepted.

---

## GUI Pages (18 total)

| # | Page | Description |
|---|------|-------------|
| 1 | Dashboard | Live stats, recent detections, system status |
| 2 | Scan File | Full pipeline scan with cloud + ML + AI + SHAP |
| 3 | Scan Hash / IoC | Hash lookup and IoC batch processing |
| 4 | Live EDR | Live process enumeration and on-demand scanning |
| 5 | LoLBin Abuse | 5-layer LoLBin checker with parent context input |
| 6 | BYOVD Drivers | LOLDrivers hash scan of System32\drivers |
| 7 | Attack Chains | Event timeline correlation sweep |
| 8 | Baseline | Per-machine behavioral profile management |
| 9 | Fileless / AMSI | PowerShell ScriptBlock obfuscation alert history |
| 10 | Network | Host isolation and restore controls |
| 11 | Intel Feeds | Feed update management and status |
| 12 | Settings | API keys, webhook, threshold configuration |
| 13 | Evaluation | Quantitative ML benchmarking harness |
| 14 | Analyst Feedback | Manual verdict review and correction submission |
| 15 | Adaptive Learning | Queue management, anchor store, retraining controls |
| 16 | Explainability | SHAP explanation history and per-scan feature breakdown |
| 17 | Risk Scores | Dynamic Risk Score history and signal breakdown |
| 18 | Drift Monitor | Page-Hinkley statistics and concept drift alert history |

---

## Project Structure

```
CyberSentinel/
├── CyberSentinel.py          # CLI entry point — 14-option menu
├── gui.py                    # PyQt6 desktop GUI — 18 pages
├── dashboard.py              # Flask SOC web dashboard
├── eval_harness.py           # Quantitative ML benchmarking harness
├── requirements.txt          # Python dependencies
├── .gitignore
│
├── modules/
│   ├── analysis_manager.py   # Pipeline orchestration (11 tiers)
│   ├── scanner_api.py        # Cloud API wrappers (concurrent)
│   ├── ml_engine.py          # LightGBM + EMBER2024 (2568-dim)
│   ├── explainability.py     # SHAP TreeExplainer — NC-2
│   ├── risk_scorer.py        # Dynamic Risk Scoring — NC-3
│   ├── adaptive_learner.py   # Incremental retraining — NC-1
│   ├── drift_detector.py     # Page-Hinkley drift — NC-4
│   ├── daemon_monitor.py     # WMI process hook + parent context
│   ├── lolbas_detector.py    # 5-layer LoLBin detection
│   ├── byovd_detector.py     # Vulnerable driver detection
│   ├── c2_fingerprint.py     # Feodo + DGA + JA3 monitors
│   ├── chain_correlator.py   # Attack chain correlation
│   ├── baseline_engine.py    # Behavioral baselining
│   ├── amsi_monitor.py       # Fileless / AMSI detection
│   ├── intel_updater.py      # Threat feed downloader
│   ├── network_isolation.py  # Windows Firewall containment
│   ├── quarantine.py         # Fernet AES-128 quarantine
│   ├── feedback.py           # Analyst feedback + learning loop
│   ├── live_edr.py           # Live process enumeration
│   ├── utils.py              # Encryption, SQLite, webhooks
│   ├── colors.py             # Terminal color output
│   └── loading.py            # CLI spinner
│
├── data/                     # Bundled fallback intel data
│   ├── lolbas_patterns.json
│   ├── loldrivers.json
│   └── ja3_blocklist.json
│
├── Analysis Files/           # Saved session reports (.txt)
├── intel/                    # Auto-downloaded live feeds (gitignored)
├── models/                   # ML model files (gitignored)
└── threat_cache.db           # SQLite database (gitignored)
```

---

## Database

All detections are stored in `threat_cache.db` (SQLite, auto-created on first run).
Records older than 90 days are automatically pruned at startup.

| Table | Contents |
|-------|----------|
| `scan_cache` | File scan verdicts + detected APIs (for AI report continuity on cache hits) |
| `event_timeline` | Shared event bus for chain correlator |
| `chain_alerts` | Correlated attack chain alerts |
| `driver_alerts` | BYOVD findings |
| `c2_alerts` | Feodo / DGA / JA3 findings |
| `fileless_alerts` | AMSI / obfuscation findings |
| `baseline_profiles` | Per-process behavioral profiles |
| `analyst_feedback` | Analyst review decisions |
| `learning_queue` | Pending / trained ML corrections |
| `anchor_samples` | Confirmed ground-truth samples for retraining balance |
| `retraining_log` | Retraining session audit trail |
| `shap_explanations` | Per-scan SHAP feature attributions |
| `risk_scores` | Dynamic Risk Score history |
| `drift_alerts` | Concept drift detection events |
| `ml_score_log` | Rolling ML confidence score stream for drift detection |

---

## Adaptive Learning Anti-Bias Safeguards

The incremental retraining engine implements four safeguards to prevent class imbalance drift:

| Constant | Value | Purpose |
|---|---|---|
| `MIN_ANCHORS_PER_CLASS` | 5 | Blocks retraining until ≥5 confirmed samples of each class exist |
| `ANCHOR_RECENT_DAYS` | 90 | Prefers anchors confirmed within the last 90 days |
| `ANCHOR_EXPIRY_DAYS` | 365 | Excludes anchors older than 1 year from retraining batches |
| `MAX_IMBALANCE_RATIO` | 3.0 | Blocks retraining if final batch exceeds 3:1 class skew |

---

## LoLBin Detection Layers

The production LoLBin engine runs five layers in sequence per process event:

1. **Command-line normalization** — strips caret escaping (`ce^r^tutil` → `certutil`), empty-quote injection, and control characters
2. **Path normalization** — extracts binary name from full executable path so renamed binaries are caught
3. **Pattern matching** — 22 built-in high-confidence regex patterns + LOLBAS community feed
4. **Shannon entropy scoring** — flags command-line tokens with entropy > 4.2 (Base64 / obfuscation indicator)
5. **Parent process context scoring** — elevates confidence when Office/browser spawns a system binary; reduces confidence for trusted service parents

---

## Security Hardening

| Area | Implementation |
|---|---|
| API key storage | Fernet AES-128 + PBKDF2-HMAC-SHA256 (100,000 iterations) |
| Quarantine | Fernet AES-128 encrypted vault — files cannot execute |
| Webhook | HTTPS-only, blocks private IP ranges (SSRF protection) |
| Intel feed integrity | Minimum size check + JSON/CSV parseability validation |
| Hash input validation | Regex fullmatch `[0-9a-fA-F]{32|40|64}` before API calls |
| Model integrity | SHA-256 hash file (TOFU) — tamper detection on model load |
| Rate limiting | Token bucket per API: VirusTotal 4/min, OTX 10/min |
| Anchor validation | Cross-checked against scan cache before registration |

---

## Testing

See `TESTING_GUIDE.txt` for step-by-step test cases covering all features.

Quick sanity check:

```bash
# 1. Update intel feeds
python CyberSentinel.py --update-intel

# 2. Scan the EICAR test string (save as eicar.com first)
python CyberSentinel.py
# Select 1 → paste path to eicar.com → Select 5 (Consensus)
# Expected: MALICIOUS verdict from cloud + quarantine prompt
# Note: EICAR is not a valid PE — Tier 2 ML correctly skips it
```

**SHAP trigger:** Scan any `.exe` under 100 MB. The file will reach Tier 2 ML and SHAP will run automatically. Check the **Explainability** page after scanning.

**Adaptive learning trigger:** Submit a FALSE_POSITIVE correction from the Analyst Feedback page. Check the **Adaptive Learning** page — the correction appears in the queue.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'PyQt6'`**
```bash
pip install PyQt6
```

**`ModuleNotFoundError: No module named 'shap'`**
```bash
pip install shap
```

**ML engine says "Not a valid Windows PE"**
The file is not a real executable. ML and SHAP require valid PE structure (MZ magic byte). EICAR is a plain-text COM file — this is expected behaviour.

**SHAP feature count mismatch**
No longer an issue — the engine dynamically detects the feature count on first run. 2568 is the correct dimension for EMBER feature version 3.

**AI report shows "No extracted APIs"**
The file is packed, obfuscated, or has no Import Address Table. The AI report will generate an entropy/size-based YARA rule instead. This is correct behaviour.

**Webhook not firing**
- Configure URL in Settings — must start with `https://`
- Must not point to a private IP range (10.x, 192.168.x, 127.x)

**Retraining blocked — "Anchor store insufficient"**
Safety feature. Confirm more verdicts in Analyst Feedback (both SAFE and MALICIOUS files) until the anchor store reaches 5 samples per class. Use Force Retrain to override with a warning.

**Daemon requires Administrator**
Right-click Command Prompt → Run as Administrator.

---

## License

MIT License — see `LICENSE` file.

---

## Acknowledgements

- [LOLBAS Project](https://lolbas-project.github.io/) — Living-off-the-land binary database
- [LOLDrivers](https://www.loldrivers.io/) — Vulnerable kernel driver database
- [abuse.ch](https://abuse.ch/) — Feodo Tracker and SSLBL JA3 feeds
- [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) — ML feature dataset and thrember extractor
- [Ollama](https://ollama.com) — Local LLM inference
- [SHAP](https://github.com/shap/shap) — SHapley Additive exPlanations (Lundberg & Lee, 2017)
- [LightGBM](https://github.com/microsoft/LightGBM) — Gradient boosting framework
