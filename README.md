<div align="center">

# 🛡️ CyberSentinel v2

**A Multi-Tiered Endpoint Detection & Response (EDR) Framework**

*Built for under-resourced SOCs — Python-native, offline-capable, AI-assisted*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

</div>

---

## Overview

CyberSentinel is a modular EDR framework that chains multiple detection tiers — cloud reputation, offline machine learning, and local AI analysis — into a single pipeline. It includes a CLI, a desktop GUI (PyQt6), a SOC web dashboard (Flask), and a headless daemon for real-time folder monitoring.

Designed as a thesis project for cybersecurity programs and SOC teams that cannot afford commercial EDR licensing.

---

## Detection Architecture

```
File / Process / Network Event
         │
    ┌────▼─────────────────────────────────────────────────────┐
    │  Tier 0    Exclusion / Allowlist check                   │
    │  Tier 0.5  Local SQLite cache (instant repeat-detection) │
    │  Tier 1    Cloud Consensus: VirusTotal + OTX +           │
    │            MetaDefender + MalwareBazaar (concurrent)     │
    │  Tier 2    Offline LightGBM ML — EMBER2024 PE features   │
    │  Tier 3    Local Ollama LLM — YARA + MITRE triage report │
    │  Tier 4    Containment: Quarantine + Network Isolation   │
    └──────────────────────────────────────────────────────────┘
```

---

## Features

| Category | Feature |
|----------|---------|
| **Scanning** | File, directory, hash, IoC batch list, live process |
| **Cloud Intel** | VirusTotal, AlienVault OTX, MetaDefender, MalwareBazaar |
| **ML Detection** | LightGBM Stage 1 (malware/safe) + Stage 2 (family classification) |
| **AI Reports** | Ollama LLM triage reports with MITRE ATT&CK mapping and YARA rules |
| **LoLBin Detection** | 22 built-in patterns + live LOLBAS feed (certutil, mshta, powershell -enc, etc.) |
| **BYOVD Detection** | Vulnerable driver detection via LOLDrivers SHA-256 + filename matching |
| **C2 Fingerprinting** | Feodo IP blocklist + DGA entropy analysis + JA3 TLS fingerprinting |
| **Attack Chains** | Multi-event correlation with 7 predefined chain patterns |
| **Baselining** | Per-machine behavioral baselining — flags process deviations |
| **Fileless/AMSI** | PowerShell ScriptBlock obfuscation detection via Windows Event Log 4104 |
| **Quarantine** | AES-encrypted file quarantine with hidden vault directory |
| **Network Isolation** | Windows Firewall emergency host isolation + one-click restore |
| **SOC Dashboard** | Flask web dashboard — 7 tabs, live stats, auto-refresh |
| **Desktop GUI** | Full PyQt6 GUI with all features, colored console, process table |
| **Daemon Mode** | Headless real-time folder monitoring with auto-quarantine |
| **Webhook Alerts** | Discord / Slack / Teams webhook on every malicious verdict |
| **Analyst Feedback** | True Positive / False Positive feedback loop with exclusion list |
| **Intel Feeds** | Auto-updating LOLBAS, LOLDrivers, Feodo, JA3 feeds |

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

These cannot be listed in `requirements.txt` as they require Windows:

```bash
pip install pywin32
pip install wmi
```

> `pywin32` is required for the AMSI monitor and WMI daemon.
> `wmi` is required for the Tier 0 kernel-bridge process hook.

### Step 5 — Install Ollama and Pull a Model

1. Download and install Ollama from https://ollama.com
2. Open a terminal and pull the recommended model:

```bash
ollama pull deepseek-r1:8b
```

Fallback options (less RAM required):

```bash
ollama pull qwen2.5:7b    # 4.7 GB RAM
ollama pull qwen2.5:3b    # 2.0 GB RAM
```

Ollama must be running in the background when using the AI triage report feature.

### Step 6 — Install EMBER2024 ML Features (Optional but Recommended)

The ML engine uses thrember for PE feature extraction from the EMBER2024 dataset:

```bash
git clone https://github.com/FutureComputing4AI/EMBER2024
cd EMBER2024
pip install .
cd ..
```

Without this, Tier 2 ML scanning is disabled. Cloud and AI tiers still function.

### Step 7 — (Optional) Install Npcap for JA3 Monitor

Download and install from https://npcap.com/

Then uncomment scapy in requirements.txt and install:

```bash
pip install scapy
```

### Step 8 — Enable PowerShell ScriptBlock Logging for AMSI Monitor

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

Full GUI with all 12 pages, colored console, process table, clickable controls.

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

Monitors the folder continuously. Auto-quarantines threats. Fires webhook alerts.

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

### Setting Up a Discord Webhook Alert

1. In your Discord server: **Server Settings → Integrations → Webhooks → New Webhook**
2. Copy the webhook URL
3. Paste it into CyberSentinel settings

Format: `https://discord.com/api/webhooks/XXXXXXXXXX/XXXXXXXXXX`

---

## Project Structure

```
CyberSentinel/
├── CyberSentinel.py          # CLI entry point — 14-option menu
├── gui.py                    # PyQt6 desktop GUI
├── dashboard.py              # Flask SOC web dashboard
├── eval_harness.py           # ML benchmarking harness
├── requirements.txt          # Python dependencies
├── .gitignore
│
├── modules/
│   ├── analysis_manager.py   # 5-tier pipeline orchestration
│   ├── scanner_api.py        # Cloud API wrappers (concurrent)
│   ├── ml_engine.py          # LightGBM + EMBER2024
│   ├── daemon_monitor.py     # 7-thread headless daemon
│   ├── lolbas_detector.py    # LoLBin abuse pattern matching
│   ├── byovd_detector.py     # Vulnerable driver detection
│   ├── c2_fingerprint.py     # Feodo + DGA + JA3 monitors
│   ├── chain_correlator.py   # Attack chain correlation
│   ├── baseline_engine.py    # Behavioral baselining
│   ├── amsi_monitor.py       # Fileless/AMSI detection
│   ├── intel_updater.py      # Threat feed downloader
│   ├── network_isolation.py  # Windows Firewall containment
│   ├── quarantine.py         # Encrypted file quarantine
│   ├── feedback.py           # Analyst feedback loop
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
├── intel/                    # Auto-downloaded live feeds (gitignored)
├── models/                   # ML model files (gitignored)
└── threat_cache.db           # SQLite database (gitignored)
```

---

## Database

All detections are stored in `threat_cache.db` (SQLite, auto-created on first run):

| Table | Contents |
|-------|----------|
| `scan_cache` | File scan verdicts |
| `event_timeline` | Shared event bus for chain correlator |
| `chain_alerts` | Correlated attack chain alerts |
| `driver_alerts` | BYOVD findings |
| `c2_alerts` | Feodo / DGA / JA3 findings |
| `fileless_alerts` | AMSI/obfuscation findings |
| `baseline_profiles` | Per-process behavioral profiles |
| `analyst_feedback` | Analyst review decisions |

---

## Testing

See `TESTING_GUIDE.txt` for step-by-step test cases covering all 22 features,
including the EICAR standard test file procedure.

Quick sanity check:

```bash
# 1. Update intel feeds
python CyberSentinel.py --update-intel

# 2. Scan the EICAR test string (save as eicar.com first)
python CyberSentinel.py
# Select 1 → paste path to eicar.com → Select 5 (Consensus)
# Expected: MALICIOUS verdict + webhook alert + quarantine prompt
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'PyQt6'`**
```bash
pip install PyQt6
```

**`ModuleNotFoundError: No module named 'pefile'` / `lightgbm` / etc.**
```bash
pip install -r requirements.txt
```

**ML engine says "Not a valid Windows PE"**
The file is not a real executable (e.g. EICAR is a text file). ML requires valid PE structure. Use cloud APIs for non-PE files.

**Webhook not firing**
- Configure the URL in Settings (Option 11 / GUI Settings page)
- URL must start with `https://`
- Test with the **Test** button in the GUI Settings page

**Dashboard shows blank / "Loading..."**
- Run `python dashboard.py` from inside the CyberSentinel project folder
- Verify at http://127.0.0.1:5000/api/health — `db_exists` must be `true`
- Run at least one scan first to create `threat_cache.db`

**Daemon requires Administrator**
Right-click Command Prompt → Run as Administrator, then:
```bash
python CyberSentinel.py --daemon "C:\Path\To\Watch"
```

---

## License

MIT License — see `LICENSE` file.

---

## Acknowledgements

- [LOLBAS Project](https://lolbas-project.github.io/) — Living-off-the-land binary database
- [LOLDrivers](https://www.loldrivers.io/) — Vulnerable kernel driver database
- [abuse.ch](https://abuse.ch/) — Feodo Tracker and SSLBL JA3 feeds
- [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) — ML feature dataset
- [Ollama](https://ollama.com) — Local LLM inference
