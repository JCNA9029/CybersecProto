# CyberSentinel SOC Dashboard — Complete Manual

---

## What the Dashboard Is

The SOC Dashboard is a local web application built with Flask. It reads data
directly from `threat_cache.db` — the same SQLite database that CyberSentinel
writes to when it scans files, detects chains, flags drivers, etc.

It does NOT run in real time by itself. It is a **read-only viewer** of what
CyberSentinel has already logged. Think of it as your investigation screen,
not your detection engine.

---

## Requirement Checklist

Before the dashboard will work, you need ALL of the following:

| # | Requirement | How to verify |
|---|-------------|---------------|
| 1 | Python 3.10+ installed | `python --version` |
| 2 | Flask installed | `python -c "import flask; print(flask.__version__)"` |
| 3 | CyberSentinel has been run at least once | `threat_cache.db` file must exist in the project folder |
| 4 | At least one scan has been completed | Database must have data |
| 5 | Port 5000 is not in use by another app | See troubleshooting below |

Install Flask if missing:
```
pip install flask
```

---

## The Single Most Common Mistake — Working Directory

The dashboard reads `threat_cache.db` from **wherever your terminal is pointing
when you run the command**. If you run it from the wrong folder, it either
crashes or shows a blank dashboard because it cannot find the database.

**ALWAYS run the dashboard from inside the CyberSentinel project folder.**

### Step 1 — Open Command Prompt or PowerShell

Press `Win + R`, type `cmd`, press Enter.

### Step 2 — Navigate to the project folder

```
cd C:\CyberSentinel
```

Replace the path with wherever your CyberSentinel folder actually is.
You can also just type `cd ` (with a space) and then drag-and-drop the
folder from File Explorer into the terminal window — it will paste the path.

### Step 3 — Confirm you are in the right place

```
dir
```

You should see these files listed:
```
CyberSentinel.py
dashboard.py
threat_cache.db       ← This MUST be present
requirements.txt
modules\
```

If `threat_cache.db` is NOT listed, go run a scan first:
```
python CyberSentinel.py
```
Scan any file. Exit. Then come back and start the dashboard.

### Step 4 — Start the dashboard

**Option A — Directly:**
```
python dashboard.py
```

**Option B — Via main app:**
```
python CyberSentinel.py --dashboard
```

Both do the same thing.

### Step 5 — Open your browser

Do NOT close the terminal. Open any browser (Chrome, Edge, Firefox) and go to:

```
http://127.0.0.1:5000
```

or equivalently:

```
http://localhost:5000
```

You should see the dark CyberSentinel dashboard with your scan data.

---

## What Each Tab Shows

| Tab | What it displays | Populated by |
|-----|-----------------|--------------|
| **Scan History** | Every file scan with SHA-256, filename, verdict, timestamp | Running scans via Menu 1, 2, or 3 |
| **Attack Chains** | Multi-step attack sequences detected by the Chain Correlator | Daemon mode or Menu 6 |
| **BYOVD** | Vulnerable kernel drivers detected | Menu 5 or daemon mode |
| **C2 / DGA** | Feodo IP matches, DGA beaconing, JA3 fingerprint hits | Daemon mode (background monitoring) |
| **Fileless** | PowerShell obfuscation alerts from AMSI monitor | Daemon mode with pywin32 installed |
| **Analyst Feedback** | Your Y/F/S reviews after each malicious verdict | Interactive scan sessions |
| **Event Timeline** | Raw event log that the Chain Correlator reads from | All detectors write here |

---

## Why Tabs Show "No records yet"

This is normal and expected — it means that specific detection type has not
been triggered yet. Here is what each tab needs:

**Scan History** — Run `python CyberSentinel.py` and scan at least one file.
The EICAR test file is perfect for this:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
Save that as `eicar.txt` and scan it.

**Attack Chains** — Requires the daemon (`--daemon`) to be running and
multiple detection events to occur within 10 minutes. You will not see
data here from a single interactive scan.

**BYOVD** — Requires running Menu Option 5 (BYOVD Vulnerable Driver Scan)
or running the daemon and loading a vulnerable driver.

**C2 / DGA** — Requires daemon mode with an active network connection.
Feodo alerts only appear when an outbound connection hits a known C2 IP.

**Fileless** — Requires pywin32 AND PowerShell Script Block Logging to be
enabled on your machine. See the Fileless section below.

**Analyst Feedback** — Requires you to answer Y/F/S after a scan verdict
in interactive mode.

---

## Running the Dashboard AND CyberSentinel at the Same Time

The dashboard and CyberSentinel write/read the same database file.
To see live data while scanning:

1. Open **two separate terminal windows**.
2. In Terminal 1 — start the dashboard:
   ```
   cd C:\CyberSentinel
   python dashboard.py
   ```
3. In Terminal 2 — run scans or start the daemon:
   ```
   cd C:\CyberSentinel
   python CyberSentinel.py
   ```
4. As you complete scans in Terminal 2, click **↻ Refresh** in the browser
   or wait 30 seconds for the auto-refresh to update the dashboard.

---

## Enabling Fileless / AMSI Alerts (Advanced)

The Fileless tab requires two things:

**1. Install pywin32:**
```
pip install pywin32
```

**2. Enable PowerShell Script Block Logging** (run as Administrator in PowerShell):
```powershell
$path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $path)) { New-Item $path -Force }
Set-ItemProperty $path -Name "EnableScriptBlockLogging" -Value 1
```

After this, any PowerShell execution on your machine will be logged to the
Windows Event Log and the AMSI monitor will pick it up when the daemon runs.
The dashboard Fileless tab will start showing results.

---

## Troubleshooting

### "Address already in use" / Port 5000 error
Something else is using port 5000. Find and stop it:
```
netstat -ano | findstr :5000
taskkill /PID <the_pid_number> /F
```
Or change the dashboard port — open `dashboard.py`, find the last line,
and change `port=5000` to `port=5001`. Then go to `http://127.0.0.1:5001`.

### Dashboard opens but all numbers show "—" and tables are empty
The database does not exist yet, or it is in a different folder.
Check: does `threat_cache.db` exist in your CyberSentinel folder?
```
dir C:\CyberSentinel\threat_cache.db
```
If not found, run CyberSentinel and complete at least one scan first.

### "ModuleNotFoundError: No module named 'flask'"
```
pip install flask
```

### Dashboard shows old data / does not update
The dashboard auto-refreshes every 30 seconds. You can also click
**↻ Refresh** in the top right of the page manually.
Note: The database is only updated when CyberSentinel is actively scanning.
If no scans are running, the data will not change.

### Browser shows "This site can't be reached"
The dashboard is not running. Go back to your terminal and confirm you see:
```
[*] CyberSentinel SOC Dashboard → http://127.0.0.1:5000
 * Running on http://127.0.0.1:5000
```
If you do not see this, the dashboard crashed. Read the error message in
the terminal — it will tell you exactly what failed.

### Windows Firewall popup when starting dashboard
Click "Allow access" or "Allow private networks". The dashboard only
listens on 127.0.0.1 (localhost) — it is not accessible from outside
your machine, so this is safe to allow.

---

## Full Startup Sequence (Quick Reference)

```
1.  Open Command Prompt
2.  cd C:\CyberSentinel
3.  python dashboard.py
4.  Open browser → http://127.0.0.1:5000
5.  Open a SECOND terminal for running scans
6.  cd C:\CyberSentinel
7.  python CyberSentinel.py
8.  Run scans, then click Refresh in the browser
```

---

## Database Location Reference

All data shown in the dashboard comes from these SQLite tables inside
`threat_cache.db`:

| Dashboard Tab | Database Table |
|---------------|---------------|
| Scan History | `scan_cache` |
| Attack Chains | `chain_alerts` |
| BYOVD | `driver_alerts` |
| C2 / DGA | `c2_alerts` |
| Fileless | `fileless_alerts` |
| Analyst Feedback | `analyst_feedback` |
| Event Timeline | `event_timeline` |

If you want to inspect the database directly, install DB Browser for SQLite:
https://sqlitebrowser.org/ — a free GUI tool that lets you browse every table.
