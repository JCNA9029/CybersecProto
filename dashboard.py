# dashboard.py — CyberSentinel SOC Dashboard v1
# Run: python dashboard.py   OR   python CyberSentinel.py --dashboard
# Opens at http://127.0.0.1:5000

import sqlite3
import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# CRITICAL: Always resolve DB path from THIS script's location, never from cwd.
# This fixes the blank-dashboard bug where dashboard and CLI used different DBs.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "threat_cache.db")


# ─── Database helper ──────────────────────────────────────────────────────────

def _q(sql, params=()):
    """Execute a SELECT and return list of dicts. Returns [] on any error."""
    if not os.path.isfile(DB):
        return []
    try:
        with sqlite3.connect(DB) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(sql, params).fetchall()]
    except Exception:
        return []

def _cnt(sql, params=()):
    rows = _q(sql, params)
    return rows[0]["c"] if rows else 0


# ─── HTML ─────────────────────────────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CyberSentinel SOC</title>
<style>
  :root{
    --bg:#0d1117; --s:#161b22; --b:#30363d; --t:#c9d1d9; --m:#8b949e;
    --r:#f85149;  --g:#3fb950; --y:#d29922; --bl:#58a6ff; --p:#bc8cff;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--t);font-family:Consolas,monospace;font-size:13px}

  header{
    background:var(--s);border-bottom:1px solid var(--b);
    padding:14px 28px;display:flex;align-items:center;gap:12px;
  }
  header h1{color:var(--bl);font-size:1.1rem}
  #status{font-size:.8rem}
  #status.ok   {color:var(--g)}
  #status.err  {color:var(--r)}
  #status.warn {color:var(--y)}
  #rfbtn{
    margin-left:auto;background:var(--s);border:1px solid var(--b);
    color:var(--t);padding:5px 14px;border-radius:5px;cursor:pointer;
  }
  #rfbtn:hover{border-color:var(--bl);color:var(--bl)}

  .stats{
    display:grid;grid-template-columns:repeat(7,1fr);
    gap:12px;padding:20px 28px;
  }
  .card{
    background:var(--s);border:1px solid var(--b);
    border-radius:8px;padding:16px;text-align:center;
  }
  .card .v{font-size:1.7rem;font-weight:bold}
  .card .l{color:var(--m);font-size:.75rem;margin-top:3px}

  .tabs{display:flex;gap:0;padding:0 28px;margin-bottom:-1px}
  .tab{
    padding:7px 18px;cursor:pointer;border:1px solid var(--b);
    border-bottom:none;background:var(--bg);color:var(--m);
    border-radius:5px 5px 0 0;font-size:.8rem;
  }
  .tab.active{background:var(--s);color:var(--t)}

  .panel-wrap{
    background:var(--s);border:1px solid var(--b);
    border-radius:0 8px 8px 8px;padding:16px 20px;margin:0 28px 24px;
    min-height:120px;overflow-x:auto;
  }
  .panel{display:none}.panel.active{display:block}

  table{width:100%;border-collapse:collapse;table-layout:auto}
  th{text-align:left;padding:6px 10px;color:var(--m);border-bottom:1px solid var(--b);white-space:nowrap}
  td{padding:6px 10px;border-bottom:1px solid var(--b);white-space:nowrap;max-width:480px;overflow:hidden;text-overflow:ellipsis}
  td:last-child{white-space:normal;max-width:none}
  tr:hover td{background:rgba(255,255,255,.03)}

  .badge{
    display:inline-block;padding:2px 7px;border-radius:4px;
    font-size:.72rem;font-weight:bold;
  }
  .br{background:rgba(248,81,73,.15);color:var(--r)}
  .bg{background:rgba(63,185,80,.15);color:var(--g)}
  .by{background:rgba(210,153,34,.15);color:var(--y)}
  .bb{background:rgba(88,166,255,.15);color:var(--bl)}
  .bp{background:rgba(188,140,255,.15);color:var(--p)}
  .sha{color:var(--m);font-size:.72rem}

  #dbinfo{
    margin:0 28px 16px;padding:10px 14px;background:var(--s);
    border:1px solid var(--b);border-radius:6px;font-size:.75rem;
    color:var(--m);
  }
  #dbinfo span{color:var(--bl)}
  .empty-msg{color:var(--m);padding:16px 10px;font-style:italic}
</style>
</head>
<body>

<header>
  <h1>🛡️ CyberSentinel SOC Dashboard</h1>
  <span id="status" class="warn">Connecting...</span>
  <button id="rfbtn" onclick="loadAll()">↻ Refresh</button>
</header>

<div id="dbinfo">DB path: <span id="dbpath">—</span> &nbsp;|&nbsp; Records: <span id="dbrows">—</span></div>

<div class="stats">
  <div class="card"><div class="v bb" id="s-t">—</div><div class="l">Total Scans</div></div>
  <div class="card"><div class="v br" id="s-m">—</div><div class="l">Malicious</div></div>
  <div class="card"><div class="v bg" id="s-s">—</div><div class="l">Safe</div></div>
  <div class="card"><div class="v by" id="s-fp">—</div><div class="l">False Positives</div></div>
  <div class="card"><div class="v br" id="s-ch">—</div><div class="l">Chain Alerts</div></div>
  <div class="card"><div class="v br" id="s-bv">—</div><div class="l">BYOVD Alerts</div></div>
  <div class="card"><div class="v bp" id="s-fi">—</div><div class="l">Fileless Alerts</div></div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('scans')">Scan History</div>
  <div class="tab" onclick="showTab('chains')">Attack Chains</div>
  <div class="tab" onclick="showTab('byovd')">BYOVD</div>
  <div class="tab" onclick="showTab('c2')">C2 / DGA</div>
  <div class="tab" onclick="showTab('fileless')">Fileless</div>
  <div class="tab" onclick="showTab('feedback')">Analyst Feedback</div>
  <div class="tab" onclick="showTab('timeline')">Event Timeline</div>
</div>

<div class="panel-wrap">
  <div id="tab-scans" class="panel active">
    <table>
      <thead><tr><th>Timestamp</th><th>File</th><th>SHA-256</th><th>Verdict</th></tr></thead>
      <tbody id="t-scans"></tbody>
    </table>
  </div>
  <div id="tab-chains" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>Chain</th><th>MITRE</th><th>Severity</th><th>Description</th></tr></thead>
      <tbody id="t-chains"></tbody>
    </table>
  </div>
  <div id="tab-byovd" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>Driver</th><th>CVE</th><th>SHA-256</th><th>Details</th></tr></thead>
      <tbody id="t-byovd"></tbody>
    </table>
  </div>
  <div id="tab-c2" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>Type</th><th>Indicator</th><th>Malware</th><th>Details</th></tr></thead>
      <tbody id="t-c2"></tbody>
    </table>
  </div>
  <div id="tab-fileless" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>Source</th><th>PID</th><th>Findings</th></tr></thead>
      <tbody id="t-fileless"></tbody>
    </table>
  </div>
  <div id="tab-feedback" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>File</th><th>System Verdict</th><th>Analyst</th><th>Notes</th></tr></thead>
      <tbody id="t-feedback"></tbody>
    </table>
  </div>
  <div id="tab-timeline" class="panel">
    <table>
      <thead><tr><th>Timestamp</th><th>Event Type</th><th>PID</th><th>Detail</th></tr></thead>
      <tbody id="t-timeline"></tbody>
    </table>
  </div>
</div>

<script>
// ── Tab switching ────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.textContent.toLowerCase().includes(name.slice(0,4)));
  });
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.toggle('active', p.id === 'tab-' + name);
  });
}

// ── Verdict badge ────────────────────────────────────────────────────────────
function vbadge(v) {
  if (!v) return '<span class="badge bb">UNKNOWN</span>';
  const u = v.toUpperCase();
  if (u.includes('MALICIOUS') || u.includes('CRITICAL')) return `<span class="badge br">${v}</span>`;
  if (u.includes('SUSPICIOUS')) return `<span class="badge by">${v}</span>`;
  if (u.includes('SAFE'))       return `<span class="badge bg">${v}</span>`;
  return `<span class="badge bb">${v}</span>`;
}
function sbadge(s) {
  return s === 'CRITICAL'
    ? `<span class="badge br">${s}</span>`
    : `<span class="badge by">${s}</span>`;
}

// ── Empty row ────────────────────────────────────────────────────────────────
function emptyRow(msg) {
  return `<tr><td colspan="6" class="empty-msg">${msg}</td></tr>`;
}

// ── Safe JSON fetch — never throws ──────────────────────────────────────────
async function safeFetch(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    console.error(url, e);
    return null;
  }
}

// ── Main load ────────────────────────────────────────────────────────────────
async function loadAll() {
  const status = document.getElementById('status');
  status.textContent = 'Loading...';
  status.className = 'warn';

  // 1. Health check first — shows DB path and confirms connectivity
  const health = await safeFetch('/api/health');
  if (!health) {
    status.textContent = 'ERROR — Flask API not responding';
    status.className = 'err';
    return;
  }
  if (!health.ok) {
    status.textContent = `ERROR — DB not found at: ${health.db_path}`;
    status.className = 'err';
    document.getElementById('dbpath').textContent = health.db_path;
    document.getElementById('dbrows').textContent = 'database missing — run a scan first';
    return;
  }

  // Show DB path and total row count in info bar
  document.getElementById('dbpath').textContent = health.db_path;
  const totalRows = Object.values(health.row_counts || {}).reduce((a,b) => a+b, 0);
  document.getElementById('dbrows').textContent =
    Object.entries(health.row_counts || {})
      .map(([t,c]) => `${t}: ${c}`)
      .join('  |  ');

  // 2. Stats
  const st = await safeFetch('/api/stats');
  if (st) {
    document.getElementById('s-t').textContent  = st.total           ?? '—';
    document.getElementById('s-m').textContent  = st.malicious       ?? '—';
    document.getElementById('s-s').textContent  = st.safe            ?? '—';
    document.getElementById('s-fp').textContent = st.false_positives ?? '—';
    document.getElementById('s-ch').textContent = st.chain_alerts    ?? '—';
    document.getElementById('s-bv').textContent = st.byovd_alerts    ?? '—';
    document.getElementById('s-fi').textContent = st.fileless_alerts ?? '—';
  }

  // 3. Tables
  const defs = [
    ['scans',    '/api/scans',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td>${r.filename||'—'}</td>
       <td class="sha">${(r.sha256||'').slice(0,24)}…</td>
       <td>${vbadge(r.verdict)}</td>
     </tr>`],
    ['chains',   '/api/chains',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td>${r.chain_name||'—'}</td>
       <td class="sha">${r.mitre||'—'}</td>
       <td>${sbadge(r.severity||'MEDIUM')}</td>
       <td style="color:var(--m)">${(r.description||'').slice(0,80)}</td>
     </tr>`],
    ['byovd',    '/api/byovd',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td>${r.driver_name||'—'}</td>
       <td class="sha">${r.cve||'N/A'}</td>
       <td class="sha">${(r.sha256||'').slice(0,24)}…</td>
       <td style="color:var(--m)">${(r.description||'').slice(0,60)}</td>
     </tr>`],
    ['c2',       '/api/c2',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td><span class="badge bp">${r.detection_type||'—'}</span></td>
       <td class="sha">${r.indicator||'—'}</td>
       <td>${r.malware_family||'—'}</td>
       <td style="color:var(--m)">${(r.details||'').slice(0,60)}</td>
     </tr>`],
    ['fileless', '/api/fileless',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td>${r.source||'—'}</td>
       <td>${r.pid||'—'}</td>
       <td style="color:var(--m)">${(r.findings||'').slice(0,120)}</td>
     </tr>`],
    ['feedback', '/api/feedback',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td>${r.filename||'—'}</td>
       <td>${vbadge(r.original_verdict)}</td>
       <td><span class="badge ${r.analyst_verdict==='FALSE_POSITIVE'?'by':'bg'}">${r.analyst_verdict||'—'}</span></td>
       <td style="color:var(--m)">${r.notes||''}</td>
     </tr>`],
    ['timeline', '/api/timeline',
     r => `<tr>
       <td>${r.timestamp||'—'}</td>
       <td><span class="badge bb">${r.event_type||'—'}</span></td>
       <td>${r.pid||'—'}</td>
       <td style="color:var(--m)">${(r.detail||'').slice(0,80)}</td>
     </tr>`],
  ];

  for (const [name, url, tmpl] of defs) {
    const rows = await safeFetch(url);
    const tbody = document.getElementById('t-' + name);
    if (!rows || rows.length === 0) {
      tbody.innerHTML = emptyRow('No records yet.');
    } else {
      tbody.innerHTML = rows.map(tmpl).join('');
    }
  }

  status.textContent = 'Updated: ' + new Date().toLocaleTimeString();
  status.className = 'ok';
}

loadAll();
setInterval(loadAll, 30000);
</script>
</body>
</html>
"""


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serves the main SOC dashboard HTML page."""
    return render_template_string(HTML)

@app.route("/api/health")
def api_health():
    """Returns database health status including path, existence, and table row counts."""
    db_exists = os.path.isfile(DB)
    tables, row_counts = [], {}
    if db_exists:
        try:
            with sqlite3.connect(DB) as c:
                tables = [r[0] for r in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for t in tables:
                    row_counts[t] = c.execute(
                        f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        except Exception as e:
            return jsonify({"ok": False, "error": str(e), "db_path": DB})
    return jsonify({
        "ok": db_exists, "db_path": DB,
        "db_exists": db_exists, "tables": tables, "row_counts": row_counts,
    })

@app.route("/api/stats")
def api_stats():
    """Returns aggregate detection statistics for the dashboard stat cards."""
    return jsonify({
        "total":           _cnt("SELECT COUNT(*) c FROM scan_cache"),
        "malicious":       _cnt("SELECT COUNT(*) c FROM scan_cache WHERE verdict LIKE '%MALICIOUS%' OR verdict LIKE '%CRITICAL%'"),
        "safe":            _cnt("SELECT COUNT(*) c FROM scan_cache WHERE verdict='SAFE'"),
        "false_positives": _cnt("SELECT COUNT(*) c FROM analyst_feedback WHERE analyst_verdict='FALSE_POSITIVE'"),
        "chain_alerts":    _cnt("SELECT COUNT(*) c FROM chain_alerts"),
        "byovd_alerts":    _cnt("SELECT COUNT(*) c FROM driver_alerts"),
        "fileless_alerts": _cnt("SELECT COUNT(*) c FROM fileless_alerts"),
    })

@app.route("/api/scans")
def api_scans():
    """Returns the most recent scan history records from the cache."""
    return jsonify(_q(
        "SELECT sha256, filename, verdict, timestamp FROM scan_cache ORDER BY timestamp DESC LIMIT 200"))

@app.route("/api/chains")
def api_chains():
    """Returns recent attack chain correlation alerts."""
    return jsonify(_q(
        "SELECT chain_name, mitre, severity, description, timestamp FROM chain_alerts ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/byovd")
def api_byovd():
    """Returns recent BYOVD vulnerable driver detection alerts."""
    return jsonify(_q(
        "SELECT sha256, driver_name, path, cve, description, timestamp FROM driver_alerts ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/c2")
def api_c2():
    """Returns recent C2 fingerprinting alerts."""
    return jsonify(_q(
        "SELECT detection_type, indicator, malware_family, details, timestamp FROM c2_alerts ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/fileless")
def api_fileless():
    """Returns recent fileless and AMSI detection alerts."""
    return jsonify(_q(
        "SELECT source, findings, pid, timestamp FROM fileless_alerts ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/feedback")
def api_feedback():
    """Returns analyst feedback history records."""
    return jsonify(_q(
        "SELECT sha256, filename, original_verdict, analyst_verdict, notes, timestamp FROM analyst_feedback ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/timeline")
def api_timeline():
    """Returns the shared event timeline entries used by chain correlation."""
    return jsonify(_q(
        "SELECT event_type, detail, pid, timestamp FROM event_timeline ORDER BY timestamp DESC LIMIT 200"))


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n[*] CyberSentinel SOC Dashboard")
    print(f"[*] Database : {DB}")
    print(f"[*] DB exists: {os.path.isfile(DB)}")
    print(f"[*] Open     : http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
