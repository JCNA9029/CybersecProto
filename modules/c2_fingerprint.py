# modules/c2_fingerprint.py — C2 Traffic Fingerprinting Engine
#
# Three passive detection mechanisms — no traffic decryption required:
#   1. Feodo IP blocklist  — checks outbound connections vs abuse.ch botnet C2 IPs
#   2. DNS DGA entropy     — Shannon entropy analysis detects Domain Generation Algorithms
#   3. JA3 TLS fingerprint — matches TLS ClientHello signatures vs abuse.ch SSLBL
#                            (requires: pip install scapy + Npcap on Windows)

import json
import math
import hashlib
import struct
import sqlite3
import datetime
import threading
import time
from collections import defaultdict

import psutil
from . import utils
from .intel_updater import load_feodo_blocklist, load_ja3_blocklist


# ─────────────────────────────────────────────
#  SHARED UTILITIES
# ─────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. High values (>3.5) indicate DGA names."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_dga_suspicious(fqdn: str) -> tuple[bool, float]:
    """
    Heuristic DGA detection. Returns (suspicious, entropy).
    Criteria: entropy > 3.5  AND  label length > 12  OR  consonant/vowel ratio > 4.
    Known CDN/infra suffixes are whitelisted.
    """
    # R5 Fix: Expanded CDN/infrastructure whitelist to reduce false positives
    # in enterprise environments with many high-entropy cloud service subdomains.
    SAFE_SUFFIXES = {
        # Google
        "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "googleusercontent.com", "ggpht.com",
        # Microsoft / Azure
        "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com",
        "live.com", "outlook.com", "azure.com", "azureedge.net",
        "blob.core.windows.net", "azurefd.net", "trafficmanager.net",
        # AWS
        "amazonaws.com", "awsstatic.com", "cloudfront.net",
        "execute-api.us-east-1.amazonaws.com",
        # Akamai / CDN
        "akamai.net", "akamaiedge.net", "akamaihd.net", "edgesuite.net",
        # Fastly / Cloudflare
        "fastly.net", "fastly.com", "cloudflare.com", "cloudflare.net",
        "cdn77.com", "edgecastcdn.net", "llnwd.net",
        # Certificate authorities
        "digicert.com", "verisign.com", "letsencrypt.org",
        "sectigo.com", "comodo.com", "globalsign.com",
        # Apple
        "apple.com", "icloud.com", "mzstatic.com",
        # Misc enterprise SaaS
        "adobe.com", "adobecc.com", "salesforce.com",
        "office.com", "office365.com", "sharepoint.com",
    }
    for safe in SAFE_SUFFIXES:
        if fqdn.endswith(safe):
            return False, 0.0

    parts = fqdn.split(".")
    if len(parts) < 2:
        return False, 0.0

    label = parts[0]
    if len(label) < 10:
        return False, 0.0

    entropy = _shannon_entropy(label)
    vowels    = sum(1 for c in label.lower() if c in "aeiou")
    cv_ratio  = (len(label) - vowels) / max(vowels, 1)
    suspicious = entropy > 3.5 and (len(label) > 12 or cv_ratio > 4)
    return suspicious, entropy


# ─────────────────────────────────────────────
#  FEODO IP MONITOR
# ─────────────────────────────────────────────

class FeodoMonitor:
    """
    Polls psutil.net_connections() every N seconds. For each new ESTABLISHED
    connection, checks the remote IP against the Feodo Tracker C2 blocklist.
    Identifies the owning process for targeted containment.
    MITRE: T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol)
    """

    def __init__(self, poll_interval: float = 5.0):
        self.poll_interval   = poll_interval
        self._blocklist: set[str] = load_feodo_blocklist()
        self._seen: set[tuple]    = set()
        self._running             = False
        self._thread: threading.Thread | None = None
        if self._blocklist:
            print(f"[*] Feodo Tracker: {len(self._blocklist)} C2 IPs loaded.")

    def start(self):
        """Starts the background monitoring thread."""
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signals the monitoring thread to stop."""
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._check()
            except Exception:
                pass  # Non-critical: operation continues regardless
            time.sleep(self.poll_interval)

    def _check(self):
        if not self._blocklist:
            return
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port)
            if key in self._seen:
                continue
            self._seen.add(key)

            if conn.raddr.ip not in self._blocklist:
                continue

            proc_name, proc_path = "Unknown", "Unknown"
            try:
                if conn.pid:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                    proc_path = p.exe()
            except Exception:
                pass  # Non-critical: operation continues regardless

            finding = {
                "type": "C2_IP_MATCH", "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port, "process_name": proc_name,
                "process_path": proc_path, "pid": conn.pid,
            }
            self._persist(finding)
            self._print_alert(finding)

    def check_ip(self, ip: str) -> bool:
        """Checks a single IP address against the Feodo C2 blocklist. Returns a finding dict or None."""
        return ip in self._blocklist

    def _persist(self, f: dict):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO c2_alerts (detection_type,indicator,malware_family,details,timestamp) VALUES (?,?,?,?,?)",
                    ("C2_IP", f["remote_ip"], "Feodo-Tracked", json.dumps(f), now),
                )
                conn.execute(
                    "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
                    ("C2_CONNECTION", json.dumps({"ip": f["remote_ip"], "process": f["process_name"]}),
                     f["pid"] or 0, now),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _print_alert(self, f: dict):
        print(
            f"\n{'='*60}\n"
            f"  🌐  C2 CONNECTION — Feodo Tracker Match\n"
            f"  Remote IP : {f['remote_ip']}:{f['remote_port']}\n"
            f"  Process   : {f['process_name']} (PID {f['pid']})\n"
            f"  Path      : {f['process_path']}\n"
            f"  MITRE     : T1071 / T1095\n"
            f"{'='*60}"
        )


# ─────────────────────────────────────────────
#  DNS DGA MONITOR
# ─────────────────────────────────────────────

class DgaMonitor:
    """
    Analyses queried domain names for DGA (Domain Generation Algorithm) characteristics
    using Shannon entropy. DGA malware queries hundreds of high-entropy random domains
    until one resolves to the active C2. The burst pattern is detectable before any
    connection is established.
    MITRE: T1568.002 (Dynamic Resolution: Domain Generation Algorithms)
    """

    ENTROPY_THRESHOLD = 3.5
    BURST_THRESHOLD   = 5       # N suspicious queries within WINDOW_SECS
    WINDOW_SECS       = 60

    def __init__(self):
        self._window: list[tuple]   = []   # (datetime, domain, entropy)
        self._alerted: set[str]     = set()

    def analyse(self, fqdn: str) -> dict | None:
        """Analyses a DNS query string for DGA entropy indicators. Returns a finding dict or None."""
        fqdn = fqdn.strip().lower().rstrip(".")
        if fqdn in self._alerted:
            return None

        suspicious, entropy = _is_dga_suspicious(fqdn)
        if not suspicious:
            return None

        now     = datetime.datetime.now()
        cutoff  = now - datetime.timedelta(seconds=self.WINDOW_SECS)
        self._window = [(t, d, e) for t, d, e in self._window if t > cutoff]
        self._window.append((now, fqdn, entropy))

        if len(self._window) >= self.BURST_THRESHOLD:
            finding = {
                "type": "DGA_BEACON", "domain": fqdn, "entropy": round(entropy, 3),
                "burst_count": len(self._window),
                "sample_domains": [d for _, d, _ in self._window[-8:]],
            }
            self._alerted.add(fqdn)
            self._persist(finding)
            return finding
        return None

    def _persist(self, f: dict):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO c2_alerts (detection_type,indicator,malware_family,details,timestamp) VALUES (?,?,?,?,?)",
                    ("DGA_BEACON", f["domain"], "DGA-Suspected", json.dumps(f), now),
                )
                conn.execute(
                    "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
                    ("DGA_BEACON", json.dumps({"domain": f["domain"], "entropy": f["entropy"]}), 0, now),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def format_alert(self, f: dict) -> str:
        """Formats a C2 finding dict into a human-readable alert string."""
        samples = "\n    ".join(f.get("sample_domains", [])[:5])
        return (
            f"\n{'='*60}\n"
            f"  🔁  DGA BEACONING DETECTED\n"
            f"  Trigger   : {f['domain']}  (entropy={f['entropy']})\n"
            f"  Burst     : {f['burst_count']} suspicious queries in 60s\n"
            f"  Samples   :\n    {samples}\n"
            f"  MITRE     : T1568.002\n"
            f"{'='*60}"
        )


# ─────────────────────────────────────────────
#  JA3 TLS FINGERPRINT MONITOR
# ─────────────────────────────────────────────

def _compute_ja3(data: bytes) -> str | None:
    """
    Pure-Python JA3 fingerprint from raw TLS ClientHello bytes.
    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
    Returns MD5 hex string or None if data is not a valid ClientHello.
    """
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 9
        ver  = struct.unpack("!H", data[pos:pos+2])[0]; pos += 34  # ver + random
        pos += 1 + data[pos]                                        # session id
        cs_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
        ciphers = [struct.unpack("!H", data[pos+i:pos+i+2])[0]
                   for i in range(0, cs_len, 2)
                   if struct.unpack("!H", data[pos+i:pos+i+2])[0] not in (0,0xFF)]
        pos += cs_len + 1 + data[pos]                               # skip compression
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
        exts, curves, fmts = [], [], []
        while pos + 4 <= ext_end:
            et = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
            el = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
            if et not in (0, 1): exts.append(et)
            if et == 0x0A:
                gl = struct.unpack("!H", data[pos:pos+2])[0]
                curves = [struct.unpack("!H", data[pos+2+i:pos+4+i])[0] for i in range(0, gl, 2)]
            elif et == 0x0B:
                fmts = list(data[pos+1:pos+1+data[pos]])
            pos += el
        s = f"{ver},{'-'.join(map(str,ciphers))},{'-'.join(map(str,exts))},{'-'.join(map(str,curves))},{'-'.join(map(str,fmts))}"
        return hashlib.md5(s.encode()).hexdigest()
    except Exception:
        return None


class Ja3Monitor:
    """
    Sniffs TLS traffic on port 443/8443 via scapy, computes JA3 fingerprints,
    and alerts when a fingerprint matches the abuse.ch SSLBL blocklist.
    Silently disabled if scapy/Npcap not installed.
    MITRE: T1071.001 (Web Protocols)
    """

    def __init__(self):
        self._blocklist: set[str] = load_ja3_blocklist()
        self._available           = self._check_scapy()
        self._running             = False
        if self._blocklist:
            print(f"[*] JA3: {len(self._blocklist)} malicious fingerprints loaded.")
        if not self._available:
            print("[!] JA3 monitor disabled — install scapy + Npcap to enable.")

    def _check_scapy(self) -> bool:
        try:
            import scapy.all  # noqa
            return True
        except ImportError:
            return False

    def start(self):
        """Starts the background monitoring thread."""
        if not self._available:
            return
        self._running = True
        threading.Thread(target=self._capture, daemon=True).start()

    def stop(self):
        """Signals the monitoring thread to stop."""
        self._running = False

    def _capture(self):
        try:
            from scapy.all import sniff, TCP, Raw, IP
            def cb(pkt):
                """Packet capture callback — processes each captured TLS packet."""
                if not self._running:
                    return
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    ja3 = _compute_ja3(bytes(pkt[Raw].load))
                    if ja3 and ja3 in self._blocklist:
                        src = pkt[IP].src if pkt.haslayer(IP) else "?"
                        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
                        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        print(
                            f"\n{'='*60}\n"
                            f"  🔒  MALICIOUS TLS FINGERPRINT (JA3)\n"
                            f"  JA3  : {ja3}\n"
                            f"  Flow : {src} → {dst}\n"
                            f"  MITRE: T1071.001\n"
                            f"{'='*60}"
                        )
                        try:
                            with sqlite3.connect(utils.DB_FILE) as conn:
                                conn.execute(
                                    "INSERT INTO c2_alerts (detection_type,indicator,malware_family,details,timestamp) VALUES (?,?,?,?,?)",
                                    ("JA3_MATCH", ja3, "TLS-C2",
                                     json.dumps({"ja3": ja3, "src": src, "dst": dst}), now),
                                )
                        except Exception:
                            pass  # Non-critical: operation continues regardless
            sniff(filter="tcp port 443 or tcp port 8443", prn=cb, store=False,
                  stop_filter=lambda _: not self._running)
        except Exception as e:
            print(f"[-] JA3 capture error: {e}")

    def check_fingerprint(self, ja3: str) -> bool:
        """Checks a JA3 hash string against the SSLBL malicious fingerprint blocklist."""
        return ja3.lower() in self._blocklist
