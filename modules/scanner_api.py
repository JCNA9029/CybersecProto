# modules/scanner_api.py
#
# Tier 1 Cloud Intelligence API wrappers.
#
# Each class encapsulates authentication, request construction, response parsing,
# and error handling for one cloud threat intelligence service. All four classes
# expose a standardized get_report(hash) interface that returns a consistent
# verdict dictionary for the consensus engine in analysis_manager.py.
#
# Standardized return format:
#   {"verdict": "MALICIOUS" | "SAFE", "engines_detected": int}
#   None — when the hash has no record or the API is unreachable.
#
# All requests are capped at a 5-second timeout to prevent blocking the pipeline.

import requests
from requests.exceptions import Timeout, RequestException
import threading
import time


# ─────────────────────────────────────────────────────────────────────────────
#  D2 Fix: Token Bucket Rate Limiter
#
#  VirusTotal free tier: 4 requests/minute, 500/day.
#  Without throttling, scanning a folder of 100 files would fire 400 concurrent
#  API requests, exhausting the daily quota in seconds.
#
#  The token bucket algorithm allows burst usage while enforcing the average
#  rate. Tokens accumulate at the configured rate up to the bucket capacity.
# ─────────────────────────────────────────────────────────────────────────────

class _TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, calls_per_minute: float):
        self._rate    = calls_per_minute / 60.0   # tokens per second
        self._tokens  = calls_per_minute           # start full
        self._lock    = threading.Lock()
        self._last    = time.monotonic()

    def acquire(self):
        """Blocks until a token is available."""
        with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(
                self._tokens + elapsed * self._rate,
                self._rate * 60          # cap at one minute of tokens
            )
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                time.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# One limiter per service — conservative rates for free tiers
_vt_limiter    = _TokenBucket(calls_per_minute=4)    # VirusTotal free: 4/min
_otx_limiter   = _TokenBucket(calls_per_minute=10)   # AlienVault OTX: generous
_md_limiter    = _TokenBucket(calls_per_minute=10)   # MetaDefender free: ~10/min
_mb_limiter    = _TokenBucket(calls_per_minute=20)   # MalwareBazaar: generous



class VirusTotalAPI:
    """
    Wrapper for the VirusTotal v3 Files API.

    Consensus threshold: 3 or more detection engines must flag the hash
    before the verdict is elevated to MALICIOUS. This reduces false positives
    from single-engine noise in the aggregated results.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"accept": "application/json", "x-apikey": api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """
        Queries the VirusTotal v3 API for a file hash verdict.

        Returns a standardized verdict dict, or None if the hash has no record
        or the request fails.
        """
        if not self.api_key:
            return None
        _vt_limiter.acquire()
        try:
            response = requests.get(
                self.BASE_URL + file_hash,
                headers=self.headers,
                timeout=5,
            )
            if response.status_code == 200:
                stats = (
                    response.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious_count = stats.get("malicious", 0)
                return {
                    "verdict":          "MALICIOUS" if malicious_count >= 3 else "SAFE",
                    "engines_detected": malicious_count,
                }
            return None
        except RequestException:
            return None


class AlienVaultAPI:
    """
    Wrapper for the AlienVault OTX Indicators API.

    A hash is considered MALICIOUS if it belongs to one or more threat
    intelligence "pulses" in the OTX community database.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """
        Queries the AlienVault OTX API for a file hash verdict.

        Returns a standardized verdict dict, or None if the hash has no record
        or the request fails.
        """
        if not self.api_key:
            return None
        try:
            _otx_limiter.acquire()
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                pulse_count = (
                    resp.json().get("pulse_info", {}).get("count", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if pulse_count > 0 else "SAFE",
                    "engines_detected": pulse_count,
                }
            return None
        except Timeout:
            print("[-] AlienVault: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] AlienVault: Network error — {e}")
            return None
        except ValueError:
            print("[-] AlienVault: Invalid JSON in response.")
            return None


class MetaDefenderAPI:
    """
    Wrapper for the OPSWAT MetaDefender v4 Hash Lookup API.

    Reports the number of threat detections across MetaDefender's
    multi-engine scan results.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"apikey": self.api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """
        Queries the MetaDefender v4 API for a file hash verdict.

        Returns a standardized verdict dict, or None if the hash has no record
        or the request fails.
        """
        if not self.api_key:
            return None
        try:
            _md_limiter.acquire()
            url = f"https://api.metadefender.com/v4/hash/{file_hash}"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                threats = (
                    resp.json().get("scan_results", {}).get("threats", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if threats > 0 else "SAFE",
                    "engines_detected": threats,
                }
            return None
        except Timeout:
            print("[-] MetaDefender: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MetaDefender: Network error — {e}")
            return None
        except ValueError:
            print("[-] MetaDefender: Invalid JSON in response.")
            return None


class MalwareBazaarAPI:
    """
    Wrapper for the abuse.ch MalwareBazaar hash lookup API.

    MalwareBazaar is a repository of confirmed malware samples. A hash
    present in the database is definitively malicious (engines_detected = 1).
    A hash absent from the database returns SAFE with engines_detected = 0.

    The User-Agent header is set to identify CyberSentinel as the client
    per the MalwareBazaar API usage guidelines.
    """

    _API_URL = "https://mb-api.abuse.ch/api/v1/"
    _HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; CyberSentinel-EDR/2.0; "
            "+https://github.com/JCNA9029/CybersentinelModularized)"
        )
    }

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_report(self, file_hash: str) -> dict | None:
        """
        Queries the MalwareBazaar API for a file hash verdict.

        Returns {"verdict": "MALICIOUS", "engines_detected": 1} if the hash
        is in the confirmed malware database, {"verdict": "SAFE", ...} if not
        found, or None on API failure.
        """
        if not self.api_key:
            return None
        try:
            _mb_limiter.acquire()
            headers = {**self._HEADERS, "Auth-Key": self.api_key}
            resp = requests.post(
                self._API_URL,
                data={"query": "get_info", "hash": file_hash},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                result = resp.json()
                if result.get("query_status") == "ok":
                    return {"verdict": "MALICIOUS", "engines_detected": 1}
                return {"verdict": "SAFE", "engines_detected": 0}
            print(f"[-] MalwareBazaar: HTTP {resp.status_code}")
            return None
        except Timeout:
            print("[-] MalwareBazaar: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MalwareBazaar: Network error — {e}")
            return None
        except ValueError:
            print("[-] MalwareBazaar: Invalid JSON in response.")
            return None
