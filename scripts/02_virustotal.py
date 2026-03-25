#!/usr/bin/env python3
"""
Step 2 — VirusTotal Public Page Lookup (no API key required)

Fetches the publicly accessible VirusTotal report page for a given SHA-256 hash
and extracts detection data from embedded JSON inside <script> tags.

No file is uploaded. No API key is needed. Only the hash is sent as part of a
standard HTTPS GET request to the public VirusTotal website.

IMPORTANT — Fragility notice:
  This script scrapes VirusTotal's HTML/JS page rather than using their API.
  If VirusTotal changes their frontend structure, the parser may need updating.
  The script degrades gracefully: if structured JSON extraction fails it falls
  back to regex-based extraction, and if that fails it still returns the public
  link so the analyst can check manually.

Usage: python 02_virustotal.py <sha256>
Output: JSON to stdout
"""

import json
import re
import sys

# Realistic browser User-Agent reduces the chance of being served a bot page.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "DNT":             "1",
}

# VirusTotal embeds report data as JSON assigned to one of these JS variable names.
# The list is ordered by preference — we try each in turn.
JS_DATA_PATTERNS = [
    # Modern VT frontend: data blob assigned to a variable in a <script> tag
    re.compile(r'window\.__REPORT_DATA__\s*=\s*(\{.+?\});', re.DOTALL),
    re.compile(r'window\.__vt_widget_data\s*=\s*(\{.+?\});', re.DOTALL),
    re.compile(r'"last_analysis_stats"\s*:\s*(\{[^}]+\})', re.DOTALL),
]

# Fallback: detection ratio expressed as "X / Y" in the page text.
DETECTION_RATIO_RE = re.compile(r'(\d+)\s*/\s*(\d+)\s*security vendors', re.IGNORECASE)

# Threat category / label often appears near "Trojan", "Ransomware", etc.
THREAT_LABEL_RE = re.compile(
    r'"suggested_threat_label"\s*:\s*"([^"]+)"'
)


def _extract_from_json_blob(html: str) -> dict | None:
    """
    Try to find and parse a JSON blob containing last_analysis_stats.
    Returns a dict with keys: malicious, suspicious, undetected, total_engines,
    threat_label — or None if nothing useful was found.
    """
    # First: look for a named JS variable containing the full report object.
    for pattern in JS_DATA_PATTERNS[:2]:
        match = pattern.search(html)
        if match:
            try:
                data = json.loads(match.group(1))
                stats = (
                    data.get("attributes", {}).get("last_analysis_stats")
                    or data.get("last_analysis_stats")
                    or {}
                )
                if stats:
                    total = sum(stats.values())
                    threat_label = (
                        data.get("attributes", {})
                            .get("popular_threat_classification", {})
                            .get("suggested_threat_label", "N/A")
                        or data.get("popular_threat_classification", {})
                               .get("suggested_threat_label", "N/A")
                    )
                    return {
                        "malicious":     stats.get("malicious", 0),
                        "suspicious":    stats.get("suspicious", 0),
                        "undetected":    stats.get("undetected", 0),
                        "total_engines": total,
                        "threat_label":  threat_label,
                    }
            except (json.JSONDecodeError, AttributeError):
                continue

    # Second: look for a bare last_analysis_stats JSON fragment anywhere in the page.
    match = JS_DATA_PATTERNS[2].search(html)
    if match:
        try:
            stats = json.loads(match.group(1))
            total = sum(stats.values())
            # Try to also pull the threat label from elsewhere in the page.
            label_match = THREAT_LABEL_RE.search(html)
            return {
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "undetected":    stats.get("undetected", 0),
                "total_engines": total,
                "threat_label":  label_match.group(1) if label_match else "N/A",
            }
        except (json.JSONDecodeError, AttributeError):
            pass

    return None


def _extract_from_text(html: str) -> dict | None:
    """
    Regex fallback: parse detection ratio text like "14 / 72 security vendors".
    Returns a minimal dict or None.
    """
    match = DETECTION_RATIO_RE.search(html)
    if match:
        malicious = int(match.group(1))
        total     = int(match.group(2))
        label_match = THREAT_LABEL_RE.search(html)
        return {
            "malicious":     malicious,
            "suspicious":    0,           # not available via text scrape
            "undetected":    total - malicious,
            "total_engines": total,
            "threat_label":  label_match.group(1) if label_match else "N/A",
        }
    return None


def lookup_virustotal(sha256: str) -> dict:
    try:
        import requests
    except ImportError:
        return {
            "skipped": True,
            "reason":  "requests library not installed. Run: pip install requests",
        }

    vt_url = f"https://www.virustotal.com/gui/file/{sha256}"

    try:
        resp = requests.get(vt_url, headers=HEADERS, timeout=20, allow_redirects=True)
    except requests.RequestException as e:
        return {
            "skipped": False,
            "known":   None,
            "error":   f"Network error: {e}",
            "vt_link": vt_url,
        }

    # A 404 means VirusTotal has no record of this hash.
    if resp.status_code == 404:
        return {
            "skipped": False,
            "known":   False,
            "message": "Hash not found on VirusTotal (never submitted).",
            "vt_link": vt_url,
        }

    # Any non-200 beyond 404 is an unexpected error.
    if resp.status_code != 200:
        return {
            "skipped": False,
            "known":   None,
            "error":   f"VirusTotal returned HTTP {resp.status_code}",
            "vt_link": vt_url,
        }

    html = resp.text

    # Attempt structured extraction first, then fall back to text regex.
    extracted = _extract_from_json_blob(html) or _extract_from_text(html)

    if extracted:
        return {
            "skipped":          False,
            "known":            True,
            "source":           "web_scrape",   # distinguishes from API-based results
            "malicious":        extracted["malicious"],
            "suspicious":       extracted["suspicious"],
            "undetected":       extracted["undetected"],
            "total_engines":    extracted["total_engines"],
            "threat_label":     extracted["threat_label"],
            "vt_link":          vt_url,
        }

    # Page loaded but we couldn't parse any detection data.
    # The hash IS known (200 response) but we can't extract numbers.
    return {
        "skipped":  False,
        "known":    True,
        "source":   "web_scrape",
        "warning":  (
            "Hash is known to VirusTotal but detection data could not be parsed. "
            "VirusTotal may have changed their page structure. "
            "Visit the link below to view the full report manually."
        ),
        "vt_link":  vt_url,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 02_virustotal.py <sha256>", file=sys.stderr)
        sys.exit(1)

    result = lookup_virustotal(sys.argv[1])
    print(json.dumps(result, indent=2))
