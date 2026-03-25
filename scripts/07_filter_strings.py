#!/usr/bin/env python3
"""
Step 7 — String Filtering & Categorization
Filters raw floss output: keeps strings with length >= 6 AND entropy < 6.5.
Categorizes survivors into: network, filesystem, registry, other.

Usage: python 07_filter_strings.py <floss_raw.txt> [--min-length 6] [--max-entropy 6.5]
Output: JSON to stdout
"""

import argparse
import json
import math
import re
import sys


# --- Regex patterns for IoC categorization ---

PATTERNS = {
    "network": [
        re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"),                    # IPv4
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
                   r"+(?:com|net|org|io|gov|edu|ru|cn|de|uk|onion)\b",
                   re.IGNORECASE),                                                 # Domain
    ],
    "filesystem": [
        re.compile(r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]*"),
        re.compile(r"\\\\[^\\]+\\[^\\]+"),                                        # UNC path
        re.compile(r"%(?:SystemRoot|AppData|Temp|WinDir|ProgramFiles"
                   r"|USERPROFILE|ComSpec)%", re.IGNORECASE),                     # Env vars
    ],
    "registry": [
        re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT"
                   r"|USERS|CURRENT_CONFIG)[\\a-zA-Z0-9_\s]*", re.IGNORECASE),
        re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s]+", re.IGNORECASE),
    ],
}


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def categorize(s: str) -> str:
    for category, regexes in PATTERNS.items():
        for rx in regexes:
            if rx.search(s):
                return category
    return "other"


def filter_strings(input_path: str,
                   min_length: int = 6,
                   max_entropy: float = 6.5) -> dict:
    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        return {"error": f"File not found: {input_path}"}

    total_raw = len(raw_lines)
    buckets   = {"network": [], "filesystem": [], "registry": [], "other": []}

    for line in raw_lines:
        s = line.strip()
        if len(s) < min_length:
            continue
        if string_entropy(s) >= max_entropy:
            continue
        bucket = categorize(s)
        buckets[bucket].append(s)

    # Sort "other" strings by entropy descending: meaningful readable strings
    # (moderate-high entropy) come first; repetitive junk (near-zero entropy) last.
    buckets["other"] = sorted(buckets["other"], key=string_entropy, reverse=True)

    total_kept = sum(len(v) for v in buckets.values())

    return {
        "filter_settings": {
            "min_length":  min_length,
            "max_entropy": max_entropy,
        },
        "stats": {
            "total_raw":     total_raw,
            "total_kept":    total_kept,
            "total_filtered": total_raw - total_kept,
        },
        "strings": buckets,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter and categorize floss strings")
    parser.add_argument("input",        help="Path to raw floss output file")
    parser.add_argument("--min-length", type=int,   default=6,   help="Minimum string length (default: 6)")
    parser.add_argument("--max-entropy",type=float, default=6.5, help="Max entropy threshold (default: 6.5)")
    args = parser.parse_args()

    result = filter_strings(args.input, args.min_length, args.max_entropy)
    print(json.dumps(result, indent=2))
