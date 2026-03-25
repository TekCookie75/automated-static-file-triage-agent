#!/usr/bin/env python3
"""
Step 1 — SHA-256 Hash Calculation
Read-only. Never executes the sample.

Usage: python 01_hash.py <sample_path>
Output: JSON to stdout
"""

import hashlib
import json
import os
import sys


def calculate_hashes(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()

    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "size_bytes": len(data),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 01_hash.py <sample_path>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    result = calculate_hashes(path)
    print(json.dumps(result, indent=2))
