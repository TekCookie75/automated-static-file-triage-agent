#!/usr/bin/env python3
"""
Step 3 — PE Section Entropy Analysis
Read-only. Calculates Shannon entropy per section.
Flags sections at or above the threshold (default: 6.5).

Usage: python 03_entropy.py <sample_path> [--threshold 6.5]
Output: JSON to stdout
"""

import json
import math
import sys


ENTROPY_THRESHOLD_DEFAULT = 6.5


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence. Returns value in [0, 8]."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def analyze_sections(path: str, threshold: float = ENTROPY_THRESHOLD_DEFAULT) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed. Run: pip install pefile"}

    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {e}"}

    sections = []
    for section in pe.sections:
        name = section.Name.decode(errors="replace").rstrip("\x00")
        data = section.get_data()
        h    = shannon_entropy(data)
        sections.append({
            "name":          name,
            "virtual_address": f"0x{section.VirtualAddress:08X}",
            "size_bytes":    len(data),
            "entropy":       round(h, 4),
            "high_entropy":  h >= threshold,
        })

    pe.close()

    high_entropy_count = sum(1 for s in sections if s["high_entropy"])

    return {
        "threshold":          threshold,
        "section_count":      len(sections),
        "high_entropy_count": high_entropy_count,
        "sections":           sections,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PE section entropy analysis")
    parser.add_argument("sample", help="Path to PE sample")
    parser.add_argument("--threshold", type=float, default=ENTROPY_THRESHOLD_DEFAULT,
                        help="Entropy threshold for flagging (default: 6.5)")
    args = parser.parse_args()

    result = analyze_sections(args.sample, args.threshold)
    print(json.dumps(result, indent=2))
