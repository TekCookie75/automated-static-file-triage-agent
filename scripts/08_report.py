#!/usr/bin/env python3
"""
Step 8 — Markdown Report Generator
Assembles JSON outputs from scripts 01–07 into the final triage report.

Usage:
  python 08_report.py \\
    --hash      hash.json \\
    --vt        vt.json \\
    --entropy   entropy.json \\
    --imports   imports.json \\
    --exports   exports.json \\
    --strings   strings.json \\
    --sample    <original_filename> \\
    --output    <report.md>
"""

import argparse
import json
import os
from datetime import datetime, timezone


def load(path: str) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def vt_summary(vt: dict) -> str:
    if not vt or vt.get("skipped"):
        return f"Not checked ({vt.get('reason', 'no API key')})"
    if not vt.get("known"):
        return "Not found on VirusTotal (first seen / unknown hash)"
    mal  = vt.get("malicious", 0)
    sus  = vt.get("suspicious", 0)
    tot  = vt.get("total_engines", "?")
    link = vt.get("vt_link", "")
    return f"{mal} malicious, {sus} suspicious / {tot} engines — [View on VirusTotal]({link})"


def build_report(hash_d, vt_d, entropy_d, imports_d, exports_d, strings_d,
                 sample_name: str) -> str:

    sha256     = hash_d.get("sha256", "N/A")
    short_hash = sha256[:12] if sha256 != "N/A" else "unknown"
    now        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []

    # ── Header ─────────────────────────────────────────────────────────────
    lines += [
        f"# Malware Triage Report",
        f"",
        f"**File:** `{sample_name}`  ",
        f"**SHA-256:** `{sha256}`  ",
        f"**Analysis Date:** {now}  ",
        f"",
        f"> ⚠️ This report was produced using **static analysis only**. "
        f"The sample was never executed.",
        f"",
        f"---",
        f"",
    ]

    # ── 1. File Meta-Data ──────────────────────────────────────────────────
    lines += [
        f"## File Meta-Data",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| File Name | `{sample_name}` |",
        f"| File Size | {hash_d.get('size_bytes', 'N/A'):,} bytes |",
        f"| MD5 | `{hash_d.get('md5', 'N/A')}` |",
        f"| SHA-1 | `{hash_d.get('sha1', 'N/A')}` |",
        f"| SHA-256 | `{sha256}` |",
        f"| Architecture | {exports_d.get('architecture', 'N/A')} |",
        f"| Image Base | `{exports_d.get('image_base', 'N/A')}` |",
        f"| Entry Point | `{exports_d.get('entry_point', {}).get('rva', 'N/A')}` |",
        f"| VirusTotal | {vt_summary(vt_d)} |",
    ]
    if vt_d and vt_d.get("known"):
        lines += [
            f"| VT Threat Label | {vt_d.get('threat_label', 'N/A')} |",
            f"| VT First Seen | {vt_d.get('first_seen', 'N/A')} |",
            f"| VT Tags | {', '.join(vt_d.get('tags', [])) or 'none'} |",
        ]
    lines += [""]

    # Section entropy table
    lines += [
        f"### PE Sections",
        f"",
        f"| Section | Size (bytes) | Entropy | Flag |",
        f"|---|---|---|---|",
    ]
    for s in entropy_d.get("sections", []):
        flag = "⚠️ HIGH ENTROPY" if s.get("high_entropy") else ""
        lines.append(
            f"| `{s['name']}` | {s['size_bytes']:,} | {s['entropy']} | {flag} |"
        )
    lines += [""]

    # ── 2. Imports / Exports ───────────────────────────────────────────────
    lines += [
        f"---",
        f"",
        f"## Imports / Exports",
        f"",
    ]

    # Suspicious imports
    sus_imports = imports_d.get("suspicious_imports", [])
    lines += [
        f"### Suspicious Imports ({len(sus_imports)} hits)",
        f"",
    ]
    if sus_imports:
        lines += [
            f"| DLL | Function | Category |",
            f"|---|---|---|",
        ]
        for imp in sus_imports:
            lines.append(f"| `{imp['dll']}` | `{imp['function']}` | {imp['category']} |")
    else:
        lines.append("_No suspicious imports detected._")
    lines += [""]

    # DLL summary
    dll_summary = imports_d.get("dll_summary", {})
    lines += [
        f"### All Imported DLLs",
        f"",
        f"| DLL | Import Count |",
        f"|---|---|",
    ]
    for dll, count in sorted(dll_summary.items(), key=lambda x: -x[1]):
        lines.append(f"| `{dll}` | {count} |")
    lines += [""]

    # Exports + TLS callbacks
    exports     = exports_d.get("exports", [])
    tls_cbs     = exports_d.get("tls_callbacks", [])
    lines += [
        f"### Exports & TLS Callbacks",
        f"",
        f"| Type | RVA | Name |",
        f"|---|---|---|",
    ]
    for exp in exports:
        name = f"`{exp['name']}`" if exp["name"] else f"ordinal `{exp['ordinal']}`"
        lines.append(f"| Export | `{exp['rva']}` | {name} |")
    for cb in tls_cbs:
        if "error" in cb:
            lines.append(f"| TLS Callback | — | ⚠️ {cb['error']} |")
        else:
            lines.append(f"| TLS Callback | `{cb['rva']}` | — |")
    if not exports and not tls_cbs:
        lines.append("| — | — | No exports or TLS callbacks found |")
    lines += [""]

    # ── 3. Relevant IoCs (Strings) ─────────────────────────────────────────
    string_buckets = strings_d.get("strings", {})
    stats          = strings_d.get("stats", {})
    settings       = strings_d.get("filter_settings", {})

    lines += [
        f"---",
        f"",
        f"## Relevant IoCs",
        f"",
        f"> Strings extracted by **floss** and filtered to "
        f"length ≥ {settings.get('min_length', 6)} chars and "
        f"entropy < {settings.get('max_entropy', 6.5)}.  ",
        f"> **{stats.get('total_kept', 0)}** strings kept from "
        f"**{stats.get('total_raw', 0)}** total "
        f"({stats.get('total_filtered', 0)} filtered out).",
        f"",
    ]

    section_labels = {
        "network":    "### Network Indicators",
        "filesystem": "### File System Paths",
        "registry":   "### Registry Keys",
        "other":      "### Other Strings",
    }

    for key, label in section_labels.items():
        items = string_buckets.get(key, [])
        lines += [label, ""]
        if items:
            for s in items:
                lines.append(f"- `{s}`")
        else:
            lines.append("_None found._")
        lines += [""]

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Assemble final triage Markdown report")
    parser.add_argument("--hash",     required=True)
    parser.add_argument("--vt",       required=True)
    parser.add_argument("--entropy",  required=True)
    parser.add_argument("--imports",  required=True)
    parser.add_argument("--exports",  required=True)
    parser.add_argument("--strings",  required=True)
    parser.add_argument("--sample",   required=True, help="Original sample filename")
    parser.add_argument("--output",   default=None,  help="Output .md path (default: <sha256[:12]>_triage.md)")
    args = parser.parse_args()

    hash_d    = load(args.hash)
    vt_d      = load(args.vt)
    entropy_d = load(args.entropy)
    imports_d = load(args.imports)
    exports_d = load(args.exports)
    strings_d = load(args.strings)

    report_md = build_report(hash_d, vt_d, entropy_d, imports_d, exports_d,
                              strings_d, args.sample)

    sha256     = hash_d.get("sha256", "unknown")
    out_path   = args.output or f"{sha256[:12]}_triage.md"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"[+] Report written to: {out_path}")
