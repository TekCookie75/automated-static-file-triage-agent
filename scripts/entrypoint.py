#!/usr/bin/env python3
"""
Malware Triage — Container Entrypoint

Orchestrates all analysis steps (01–08) inside the Docker container.
Intermediate JSON files and human-readable .txt files are written to /report/.
The final Markdown report is also placed in /report/.

Usage: python entrypoint.py <sample_path>
"""

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path("/app")
REFS    = Path("/app/references")
REPORT  = Path("/report")
PYTHON  = sys.executable


# ── Helpers ──────────────────────────────────────────────────────────────────

def run_json(args: list, step_name: str, timeout: int = 60) -> dict:
    """Run a Python script, capture stdout as JSON. Return {} on failure."""
    print(f"  [*] {step_name}", flush=True)
    try:
        r = subprocess.run(
            [PYTHON] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            print(f"  [!] {step_name} exited {r.returncode}: {r.stderr[:300]}", flush=True)
            return {}
        return json.loads(r.stdout)
    except Exception as e:
        print(f"  [!] {step_name} error: {e}", flush=True)
        return {}


def write_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Human-readable report file writers ───────────────────────────────────────

def write_sections_txt(entropy_d: dict):
    threshold = entropy_d.get("threshold", 6.5)
    lines = [
        "PE Sections",
        "=" * 50,
        f"{'Section':<14} {'Size (bytes)':>12}  {'Entropy':>8}  Flag",
        "-" * 50,
    ]
    for s in entropy_d.get("sections", []):
        flag = "*** HIGH ENTROPY ***" if s.get("high_entropy") else ""
        lines.append(
            f"  {s['name']:<12} {s['size_bytes']:>12,}  {s['entropy']:>8.4f}  {flag}"
        )
    lines += [
        "-" * 50,
        f"Threshold: {threshold}  |  High-entropy sections: {entropy_d.get('high_entropy_count', 0)}",
    ]
    (REPORT / "sections.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_imports_txt(imports_d: dict):
    sus = imports_d.get("suspicious_imports", [])
    lines = [
        "Imports",
        "=" * 50,
        f"Total imports:       {imports_d.get('total_imports', 0)}",
        f"Suspicious hits:     {len(sus)}",
    ]
    if sus:
        lines += ["", "Suspicious Imports:", "-" * 50]
        for imp in sus:
            lines.append(f"  [{imp['category']}]  {imp['dll']}!{imp['function']}")
    lines += ["", "All Imported DLLs:", "-" * 50]
    for dll, count in sorted(imports_d.get("dll_summary", {}).items(), key=lambda x: -x[1]):
        lines.append(f"  {dll:<42} {count:>4} import(s)")
    (REPORT / "imports.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_strings_txt(strings_d: dict):
    buckets = strings_d.get("strings", {})
    stats   = strings_d.get("stats", {})
    lines = [
        "Strings",
        "=" * 50,
        f"Total raw:   {stats.get('total_raw', 0)}",
        f"Kept:        {stats.get('total_kept', 0)}",
        f"Filtered:    {stats.get('total_filtered', 0)}",
    ]
    for category in ("network", "filesystem", "registry", "other"):
        items = buckets.get(category, [])
        lines += ["", f"[{category.upper()}]  ({len(items)} strings)", "-" * 50]
        for s in items:
            lines.append(f"  {s}")
    (REPORT / "strings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: entrypoint.py <sample_path>", file=sys.stderr)
        sys.exit(1)

    sample = sys.argv[1]
    if not os.path.isfile(sample):
        print(f"[!] Sample not found: {sample}", file=sys.stderr)
        sys.exit(1)

    REPORT.mkdir(parents=True, exist_ok=True)
    sample_name = os.path.basename(sample)

    print(f"\n{'=' * 54}", flush=True)
    print("  Malware Initial Triage", flush=True)
    print(f"{'=' * 54}", flush=True)
    print(f"  Sample : {sample}", flush=True)
    print(f"  Report : {REPORT}", flush=True)
    print(f"{'=' * 54}\n", flush=True)

    # ── 1. Hashes ─────────────────────────────────────────────────────────────
    print("[1/8] Hashes", flush=True)
    hash_d = run_json([str(SCRIPTS / "01_hash.py"), sample], "calculate hashes")
    write_json(REPORT / "hash.json", hash_d)
    sha256 = hash_d.get("sha256", "unknown")
    print(f"      SHA-256: {sha256}", flush=True)

    # ── 2. VirusTotal ─────────────────────────────────────────────────────────
    print("[2/8] VirusTotal lookup", flush=True)
    vt_d = run_json([str(SCRIPTS / "02_virustotal.py"), sha256], "virustotal lookup", timeout=30)
    write_json(REPORT / "virustotal.json", vt_d)

    # ── 3. Section entropy ────────────────────────────────────────────────────
    print("[3/8] Section entropy", flush=True)
    entropy_d = run_json([str(SCRIPTS / "03_entropy.py"), sample], "entropy analysis")
    write_json(REPORT / "entropy.json", entropy_d)
    write_sections_txt(entropy_d)
    print(f"      sections.txt written  ({entropy_d.get('high_entropy_count', 0)} high-entropy)", flush=True)

    # ── 4. Import analysis ────────────────────────────────────────────────────
    print("[4/8] Import analysis", flush=True)
    imports_d = run_json(
        [str(SCRIPTS / "04_imports.py"), sample, str(REFS / "suspicious_imports.md")],
        "import analysis",
    )
    write_json(REPORT / "imports.json", imports_d)
    write_imports_txt(imports_d)
    print(f"      imports.txt written  ({imports_d.get('suspicious_hit_count', 0)} suspicious)", flush=True)

    # ── 5. Exports & TLS callbacks ────────────────────────────────────────────
    print("[5/8] Exports & TLS callbacks", flush=True)
    exports_d = run_json([str(SCRIPTS / "05_exports.py"), sample], "exports analysis")
    write_json(REPORT / "exports.json", exports_d)
    print(f"      Exports: {exports_d.get('export_count', 0)}  |  TLS callbacks: {exports_d.get('tls_callback_count', 0)}", flush=True)

    # ── 6. floss string extraction ────────────────────────────────────────────
    print("[6/8] floss string extraction", flush=True)
    floss_raw = str(REPORT / "floss_raw.txt")
    r6 = subprocess.run(
        [PYTHON, str(SCRIPTS / "06_floss.py"), sample, "--output", floss_raw],
        capture_output=True, text=True, timeout=1200,
    )
    if r6.returncode != 0:
        print(f"  [!] floss failed (exit {r6.returncode}): {r6.stderr[:300]}", flush=True)
        floss_ok = False
    else:
        print(r6.stdout.strip(), flush=True)
        floss_ok = True

    # ── 7. String filtering ───────────────────────────────────────────────────
    print("[7/8] String filtering", flush=True)
    if floss_ok and os.path.isfile(floss_raw):
        strings_d = run_json([str(SCRIPTS / "07_filter_strings.py"), floss_raw], "string filtering")
    else:
        strings_d = {}
    write_json(REPORT / "strings.json", strings_d)
    write_strings_txt(strings_d)
    kept  = strings_d.get("stats", {}).get("total_kept", 0)
    total = strings_d.get("stats", {}).get("total_raw", 0)
    print(f"      strings.txt written  ({kept} of {total} kept)", flush=True)

    # ── 8. Assemble Markdown report ───────────────────────────────────────────
    print("[8/8] Assembling Markdown report", flush=True)
    out_md = str(REPORT / f"{sha256[:12]}_triage.md")
    subprocess.run(
        [
            PYTHON, str(SCRIPTS / "08_report.py"),
            "--hash",    str(REPORT / "hash.json"),
            "--vt",      str(REPORT / "virustotal.json"),
            "--entropy", str(REPORT / "entropy.json"),
            "--imports", str(REPORT / "imports.json"),
            "--exports", str(REPORT / "exports.json"),
            "--strings", str(REPORT / "strings.json"),
            "--sample",  sample_name,
            "--output",  out_md,
        ],
        check=True,
    )

    print(f"\n{'=' * 54}", flush=True)
    print("  Triage complete", flush=True)
    print(f"  Report : {out_md}", flush=True)
    print(f"{'=' * 54}\n", flush=True)


if __name__ == "__main__":
    main()
