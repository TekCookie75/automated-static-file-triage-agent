#!/usr/bin/env python3
"""
Step 6 — String Extraction via floss

floss is installed inside the triage container via pip (flare-floss).
It is called as a subprocess with stdout captured (strings) and stderr
discarded (info/progress lines).  The sample is never executed.

Usage: python 06_floss.py <sample_path> [--output floss_raw.txt]
Output: raw floss string output written to file
"""

import argparse
import subprocess
import sys


def run_floss(sample_path: str, output_path: str) -> dict:
    cmd = ["floss", sample_path, "-q"]

    print(f"[*] Running: {' '.join(cmd)}", flush=True)

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # Suppress info/progress lines; strings go to stdout
            text=True,
            timeout=1200,              # 20-minute ceiling
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "floss timed out after 20 minutes."}
    except Exception as e:
        return {"success": False, "error": str(e)}

    if result.returncode not in (0, 1):  # floss exits 1 on some warnings
        return {"success": False, "error": f"floss exited with code {result.returncode}"}

    with open(output_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(result.stdout)

    line_count = result.stdout.count("\n")
    print(f"[+] floss completed. {line_count} lines → {output_path}", flush=True)

    return {"success": True, "output_file": output_path, "line_count": line_count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run floss string extraction")
    parser.add_argument("sample", help="Path to PE sample")
    parser.add_argument("--output", default="floss_raw.txt",
                        help="Output file for raw floss results (default: floss_raw.txt)")
    args = parser.parse_args()

    result = run_floss(args.sample, args.output)

    if not result["success"]:
        print(f"[!] Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Done: {result}")
