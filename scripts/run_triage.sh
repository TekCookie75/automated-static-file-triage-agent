#!/usr/bin/env bash
# =============================================================================
# run_triage.sh — Malware Initial Triage (Docker wrapper)
#
# Builds the malware-triage container image (cached after first build) then
# runs all analysis steps inside it.  The sample is mounted read-only;
# all output files are written to output_dir via a writable bind mount.
#
# Usage:
#   bash scripts/run_triage.sh <sample_path> [output_dir]
#
#   sample_path  Path to the PE file to analyse
#   output_dir   Directory for report files (default: current directory)
#
# Output files written to output_dir:
#   sections.txt            PE section entropy (human-readable)
#   imports.txt             Import table summary (human-readable)
#   strings.txt             Filtered floss strings (human-readable)
#   hash.json               Hashes + file size
#   virustotal.json         VirusTotal lookup result
#   entropy.json            Section entropy data
#   imports.json            Full import analysis
#   exports.json            Exports & TLS callbacks
#   strings.json            Filtered + categorised strings
#   floss_raw.txt           Raw floss output (before filtering)
#   <sha256[:12]>_triage.md Final Markdown report
# =============================================================================

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: bash scripts/run_triage.sh <sample_path> [output_dir]" >&2
    exit 1
fi

SAMPLE_PATH="$(realpath "$1")"
OUTPUT_DIR="${2:-.}"
OUTPUT_DIR="$(realpath "$OUTPUT_DIR")/report"
SAMPLE_DIR="$(dirname "$SAMPLE_PATH")"
SAMPLE_NAME="$(basename "$SAMPLE_PATH")"

if [[ ! -f "$SAMPLE_PATH" ]]; then
    echo "[!] Sample not found: $SAMPLE_PATH" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

BUILD_CTX="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "======================================================"
echo "  Malware Initial Triage"
echo "======================================================"
echo "[*] Sample    : $SAMPLE_PATH"
echo "[*] Output    : $OUTPUT_DIR"
echo ""

echo "[*] Building malware-triage image (cached after first build)..."
docker build -t malware-triage "$BUILD_CTX"

echo ""
echo "[*] Running triage container..."
docker run --rm \
    -v "$SAMPLE_DIR:/samples:ro,z" \
    -v "$OUTPUT_DIR:/report:z" \
    malware-triage "/samples/$SAMPLE_NAME"
