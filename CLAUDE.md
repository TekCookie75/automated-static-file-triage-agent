# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an automated malware triage service that monitors an inbox directory for PE samples and runs static analysis via Claude Code inside a Docker container. **Samples are never executed** — all analysis is strictly static and read-only.

## Key Commands

### Installation & Setup
```bash
sudo bash install.sh          # One-time setup: directories, Python venv, systemd service
docker build -t malware-triage skill/   # Build the analysis Docker image
```

### Running Triage Manually
```bash
bash skill/scripts/run_triage.sh <sample_path> [output_dir]
```

### Service Management
```bash
sudo systemctl start malware-watcher
sudo systemctl status malware-watcher
journalctl -u malware-watcher -f
tail -f /opt/malware-triage/logs/watcher.log
```

### Watcher CLI Options
```bash
python malware_watcher.py \
  --base-dir /opt/malware-triage \  # default
  --workers 4 \                     # concurrent triage jobs
  --settle 2 \                      # seconds to wait after CLOSE_WRITE
  --debug
```

## Architecture

### Data Flow
```
inbox/*.exe|dll|sys → inotify (IN_CLOSE_WRITE) → settle 2s → ThreadPoolExecutor (4 workers)
  → docker build + docker run (8-step pipeline) → work_dir/report/
  → copy all files to reports/ → claude --print (summarize only)
  → reports/*_triage_summary.md → processed/ (sample moved)
```

### Components

**`malware_watcher.py`** — Main service daemon. Uses `inotify_simple` to watch `inbox/` for PE files. On `IN_CLOSE_WRITE`, validates file, submits to a thread pool, tracks in-flight paths to prevent duplicate processing. Runs `docker build` + `docker run` directly, copies all output files to `reports/`, then invokes Claude only to summarize the finished report. Falls back to polling if inotify is unavailable.

**`skill/scripts/run_triage.sh`** — Standalone Docker wrapper (not used by the watcher). Useful for manual one-off triage runs outside the automated pipeline.

**`skill/scripts/entrypoint.py`** — Container entry point. Runs scripts 01–08 sequentially, writing intermediate JSON and `.txt` files to `/report`, then assembles the final Markdown report.

**Analysis scripts (01–08):**
| Script | Purpose |
|--------|---------|
| `01_hash.py` | SHA-256, MD5, SHA-1, file size |
| `02_virustotal.py` | VirusTotal public hash lookup (no upload) |
| `03_entropy.py` | Shannon entropy per PE section; flags ≥ 6.5 |
| `04_imports.py` | PE import table; cross-references `suspicious_imports.md` |
| `05_exports.py` | Exports, TLS callbacks, entry point RVA |
| `06_floss.py` | `flare-floss` string extraction |
| `07_filter_strings.py` | Filter/categorize strings (Network/Filesystem/Registry/Other) |
| `08_report.py` | Assemble all JSON outputs into structured Markdown |

**`skill/references/suspicious_imports.md`** — Reference list of suspicious Windows APIs (process injection, hollowing, shellcode loaders, etc.) used by `04_imports.py`.

### Runtime Directory Layout (after install)
```
/opt/malware-triage/
├── inbox/          ← drop PE samples here
├── reports/        ← triage reports appear here
├── processed/      ← analyzed samples moved here
├── logs/           ← watcher.log (rotating 10 MB × 5)
├── scripts/        ← analysis scripts + container entrypoint
├── references/     ← suspicious_imports.md reference data
├── skill/          ← Claude Code skill definition (SKILL.md)
├── Dockerfile
└── venv/           ← Python virtualenv (inotify_simple)
```

## Safety Rules

- **Never execute samples.** The Docker container mounts samples read-only. No script should invoke the sample binary.
- The watcher service runs under systemd with `ProtectSystem=full`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `MemoryMax=4G`.
- Claude is invoked headless (`--dangerously-skip-permissions`) with a 30-minute timeout per sample.

## Dependencies

- Python 3.9+, Linux (inotify), Docker, Claude Code CLI
- Venv packages: `inotify_simple`
- Container packages: `pefile`, `requests`, `flare-floss`
