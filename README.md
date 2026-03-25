# Malware Triage Watcher

Automated malware initial triage service that monitors an inbox directory for
new PE samples using Linux kernel notifications (`inotify`), dispatches
analysis jobs to a thread pool, and invokes Claude Code to run the
`malware-triage` skill.

Everything lives under a single directory — `/opt/malware-triage` by default.

## Directory Layout

```
/opt/malware-triage/
├── inbox/               # Drop PE samples here (monitored by inotify)
├── reports/             # Full *_triage.md + *_summary.md land here
├── processed/           # Analysed samples are moved here
├── logs/                # watcher.log (10 MB × 5 rotating backups)
├── skill/               # Malware-triage skill (Dockerfile, scripts, refs)
│   ├── Dockerfile
│   ├── SKILL.md
│   ├── scripts/
│   └── references/
├── venv/                # Python virtualenv (inotify_simple)
├── malware_watcher.py   # Main service script
└── README.md
```

## Architecture

```
  inbox/                IN_CLOSE_WRITE     ┌───────────────────┐
  ├── sample_A.exe  ──────────────────────►│ ThreadPoolExecutor │
  ├── sample_B.dll  ──────────────────────►│   (4 workers)      │
  └── ...           ──────────────────────►│                     │
                                           └──────┬──────┬──────┘
                                                  │      │
                                            claude -p  claude -p
                                            (triage)   (triage)
                                                  │      │
                                            reports/  reports/
                                            processed/ processed/
```

## Lifecycle of a Sample

1. Analyst (or automation) copies `suspect.exe` into `inbox/`
2. Kernel fires `IN_CLOSE_WRITE` when the copy completes
3. Watcher picks up the event, waits 2 s settle time, validates file exists
4. Submits a job to the thread pool (skips if already in-flight)
5. Worker invokes `claude --print` with a prompt that:
   - Runs `run_triage.sh <sample> <workdir>` → full Markdown report
   - Reads the report and writes `summary.md`
6. Worker copies `*_triage.md` and `summary.md` to `reports/`
7. Worker moves the sample from `inbox/` to `processed/`

## Logging

The watcher writes logs to **two destinations simultaneously**:

- **journald** — `journalctl -u malware-watcher -f`
- **File** — `tail -f /opt/malware-triage/logs/watcher.log`

The file logger uses `RotatingFileHandler`: each file caps at 10 MB, with 5
backups kept (`watcher.log.1` through `.5`), bounding total disk usage to ~60 MB.

## Installation

```bash
# From the directory containing install.sh:
sudo bash install.sh

# If the skill source is elsewhere:
sudo bash install.sh --skill-source /path/to/malware-triage

# Start the service:
sudo systemctl start malware-watcher
```

## Usage

```bash
# Drop a sample
cp suspicious.exe /opt/malware-triage/inbox/

# Watch the logs (pick either)
journalctl -u malware-watcher -f
tail -f /opt/malware-triage/logs/watcher.log

# Check for reports
ls -la /opt/malware-triage/reports/
```

## Configuration

All settings are adjustable via CLI arguments in the service unit file
(`ExecStart` line in `/etc/systemd/system/malware-watcher.service`):

| Argument     | Default              | Description                          |
|--------------|----------------------|--------------------------------------|
| `--base-dir` | `/opt/malware-triage`| Root directory for all subdirectories|
| `--workers`  | `4`                  | Max concurrent triage jobs           |
| `--settle`   | `2`                  | Seconds to wait after CLOSE_WRITE    |
| `--poll`     | `5`                  | Polling interval (fallback mode)     |
| `--debug`    | off                  | Enable debug-level logging           |

## Troubleshooting

**Service won't start** — `journalctl -u malware-watcher -e`

**"Triage script not found"** — The skill wasn't copied correctly. Re-run
`install.sh` or manually verify `/opt/malware-triage/skill/scripts/run_triage.sh`
exists.

**"inotify_simple not available"** — The venv install failed. Run:
`/opt/malware-triage/venv/bin/pip install inotify_simple`

**Files in inbox not detected** — Ensure the file extension is one of:
`.exe`, `.dll`, `.sys`, `.drv`, `.ocx`, `.scr`, `.bin`

**Docker permission denied** — The user running the service needs docker
group membership, or run the service as root.
