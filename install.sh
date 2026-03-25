#!/usr/bin/env bash
# install.sh — Sets up the malware-watcher service
#
# Usage:  sudo bash install.sh
#
# Expects to be run from the delivery directory, which must already
# contain Dockerfile, scripts/, and references/ at the top level.
#
# What this script does:
#   1. Creates runtime directories (inbox/, reports/, processed/, logs/)
#   2. Validates the bundled skill/ directory
#   3. Creates a Python venv with inotify_simple
#   4. Installs the systemd unit and enables it
#
set -euo pipefail

BASE_DIR="/opt/malware-triage"
SERVICE_USER="agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Pre-flight checks ─────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.9+." >&2
    exit 1
fi

if ! command -v claude &>/dev/null; then
    echo "WARNING: 'claude' CLI not found on PATH."
    echo "         Set CLAUDE_BIN= in the service unit if installed elsewhere."
fi

if ! command -v docker &>/dev/null; then
    echo "WARNING: 'docker' not found. The triage skill requires Docker."
fi

if ! id "$SERVICE_USER" &>/dev/null; then
    echo "ERROR: User '$SERVICE_USER' does not exist." >&2
    echo "       Edit SERVICE_USER in this script or create the user." >&2
    exit 1
fi

if ! id -nG "$SERVICE_USER" | grep -qw docker; then
    echo "WARNING: User '$SERVICE_USER' is NOT in the 'docker' group."
    echo "         Run: sudo usermod -aG docker $SERVICE_USER"
fi

if [[ ! -f "$SCRIPT_DIR/Dockerfile" ]]; then
    echo "ERROR: Dockerfile not found at $SCRIPT_DIR/" >&2
    echo "       The delivery directory must contain Dockerfile, scripts/, and references/" >&2
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        Malware Triage Watcher — Installation                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo
echo "  Base directory:  $BASE_DIR"
echo

# ── Step 1: Create runtime directories ────────────────────────────────────
echo "[1/5] Creating runtime directories …"
for subdir in inbox reports processed logs; do
    mkdir -p "$BASE_DIR/$subdir"
    echo "       ✓ $BASE_DIR/$subdir"
done

# ── Step 2: Install application files ─────────────────────────────────────
echo "[2/5] Installing application files …"

# Copy watcher script (safe even if SCRIPT_DIR == BASE_DIR)
cp -f "$SCRIPT_DIR/malware_watcher.py" "$BASE_DIR/malware_watcher.py"
chmod 755 "$BASE_DIR/malware_watcher.py"
echo "       ✓ $BASE_DIR/malware_watcher.py"

# Copy Dockerfile, scripts/, and references/ (skip if already in place)
if [[ "$(realpath "$SCRIPT_DIR")" != "$(realpath "$BASE_DIR")" ]]; then
    cp -f  "$SCRIPT_DIR/Dockerfile"    "$BASE_DIR/Dockerfile"
    cp -a  "$SCRIPT_DIR/scripts/."     "$BASE_DIR/scripts/"
    cp -a  "$SCRIPT_DIR/references/."  "$BASE_DIR/references/"
    echo "       ✓ Dockerfile, scripts/, references/ copied to $BASE_DIR/"
else
    echo "       ✓ Dockerfile/scripts/references already at $BASE_DIR/ (in-place install)"
fi

# Copy the skill definition (SKILL.md only)
if [[ "$(realpath "$SCRIPT_DIR/skill")" != "$(realpath "$BASE_DIR/skill")" ]]; then
    mkdir -p "$BASE_DIR/skill"
    cp -a "$SCRIPT_DIR/skill/." "$BASE_DIR/skill/"
    echo "       ✓ Skill definition copied to $BASE_DIR/skill/"
fi

chmod +x "$BASE_DIR/scripts/run_triage.sh"
echo "       ✓ run_triage.sh marked executable"

# Fix ownership after all copies — chown in step 1 only covers pre-existing dirs
chown -R "$SERVICE_USER:$SERVICE_USER" "$BASE_DIR"
echo "       ✓ Ownership set to $SERVICE_USER"

# ── Step 3: Python virtual environment ────────────────────────────────────
echo "[3/5] Setting up Python virtual environment …"
python3 -m venv "$BASE_DIR/venv"
"$BASE_DIR/venv/bin/pip" install --upgrade pip --quiet
"$BASE_DIR/venv/bin/pip" install inotify_simple --quiet
echo "       ✓ venv created at $BASE_DIR/venv"
echo "       ✓ inotify_simple installed"

# ── Step 4: Install systemd unit ─────────────────────────────────────────
echo "[4/5] Installing systemd service …"
cp "$SCRIPT_DIR/malware-watcher.service" /etc/systemd/system/malware-watcher.service
systemctl daemon-reload
echo "       ✓ Service unit installed"

# ── Step 5: Enable (but don't start yet) ──────────────────────────────────
echo "[5/5] Enabling service …"
systemctl enable malware-watcher.service
echo "       ✓ Service enabled (will start on next boot)"

echo
echo "════════════════════════════════════════════════════════════════"
echo " Installation complete!"
echo
echo " Directory layout:"
echo "   $BASE_DIR/"
echo "   ├── inbox/           # Drop samples here"
echo "   ├── reports/         # Reports appear here"
echo "   ├── processed/       # Analysed samples moved here"
echo "   ├── logs/            # watcher.log (rotating)"
echo "   ├── scripts/         # Analysis scripts + container entrypoint"
echo "   ├── references/      # suspicious_imports.md reference data"
echo "   ├── skill/           # Claude Code skill definition (SKILL.md)"
echo "   ├── Dockerfile"
echo "   ├── venv/            # Python virtualenv"
echo "   └── malware_watcher.py"
echo
echo " Commands:"
echo "   sudo systemctl start malware-watcher     # Start now"
echo "   sudo systemctl status malware-watcher    # Check status"
echo "   journalctl -u malware-watcher -f          # Follow journal logs"
echo "   tail -f $BASE_DIR/logs/watcher.log        # Follow file logs"
echo
echo " Test:"
echo "   cp some_sample.exe $BASE_DIR/inbox/       # Drop a sample"
echo "   ls $BASE_DIR/reports/                      # Check for report"
echo "════════════════════════════════════════════════════════════════"
