#!/usr/bin/env bash
# MSRA -- pull latest version and restart
set -euo pipefail

PORT="${PORT:-5001}"
PID_FILE="/tmp/msra_server.pid"

echo "=== MSRA Update ==="
echo ""

# 1. Check we are inside the repo
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "ERROR: Not a git repository. Clone MSRA with git to use this script."
  exit 1
fi

# 2. Show current version
CURRENT=$(git rev-parse --short HEAD)
echo "Current version : $CURRENT ($(git log -1 --format='%s'))"

# 3. Fetch and check for updates
echo "Checking for updates..."
git fetch origin main --quiet

BEHIND=$(git rev-list HEAD..origin/main --count 2>/dev/null || echo "0")

if [ "$BEHIND" -eq 0 ]; then
  echo "Already up to date."
  echo ""
  read -rp "Restart server anyway? [y/N] " yn
  case "$yn" in [Yy]*) ;; *) exit 0 ;; esac
else
  echo "Found $BEHIND new commit(s):"
  git log HEAD..origin/main --oneline
  echo ""
  read -rp "Apply update and restart? [Y/n] " yn
  case "$yn" in [Nn]*) echo "Aborted."; exit 0 ;; esac

  # 4. Pull latest code
  echo ""
  echo "Pulling updates..."
  git pull --ff-only origin main
  NEW=$(git rev-parse --short HEAD)
  echo "Updated: $CURRENT -> $NEW"
fi

# 5. Install / update Python dependencies
echo ""
echo "Updating dependencies..."
pip3 install -q -r requirements.txt

# 6. Stop existing server
echo ""
echo "Restarting MSRA..."
if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi
lsof -ti:"$PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true

# 7. Start server (reuse start.sh)
bash "$DIR/start.sh"
