#!/usr/bin/env bash
# MSRA -- start the dashboard
set -euo pipefail

PORT="${PORT:-5001}"
PID_FILE="/tmp/msra_server.pid"
LOG_FILE="/tmp/msra_server.log"

# Stop any existing instance
if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping existing MSRA server (PID $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi

# Also free the port if anything else is holding it
lsof -ti:"$PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true

# Check jadx
if ! command -v jadx &>/dev/null; then
  echo "WARNING: jadx not found -- APK scanning will fail."
  echo "  Install: brew install jadx  (macOS) or apt install jadx (Linux)"
fi

# Check WeasyPrint system dependencies (needed for PDF export)
if ! python3 -c "from weasyprint import HTML" 2>/dev/null; then
  echo "WARNING: WeasyPrint not working -- PDF export will be unavailable."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "  Fix: brew install pango cairo gdk-pixbuf && pip install weasyprint"
  else
    echo "  Fix: apt install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 && pip install weasyprint"
  fi
fi

# Start server
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Starting MSRA on port $PORT..."

nohup python3 "$DIR/server.py" --port "$PORT" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

# Wait for it to be ready
echo -n "Waiting for server"
for i in $(seq 1 20); do
  sleep 0.5
  if curl -s "http://localhost:${PORT}" -o /dev/null 2>/dev/null; then
    echo " ready!"
    break
  fi
  echo -n "."
done

echo ""
echo "  MSRA   --> http://localhost:${PORT}"
echo "  Logs   --> $LOG_FILE"
echo "  Stop   --> ./stop.sh"
echo ""

# Open browser
if command -v open &>/dev/null; then
  open "http://localhost:${PORT}"
elif command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:${PORT}" 2>/dev/null &
fi
