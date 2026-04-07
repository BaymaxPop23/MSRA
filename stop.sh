#!/usr/bin/env bash
# MSRA -- stop the dashboard

PID_FILE="/tmp/msra_server.pid"

if [ -f "$PID_FILE" ]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "MSRA server stopped (PID $PID)"
  else
    echo "MSRA server was not running"
  fi
  rm -f "$PID_FILE"
else
  echo "No PID file found -- killing by port 5001..."
  lsof -ti:5001 2>/dev/null | xargs kill -9 2>/dev/null && echo "Stopped" || echo "Nothing running on port 5001"
fi
