#!/bin/sh
set -eu
cd /workspace
export PYTHONPATH=/workspace
export OSINT_HOST="${OSINT_HOST:-0.0.0.0}"
export OSINT_PORT="${OSINT_PORT:-8080}"
export OSINT_DATA_DIR="${OSINT_DATA_DIR:-/workspace/data/app}"
if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/healthz || curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/; then
  exit 0
fi
python3 -m uvicorn osint.app:app --host 0.0.0.0 --port 8080 >>/tmp/app-startup.log 2>&1 &
# wait until healthy
i=0
while [ "$i" -lt 40 ]; do
  if curl -sf -o /dev/null --max-time 1 http://127.0.0.1:8080/healthz; then
    exit 0
  fi
  i=$((i + 1))
  sleep 0.25
done
exit 0
