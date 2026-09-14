#!/usr/bin/env bash
# Takeover Hunter — local setup & run helper.
#
#   ./run.sh          start a local dev server (Flask, http://127.0.0.1:5000)
#   ./run.sh prod     start a production server (gunicorn)
#   ./run.sh test     install dev deps and run the test suite
set -euo pipefail

cd "$(dirname "$0")"

echo "================================================"
echo "  Takeover Hunter — Subdomain Takeover Engine"
echo "================================================"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found." >&2
  exit 1
fi

# Virtual environment
if [ ! -d "venv" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

MODE="${1:-dev}"

if [ "$MODE" = "test" ]; then
  echo "[*] Installing dev dependencies..."
  pip install -q -r requirements-dev.txt
  echo "[*] Running tests..."
  exec python -m pytest
fi

echo "[*] Installing runtime dependencies..."
pip install -q -r requirements.txt

echo "[*] Optional recon tools:"
for tool in subfinder assetfinder amass dnsx httpx katana gau waybackurls; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  [OK] $tool"
  else
    echo "  [--] $tool (not installed — the app degrades gracefully)"
  fi
done

PORT="${PORT:-5000}"
if [ "$MODE" = "prod" ]; then
  echo "[*] Starting production server (gunicorn) on http://0.0.0.0:${PORT}"
  exec gunicorn --bind "0.0.0.0:${PORT}" --workers "${WEB_CONCURRENCY:-4}" \
       --threads "${WEB_THREADS:-8}" --timeout "${WEB_TIMEOUT:-300}" wsgi:app
else
  echo "[*] Starting dev server on http://127.0.0.1:${PORT}  (Ctrl+C to stop)"
  exec python app.py
fi
