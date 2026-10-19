#!/bin/bash
# TAKEOVER.HUNTER V2 — Production Setup & Run

set -e

echo ""
echo "================================================"
echo "  TAKEOVER.HUNTER V2 — Subdomain Takeover Hunter"
echo "================================================"
echo ""

if ! command -v python3 &>/dev/null; then
  echo "[ERROR] python3 not found."
  exit 1
fi

if [ ! -d "venv" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv venv
fi

if [ -f "venv/bin/activate" ]; then
  source venv/bin/activate
fi

echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "[*] Optional recon tools:"
for tool in subfinder assetfinder dnsx httpx katana waybackurls gau amass; do
  if command -v "$tool" &>/dev/null; then
    echo " [OK] $tool found"
  else
    echo " [--] $tool not found (graceful fallback enabled)"
  fi
done

PORT="${PORT:-3000}"
HOST="${HOST:-0.0.0.0}"

echo ""
echo "[*] Starting Gunicorn WSGI server at http://${HOST}:${PORT}"
echo "[*] Press Ctrl+C to stop"
echo ""

exec gunicorn --bind "${HOST}:${PORT}" --workers 2 --threads 8 --timeout 120 wsgi:app