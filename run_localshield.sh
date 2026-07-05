#!/usr/bin/env bash
# LocalShield launcher for Linux / macOS.
#
# Runs the cross-platform detection core + Streamlit dashboard. Live Windows
# Event Log capture and firewall auto-response are Windows-only (use
# run_localshield.bat there); on Linux/macOS you feed the detection engine with
# the auth.log importer instead — see the hint printed below.
set -euo pipefail

# Always operate from the script's own directory.
cd "$(dirname "$0")"

echo "========================================"
echo "   LocalShield - Starting..."
echo "========================================"

# 1. Python check
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 was not found on your PATH. Install Python 3.10+ first."
    exit 1
fi

# 2. Virtual environment
if [ ! -d "venv" ]; then
    echo "[1/3] Virtual environment not found, creating..."
    python3 -m venv venv
else
    echo "[1/3] Virtual environment found."
fi
# shellcheck disable=SC1091
source venv/bin/activate

# 3. Dependencies
echo "[2/3] Installing dependencies..."
pip install -r requirements.txt --quiet

# 4. Launch dashboard
echo "[3/3] Starting dashboard at http://localhost:8501"
echo
echo "Tip: feed the detection core with Linux SSH logs, e.g."
echo "     python -m modules.log_importer /var/log/auth.log"
echo "     (or run 'python generate_demo_data.py' first to see sample data)"
echo
streamlit run dashboard.py
