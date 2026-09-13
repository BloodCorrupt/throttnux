#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

# 1. Check if virtual environment exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[!] Virtual environment not found. Running setup.sh first..."
    bash "$SCRIPT_DIR/setup.sh"
fi

# 2. Launch throttnux as root using the virtual environment's Python interpreter
if [ "$EUID" -ne 0 ]; then
    echo "[+] Elevating privileges with sudo..."
    exec sudo "$VENV_PYTHON" "$SCRIPT_DIR/main.py" "$@"
else
    exec "$VENV_PYTHON" "$SCRIPT_DIR/main.py" "$@"
fi
