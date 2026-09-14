#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================="
echo " Throttnux Plus - Virtualenv & Setup Script"
echo "============================================="

# 1. Check Python 3 availability
if ! command -v python3 &>/dev/null; then
    echo "[!] Error: python3 is not installed or not in PATH."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Using Python $PYTHON_VERSION"

# 2. Create virtual environment if it doesn't exist
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "[*] Virtual environment already exists in $VENV_DIR"
fi

# 3. Upgrade pip & install requirements
echo "[+] Upgrading pip..."
"$VENV_DIR/bin/pip" install --upgrade pip

if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "[+] Installing requirements from requirements.txt..."
    "$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
fi

echo "[+] Installing throttnux package in editable mode..."
"$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR"

# 4. Make launcher executable
if [ -f "$SCRIPT_DIR/run.sh" ]; then
    chmod +x "$SCRIPT_DIR/run.sh"
fi

echo "========================================"
echo "[✓] Setup complete!"
echo "Run Throttnux using: ./run.sh (or sudo ./run.sh)"
echo "========================================"
