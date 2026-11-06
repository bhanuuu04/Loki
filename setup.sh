#!/usr/bin/env bash
# Quick Setup for Linux (Kali, Ubuntu, Debian) / macOS
# Usage: ./setup.sh

set -e

echo "=================================================="
echo "         Loki Setup & Environment Config          "
echo "=================================================="

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

VENV_DIR=".venv"
PIP_FLAGS=""

# Handle Debian / Kali / Ubuntu PEP 668 (externally-managed-environment)
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating isolated virtual environment in $VENV_DIR..."
    if ! $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
        echo "[!] python3-venv package required. Attempting installation via apt..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -y && sudo apt-get install -y python3-venv python3-full
            $PYTHON_CMD -m venv "$VENV_DIR"
        fi
    fi
fi

if [ -f "$VENV_DIR/bin/python" ]; then
    RUN_PYTHON="$VENV_DIR/bin/python"
    RUN_PIP="$VENV_DIR/bin/pip"
    echo "[*] Using dedicated virtual environment: $VENV_DIR"
else
    # Fallback if venv creation was not possible
    RUN_PYTHON="$PYTHON_CMD"
    RUN_PIP="$PYTHON_CMD -m pip"
    PIP_FLAGS="--break-system-packages"
    echo "[!] Using system Python with --break-system-packages fallback"
fi

echo "[1/2] Installing Loki package and dependencies..."
$RUN_PIP install --upgrade pip --quiet $PIP_FLAGS 2>/dev/null || true
$RUN_PIP install -e . --quiet $PIP_FLAGS

echo "[2/2] Launching interactive onboarding wizard..."
exec $RUN_PYTHON -m loki onboard "$@"
