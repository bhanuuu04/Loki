#!/usr/bin/env bash
# Quick Setup for Linux / macOS
# Usage: ./setup.sh

set -e

echo "=================================================="
echo "         Loki Setup & Environment Config          "
echo "=================================================="

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

echo "[1/2] Installing Loki package and dependencies..."
$PYTHON_CMD -m pip install --quiet --upgrade pip
$PYTHON_CMD -m pip install -e . --quiet

echo "[2/2] Launching interactive setup wizard..."
exec $PYTHON_CMD -m loki.cli.main setup
