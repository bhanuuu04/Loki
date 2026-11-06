#!/usr/bin/env bash
# Loki Uninstaller for Linux
# Usage: chmod +x uninstall.sh && ./uninstall.sh

echo "Uninstalling Loki agent harness..."

if [ -f ".venv/bin/pip" ]; then
    .venv/bin/pip uninstall -y loki-agent 2>/dev/null || true
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi
$PYTHON_CMD -m pip uninstall -y loki-agent 2>/dev/null || true

read -p "Do you want to remove the virtual environment (.venv)? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf .venv
    echo "Removed .venv directory."
fi

read -p "Do you want to remove assessment logs and reports? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf assessments reports logs
    echo "Assessment data removed."
fi

echo "Loki successfully uninstalled."
