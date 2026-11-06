#!/usr/bin/env bash
# Loki Uninstaller for Linux
# Usage: chmod +x uninstall.sh && ./uninstall.sh

echo "Uninstalling Loki agent harness..."

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

$PYTHON_CMD -m pip uninstall -y loki-agent

read -p "Do you want to remove assessment logs and reports? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf assessments reports logs
    echo "Assessment data removed."
fi

echo "Loki successfully uninstalled."
