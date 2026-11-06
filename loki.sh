#!/usr/bin/env bash
# Root launcher script for Linux / macOS
# Usage: ./loki.sh [arguments]

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

exec $PYTHON_CMD -m loki.cli.main "$@"
