#!/usr/bin/env bash
# Root launcher script for Linux / macOS
# Usage: ./loki.sh [arguments]

# Prefer local virtual environment if present
if [ -f ".venv/bin/python" ]; then
    exec .venv/bin/python -m loki "$@"
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

exec $PYTHON_CMD -m loki "$@"
