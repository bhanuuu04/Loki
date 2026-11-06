#!/usr/bin/env bash
# Loki One-Command Installer for Linux (Kali, Ubuntu, Debian, etc.)
# Usage: curl -fsSL https://.../install.sh | bash
# Or locally: chmod +x install.sh && ./install.sh

set -e

echo ""
echo "=================================================="
echo "        LOKI AGENT HARNESS - LINUX INSTALLER      "
echo "=================================================="
echo ""

# 1. Architecture & OS Check
ARCH=$(uname -m)
OS=$(uname -s)
echo "[1/8] Detecting System: $OS on $ARCH"

# 2. Check Python >= 3.10
echo "[2/8] Checking Python runtime..."
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[-] Python3 is not installed. Installing via package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv python3-full
        PYTHON_CMD="python3"
    else
        echo "[-] Please install Python 3.10+ and re-run."
        exit 1
    fi
fi

PY_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "      Detected Python $PY_VERSION"

# 3. Directory Structure
echo "[3/8] Initializing Loki directory structure..."
mkdir -p assessments reports logs

# 4. Generate Default Configuration
echo "[4/8] Configuring environment..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "      Created .env from .env.example"
    fi
else
    echo "      Preserved existing .env configuration"
fi

# 5. Handle Virtual Environment (PEP 668 on Debian/Kali)
echo "[5/8] Setting up isolated Python environment..."
VENV_DIR=".venv"
PIP_FLAGS=""

if [ ! -d "$VENV_DIR" ]; then
    if ! $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
        echo "      Installing python3-venv package via apt..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -y && sudo apt-get install -y python3-venv python3-full
            $PYTHON_CMD -m venv "$VENV_DIR"
        fi
    fi
fi

if [ -f "$VENV_DIR/bin/python" ]; then
    RUN_PYTHON="$VENV_DIR/bin/python"
    RUN_PIP="$VENV_DIR/bin/pip"
    echo "      Using virtual environment: $VENV_DIR"
else
    RUN_PYTHON="$PYTHON_CMD"
    RUN_PIP="$PYTHON_CMD -m pip"
    PIP_FLAGS="--break-system-packages"
    echo "      Using system Python with fallback flags"
fi

$RUN_PIP install --upgrade pip --quiet $PIP_FLAGS 2>/dev/null || true
$RUN_PIP install -e . --quiet $PIP_FLAGS

# 6. Check Container Runtimes & Security Tools
echo "[6/8] Checking environment capabilities..."
if command -v docker >/dev/null 2>&1; then
    echo "      Docker is available for containerized execution"
else
    echo "      Docker not detected (optional)"
fi

if [ -f "/etc/os-release" ] && grep -qi "kali" /etc/os-release; then
    echo "      Running natively on Kali Linux with security tool ecosystem"
fi

# 7. Verification Check
echo "[7/8] Running Loki diagnostic verification..."
$RUN_PYTHON -m loki.cli.main doctor

# 8. Complete
echo ""
echo "=================================================="
echo "          INSTALLATION COMPLETE!                  "
echo "=================================================="
echo ""
echo "Launch Loki with:"
echo "  ./loki.sh                         # Interactive Hermes-style chat"
echo "  ./loki.sh start                   # Starts Web UI on http://127.0.0.1:8000"
echo "  ./loki.sh doctor                  # Run System Health Diagnostic"
echo ""
