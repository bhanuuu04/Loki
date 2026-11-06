# Loki One-Command Installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/.../install.ps1 | iex
# Or locally: .\install.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       LOKI AGENT HARNESS - WINDOWS INSTALLER     " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Architecture & OS Check
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$os = [System.Environment]::OSVersion
Write-Host "[1/8] Detecting System: Windows ($os) on $arch" -ForegroundColor Green

# 2. Check Python >= 3.10
Write-Host "[2/8] Checking Python runtime..." -ForegroundColor Green
$pythonCmd = $null

if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} else {
    Write-Host "[-] Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "    Attempting to install Python via winget..." -ForegroundColor Yellow
    if (Get-Command "winget" -ErrorAction SilentlyContinue) {
        winget install -e --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        $pythonCmd = "python"
    } else {
        Write-Host "[-] Please install Python 3.10+ from https://python.org and re-run." -ForegroundColor Red
        exit 1
    }
}

$pyVersion = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "      Detected Python $pyVersion" -ForegroundColor Gray

# 3. Directory Structure
Write-Host "[3/8] Initializing Loki directory structure..." -ForegroundColor Green
$dirs = @("assessments", "reports", "logs")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# 4. Generate Default Configuration
Write-Host "[4/8] Configuring environment..." -ForegroundColor Green
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "      Created .env from .env.example" -ForegroundColor Gray
    }
} else {
    Write-Host "      Preserved existing .env configuration" -ForegroundColor Gray
}

# 5. Install Dependencies
Write-Host "[5/8] Installing Python dependencies..." -ForegroundColor Green
& $pythonCmd -m pip install --quiet --upgrade pip
& $pythonCmd -m pip install -e .

# 6. WSL2 & Docker Check
Write-Host "[6/8] Checking optional container runtimes..." -ForegroundColor Green
if (Get-Command "wsl" -ErrorAction SilentlyContinue) {
    Write-Host "      WSL2 is available for Kali Linux tool execution" -ForegroundColor Gray
} else {
    Write-Host "      WSL2 not detected (optional)" -ForegroundColor Gray
}

if (Get-Command "docker" -ErrorAction SilentlyContinue) {
    Write-Host "      Docker is available for containerized execution" -ForegroundColor Gray
} else {
    Write-Host "      Docker not detected (optional)" -ForegroundColor Gray
}

# 7. Verification Check
Write-Host "[7/8] Running Loki diagnostic verification..." -ForegroundColor Green
& $pythonCmd -m loki.cli.main doctor

# 8. Complete
Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "          INSTALLATION COMPLETE!                  " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Launch Loki with:" -ForegroundColor Cyan
Write-Host "  python -m loki.cli.main start      # Starts Web UI on http://127.0.0.1:8000" -ForegroundColor White
Write-Host "  python -m loki.cli.main chat       # Interactive Terminal REPL" -ForegroundColor White
Write-Host "  python -m loki.cli.main doctor     # Run System Health Diagnostic" -ForegroundColor White
Write-Host ""
