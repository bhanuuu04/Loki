@echo off
setlocal
echo ==================================================
echo         Loki Setup ^& Environment Config
echo ==================================================
echo [1/2] Installing Loki package and dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -e . --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Please ensure Python 3.10+ is installed and on PATH.
    pause
    exit /b %errorlevel%
)

echo [2/2] Launching interactive onboarding wizard...
python -m loki onboard %*
endlocal
