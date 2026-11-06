# Loki Uninstaller for Windows (PowerShell)
# Usage: .\uninstall.ps1

Write-Host "Uninstalling Loki agent harness..." -ForegroundColor Yellow

# Uninstall package from python
python -m pip uninstall -y loki-agent

# Ask before cleaning assessment data
$clean = Read-Host "Do you want to remove assessment logs and reports? (y/N)"
if ($clean -eq "y" -or $clean -eq "Y") {
    Remove-Item -Recurse -Force assessments, reports, logs -ErrorAction SilentlyContinue
    Write-Host "Assessment data cleaned." -ForegroundColor Gray
}

Write-Host "Loki successfully uninstalled." -ForegroundColor Green
