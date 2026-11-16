# ==============================================================================
# VulnX: Scanning and Vulnerability Management Platform
# Application Execution Script (PowerShell)
# ==============================================================================

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  🛡️  Launching VulnX — Scanning and Vulnerability Management Platform..." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$pyToUse = if (Test-Path $venvPython) { $venvPython } else { "python" }

# Set environment defaults
$env:STREAMLIT_SERVER_HEADLESS = "false"
$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = "false"

# Run Streamlit
Write-Host "[*] Starting Streamlit server on http://localhost:8501" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C in this terminal to stop the application." -ForegroundColor Gray
Write-Host ""

& $pyToUse -m streamlit run app.py

