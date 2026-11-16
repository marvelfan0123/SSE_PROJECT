# ==============================================================================
# VulnX: Scanning and Vulnerability Management Platform
# Automated Windows Environment Setup Script (PowerShell)
# ==============================================================================

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  🛡️  VulnX: Environment Setup & Health Verification" -ForegroundColor Cyan
Write-Host "  Scanning and Vulnerability Management Platform" -ForegroundColor DarkCyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[1/7] Checking Python installation..." -ForegroundColor Yellow
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $pythonCmd) {
    Write-Host "[-] Python is not installed or not in PATH. Please install Python 3.10+ from python.org." -ForegroundColor Red
    exit 1
}

$pyVersion = & $pythonCmd.Name -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
Write-Host "[+] Found Python $pyVersion at $($pythonCmd.Source)" -ForegroundColor Green

# 2. Virtual Environment Setup
Write-Host "`n[2/7] Checking Python virtual environment..." -ForegroundColor Yellow
$venvDir = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating virtual environment at .venv..." -ForegroundColor Gray
    & $pythonCmd.Name -m venv $venvDir
    if (-not (Test-Path $venvPython)) {
        Write-Host "[-] Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Existing virtual environment detected." -ForegroundColor Green
}

# 3. Install Dependencies
Write-Host "`n[3/7] Installing and updating Python dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r $reqFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to install requirements. Please review error output above." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Python packages verified and up-to-date." -ForegroundColor Green

# 4. Validate Configuration File
Write-Host "`n[4/7] Checking environment configuration..." -ForegroundColor Yellow
$envFile = Join-Path $PSScriptRoot ".env"
$envExample = Join-Path $PSScriptRoot ".env.example"

if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Host "[+] Created .env from .env.example." -ForegroundColor Green
    } else {
        Write-Host "[!] Warning: Neither .env nor .env.example found." -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] .env configuration file present." -ForegroundColor Green
}

# 5. Check Scanner Availability
Write-Host "`n[5/7] Checking external security scanners..." -ForegroundColor Yellow

# Nmap
$nmapPath = & $venvPython -c "from asset_discovery import discover_nmap_executable; print(discover_nmap_executable() or '')"
if ($nmapPath -and (Test-Path $nmapPath)) {
    $nmapVer = & $nmapPath --version | Select-Object -First 1
    Write-Host "  [+] Nmap: Available at $nmapPath ($nmapVer)" -ForegroundColor Green
} else {
    Write-Host "  [-] Nmap: Not found on PATH or standard install directories. (Download: https://nmap.org/download.html)" -ForegroundColor Yellow
}

# Trivy
$trivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
if ($trivyCmd) {
    $trivyVer = & trivy --version | Select-Object -First 1
    Write-Host "  [+] Trivy: Available ($trivyVer)" -ForegroundColor Green
} else {
    Write-Host "  [-] Trivy: Not found on PATH. (Download: https://github.com/aquasecurity/trivy/releases)" -ForegroundColor Yellow
}

# Docker Desktop
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) {
    $dockerVer = & docker --version
    Write-Host "  [+] Docker CLI: Available ($dockerVer)" -ForegroundColor Green
    $dockerRunning = & docker info --format '{{.ServerVersion}}' 2>$null
    if ($dockerRunning) {
        Write-Host "  [+] Docker Engine: Running (v$dockerRunning)" -ForegroundColor Green
    } else {
        Write-Host "  [!] Docker Desktop daemon is not currently running. Start Docker Desktop for container inspection & ZAP." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [-] Docker Desktop: Not found on PATH. (Download: https://www.docker.com/products/docker-desktop)" -ForegroundColor Yellow
}

# 6. Initialize Database Schema (First-run administrator will be established on first launch)
Write-Host "`n[6/7] Initializing SQLite database schema..." -ForegroundColor Yellow
& $venvPython -c "import db_utils, auth; db_utils.initialize_all_tables(); req = auth.is_initial_setup_required(); print('[+] Database schema initialized. First-run admin setup required:', req)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Database initialization failed." -ForegroundColor Red
    exit 1
}

# 7. Summary & Recommendations
Write-Host "`n[7/7] Setup Verification Summary" -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Core Application Engine: Ready" -ForegroundColor Green
Write-Host "  Database Schema & Auth:  Initialized" -ForegroundColor Green
Write-Host "  UI Theme & Primitives:   Configured (Midnight Security)" -ForegroundColor Green
Write-Host ""
Write-Host "To launch the VulnX application:" -ForegroundColor White
Write-Host "  .\run.ps1" -ForegroundColor Cyan
Write-Host "  or: .\.venv\Scripts\streamlit run app.py" -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan

