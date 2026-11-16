# WINDOWS SETUP & OPERATIONS GUIDE

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  

---

## 1. Prerequisites

- **Operating System:** Windows 10 / Windows 11 (64-bit)
- **Python:** Python 3.10+ (tested on Python 3.13)
- **External Security Scanners (Optional for Imported Reports, Required for Live Scans):**
  - **Nmap:** Install from `https://nmap.org/download.html` and ensure `nmap.exe` is on `PATH`.
  - **Trivy:** Install from `https://github.com/aquasecurity/trivy/releases` and ensure `trivy.exe` is on `PATH`.
  - **Docker Desktop:** Install from `https://www.docker.com/products/docker-desktop/` and ensure the **Docker Desktop Engine** daemon is running for live container inspection and OWASP ZAP container scans.

---

## 2. Automated Installation

From the project root directory in PowerShell:

```powershell
.\setup.ps1
```

This script:
1. Verifies Python 3.10+ availability.
2. Creates and populates `.venv` using `requirements.txt`.
3. Creates `.env` from `.env.example` (containing empty placeholders only — no hardcoded secrets).
4. Checks operational availability of `nmap`, `trivy`, and the Docker Desktop daemon (`docker info`).
5. Initializes the SQLite WAL database schema (`scan_history.db`).

---

## 3. First-Run Administrator Bootstrap

VulnX ships with zero default or hardcoded credentials. On first launch:

- **Via Web UI:** Navigate to `http://localhost:8501`. When no active `Admin` exists in `scan_history.db`, VulnX automatically displays the **First-Run Administrator Initialization** screen with password confirmation.
- **Via CLI (Secure Interactive Prompt):**
  ```powershell
  .\.venv\Scripts\python.exe auth.py --init-admin admin_user
  ```
  You will be prompted securely with masked password input:
  ```text
  Enter password for admin_user: [hidden]
  Confirm password: [hidden]
  ```
  *Non-interactive / CI / script environments:*
  Set the password in the environment variable rather than passing plaintext via CLI:
  ```powershell
  $env:VULNX_ADMIN_PASSWORD = "YourStrongPassword123!"
  .\.venv\Scripts\python.exe auth.py --init-admin admin_user
  Remove-Item Env:\VULNX_ADMIN_PASSWORD
  ```
  Passwords must be at least 10 characters and include uppercase, lowercase, numeric, and special characters.

---

## 4. Launching VulnX

```powershell
.\run.ps1
```

Or directly:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.port 8501
```

---

## 5. Executing Security Assessments

1. Navigate to **Security Assessment** in the sidebar.
2. **Step 1 — Target Configuration:**
   - Select one of:
     - **Quick Select — Local Vulnerable Lab Container** (`OWASP Juice Shop` or `DVWA`)
     - **Custom Container Image** (e.g., `nginx:1.24`, `python:3.11-slim`)
     - **Custom Network Target (Host / IP)** (authorized loopback/RFC1918 host and ports, e.g., `127.0.0.1`, port `8501`)
     - **Custom Web Application URL**
     - **Import Scanner JSON Report (Trivy)** (upload any real `trivy image --format json` file)
   - Click **Next: Scanner & Context Configuration →**.
3. **Step 2 — Scanner Selection, Asset Context & Execution:**
   - Select the desired scanners (**Nmap**, **Trivy**, **OWASP ZAP**), asset criticality level (`1`–`5`), and network reachability assumption (`1.0`, `0.5`, `0.0`).
   - Click **🚀 Initiate Assessment**.
4. **Live Execution & Scanner Telemetry:**
   - VulnX automatically switches to **Live Execution & Scanner Telemetry**, displaying the 15-stage pipeline tracker, per-scanner execution output, and worker diagnostic logs.
