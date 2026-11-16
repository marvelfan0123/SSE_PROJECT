# VulnX Enterprise Deployment & Operations Guide

## 1. Prerequisites & System Requirements

- **Operating System:** Windows 10/11, Ubuntu 20.04/22.04 LTS, macOS 12+
- **Python Runtime:** Python 3.10 to 3.14
- **Security Scanners (Optional for Demo / Required for Live Production):**
  - **Trivy:** Aqua Security Trivy CLI v0.50+ on PATH
  - **Nmap:** Nmap Security Scanner v7.80+ on PATH
  - **Docker Engine:** Docker Desktop or Docker Engine v24+ (for OWASP ZAP & Container Discovery)

---

## 2. Installation & Quickstart (PowerShell / Windows)

```powershell
# 1. Clone repository and navigate to root directory
cd c:\Users\rahul\OneDrive\Desktop\VulnGraph

# 2. Create and activate a Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install core dependencies
pip install -r requirements.txt
pip install google-genai requests

# 4. Initialize database schema & run migrations
python migrate_enterprise_schema.py

# 5. Launch the VulnX Web Application
streamlit run app.py --server.port 8501
```

Access the web interface at: `http://localhost:8501`

---

## 3. Environment Configuration (`.env`)

Copy `.env.example` to `.env` and configure options:

```bash
# Set to 1 to enable live FIRST.org EPSS and CISA KEV lookups
VULNX_THREAT_ENRICHMENT=1

# Optional Google Gemini API Key for AI Security Copilot
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash

# Optional Local Ollama URL (For 100% offline air-gapped deployments)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b
```

---

## 4. Secure First-Run Administrator Setup

VulnX eliminates static or default credentials for security hygiene.

When deployed on a fresh environment without an existing database:
1. Launch the application: `streamlit run app.py --server.port 8501`.
2. The initial administrator setup screen is displayed automatically.
3. Establish your primary administrator account with a strong password (minimum 10 characters with mixed-case, numbers, and symbols).
4. The system stores the credentials using salted PBKDF2-HMAC-SHA256.
5. Create additional Security Analyst and Approver accounts dynamically using the **User Management** portal.

