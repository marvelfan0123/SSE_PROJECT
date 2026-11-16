# VulnX Security Hardening & Release Hygiene Audit Report

**Date:** November 12, 2026  
**Auditor:** Application Security Engineer & Release Certification Lead  
**Classification:** Confidential Security Engineering Audit  
**Status:** **CLEAN RELEASE CERTIFIED**

---

## 1. Executive Summary

This security audit inspects the VulnX platform for credential exposure, secret leakage, cryptographic implementation safety, subprocess security, and release archive hygiene.

All identified pre-release issues (accidental bundling of local SQLite database files, root HMAC keys in archive, and static credentials in documentation) have been mitigated. The distribution packaging pipeline now strictly excludes runtime databases, private cryptographic keys, and virtual environments.

---

## 2. Secret & Credential Scanning Audit

| Category | Target Files Scanned | Findings / Status | Remediation Applied |
| :--- | :--- | :--- | :--- |
| **API Keys** | `.env`, `.env.example`, `config.py`, `ai/ai_provider.py` | Clean. No hardcoded Gemini or Google API keys exist. | `GEMINI_API_KEY` is loaded strictly via environment variables. |
| **Default Passwords** | `README.md`, `DEPLOYMENT_GUIDE.md`, `auth.py` | Clean. Static default passwords removed from documentation. | Dynamically enforced via **First-Run Administrator Setup Wizard** on fresh deployment. |
| **HMAC Secret Key** | `.vulnx_protected/audit_checkpoint.key` | **CRITICAL RELEASE ISOLATION ENFORCED**. Key is kept strictly on local host. | Excluded from the distribution ZIP. Generated automatically on host at runtime with `0600` permissions. |
| **Database Credentials**| `scan_history.db`, backups | Clean. No production database files bundled in release archive. | All `*.db`, `*.sqlite`, `*.db-wal`, and `*.db-shm` excluded from release packaging. |
| **Subprocess Execution**| `scanners/*.py`, `asset_discovery.py`, `assessment_worker.py` | Clean. Subprocess calls strictly utilize argument lists (`shell=False`). | Eliminates arbitrary shell command injection risks. |

---

## 3. Cryptographic Implementation Review

1. **Password Hashing:**
   - Evaluated: `auth.py`
   - Algorithm: **PBKDF2-HMAC-SHA256**
   - Salt: 16 bytes of cryptographically secure pseudorandom salt (`secrets.token_bytes(16)`).
   - Iterations: 600,000 iterations (OWASP Recommended Standard).
   - Constant-time comparison: `secrets.compare_digest` used to eliminate timing side-channel attacks.

2. **Audit Ledger Hash Chaining:**
   - Evaluated: `audit/audit_ledger.py` and `audit/audit_verifier.py`.
   - Formulation: $\text{Current Hash} = \text{HMAC-SHA256}(K_{\text{secret}}, \text{Previous Hash} \parallel \text{Canonical JSON})$.
   - Tamper Detection: Verified. Out-of-band database row modification triggers instant verification failure.

---

## 4. Web Application Security Posture (`.streamlit/config.toml`)

- **Host Binding:** `address = "127.0.0.1"` (Restricted to localhost loopback; prevents unauthorized network exposure).
- **CORS Protection:** `enableCORS = true` (Enforced).
- **XSRF Protection:** `enableXsrfProtection = true` (Enforced).
- **Upload Restrictions:** `maxUploadSize = 25` (Enforces 25 MB ceiling on evidence file uploads).
- **Telemetry:** `gatherUsageStats = false` (Zero outbound tracking data sent).

---

## 5. Security Verdict

The codebase and release configuration adhere to enterprise application security practices. No unmanaged secrets, unverified default accounts, or private key materials are distributed within the release packaging.
