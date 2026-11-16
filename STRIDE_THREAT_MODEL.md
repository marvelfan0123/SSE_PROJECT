# STRIDE THREAT MODEL & SECURITY CONTROLS

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  

---

## 1. Threat Modeling Matrix (STRIDE)

| STRIDE Category | Identified Threat | Implemented Security Control in VulnX | Verification Module |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Unauthorized access via default or hardcoded credentials | Zero default passwords; mandatory first-run administrator initialization; Bcrypt (`rounds=12`) password hashing; strict password complexity validation | `auth.py`, `tests/test_database_auth_rbac.py` |
| **Tampering** | Modification of historical audit records or assessment findings | Append-only SHA-256 hash-chained audit trail (`prev_hash` + `event_hash`) with external HMAC-SHA256 checkpoint verification; parameterized SQLite queries | `audit_log.py`, `tests/test_audit_log_tamper.py` |
| **Repudiation** | Unattributed approval or closure of high-risk vulnerability tickets | Every ticket creation, status transition, approval, rejection, and user lifecycle action is logged with actor username, role, UTC timestamp, and mandatory decision justification | `remediation_workflow.py`, `audit_log.py` |
| **Information Disclosure** | Leakage of password hashes, API keys, or CSV formula injection in exports | Password hashes are never returned by `list_users()`; `.env.example` contains empty placeholders only; CSV exports sanitize leading `=`, `+`, `-`, `@` characters via `csv_cell()` | `security_controls.py`, `auth.py` |
| **Denial of Service** | Subprocess hang during external scanner execution or duplicate scan clicks | Bounded subprocess timeouts (`VULNGRAPH_TRIVY_TIMEOUT`, `VULNGRAPH_NMAP_TIMEOUT`, `VULNGRAPH_ZAP_TIMEOUT`), duplicate submission guard (`find_recent_active_assessment`), and stale worker recovery (`recover_stale_assessments`) | `assessment_manager.py`, `assessment_worker.py` |
| **Elevation of Privilege** | Security Analyst self-approving their own remediation ticket or accessing Admin controls | Role-Based Access Control (`Admin`, `Security Analyst`, `Approver`) enforced in both UI and backend (`require_permission`); strict Maker-Checker self-approval prevention (`actor != requested_by`) | `auth.py`, `remediation_workflow.py`, `tests/test_remediation_workflow.py` |
