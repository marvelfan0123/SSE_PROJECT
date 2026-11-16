# VulnX — architecture and boundaries

`app.py` (Streamlit UI) → `assessment_portal.py` / `assessment_manager.py` → `assessment_worker.py` → Nmap / Trivy / ZAP adapters → SQLite-backed assessment history → `phase3_analysis.py` / risk engine → `remediation_workflow.py` → `phase5_reporting.py`.

Cross-cutting modules: `auth.py`, `authorized_actions.py`, `audit_log.py`, `security_controls.py`, `db_utils.py`.

Data is scoped to assessments. Scanner failure can produce partial coverage; absent findings are not automatically proven remediated. Nmap port observations are not confirmed CVE vulnerabilities. Asset business criticality requires evidence/confirmation. Correlation is conservative. NVD enrichment may be rate-limited or unavailable.

**Deployment limits:** local academic prototype only. SQLite is not a distributed database; demo credentials, in-process login throttling, audit logging and local-only scanner controls are not equivalent to production IAM, immutable logging or network isolation. Public deployment requires a separate security review, TLS, centralized authentication/rate limiting, secrets management, monitoring, backups and recovery exercises.
