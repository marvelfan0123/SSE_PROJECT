# VulnX reliability and security hardening update

## Changes in this ZIP

1. Added `db_utils.py` to centralize SQLite connection settings (WAL, bounded busy timeout, foreign keys, configurable DB path).
2. Updated scan-history, asset-discovery, remediation, comparison, audit-log and asset-profile persistence to use the shared connection helper.
3. Added strict, bounded timeout validation for Trivy, Nmap and ZAP. Nmap XML is capped at 5 MB before parsing.
4. Added strict CVE ID validation and environment-based `NVD_API_KEY` fallback.
5. Added `.env.example` and ignored real `.env` files.
6. Added `SECURITY_AND_SCALE_REVIEW.md` to distinguish implemented hardening from work that still requires architectural migration.
7. Preserved the original `scan_history.db` and included a copy at `backups/scan_history.db.before-hardening`.

## Verification

- Python compile check: passed.
- Unit tests: 119 passed.
- External scanner tests use mocks; no live Trivy, Nmap, ZAP, NVD or production deployment test is claimed.

## Not yet implemented

PostgreSQL/SQLAlchemy migration and Celery/Redis asynchronous job execution are deliberately not marked complete. The current app uses SQLite-specific SQL and synchronous Streamlit flows. Implementing either safely requires coordinated schema, job-state, UI polling, deployment and migration work; adding dependencies alone would be misleading and could break the existing scan history.
