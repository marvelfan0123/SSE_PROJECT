# Security, reliability and scale review

## Implemented in this revision

- Scanner commands continue to use argument arrays (no shell interpolation).
- Trivy, ZAP and Nmap execution timeouts are now bounded by validated ranges.
- Trivy and ZAP validate their machine-readable output before accepting a report.
- Nmap output is size-limited before XML parsing; its target and port validation remains restrictive to the local/private lab.
- NVD CVE identifiers are validated with a strict format before any request. `NVD_API_KEY` can be supplied through the process environment; the key is not written to the cache or source files.
- SQLite connections now share a connection policy: WAL journaling, a bounded busy timeout, foreign-key enforcement and normal synchronous mode. `VULNX_DATABASE_PATH` supports a separate database path. Keep regular backups.
- Existing role-checked entry points in `authorized_actions.py` remain the route for scanner and enrichment operations. Remediation service methods enforce role and workflow checks.
- Existing finding correlation uses conservative identities and preserves incomplete records rather than merging them speculatively.

## Important limits / not represented as completed

This remains a local academic/demo deployment. WAL and busy-timeout reduce SQLite contention; they do not provide multi-node database concurrency or enterprise HA. PostgreSQL is **not** enabled by this revision because the current application modules use SQLite-specific SQL and schema creation. A safe PostgreSQL migration requires a shared repository/ORM layer, migration scripts, transaction tests and a verified copy of the existing `scan_history.db`.

Celery/Redis is **not** wired into the Streamlit scan workflow in this revision. Simply adding a broker would not be sufficient: the UI needs persisted job IDs, queued/running/succeeded/failed states, result retrieval, cancellation/timeout handling and authorization checks at both enqueue and worker execution. Until that workflow exists, scans run synchronously with bounded timeouts.

## Production-hardening checklist

1. Replace demo PBKDF2 accounts with an organization identity provider or managed user store; enforce HTTPS and secure session handling at the deployment layer.
2. Add CSRF/session protections appropriate to the chosen deployment and rate-limit login attempts.
3. Run scanners in isolated workers with least privilege and resource limits; restrict allowed targets at network egress as well as in application validation.
4. Introduce SQLAlchemy/Alembic or an equivalent repository layer, migrate SQLite data to PostgreSQL, and test rollback/concurrent writes before switching the default database.
5. Add Celery/Redis (or equivalent) only alongside durable job state, retry policy, idempotency keys, worker authorization, and UI polling.
6. Add CI tests with representative Trivy/ZAP/Nmap fixtures and mocks; reserve live scans for explicitly configured lab integration tests.
7. Add structured logging, log rotation, backup/restore drills, dependency pinning and vulnerability scanning of the platform itself.

## Suggested deployment environment

Copy `.env.example` to a private environment file or set the variables in the host/container environment. Do not commit real API keys, passwords, tokens or production database URLs. The current demo login credentials and SQLite database are for local demonstration only.
