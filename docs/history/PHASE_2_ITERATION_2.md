# Phase 2 — Iteration 2: Scanner reliability

Implemented:
- Configurable per-scanner bounded timeouts via `VULNX_TRIVY_TIMEOUT` (30–3600, default 1800), `VULNX_NMAP_TIMEOUT` (10–600, default 120), `VULNX_ZAP_TIMEOUT` (60–3600, default 900), in seconds. Invalid values revert to defaults.
- Scanner failure details persisted in scanner `result_json` (`error_type` and truncated error message); scanner-failure audit event excludes potentially sensitive error strings.
- Normalized findings are saved before NVD enrichment and correlation, retaining evidence if later processing fails. An interrupted assessment with saved findings or a completed scanner is `Partial` rather than `Failed`.
- Four focused regression tests for timeout and failure handling.

Not implemented yet: a safe retry button for failed scanners, crash recovery after the entire worker process is killed, live Windows/Docker end-to-end testing. Those require additional design and validation.
