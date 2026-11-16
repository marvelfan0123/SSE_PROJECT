# VulnX update: Audit logging and OWASP checks

## Added
- SQLite `audit_events` table with timestamp, user, role, action, entity, and JSON details.
- Audit events for login success/failure, logout, remediation create/duplicate/update, and completed Nmap scans.
- Admin-only audit table and CSV export.
- Evidence-aware OWASP Top 10:2021 dashboard checks for A01, A02, A03, A05, A06, and A07.
- Unit tests for audit log storage and OWASP check semantics.

## Safety / scope notes
- Passwords are never sent to the audit logger.
- The log is application-level and can be modified by a user with direct write access to SQLite; it is not tamper-proof.
- OWASP statuses are not a full compliance assessment. Unassessed categories are labeled explicitly; Trivy package scanning is not source-code analysis or DAST.
- Existing `scan_history.db` and scan reports are preserved in this ZIP. Tests for audit logging use temporary databases.

## Validation run in build environment
- `python -m unittest discover -s tests -v`: 73 tests passed.
- `python -m compileall -q .`: passed.
- `python tools/validate_scan_comparison.py`: passed; actual bundled Juice Shop reports share 105 persistent finding identities, while the controlled fixture correctly reports 1 new, 1 persistent, and 1 no-longer-detected finding.
- Streamlit was not interactively launched on the user's Windows computer as part of this validation.
