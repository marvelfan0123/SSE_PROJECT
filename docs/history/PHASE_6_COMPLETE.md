# Phase 6 — Security Hardening, RBAC and Audit Improvements

## Iteration 1 — Authentication safeguards
- Added per-process username login throttling (five failures within five minutes, five-minute block).
- Generic error messages avoid disclosing whether a username exists.
- Existing PBKDF2 password verification and backend RBAC checks retained.

## Iteration 2 — Audit data minimization
- Recursive redaction of password, token, secret, authorization, API key, cookie and credential fields before SQLite persistence.
- Existing admin-only audit access retained.

## Iteration 3 — Output and deployment hygiene
- Integrated `csv_cell()` into Phase 3, Phase 4, Phase 5, and assessment findings CSV exports to prevent spreadsheet formula injection.
- Admin Settings includes security deployment warnings.

## Iteration 4 — Regression verification
- Added focused security regression tests and ran the complete automated suite.

## Security limitations
This is a **local academic demonstration**, not production IAM. Demo credentials remain present in `auth.py`; do not expose this service to public networks. Rate limits are process-local and reset on restart. Audit records are not tamper-proof. TLS, SSO/MFA, reverse-proxy rate limits, centralized logs, production secrets management, network isolation and penetration testing are required before shared deployment. Live Windows/Docker testing is deferred to Phase 7 as requested.
