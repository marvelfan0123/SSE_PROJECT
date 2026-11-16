# VulnX Testing, Verification & Quality Assurance Guide

## 1. Test Suite Architecture

VulnX maintains a comprehensive, automated test suite covering unit, integration, security guardrails, and end-to-end workflows.

All tests are located in `tests/` and run using standard `pytest`.

```powershell
# Run the complete test suite
python -m pytest tests -v

# Run with quiet progress indicator
python -m pytest tests -q
```

---

## 2. Test Categories & Verification Scope

| Test Module | Coverage Scope |
| :--- | :--- |
| `test_ai_copilot.py` | AI provider fallback, prompt injection sanitization, JSON schema enforcement, playbook generation, impact analyzer, virtual patch synthesis, attack path storyteller. |
| `test_modular_core.py` | Canonical risk formula clamping, EPSS weighting, KEV priority override, finding deduplication, rescan verification guardrails. |
| `test_demo_mode.py` | Isolated viva demonstration mode activation, data injection, and clean database deactivation. |
| `test_database_auth_rbac.py` | PBKDF2 password hashing, session tokens, and role-based permissions matrix. |
| `test_audit_log.py` | HMAC-SHA256 append-only logging, hash continuity, and live tampering detection. |
| `test_vulngraph_core.py` | NetworkX compound attack graph, ForceAtlas2 stability, and edge relationship integrity. |
| `test_golden_path_e2e.py` | Full end-to-end workflow: scan creation $\rightarrow$ finding extraction $\rightarrow$ risk scoring $\rightarrow$ graph rendering $\rightarrow$ ticket lifecycle $\rightarrow$ resolution. |

---

## 3. Negative Testing Scenarios Verified

- **Maker-Checker Bypass Attempt:** An Analyst attempts to approve their own ticket $\rightarrow$ Caught with `PermissionError: Maker-Checker Violation`.
- **Premature Resolution Attempt:** Attempting to mark a ticket `Resolved` without rescan proof $\rightarrow$ Rejected with `ValueError: Resolution requires a later comparable rescan`.
- **Database Tampering Simulation:** Modifying an audit event payload directly in SQLite $\rightarrow$ Caught by `AuditVerifier` with `valid: False, reason: Audit record modified`.
- **Offline / Disconnected API:** Executing AI copilot or threat intelligence without network $\rightarrow$ Graceful fallback to cached EPSS and deterministic playbooks. Zero system crashes.

