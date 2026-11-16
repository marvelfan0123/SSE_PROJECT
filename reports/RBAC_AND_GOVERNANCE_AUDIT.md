# VulnX RBAC & Maker-Checker Governance Audit Report

**Date:** November 12, 2026  
**Auditor:** Compliance & Governance Auditor  
**Standard Evaluated:** **Separation of Duties (SOC 2 CC6.8 / PCI-DSS 6.4 / ISO 27001 A.8.32)**  
**Status:** **BACKEND ENFORCEMENT VERIFIED**

---

## 1. Role-Based Access Control (RBAC) Matrix

| Operation | Admin | Security Analyst | Approver | Viewer |
| :--- | :---: | :---: | :---: | :---: |
| **Manage Users & Roles** | ✅ ALLOWED | ❌ BLOCKED | ❌ BLOCKED | ❌ BLOCKED |
| **Launch Security Assessments**| ✅ ALLOWED | ✅ ALLOWED | ❌ BLOCKED | ❌ BLOCKED |
| **Propose Remediation Tickets** | ✅ ALLOWED | ✅ ALLOWED | ❌ BLOCKED | ❌ BLOCKED |
| **Approve / Reject Tickets** | ✅ ALLOWED | ❌ BLOCKED | ✅ ALLOWED | ❌ BLOCKED |
| **Verify Rescan Resolutions** | ✅ ALLOWED | ❌ BLOCKED | ✅ ALLOWED | ❌ BLOCKED |
| **Audit Log Integrity Verify** | ✅ ALLOWED | ❌ BLOCKED | ❌ BLOCKED | ❌ BLOCKED |

Permissions are verified in backend functions (`auth.require_permission`) and raise `PermissionError` on unauthorized invocations.

---

## 2. Maker-Checker Separation of Duties Verification

```python
# Tested in tests/test_wizard_state_recovery.py and tests/test_remediation.py:
if maker.strip().lower() == approver.strip().lower():
    raise PermissionError("Maker-Checker Violation: You cannot approve a ticket you requested.")
```

- **Negative Test Case Passed:** An Analyst attempting to self-approve a ticket is blocked at the backend with an explicit `PermissionError`.
- **Mandatory Justification:** Approver must provide written justification for approval or rejection.
- **Rescan Verification Guardrail:** Tickets cannot transition to `Resolved` manually; backend requires an assessment showing verified absence proof.
