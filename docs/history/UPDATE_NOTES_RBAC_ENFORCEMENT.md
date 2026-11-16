# RBAC Enforcement Update

## What changed

- Centralized role permissions in `auth.py`.
- Added `require_permission()` and explicit permissions for Admin, Analyst, and Approver.
- Added permission-checked service entry points in `authorized_actions.py` for Trivy, Nmap, ZAP, and NVD enrichment.
- Added backend role checks to remediation creation and updates.
- Added role-specific remediation transitions and field restrictions.
- Added backend Admin-only checks to audit-log reading.
- Added an **Access & Roles** dashboard page with the permission matrix.
- Added `ROLE_BASED_ACCESS_CONTROL.md` as the documentation for the exact current implementation.

## Remediation sequence

1. Analyst creates a Pending item.
2. Approver approves or rejects it.
3. After approval, Analyst can move it to In Progress.
4. Approver or Admin records verification evidence.
5. Resolved requires verification status Pass and non-empty evidence.

## Test result

Run `python -m unittest discover -s tests -v` from this folder. The RBAC update adds tests for denied scanner actions, denied NVD enrichment, denied audit-log access, remediation role restrictions, and the full Analyst/Approver workflow.

## Limitations

This is a local academic prototype with fixed demo accounts. There is no user creation, password reset, external identity provider, or production-grade session management. Admin can perform approval actions, so production deployments should consider stricter dual-control rules. Audit logs are not tamper-proof against direct database access.
