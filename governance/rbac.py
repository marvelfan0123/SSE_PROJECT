"""Role-Based Access Control and Permission Matrix for VulnX."""
from __future__ import annotations
import auth


class RBAC:
    """Manages role-based authorization for VulnX operations."""

    ROLES = ("Admin", "Security Analyst", "Approver", "Viewer")

    @staticmethod
    def require_permission(role: str, action: str) -> None:
        """Enforce role permissions, raising PermissionError if unauthorized."""
        auth.require_permission(role, action)

    @staticmethod
    def can_manage_users(role: str) -> bool:
        return auth.can_manage_users(role)

    @staticmethod
    def can_create_remediation(role: str) -> bool:
        return auth.can_create_remediation(role)

    @staticmethod
    def can_manage_approvals(role: str) -> bool:
        return auth.can_manage_approvals(role)

    @staticmethod
    def can_verify_remediation(role: str) -> bool:
        return auth.can_verify_remediation(role)

