"""Formal Approval Engine with Maker-Checker Enforcement."""
from __future__ import annotations
from typing import Any, Dict, Optional
import remediation_workflow
from governance.rbac import RBAC


class ApprovalEngine:
    """Enforces separation of duties and Maker-Checker governance on remediation tickets."""

    @staticmethod
    def approve_ticket(ticket_id: int, approver: str, role: str, justification: str) -> None:
        """Approve a ticket with strict Maker-Checker verification."""
        RBAC.require_permission(role, "approve_remediation")
        if not (justification or "").strip():
            raise ValueError("Mandatory written justification is required for ticket approval.")

        # Check Maker identity
        ticket = remediation_workflow.get_ticket(ticket_id)
        maker = ticket.get("requested_by")
        if maker and maker.strip().lower() == approver.strip().lower():
            raise PermissionError("Maker-Checker Violation: You cannot approve a ticket you requested.")

        remediation_workflow.change_ticket(
            ticket_id=ticket_id,
            new_status="Approved",
            actor=approver,
            role=role,
            evidence=justification.strip()
        )

    @staticmethod
    def reject_ticket(ticket_id: int, reviewer: str, role: str, justification: str) -> None:
        """Reject a proposed remediation ticket with mandatory reason."""
        RBAC.require_permission(role, "approve_remediation")
        if not (justification or "").strip():
            raise ValueError("Mandatory written rejection reason is required.")

        remediation_workflow.change_ticket(
            ticket_id=ticket_id,
            new_status="Rejected",
            actor=reviewer,
            role=role,
            evidence=justification.strip()
        )

