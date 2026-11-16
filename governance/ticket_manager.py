"""Remediation Ticket Lifecycle Manager."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import remediation_workflow


class TicketManager:
    """Manages ticketing operations across assessments."""

    @staticmethod
    def create_ticket(
        assessment_id: str,
        finding_id: str,
        actor: str,
        role: str,
        owner: str = "",
        due_date: str = "",
        notes: str = ""
    ) -> int:
        """Create a new remediation ticket."""
        return remediation_workflow.create_ticket(
            assessment_id=assessment_id,
            finding_id=finding_id,
            actor=actor,
            role=role,
            owner=owner,
            due_date=due_date,
            notes=notes
        )

    @staticmethod
    def list_tickets_for_assessment(assessment_id: str) -> List[Dict[str, Any]]:
        """Retrieve all tickets for an assessment."""
        return remediation_workflow.tickets_for_assessment(assessment_id)

    @staticmethod
    def get_ticket(ticket_id: int) -> Dict[str, Any]:
        """Fetch ticket by ID."""
        return remediation_workflow.get_ticket(ticket_id)

