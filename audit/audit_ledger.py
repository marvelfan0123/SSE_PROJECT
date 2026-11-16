"""Cryptographic Append-Only Audit Ledger for VulnX."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import audit_log
import audit_checkpoint


class AuditLedger:
    """Manages append-only cryptographic event logging and checkpoints."""

    @staticmethod
    def record_event(
        actor: str,
        role: str,
        action: str,
        entity_type: str = "",
        entity_id: str = "",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record an auditable action into the HMAC-SHA256 ledger."""
        audit_log.log_event(
            username=actor,
            role=role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details
        )

    @staticmethod
    def list_events(limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        return audit_log.get_audit_events(limit=limit)

    @staticmethod
    def create_checkpoint(actor: str = "Admin") -> Dict[str, Any]:
        """Generate a cryptographically signed HMAC checkpoint of the ledger."""
        return audit_checkpoint.create_checkpoint(actor=actor)

