"""Cryptographic Audit Chain and Checkpoint Verifier."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional
import audit_log
import audit_checkpoint


@dataclass
class AuditVerificationResult:
    valid: bool
    events_count: int
    reason: str
    checkpoint_verified: bool = False
    details: Dict[str, Any] = None


class AuditVerifier:
    """Verifies HMAC-SHA256 chain integrity and detects record tampering."""

    @staticmethod
    def verify_ledger() -> AuditVerificationResult:
        """Verify the complete hash-chain from genesis to the latest record."""
        res = audit_log.verify_audit_log_integrity()
        return AuditVerificationResult(
            valid=bool(res.get("valid")),
            events_count=int(res.get("events_count", 0)),
            reason=str(res.get("reason", "")),
            details=res
        )

    @staticmethod
    def verify_checkpoint_file(checkpoint_json_path: str) -> Dict[str, Any]:
        """Verify an exported checkpoint against the live database and HMAC key."""
        return audit_checkpoint.verify_checkpoint(checkpoint_json_path)

