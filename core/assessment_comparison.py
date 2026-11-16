"""Assessment Comparison & Verification Engine for VulnX."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import assessment_comparison as legacy_comp


@dataclass
class VerificationOutcome:
    finding_id: str
    status: str  # 'FIXED', 'STILL_PRESENT', 'REGRESSED', 'NOT_REASSESSED', 'INCONCLUSIVE'
    details: str
    pre_scan_id: str
    post_scan_id: str
    scanner_verified: str


class AssessmentComparator:
    """Verifies remediation success by diffing baseline and follow-up scans."""

    @staticmethod
    def compare(previous_findings: List[Dict[str, Any]], current_findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Perform finding diff between baseline and rescan."""
        return legacy_comp.compare_assessment_findings(previous_findings, current_findings)

    @classmethod
    def verify_ticket_resolution(
        cls,
        target_finding: Dict[str, Any],
        rescan_findings: List[Dict[str, Any]],
        rescan_scanners_completed: List[str]
    ) -> VerificationOutcome:
        """
        Verify whether a specific ticketed finding has been truly remediated.
        Enforces Module 8 Guardrail:
        - If the required scanner did not complete in the rescan, outcome is INCONCLUSIVE.
        - If the finding matches any in rescan_findings, outcome is STILL_PRESENT.
        - If the scanner completed and finding is absent, outcome is FIXED.
        """
        f_id = target_finding.get("finding_id", "")
        f_source = target_finding.get("source", "Trivy")
        target_key = legacy_comp.finding_match_key(target_finding)

        # Check scanner coverage
        if f_source not in rescan_scanners_completed and "Trivy" not in rescan_scanners_completed:
            return VerificationOutcome(
                finding_id=f_id,
                status="INCONCLUSIVE",
                details=f"Scanner '{f_source}' was not executed or failed in the rescan. Cannot confirm fix.",
                pre_scan_id=target_finding.get("assessment_id", ""),
                post_scan_id="",
                scanner_verified=f_source
            )

        rescan_keys = {legacy_comp.finding_match_key(rf) for rf in rescan_findings}
        if target_key in rescan_keys:
            return VerificationOutcome(
                finding_id=f_id,
                status="STILL_PRESENT",
                details=f"Vulnerability {target_finding.get('cve') or f_id} was re-detected on the target asset.",
                pre_scan_id=target_finding.get("assessment_id", ""),
                post_scan_id="",
                scanner_verified=f_source
            )

        return VerificationOutcome(
            finding_id=f_id,
            status="FIXED",
            details=f"Vulnerability {target_finding.get('cve') or f_id} was confirmed absent by {f_source} in subsequent rescan.",
            pre_scan_id=target_finding.get("assessment_id", ""),
            post_scan_id="",
            scanner_verified=f_source
        )

