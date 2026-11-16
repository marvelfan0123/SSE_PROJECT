"""Tests for VulnX Modular Core Engines."""
import pytest
from core.risk_engine import RiskEngine
from core.finding_normalizer import FindingNormalizer
from core.finding_deduplicator import FindingDeduplicator
from core.assessment_comparison import AssessmentComparator


def test_canonical_risk_engine():
    """Verify canonical formula R = 10 * [0.3 * (CVSS / 10) + 0.7 * EPSS] * Reach * (Crit / 5)."""
    # CVSS=10.0, EPSS=1.0, Reach=1.0, Crit=5 -> 10.0
    res = RiskEngine.calculate_canonical_risk(cvss=10.0, epss=1.0, reachability=1.0, criticality=5)
    assert res.score == 10.0
    assert "Tier 1 - Critical Risk" in res.priority_tier

    # Clamping test
    res_clamped = RiskEngine.calculate_canonical_risk(cvss=9.0, epss=0.5, reachability=1.0, criticality=4)
    assert 0.0 <= res_clamped.score <= 10.0


def test_risk_engine_kev_elevation():
    """KEV listing must assign Tier 0 urgency."""
    res = RiskEngine.calculate_canonical_risk(cvss=6.0, epss=0.1, reachability=0.7, criticality=3, kev_status="Listed")
    assert "Tier 0 - Immediate KEV Directive" in res.priority_tier


def test_finding_normalizer_and_deduplicator():
    """Verify normalization and entity-aware deduplication."""
    trivy_raw = {
        "VulnerabilityID": "CVE-2023-1234",
        "PkgName": "curl",
        "InstalledVersion": "7.68.0",
        "FixedVersion": "7.68.1",
        "Severity": "HIGH",
        "Title": "Curl buffer overflow"
    }
    norm = FindingNormalizer.from_trivy_vuln(trivy_raw, "ASSESS-1", "ASSET-1")
    assert norm.finding_type == "package_vulnerability"
    assert norm.cve_id == "CVE-2023-1234"

    # Deduplication test with duplicate finding
    dups = [norm, norm]
    deduped = FindingDeduplicator.deduplicate(dups)
    assert len(deduped) == 1


def test_assessment_comparator_resolution_guardrails():
    """Ensure resolution requires completed scanner and verified absence."""
    target_f = {"finding_id": "F1", "source": "Trivy", "cve": "CVE-2021-3517", "package": "libxml2", "asset": "web"}
    
    # Case 1: Inconclusive because Trivy was not executed in rescan
    res_inconclusive = AssessmentComparator.verify_ticket_resolution(
        target_f, rescan_findings=[], rescan_scanners_completed=["Nmap"]
    )
    assert res_inconclusive.status == "INCONCLUSIVE"

    # Case 2: Still present
    res_present = AssessmentComparator.verify_ticket_resolution(
        target_f, rescan_findings=[target_f], rescan_scanners_completed=["Trivy"]
    )
    assert res_present.status == "STILL_PRESENT"

    # Case 3: Fixed
    res_fixed = AssessmentComparator.verify_ticket_resolution(
        target_f, rescan_findings=[], rescan_scanners_completed=["Trivy"]
    )
    assert res_fixed.status == "FIXED"

