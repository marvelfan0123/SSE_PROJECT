"""VulnX Legacy Evidence-Aware Risk Model (v2).

ARCHITECTURAL CONSOLIDATION NOTICE:
===================================
The canonical risk-scoring engine for the VulnX platform is implemented in `vulngraph_core.py`
using the unified 0-10 contextual risk formula:
    R = 10 * [0.3 * (CVSS / 10) + 0.7 * EPSS] * Reachability * (Criticality / 5)

This module (`risk_model.py`) preserves the v2 additive heuristic model for backwards
compatibility with offline benchmark tests and legacy research tooling. For all active
platform workflows (live assessments, workers, SQLite persistence, and UI dashboards),
use `vulngraph_core.score_finding_canonical()` or `vulngraph_core.contextual_risk()`.
"""

from __future__ import annotations

# Re-export canonical engine references for convenient migration
from vulngraph_core import (
    contextual_risk as canonical_contextual_risk,
    score_finding_canonical,
    resolve_reachability,
    resolve_criticality,
    classify_reachability,
)
import math

EXPOSURE_FACTORS = {"loopback": .8, "internal": 1., "private_network": 1., "all_interfaces": 1.2, "unknown": 1.}
CRITICALITY_FACTORS = {"Low": .8, "Normal": 1., "High": 1.2}
ZAP_BASE_SCORES = {"HIGH": 8., "MEDIUM": 5., "LOW": 3., "INFO": 1., "INFORMATIONAL": 1.}
SEVERITY_BASE_SCORES = {"CRITICAL": 9.5, "HIGH": 8., "MEDIUM": 5.5, "LOW": 2.5}
MODEL_VERSION = "vulnx-priority-3.1-evidence-guardrails"

def _numeric(value, low, high):
    try:
        number = float(value)
        return number if math.isfinite(number) and low <= number <= high else None
    except (ValueError, TypeError):
        return None

def _label(score):
    # Bands mirror the CVSS v3 qualitative ratings on the 0-100 scale (CVSS x 10):
    # Critical 9.0+, High 7.0+, Medium 4.0+. With no extra evidence a Medium
    # finding therefore stays Medium instead of being promoted a band.
    return "Critical" if score >= 90 else "High" if score >= 70 else "Medium" if score >= 40 else "Low"

def score_assessment_finding(finding, exposure_factor=None, criticality_factor=1., nvd_record=None):
    item = dict(finding)
    if item.get("source") == "Nmap" or item.get("finding_type") == "network_exposure_observation":
        item.update(risk_score=None, risk_label="Exposure observation", contextual_risk=None,
                    base_risk=None, threat_priority=None, scoring_model=MODEL_VERSION)
        return item
    severity = str(item.get("severity") or "UNKNOWN").upper()
    scanner_cvss = _numeric(item.get("cvss"), 0, 10)
    nvd_cvss = (_numeric(nvd_record.get("cvss_score"), 0, 10) if isinstance(nvd_record, dict)
                and nvd_record.get("status") == "enriched" else None)
    if scanner_cvss is not None:
        base, provenance = scanner_cvss, "Trivy CVSS" if item.get("source") == "Trivy" else "Scanner CVSS"
    elif nvd_cvss is not None:
        base, provenance = nvd_cvss, "NVD CVSS"
    elif item.get("source") == "OWASP ZAP" and severity in ZAP_BASE_SCORES:
        base, provenance = ZAP_BASE_SCORES[severity], "ZAP severity proxy (not CVSS)"
    elif severity in SEVERITY_BASE_SCORES:
        base, provenance = SEVERITY_BASE_SCORES[severity], "Severity estimate (not CVSS)"
    else:
        base, provenance = None, "Unavailable"
    item.update(base_score=base, base_score_source=provenance,
                base_risk=round(base * 10, 2) if base is not None else None,
                scoring_model=MODEL_VERSION)
    # Preserve original CVSS. A proxy must never masquerade as CVSS.
    if base is None:
        item.update(risk_score=None, risk_label="Insufficient evidence", threat_priority=None,
                    contextual_risk=None, scoring_confidence="Insufficient Evidence")
        return item
    # Never use stale or invalid threat intelligence as current evidence.
    epss_state = item.get("epss_status", "available" if item.get("epss_percentile") is not None else "unavailable")
    kev_state = item.get("kev_evidence_status", "available")
    epss_percentile = _numeric(item.get("epss_percentile"), 0, 1) if epss_state == "available" else None
    epss_probability = _numeric(item.get("epss_probability"), 0, 1)
    kev = item.get("kev_status")
    if kev_state != "available" or kev not in ("listed", "not_listed"):
        kev = "unavailable"
    # Bounded, evidence-aware additive model. Missing evidence contributes no
    # *observed* boost; it is not recorded as a measured zero. This deliberately
    # preserves base severity as a floor to avoid enrichment-driven score drops.
    # Weights are unvalidated research heuristics, NOT calibrated probabilities.
    base_risk = base * 10
    epss_boost = (.35 * epss_percentile if epss_percentile is not None else 0.)
    kev_boost = (.35 if kev == "listed" else 0.)
    threat = base_risk + (100 - base_risk) * min(1., epss_boost + kev_boost)
    available = ["CVSS or severity proxy"]
    if epss_percentile is not None:
        available.append("EPSS percentile")
    if kev != "unavailable":
        available.append("KEV status")
    threat_model = "Bounded evidence-aware additive (v3); " + ", ".join(available)
    threat = round(min(100, max(0, threat)), 2)
    criticality = _numeric(criticality_factor, 0, 2)
    if criticality is None:
        criticality = 1.
    exposure = _numeric(exposure_factor, 0, 2)
    verified_exposure = exposure is not None
    if exposure is None:
        exposure = 1.
    mitigation = 1.
    if item.get("mitigation_verified") is True:
        mitigation = _numeric(item.get("verified_mitigation_factor"), .1, 1.) or 1.
    contextual = round(min(100, max(0, threat * criticality * exposure * mitigation)), 2)
    label = _label(contextual)
    if kev == "listed" and item.get("kev_applicable") is not False and label in ("Low", "Medium"):
        label = "High"  # Policy floor; numeric score remains unchanged.
    # Completeness is not verification: available EPSS/KEV/exposure alone cannot
    # establish source freshness, applicability or independently verified findings.
    complete = (verified_exposure and epss_percentile is not None and kev != "unavailable"
                and provenance not in ("Severity estimate (not CVSS)", "ZAP severity proxy (not CVSS)"))
    confidence = "Evidence Complete (Not Independently Verified)" if complete else "Provisional"
    item.update(threat_priority=threat, threat_model=threat_model,
                contextual_risk=contextual, risk_score=contextual, risk_label=label,
                exposure_factor=exposure, criticality_factor=criticality,
                exposure_verified=verified_exposure, scoring_confidence=confidence,
                epss_probability=epss_probability, epss_percentile=epss_percentile,
                kev_status=kev, verified_mitigation_factor=mitigation,
                scoring_evidence={"epss_status": "available" if epss_percentile is not None else epss_state if epss_state != "available" else "unavailable",
                                  "kev_status": kev, "kev_evidence_status": kev_state, "exposure_status": "verified" if verified_exposure else "unknown",
                                  "mitigation_verified": item.get("mitigation_verified") is True},
                threat_boost=round(threat - base_risk, 2))
    return item

def image_risk(findings):
    """Bounded image-level score. Deduplicate stable finding identities."""
    unique = {}
    for f in findings:
        score = _numeric(f.get("threat_priority"), 0, 100)
        if score is None:
            continue
        # Component/location distinguishes distinct affected installations.
        # Scanner identity is retained for non-CVE findings to avoid merging
        # unrelated scanner observations that happen to share a title.
        identifier = f.get("cve") or f.get("finding_id") or (f.get("source"), f.get("title"))
        key = (f.get("asset"), identifier, f.get("package"),
               f.get("installed_version"), f.get("location") or f.get("path") or f.get("target"))
        unique[key] = max(score, unique.get(key, 0))
    if not unique:
        return None
    values = sorted(unique.values(), reverse=True)
    extra = sum(value >= 50 for value in values[1:])
    return round(min(100, values[0] + .1 * (100 - values[0]) * (1 - math.exp(-extra / 10))), 2)
