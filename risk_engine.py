"""VulnX Legacy Risk Prioritization Module.

ARCHITECTURAL CONSOLIDATION NOTICE:
===================================
The canonical risk-scoring engine for the VulnX platform is implemented in `vulngraph_core.py`
using the unified 0-10 contextual risk formula:
    R = 10 * [0.3 * (CVSS / 10) + 0.7 * EPSS] * Reachability * (Criticality / 5)

This module (`risk_engine.py`) preserves legacy 0-100 severity-proxy scoring for historical
scripts and backwards compatibility with earlier benchmark tests. For all active platform
workflows (live assessments, background workers, reports, and UI dashboards), use
`vulngraph_core.score_finding_canonical()` or `vulngraph_core.contextual_risk()`.
"""

# Re-export canonical engine references for convenient migration
from vulngraph_core import (
    contextual_risk as canonical_contextual_risk,
    score_finding_canonical,
    resolve_reachability,
    resolve_criticality,
    classify_reachability,
)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEVERITY_CVSS_PROXY = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5, "UNKNOWN": 0.0}
EXPOSURE_WEIGHTS = {"INTERNAL": 1.0, "EXPOSED": 1.5}
MAX_RAW_RISK = 10.0 * 1.5

def _valid_cvss(nvd_record):
    if not isinstance(nvd_record, dict) or nvd_record.get("status") != "enriched":
        return None
    try:
        score = float(nvd_record.get("cvss_score"))
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None

def score_finding(finding, nvd_cache=None, asset_criticality=None, exposure="Internal"):
    """Score a finding; asset_criticality is accepted only for old callers and ignored."""
    finding = dict(finding)
    severity = str(finding.get("Severity") or "UNKNOWN").upper()
    if severity not in SEVERITY_CVSS_PROXY:
        severity = "UNKNOWN"
    cve = str(finding.get("CVE") or "").strip().upper()
    record = (nvd_cache or {}).get(cve, {}) if cve.startswith("CVE-") else {}
    cvss = _valid_cvss(record)
    if cvss is None:
        base_score = SEVERITY_CVSS_PROXY[severity]
        basis = f"Severity-derived proxy ({base_score:g}/10); NVD CVSS unavailable"
        finding["NVD CVSS"] = ""
        finding["CVSS Basis"] = "Severity proxy (not CVSS)"
    else:
        base_score = cvss
        basis = f"NVD CVSS {base_score:g}/10"
        finding["NVD CVSS"] = cvss
        finding["CVSS Basis"] = "NVD CVSS"
    exposure_level = str(exposure or "Internal").upper()
    if exposure_level not in EXPOSURE_WEIGHTS:
        exposure_level = "INTERNAL"
    exposure_weight = EXPOSURE_WEIGHTS[exposure_level]
    raw_risk = base_score * exposure_weight
    normalized = round(raw_risk / MAX_RAW_RISK * 100)
    if normalized >= 40:
        priority = "P1 - Urgent"
    elif normalized >= 30:
        priority = "P2 - High"
    elif normalized >= 20:
        priority = "P3 - Moderate"
    else:
        priority = "P4 - Low"
    finding["Exposure"] = exposure_level.title()
    finding["Exposure Weight"] = exposure_weight
    finding["Raw Risk"] = round(raw_risk, 2)
    finding["Risk Score"] = normalized
    finding["Priority"] = priority
    finding["Why Prioritized"] = (
        f"{basis} × exposure weight {exposure_weight:g} ({exposure_level.title()}) "
        f"= raw risk {raw_risk:.2f}; normalized score {normalized}/100. "
        "Exposure is contextual information, not proof of exploitability. "
        "A severity-derived proxy is an estimate, not an NVD CVSS value."
    )
    return finding

def prioritize_findings(findings, nvd_cache=None, asset_criticality=None, exposure="Internal", asset_criticality_by_asset=None):
    """Prioritize findings by CVSS/severity and exposure; legacy criticality args are ignored."""
    scored = [score_finding(item, nvd_cache=nvd_cache, exposure=exposure) for item in findings]
    scored.sort(key=lambda item: (str(item.get("CVE", "")), str(item.get("Package", ""))))
    scored.sort(key=lambda item: (item["Risk Score"], SEVERITY_RANK.get(str(item.get("Severity", "UNKNOWN")).upper(), 0), bool(item.get("Fixed Version") and str(item["Fixed Version"]).strip().lower() not in {"", "no fix listed", "none", "n/a"})), reverse=True)
    return scored
