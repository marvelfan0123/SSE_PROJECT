"""Evidence-based OWASP Top 10:2025 classification for VulnX.

VulnX: Scanning and Vulnerability Management Platform.
Conservative classification mapping scanner-reported CWEs to OWASP Top 10:2025 categories.
Never guesses classification from CVE ID alone.
"""
from __future__ import annotations
from typing import Any

MAPPING_VERSION = "OWASP-Top-10:2025-v1.0"

CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# Evidence-backed CWE registry mapped to primary OWASP 2025 categories
CWE_MAP = {
    # A01: Broken Access Control
    "CWE-22": "A01", "CWE-284": "A01", "CWE-862": "A01", "CWE-863": "A01",
    "CWE-639": "A01", "CWE-918": "A01", "CWE-352": "A01", "CWE-285": "A01",
    "CWE-264": "A01", "CWE-749": "A01", "CWE-27": "A01", "CWE-29": "A01",
    "CWE-59": "A01", "CWE-732": "A01",
    # A02: Security Misconfiguration
    "CWE-16": "A02", "CWE-200": "A02", "CWE-611": "A02", "CWE-1004": "A02",
    "CWE-215": "A02", "CWE-1021": "A02", "CWE-693": "A02", "CWE-524": "A02",
    "CWE-538": "A02",
    # A03: Software Supply Chain Failures
    "CWE-1395": "A03", "CWE-1357": "A03", "CWE-1104": "A03", "CWE-937": "A03",
    "CWE-1078": "A03", "CWE-829": "A03",
    # A04: Cryptographic Failures
    "CWE-319": "A04", "CWE-327": "A04", "CWE-326": "A04", "CWE-330": "A04",
    "CWE-310": "A04", "CWE-328": "A04", "CWE-295": "A04", "CWE-331": "A04",
    "CWE-338": "A04", "CWE-916": "A04",
    # A05: Injection
    "CWE-79": "A05", "CWE-89": "A05", "CWE-78": "A05", "CWE-77": "A05",
    "CWE-94": "A05", "CWE-91": "A05", "CWE-564": "A05", "CWE-116": "A05",
    # A06: Insecure Design
    "CWE-73": "A06", "CWE-183": "A06", "CWE-213": "A06", "CWE-235": "A06",
    "CWE-657": "A06", "CWE-1053": "A06",
    # A07: Authentication Failures
    "CWE-287": "A07", "CWE-306": "A07", "CWE-798": "A07", "CWE-522": "A07",
    "CWE-384": "A07", "CWE-640": "A07",
    # A08: Software or Data Integrity Failures
    "CWE-347": "A08", "CWE-502": "A08", "CWE-494": "A08", "CWE-915": "A08",
    "CWE-1321": "A08",
    # A09: Security Logging and Alerting Failures
    "CWE-778": "A09", "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09",
    # A10: Mishandling of Exceptional Conditions
    "CWE-209": "A10", "CWE-703": "A10", "CWE-754": "A10", "CWE-755": "A10",
    "CWE-390": "A10", "CWE-1333": "A10", "CWE-400": "A10", "CWE-770": "A10",
    "CWE-789": "A10", "CWE-835": "A10", "CWE-674": "A10", "CWE-248": "A10",
    "CWE-404": "A10", "CWE-405": "A10", "CWE-407": "A10", "CWE-617": "A10",
}

LIMITATIONS_DISCLAIMER = (
    "Classification is inferred from scanner-reported CWE metadata. "
    "Scanner CWEs indicate general software weakness types and do not prove exploitability in this deployment."
)


def register_cwe_mapping(cwe_id: str, category_code: str) -> None:
    """Extensibility API: register or override a CWE to OWASP category mapping."""
    cwe_clean = str(cwe_id).strip().upper()
    cat_clean = str(category_code).strip().upper()
    if not cwe_clean.startswith("CWE-"):
        raise ValueError("CWE ID must begin with 'CWE-'.")
    if cat_clean not in CATEGORIES:
        raise ValueError(f"Category must be one of {list(CATEGORIES.keys())}.")
    CWE_MAP[cwe_clean] = cat_clean


def classify(finding: dict[str, Any], assessment_id: str) -> dict[str, Any]:
    """Classify a vulnerability finding into OWASP Top 10:2025.
    
    Requires explicit CWE evidence. Rejects guessing from CVE ID alone.
    If multiple conflicting categories match, requires manual review and returns UNCLASSIFIED.
    """
    evidence = finding.get("evidence") or {}
    cwes = (
        finding.get("cwe_ids") or
        finding.get("cwe") or
        finding.get("cwe_id") or
        evidence.get("cwe_ids") or
        evidence.get("cwe") or
        evidence.get("cwe_id") or
        []
    )
    if isinstance(cwes, str):
        cwes = [c.strip() for c in cwes.replace(";", ",").split(",") if c.strip()]
    if not isinstance(cwes, (list, tuple)):
        cwes = []

    matched = []
    for raw_cwe in cwes:
        cwe_norm = str(raw_cwe).strip().upper()
        if not cwe_norm.startswith("CWE-") and cwe_norm.isdigit():
            cwe_norm = f"CWE-{cwe_norm}"
        if cwe_norm in CWE_MAP:
            matched.append((cwe_norm, CWE_MAP[cwe_norm]))

    categories = sorted(set(cat for _, cat in matched))

    if not matched:
        return {
            "assessment_id": assessment_id,
            "finding_id": finding.get("finding_id"),
            "category": "UNCLASSIFIED",
            "category_name": "Unclassified",
            "matched_categories": [],
            "explanation": "No scanner-reported CWE evidence available for this finding; manual review required.",
            "evidence": [],
            "confidence": "Manual Review",
            "mapping_version": MAPPING_VERSION,
            "limitations": LIMITATIONS_DISCLAIMER,
        }

    if len(categories) > 1:
        # Multiple categories: require analyst review rather than forcing an ambiguous choice
        return {
            "assessment_id": assessment_id,
            "finding_id": finding.get("finding_id"),
            "category": "UNCLASSIFIED",
            "category_name": "Multiple Categories Identified",
            "matched_categories": categories,
            "explanation": f"Multiple evidence-backed OWASP categories identified ({', '.join(categories)}); manual review required to select primary category.",
            "evidence": matched,
            "confidence": "Manual Review",
            "mapping_version": MAPPING_VERSION,
            "limitations": LIMITATIONS_DISCLAIMER,
        }

    # Exactly one matching category
    code = categories[0]
    return {
        "assessment_id": assessment_id,
        "finding_id": finding.get("finding_id"),
        "category": code,
        "category_name": CATEGORIES[code],
        "matched_categories": [code],
        "explanation": f"Classification inferred from scanner-reported CWE ({', '.join(c for c, _ in matched)}) matching OWASP {code}: {CATEGORIES[code]}.",
        "evidence": matched,
        "confidence": "Inferred",
        "mapping_version": MAPPING_VERSION,
        "limitations": LIMITATIONS_DISCLAIMER,
    }
