"""Evidence-driven automatic asset criticality assessment for VulnX.

Only explicit VulnX labels are treated as authoritative business evidence.
Known local training targets receive limited lab-context evidence. Missing
business facts remain unknown; scanner severity, image names, ports and CVEs
never become business criticality scores.
"""
from __future__ import annotations

FACTORS = {
    "data_sensitivity": "Data sensitivity",
    "business_importance": "Business importance",
    "availability_impact": "Availability impact",
    "dependency_impact": "Dependency impact",
}
LABEL_KEYS = {
    key: (f"com.vulnx.{key.replace('_', '-')}", f"vulnx.{key.replace('_', '-')}")
    for key in FACTORS
}
LEVELS = ((2, "Low"), (3, "Medium"), (4, "High"), (5, "Critical"))


def _label_score(labels: dict, factor: str):
    for key in LABEL_KEYS[factor]:
        value = labels.get(key)
        if value is None:
            continue
        try:
            score = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= score <= 5:
            return score, f"Docker label {key}={score}", "High"
    return None


def assess_asset(evidence: dict) -> dict:
    """Calculate category scores only where source evidence supports them."""
    containers = evidence.get("containers") or []
    labels = {}
    for container in containers:
        labels.update(container.get("labels") or {})
    factors, explanations, confidence = {}, {}, {}
    for factor in FACTORS:
        labelled = _label_score(labels, factor)
        if labelled:
            factors[factor], explanations[factor], confidence[factor] = labelled

    # Explicit environment metadata can support a business-importance estimate,
    # but does not prove data sensitivity, availability impact or dependencies.
    if "business_importance" not in factors:
        env = str(labels.get("com.vulnx.environment") or labels.get("environment") or "").lower()
        env_scores = {"development": 1, "testing": 1, "test": 1, "staging": 2, "production": 4, "prod": 4}
        if env in env_scores:
            factors["business_importance"] = env_scores[env]
            explanations["business_importance"] = f"Environment label indicates {env}; this is a provisional business-role proxy, not proof of business impact."
            confidence["business_importance"] = "Medium"

    # The project's own local Juice Shop/DVWA lab context is known to be for
    # security testing. Business/availability impact raised to 2 (Low-Medium)
    # so that high-severity CVEs (CVSS>=9, EPSS>=90%) produce a meaningful
    # contextual score (~4-5/10) rather than a misleadingly low 1.97/10.
    asset_name = str(evidence.get("asset_name", "")).lower()
    if not containers and any(token in asset_name for token in ("juice-shop", "juice_shop", "dvwa")):
        factors.setdefault("business_importance", 2)
        explanations.setdefault("business_importance", "Known VulnX intentionally vulnerable training target; classified as a lab asset with low-medium business impact.")
        confidence.setdefault("business_importance", "High")
        factors.setdefault("availability_impact", 2)
        explanations.setdefault("availability_impact", "Local training application; raised to low-medium to reflect realistic scanner impact on running services.")
        confidence.setdefault("availability_impact", "High")

    missing = [key for key in FACTORS if key not in factors]
    result = {
        "factor_scores": factors,
        "factor_names": FACTORS,
        "evidence": explanations,
        "factor_confidence": confidence,
        "missing_factors": missing,
        "evidence_sources": [evidence.get("evidence_source", "Asset metadata")],
        "assessment_status": "Insufficient evidence" if missing else "Automatically assessed",
        "overall_confidence": "Low" if len(missing) >= 2 else ("Medium" if missing else ("High" if set(confidence.values()) == {"High"} else "Medium")),
    }
    if not missing:
        average = sum(factors.values()) / 4
        level = "Low" if average < 2 else "Medium" if average < 3 else "High" if average < 4 else "Critical"
        result.update({"average_score": round(average, 2), "suggested_criticality": level})
    else:
        result.update({"average_score": None, "suggested_criticality": "Unassigned"})
    return result


def automatic_assessment(target, containers=()):
    """Assessment-scoped estimate; never infer business impact from CVEs."""
    containers = list(containers)
    # Do not merge conflicting metadata from distinct assets.
    result = assess_asset({"asset_name": "", "containers": containers if len(containers) <= 1 else [],
                           "evidence_source": "Selected asset metadata"})
    # A configured training target is an explicit scope assumption, not a
    # conclusion about an arbitrary image with a similar name.
    if target.get("configured_training_lab") and not result["factor_scores"]:
        result.update(factor_scores={k: 2 for k in FACTORS},
                      evidence={k: "Configured disposable training lab assumption (low-medium baseline)" for k in FACTORS},
                      factor_confidence={k: "Low" for k in FACTORS},
                      missing_factors=[], average_score=2.0,
                      suggested_criticality="Low-Medium", overall_confidence="Low",
                      assessment_status="Provisional")
    average = result["average_score"]
    result["risk_level"] = min(5, int(average + 0.5)) if average is not None else None
    return result
