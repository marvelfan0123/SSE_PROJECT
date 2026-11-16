"""Scanner-specific matching for assessment-to-assessment comparison."""


def finding_match_key(finding):
    source = finding.get("source")
    evidence = finding.get("evidence") or {}
    if source == "Trivy":
        return (source, finding.get("asset"), finding.get("cve"), finding.get("package"))
    if source == "Nmap":
        return (source, finding.get("asset"), evidence.get("port"), evidence.get("service"))
    if source == "OWASP ZAP":
        instances = evidence.get("instances") or []
        uri = instances[0].get("uri", "") if instances and isinstance(instances[0], dict) else ""
        return (source, evidence.get("plugin_id"), uri)
    return (source, finding.get("finding_id"))


def compare_assessment_findings(previous, current):
    """Compare two lists; return new, persistent and no-longer-detected records."""
    previous_map = {finding_match_key(item): item for item in previous}
    current_map = {finding_match_key(item): item for item in current}
    previous_keys, current_keys = set(previous_map), set(current_map)
    return {
        "new": [current_map[key] for key in sorted(current_keys - previous_keys, key=str)],
        "persistent": [current_map[key] for key in sorted(current_keys & previous_keys, key=str)],
        "no_longer_detected": [previous_map[key] for key in sorted(previous_keys - current_keys, key=str)],
    }
