"""Evidence-based, conservative attack-path analysis for VulnX.

This module does not exploit targets or run scans. It only builds paths from
observations supplied by the existing VulnX scanners and explicitly configured
lab relationships. Missing relationships are never guessed.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    source: str
    destination: str
    steps: list[str]
    evidence: list[str]
    confidence: str
    caveat: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_open(observation: dict[str, Any]) -> bool:
    state = _norm(observation.get("state", observation.get("State", "open")))
    return state in {"open", "up", "listening"}


def _port(observation: dict[str, Any]) -> str:
    return str(observation.get("port", observation.get("Port", ""))).strip()


def _asset(observation: dict[str, Any]) -> str:
    return str(observation.get("asset", observation.get("Asset", observation.get("target", observation.get("Target", "Unknown asset"))))).strip()


def _severity(finding: dict[str, Any]) -> str:
    return _norm(finding.get("Severity", finding.get("severity", "unknown"))).upper()


def _cve(finding: dict[str, Any]) -> str:
    return str(finding.get("CVE", finding.get("cve", finding.get("VulnerabilityID", finding.get("vulnerability_id", ""))))).strip()


def _finding_asset(finding: dict[str, Any]) -> str:
    return str(finding.get("Asset", finding.get("asset", finding.get("Target", finding.get("target", ""))))) .strip()


def _has_substantive_relationship_evidence(evidence: str) -> bool:
    """Avoid upgrading a path to Medium from arbitrary non-empty text alone.

    This is a lightweight quality gate, not proof that the supplied evidence is
    true. The final caveat still requires manual verification.
    """
    normalized = _norm(evidence)
    evidence_terms = (
        "docker", "network", "compose", "container", "service", "connect",
        "reachable", "firewall", "route", "iptables", "port", "config",
        "inspect", "curl", "http", "tcp", "subnet", "security group", "log",
    )
    return len(normalized) >= 16 and any(term in normalized for term in evidence_terms)


def build_attack_paths(
    findings: Iterable[dict[str, Any]],
    network_observations: Iterable[dict[str, Any]],
    asset_relationships: Iterable[dict[str, str]] = (),
    internet_exposed_assets: Iterable[str] = (),
) -> list[AttackPath]:
    """Create conservative candidate paths from explicit evidence.

    `network_observations`: rows with asset/target, port, service, optional state.
    `asset_relationships`: explicitly configured rows {source, destination, evidence}.
      These should represent known lab connectivity, not a guessed relationship.
    `internet_exposed_assets`: assets explicitly known to be internet-reachable.
      If omitted, an open port on localhost is labelled locally exposed, not Internet.
    """
    findings = list(findings)
    observations = [row for row in network_observations if _is_open(row)]
    relationships = list(asset_relationships)
    internet_assets = {_norm(item) for item in internet_exposed_assets if _norm(item)}
    paths: list[AttackPath] = []
    path_no = 1

    # A network observation is evidence of an open/listening port only. It does
    # not by itself establish Internet exposure or link a service to an image CVE.
    for obs in observations:
        asset = _asset(obs)
        port = _port(obs)
        service = str(obs.get("service", obs.get("Service", "unknown service"))).strip() or "unknown service"
        if not port:
            continue
        evidence = [f"Nmap observation: {asset} has port {port} open ({service})."]
        if _norm(asset) in internet_assets:
            steps = ["Internet-reachable asset", f"{asset}:{port} ({service})"]
            source = "Internet"
            confidence = "Medium"
            caveat = "Internet reachability was explicitly configured; this is not proof of exploitation."
        else:
            steps = ["Scanner vantage point / local host", f"{asset}:{port} ({service})"]
            source = "Local scanner vantage point"
            confidence = "Low"
            caveat = "An open port was observed from the scanner vantage point; public Internet exposure is not established."
        paths.append(AttackPath(f"AP-{path_no:03d}", source, asset, steps, evidence, confidence, caveat))
        path_no += 1

    # Only connect a vulnerable asset to another asset if a user explicitly
    # supplied the relationship. Match finding target to either endpoint label.
    for rel in relationships:
        source = str(rel.get("source", "")).strip()
        destination = str(rel.get("destination", "")).strip()
        if not source or not destination:
            continue
        rel_evidence = str(rel.get("evidence", "")).strip()
        # Prefer exact asset-name matches. When report targets use scanner-specific
        # names (for example, "Node.js" or an OS package target) rather than the
        # Docker service name, allow the UI to carry an explicit user-confirmed
        # mapping of the selected Trivy report to one relationship endpoint.
        finding_endpoint = str(rel.get("finding_endpoint", "")).strip()
        if finding_endpoint and _norm(finding_endpoint) in {_norm(source), _norm(destination)}:
            matching = findings
        else:
            matching = [
                f for f in findings
                if _norm(_finding_asset(f)) in {_norm(source), _norm(destination)}
            ]
        vuln_evidence = []
        for finding in matching:
            cve = _cve(finding)
            severity = _severity(finding)
            if cve and severity in {"CRITICAL", "HIGH"}:
                vuln_evidence.append(f"{_finding_asset(finding)}: {cve} ({severity}) reported by scanner.")
        if not vuln_evidence:
            continue
        evidence = [f"Configured lab relationship: {source} -> {destination}."]
        if rel_evidence:
            evidence.append(f"Relationship evidence: {rel_evidence}")
        if finding_endpoint and _norm(finding_endpoint) in {_norm(source), _norm(destination)}:
            evidence.append(
                f"Selected Trivy report explicitly associated by the user with endpoint: {finding_endpoint}."
            )
        evidence.extend(vuln_evidence[:5])
        evidence_is_substantive = _has_substantive_relationship_evidence(rel_evidence)
        paths.append(AttackPath(
            f"AP-{path_no:03d}", source, destination,
            [source, "High/Critical scanner finding associated with a linked endpoint", destination],
            evidence, "Medium" if evidence_is_substantive else "Low",
            "Candidate attack path only. The endpoint-to-report association is user-supplied. Connectivity and scanner findings do not prove the vulnerability is exploitable or that this route can be traversed. Validate the relationship and vulnerability manually."
        ))
        path_no += 1

    return paths


def summarize_attack_paths(paths: Iterable[AttackPath]) -> dict[str, int]:
    paths = list(paths)
    return {
        "candidate_paths": len(paths),
        "high_confidence": sum(p.confidence == "High" for p in paths),
        "medium_confidence": sum(p.confidence == "Medium" for p in paths),
        "low_confidence": sum(p.confidence == "Low" for p in paths),
    }


def build_attack_path_graphviz(paths: Iterable[AttackPath]) -> str:
    """Return a Graphviz DOT diagram for the supplied candidate paths.

    Labels are escaped before insertion into DOT. Node identity is based on the
    displayed step text, so shared assets/components are shown as shared nodes.
    Confidence colors describe the evidence heuristic, not exploit probability.
    """
    paths = list(paths)
    if not paths:
        return ""

    def quote(value: str) -> str:
        return (str(value).replace("\\", "\\\\")
                .replace('"', '\\"').replace("\n", " ").replace("\r", " "))

    colors = {"High": "#dc2626", "Medium": "#d97706", "Low": "#2563eb"}
    node_ids: dict[str, str] = {}
    lines = [
        "digraph VulnXAttackPaths {",
        '  graph [rankdir=LR, bgcolor="transparent", pad="0.25", nodesep="0.45", ranksep="0.7"];',
        '  node [shape=box, style="rounded,filled", fillcolor="#e5e7eb", color="#64748b", fontname="Arial", fontsize=10, margin="0.14,0.08"];',
        '  edge [fontname="Arial", fontsize=9, color="#64748b", arrowsize=0.7];',
    ]

    def node_id(label: str) -> str:
        if label not in node_ids:
            node_ids[label] = f"node_{len(node_ids) + 1}"
            lines.append(f'  {node_ids[label]} [label="{quote(label)}"];')
        return node_ids[label]

    for path in paths:
        color = colors.get(path.confidence, colors["Low"])
        for left, right in zip(path.steps, path.steps[1:]):
            left_id = node_id(left)
            right_id = node_id(right)
            lines.append(
                f'  {left_id} -> {right_id} [label="{quote(path.path_id)} · {quote(path.confidence)}", color="{color}", fontcolor="{color}"];'
            )
    lines.append("}")
    return "\n".join(lines)
