"""Canonical Finding Normalizer for VulnX."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedFinding:
    finding_id: str
    assessment_id: str
    asset_id: str
    source: str
    finding_type: str  # 'package_vulnerability', 'network_observation', 'web_vulnerability'
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    url: Optional[str] = None
    evidence: Any = None
    epss_score: Optional[float] = None
    kev_status: str = "Not Listed"
    reachability: float = 0.5
    criticality: int = 3
    contextual_risk: Optional[float] = None
    remediation_status: str = "Open"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FindingNormalizer:
    """Normalizes raw scanner outputs into the canonical VulnX finding schema."""

    @staticmethod
    def generate_finding_id(parts: List[Any]) -> str:
        """Create a deterministic SHA-256 fingerprint from finding attributes."""
        serialized = json.dumps([str(p) for p in parts], sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_trivy_vuln(
        cls,
        vuln: dict,
        assessment_id: str,
        asset_id: str,
        target_name: str = ""
    ) -> NormalizedFinding:
        cve = vuln.get("cve") or vuln.get("VulnerabilityID") or "UNKNOWN"
        pkg = vuln.get("package") or vuln.get("PkgName") or "unknown"
        installed = vuln.get("installed_version") or vuln.get("InstalledVersion") or ""
        fixed = vuln.get("fixed_version") or vuln.get("FixedVersion") or "None listed"
        sev = str(vuln.get("severity") or vuln.get("Severity") or "UNKNOWN").upper()
        title = vuln.get("title") or vuln.get("Title") or f"Vulnerability in {pkg}"
        desc = vuln.get("description") or vuln.get("Description") or ""

        # Extract CVSS
        cvss = vuln.get("cvss")
        if cvss is None and isinstance(vuln.get("CVSS"), dict):
            # Try parsing nested CVSS
            nvd_v3 = vuln["CVSS"].get("nvd", {}).get("V3Score")
            if nvd_v3 is not None:
                try:
                    cvss = float(nvd_v3)
                except (ValueError, TypeError):
                    pass

        finding_id = cls.generate_finding_id([assessment_id, asset_id, cve, pkg, installed])

        return NormalizedFinding(
            finding_id=finding_id,
            assessment_id=assessment_id,
            asset_id=asset_id,
            source="Trivy",
            finding_type="package_vulnerability",
            title=title,
            description=desc,
            severity=sev,
            cvss_score=cvss,
            cve_id=cve,
            package_name=pkg,
            installed_version=installed,
            fixed_version=fixed,
            host=target_name,
            evidence=vuln
        )

    @classmethod
    def from_nmap_port(
        cls,
        port_info: dict,
        assessment_id: str,
        asset_id: str,
        host: str
    ) -> NormalizedFinding:
        port_num = port_info.get("port")
        proto = port_info.get("protocol", "tcp")
        service = port_info.get("service", "unknown")
        version = port_info.get("version", "")

        finding_id = cls.generate_finding_id([assessment_id, asset_id, host, port_num, proto, service])

        return NormalizedFinding(
            finding_id=finding_id,
            assessment_id=assessment_id,
            asset_id=asset_id,
            source="Nmap",
            finding_type="network_observation",
            title=f"Open Port {port_num}/{proto} ({service})",
            description=f"Port {port_num}/{proto} is open on {host}, running {service} {version}".strip(),
            severity="INFO",
            cvss_score=0.0,
            host=host,
            port=int(port_num) if str(port_num).isdigit() else None,
            service=service,
            evidence=port_info
        )

    @classmethod
    def from_zap_alert(
        cls,
        alert: dict,
        assessment_id: str,
        asset_id: str,
        target_url: str
    ) -> NormalizedFinding:
        title = alert.get("title") or alert.get("alert") or "Web Security Finding"
        desc = alert.get("description") or alert.get("desc") or ""
        sev = str(alert.get("severity") or alert.get("riskdesc", "LOW")).split(" ")[0].upper()
        cwe = alert.get("cwe_id") or alert.get("cweid")
        solution = alert.get("solution", "")

        finding_id = cls.generate_finding_id([assessment_id, asset_id, target_url, title])

        return NormalizedFinding(
            finding_id=finding_id,
            assessment_id=assessment_id,
            asset_id=asset_id,
            source="OWASP ZAP",
            finding_type="web_vulnerability",
            title=title,
            description=desc,
            severity=sev,
            cwe_id=str(cwe) if cwe else None,
            url=target_url,
            fixed_version=solution,
            evidence=alert
        )

