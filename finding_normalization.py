"""Normalize scanner outputs into a shared, source-aware VulnX schema.

This module does not decide whether a network observation is a vulnerability.
Trivy package vulnerabilities and Nmap open-port observations have distinct
finding_type values and retain scanner-specific evidence.
"""

import hashlib
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"


def _stable_id(parts):
    """Build a repeatable ID from the identifying parts of a finding."""
    serialized = json.dumps(parts, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _text(value, default=""):
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def _trivy_cvss(vuln):
    """Choose an actual Trivy CVSS score, preserving its vendor and version.

    Trivy's CVSS is a mapping of vendor -> {V3Score, V3Vector, ...}.
    A scanner score is evidence, not an estimated severity proxy.
    """
    cvss = vuln.get("CVSS") or {}
    if not isinstance(cvss, dict):
        return None, None, None, None
    for vendor in ("nvd", "redhat", "ghsa", "ubuntu", "debian"):
        if vendor in cvss:
            candidates = [(vendor, cvss[vendor])]
            break
    else:
        candidates = list(cvss.items())
    # Prefer v4 then v3 then v2 within a provider, never accept invalid values.
    for vendor, data in candidates:
        if not isinstance(data, dict):
            continue
        for version, key, vector_key in (("4", "V4Score", "V4Vector"), ("3", "V3Score", "V3Vector"), ("2", "V2Score", "V2Vector")):
            try:
                value = float(data[key])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= value <= 10:
                return value, str(vendor), version, data.get(vector_key)
    return None, None, None, None


def normalize_trivy_report(scan_data, report_name=""):
    """Convert Trivy Results[].Vulnerabilities[] into common VulnX records."""
    normalized = []
    if not isinstance(scan_data, dict):
        return normalized
    for result in scan_data.get("Results") or []:
        target = _text(result.get("Target"), "Unknown")
        result_type = _text(result.get("Type"), "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            cve = _text(vuln.get("VulnerabilityID"), "Unknown")
            package = _text(vuln.get("PkgName"), "Unknown")
            installed_version = _text(vuln.get("InstalledVersion"))
            fixed_version = _text(vuln.get("FixedVersion"))
            severity = _text(vuln.get("Severity"), "UNKNOWN").upper()
            title = _text(vuln.get("Title"), cve)
            identity = ["trivy", target, cve, package, installed_version]
            cvss_score, cvss_vendor, cvss_version, cvss_vector = _trivy_cvss(vuln)
            cwe_raw = vuln.get("CweIDs") or []
            cwe_ids = [str(c).strip().upper() for c in cwe_raw if str(c).strip()]
            primary_cwe = cwe_ids[0] if cwe_ids else ""
            normalized.append({
                "schema_version": SCHEMA_VERSION,
                "finding_id": _stable_id(identity),
                "source": "Trivy",
                "source_report": _text(report_name),
                "finding_type": "package_vulnerability",
                "is_vulnerability": True,
                "asset": target,
                "title": title,
                "severity": severity,
                "cvss": cvss_score,
                "cvss_source": cvss_vendor,
                "cvss_version": cvss_version,
                "cvss_vector": cvss_vector,
                "cve": cve,
                "cwe": primary_cwe,
                "cwe_ids": cwe_ids,
                "package": package,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "evidence": {
                    "result_type": result_type,
                    "primary_url": _text(vuln.get("PrimaryURL")),
                    "description": _text(vuln.get("Description")),
                    "references": vuln.get("References") or [],
                    "cwe": primary_cwe,
                    "cwe_ids": cwe_ids,
                },
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
    return normalized


def normalize_nmap_result(scan_result):
    """Convert open Nmap ports into network observations, not confirmed CVEs."""
    normalized = []
    target = _text(scan_result.get("target"), "Unknown")
    for port in scan_result.get("open_ports") or []:
        port_number = _text(port.get("port"), "unknown")
        protocol = _text(port.get("protocol"), "tcp").lower()
        service = _text(port.get("service"), "unknown")
        version = _text(port.get("version"), "Not identified")
        identity = ["nmap", target, protocol, port_number, service, version]
        normalized.append({
            "schema_version": SCHEMA_VERSION,
            "finding_id": _stable_id(identity),
            "source": "Nmap",
            "source_report": "",
            "finding_type": "network_exposure_observation",
            "is_vulnerability": False,
            "asset": target,
            "title": f"Open {protocol.upper()} port {port_number} ({service})",
            "severity": "INFO",
            "cve": "",
            "cwe": "",
            "cwe_ids": [],
            "package": "",
            "installed_version": version,
            "fixed_version": "",
            "evidence": {
                "port": port_number,
                "protocol": protocol,
                "state": _text(port.get("state"), "open"),
                "service": service,
                "version": version,
                "cwe": "",
                "cwe_ids": [],
                "host_status": _text(scan_result.get("host_status"), "unknown"),
                "ports_checked": _text(scan_result.get("ports_checked")),
            },
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return normalized



def normalize_zap_report(scan_data, report_name="", app_name="Web application"):
    """Convert OWASP ZAP passive-scan alerts into common VulnX records.

    ZAP alerts are web-application findings, not package CVEs. CWE and
    instance URLs are retained as evidence; no CVE is invented when absent.
    """
    normalized = []
    if not isinstance(scan_data, dict):
        return normalized

    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in scan_data.get("site") or []:
        if not isinstance(site, dict):
            continue
        site_name = _text(site.get("@name"), app_name)
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            risk_code = _text(alert.get("riskcode"), "")
            risk_desc = _text(alert.get("riskdesc"), "").split("(")[0].strip().upper()
            severity = risk_map.get(risk_code, risk_desc if risk_desc in {"HIGH", "MEDIUM", "LOW", "INFO"} else "UNKNOWN")
            name = _text(alert.get("alert"), _text(alert.get("name"), "ZAP alert"))
            plugin_id = _text(alert.get("pluginid"), _text(alert.get("alertRef"), "unknown"))
            instances = alert.get("instances") or []
            instance_evidence = []
            for instance in instances[:20]:
                if isinstance(instance, dict):
                    instance_evidence.append({
                        "uri": _text(instance.get("uri")),
                        "method": _text(instance.get("method")),
                        "param": _text(instance.get("param")),
                        "evidence": _text(instance.get("evidence")),
                    })
            raw_cwe = _text(alert.get("cweid"))
            cwe_ids = []
            cwe_val = ""
            if raw_cwe and raw_cwe != "-1":
                cwe_val = f"CWE-{raw_cwe}" if raw_cwe.isdigit() else raw_cwe.upper()
                cwe_ids = [cwe_val]
            identity = ["zap", site_name, plugin_id, name]
            normalized.append({
                "schema_version": SCHEMA_VERSION,
                "finding_id": _stable_id(identity),
                "source": "OWASP ZAP",
                "source_report": _text(report_name),
                "finding_type": "web_application_vulnerability",
                "is_vulnerability": severity != "INFO",
                "asset": site_name,
                "title": name,
                "severity": severity,
                "cve": "",
                "cwe": cwe_val,
                "cwe_ids": cwe_ids,
                "package": "",
                "installed_version": "",
                "fixed_version": "",
                "evidence": {
                    "plugin_id": plugin_id,
                    "risk_description": _text(alert.get("riskdesc")),
                    "confidence": _text(alert.get("confidence")),
                    "description": _text(alert.get("desc")),
                    "solution": _text(alert.get("solution")),
                    "reference": _text(alert.get("reference")),
                    "cwe_id": raw_cwe,
                    "cwe": cwe_val,
                    "cwe_ids": cwe_ids,
                    "wasc_id": _text(alert.get("wascid")),
                    "instance_count": len(instances),
                    "instances": instance_evidence,
                    "scan_mode": "ZAP Baseline (passive checks)",
                },
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
    return normalized

def to_legacy_trivy_finding(record):
    """Adapt normalized Trivy records to the current dashboard's field names."""
    return {
        "Target": record["asset"],
        "Package": record["package"],
        "CVE": record["cve"],
        "CWE": record.get("cwe", ""),
        "Severity": record["severity"],
        "Installed Version": record["installed_version"],
        "Fixed Version": record["fixed_version"] or "No fix listed",
        "Title": record["title"],
        "Finding ID": record["finding_id"],
        "Source": record["source"],
        "Finding Type": record["finding_type"],
    }
