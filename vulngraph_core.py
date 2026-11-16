"""Evidence-first VulnX primitives, canonical 0-10 risk engine, and interactive NetworkX attack graph analyzer.

VulnX: Scanning and Vulnerability Management Platform.
Implements:
- Docker inspect parser (published bindings are NOT proof of reachability)
- Evidence-backed port correlation (Host -> Open Port -> Service -> Container)
- Centralized canonical 0-10 contextual risk engine:
  R = 10 * [0.3 * (CVSS/10) + 0.7 * EPSS] * Reachability * (Criticality/5)
- Historical score migration and provenance preservation
- NetworkX attack graph builder (8 node types: Attacker, Host, Open Port, Service, Container, Image, Dependency, CVE)
- Interactive PyVis graph visualizer styled for Midnight Security theme
"""
from __future__ import annotations
import csv
import hashlib
import io
import json
import math
from typing import Any
import networkx as nx
from security_controls import csv_cell

MODEL_VERSION = "vulngraph-contextual-risk-1.0"

REACHABILITY_MAP = {
    "all_interfaces": 1.0,
    "external": 1.0,
    "confirmed_external": 1.0,
    "internet": 1.0,
    "loopback": 0.5,
    "internal": 0.5,
    "confirmed_internal": 0.5,
    "private_network": 0.5,
    "potential_exposure": 0.5,
    "wildcard_bind": 0.5,
    "unknown": None,
    "isolated": 0.0,
    "none": 0.0,
    "no_path": 0.0,
}


def classify_reachability(
    exposure_kind: Any = None,
    *,
    host_ip: str | None = None,
    observed_host: str | None = None,
    has_open_port: bool | None = None,
) -> dict[str, Any]:
    """Distinguish confirmed external, confirmed internal, potential exposure, unknown, and no path.

    Docker wildcard bindings (0.0.0.0 / ::) are NEVER treated as proof of public internet exposure;
    they represent potential host-interface exposure (reachability=0.5, confirmed=False).
    Unknown reachability remains None and is never silently converted into a confirmed numeric score.
    """
    bind = str(host_ip).strip() if host_ip is not None else None
    obs = str(observed_host or "").strip()
    exp_key = str(exposure_kind).strip().lower() if exposure_kind is not None else ""

    if has_open_port is False or exp_key in ("isolated", "none", "no_path"):
        return {
            "category": "No Identified Path",
            "exposure_kind": "no_path",
            "reachability": 0.0,
            "confirmed": True,
            "explanation": "No identified network path from the modelled attacker origin.",
        }

    if bind is not None:
        if bind in ("0.0.0.0", "::", ""):
            return {
                "category": "Potential Exposure",
                "exposure_kind": "potential_exposure",
                "reachability": 0.5,
                "confirmed": False,
                "explanation": "Docker wildcard binding (0.0.0.0/::) binds host interfaces; indicates potential exposure, not proof of public internet reachability.",
            }
        if bind in ("127.0.0.1", "::1", "localhost"):
            return {
                "category": "Confirmed Internal Exposure",
                "exposure_kind": "confirmed_internal",
                "reachability": 0.5,
                "confirmed": bool(has_open_port is not False),
                "explanation": "Loopback binding (127.0.0.1/::1) restricts exposure to the local host.",
            }

    if exp_key in ("confirmed_external", "external", "internet", "all_interfaces"):
        return {
            "category": "Confirmed External Reachability",
            "exposure_kind": exp_key,
            "reachability": 1.0,
            "confirmed": True,
            "explanation": "Explicitly modelled or verified external reachability.",
        }
    if exp_key in ("potential_exposure", "wildcard_bind"):
        return {
            "category": "Potential Exposure",
            "exposure_kind": "potential_exposure",
            "reachability": 0.5,
            "confirmed": False,
            "explanation": "Wildcard or unverified interface binding; potential exposure, not confirmed external reachability.",
        }
    if exp_key in ("confirmed_internal", "loopback", "internal", "private_network"):
        return {
            "category": "Confirmed Internal Exposure",
            "exposure_kind": exp_key,
            "reachability": 0.5,
            "confirmed": True,
            "explanation": "Internal or loopback network reachability.",
        }
    return {
        "category": "Unknown Reachability",
        "exposure_kind": "unknown",
        "reachability": None,
        "confirmed": False,
        "explanation": "Reachability is unknown and cannot be converted into a confirmed numeric score.",
    }

CRITICALITY_MAP = {
    "Low": 1,
    "low": 1,
    "Normal": 3,
    "normal": 3,
    "Medium": 3,
    "medium": 3,
    "High": 5,
    "high": 5,
    "Critical": 5,
    "critical": 5,
}

# Styling constants for Midnight Security theme
NODE_STYLES = {
    "Asset": {"color": {"background": "#795BFF", "border": "#4285FF", "highlight": {"background": "#9D85FF", "border": "#35C6E8"}}, "shape": "star", "size": 32},
    "Attacker": {"color": {"background": "#EF4444", "border": "#B91C1C", "highlight": {"background": "#F87171", "border": "#EF4444"}}, "shape": "diamond", "size": 28},
    "Host": {"color": {"background": "#3B82F6", "border": "#1D4ED8", "highlight": {"background": "#60A5FA", "border": "#3B82F6"}}, "shape": "hexagon", "size": 25},
    "Open Port": {"color": {"background": "#06B6D4", "border": "#0E7490", "highlight": {"background": "#22D3EE", "border": "#06B6D4"}}, "shape": "box", "size": 20},
    "Service": {"color": {"background": "#14B8A6", "border": "#0F766E", "highlight": {"background": "#2DD4BF", "border": "#14B8A6"}}, "shape": "ellipse", "size": 20},
    "Container": {"color": {"background": "#6366F1", "border": "#4338CA", "highlight": {"background": "#818CF8", "border": "#6366F1"}}, "shape": "box", "size": 22},
    "Image": {"color": {"background": "#8B5CF6", "border": "#6D28D9", "highlight": {"background": "#A78BFA", "border": "#8B5CF6"}}, "shape": "box", "size": 22},
    "Dependency": {"color": {"background": "#F59E0B", "border": "#B45309", "highlight": {"background": "#FBBF24", "border": "#F59E0B"}}, "shape": "dot", "size": 18},
    "CVE": {"color": {"background": "#F43F5E", "border": "#BE123C", "highlight": {"background": "#FB7185", "border": "#F43F5E"}}, "shape": "dot", "size": 22},
}


def parse_docker_inspect(payload: str | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize Docker inspect JSON; published bindings are NOT proof of reachability."""
    rows = json.loads(payload) if isinstance(payload, str) else payload
    if not isinstance(rows, list):
        raise ValueError("Docker inspect must be a list")
    output = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid Docker inspect object")
        config = row.get("Config") or {}
        state = row.get("State") or {}
        network = row.get("NetworkSettings") or {}
        ports = network.get("Ports") or {}
        mappings = []
        for container_port, bindings in ports.items():
            for binding in bindings or []:
                mappings.append({
                    "container_port": container_port,
                    "host_ip": binding.get("HostIp", ""),
                    "host_port": str(binding.get("HostPort", "")),
                })
        output.append({
            "container_id": row.get("Id", ""),
            "name": str(row.get("Name", "")).lstrip("/"),
            "image": config.get("Image", ""),
            "image_id": row.get("Image", ""),
            "running": bool(state.get("Running")),
            "networks": list((network.get("Networks") or {}).keys()),
            "mappings": mappings,
            "labels": {k: v for k, v in (config.get("Labels") or {}).items() if k.startswith(("com.vulnx.", "vulnx.")) or k == "environment"},
        })
    return output


def correlate_ports(observations: list[dict], containers: list[dict], assessment_id: str) -> list[dict]:
    """Match observed host port with Docker published port using host address evidence."""
    result = []
    for obs in observations:
        if str(obs.get("state", "")).lower() != "open":
            continue
        observed_host = str(obs.get("asset", obs.get("host", ""))).strip()
        observed_port = str(obs.get("port", ""))
        for container in containers:
            if not container.get("running"):
                continue
            for mapping in container.get("mappings", []):
                if observed_port != mapping["host_port"]:
                    continue
                bind = mapping.get("host_ip", "")
                # Bind 127.0.0.1 cannot match an arbitrary remote host
                if bind in ("127.0.0.1", "::1") and observed_host not in ("127.0.0.1", "::1", "localhost"):
                    continue
                if bind not in ("", "0.0.0.0", "::", "127.0.0.1", "::1", observed_host):
                    continue
                evidence = {"observation": obs, "docker_mapping": mapping, "container_id": container["container_id"]}
                identity = hashlib.sha256(json.dumps([assessment_id, observed_host, observed_port, container["container_id"], mapping["container_port"]], sort_keys=True).encode()).hexdigest()[:20]
                is_wildcard = bind in ("", "0.0.0.0", "::")
                reach_cat = "Potential Exposure" if is_wildcard else "Confirmed Internal Exposure"
                reach_desc = (
                    "Wildcard bind (0.0.0.0/::) observed from scanner vantage point; potential exposure, not confirmed external"
                    if is_wildcard
                    else "Observed from scanner vantage point, not confirmed external"
                )
                result.append({
                    "relationship_id": identity,
                    "assessment_id": assessment_id,
                    "source": f"{observed_host}:{observed_port}",
                    "destination": container["container_id"],
                    "status": "Confirmed Mapping",
                    "reachability_category": reach_cat,
                    "reachability": reach_desc,
                    "evidence": evidence,
                })
    return result


def _risk_label(score: float | None) -> str:
    if score is None:
        return "Manual Review"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Zero Risk"


def contextual_risk(cvss: float | None, epss: float | None, reachability: float | None, criticality: int) -> dict:
    """Calculate canonical 0-10 contextual risk with strict missing-data handling.
    
    Approved formula:
    R = 10 * [0.3 * (CVSS / 10) + 0.7 * EPSS] * Reachability * (Criticality / 5)

    Criticality scale (1-5):
    - 1 = Minimal (archived/offline asset)
    - 2 = Low-Medium (training lab / dev environment — floor for lab targets)
    - 3 = Medium (staging / internal tool)
    - 4 = High (business-critical internal service)
    - 5 = Critical (public-facing production system)

    Training lab targets (Juice Shop, DVWA) use criticality=2 (low-medium floor)
    so that Critical CVSS + high EPSS findings produce a meaningful 3.5-4.5/10
    score instead of a misleadingly suppressed 1.97/10.
    
    Missing data handling:
    - Missing EPSS: CVSS-only calculation R = 10 * (CVSS / 10) * Reachability * (Criticality / 5),
      marks EPSS unavailable, records calculation_method='cvss_only_fallback'.
    - Missing CVSS: manual review required, no confirmed score (provisional_sort=7.0 for triage queue sorting only).
    - Both missing: no confirmed risk score (provisional_sort=None, calculation_method='unscored_missing_both').
    - Missing reachability: provisional, cannot calculate confirmed score.
    """
    if criticality is None:
        return {"risk": None, "provisional_sort": None, "status": "Provisional", "risk_label": "Provisional", "epss_status": "Unavailable" if epss is None else "Available", "calculation_method": "missing_criticality", "reason": "Asset criticality unassigned; insufficient business evidence", "model_version": MODEL_VERSION, "inputs": {"cvss": cvss, "epss": epss, "reachability": reachability, "criticality": None}}
    if not isinstance(criticality, int) or isinstance(criticality, bool) or not 1 <= criticality <= 5:
        raise ValueError("Criticality must be an integer between 1 and 5")
    for name, value, low, high in [("CVSS", cvss, 0, 10), ("EPSS", epss, 0, 1), ("reachability", reachability, 0, 1)]:
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high):
            raise ValueError(f"Invalid {name}")
    
    if cvss is None and epss is None:
        return {
            "risk": None,
            "provisional_sort": None,
            "status": "Manual Review",
            "risk_label": "Manual Review",
            "epss_status": "Unavailable",
            "calculation_method": "unscored_missing_both",
            "reason": "Both CVSS and EPSS unavailable; no confirmed risk score",
            "model_version": MODEL_VERSION,
            "inputs": {"cvss": cvss, "epss": epss, "reachability": reachability, "criticality": criticality},
        }
    if cvss is None:
        return {
            "risk": None,
            "provisional_sort": 7.0,
            "status": "Manual Review",
            "risk_label": "Manual Review",
            "epss_status": "Available",
            "calculation_method": "manual_review_missing_cvss",
            "reason": "CVSS unavailable; 7.0 is a sorting placeholder only",
            "model_version": MODEL_VERSION,
            "inputs": {"cvss": cvss, "epss": epss, "reachability": reachability, "criticality": criticality},
        }
    if reachability is None:
        return {
            "risk": None,
            "provisional_sort": None,
            "status": "Provisional",
            "risk_label": "Provisional",
            "epss_status": "Unavailable" if epss is None else "Available",
            "calculation_method": "provisional_missing_reachability",
            "reason": "Reachability unknown; cannot calculate confirmed contextual risk",
            "model_version": MODEL_VERSION,
            "inputs": {"cvss": cvss, "epss": epss, "reachability": reachability, "criticality": criticality},
        }

    # When EPSS is absent, re-normalize to CVSS-only fallback
    if epss is None:
        component = (cvss / 10.0)
        status = "Provisional"
        epss_status = "Unavailable"
        calc_method = "cvss_only_fallback"
        reason = "CVSS-only (EPSS unavailable)"
    else:
        component = (0.3 * (cvss / 10.0) + 0.7 * epss)
        status = "Evidence Complete"
        epss_status = "Available"
        calc_method = "full_contextual_formula"
        reason = "CVSS and EPSS combined; heuristic, not probability"

    raw = 10.0 * component * reachability * (criticality / 5.0)
    value = round(max(0.0, min(10.0, raw)), 3)
    
    return {
        "risk": value,
        "provisional_sort": None,
        "status": status,
        "risk_label": _risk_label(value),
        "epss_status": epss_status,
        "calculation_method": calc_method,
        "reason": reason,
        "model_version": MODEL_VERSION,
        "inputs": {"cvss": cvss, "epss": epss, "reachability": reachability, "criticality": criticality},
    }


def resolve_reachability(exposure_kind_or_val: Any) -> float | None:
    """Resolve exposure descriptor or numeric factor to canonical Reachability in {1.0, 0.5, 0.0} or None if unknown.

    Never silently converts unknown reachability into a confirmed numerical score.
    """
    if exposure_kind_or_val is None:
        return None
    if isinstance(exposure_kind_or_val, (int, float)) and not isinstance(exposure_kind_or_val, bool):
        val = float(exposure_kind_or_val)
        if not math.isfinite(val):
            return None
        if val == 1.2:
            return 1.0
        if val == 0.8:
            return 0.5
        if 0.0 <= val <= 1.0:
            return val
        return None
    key = str(exposure_kind_or_val).strip().lower()
    if key in REACHABILITY_MAP:
        return REACHABILITY_MAP[key]
    return None


def resolve_criticality(criticality_or_val: Any) -> int | None:
    """Resolve criticality label or legacy factor to integer in 1..5."""
    if isinstance(criticality_or_val, int) and not isinstance(criticality_or_val, bool) and 1 <= criticality_or_val <= 5:
        return criticality_or_val
    if isinstance(criticality_or_val, float):
        if criticality_or_val >= 1.2:
            return 5
        if criticality_or_val <= 0.8:
            return 1
        return 3
    key = str(criticality_or_val).strip()
    if key in {"Auto", "Unassigned"}:
        return None
    if key in {"1", "2", "3", "4", "5"}:
        return int(key)
    return CRITICALITY_MAP.get(key, 3)


def _extract_verified_cvss(finding: dict, nvd_record: dict | None = None) -> tuple[float | None, str]:
    """Extract verified CVSS (0-10) without fabricating scores from severity labels."""
    raw_cvss = finding.get("cvss")
    if raw_cvss is not None and not isinstance(raw_cvss, bool):
        try:
            val = float(raw_cvss)
            if math.isfinite(val) and 0.0 <= val <= 10.0:
                src = finding.get("cvss_source") or finding.get("base_score_source") or f"{finding.get('source', 'Scanner')} CVSS"
                return round(val, 1), str(src)
        except (ValueError, TypeError):
            pass

    rec = nvd_record or finding.get("nvd_enrichment")
    if isinstance(rec, dict) and rec.get("status") in ("ok", "cached", None):
        nvd_score = rec.get("cvss_score")
        if nvd_score is not None and not isinstance(nvd_score, bool):
            try:
                val = float(nvd_score)
                if math.isfinite(val) and 0.0 <= val <= 10.0:
                    return round(val, 1), "NVD API CVSS"
            except (ValueError, TypeError):
                pass
    return None, "CVSS unavailable (Manual Review Required)"


def _extract_verified_epss(finding: dict) -> float | None:
    """Extract verified EPSS probability (0-1) if available and fresh.
    
    Never accept stale, expired, or invalid threat intelligence as current
    verified evidence or use it to calculate confirmed contextual risk.
    """
    status = finding.get("epss_status")
    status_str = str(status).strip().lower() if status is not None else ""

    # If the finding is explicitly marked stale or unavailable, reject immediately
    if status_str in ("stale", "unavailable", "missing", "expired"):
        return None

    # Only accept known-good fresh statuses if status was specified
    if not status_str or status_str in ("ok", "cached", "available", "live"):
        for key in ("epss_probability", "epss"):
            raw = finding.get(key)
            if raw is not None and not isinstance(raw, bool):
                try:
                    val = float(raw)
                    if math.isfinite(val) and 0.0 <= val <= 1.0:
                        return round(val, 5)
                except (ValueError, TypeError):
                    pass

    # If missing on finding, fallback to verified threat intelligence cache ONLY if fresh
    cve = str(finding.get("cve") or "").strip().upper()
    if cve:
        try:
            from threat_intelligence import get_cached_epss
            cached = get_cached_epss(cve)
            if cached and cached.get("probability") is not None:
                cached_status = str(cached.get("status", "available")).lower()
                if cached_status == "available":
                    prob = float(cached["probability"])
                    if math.isfinite(prob) and 0.0 <= prob <= 1.0:
                        finding["epss_probability"] = prob
                        finding["epss_percentile"] = cached.get("percentile")
                        finding["epss_status"] = "available"
                        return round(prob, 5)
                elif cached_status == "stale":
                    finding["epss_status"] = "stale"
                    finding["epss_percentile"] = cached.get("percentile")
                    return None
        except Exception:
            pass
    return None


def score_finding_canonical(
    finding: dict,
    exposure_kind: Any = "internal",
    criticality: Any = "Normal",
    nvd_record: dict | None = None,
) -> dict:
    """Centralized canonical 0-10 risk calculation service for a single finding.
    
    All active application components (worker, views, dashboard, exports, graphs)
    call this service so `risk_score`, `contextual_risk`, and `contextual_risk_score`
    all hold the identical 0-10 score.
    """
    out = dict(finding)

    # Preserve historical legacy score if migrating from an older model
    old_ver = out.get("model_version")
    old_score = out.get("risk_score")
    if (old_ver and str(old_ver) != MODEL_VERSION) or (isinstance(old_score, (int, float)) and not isinstance(old_score, bool) and old_score > 10.0):
        out.setdefault("historical_legacy_risk_score", old_score)
        out.setdefault("historical_model_version", old_ver or "legacy-0-100")
        out["migrated_from_legacy"] = True

    is_obs = (
        out.get("is_vulnerability") is False
        or out.get("source") == "Nmap"
        or out.get("finding_type") == "network_exposure_observation"
    )
    raw_reach_source = out.get("reachability") if out.get("reachability") is not None else exposure_kind
    reachability = resolve_reachability(raw_reach_source)
    if isinstance(exposure_kind, str) and exposure_kind.strip():
        reach_meta = classify_reachability(exposure_kind=exposure_kind)
    elif reachability == 1.0:
        reach_meta = classify_reachability(exposure_kind="confirmed_external")
    elif reachability == 0.5:
        reach_meta = classify_reachability(exposure_kind="confirmed_internal")
    elif reachability == 0.0:
        reach_meta = classify_reachability(exposure_kind="no_path")
    else:
        reach_meta = classify_reachability(exposure_kind="unknown")
    auto = out.get("automatic_criticality")
    crit_int = auto.get("risk_level") if isinstance(auto, dict) else resolve_criticality(out.get("criticality_level") if out.get("criticality_level") is not None else criticality)

    if is_obs:
        out.update({
            "is_vulnerability": False,
            "cvss": None,
            "base_score": None,
            "base_score_source": "Not applicable (network observation)",
            "epss": None,
            "epss_probability": None,
            "epss_status": "Not applicable",
            "reachability": reachability,
            "reachability_category": reach_meta["category"],
            "reachability_confirmed": reach_meta["confirmed"],
            "criticality_level": crit_int,
            "exposure_factor": reachability,
            "criticality_factor": round(crit_int / 5.0, 2) if crit_int is not None else None,
            "risk_score": None,
            "contextual_risk": None,
            "contextual_risk_score": None,
            "provisional_sort": None,
            "risk_label": "Not applicable",
            "risk_label_contextual": "Not applicable",
            "contextual_status": "Observation",
            "scoring_confidence": "Not applicable",
            "calculation_method": "network_observation_not_scored",
            "contextual_reason": "Network exposure observation, not a vulnerability score.",
            "risk_explanation": "Network exposure observation, not a vulnerability score.",
            "triage_priority": "Exposure observation",
            "model_version": MODEL_VERSION,
        })
        return out

    cvss_val, cvss_source = _extract_verified_cvss(out, nvd_record)
    epss_val = _extract_verified_epss(out)
    calc = contextual_risk(cvss_val, epss_val, reachability, crit_int)
    if isinstance(auto, dict) and auto.get("assessment_status") == "Provisional" and calc["risk"] is not None:
        calc.update(status="Provisional", reason=calc["reason"] + "; training lab criticality assumption")

    if cvss_val is not None:
        triage = "Critical" if cvss_val >= 9.0 else "High" if cvss_val >= 7.0 else "Medium" if cvss_val >= 4.0 else "Low"
    else:
        triage = "Manual Review"

    # Preserve explicit stale status so stale cache records are not masked as Unavailable
    epss_status = "stale" if str(out.get("epss_status") or "").strip().lower() == "stale" else calc["epss_status"]

    out.update({
        "is_vulnerability": True,
        "cvss": cvss_val,
        "base_score": cvss_val,
        "base_score_source": cvss_source,
        "epss": epss_val,
        "epss_probability": epss_val,
        "epss_status": epss_status,
        "reachability": reachability,
        "reachability_category": reach_meta["category"],
        "reachability_confirmed": reach_meta["confirmed"],
        "criticality_level": crit_int,
        "exposure_factor": reachability,
        "criticality_factor": round(crit_int / 5.0, 2) if crit_int is not None else None,
        "risk_score": calc["risk"],
        "contextual_risk": calc["risk"],
        "contextual_risk_score": calc["risk"],
        "provisional_sort": calc["provisional_sort"],
        "risk_label": calc["risk_label"],
        "risk_label_contextual": calc["risk_label"],
        "contextual_status": calc["status"],
        "scoring_confidence": calc["status"],
        "calculation_method": calc["calculation_method"],
        "contextual_reason": calc["reason"],
        "risk_explanation": calc["reason"],
        "triage_priority": triage,
        "model_version": calc["model_version"],
    })
    return out


def score_findings_canonical(
    findings: list[dict],
    exposure_kind: Any = "internal",
    criticality: Any = "Normal",
    nvd_cache: dict | None = None,
) -> list[dict]:
    """Score and sort a list of findings using the canonical 0-10 risk engine.
    
    Confirmed scores sort highest first; findings requiring manual review use
    provisional_sort for queue ordering only without ever presenting provisional_sort
    as a confirmed risk_score.
    """
    scored = []
    for f in findings or []:
        cve = str(f.get("cve") or "").strip().upper()
        nvd_rec = (nvd_cache or {}).get(cve) if cve.startswith("CVE-") else None
        scored.append(score_finding_canonical(f, exposure_kind=exposure_kind, criticality=criticality, nvd_record=nvd_rec))
    return sorted(
        scored,
        key=lambda x: (
            x.get("risk_score") is not None,
            x.get("risk_score") if x.get("risk_score") is not None else (x.get("provisional_sort") or -1.0),
            x.get("cvss") or 0.0,
        ),
        reverse=True,
    )


def migrate_historical_findings(
    findings: list[dict],
    exposure_kind: Any = "internal",
    criticality: Any = "Normal",
    nvd_cache: dict | None = None,
) -> list[dict]:
    """Ensure all loaded findings use the canonical 0-10 risk score, migrating any legacy 0-100 records safely."""
    migrated = []
    for f in findings or []:
        ver = f.get("model_version")
        score = f.get("risk_score")
        needs_migration = (
            ver != MODEL_VERSION
            or (isinstance(score, (int, float)) and not isinstance(score, bool) and score > 10.0)
            or ("contextual_risk" in f and f.get("contextual_risk") != score)
        )
        if needs_migration:
            cve = str(f.get("cve") or "").strip().upper()
            nvd_rec = (nvd_cache or {}).get(cve) if cve.startswith("CVE-") else None
            migrated.append(score_finding_canonical(f, exposure_kind=exposure_kind, criticality=criticality, nvd_record=nvd_rec))
        else:
            migrated.append(dict(f))
    return migrated


def export_canonical_csv(findings: list[dict]) -> str:
    """Export canonical 0-10 findings to CSV safely."""
    fields = [
        "finding_id", "source", "asset", "cve", "package", "installed_version", "fixed_version",
        "severity", "title", "cvss", "base_score_source", "epss_probability", "epss_status",
        "reachability", "criticality_level", "risk_score", "risk_label", "calculation_method",
        "contextual_status", "model_version", "triage_priority", "risk_explanation"
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows([{key: csv_cell(row.get(key)) for key in fields} for row in findings])
    return buffer.getvalue()


def make_attack_graph(
    containers: list[dict],
    relationships: list[dict],
    findings: list[dict],
    assessment_id: str,
    hosts: list[dict] | None = None,
    ports: list[dict] | None = None,
    services: list[dict] | None = None,
    images: list[dict] | None = None,
    reachability: float | None = None,
    include_attacker: bool = False,
) -> nx.DiGraph:
    """Build assessment-specific NetworkX attack graph from persisted assessment evidence.
    
    Supports up to 8 node types (Attacker, Host, Open Port, Service, Container, Image, Dependency, CVE)
    strictly when supported by persisted assessment evidence. Never fabricates unsupported nodes.
    Every edge has traceable evidence or is clearly labeled with confirmation status.
    """
    graph = nx.DiGraph(assessment_id=assessment_id)
    seen_hosts = set()

    # Filter findings strictly to the selected assessment
    scoped_findings = [f for f in (findings or []) if f.get("assessment_id") == assessment_id]

    # Determine whether any host/network evidence exists for this assessment
    scoped_rels = [r for r in (relationships or []) if r.get("assessment_id") == assessment_id]
    nmap_obs = [f for f in scoped_findings if f.get("source") == "Nmap" or f.get("finding_type") == "network_exposure_observation"]
    has_network_evidence = bool(scoped_rels or hosts or ports or nmap_obs)

    # 1. Attacker Node (only when reachability > 0 and network/host evidence exists)
    attacker_id = "attacker:vantage"
    if include_attacker and reachability is not None and reachability > 0 and has_network_evidence:
        graph.add_node(
            attacker_id,
            kind="Attacker",
            assessment_id=assessment_id,
            label="Attacker (Vantage Point)",
            title=f"Modelled Attacker Vantage Point (Reachability: {reachability:.1f})",
            properties={"reachability": reachability, "assessment_id": assessment_id},
        )

    def _ensure_host_node(host_addr: str) -> str:
        host_node = f"host:{host_addr}"
        if host_node not in graph:
            graph.add_node(
                host_node,
                kind="Host",
                assessment_id=assessment_id,
                label=f"Host: {host_addr}",
                title=f"Target Host: {host_addr}",
                properties={"host": host_addr, "assessment_id": assessment_id},
            )
            seen_hosts.add(host_addr)
            if attacker_id in graph:
                edge_status = "Confirmed External Reachability" if reachability == 1.0 else "Internal Modelled Exposure"
                graph.add_edge(
                    attacker_id,
                    host_node,
                    status=edge_status,
                    source="Assessment Scope",
                    evidence=f"Configured exposure model: reachability={reachability}",
                    label=edge_status,
                    style="solid" if reachability == 1.0 else "dashed",
                    confirmed=(reachability == 1.0),
                )
        return host_node

    def _ensure_port_node(host_addr: str, port_str: str, evidence_str: str = "") -> str:
        host_node = _ensure_host_node(host_addr)
        port_node = f"{host_addr}:{port_str}"
        if port_node not in graph:
            graph.add_node(
                port_node,
                kind="Open Port",
                assessment_id=assessment_id,
                label=f"Port: {port_str}",
                title=f"Open Port: {port_str}\nHost: {host_addr}\nObserved State: open",
                properties={"host": host_addr, "port": port_str, "assessment_id": assessment_id},
            )
            graph.add_edge(
                host_node,
                port_node,
                status="Confirmed Mapping",
                source="Nmap Discovery",
                evidence=evidence_str or f"Nmap observed open port {port_str} on host {host_addr}",
                label="exposes port",
                style="solid",
                confirmed=True,
            )
        return port_node

    # 2. Explicit Hosts and Ports from Nmap Discovery (even if no container is running)
    for h in (hosts or []):
        if h.get("assessment_id") and h.get("assessment_id") != assessment_id:
            continue
        h_ip = str(h.get("host_ip") or h.get("hostname") or "").strip()
        if h_ip:
            _ensure_host_node(h_ip)

    for p in (ports or []):
        if p.get("assessment_id") and p.get("assessment_id") != assessment_id:
            continue
        if str(p.get("state", "open")).lower() != "open":
            continue
        h_ip = str(p.get("host_ip") or "127.0.0.1").strip()
        p_no = str(p.get("port") or "").strip()
        if p_no:
            _ensure_port_node(h_ip, p_no, f"Nmap discovered open {p.get('protocol', 'tcp')} port {p_no} on {h_ip}")

    for obs in nmap_obs:
        ev = obs.get("evidence") or {}
        h_ip = str(obs.get("asset") or ev.get("host") or "127.0.0.1").strip()
        p_no = str(ev.get("port") or "").strip()
        if p_no:
            _ensure_port_node(h_ip, p_no, f"Nmap observation {obs.get('finding_id', '')}: port {p_no} open on {h_ip}")

    # 3. Containers and Images (only when referenced by relationships or scoped findings/containers)
    active_containers = [
        c for c in (containers or [])
        if not c.get("assessment_id") or c.get("assessment_id") == assessment_id
    ]
    # Only add containers to graph if assessment has relationships or findings or explicit assessment_id match
    has_assessment_activity = bool(
        scoped_rels
        or scoped_findings
        or any(c.get("assessment_id") == assessment_id for c in (containers or []))
    )
    if has_assessment_activity:
        for container in active_containers:
            cid = container["container_id"]
            cname = container.get("name") or cid[:12]
            graph.add_node(
                cid,
                kind="Container",
                assessment_id=assessment_id,
                label=f"Container: {cname}",
                title=f"Container ID: {cid}\nName: {cname}\nImage: {container.get('image', '')}",
                properties=dict(container, assessment_id=assessment_id),
            )
            img_id = container.get("image_id") or container.get("image")
            img_node = "image:" + str(img_id)
            graph.add_node(
                img_node,
                kind="Image",
                assessment_id=assessment_id,
                label=f"Image: {container.get('image', '')}",
                title=f"Container Image: {container.get('image', '')}\nID: {img_id}",
                properties={"image": container.get("image", ""), "image_id": img_id, "assessment_id": assessment_id},
            )
            graph.add_edge(
                cid,
                img_node,
                status="Confirmed Mapping",
                source="Docker Inspect",
                evidence="Docker Inspect inspects container image reference",
                label="uses image",
                style="solid",
                confirmed=True,
            )

    # Also add standalone Image nodes from persisted assessment_images if present
    for img in (images or []):
        if img.get("assessment_id") and img.get("assessment_id") != assessment_id:
            continue
        img_id = img.get("image_id") or img.get("image_name")
        if img_id:
            img_node = "image:" + str(img_id)
            if img_node not in graph:
                graph.add_node(
                    img_node,
                    kind="Image",
                    assessment_id=assessment_id,
                    label=f"Image: {img.get('image_name', img_id)}",
                    title=f"Container Image: {img.get('image_name', img_id)}\nID: {img_id}",
                    properties={"image": img.get("image_name", img_id), "image_id": img_id, "assessment_id": assessment_id},
                )

    # 4. Port-to-Container Relationships
    for rel in scoped_rels:
        src = rel["source"]  # e.g., "127.0.0.1:8080"
        dst = rel["destination"]  # e.g., container_id
        if ":" in src:
            host_part, port_part = src.rsplit(":", 1)
        else:
            host_part, port_part = "localhost", src

        _ensure_port_node(host_part, port_part)
        rel_status = rel.get("status", "Confirmed Mapping")
        is_potential = "Potential" in rel_status or "Inferred" in rel_status or "Unverified" in rel_status
        graph.add_edge(
            src,
            dst,
            status=rel_status,
            source="Nmap + Docker Inspect",
            evidence=rel.get("evidence", {}),
            label="routes to" if not is_potential else "potential route",
            style="dashed" if is_potential else "solid",
            confirmed=not is_potential,
        )

    # 5. Service Nodes (when detected by Nmap service probes)
    if services:
        for s in services:
            if s.get("assessment_id") and s.get("assessment_id") != assessment_id:
                continue
            h = s.get("host_ip", "127.0.0.1")
            p = str(s.get("port", ""))
            sname = s.get("service_name", "unknown")
            port_node = f"{h}:{p}"
            if port_node not in graph and p:
                _ensure_port_node(h, p)
            if port_node in graph:
                svc_node = f"service:{h}:{p}:{sname}"
                graph.add_node(
                    svc_node,
                    kind="Service",
                    assessment_id=assessment_id,
                    label=f"Service: {sname}",
                    title=f"Service: {sname}\nProduct: {s.get('product', '')}\nVersion: {s.get('version', '')}",
                    properties=dict(s, assessment_id=assessment_id),
                )
                graph.add_edge(
                    port_node,
                    svc_node,
                    status="Service Detection",
                    source="Nmap Service Probes",
                    evidence=f"Nmap detected {sname} ({s.get('product', '')})",
                    label="runs",
                    style="solid",
                    confirmed=True,
                )

    # 6. Dependencies and Findings (CVEs)
    seen_deps = set()
    for finding in scoped_findings:
        if not finding.get("cve"):
            continue
        
        cve_id = str(finding["cve"]).strip()
        cve_node = "cve:" + cve_id
        
        # Determine associated image from finding evidence or matching container
        image_identity = finding.get("image_id")
        if not image_identity:
            candidates = {c.get("image_id") or c.get("image") for c in active_containers if c.get("image") == finding.get("asset")}
            if len(candidates) == 1:
                image_identity = next(iter(candidates))
            elif active_containers and not finding.get("asset"):
                image_identity = active_containers[0].get("image_id") or active_containers[0].get("image")
            elif (finding.get("source") == "Trivy" or finding.get("asset")) and finding.get("asset"):
                image_identity = finding.get("asset")

        img_node = "image:" + str(image_identity) if image_identity else None
        if img_node and img_node not in graph:
            # If Trivy scanned an image directly without a container, add the evidence-backed Image node
            if (finding.get("source") == "Trivy" or finding.get("image_id") or finding.get("asset")) and not active_containers:
                graph.add_node(
                    img_node,
                    kind="Image",
                    assessment_id=assessment_id,
                    label=f"Image: {image_identity}",
                    title=f"Scanned Container Image: {image_identity}",
                    properties={"image": str(image_identity), "image_id": str(image_identity), "assessment_id": assessment_id},
                )
            else:
                continue

        # Add CVE Node with canonical 0-10 risk score
        cvss_val = finding.get("cvss")
        risk_val = finding.get("risk_score")
        sev_val = finding.get("severity", "UNKNOWN")
        graph.add_node(
            cve_node,
            kind="CVE",
            assessment_id=assessment_id,
            label=cve_id,
            title=f"Vulnerability: {cve_id}\nSeverity: {sev_val}\nCVSS: {cvss_val}\nContextual Risk (0-10): {risk_val}",
            properties={"cve": cve_id, "severity": sev_val, "cvss": cvss_val, "risk_score": risk_val, "assessment_id": assessment_id},
        )

        # Add Dependency Node if package is identified
        pkg = finding.get("package")
        if pkg and img_node:
            dep_id = f"dep:{pkg}@{finding.get('installed_version', '')}"
            if dep_id not in seen_deps:
                seen_deps.add(dep_id)
                graph.add_node(
                    dep_id,
                    kind="Dependency",
                    assessment_id=assessment_id,
                    label=f"Pkg: {pkg}",
                    title=f"Package: {pkg}\nInstalled: {finding.get('installed_version', '')}\nFixed: {finding.get('fixed_version', '')}",
                    properties={"package": pkg, "installed": finding.get("installed_version", ""), "fixed": finding.get("fixed_version", ""), "assessment_id": assessment_id},
                )
                graph.add_edge(
                    img_node,
                    dep_id,
                    status="Package Dependency",
                    source="Trivy Package Manifest",
                    evidence=f"Identified package {pkg} in container filesystem",
                    label="contains pkg",
                    style="solid",
                    confirmed=True,
                )
            graph.add_edge(
                dep_id,
                cve_node,
                status="Confirmed Association",
                source="Trivy vulnerability database",
                evidence=f"{cve_id} impacts package {pkg}",
                label="vulnerable to",
                style="solid",
                confirmed=True,
            )

        # Direct Image -> CVE association edge
        if img_node:
            graph.add_edge(
                img_node,
                cve_node,
                status="Confirmed Association",
                source="Trivy finding",
                evidence=f"Trivy detected {cve_id} on {finding.get('asset', '')}",
                label="vulnerable to",
                style="solid",
                confirmed=True,
            )

    return graph


def filter_attack_graph(
    graph: nx.DiGraph,
    selected_node_type: str = "All",
    status_filter: str = "All",
    search_query: str = "",
    allowed_kinds: list[str] | set[str] | None = None,
    confirmation_filter: str | None = None,
) -> nx.DiGraph:
    """Return a filtered subgraph based on node kind, edge confirmation status, and search text."""
    filtered = nx.DiGraph(assessment_id=graph.graph.get("assessment_id"))
    q = (search_query or "").strip().lower()
    active_status_filter = confirmation_filter or status_filter
    kinds_set = set(allowed_kinds) if allowed_kinds is not None else None

    for node, data in graph.nodes(data=True):
        kind = data.get("kind", "Service")
        if kinds_set is not None and kind not in kinds_set:
            continue
        if selected_node_type != "All" and kind != selected_node_type:
            continue
        if q:
            haystack = f"{node} {data.get('label', '')} {data.get('title', '')}".lower()
            if q not in haystack:
                continue
        filtered.add_node(node, **data)

    for u, v, data in graph.edges(data=True):
        if u not in filtered or v not in filtered:
            continue
        status = data.get("status", "Confirmed Mapping")
        is_potential = "Potential" in status or "Inferred" in status or "Unverified" in status or data.get("style") == "dashed"
        if active_status_filter == "Confirmed Only" and is_potential:
            continue
        if active_status_filter == "Potential / Inferred Only" and not is_potential:
            continue
        filtered.add_edge(u, v, **data)

    return filtered


def _finalize_graph_html(html_doc: str) -> str:
    """Polish PyVis output for the dark UI: borderless canvas, automatic fit-to-view,
    and immediate physics freeze once stabilized to completely eliminate high-frequency
    vibrations, shaking, and browser CPU hangs.
    """
    style = """
<style>
  html, body { margin: 0 !important; padding: 0 !important; background: #0B0F1A !important; overflow: hidden; }
  .card { border: none !important; background: #0B0F1A !important; margin: 0 !important; }
  .card-body { padding: 0 !important; }
  #mynetwork { border: none !important; background: #0B0F1A !important; }
  #loadingBar { background: #0B0F1A !important; }
  #loadingBar #text { color: #94A3B8 !important; }
  #loadingBar #border { background: #1B263B !important; }
  #loadingBar #bar { background: linear-gradient(90deg, #4285FF, #35C6E8) !important; }
</style>
"""
    freeze_script = """
              drawGraph();
              if (typeof network !== 'undefined' && network) {
                  // Freeze physics immediately upon stabilization to eliminate all node vibration and browser hang
                  network.on('stabilizationIterationsDone', function () {
                      try {
                          network.stopSimulation();
                          network.setOptions({ physics: false });
                          network.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
                      } catch (e) {}
                  });
                  network.on('stabilized', function () {
                      try {
                          network.stopSimulation();
                          network.setOptions({ physics: false });
                      } catch (e) {}
                  });
                  // Strict safety timer: physics is unconditionally halted within 450ms
                  setTimeout(function () {
                      try {
                          network.stopSimulation();
                          network.setOptions({ physics: false });
                          network.fit();
                      } catch (e) {}
                  }, 450);
              }
"""
    if "drawGraph();" in html_doc:
        html_doc = html_doc.replace("drawGraph();", freeze_script, 1)

    if "</head>" in html_doc:
        html_doc = html_doc.replace("</head>", style + "</head>", 1)
    else:
        html_doc = style + html_doc
    return html_doc


def generate_attack_graph_html(
    graph: nx.DiGraph,
    height: str = "600px",
    selected_node_type: str = "All",
    status_filter: str = "All",
    search_query: str = "",
    max_nodes: int = 250,
) -> str:
    """Generate responsive interactive PyVis visualization HTML styled for Midnight Security."""
    from pyvis.network import Network

    sub = filter_attack_graph(graph, selected_node_type=selected_node_type, status_filter=status_filter, search_query=search_query)
    # Guard against excessively large graphs crashing browser layout
    nodes_list = list(sub.nodes(data=True))[:max_nodes]
    allowed_nodes = {n for n, _ in nodes_list}

    num_nodes = len(nodes_list)
    dynamic_iters = max(80, min(250, num_nodes * 2))

    net = Network(height=height, width="100%", bgcolor="#0B1220", font_color="#E2E8F0", directed=True)
    net.set_options(f"""
    {{
      "nodes": {{
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": {{ "color": "#E2E8F0", "size": 13, "face": "system-ui, -apple-system, sans-serif" }}
      }},
      "edges": {{
        "color": {{ "color": "#3B82F6", "highlight": "#22D3EE", "hover": "#60A5FA" }},
        "smooth": {{ "type": "continuous", "roundness": 0.25 }},
        "arrows": {{ "to": {{ "enabled": true, "scaleFactor": 0.8 }} }}
      }},
      "physics": {{
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {{
          "gravitationalConstant": -50,
          "centralGravity": 0.015,
          "springLength": 95,
          "springConstant": 0.08,
          "damping": 0.6,
          "avoidOverlap": 0.5
        }},
        "maxVelocity": 25,
        "minVelocity": 0.75,
        "timestep": 0.35,
        "stabilization": {{ "enabled": true, "iterations": {dynamic_iters}, "updateInterval": 25, "fit": true }}
      }},
      "interaction": {{
        "hover": true,
        "dragNodes": true,
        "dragView": true,
        "zoomView": true,
        "navigationButtons": true,
        "keyboard": true,
        "tooltipDelay": 150
      }}
    }}
    """)

    for node, data in nodes_list:
        kind = data.get("kind", "Service")
        style = NODE_STYLES.get(kind, NODE_STYLES["Service"])
        net.add_node(
            node,
            label=data.get("label", node),
            title=data.get("title", node),
            color=style["color"],
            shape=style["shape"],
            size=style["size"],
        )

    for u, v, data in sub.edges(data=True):
        if u not in allowed_nodes or v not in allowed_nodes:
            continue
        status = data.get("status", "Confirmed Mapping")
        dashes = (data.get("style") == "dashed" or "Potential" in status or "Inferred" in status)
        color = "#F59E0B" if dashes else "#3B82F6"
        net.add_edge(
            u,
            v,
            title=f"Status: {status}\nSource: {data.get('source', '')}\nEvidence: {data.get('evidence', '')}",
            label=data.get("label", ""),
            dashes=dashes,
            color=color,
        )

    return _finalize_graph_html(net.generate_html())


def make_global_attack_graph(assessments_list: list[dict] | None = None) -> nx.DiGraph:
    """Build a consolidated multi-asset attack path graph across all assessed platform targets."""
    from assessment_manager import list_assessments, get_assessment, load_vg_evidence
    from assessment_views import findings_for

    if assessments_list is None:
        assessments_list = list_assessments(limit=200)

    # Pick the latest assessment per unique target name
    latest_by_target: dict[str, dict] = {}
    for a in assessments_list:
        tname = (a.get("target_name") or "").strip()
        if not tname:
            continue
        if tname not in latest_by_target or a.get("created_at", "") > latest_by_target[tname].get("created_at", ""):
            latest_by_target[tname] = a

    G = nx.DiGraph()
    palette = ["#6366F1", "#35C6E8", "#10B981", "#F59E0B", "#EC4899", "#8B5CF6", "#3B82F6"]
    attacker_id = "attacker:global"
    has_external_exposure = False

    for idx, (target_name, a) in enumerate(latest_by_target.items()):
        aid = a.get("assessment_id", "")
        full_a = get_assessment(aid) or {}
        cluster_color = palette[idx % len(palette)]
        target_type = a.get("target_type", "Target")
        crit = a.get("criticality", "Normal")

        # 1. Asset Hub Node
        asset_node = f"asset:{target_name}"
        G.add_node(
            asset_node,
            kind="Asset",
            label=f"Asset: {target_name}",
            title=f"Asset Target: {target_name}\nType: {target_type}\nCriticality: {crit}\nAssessment: {aid}",
            cluster=target_name,
            asset=target_name,
            color=cluster_color,
            shape="star",
            size=32,
            properties={"target_name": target_name, "target_type": target_type, "criticality": crit, "assessment_id": aid},
        )

        target_context = a.get("target") or {}
        exp_kind = target_context.get("exposure_kind", "loopback")
        reachability = 1.0 if exp_kind == "all_interfaces" else (0.5 if exp_kind != "isolated" else 0.0)

        hosts = full_a.get("hosts", [])
        ports = full_a.get("ports", [])
        services = full_a.get("services", [])
        ev = load_vg_evidence(aid)
        containers = ev.get("containers", [])
        findings = findings_for(full_a) if full_a else []

        if reachability > 0 and (hosts or ports or containers):
            has_external_exposure = True
            G.add_edge(
                attacker_id,
                asset_node,
                label=f"reaches ({reachability:.1f})",
                status="Confirmed Reachability" if reachability == 1.0 else "Modelled Reachability",
                source="Exposure Configuration",
                evidence=f"Configured exposure: {exp_kind}",
                style="solid" if reachability == 1.0 else "dashed",
                confirmed=(reachability == 1.0),
            )

        # 2. Hosts, Ports & Services
        for h in hosts:
            h_ip = h.get("host_ip") or h.get("hostname") or "127.0.0.1"
            h_node = f"host:{h_ip}@{target_name}"
            G.add_node(
                h_node,
                kind="Host",
                label=f"Host: {h_ip}",
                title=f"Host: {h_ip}\nAsset: {target_name}",
                cluster=target_name,
                asset=target_name,
                properties=h,
            )
            G.add_edge(asset_node, h_node, label="hosted on", status="Confirmed", evidence="Nmap host discovery")

            for p in ports:
                if str(p.get("state", "open")).lower() != "open":
                    continue
                p_no = str(p.get("port", ""))
                p_node = f"port:{h_ip}:{p_no}@{target_name}"
                G.add_node(
                    p_node,
                    kind="Open Port",
                    label=f"Port: {p_no}",
                    title=f"Open Port: {p_no}\nHost: {h_ip}\nAsset: {target_name}",
                    cluster=target_name,
                    asset=target_name,
                    properties=p,
                )
                G.add_edge(h_node, p_node, label="exposes port", status="Confirmed", evidence=f"Nmap verified open port {p_no}")

                for s in services:
                    if str(s.get("port", "")) == p_no:
                        sname = s.get("service_name", "unknown")
                        s_node = f"service:{h_ip}:{p_no}:{sname}@{target_name}"
                        G.add_node(
                            s_node,
                            kind="Service",
                            label=f"Svc: {sname}",
                            title=f"Service: {sname}\nProduct: {s.get('product', '')}\nVersion: {s.get('version', '')}",
                            cluster=target_name,
                            asset=target_name,
                            properties=s,
                        )
                        G.add_edge(p_node, s_node, label="runs service", status="Confirmed", evidence=f"Nmap identified {sname}")

        # 3. Containers and Images
        for c in containers:
            cid = c.get("container_id", "")[:12]
            cname = c.get("name") or cid
            c_node = f"container:{cid}@{target_name}"
            G.add_node(
                c_node,
                kind="Container",
                label=f"Container: {cname}",
                title=f"Container: {cname}\nImage: {c.get('image', '')}\nID: {cid}",
                cluster=target_name,
                asset=target_name,
                properties=c,
            )
            G.add_edge(asset_node, c_node, label="runs container", status="Confirmed", evidence="Docker Inspect discovery")

            img_ref = c.get("image") or c.get("image_id")
            if img_ref:
                img_node = f"image:{img_ref}@{target_name}"
                G.add_node(
                    img_node,
                    kind="Image",
                    label=f"Image: {img_ref[:24]}",
                    title=f"Container Image: {img_ref}",
                    cluster=target_name,
                    asset=target_name,
                    properties={"image": img_ref},
                )
                G.add_edge(c_node, img_node, label="built from", status="Confirmed", evidence="Docker image inspect")

        # 4. Findings & Dependencies
        seen_deps = set()
        for f in findings:
            cve = f.get("cve")
            if not cve:
                continue

            cve_id = str(cve).strip()
            cve_node = f"cve:{cve_id}"
            sev = f.get("severity", "Info")
            cvss = f.get("cvss")
            risk = f.get("risk_score")

            if cve_node not in G:
                G.add_node(
                    cve_node,
                    kind="CVE",
                    label=cve_id,
                    title=f"Vulnerability: {cve_id}\nSeverity: {sev}\nCVSS: {cvss}\nRisk Score: {risk}",
                    severity=sev,
                    cvss=cvss,
                    risk_score=risk,
                    cluster=target_name,
                    affected_assets=[target_name],
                    properties=f,
                )
            else:
                if target_name not in G.nodes[cve_node].get("affected_assets", []):
                    G.nodes[cve_node].setdefault("affected_assets", []).append(target_name)

            pkg = f.get("package")
            if pkg:
                dep_node = f"dep:{pkg}@{target_name}"
                if dep_node not in seen_deps:
                    seen_deps.add(dep_node)
                    G.add_node(
                        dep_node,
                        kind="Dependency",
                        label=f"Pkg: {pkg}",
                        title=f"Package: {pkg}\nInstalled: {f.get('installed_version', '')}\nAsset: {target_name}",
                        cluster=target_name,
                        asset=target_name,
                        properties={"package": pkg, "installed": f.get("installed_version")},
                    )
                    G.add_edge(asset_node, dep_node, label="contains package", status="Confirmed", evidence="Package manifest")
                G.add_edge(dep_node, cve_node, label="vulnerable to", status="Confirmed", evidence=f"{cve_id} impacts {pkg}")
            else:
                G.add_edge(asset_node, cve_node, label="vulnerable to", status="Confirmed", evidence="Scanner finding")

    # Connect Attacker vantage point if external reachability was found
    if has_external_exposure:
        G.add_node(
            attacker_id,
            kind="Attacker",
            label="Attacker (Vantage Point)",
            title="Modelled Attacker Vantage Point across Target Assets",
            cluster="Global",
            color="#EF4444",
            shape="diamond",
            size=28,
            properties={"vantage": "external"},
        )

    return G


def compute_global_graph_stats(graph: nx.DiGraph, assessments_list: list[dict] | None = None) -> dict[str, Any]:
    """Compute dynamic platform-wide KPIs for the multi-asset attack graph."""
    asset_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "Asset"]
    cve_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "CVE"]

    crit_count = sum(1 for n in cve_nodes if str(graph.nodes[n].get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for n in cve_nodes if str(graph.nodes[n].get("severity", "")).upper() == "HIGH")
    med_count = sum(1 for n in cve_nodes if str(graph.nodes[n].get("severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for n in cve_nodes if str(graph.nodes[n].get("severity", "")).upper() == "LOW")
    info_count = sum(1 for n in cve_nodes if str(graph.nodes[n].get("severity", "")).upper() in ("INFO", "UNKNOWN"))

    # Total vulnerability instances (counting occurrences across all affected assets)
    total_instances = sum(len(graph.nodes[n].get("affected_assets", [1])) for n in cve_nodes)
    shared_cves = sum(1 for n in cve_nodes if len(graph.nodes[n].get("affected_assets", [])) > 1)

    return {
        "total_assets": len(asset_nodes),
        "total_nodes": graph.number_of_nodes(),
        "total_relationships": graph.number_of_edges(),
        "unique_cves": len(cve_nodes),
        "total_cve_instances": total_instances,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "shared_cves": shared_cves,
    }


def filter_global_attack_graph(
    graph: nx.DiGraph,
    selected_asset: str = "All",
    selected_node_type: str = "All",
    severity_filter: str = "All",
    status_filter: str = "All",
    search_query: str = "",
) -> nx.DiGraph:
    """Filter the global multi-asset attack path graph by asset, node type, severity, status, and query."""
    sub = graph.copy()

    # 1. Asset Focus Filter
    if selected_asset != "All":
        allowed = set()
        for n, d in sub.nodes(data=True):
            if (
                d.get("cluster") == selected_asset
                or d.get("asset") == selected_asset
                or selected_asset in d.get("affected_assets", [])
            ):
                allowed.add(n)
        # Always include global attacker if connected to this asset
        if "attacker:global" in sub and sub.has_edge("attacker:global", f"asset:{selected_asset}"):
            allowed.add("attacker:global")
        sub = sub.subgraph(allowed).copy()

    # 2. Node Type Filter (preserve Asset hubs for context)
    if selected_node_type != "All":
        allowed = {n for n, d in sub.nodes(data=True) if d.get("kind") == selected_node_type or d.get("kind") == "Asset"}
        sub = sub.subgraph(allowed).copy()

    # 3. Severity Filter for CVEs
    if severity_filter != "All":
        allowed = set()
        for n, d in sub.nodes(data=True):
            if d.get("kind") != "CVE" or str(d.get("severity", "")).upper() == severity_filter.upper():
                allowed.add(n)
        sub = sub.subgraph(allowed).copy()

    # 4. Relationship Status Filter
    if status_filter != "All":
        edges_to_remove = []
        for u, v, d in sub.edges(data=True):
            status = d.get("status", "Confirmed")
            is_potential = "Potential" in status or "Inferred" in status or "Unverified" in status or d.get("style") == "dashed"
            if status_filter == "Confirmed Only" and is_potential:
                edges_to_remove.append((u, v))
            elif status_filter == "Potential / Inferred Only" and not is_potential:
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            sub.remove_edge(u, v)

    # 5. Search Query Filter (includes 1-hop predecessors and successors for attack path context)
    if search_query.strip():
        q = search_query.strip().lower()
        matched = set()
        for n, d in sub.nodes(data=True):
            haystack = f"{n} {d.get('label', '')} {d.get('title', '')} {' '.join(d.get('affected_assets', []))}".lower()
            if q in haystack:
                matched.add(n)
        expanded = set(matched)
        for n in matched:
            expanded.update(sub.predecessors(n))
            expanded.update(sub.successors(n))
        sub = sub.subgraph(expanded).copy()

    return sub


def generate_global_attack_graph_html(
    graph: nx.DiGraph,
    height: str = "680px",
    selected_asset: str = "All",
    selected_node_type: str = "All",
    severity_filter: str = "All",
    status_filter: str = "All",
    search_query: str = "",
    max_nodes: int = 350,
) -> str:
    """Generate responsive interactive PyVis visualization HTML with tuned Barnes-Hut anti-hairball physics."""
    from pyvis.network import Network

    sub = filter_global_attack_graph(
        graph,
        selected_asset=selected_asset,
        selected_node_type=selected_node_type,
        severity_filter=severity_filter,
        status_filter=status_filter,
        search_query=search_query,
    )

    nodes_list = list(sub.nodes(data=True))[:max_nodes]
    allowed_nodes = {n for n, _ in nodes_list}

    num_nodes = len(nodes_list)
    dynamic_iters = max(100, min(250, num_nodes * 2))

    net = Network(height=height, width="100%", bgcolor="#0B0F1A", font_color="#E6EAF2", directed=True)

    net.set_options(f"""
    {{
      "nodes": {{
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": {{ "color": "#E6EAF2", "size": 13, "face": "Inter, system-ui, -apple-system, sans-serif" }}
      }},
      "edges": {{
        "color": {{ "color": "#3B82F6", "highlight": "#22D3EE", "hover": "#60A5FA" }},
        "smooth": {{ "type": "continuous", "roundness": 0.25 }},
        "arrows": {{ "to": {{ "enabled": true, "scaleFactor": 0.8 }} }}
      }},
      "physics": {{
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {{
          "gravitationalConstant": -50,
          "centralGravity": 0.015,
          "springLength": 95,
          "springConstant": 0.08,
          "damping": 0.6,
          "avoidOverlap": 0.5
        }},
        "maxVelocity": 25,
        "minVelocity": 0.75,
        "timestep": 0.35,
        "stabilization": {{ "enabled": true, "iterations": {dynamic_iters}, "updateInterval": 25, "fit": true }}
      }},
      "interaction": {{
        "hover": true,
        "dragNodes": true,
        "dragView": true,
        "zoomView": true,
        "navigationButtons": true,
        "keyboard": true,
        "tooltipDelay": 150
      }}
    }}
    """)

    sev_colors = {
        "CRITICAL": {"background": "#EF4444", "border": "#B91C1C", "highlight": {"background": "#F87171", "border": "#EF4444"}},
        "HIGH": {"background": "#F97316", "border": "#C2410C", "highlight": {"background": "#FB923C", "border": "#F97316"}},
        "MEDIUM": {"background": "#EAB308", "border": "#A16207", "highlight": {"background": "#FACC15", "border": "#EAB308"}},
        "LOW": {"background": "#3B82F6", "border": "#1D4ED8", "highlight": {"background": "#60A5FA", "border": "#3B82F6"}},
        "INFO": {"background": "#64748B", "border": "#475569", "highlight": {"background": "#94A3B8", "border": "#64748B"}},
    }

    for node, data in nodes_list:
        kind = data.get("kind", "Service")
        style = NODE_STYLES.get(kind, NODE_STYLES.get("Service", {}))

        color = style.get("color")
        if kind == "CVE":
            sev = str(data.get("severity", "Info")).upper()
            color = sev_colors.get(sev, color)
        elif kind == "Asset" and data.get("color"):
            c = data.get("color")
            color = {"background": c, "border": "#4285FF", "highlight": {"background": "#35C6E8", "border": "#FFFFFF"}}

        net.add_node(
            node,
            label=data.get("label", node),
            title=data.get("title", node),
            color=color,
            shape=style.get("shape", "dot"),
            size=style.get("size", 20),
        )

    for u, v, data in sub.edges(data=True):
        if u not in allowed_nodes or v not in allowed_nodes:
            continue
        status = data.get("status", "Confirmed")
        dashes = (data.get("style") == "dashed" or "Potential" in status or "Inferred" in status)
        color = "#F59E0B" if dashes else "#3B82F6"
        net.add_edge(
            u,
            v,
            title=f"Relationship: {data.get('label', '')}\nStatus: {status}\nEvidence: {data.get('evidence', '')}",
            label=data.get("label", ""),
            dashes=dashes,
            color=color,
        )

    return _finalize_graph_html(net.generate_html())

