"""Detached assessment worker for VulnX: Scanning and Vulnerability Management Platform.

Orchestrates:
1. Target validation and safety checks (authorized local lab targets only)
2. Safe subprocess scanner execution (Nmap, Docker Inspect, Trivy, OWASP ZAP)
3. Asset entity extraction (Hosts, Ports, Services, Containers, Images, Dependencies)
4. Finding normalization and threat intelligence enrichment (NVD CVSS, FIRST EPSS)
5. Evidence-based OWASP Top 10:2025 classification
6. Centralized 0-10 contextual risk prioritization with calculation audit persistence
7. NetworkX attack graph evidence mapping and relational persistence
"""
from __future__ import annotations
import json, sys, os, shutil, subprocess
from pathlib import Path
from urllib.parse import urlparse
from config import load_environment
load_environment()

from assessment_manager import (
    BASE_DIR, REPORT_DIR, get_assessment, update_assessment,
    update_scanner, save_findings, replace_source_findings,
    get_nvd_cache_sqlite, put_nvd_cache_sqlite, save_discovered_assets,
    save_risk_calculations, save_vg_evidence, record_worker_heartbeat,
)
from trivy_scanner import run_trivy_image_scan
from asset_discovery import scan_target
from zap_scanner import run_zap_baseline_scan
from finding_normalization import normalize_trivy_report, normalize_nmap_result, normalize_zap_report
from nvd_enrichment import fetch_nvd_cve
from core.nvd_queue import enqueue_cve_ids, ensure_background_enricher_running
from finding_correlation import correlate_findings
from threat_intelligence import enrich_findings
from vulngraph_core import (
    contextual_risk, correlate_ports, parse_docker_inspect,
    score_finding_canonical, resolve_reachability, resolve_criticality,
)
from owasp_classifier import classify
from audit_log import log_event


# Read optional local .env without adding a runtime dependency.
def _load_env_file():
    env_path = BASE_DIR / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

_load_env_file()

ZAP_APPS = {"3000/tcp": "OWASP Juice Shop", "80/tcp": "DVWA", "8080/tcp": "DVWA"}


def scanner_timeout(name, default, minimum, maximum):
    raw = os.getenv(f"VULNX_{name}_TIMEOUT") or os.getenv(f"VULNGRAPH_{name}_TIMEOUT") or str(default)
    try:
        seconds = int(raw)
    except (ValueError, TypeError):
        return default
    return seconds if minimum <= seconds <= maximum else default


def record_scanner_failure(assessment_id, scanner, exc):
    message = str(exc).strip() or type(exc).__name__
    update_scanner(
        assessment_id, scanner, "Failed", message[:700],
        {"error_type": type(exc).__name__, "error": message[:700]}
    )
    try:
        log_event(
            "system", "System", "assessment_scanner_failed", "assessment", assessment_id,
            {"scanner": scanner, "error_type": type(exc).__name__}
        )
    except Exception:
        pass


def _risk(f, exposure_factor, criticality_factor, nvd_cache):
    """Canonical 0-10 risk calculation wrapper for worker pipeline."""
    record = (nvd_cache or {}).get(f.get("cve")) if f.get("cve") else None
    return score_finding_canonical(
        f,
        exposure_kind=exposure_factor,
        criticality=criticality_factor,
        nvd_record=record,
    )


def _read_docker_container(container_id):
    import shutil, subprocess
    if not shutil.which("docker"):
        raise RuntimeError("Docker CLI is unavailable; cannot inspect the selected container.")
    from docker_lab import list_containers
    running = [item for item in list_containers() if str(item.get("state", "")).lower() == "running"]
    match = next(
        (item for item in running if str(item.get("id", "")).startswith(str(container_id))
         and any(token in (str(item.get("name", "")).lower() + " " + str(item.get("image", "")).lower())
                 for token in ("juice-shop", "dvwa"))),
        None
    )
    if not match:
        raise RuntimeError("Selected container is no longer running or is outside the configured Juice Shop/DVWA allowlist.")
    result = subprocess.run([shutil.which("docker"), "inspect", container_id], capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or "Docker inspect failed")[:400])
    raw_output = result.stdout or ""
    if not raw_output.strip():
        detail = (result.stderr or "Docker inspect returned empty output.").strip()
        raise RuntimeError(f"Could not read Docker container metadata: {detail[:300]}")
    parsed = json.loads(raw_output)
    if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
        raise RuntimeError("Docker inspect returned an unexpected JSON structure.")
    data = parsed[0]
    ports = data.get("NetworkSettings", {}).get("Ports", {}) or {}
    published = []
    for container_port, bindings in ports.items():
        for binding in bindings or []:
            host_ip = binding.get("HostIp") or ""
            host_port = int(binding.get("HostPort"))
            if host_ip in {"127.0.0.1", "0.0.0.0", "::", "::1", ""}:
                published.append({"container_port": container_port, "host_ip": host_ip, "host_port": host_port})
    return {
        "image": data.get("Config", {}).get("Image") or data.get("Image"),
        "published": published,
        "state": data.get("State", {}).get("Status", "unknown"),
        "raw_data": data,
    }


def run(assessment_id):
    assessment = get_assessment(assessment_id)
    if not assessment:
        return
    if assessment.get("stage") == "Cancelled by operator":
        return
    target = assessment["target"]
    update_assessment(assessment_id, "Running", worker_pid=os.getpid(), heartbeat=True)
    scan_output_dir = REPORT_DIR / assessment_id
    scan_output_dir.mkdir(parents=True, exist_ok=True)

    vg_containers = list(assessment.get("containers", []))
    vg_observations = [
        {"asset": p.get("host_ip", "127.0.0.1"), "port": int(p.get("port", 0)), "state": p.get("state", "open")}
        for p in assessment.get("ports", [])
        if p.get("port")
    ]
    discovered_hosts = list(assessment.get("hosts", []))
    discovered_ports = list(assessment.get("ports", []))
    discovered_services = list(assessment.get("services", []))
    discovered_images = list(assessment.get("images", []))
    discovered_dependencies = list(assessment.get("dependencies", []))
    risk_calculations = []

    previous_findings = list(assessment.get("findings", []))
    retried_sources = set()

    try:
        update_assessment(assessment_id, "Discovering assets", stage="Automatic asset discovery", heartbeat=True)
        image = target.get("image", "")
        host = target.get("nmap_host", "")
        ports = target.get("ports", "")
        zap_app = target.get("zap_app", "")
        exposure_kind = target.get("exposure_kind", "unknown")

        if target.get("container_id"):
            details = _read_docker_container(target["container_id"])
            import shutil
            inspect_run = subprocess.run([shutil.which('docker') or 'docker', 'inspect', target['container_id']], capture_output=True, text=True, timeout=15, check=False)
            if inspect_run.returncode == 0:
                vg_containers = parse_docker_inspect(inspect_run.stdout)
            image = details.get("image") or image
            for binding in details["published"]:
                host = "127.0.0.1"
                ports = str(binding["host_port"])
                exposure_kind = "potential_exposure" if binding["host_ip"] in {"0.0.0.0", "::", ""} else "loopback"
                app_name = ZAP_APPS.get(binding["container_port"])
                if app_name:
                    zap_app = app_name
                    target["zap_target_url"] = f"http://host.docker.internal:{binding['host_port']}/"
                if not target.get("nmap_host"):
                    target["nmap_host"] = "127.0.0.1"
                    target["ports"] = str(binding["host_port"])
        elif assessment.get("target_type") == "Running lab container" and image:
            try:
                import shutil
                if shutil.which("docker"):
                    ps_run = subprocess.run(
                        [shutil.which("docker"), "ps", "--filter", f"ancestor={image}", "--format", "{{.ID}}"],
                        capture_output=True, text=True, timeout=8, check=False,
                    )
                    if ps_run.returncode == 0 and ps_run.stdout.strip():
                        cid = ps_run.stdout.strip().splitlines()[0].strip()
                        insp = subprocess.run(
                            [shutil.which("docker"), "inspect", cid],
                            capture_output=True, text=True, timeout=10, check=False,
                        )
                        if insp.returncode == 0 and insp.stdout.strip():
                            vg_containers = parse_docker_inspect(insp.stdout)
            except Exception:
                pass

        if host and host != "host.docker.internal":
            from assessment_portal import validate_host
            host = validate_host(host)
        if host and ports:
            from asset_discovery import _validate_ports
            ports = _validate_ports(ports)
        if (os.getenv("VULNX_DOCKERIZED") or os.getenv("VULNGRAPH_DOCKERIZED", "0")).strip() == "1" and host in {"127.0.0.1", "localhost"}:
            host = "host.docker.internal"

        # Map reachability and business criticality for unified risk engine
        reachability = resolve_reachability(exposure_kind)
        crit_str = assessment.get("criticality", "Normal")
        auto = None
        if crit_str == "Auto" or target.get("automatic_criticality"):
            from asset_criticality_engine import automatic_assessment
            metadata = list(vg_containers)
            if image and not metadata and not target.get("imported_trivy_report_path"):
                try:
                    import shutil
                    docker = shutil.which("docker")
                    if docker:
                        inspected = subprocess.run([docker, "image", "inspect", "--", image], capture_output=True, text=True, timeout=10, check=False)
                        if inspected.returncode == 0:
                            metadata = parse_docker_inspect(inspected.stdout)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            auto = automatic_assessment(target, metadata)
            target["automatic_criticality"] = auto
            crit_str = str(auto["risk_level"]) if auto["risk_level"] is not None else "Unassigned"
            from assessment_manager import _db
            with _db() as con:
                con.execute("UPDATE assessments SET criticality=?, target_json=? WHERE assessment_id=?", (crit_str, json.dumps(target), assessment_id))
        crit_val = resolve_criticality(crit_str)

        ef = exposure_kind
        cf = crit_val
        scanners = {x["scanner"]: x for x in assessment["scanners"]}
        normalized = []
        update_assessment(assessment_id, "Running", stage="Scanner execution", heartbeat=True)

        # 1. Trivy Image Scan (or Imported Trivy Report)
        if scanners.get("Trivy", {}).get("status") == "Pending":
            imported_path = target.get("imported_trivy_report_path")
            if imported_path:
                update_scanner(assessment_id, "Trivy", "Running", "Parsing uploaded Trivy JSON report")
                try:
                    rep_file = Path(imported_path)
                    data = json.loads(rep_file.read_text(encoding="utf-8-sig"))
                    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
                        raise ValueError("Uploaded JSON file does not contain a valid Trivy 'Results' array.")
                    items = normalize_trivy_report(data, rep_file.name)
                    inferred_img = image or (items[0].get("asset") if items else rep_file.stem)
                    discovered_images = [{"image_name": inferred_img, "image_id": inferred_img, "digest": "", "container_id": ""}]
                    discovered_dependencies = []
                    for item in items:
                        item["assessment_id"] = assessment_id
                        item["evidence"].setdefault("trivy_report", rep_file.name)
                        item["evidence"].setdefault("trivy_target", item.get("asset"))
                        if item.get("package"):
                            discovered_dependencies.append({
                                "image_name": item.get("asset") or inferred_img,
                                "package": item["package"],
                                "version": item.get("installed_version", ""),
                                "fixed_version": item.get("fixed_version", ""),
                                "ecosystem": item.get("target_path", ""),
                            })
                    replace_source_findings(assessment_id, "Trivy", items)
                    retried_sources.add("Trivy")
                    normalized.extend(items)
                    update_scanner(assessment_id, "Trivy", "Completed", f"{len(items)} vulnerability records imported",
                                   {"report_name": rep_file.name, "report_path": str(rep_file), "image": inferred_img, "vulnerability_count": len(items)})
                except Exception as exc:
                    record_scanner_failure(assessment_id, "Trivy", exc)
            elif image:
                update_scanner(assessment_id, "Trivy", "Running", "Scanning container image vulnerabilities")
                try:
                    tr = run_trivy_image_scan(image, scan_output_dir, timeout_seconds=scanner_timeout("TRIVY", 1800, 30, 3600))
                    data = json.loads(Path(tr["report_path"]).read_text(encoding="utf-8-sig"))
                    items = normalize_trivy_report(data, Path(tr["report_path"]).name)
                    discovered_images = [{"image_name": image, "image_id": image, "digest": "", "container_id": target.get("container_id", "")}]
                    discovered_dependencies = []
                    for item in items:
                        item["assessment_id"] = assessment_id
                        item["evidence"].setdefault("trivy_report", tr["report_name"])
                        item["evidence"].setdefault("trivy_target", item.get("asset"))
                        item["asset"] = image
                        if item.get("package"):
                            discovered_dependencies.append({
                                "image_name": image,
                                "package": item["package"],
                                "version": item.get("installed_version", ""),
                                "fixed_version": item.get("fixed_version", ""),
                                "ecosystem": item.get("target_path", ""),
                            })
                    replace_source_findings(assessment_id, "Trivy", items)
                    retried_sources.add("Trivy")
                    normalized.extend(items)
                    update_scanner(assessment_id, "Trivy", "Completed", f"{len(items)} vulnerability records",
                                   {"report_name": tr["report_name"], "report_path": str(tr["report_path"]), "image": image, "vulnerability_count": len(items)})
                except Exception as exc:
                    record_scanner_failure(assessment_id, "Trivy", exc)
            else:
                update_scanner(assessment_id, "Trivy", "Skipped", "No container image was identified for this target.")

        # 2. Nmap Asset Discovery
        if scanners.get("Nmap", {}).get("status") == "Pending":
            if host and ports:
                update_scanner(assessment_id, "Nmap", "Running", f"Scanning authorized host {host}, ports {ports}")
                try:
                    nr = scan_target(host, ports, timeout_seconds=scanner_timeout("NMAP", 120, 10, 600))
                    items = normalize_nmap_result(nr)
                    discovered_hosts = [{"host_ip": host, "hostname": host, "state": "up", "details": nr}]
                    discovered_ports = []
                    discovered_services = []
                    vg_observations = []
                    for p in nr.get("open_ports", []):
                        if isinstance(p, dict):
                            port_no = int(p.get("port", 0))
                            discovered_ports.append({"host_ip": host, "port": port_no, "protocol": p.get("protocol", "tcp"), "state": p.get("state", "open")})
                            if p.get("service") or p.get("product"):
                                discovered_services.append({
                                    "host_ip": host, "port": port_no,
                                    "service_name": p.get("service", "unknown"),
                                    "product": p.get("product", ""),
                                    "version": p.get("version", ""),
                                })
                            vg_observations.append({"asset": host, "port": port_no, "state": p.get("state", "open")})
                    for item in items:
                        item["assessment_id"] = assessment_id
                    replace_source_findings(assessment_id, "Nmap", items)
                    retried_sources.add("Nmap")
                    normalized.extend(items)
                    update_scanner(assessment_id, "Nmap", "Completed", f"{len(nr.get('open_ports', []))} open ports", nr)
                except Exception as exc:
                    record_scanner_failure(assessment_id, "Nmap", exc)
            else:
                update_scanner(assessment_id, "Nmap", "Skipped", "No verified authorized host/port mapping was available.")

        # 3. OWASP ZAP Web Application Scan
        if scanners.get("OWASP ZAP", {}).get("status") == "Pending":
            if zap_app:
                update_scanner(assessment_id, "OWASP ZAP", "Running", f"Running OWASP ZAP baseline passive checks against {zap_app}")
                try:
                    zr = run_zap_baseline_scan(zap_app, scan_output_dir, timeout_seconds=scanner_timeout("ZAP", 900, 60, 3600), max_spider_minutes=3)
                    data = json.loads(Path(zr["report_path"]).read_text(encoding="utf-8-sig"))
                    items = normalize_zap_report(data, zr["report_name"], zap_app)
                    for item in items:
                        item["assessment_id"] = assessment_id
                    replace_source_findings(assessment_id, "OWASP ZAP", items)
                    retried_sources.add("OWASP ZAP")
                    normalized.extend(items)
                    update_scanner(assessment_id, "OWASP ZAP", "Completed", f"{len(items)} alerts",
                                   {"report_name": zr["report_name"], "report_path": str(zr["report_path"]), "target_url": zr["target_url"], "alert_count": zr["alert_count"], "mode": "baseline/passive"})
                except Exception as exc:
                    record_scanner_failure(assessment_id, "OWASP ZAP", exc)
            else:
                update_scanner(assessment_id, "OWASP ZAP", "Skipped", "No verified Juice Shop/DVWA local endpoint was mapped.")

        # --- STAGE 1/7: Finding Normalization ---
        update_assessment(assessment_id, "Processing findings", stage="Finding normalization (1/7)", heartbeat=True)
        normalized = [f for f in previous_findings if f.get("source") not in retried_sources] + normalized

        # Retrieve existing SQLite NVD cache and assign explicit enrichment statuses immediately
        cache = get_nvd_cache_sqlite()
        for item in normalized:
            cve = item.get("cve")
            if not cve or not str(cve).startswith("CVE-"):
                item["nvd_status"] = "N/A"
                item["nvd_enrichment"] = {}
            else:
                rec = cache.get(cve)
                if rec and rec.get("status") == "enriched":
                    item["nvd_status"] = "Cached"
                    item["nvd_enrichment"] = rec
                    if rec.get("cvss_score") is not None and item.get("cvss") is None:
                        item["cvss"] = rec["cvss_score"]
                elif rec and rec.get("status") == "not_found":
                    item["nvd_status"] = "Unavailable"
                    item["nvd_enrichment"] = rec
                elif rec and rec.get("status") == "error":
                    item["nvd_status"] = "Failed"
                    item["nvd_enrichment"] = rec
                else:
                    item["nvd_status"] = "Pending"
                    item["nvd_enrichment"] = {}

        # EPSS & KEV Threat Intelligence Enrichment (fast local lookup)
        normalized = enrich_findings(normalized)

        # --- STAGE 2/7: Deduplication & Correlation ---
        update_assessment(assessment_id, "Processing findings", stage="Deduplication (2/7)", heartbeat=True)
        correlated, duplicate_groups = correlate_findings(normalized)

        # --- STAGE 3/7: Contextual Risk Calculation ---
        update_assessment(assessment_id, "Processing findings", stage="Risk calculation (3/7)", heartbeat=True)
        scored = []
        for item in correlated:
            if auto is not None:
                item["automatic_criticality"] = auto
            scored_item = _risk(item, ef, cf, cache)
            if scored_item.get("finding_id"):
                risk_calculations.append({
                    "finding_id": scored_item.get("finding_id", ""),
                    "model_version": scored_item.get("model_version", "vulngraph-contextual-risk-1.0"),
                    "cvss": scored_item.get("cvss"),
                    "epss": scored_item.get("epss"),
                    "reachability": scored_item.get("reachability", reachability),
                    "criticality": scored_item.get("criticality_level", crit_val),
                    "calculated_risk": scored_item.get("contextual_risk"),
                    "status": scored_item.get("contextual_status", "Provisional"),
                    "reason": scored_item.get("contextual_reason", ""),
                })
            scored.append(scored_item)
        correlated = scored

        # --- STAGE 4/7: Asset Correlation ---
        update_assessment(assessment_id, "Processing findings", stage="Asset correlation (4/7)", heartbeat=True)
        save_discovered_assets(
            assessment_id,
            hosts=discovered_hosts,
            ports=discovered_ports,
            services=discovered_services,
            images=discovered_images,
            dependencies=discovered_dependencies,
        )

        # --- STAGE 5/7: OWASP Classification ---
        update_assessment(assessment_id, "Processing findings", stage="OWASP classification (5/7)", heartbeat=True)
        classifications = []
        for item in correlated:
            item["related_findings"] = item.get("correlated_finding_ids", [])
            if item.get("finding_id"):
                cls_info = classify(item, assessment_id)
                classifications.append(cls_info)
                cat_code = cls_info.get("category") or cls_info.get("code") or "UNCLASSIFIED"
                cat_name = cls_info.get("category_name") or cls_info.get("name") or "Unclassified"
                item["owasp_category"] = f"{cat_code} — {cat_name}"
                item["owasp_top_10"] = cat_code

        # --- STAGE 6/7: Attack Graph Generation ---
        update_assessment(assessment_id, "Processing findings", stage="Attack graph generation (6/7)", heartbeat=True)
        links = correlate_ports(vg_observations, vg_containers, assessment_id)
        save_vg_evidence(assessment_id, vg_containers, links, classifications)

        # --- STAGE 7/7: Database Persistence & Background NVD Queue ---
        update_assessment(assessment_id, "Processing findings", stage="Database persistence (7/7)", heartbeat=True)
        save_findings(assessment_id, correlated)
        save_risk_calculations(assessment_id, risk_calculations)

        # Enqueue missing/uncached CVEs for persistent background NVD enrichment (non-blocking)
        cve_ids_to_queue = list(dict.fromkeys(
            x.get("cve") for x in correlated
            if str(x.get("cve", "")).startswith("CVE-") and x.get("nvd_status") == "Pending"
        ))
        if cve_ids_to_queue:
            enqueue_cve_ids(cve_ids_to_queue, assessment_id=assessment_id)
            ensure_background_enricher_running()

        # Final assessment state determination
        states = [x["status"] for x in get_assessment(assessment_id)["scanners"]]
        if any(s == "Running" for s in states):
            final = "Partial"
        elif all(s in {"Skipped"} for s in states):
            final = "Failed"
        elif any(s == "Failed" for s in states):
            final = "Partial" if any(s == "Completed" for s in states) else "Failed"
        else:
            final = "Completed"

        update_assessment(assessment_id, final, stage="Assessment complete")
        log_event(
            assessment.get("created_by", "system"), "System", "assessment_worker_finished", "assessment", assessment_id,
            {"status": final, "finding_count": len(correlated), "asset_count": len(discovered_hosts) + len(vg_containers)}
        )

    except Exception as exc:
        current = get_assessment(assessment_id)
        has_success = bool(current and (current.get("findings") or any(
            x["status"] == "Completed" for x in current["scanners"])))
        update_assessment(
            assessment_id, "Partial" if has_success else "Failed",
            str(exc)[:1000], stage="Processing interrupted"
        )
        try:
            log_event(
                assessment.get("created_by", "system"), "System", "assessment_worker_failed", "assessment", assessment_id,
                {"error": str(exc)[:500]}
            )
        except Exception:
            pass
        for scanner in ("Trivy", "Nmap", "OWASP ZAP"):
            current = get_assessment(assessment_id)
            state = next((x for x in current["scanners"] if x["scanner"] == scanner), None)
            if state and state["status"] in {"Pending", "Running"}:
                update_scanner(assessment_id, scanner, "Failed", f"Assessment worker stopped: {exc}"[:700])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
