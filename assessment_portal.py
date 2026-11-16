"""Guided, local-lab assessment entry point. No scanner runs on page load."""
from __future__ import annotations

import re
import os
import ipaddress
from urllib.parse import urlsplit
from asset_discovery import _validate_ports

from assessment_manager import create_assessment, get_assessment, launch_worker, list_assessments

LAB_IMAGES = {"Juice Shop": "bkimminich/juice-shop", "DVWA": "vulnerables/web-dvwa"}
LAB_PORTS = {"Juice Shop": "3000", "DVWA": "8081"}


def validate_docker_image(image: str) -> str:
    """Accept a single conventional Docker image reference, never shell syntax."""
    image = image.strip()
    if not image or len(image) > 255 or any(char.isspace() for char in image):
        raise ValueError("Enter a valid Docker image reference (maximum 255 characters).")
    # A conservative subset of Docker references, including registry:port and digest.
    pattern = r"[A-Za-z0-9][A-Za-z0-9._:/@-]*"
    if not re.fullmatch(pattern, image) or image.startswith(("-", ".", "/")) or ".." in image:
        raise ValueError("Invalid Docker image reference. Example: python:3.11-slim")
    if image.count("@") > 1 or ("@" in image and not re.search(r"@sha256:[a-fA-F0-9]{64}$", image)):
        raise ValueError("Invalid image digest; expected @sha256 followed by 64 hex digits.")
    return image


def validate_host(host: str) -> str:
    """Allow loopback by default; additional exact private IPs require operator allowlisting."""
    host = str(host).strip()
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Enter a literal host IP address (e.g. 127.0.0.1).") from exc
    if address.is_loopback:
        return str(address)
    allowed = {part.strip() for part in os.getenv("VULNX_ALLOWED_HOSTS", "").split(",") if part.strip()}
    if not address.is_private or str(address) not in allowed:
        raise ValueError("Private host IP is not allowlisted. Add its exact IP to VULNX_ALLOWED_HOSTS first.")
    return str(address)


def validate_local_web_url(url: str) -> tuple[str, str, str]:
    """Only the two configured localhost web lab endpoints are permitted for ZAP."""
    url = str(url).strip()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid local web URL or port.") from exc
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"} or port not in {3000, 8081} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Web scanning is restricted to http://localhost:3000/ and http://localhost:8081/ (no query or credentials).")
    if parsed.path not in {"", "/"}:
        raise ValueError("Use the lab application's root URL, without a path.")
    app = "OWASP Juice Shop" if port == 3000 else "DVWA"
    return f"http://localhost:{port}/", str(port), app


def make_plan(mode: str, lab: str | None, criticality: str, *, run_trivy=True, run_nmap=True, run_zap=True,
              custom_image: str | None = None, custom_host: str | None = None,
              custom_ports: str | None = None, custom_url: str | None = None):
    """Generate a bounded assessment plan for authorized localhost lab targets."""
    if mode not in {"Running lab container", "Docker image", "Local web application", "Local host"}:
        raise ValueError("Unsupported assessment target type")
    if custom_host is not None and mode != "Local host":
        raise ValueError("Custom host is only supported for Local host assessments")
    if custom_url is not None and mode != "Local web application":
        raise ValueError("Custom URL is only supported for Local web application assessments")
    if custom_image is not None:
        if mode != "Docker image":
            raise ValueError("Custom image references are only supported for Docker image assessments")
        image_reference = validate_docker_image(custom_image)
    elif custom_host is not None or custom_url is not None:
        image_reference = ""
    else:
        if lab not in LAB_IMAGES:
            raise ValueError("Target must be a configured local lab application")
        image_reference = LAB_IMAGES[lab]
    if criticality not in {"Low", "Normal", "High", "Auto"}:
        raise ValueError("Unsupported criticality")
    target = {"name": image_reference if custom_image is not None else lab, "image": image_reference if mode in {"Running lab container", "Docker image"} else "",
              "nmap_host": "127.0.0.1" if mode in {"Running lab container", "Local web application", "Local host"} else "",
              "ports": LAB_PORTS.get(lab, "") if mode in {"Running lab container", "Local web application", "Local host"} else "",
              "zap_app": lab if mode in {"Running lab container", "Local web application"} else "",
              "exposure_kind": "loopback" if mode != "Docker image" else "unknown"}
    if custom_host is not None:
        host = validate_host(custom_host)
        ports = _validate_ports(custom_ports or "")
        target.update(name=host, image="", nmap_host=host, ports=ports, zap_app="",
                      exposure_kind="loopback" if ipaddress.ip_address(host).is_loopback else "private_network")
    elif custom_url is not None:
        url, port, app = validate_local_web_url(custom_url)
        target.update(name=url, image="", nmap_host="127.0.0.1", ports=port,
                      zap_app=app, zap_target_url=url, exposure_kind="loopback")
    if lab == "Juice Shop" and custom_image is None and custom_host is None and custom_url is None:
        target["zap_app"] = "OWASP Juice Shop" if target["zap_app"] else ""
    target["configured_training_lab"] = bool(lab in LAB_IMAGES and custom_image is None and custom_host is None and custom_url is None)
    target["scanner_plan"] = [
        ("Trivy", "Pending" if run_trivy and bool(target["image"]) else "Skipped", "Container image scan"),
        ("Nmap", "Pending" if run_nmap and bool(target["nmap_host"]) else "Skipped", "Local service discovery"),
        ("OWASP ZAP", "Pending" if run_zap and bool(target["zap_app"]) else "Skipped", "Passive web scan"),
    ]
    if not any(s == "Pending" for _, s, _ in target["scanner_plan"]):
        raise ValueError("Choose at least one compatible scanner")
    return target


def render_portal(st, username: str, role: str, can_start: bool):
    st.markdown('<div id="new-assessment"></div>', unsafe_allow_html=True)
    st.header("New Assessment")
    st.caption("Select a configured, authorized local lab target. VulnX will scan, normalize, enrich, correlate and prioritize findings.")
    with st.form("vulnx_guided_assessment", clear_on_submit=False):
        left, right = st.columns(2)
        with left:
            mode = st.selectbox("Target type", ["Running lab container", "Docker image", "Local web application", "Local host"])
            lab = st.selectbox("Authorized lab target", ["Juice Shop", "DVWA"])
            criticality = "Auto"
            st.caption("Business criticality is assessed automatically from available asset evidence.")
        with right:
            st.markdown("**Scanner selection**")
            trivy = st.checkbox("Trivy — image vulnerabilities", value=True)
            nmap = st.checkbox("Nmap — local ports", value=True)
            zap = st.checkbox("OWASP ZAP — passive web scan", value=True)
            st.caption("Only scanners applicable to the selected target type will run.")
        confirmed = st.checkbox("I am authorized to scan this local training environment.")
        submitted = st.form_submit_button("Start assessment", type="primary", disabled=not can_start)
    if not can_start:
        st.warning("Your account role does not have scan permission.")
    if submitted:
        if not confirmed:
            st.error("Confirm authorization before starting a scan.")
        else:
            try:
                target = make_plan(mode, lab, criticality, run_trivy=trivy, run_nmap=nmap, run_zap=zap)
                assessment_id = create_assessment(username, mode, target, criticality)
                launch_worker(assessment_id)
                st.session_state["vulnx_selected_assessment"] = assessment_id
                st.success(f"Assessment queued: {assessment_id}")
            except (ValueError, RuntimeError, OSError) as error:
                st.error(f"Could not start assessment: {error}")
    st.markdown('<div id="my-assessments"></div>', unsafe_allow_html=True)
    st.subheader("My Assessments")
    assessments = list_assessments(limit=30)
    if not assessments:
        st.info("No assessments created yet. Start one above.")
        return
    visible = assessments if role == "Admin" else [a for a in assessments if a["created_by"] == username]
    if not visible:
        st.info("You have no assessments yet.")
        return
    options = {f'{a["assessment_id"]} · {a["target_name"]} · {a["status"]}': a["assessment_id"] for a in visible}
    current = st.session_state.get("vulnx_selected_assessment")
    labels = list(options)
    index = next((i for i, label in enumerate(labels) if options[label] == current), 0)
    selected = st.selectbox("Open assessment", labels, index=index)
    assessment_id = options[selected]
    st.session_state["vulnx_selected_assessment"] = assessment_id
    if st.button("Refresh assessment status", key="vulnx_refresh_assessment"):
        st.rerun()
    assessment = get_assessment(assessment_id)
    if not assessment:
        st.error("Assessment not found.")
        return
    st.write(f'**Status:** {assessment["status"]}  |  **Stage:** {assessment["stage"]}')
    if assessment.get("error"):
        st.error(assessment["error"])
    st.dataframe([{"Scanner": x["scanner"], "Status": x["status"], "Details": x["message"]}
                  for x in assessment["scanners"]], use_container_width=True, hide_index=True)
    findings = assessment["findings"]
    st.metric("Assessment findings", len(findings))
    if findings:
        rows = [{"Source": f.get("source"), "Severity": f.get("severity"), "CVE": f.get("cve"),
                 "Asset": f.get("asset"), "Title": f.get("title"), "Risk": f.get("risk_score"),
                 "Priority": f.get("risk_label")} for f in findings]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        import csv, io
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
        st.download_button("Download assessment findings (CSV)", buffer.getvalue(),
                           file_name=f"{assessment_id}-findings.csv", mime="text/csv")
    elif assessment["status"] in {"Queued", "Running", "Discovering assets", "Processing findings"}:
        st.info("Assessment is still processing. Use Refresh assessment status to view progress.")
    else:
        st.info("No findings recorded for this assessment. Check scanner statuses and worker logs.")
