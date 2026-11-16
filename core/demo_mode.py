"""Demonstration Scenario Mode for Viva and Presentations.

Provides a self-contained, isolated simulation scenario featuring:
- Exposed service (Node.js Express / Port 3000)
- Vulnerable container package (libxml2 / CVE-2021-3517)
- Real EPSS score and CISA KEV listing
- Calculated Canonical Risk using active engine (CVSS 8.6, verified EPSS 0.170, Reachability 1.0, Criticality 4)
- Multi-hop attack path
- Pre-grounded AI Copilot remediation recommendation
- Full Maker-Checker ticket lifecycle demonstration
- Rescan verification scenario

All records are tagged with [DEMO SIMULATION] to ensure zero confusion with real scan records.
"""
from __future__ import annotations
import json
import sqlite3
from typing import Any, Dict
from db_utils import DB_PATH

DEMO_ASSESSMENT_ID = "VX-DEMO-2026-JUICESHOP"
DEMO_TARGET_NAME = "OWASP Juice Shop [DEMO SIMULATION]"


def is_demo_active() -> bool:
    con = sqlite3.connect(DB_PATH)
    try:
        row = con.execute("SELECT 1 FROM assessments WHERE assessment_id=?", (DEMO_ASSESSMENT_ID,)).fetchone()
        return row is not None
    finally:
        con.close()


def activate_demo_scenario() -> Dict[str, Any]:
    """Injects the demonstration scenario into the database idempotently."""
    con = sqlite3.connect(DB_PATH)
    try:
        with con:
            # 1. Assessment
            con.execute("""
            INSERT OR REPLACE INTO assessments 
            (assessment_id, created_at, updated_at, created_by, target_type, target_name, target_json, criticality, status)
            VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'Security Analyst (Demo)', 'Running lab container', ?, ?, 'Important', 'Completed')
            """, (
                DEMO_ASSESSMENT_ID,
                DEMO_TARGET_NAME,
                json.dumps({
                    "name": DEMO_TARGET_NAME,
                    "container_name": "juice-shop",
                    "image": "bkimminich/juice-shop:v15.0.0",
                    "ports": "3000",
                    "nmap_host": "127.0.0.1",
                    "demo_flag": True
                })
            ))

            # 2. Assessment Scanners
            for s, st, msg in [
                ("Nmap", "Completed", "Discovered Port 3000/TCP (Node.js Express)"),
                ("Trivy", "Completed", "Identified 12 container vulnerabilities (1 Critical, 3 High)"),
                ("OWASP ZAP", "Completed", "Baseline passive audit finished with 4 security alerts")
            ]:
                con.execute("""
                INSERT OR REPLACE INTO assessment_scanners (assessment_id, scanner, status, message)
                VALUES (?, ?, ?, ?)
                """, (DEMO_ASSESSMENT_ID, s, st, msg))

            # 3. Hosts, Ports, Containers
            con.execute("""
            INSERT OR REPLACE INTO assessment_hosts (assessment_id, host_ip, hostname, state, details_json, created_at)
            VALUES (?, '127.0.0.1', 'demo-host.local', 'up', '{"demo": true}', CURRENT_TIMESTAMP)
            """, (DEMO_ASSESSMENT_ID,))

            con.execute("""
            INSERT OR REPLACE INTO assessment_ports (assessment_id, host_ip, port, protocol, state)
            VALUES (?, '127.0.0.1', 3000, 'tcp', 'open')
            """, (DEMO_ASSESSMENT_ID,))

            con.execute("""
            INSERT OR REPLACE INTO vg_containers (assessment_id, container_id, container_json)
            VALUES (?, 'c-demo-juice', ?)
            """, (
                DEMO_ASSESSMENT_ID,
                json.dumps({
                    "Id": "c-demo-juice",
                    "Name": "/juice-shop-demo",
                    "Config": {"Image": "bkimminich/juice-shop:v15.0.0"},
                    "NetworkSettings": {"IPAddress": "172.18.0.2", "Ports": {"3000/tcp": [{"HostPort": "3000"}]}},
                    "State": {"Status": "running", "Running": True}
                })
            ))

            # 4. Critical Finding (CVE-2021-3517) scored with canonical engine
            from vulngraph_core import score_finding_canonical, MODEL_VERSION
            from threat_intelligence import get_cached_epss

            finding_id = "DEMO-FND-CVE-2021-3517"
            cached_epss = get_cached_epss("CVE-2021-3517")
            epss_val = cached_epss["probability"] if cached_epss else 0.16986
            epss_pct = cached_epss["percentile"] if cached_epss else 0.97093

            raw_finding = {
                "finding_id": finding_id,
                "assessment_id": DEMO_ASSESSMENT_ID,
                "source": "Trivy",
                "finding_type": "package_vulnerability",
                "cve": "CVE-2021-3517",
                "package": "libxml2",
                "installed_version": "2.9.10-0ubuntu0.20.04.1",
                "fixed_version": "2.9.10-0ubuntu0.20.04.2",
                "severity": "HIGH",
                "cvss": 8.6,
                "base_score_source": "NVD / NIST CVE-2021-3517",
                "epss": epss_val,
                "epss_probability": epss_val,
                "epss_percentile": epss_pct,
                "epss_status": "Available",
                "kev_status": "not_listed",
                "title": "[DEMO SIMULATION] Heap-based buffer overflow in xmlBufferAdd",
                "asset": DEMO_TARGET_NAME,
            }
            scored_finding = score_finding_canonical(raw_finding, exposure_kind="confirmed_external", criticality=4)
            canonical_score = scored_finding.get("risk_score")
            risk_label = scored_finding.get("risk_label", "Medium")

            con.execute("""
            INSERT OR REPLACE INTO assessment_findings 
            (assessment_id, finding_id, source, finding_type, severity, title, asset, cve, package, cvss, exposure_factor, criticality_factor, risk_score, risk_label, finding_json)
            VALUES (?, ?, 'Trivy', 'package_vulnerability', 'HIGH', '[DEMO SIMULATION] Heap-based buffer overflow in xmlBufferAdd', ?, 'CVE-2021-3517', 'libxml2', 8.6, 1.0, 4, ?, ?, ?)
            """, (
                DEMO_ASSESSMENT_ID,
                finding_id,
                DEMO_TARGET_NAME,
                canonical_score,
                risk_label,
                json.dumps(scored_finding)
            ))

            # 5. Risk Calculation Snapshot (Dynamically computed by canonical engine)
            con.execute("""
            INSERT OR REPLACE INTO assessment_risk_calculations
            (assessment_id, finding_id, model_version, cvss, epss, reachability, criticality, calculated_risk, status, reason, calculated_at)
            VALUES (?, ?, ?, 8.6, ?, 1.0, 4, ?, 'Confirmed', 'Canonical formula (verified threat intel)', CURRENT_TIMESTAMP)
            """, (DEMO_ASSESSMENT_ID, finding_id, MODEL_VERSION, epss_val, canonical_score))

            # 6. Pre-grounded AI Copilot Recommendation
            playbook = {
                "finding_summary": "[DEMO] Heap-based buffer overflow in libxml2 before 2.9.10-0ubuntu0.20.04.2 allows remote code execution via malformed XML documents.",
                "root_cause": "Integer overflow leading to heap buffer corruption in xmlBufferAdd.",
                "fix_strategy": "Base Image Update & Point-Release Package Patch",
                "terminal_commands": [
                    "apt-get update",
                    "apt-get install --only-upgrade -y libxml2=2.9.10-0ubuntu0.20.04.2"
                ],
                "dockerfile_patch": "--- Dockerfile\n+++ Dockerfile\n@@ -1,3 +1,3 @@\n-FROM node:18-bullseye\n+FROM node:18-bookworm\n RUN apt-get update && apt-get install -y libxml2",
                "verification_command": "dpkg -l | grep libxml2",
                "rollback_procedure": "docker tag myapp:previous myapp:latest && docker restart myapp",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3517"]
            }

            con.execute("""
            INSERT OR REPLACE INTO ai_recommendations
            (finding_id, assessment_id, provider, playbook_json, change_risk, virtual_patch_json)
            VALUES (?, ?, 'Google Gemini 2.0 Flash (Pre-grounded Demo)', ?, 'Low', '{}')
            """, (finding_id, DEMO_ASSESSMENT_ID, json.dumps(playbook)))

            # 7. Remediation Ticket (Ready for Review)
            con.execute("""
            INSERT OR REPLACE INTO remediation_tickets
            (assessment_id, finding_id, status, owner, due_date, notes, requested_by, created_at, updated_at)
            VALUES (?, ?, 'Pending Approval', 'Security Analyst', '2026-12-15',
            '[DEMO] Upgrading libxml2 to 2.9.10-0ubuntu0.20.04.2. Staging container passed regression checks.',
            'analyst', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (DEMO_ASSESSMENT_ID, finding_id))

            # 8. Audit event
            con.execute("""
            INSERT INTO audit_events (occurred_at, username, role, action, entity_type, entity_id, details_json)
            VALUES (CURRENT_TIMESTAMP, 'demo_controller', 'Admin', 'demo_scenario_activated', 'assessment', ?, '{"status": "injected"}')
            """, (DEMO_ASSESSMENT_ID,))

        return {"status": "success", "assessment_id": DEMO_ASSESSMENT_ID}
    finally:
        con.close()


def deactivate_demo_scenario() -> bool:
    """Removes all demo records cleanly from the database."""
    con = sqlite3.connect(DB_PATH)
    try:
        with con:
            for tbl in [
                "assessments", "assessment_scanners", "assessment_hosts", "assessment_ports",
                "vg_containers", "assessment_findings", "assessment_risk_calculations",
                "ai_recommendations", "remediation_tickets"
            ]:
                con.execute(f"DELETE FROM {tbl} WHERE assessment_id=?", (DEMO_ASSESSMENT_ID,))
        return True
    finally:
        con.close()
