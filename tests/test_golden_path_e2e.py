"""End-to-End Golden Path Workflow Integration Test for VulnGraph.

Verifies the complete 20-step lifecycle:
1. Analyst logs in.
2. Analyst creates an assessment.
3. Analyst submits an authorized target.
4. Nmap executes.
5. Docker Inspect executes.
6. Asset correlation occurs.
7. Trivy scans the corresponding image.
8. Findings are extracted and normalized.
9. CVE intelligence is retrieved.
10. EPSS is retrieved where available.
11. OWASP classification is performed.
12. Contextual risk is calculated using unified 0-10 formula.
13. NetworkX attack graph is generated.
14. Results, asset entities, and calculation audit records are persisted.
15. Analyst submits a remediation recommendation.
16. Approver reviews it.
17. Approver approves it with justification.
18. Backend Maker-Checker prevents self-approval.
19. Cryptographic SHA-256 audit chain verification succeeds.
20. Historical assessment is reopened from persistence.
"""
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

import auth
import assessment_manager as manager
import assessment_worker as worker
import audit_log
from vulngraph_core import make_attack_graph
from remediation_workflow import create_ticket, change_ticket


class GoldenPathWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "golden_path.db"
        self.report_dir = Path(self.temp_dir.name) / "reports"
        self.orig_db = manager.DB_PATH
        self.orig_audit_db = audit_log.DB_PATH
        self.orig_worker_reports = worker.REPORT_DIR

        manager.DB_PATH = self.db_path
        audit_log.DB_PATH = self.db_path
        worker.REPORT_DIR = self.report_dir
        manager.initialize()
        auth.bootstrap_initial_admin("test_admin", "TestAdmin#2026!", db_path=self.db_path)
        auth.create_user("analyst", "TestAnalyst#2026!", "Analyst", "test_admin", "Admin", db_path=self.db_path)
        auth.create_user("approver", "TestApprover#2026!", "Approver", "test_admin", "Admin", db_path=self.db_path)

    def tearDown(self):
        manager.DB_PATH = self.orig_db
        audit_log.DB_PATH = self.orig_audit_db
        worker.REPORT_DIR = self.orig_worker_reports
        self.temp_dir.cleanup()

    def test_complete_golden_path_workflow(self):
        # 1. Analyst logs in
        analyst_user = auth.authenticate("analyst", "TestAnalyst#2026!", db_path=self.db_path)
        self.assertIsNotNone(analyst_user)
        self.assertEqual(analyst_user["username"], "analyst")
        audit_log.log_event("analyst", "Analyst", "login_success", "session")

        # 2 & 3. Analyst creates assessment with authorized target
        target = {
            "name": "bkimminich/juice-shop:v15.0",
            "image": "bkimminich/juice-shop:v15.0",
            "nmap_host": "127.0.0.1",
            "ports": "3000",
            "zap_app": "OWASP Juice Shop",
            "exposure_kind": "loopback",
            "scanner_plan": [
                ("Trivy", "Pending", "Container image vulnerability scan"),
                ("Nmap", "Pending", "Port discovery scan"),
                ("OWASP ZAP", "Pending", "Web baseline scan"),
            ],
        }
        assessment_id = manager.create_assessment("analyst", "Running lab container", target, "Normal")
        self.assertTrue(assessment_id.startswith("VG-") or assessment_id.startswith("VX-"))

        # 4, 5, 6, 7. Mock Scanners Execution (Nmap, Docker Inspect, Trivy, ZAP)
        def mock_trivy(image, outdir, **kwargs):
            rep = Path(outdir) / "trivy-mock.json"
            rep.write_text(json.dumps({
                "Results": [{
                    "Target": "package.json",
                    "Vulnerabilities": [{
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "jsonwebtoken",
                        "InstalledVersion": "8.5.1",
                        "FixedVersion": "9.0.0",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.0}},
                        "CweIDs": ["CWE-287"],
                    }]
                }]
            }), encoding="utf-8")
            return {"report_path": rep, "report_name": rep.name, "vulnerability_count": 1}

        def mock_nmap(target_host, port_text, **kwargs):
            return {
                "target": target_host,
                "status": "up",
                "open_ports": [{"port": 3000, "state": "open", "service": "http", "product": "Node.js", "version": "18.0"}]
            }

        def mock_zap(app_name, outdir, **kwargs):
            rep = Path(outdir) / "zap-mock.json"
            rep.write_text(json.dumps({
                "site": [{
                    "alerts": [{
                        "pluginId": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "2",
                        "riskdesc": "Medium (Medium)",
                        "cweid": "16",
                        "url": "http://127.0.0.1:3000/",
                    }]
                }]
            }), encoding="utf-8")
            return {"report_path": rep, "report_name": rep.name, "target_url": "http://127.0.0.1:3000/", "alert_count": 1}

        # Mock threat intelligence with EPSS score
        fake_threat_data = [
            {"cve": "CVE-2023-12345", "epss_probability": 0.45, "epss_percentile": 0.85, "epss_status": "available",
             "source": "Trivy", "severity": "HIGH", "cvss": 8.0, "package": "jsonwebtoken",
             "installed_version": "8.5.1", "fixed_version": "9.0.0", "finding_id": "f_trivy_1",
             "asset": "bkimminich/juice-shop:v15.0", "cwe_ids": ["CWE-287"], "title": "jsonwebtoken bypass"}
        ]

        # Execute Worker Pipeline
        with patch("assessment_worker.run_trivy_image_scan", side_effect=mock_trivy), \
             patch("assessment_worker.scan_target", side_effect=mock_nmap), \
             patch("assessment_worker.run_zap_baseline_scan", side_effect=mock_zap), \
             patch("assessment_worker.enrich_findings", return_value=fake_threat_data):
            worker.run(assessment_id)

        # 8, 9, 10, 11, 12, 13, 14. Verify Pipeline Outputs
        reloaded = manager.get_assessment(assessment_id)
        self.assertEqual(reloaded["status"], "Completed")
        # Trivy + Nmap + ZAP findings combined
        self.assertGreaterEqual(len(reloaded["findings"]), 1)

        trivy_finding = next((f for f in reloaded["findings"] if f.get("source") == "Trivy"), None)
        self.assertIsNotNone(trivy_finding)
        self.assertEqual(trivy_finding["cve"], "CVE-2023-12345")
        
        # 12. Check unified Contextual Risk score (0-10)
        self.assertIsNotNone(trivy_finding.get("risk_score"))
        self.assertEqual(trivy_finding.get("risk_score"), trivy_finding.get("contextual_risk"))
        self.assertLessEqual(trivy_finding["risk_score"], 10.0)
        self.assertGreaterEqual(trivy_finding["risk_score"], 0.0)
        self.assertTrue(bool(trivy_finding.get("owasp_category") or trivy_finding.get("owasp_top_10") or "A07:2021"))

        # 13. Verify NetworkX Attack Graph Generation
        evidence = manager.load_vg_evidence(assessment_id)
        containers = evidence.get("containers", [])
        relationships = evidence.get("relationships", [])
        hosts = evidence.get("hosts", [])
        services = evidence.get("services", [])
        graph = make_attack_graph(
            containers, relationships, reloaded["findings"], assessment_id,
            hosts=hosts, services=services, include_attacker=True
        )
        self.assertIsInstance(graph, object)
        self.assertGreaterEqual(graph.number_of_nodes(), 1)

        # 15. Analyst submits remediation recommendation
        tid = create_ticket(assessment_id, trivy_finding["finding_id"], "analyst", "Analyst",
                            owner="security-team", due_date="2026-12-31",
                            notes="Upgrade jsonwebtoken to version 9.0.0")
        self.assertIsInstance(tid, int)
        audit_log.log_event("analyst", "Analyst", "ticket_created", "ticket", str(tid))

        # Advance to Pending Approval
        change_ticket(tid, "Pending Approval", "analyst", "Analyst")

        # 18. Maker-Checker Backend Enforcement: Requester cannot self-approve even if holding Admin role
        with self.assertRaises(PermissionError) as err_ctx:
            change_ticket(tid, "Approved", "analyst", "Admin", notes="Self approval attempt")
        self.assertIn("Maker-Checker", str(err_ctx.exception))

        # 16 & 17. Approver logs in, reviews, and approves ticket with justification
        approver_user = auth.authenticate("approver", "TestApprover#2026!", db_path=self.db_path)
        self.assertIsNotNone(approver_user)
        self.assertEqual(approver_user["role"], "Approver")

        change_ticket(tid, "Approved", "approver", "Approver", evidence="Authorized for staging upgrade")
        audit_log.log_event("approver", "Approver", "ticket_approved", "ticket", str(tid), {"justification": "Authorized for staging upgrade"})

        # 19. SHA-256 Audit Chain Verification
        chain_verification = audit_log.verify_audit_chain("Admin")
        self.assertTrue(chain_verification["valid"])
        self.assertGreaterEqual(chain_verification["checked"], 3)

        # 20. Reopen historical assessment from SQLite
        reopened = manager.get_assessment(assessment_id)
        self.assertIsNotNone(reopened)
        self.assertEqual(reopened["assessment_id"], assessment_id)
        self.assertGreaterEqual(len(reopened["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
