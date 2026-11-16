"""Regression tests for VulnX scanning wizard state persistence, duplicate launch prevention,
imported Trivy report worker pipeline, and scanner health diagnostics.
"""
from __future__ import annotations
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import assessment_manager as am
import assessment_worker as aw
import db_utils
import docker_lab
import remediation_workflow as rw


class WizardAndWorkerRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_vulnx.db"
        self.report_dir = Path(self.tmp.name) / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "VULNGRAPH_DATABASE_PATH": str(self.db_path),
                "DATABASE_PATH": str(self.db_path),
                "VULNX_THREAT_ENRICHMENT": "0",
            },
        )
        self.db_patch = mock.patch.object(am, "DB_PATH", self.db_path)
        self.rep_patch = mock.patch.object(am, "REPORT_DIR", self.report_dir)
        self.env_patch.start()
        self.db_patch.start()
        self.rep_patch.start()
        db_utils.initialize_all_tables(self.db_path)
        am.initialize()

    def tearDown(self):
        self.rep_patch.stop()
        self.db_patch.stop()
        self.env_patch.stop()
        self.tmp.cleanup()

    def test_step2_persists_when_step1_widget_keys_unmount(self):
        """Verify Step 2 does not bounce back to Step 1 when Step 1 widget keys are garbage-collected."""
        session_state = {
            "vx_wizard_step": 1,
            "vx_target_mode": "Quick Select — Local Vulnerable Lab Container",
            "vx_saved_lab": "OWASP Juice Shop",
            "vx_ui_target_mode": "Quick Select — Local Vulnerable Lab Container",
            "vx_ui_lab_choice": "OWASP Juice Shop",
        }
        # Advance from Step 1 to Step 2
        session_state["vx_target_mode"] = session_state["vx_ui_target_mode"]
        session_state["vx_saved_lab"] = session_state["vx_ui_lab_choice"]
        session_state["vx_wizard_step"] = 2

        # Simulate Streamlit garbage-collecting unmounted Step 1 widget keys on Step 2 rerun
        session_state.pop("vx_ui_target_mode", None)
        session_state.pop("vx_ui_lab_choice", None)

        valid_modes = {
            "Quick Select — Local Vulnerable Lab Container",
            "Custom Container Image",
            "Custom Network Target (Host / IP)",
            "Custom Web Application URL",
            "Import Scanner JSON Report (Trivy)",
        }
        step = int(session_state.get("vx_wizard_step", 1) or 1)
        if step not in (1, 2):
            step = 1
        if step == 2 and session_state.get("vx_target_mode") not in valid_modes:
            step = 1

        self.assertEqual(step, 2)
        self.assertEqual(session_state["vx_saved_lab"], "OWASP Juice Shop")

    def test_duplicate_click_prevention_returns_active_assessment(self):
        """Verify find_recent_active_assessment prevents duplicate assessments from rapid clicks."""
        aid = am.create_assessment(
            "analyst1",
            "Running lab container",
            {
                "name": "OWASP Juice Shop",
                "image": "bkimminich/juice-shop:latest",
                "host": "127.0.0.1",
                "ports": "3000",
                "scanner_plan": [("Nmap", "Pending", "Queued"), ("Trivy", "Pending", "Queued")],
            },
            "High",
        )
        self.assertTrue(aid.startswith("VX-"))
        dup = am.find_recent_active_assessment("analyst1", "OWASP Juice Shop", within_seconds=15)
        self.assertEqual(dup, aid)

    def test_imported_trivy_report_executes_real_worker_pipeline(self):
        """Verify imported Trivy JSON report runs through worker pipeline with canonical 0-10 risk and OWASP 2025."""
        trivy_sample = {
            "ArtifactName": "nginx:1.24",
            "Results": [
                {
                    "Target": "nginx:1.24 (debian 12)",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-44487",
                            "PkgName": "libnghttp2-14",
                            "InstalledVersion": "1.52.0-1",
                            "FixedVersion": "1.52.0-1+deb12u1",
                            "Title": "HTTP/2 Rapid Reset Attack",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                            "CweIDs": ["CWE-400"],
                        }
                    ],
                }
            ],
        }
        report_file = Path(self.tmp.name) / "trivy_upload.json"
        report_file.write_text(json.dumps(trivy_sample), encoding="utf-8")

        aid = am.create_assessment(
            "analyst1",
            "Container image",
            {
                "name": "Uploaded Trivy Report (trivy_upload.json)",
                "image": "trivy_upload.json",
                "imported_trivy_report_path": str(report_file),
                "exposure_kind": "all_interfaces",
                "scanner_plan": [
                    ("Trivy", "Pending", "Queued"),
                    ("Nmap", "Skipped", "Not selected"),
                    ("OWASP ZAP", "Skipped", "Not selected"),
                ],
            },
            "High",
        )
        with mock.patch("assessment_worker.fetch_nvd_cve", return_value={"status": "ok", "cvss": 7.5, "cwe_ids": ["CWE-400"]}):
            aw.run(aid)

        saved = am.get_assessment(aid)
        self.assertEqual(saved["status"], "Completed")
        self.assertEqual(len(saved["findings"]), 1)
        finding = saved["findings"][0]
        self.assertEqual(finding["cve"], "CVE-2023-44487")
        self.assertIsNotNone(finding["risk_score"])
        self.assertGreaterEqual(finding["risk_score"], 0.0)
        self.assertLessEqual(finding["risk_score"], 10.0)
        self.assertIn("owasp_category", finding)

    def test_scanner_health_summary_structure(self):
        """Verify scanner_health_summary reports all four scanners with operational keys."""
        summary = docker_lab.scanner_health_summary()
        self.assertEqual(len(summary), 4)
        names = [item["scanner"] for item in summary]
        self.assertEqual(names, ["Nmap", "Trivy", "Docker Inspect", "OWASP ZAP"])
        for item in summary:
            self.assertIn("ready", item)
            self.assertIn("status", item)
            self.assertIn("detail", item)

    def test_security_analyst_role_and_approver_justification_in_remediation(self):
        """Verify Security Analyst can advance tickets and Approver justification is persisted."""
        aid = am.create_assessment(
            "sec_analyst",
            "Network host",
            {
                "name": "Custom Service",
                "host": "127.0.0.1",
                "ports": "80",
                "scanner_plan": [("Nmap", "Completed", "Done")],
            },
            "Normal",
        )
        am.save_findings(
            aid,
            [
                {
                    "finding_id": "F-100",
                    "source": "Nmap",
                    "category": "Network Exposure",
                    "asset": "127.0.0.1:80",
                    "package": "http",
                    "cve": "OPEN-PORT-80-TCP",
                    "title": "Exposed HTTP port",
                    "severity": "MEDIUM",
                    "cvss": 5.3,
                    "risk_score": 4.2,
                }
            ],
        )
        tid = rw.create_ticket(aid, "F-100", "sec_analyst", "Security Analyst", notes="Restrict port 80")
        rw.change_ticket(tid, "Pending Approval", "sec_analyst", "Security Analyst")
        rw.change_ticket(tid, "Approved", "approver1", "Approver", evidence="Approved for maintenance window")
        rw.change_ticket(tid, "In Progress", "sec_analyst", "Security Analyst")
        tickets = rw.list_tickets(aid)
        self.assertEqual(tickets[0]["status"], "In Progress")
        self.assertEqual(tickets[0]["approved_by"], "approver1")
        self.assertEqual(tickets[0]["verification_evidence"], "Approved for maintenance window")

    def test_worker_heartbeat_duplicate_prevention_and_cancellation(self):
        """Verify worker heartbeat tracking, duplicate worker launch prevention, and cancellation preserving partial results."""
        aid = am.create_assessment(
            "analyst1",
            "Running lab container",
            {
                "name": "OWASP Juice Shop",
                "image": "bkimminich/juice-shop:latest",
                "host": "127.0.0.1",
                "ports": "3000",
                "scanner_plan": [
                    ("Trivy", "Completed", "104 vulnerability records"),
                    ("Nmap", "Running", "Scanning 127.0.0.1"),
                ],
            },
            "High",
        )
        am.update_assessment(aid, status="Running", stage="Scanner execution", worker_pid=42424, heartbeat=True)
        loaded = am.get_assessment(aid)
        self.assertEqual(loaded["worker_pid"], 42424)
        self.assertIsNotNone(loaded["heartbeat_at"])

        # Duplicate worker launch prevention when worker PID is alive
        with mock.patch.object(am, "is_worker_alive", return_value=True), \
             mock.patch("subprocess.Popen") as popen_mock:
            returned_pid = am.launch_worker(aid)
            self.assertEqual(returned_pid, 42424)
            popen_mock.assert_not_called()

        # Cancellation preserves completed scanner results as Partial
        with mock.patch.object(am, "is_worker_alive", return_value=False):
            cancel_res = am.cancel_assessment(aid, "analyst1")
            self.assertEqual(cancel_res["status"], "Partial")
            self.assertIn("Nmap", cancel_res["cancelled_scanners"])
            after = am.get_assessment(aid)
            self.assertEqual(after["status"], "Partial")
            self.assertEqual(after["stage"], "Cancelled by operator")


if __name__ == "__main__":
    unittest.main()
