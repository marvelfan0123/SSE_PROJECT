import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import assessment_manager as manager
import assessment_worker as worker
import audit_log

class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db, self.old_audit, self.old_report = manager.DB_PATH, audit_log.DB_PATH, worker.REPORT_DIR
        manager.DB_PATH = Path(self.tmp.name) / "assessments.sqlite"
        audit_log.DB_PATH = manager.DB_PATH
        worker.REPORT_DIR = Path(self.tmp.name) / "reports"

    def tearDown(self):
        manager.DB_PATH, audit_log.DB_PATH, worker.REPORT_DIR = self.old_db, self.old_audit, self.old_report
        self.tmp.cleanup()

    def assessment(self):
        return manager.create_assessment("admin", "Container image", {
            "name": "local-image", "image": "local-image:latest", "exposure_kind": "loopback",
            "scanner_plan": [("Trivy", "Pending", ""), ("Nmap", "Skipped", ""), ("OWASP ZAP", "Skipped", "")]
        })

    def test_timeout_valid(self):
        with patch.dict(os.environ, {"VULNX_TRIVY_TIMEOUT": "75"}):
            self.assertEqual(worker.scanner_timeout("TRIVY", 1800, 30, 3600), 75)

    def test_timeout_invalid_uses_default(self):
        for value in ("abc", "1", "99999"):
            with patch.dict(os.environ, {"VULNX_NMAP_TIMEOUT": value}):
                self.assertEqual(worker.scanner_timeout("NMAP", 120, 10, 600), 120)

    def test_scanner_failure_preserves_error_metadata(self):
        aid = self.assessment()
        with patch.object(worker, "run_trivy_image_scan", side_effect=RuntimeError("Trivy missing")):
            worker.run(aid)
        result = manager.get_assessment(aid)
        self.assertEqual(result["status"], "Failed")
        scanner = result["scanners"][0]
        self.assertEqual(scanner["status"], "Failed")
        self.assertEqual(scanner["result"]["error_type"], "RuntimeError")
        self.assertIn("Trivy missing", scanner["message"])

    def test_completed_scan_survives_enrichment_error(self):
        aid = self.assessment()
        def fake_trivy(image, directory, **kwargs):
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"Results": [{"Target": "image", "Vulnerabilities": [{
                "VulnerabilityID": "GHSA-example", "PkgName": "pkg", "Severity": "HIGH",
                "InstalledVersion": "1", "FixedVersion": "2"}]}]}))
            return {"report_path": path, "report_name": path.name}
        with patch.object(worker, "run_trivy_image_scan", side_effect=fake_trivy), \
             patch.object(worker, "get_nvd_cache_sqlite", side_effect=RuntimeError("DB temporarily unavailable")):
            worker.run(aid)
        result = manager.get_assessment(aid)
        self.assertEqual(result["status"], "Partial")
        self.assertEqual(result["scanners"][0]["status"], "Completed")
        self.assertEqual(len(result["findings"]), 1)

if __name__ == "__main__":
    unittest.main()
