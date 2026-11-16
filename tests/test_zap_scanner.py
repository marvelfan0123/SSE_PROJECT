import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zap_scanner
from finding_normalization import normalize_zap_report


SAMPLE_REPORT = {
    "site": [{
        "@name": "http://host.docker.internal:3000",
        "alerts": [{
            "pluginid": "10021",
            "alert": "X-Content-Type-Options Header Missing",
            "riskcode": "1",
            "riskdesc": "Low (Medium)",
            "confidence": "Medium",
            "desc": "The response does not include the expected header.",
            "solution": "Configure the response header.",
            "reference": "https://owasp.org/",
            "cweid": "693",
            "instances": [{"uri": "http://host.docker.internal:3000/", "method": "GET", "param": "", "evidence": ""}],
        }]
    }]
}


class ZapScannerTests(unittest.TestCase):
    def test_only_configured_lab_apps_are_allowed(self):
        self.assertEqual(zap_scanner.validate_zap_target("OWASP Juice Shop")[1], "http://host.docker.internal:3000/")
        with self.assertRaises(ValueError):
            zap_scanner.validate_zap_target("https://example.com")
        with self.assertRaises(ValueError):
            zap_scanner.validate_zap_target("http://127.0.0.1:3000/")

    def test_requires_docker(self):
        with patch.object(zap_scanner.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Docker CLI was not found"):
                zap_scanner.run_zap_baseline_scan("DVWA", tempfile.gettempdir())

    def test_runs_zap_container_and_validates_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(command, **kwargs):
                report_name = command[command.index("-J") + 1]
                (Path(tmp) / report_name).write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
                class Result:
                    returncode = 0
                    stdout = "ZAP baseline completed"
                    stderr = ""
                return Result()
            with patch.object(zap_scanner.shutil, "which", return_value="/usr/bin/docker"), \
                 patch.object(zap_scanner.subprocess, "run", side_effect=fake_run) as run:
                result = zap_scanner.run_zap_baseline_scan("OWASP Juice Shop", tmp)
            self.assertEqual(result["alert_count"], 1)
            self.assertTrue(Path(result["report_path"]).exists())
            command = run.call_args.args[0]
            self.assertIn("zap-baseline.py", command)
            self.assertIn("http://host.docker.internal:3000/", command)
            self.assertIn("-I", command)
            self.assertNotIn("zap-full-scan.py", command)

    def test_rejects_bad_report_or_docker_execution_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            def failed_run(command, **kwargs):
                class Result:
                    returncode = 3
                    stdout = ""
                    stderr = "execution error"
                return Result()
            with patch.object(zap_scanner.shutil, "which", return_value="docker"), \
                 patch.object(zap_scanner.subprocess, "run", side_effect=failed_run):
                with self.assertRaisesRegex(RuntimeError, "scan failed"):
                    zap_scanner.run_zap_baseline_scan("DVWA", tmp)

    def test_load_zap_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
            self.assertEqual(len(zap_scanner.load_zap_report(path)["site"]), 1)
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a ZAP report"):
                zap_scanner.load_zap_report(path)

    def test_normalizes_zap_alert_with_cwe_and_instance_evidence(self):
        records = normalize_zap_report(SAMPLE_REPORT, "zap-juice-shop.json", "OWASP Juice Shop")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["source"], "OWASP ZAP")
        self.assertEqual(record["finding_type"], "web_application_vulnerability")
        self.assertEqual(record["severity"], "LOW")
        self.assertEqual(record["cve"], "")
        self.assertEqual(record["evidence"]["cwe_id"], "693")
        self.assertEqual(record["evidence"]["instance_count"], 1)
        self.assertEqual(record["evidence"]["scan_mode"], "ZAP Baseline (passive checks)")


if __name__ == "__main__":
    unittest.main()
