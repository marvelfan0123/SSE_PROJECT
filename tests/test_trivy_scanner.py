import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import trivy_scanner


class TrivyScannerTests(unittest.TestCase):
    def test_validates_image_reference(self):
        self.assertEqual(trivy_scanner.validate_image_reference("python:3.12-slim"), "python:3.12-slim")
        for value in ("", "-evil", "python image", "../bad", "https://example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                trivy_scanner.validate_image_reference(value)

    def test_requires_trivy_on_path(self):
        with patch.object(trivy_scanner.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "not found on PATH"):
                trivy_scanner.run_trivy_image_scan("python:3.12-slim", tempfile.gettempdir())

    def test_runs_trivy_and_validates_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(command, **kwargs):
                output_index = command.index("--output") + 1
                Path(command[output_index]).write_text(json.dumps({
                    "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2025-1234"}]}]
                }), encoding="utf-8")
                class Result:
                    returncode = 0
                    stdout = "scan complete"
                    stderr = ""
                return Result()

            with patch.object(trivy_scanner.shutil, "which", return_value="/usr/bin/trivy"), \
                 patch.object(trivy_scanner.subprocess, "run", side_effect=fake_run) as run:
                result = trivy_scanner.run_trivy_image_scan(
                    "python:3.12-slim", tmp, severities=["HIGH", "CRITICAL"], include_unfixed=False
                )
            self.assertEqual(result["vulnerability_count"], 1)
            self.assertTrue(Path(result["report_path"]).exists())
            args = run.call_args.args[0]
            self.assertIn("--scanners", args)
            self.assertIn("vuln", args)
            self.assertIn("--ignore-unfixed", args)
            self.assertEqual(args[-1], "python:3.12-slim")

    def test_rejects_invalid_trivy_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(command, **kwargs):
                Path(command[command.index("--output") + 1]).write_text("{}", encoding="utf-8")
                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = ""
                return Result()
            with patch.object(trivy_scanner.shutil, "which", return_value="/usr/bin/trivy"), \
                 patch.object(trivy_scanner.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "invalid report"):
                    trivy_scanner.run_trivy_image_scan("python:3.12-slim", tmp)

    def test_fallback_to_docker_on_winerror_4551(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_docker_run(image, selected, include_unfixed, timeout_seconds, temporary_path):
                temporary_path.write_text(json.dumps({
                    "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-9999"}]}]
                }), encoding="utf-8")
                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = ""
                return Result()

            with patch.object(trivy_scanner.shutil, "which", return_value="C:\\trivy.exe"), \
                 patch.object(trivy_scanner.subprocess, "run", side_effect=OSError("[WinError 4551] An Application Control policy has blocked this file")), \
                 patch.object(trivy_scanner, "_is_docker_available", return_value=True), \
                 patch.object(trivy_scanner, "_run_docker_trivy", side_effect=fake_docker_run):
                result = trivy_scanner.run_trivy_image_scan("python:3.12-slim", tmp)
            self.assertEqual(result["vulnerability_count"], 1)
            self.assertTrue(Path(result["report_path"]).exists())


if __name__ == "__main__":
    unittest.main()
