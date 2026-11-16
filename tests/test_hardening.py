import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import asset_discovery
import finding_normalization
import nvd_enrichment


class InputHardeningTests(unittest.TestCase):
    def test_non_ascii_digits_rejected_cleanly(self):
        with self.assertRaises(ValueError):
            asset_discovery._validate_ports("\u00b2")

    def test_public_and_hostname_targets_rejected(self):
        for target in ("8.8.8.8", "example.com", "-oX", ""):
            with self.assertRaises(ValueError):
                asset_discovery._validate_target(target)
        self.assertEqual(asset_discovery._validate_target("192.168.1.5"), "192.168.1.5")

    def test_port_limit(self):
        with self.assertRaises(ValueError):
            asset_discovery._validate_ports(",".join(str(p) for p in range(1, 32)))

    def test_non_dict_trivy_json_returns_no_findings(self):
        self.assertEqual(finding_normalization.normalize_trivy_report([1, 2, 3]), [])


class NvdRateLimitTests(unittest.TestCase):
    def test_batch_stops_after_rate_limit(self):
        calls = []

        def fake_fetch(cve, api_key=None, timeout=15):
            calls.append(cve)
            if len(calls) == 2:
                return {"cve": cve, "status": "error", "error": "NVD rate limit reached."}
            return {"cve": cve, "status": "enriched", "cvss_score": 5}

        with tempfile.TemporaryDirectory() as tmp, patch.object(nvd_enrichment, "fetch_nvd_cve", fake_fetch):
            path = Path(tmp) / "cache.json"
            _, results, remaining = nvd_enrichment.enrich_cve_batch(
                ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"], path, limit=10, delay_seconds=0
            )
        self.assertEqual(len(calls), 2)
        self.assertEqual(remaining, 2)


if __name__ == "__main__":
    unittest.main()

class ScannerTimeoutBoundsTests(unittest.TestCase):
    def test_trivy_timeout_is_bounded(self):
        import trivy_scanner
        with self.assertRaisesRegex(ValueError, "between 30 and 3600"):
            trivy_scanner.run_trivy_image_scan("python:3.12-slim", ".", timeout_seconds=999999)

    def test_zap_timeout_is_bounded(self):
        import zap_scanner
        with self.assertRaisesRegex(ValueError, "between 60 and 3600"):
            zap_scanner.run_zap_baseline_scan("DVWA", ".", timeout_seconds=999999)

    def test_nmap_timeout_is_bounded_before_scanner_launch(self):
        import asset_discovery
        with self.assertRaisesRegex(ValueError, "between 10 and 600"):
            asset_discovery.scan_target("127.0.0.1", "80", timeout_seconds=999999)


class NvdIdentifierValidationTests(unittest.TestCase):
    def test_rejects_malformed_cve_identifiers(self):
        import nvd_enrichment
        for value in ("CVE-", "CVE-2025-abc", "CVE-2025-1234;evil"):
            with self.subTest(value=value):
                self.assertEqual(nvd_enrichment.fetch_nvd_cve(value)["status"], "skipped_non_cve")
