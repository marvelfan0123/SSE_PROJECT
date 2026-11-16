import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nvd_enrichment import enrich_cve_batch, parse_nvd_response, save_cache, load_cache


class NvdEnrichmentTests(unittest.TestCase):
    def test_parse_cvss31_and_description(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-12345", "published": "2024-01-01", "lastModified": "2024-01-02",
            "descriptions": [{"lang": "en", "value": "Example description"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/test"}}]},
            "references": [{"url": "https://example.com/advisory"}]
        }}]}
        result = parse_nvd_response(payload, "CVE-2024-12345")
        self.assertEqual(result["status"], "enriched")
        self.assertEqual(result["cvss_score"], 8.8)
        self.assertEqual(result["cvss_version"], "3.1")
        self.assertEqual(result["description"], "Example description")
        self.assertEqual(result["references"], ["https://example.com/advisory"])

    def test_missing_cvss_is_allowed(self):
        result = parse_nvd_response({"vulnerabilities": [{"cve": {"id": "CVE-2024-12345"}}]}, "CVE-2024-12345")
        self.assertEqual(result["status"], "enriched")
        self.assertIsNone(result["cvss_score"])

    def test_not_found_response(self):
        result = parse_nvd_response({"vulnerabilities": []}, "CVE-2024-12345")
        self.assertEqual(result["status"], "not_found")

    def test_cache_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            save_cache(path, {"CVE-2024-12345": {"status": "enriched"}})
            self.assertEqual(load_cache(path)["CVE-2024-12345"]["status"], "enriched")

    def test_batch_skips_non_cve_and_uses_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            save_cache(path, {"CVE-2024-00001": {"cve": "CVE-2024-00001", "status": "enriched", "cvss_score": 7.0}})
            with patch("nvd_enrichment.fetch_nvd_cve", return_value={"cve": "CVE-2024-00002", "status": "not_found"}) as mocked:
                cache, results, remaining = enrich_cve_batch(["GHSA-abc", "CVE-2024-00001", "CVE-2024-00002"], path, limit=10, delay_seconds=0)
            mocked.assert_called_once()
            self.assertIn("CVE-2024-00002", cache)
            self.assertEqual(len(results), 1)
            self.assertEqual(remaining, 0)


if __name__ == "__main__":
    unittest.main()
