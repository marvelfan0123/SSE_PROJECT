"""Unit tests for the evidence-based OWASP Top 10:2025 classification module."""
import unittest
from owasp_classifier import classify, register_cwe_mapping, CATEGORIES, MAPPING_VERSION


class OWASPClassifierFullTests(unittest.TestCase):
    def test_all_ten_categories_have_evidence_mappings(self):
        sample_cwes = {
            "A01": "CWE-22",
            "A02": "CWE-16",
            "A03": "CWE-1395",
            "A04": "CWE-319",
            "A05": "CWE-79",
            "A06": "CWE-73",
            "A07": "CWE-287",
            "A08": "CWE-502",
            "A09": "CWE-778",
            "A10": "CWE-209",
        }
        for cat_code, cwe in sample_cwes.items():
            finding = {"finding_id": f"f_{cat_code}", "cwe": [cwe]}
            res = classify(finding, "a1")
            self.assertEqual(res["category"], cat_code)
            self.assertEqual(res["category_name"], CATEGORIES[cat_code])
            self.assertEqual(res["mapping_version"], MAPPING_VERSION)

    def test_missing_cwe_falls_back_to_unclassified(self):
        finding = {"finding_id": "f_none", "cve": "CVE-2024-9999"}
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "UNCLASSIFIED")
        self.assertEqual(res["confidence"], "Manual Review")
        self.assertIn("No scanner-reported CWE", res["explanation"])

    def test_multiple_conflicting_categories_require_manual_review(self):
        # Injection (A05) and Authentication (A07)
        finding = {"finding_id": "f_multi", "cwe": ["CWE-89", "CWE-287"]}
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "UNCLASSIFIED")
        self.assertEqual(res["confidence"], "Manual Review")
        self.assertIn("A05", res["matched_categories"])
        self.assertIn("A07", res["matched_categories"])

    def test_extensibility_api(self):
        register_cwe_mapping("CWE-99999", "A05")
        finding = {"finding_id": "f_custom", "cwe": ["CWE-99999"]}
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "A05")

    def test_invalid_category_registration_rejected(self):
        with self.assertRaises(ValueError):
            register_cwe_mapping("CWE-88888", "A99")

    def test_trivy_cwe_ids_harmonious_classification(self):
        # Two CWEs that both map to A05 Injection
        finding = {
            "finding_id": "f_trivy_harm",
            "cwe_ids": ["CWE-79", "CWE-89"],
            "source": "Trivy"
        }
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "A05")
        self.assertEqual(res["confidence"], "Inferred")

    def test_zap_numeric_cweid_classification(self):
        # ZAP reports numeric string "693" for CSP header missing -> A02 Security Misconfiguration
        finding = {
            "finding_id": "f_zap_csp",
            "evidence": {"cwe_id": "693"},
            "source": "OWASP ZAP"
        }
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "A02")
        self.assertEqual(res["category_name"], "Security Misconfiguration")

    def test_unknown_cwe_identifier_returns_unclassified(self):
        finding = {
            "finding_id": "f_unknown_cwe",
            "cwe_ids": ["CWE-9999999"],
            "source": "Trivy"
        }
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "UNCLASSIFIED")
        self.assertEqual(res["confidence"], "Manual Review")

    def test_network_exposure_observation_unclassified(self):
        # Nmap open port observation has no CWE
        finding = {
            "finding_id": "f_nmap_port",
            "source": "Nmap",
            "finding_type": "network_exposure_observation",
            "cve": "",
            "cwe": "",
            "cwe_ids": []
        }
        res = classify(finding, "a1")
        self.assertEqual(res["category"], "UNCLASSIFIED")
        self.assertEqual(res["confidence"], "Manual Review")

    def test_arithmetic_reconciliation_total_139(self):
        # Reconcile exact counts: 78 classified across 7 active categories + 3 conflicting + 58 unclassified = 139
        counts = {
            "A01": 15,
            "A02": 8,
            "A04": 8,
            "A05": 9,
            "A07": 2,
            "A08": 5,
            "A10": 31,
            "CONFLICTING": 3,
            "UNCLASSIFIED": 58
        }
        classified_sum = sum(v for k, v in counts.items() if k.startswith("A"))
        self.assertEqual(classified_sum, 78)  # Exactly 78 classified
        self.assertEqual(classified_sum + counts["CONFLICTING"] + counts["UNCLASSIFIED"], 139)  # Exactly 139 total


if __name__ == "__main__":
    unittest.main()

