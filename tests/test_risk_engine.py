import unittest
from risk_engine import score_finding, prioritize_findings


class RiskEngineTests(unittest.TestCase):
    def setUp(self):
        self.finding = {"Severity": "HIGH", "CVE": "CVE-2024-12345", "Fixed Version": "2.0", "Package": "demo"}

    def test_uses_nvd_cvss_and_exposure_formula(self):
        cache = {"CVE-2024-12345": {"status": "enriched", "cvss_score": 9.8}}
        result = score_finding(self.finding, cache, exposure="Exposed")
        self.assertEqual(result["NVD CVSS"], 9.8)
        self.assertEqual(result["Raw Risk"], 14.7)
        self.assertEqual(result["Risk Score"], 98)
        self.assertEqual(result["Exposure Weight"], 1.5)
        self.assertEqual(result["CVSS Basis"], "NVD CVSS")
        self.assertIn("exposure weight", result["Why Prioritized"])

    def test_falls_back_to_labeled_severity_proxy(self):
        result = score_finding(self.finding, {}, exposure="Internal")
        self.assertEqual(result["Risk Score"], 53)
        self.assertEqual(result["NVD CVSS"], "")
        self.assertEqual(result["CVSS Basis"], "Severity proxy (not CVSS)")
        self.assertIn("not an NVD CVSS value", result["Why Prioritized"])

    def test_legacy_criticality_argument_does_not_change_score(self):
        cache = {"CVE-2024-12345": {"status": "enriched", "cvss_score": 8.0}}
        scores = [score_finding(self.finding, cache, level, "Internal")["Risk Score"]
                  for level in ["Low", "Medium", "High", "Critical", "Unassigned"]]
        self.assertEqual(scores, [53, 53, 53, 53, 53])

    def test_exposure_changes_score(self):
        cache = {"CVE-2024-12345": {"status": "enriched", "cvss_score": 8.0}}
        internal = score_finding(self.finding, cache, exposure="Internal")
        exposed = score_finding(self.finding, cache, exposure="Exposed")
        self.assertLess(internal["Risk Score"], exposed["Risk Score"])

    def test_score_is_bounded(self):
        finding = {"Severity": "CRITICAL", "CVE": "CVE-2024-12345", "Fixed Version": "9"}
        cache = {"CVE-2024-12345": {"status": "enriched", "cvss_score": 10}}
        self.assertEqual(score_finding(finding, cache, exposure="Exposed")["Risk Score"], 100)

    def test_priority_thresholds_match_normalized_formula(self):
        cache = {"CVE-2024-12345": {"status": "enriched", "cvss_score": 9.8}}
        internal = score_finding(self.finding, cache, exposure="Internal")
        exposed = score_finding(self.finding, cache, exposure="Exposed")
        self.assertEqual(internal["Risk Score"], 65)
        self.assertEqual(internal["Priority"], "P1 - Urgent")
        self.assertEqual(exposed["Priority"], "P1 - Urgent")

    def test_critical_severity_proxy_is_prioritized(self):
        finding = {"Severity": "CRITICAL", "CVE": "CVE-2024-12345", "Package": "demo"}
        result = score_finding(finding, {}, exposure="Internal")
        self.assertEqual(result["Risk Score"], 63)
        self.assertEqual(result["Priority"], "P1 - Urgent")

    def test_sorting_highest_score_first(self):
        low = {"Severity": "LOW", "CVE": "", "Fixed Version": ""}
        high = {"Severity": "CRITICAL", "CVE": "", "Fixed Version": "1"}
        rows = prioritize_findings([low, high])
        self.assertEqual(rows[0]["Severity"], "CRITICAL")

    def test_ties_break_by_severity(self):
        high = {"Severity": "HIGH", "CVE": "CVE-1", "Fixed Version": ""}
        medium = {"Severity": "MEDIUM", "CVE": "CVE-2", "Fixed Version": ""}
        rows = prioritize_findings([medium, high])
        self.assertGreaterEqual(rows[0]["Risk Score"], rows[1]["Risk Score"])


if __name__ == "__main__":
    unittest.main()
