import unittest
from finding_normalization import normalize_trivy_report
from phase3_analysis import analyze_findings, export_csv


class CvssPipelineRepairTests(unittest.TestCase):
    def _findings(self):
        return normalize_trivy_report({"Results": [{"Target": "node:18-bullseye", "Type": "debian", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-12345", "PkgName": "libx", "InstalledVersion": "1", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 8.7, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}},
            {"VulnerabilityID": "CVE-2024-12346", "PkgName": "liby", "InstalledVersion": "2", "Severity": "CRITICAL"}
        ]}]})

    def test_trivy_cvss_preserved_with_provenance(self):
        f = self._findings()[0]
        self.assertEqual(f["cvss"], 8.7)
        self.assertEqual(f["cvss_source"], "nvd")
        self.assertEqual(f["cvss_version"], "3")
        self.assertTrue(f["cvss_vector"].startswith("CVSS:3.1"))

    def test_unknown_exposure_has_base_scores_but_not_contextual(self):
        a = analyze_findings(self._findings(), exposure="unknown", criticality="Normal")
        self.assertTrue(all(x["risk_score"] is not None for x in a))
        self.assertEqual(sorted(x["base_score"] for x in a), [8.7, 9.5])
        self.assertIn("Trivy CVSS", [x["base_score_source"] for x in a])
        self.assertTrue(any("Severity estimate" in x["base_score_source"] for x in a))

    def test_verified_loopback_scores(self):
        a = analyze_findings(self._findings(), exposure="loopback", criticality="Normal")
        self.assertEqual(len([x for x in a if x["risk_score"] is not None]), 2)
        self.assertIn("base_score_source", export_csv(a))

    def test_invalid_cvss_does_not_become_trusted(self):
        f = normalize_trivy_report({"Results": [{"Target": "x", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-12345", "PkgName": "x", "Severity": "LOW", "CVSS": {"nvd": {"V3Score": 15}}}]}]})[0]
        self.assertIsNone(f["cvss"])

if __name__ == "__main__":
    unittest.main()
