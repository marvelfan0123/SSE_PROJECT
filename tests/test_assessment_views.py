import unittest
from assessment_views import visible_assessments, assessment_ready, findings_for, severity_counts, findings_csv, unique_assets

class AssessmentViewsTests(unittest.TestCase):
    def test_no_results_before_completion(self):
        a = {"status": "Running", "findings": [{"severity": "HIGH"}]}
        self.assertFalse(assessment_ready(a))
        self.assertEqual(findings_for(a), [])

    def test_partial_assessment_exposes_only_persisted_findings(self):
        a = {"status": "Partial", "findings": [{"severity": "HIGH", "asset": "lab"}]}
        self.assertEqual(len(findings_for(a)), 1)

    def test_role_filter(self):
        items = [{"created_by": "a"}, {"created_by": "b"}]
        self.assertEqual(len(visible_assessments(items, "a", "Analyst")), 1)
        self.assertEqual(len(visible_assessments(items, "a", "Admin")), 2)

    def test_empty_csv_has_header(self):
        self.assertIn("Contextual risk", findings_csv([]))

    def test_asset_dedup_and_severity(self):
        findings = [{"asset": "x", "severity": "HIGH"}, {"asset": "x", "severity": "LOW"}]
        self.assertEqual(unique_assets(findings), ["x"])
        self.assertEqual(severity_counts(findings)["HIGH"], 1)

if __name__ == "__main__":
    unittest.main()
