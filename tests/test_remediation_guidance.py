import unittest
from remediation_guidance import build_remediation_guidance, validate_approval, validate_resolution

class RemediationGuidanceTests(unittest.TestCase):
    def test_fixed_version_plan_mentions_update_and_rescan(self):
        plan = build_remediation_guidance({"Package":"demo", "CVE":"CVE-2025-0001", "Installed Version":"1.0", "Fixed Version":"1.2", "Target":"lab", "Severity":"HIGH"})
        joined = " ".join(plan["steps"]).lower()
        self.assertIn("1.2", joined)
        self.assertIn("re-scan", joined)
    def test_no_fix_does_not_invent_version(self):
        plan = build_remediation_guidance({"Package":"demo", "CVE":"GHSA-example", "Installed Version":"1.0", "Fixed Version":"No fix listed"})
        self.assertTrue(any("no fixed version" in step.lower() for step in plan["steps"]))
    def test_approval_required_for_approved_and_in_progress(self):
        with self.assertRaises(ValueError): validate_approval("Approved", "")
        self.assertTrue(validate_approval("Approved", "Reviewer A"))
        with self.assertRaises(ValueError): validate_approval("In Progress", "")
        self.assertTrue(validate_approval("In Progress", "Reviewer A"))
        self.assertTrue(validate_approval("Pending", ""))
    def test_resolution_requires_valid_verification_status(self):
        with self.assertRaises(ValueError): validate_resolution("Not verified", "scan-123")
        with self.assertRaises(ValueError): validate_resolution("Still present", "scan-123")
    def test_resolution_requires_evidence(self):
        with self.assertRaises(ValueError): validate_resolution("Pass", "  ")
        self.assertTrue(validate_resolution("Pass", "scan ID 123; report.json"))
        self.assertTrue(validate_resolution("Pass", "Fresh scan evidence: report-123.json"))

if __name__ == "__main__": unittest.main()
