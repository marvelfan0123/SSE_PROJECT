import unittest
from scan_flow import allowed_pages, landing_page, coverage_comparable, results_unlocked

class ResolvedFlowTests(unittest.TestCase):
    def test_can_start_another_scan_while_running(self):
        self.assertIn('New Assessment',allowed_pages({'status':'Running'},'Analyst'))
        self.assertFalse(results_unlocked({'status':'Running'}))
    def test_failed_scan_does_not_publish_results(self):
        self.assertFalse(results_unlocked({'status':'Failed'}))
    def test_partial_has_results_with_coverage_warning_required_in_ui(self):
        self.assertTrue(results_unlocked({'status':'Partial'}))
    def test_verification_requires_matching_coverage(self):
        a={'status':'Completed','target_type':'Docker image','target_name':'Juice Shop','scanners':[{'scanner':'Trivy','status':'Completed'}]}
        self.assertTrue(coverage_comparable(a,dict(a)))
        self.assertFalse(coverage_comparable(a,dict(a,status='Partial')))
        self.assertFalse(coverage_comparable(a,dict(a,scanners=[{'scanner':'Nmap','status':'Completed'}])))
    def test_no_successful_scanner_is_not_comparable(self):
        a={'status':'Completed','target_type':'Host','target_name':'local','scanners':[]}
        self.assertFalse(coverage_comparable(a,a))
