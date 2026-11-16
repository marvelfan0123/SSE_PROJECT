import unittest
from scan_flow import allowed_pages, landing_page, RESULT_PAGES, results_unlocked

class ScanFlowTests(unittest.TestCase):
    def test_fresh_user_starts_at_empty_dashboard(self):
        self.assertEqual(landing_page(None), 'Dashboard')
        self.assertIn('New Assessment', allowed_pages(None, 'Analyst'))
    def test_active_scan_shows_empty_result_pages(self):
        for status in ('Queued', 'Running', 'Processing findings'):
            a={'status':status}
            self.assertEqual(landing_page(a), 'Dashboard')
            self.assertFalse(results_unlocked(a))
            self.assertIn('Vulnerability Findings', allowed_pages(a,'Analyst'))
    def test_completed_scan_unlocks_results(self):
        self.assertTrue(results_unlocked({'status':'Completed'}))
        self.assertTrue(results_unlocked({'status':'Partial'}))
    def test_failed_scan_does_not_unlock_results(self):
        self.assertFalse(results_unlocked({'status':'Failed'}))
        self.assertIn('Scan Progress', allowed_pages({'status':'Failed'},'Analyst'))
    def test_admin_only_audit(self):
        self.assertIn('Audit Logs',allowed_pages(None,'Admin'))
        self.assertNotIn('Audit Logs',allowed_pages(None,'Analyst'))
