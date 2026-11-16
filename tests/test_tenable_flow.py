import json
import unittest
from scan_flow import allowed_pages, landing_page, results_unlocked, dashboard_metrics
from report_import import validate_trivy_json

class TenableFlowTests(unittest.TestCase):
    def test_first_page_is_dashboard(self):
        self.assertEqual(landing_page(None), 'Dashboard')
    def test_empty_dashboard_not_scanned(self):
        m = dashboard_metrics(None)
        self.assertEqual(m['total'], 0)
        self.assertEqual(m['status'], 'Not Scanned')
    def test_pages_visible_before_scan_but_results_locked(self):
        self.assertIn('Vulnerability Findings', allowed_pages(None, 'Analyst'))
        self.assertFalse(results_unlocked(None))
        self.assertFalse(results_unlocked({'status':'Failed'}))
        self.assertTrue(results_unlocked({'status':'Completed'}))
    def test_import_rejects_unrecognized_json(self):
        with self.assertRaises(ValueError):
            validate_trivy_json(b'{"unrelated":true}')
    def test_import_accepts_trivy_shape(self):
        report = validate_trivy_json(json.dumps({'Results':[{'Target':'image','Vulnerabilities':[]}]}).encode())
        self.assertEqual(report['Results'][0]['Target'],'image')
    def test_import_rejects_oversize(self):
        with self.assertRaises(ValueError):
            validate_trivy_json(b' ' * (5*1024*1024 + 1))
