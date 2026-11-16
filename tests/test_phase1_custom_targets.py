import os
import unittest
from unittest.mock import patch
from assessment_portal import make_plan, validate_host, validate_local_web_url

class Phase1CustomTargets(unittest.TestCase):
    def test_custom_host_multiple_ports(self):
        plan = make_plan('Local host', None, 'Normal', custom_host='127.0.0.1', custom_ports='3000,8081', run_trivy=False, run_zap=False)
        self.assertEqual(plan['nmap_host'], '127.0.0.1')
        self.assertEqual(plan['ports'], '3000,8081')
        self.assertEqual(plan['name'], '127.0.0.1')
        self.assertEqual([x[1] for x in plan['scanner_plan']], ['Skipped','Pending','Skipped'])
    def test_custom_web_lab(self):
        plan = make_plan('Local web application', None, 'High', custom_url='http://localhost:3000/', run_trivy=False)
        self.assertEqual(plan['zap_app'], 'OWASP Juice Shop')
        self.assertEqual(plan['ports'], '3000')
        self.assertEqual([x[1] for x in plan['scanner_plan']], ['Skipped','Pending','Pending'])
    def test_dvwa_web_lab(self):
        self.assertEqual(validate_local_web_url('http://127.0.0.1:8081/')[2], 'DVWA')
    def test_reject_unsafe_urls(self):
        for url in ['https://example.com/', 'http://localhost:8501/', 'http://localhost:3000@evil.test/', 'http://localhost:3000/admin', 'http://localhost:3000/?x=1']:
            with self.subTest(url=url), self.assertRaises(ValueError): validate_local_web_url(url)
    def test_reject_bad_ports(self):
        for ports in ['-1', '0', '65536', '3000;whoami', '', '1-65535']:
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                make_plan('Local host', None, 'Normal', custom_host='127.0.0.1', custom_ports=ports)
    def test_private_requires_allowlist(self):
        with patch.dict(os.environ, {'VULNX_ALLOWED_HOSTS': ''}):
            with self.assertRaises(ValueError): validate_host('192.168.1.10')
        with patch.dict(os.environ, {'VULNX_ALLOWED_HOSTS': '192.168.1.10'}):
            self.assertEqual(validate_host('192.168.1.10'), '192.168.1.10')
    def test_public_not_allowed_even_if_listed(self):
        with patch.dict(os.environ, {'VULNX_ALLOWED_HOSTS': '8.8.8.8'}):
            with self.assertRaises(ValueError): validate_host('8.8.8.8')
    def test_wrong_mode_rejected(self):
        with self.assertRaises(ValueError): make_plan('Docker image', None, 'Normal', custom_host='127.0.0.1')
        with self.assertRaises(ValueError): make_plan('Local host', None, 'Normal', custom_url='http://localhost:3000/')
