import unittest
from unittest.mock import patch
import security_controls as sc

class Phase6SecurityTests(unittest.TestCase):
    def setUp(self):
        sc._FAILURES.clear()
        sc._BLOCKED.clear()

    def test_login_throttle_after_five_failures(self):
        for i in range(5):
            self.assertTrue(sc.login_allowed('test', now=100+i))
            sc.record_login_attempt('test', False, now=100+i)
        self.assertFalse(sc.login_allowed('test', now=105))
        self.assertTrue(sc.login_allowed('test', now=500))

    def test_success_resets_failed_attempts(self):
        sc.record_login_attempt('user', False, now=10)
        sc.record_login_attempt('user', True, now=11)
        self.assertEqual(sc._FAILURES.get('user'), None)

    def test_redacts_nested_secrets(self):
        obj = {'token':'abc', 'meta':{'api_key':'xyz', 'event':'ok'}}
        safe = sc.redact_audit_details(obj)
        self.assertEqual(safe['token'], '[REDACTED]')
        self.assertEqual(safe['meta']['api_key'], '[REDACTED]')
        self.assertEqual(safe['meta']['event'], 'ok')

    def test_redaction_limits_recursion(self):
        obj = {'a': {'b': {'c': {'d': {'e': {'f': 'g'}}}}}}
        self.assertIn('truncated', str(sc.redact_audit_details(obj)))

    def test_csv_formula_escaping(self):
        for v in ('=SUM(1,2)', '+cmd', '-cmd', '@foo', '  =2'):
            self.assertTrue(sc.csv_cell(v).startswith("'"))
        self.assertEqual(sc.csv_cell('ordinary'), 'ordinary')

    def test_deployment_warnings(self):
        with patch.dict('os.environ', {'VULNX_DEMO_MODE':'1'}):
            self.assertTrue(any('Demo accounts' in x for x in sc.deployment_warnings()))

class Phase6ExportIntegrationTests(unittest.TestCase):
    def test_phase3_csv_escapes_scanner_title(self):
        from phase3_analysis import export_csv
        csv_data = export_csv([{'finding_id':'id','title':'=HYPERLINK("bad")'}])
        self.assertIn("'=HYPERLINK", csv_data)

    def test_findings_csv_escapes_asset(self):
        from assessment_views import findings_csv
        csv_data = findings_csv([{'source':'Trivy','asset':'=1+1','title':'example'}])
        self.assertIn("'=1+1", csv_data)

    def test_audit_log_redacts_secret_before_persistence(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import audit_log
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(audit_log, 'DB_PATH', Path(tmp)/'audit.db'):
                audit_log.log_event('admin','Admin','test',details={'password':'abc','nested':{'token':'xyz'}})
                events = audit_log.get_audit_events(actor_role='Admin')
                self.assertEqual(events[0]['details']['password'], '[REDACTED]')
                self.assertEqual(events[0]['details']['nested']['token'], '[REDACTED]')
