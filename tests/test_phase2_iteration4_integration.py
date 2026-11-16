"""Offline integration checks: real SQLite/worker lifecycle, mocked external scanner boundaries."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import assessment_manager as m
import assessment_worker as w


def finding(fid, source, kind='Exposure', severity='INFO'):
    return {'finding_id':fid,'source':source,'finding_type':kind,'severity':severity,
            'title':fid,'asset':'127.0.0.1','evidence':{},'cve':'', 'risk_label':'Unscored'}

class WorkerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.old_db=m.DB_PATH
        self.old_report=w.REPORT_DIR
        m.DB_PATH=Path(self.temp.name)/'assessments.sqlite'
        w.REPORT_DIR=Path(self.temp.name)/'reports'
        self.patches=[patch.object(w,'get_nvd_cache_sqlite',return_value={}),
                      patch.object(w,'put_nvd_cache_sqlite'),
                      patch.object(w,'log_event'),
                      patch.object(w,'correlate_findings',side_effect=lambda rows:(rows,[])),
                      patch.object(w,'_risk',side_effect=lambda f,*args:f)]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        m.DB_PATH=self.old_db
        w.REPORT_DIR=self.old_report
        self.temp.cleanup()
    def assessment(self, scanners, **target):
        payload={'name':'authorized localhost','nmap_host':'127.0.0.1','ports':'3000',
                 'exposure_kind':'loopback','scanner_plan':[(s,'Pending','') for s in scanners], **target}
        return m.create_assessment('alice','Local host',payload)
    def test_nmap_success_persists_exposure_and_attempt(self):
        aid=self.assessment(['Nmap'])
        with patch.object(w,'scan_target',return_value={'open_ports':[3000]}), \
             patch.object(w,'normalize_nmap_result',return_value=[finding('port-3000','Nmap')]):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Completed')
        self.assertEqual(result['scanners'][0]['status'],'Completed')
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['attempts'][0]['status'],'Completed')
    def test_scanner_failure_records_error_and_failed_assessment(self):
        aid=self.assessment(['Nmap'])
        with patch.object(w,'scan_target',side_effect=TimeoutError('Nmap exceeded timeout')):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Failed')
        self.assertIn('timeout',result['scanners'][0]['message'])
        self.assertEqual(result['attempts'][0]['status'],'Failed')
    def test_partial_result_retained_when_zap_fails(self):
        aid=self.assessment(['Nmap','OWASP ZAP'],zap_app='OWASP Juice Shop')
        with patch.object(w,'scan_target',return_value={'open_ports':[3000]}), \
             patch.object(w,'normalize_nmap_result',return_value=[finding('port','Nmap')]), \
             patch.object(w,'run_zap_baseline_scan',side_effect=RuntimeError('ZAP container missing')):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Partial')
        self.assertEqual([x['status'] for x in result['scanners']],['Completed','Failed'])
        self.assertEqual([x['source'] for x in result['findings']],['Nmap'])
    def test_retry_only_failed_zap_preserves_nmap_and_attempt_history(self):
        aid=self.assessment(['Nmap','OWASP ZAP'],zap_app='OWASP Juice Shop')
        with patch.object(w,'scan_target',return_value={'open_ports':[3000]}), \
             patch.object(w,'normalize_nmap_result',return_value=[finding('port','Nmap')]), \
             patch.object(w,'run_zap_baseline_scan',side_effect=RuntimeError('temporary failure')):
            w.run(aid)
        self.assertEqual(m.retry_failed_scanners(aid,'alice'),['OWASP ZAP'])
        report=Path(self.temp.name)/'zap.json';report.write_text('{}')
        with patch.object(w,'scan_target',side_effect=AssertionError('Nmap must not rerun')), \
             patch.object(w,'run_zap_baseline_scan',return_value={'report_path':str(report),'report_name':'zap.json','target_url':'http://localhost:3000/','alert_count':1}), \
             patch.object(w,'normalize_zap_report',return_value=[finding('zap-1','OWASP ZAP','Vulnerability','LOW')]):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Completed')
        self.assertEqual(len(result['findings']),2)
        self.assertEqual(len(result['attempts']),3)
        self.assertEqual([a['status'] for a in result['attempts'] if a['scanner']=='OWASP ZAP'],['Failed','Completed'])
    def test_retry_does_not_duplicate_zap_findings(self):
        aid=self.assessment(['OWASP ZAP'],zap_app='OWASP Juice Shop')
        old=finding('zap-1','OWASP ZAP','Vulnerability','LOW')
        m.save_findings(aid,[old])
        m.update_scanner(aid,'OWASP ZAP','Running')
        m.update_scanner(aid,'OWASP ZAP','Failed','interrupted')
        m.update_assessment(aid,'Partial')
        m.retry_failed_scanners(aid,'alice')
        report=Path(self.temp.name)/'zap.json';report.write_text('{}')
        with patch.object(w,'run_zap_baseline_scan',return_value={'report_path':str(report),'report_name':'zap.json','target_url':'http://localhost:3000/','alert_count':1}), \
             patch.object(w,'normalize_zap_report',return_value=[old]):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Completed')
        self.assertEqual(len(result['findings']),1)
    def test_processing_failure_keeps_scanner_findings(self):
        aid=self.assessment(['Nmap'])
        with patch.object(w,'scan_target',return_value={'open_ports':[3000]}), \
             patch.object(w,'normalize_nmap_result',return_value=[finding('port','Nmap')]), \
             patch.object(w,'correlate_findings',side_effect=RuntimeError('correlation failed')):
            w.run(aid)
        result=m.get_assessment(aid)
        self.assertEqual(result['status'],'Partial')
        self.assertEqual(len(result['findings']),1)
        self.assertIn('correlation failed',result['error'])
    def test_timeout_configuration_passed_to_nmap(self):
        aid=self.assessment(['Nmap'])
        with patch.dict(w.os.environ,{'VULNX_NMAP_TIMEOUT':'42'}), \
             patch.object(w,'scan_target',return_value={'open_ports':[]}) as scan, \
             patch.object(w,'normalize_nmap_result',return_value=[]):
            w.run(aid)
        self.assertEqual(scan.call_args.kwargs['timeout_seconds'],42)

if __name__=='__main__':unittest.main()
