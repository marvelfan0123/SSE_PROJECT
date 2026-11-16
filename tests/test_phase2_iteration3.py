import tempfile, unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
import assessment_manager as m

class RetryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.old=m.DB_PATH
        m.DB_PATH=Path(self.temp.name)/'db.sqlite'
        self.aid=m.create_assessment('alice','Local host',{'name':'localhost','scanner_plan':[('Nmap','Pending',''),('Trivy','Pending',''),('OWASP ZAP','Skipped','')]})
    def tearDown(self):
        m.DB_PATH=self.old; self.temp.cleanup()
    def test_retry_only_failed_and_keep_success(self):
        m.update_scanner(self.aid,'Nmap','Running'); m.update_scanner(self.aid,'Nmap','Completed','ok')
        m.update_scanner(self.aid,'Trivy','Running'); m.update_scanner(self.aid,'Trivy','Failed','unavailable')
        m.update_assessment(self.aid,'Partial')
        self.assertEqual(m.retry_failed_scanners(self.aid,'alice'),['Trivy'])
        x=m.get_assessment(self.aid)
        self.assertEqual([r['status'] for r in x['scanners']],['Completed','Pending','Skipped'])
        self.assertEqual(x['status'],'Queued')
        m.update_scanner(self.aid,'Trivy','Running'); m.update_scanner(self.aid,'Trivy','Completed')
        self.assertEqual(len(x['attempts']),2)
        self.assertEqual(len(m.get_assessment(self.aid)['attempts']),3)
    def test_reject_unauthorized_retry(self):
        m.update_scanner(self.aid,'Trivy','Failed'); m.update_assessment(self.aid,'Failed')
        with self.assertRaises(PermissionError): m.retry_failed_scanners(self.aid,'bob')
    def test_recovery_requires_stale(self):
        m.update_assessment(self.aid,'Running')
        with self.assertRaises(ValueError): m.recover_interrupted_assessment(self.aid,'alice')
    def test_recovery_stale(self):
        m.update_scanner(self.aid,'Nmap','Running'); m.update_assessment(self.aid,'Running')
        stale=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
        with m._db() as con: con.execute('UPDATE assessments SET updated_at=? WHERE assessment_id=?',(stale,self.aid))
        recovered=m.recover_interrupted_assessment(self.aid,'alice')
        self.assertCountEqual(recovered,['Nmap','Trivy'])
        self.assertEqual(m.get_assessment(self.aid)['status'],'Failed')
    def test_replace_findings_no_duplicate(self):
        finding={'finding_id':'f1','source':'Nmap','finding_type':'Exposure','severity':'INFO','title':'open','asset':'127.0.0.1'}
        m.replace_source_findings(self.aid,'Nmap',[finding])
        m.replace_source_findings(self.aid,'Nmap',[finding])
        self.assertEqual(len(m.get_assessment(self.aid)['findings']),1)
        m.replace_source_findings(self.aid,'Nmap',[])
        self.assertEqual(len(m.get_assessment(self.aid)['findings']),0)
if __name__=='__main__': unittest.main()
