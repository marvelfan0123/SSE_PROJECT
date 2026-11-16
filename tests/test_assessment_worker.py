import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import assessment_manager as manager
import assessment_worker as worker
import audit_log

class AssessmentWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.old_db=manager.DB_PATH; self.old_audit_db=audit_log.DB_PATH; self.old_reports=worker.REPORT_DIR
        manager.DB_PATH=Path(self.temp.name)/"assessment.db"
        audit_log.DB_PATH=manager.DB_PATH
        worker.REPORT_DIR=Path(self.temp.name)/"reports"
        manager.initialize()
    def tearDown(self):
        manager.DB_PATH=self.old_db; audit_log.DB_PATH=self.old_audit_db; worker.REPORT_DIR=self.old_reports
        self.temp.cleanup()
    def test_worker_keeps_scanner_results_assessment_scoped_and_marks_skips(self):
        target={"name":"test-image","image":"test-image:latest","exposure_kind":"loopback",
                "scanner_plan":[("Trivy","Pending","image"),("Nmap","Skipped","no host"),("OWASP ZAP","Skipped","no url")]}
        aid=manager.create_assessment("admin","Container image",target,"Normal")
        def fake_trivy(image,outdir,**kwargs):
            report=Path(outdir)/"trivy-test.json"
            report.write_text(json.dumps({"Results":[{"Target":"test","Vulnerabilities":[{
                "VulnerabilityID":"GHSA-test","PkgName":"pkg","Severity":"HIGH","InstalledVersion":"1.0","FixedVersion":"1.1","CVSS":{"nvd":{"V3Score":8.0}}
            }]}]}),encoding="utf-8")
            return {"report_path":report,"report_name":report.name,"vulnerability_count":1}
        with patch.object(worker,"run_trivy_image_scan",side_effect=fake_trivy):
            worker.run(aid)
        result=manager.get_assessment(aid)
        self.assertEqual(result["status"],"Completed")
        states={x["scanner"]:x["status"] for x in result["scanners"]}
        self.assertEqual(states,{"Trivy":"Completed","Nmap":"Skipped","OWASP ZAP":"Skipped"})
        self.assertEqual(len(result["findings"]),1)
        self.assertEqual(result["findings"][0]["assessment_id"],aid)
        self.assertEqual(result["findings"][0]["risk_score"],2.4)
        self.assertEqual(result["findings"][0]["contextual_risk"],2.4)
        self.assertEqual(result["findings"][0]["model_version"],"vulngraph-contextual-risk-1.0")

if __name__=="__main__": unittest.main()
