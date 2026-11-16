import tempfile
import unittest
from pathlib import Path
import assessment_manager as manager

class AssessmentManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.old=manager.DB_PATH
        manager.DB_PATH=Path(self.temp.name)/"test.db"
        manager.initialize()
    def tearDown(self):
        manager.DB_PATH=self.old
        self.temp.cleanup()
    def test_assessment_and_scanner_statuses_persist(self):
        aid=manager.create_assessment("admin","Container image",{"name":"demo","scanner_plan":[("Trivy","Pending","Image identified"),("Nmap","Skipped","No host") ]},"Normal")
        manager.update_scanner(aid,"Trivy","Running","started")
        manager.update_scanner(aid,"Trivy","Completed","done",{"count":2})
        item=manager.get_assessment(aid)
        self.assertEqual(item["status"],"Queued")
        self.assertEqual(item["scanners"][0]["status"],"Completed")
        self.assertEqual(item["scanners"][0]["result"],{"count":2})
        self.assertEqual(len(manager.list_assessments()),1)
    def test_nvd_cache_sqlite_round_trip(self):
        manager.put_nvd_cache_sqlite({"CVE-2025-1234":{"status":"enriched","cvss_score":7.5}})
        self.assertEqual(manager.get_nvd_cache_sqlite()["CVE-2025-1234"]["cvss_score"],7.5)

if __name__=="__main__": unittest.main()
