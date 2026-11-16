import unittest
from phase2_progress import scanner_progress, scanner_timeline

class ProgressTests(unittest.TestCase):
    def test_queued(self):
        self.assertEqual(scanner_progress({'status':'Queued','scanners':[{'status':'Pending'}]})['percent'],0)
    def test_mixed_scanners(self):
        state={'status':'Running','scanners':[{'scanner':'Trivy','status':'Completed'}, {'scanner':'Nmap','status':'Running'}, {'scanner':'OWASP ZAP','status':'Skipped'}]}
        self.assertEqual(scanner_progress(state)['percent'],67)
        self.assertEqual(scanner_progress(state)['active'],['Nmap'])
    def test_failed_is_finished_task(self):
        state={'status':'Partial','scanners':[{'scanner':'Trivy','status':'Failed'}, {'scanner':'Nmap','status':'Completed'}]}
        self.assertEqual(scanner_progress(state)['percent'],100)
        self.assertEqual(scanner_progress(state)['failed'],['Trivy'])
    def test_duration(self):
        row=scanner_timeline({'scanners':[{'scanner':'Nmap','status':'Completed','started_at':'2026-11-02T10:00:00+05:30','completed_at':'2026-11-02T10:00:04+05:30'}]})[0]
        self.assertEqual(row['Duration (s)'],4)
    def test_no_scanners(self):
        self.assertEqual(scanner_progress({})['percent'],0)

if __name__=='__main__': unittest.main()
