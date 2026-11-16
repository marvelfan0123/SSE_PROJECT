import unittest
from scoring_benchmark import evaluate_cases, evaluate_labeled_csv
import csv
import tempfile
from pathlib import Path

class BenchmarkTests(unittest.TestCase):
    def test_controlled_diagnostics(self):
        result=evaluate_cases()
        self.assertEqual(result['case_count'],8)
        self.assertTrue(result['diagnostics']['severity_floor_preserved'])
        self.assertTrue(result['diagnostics']['kev_partial_enrichment_preserved'])
        self.assertTrue(result['diagnostics']['image_deduplication'])
    def test_independent_labels_auc(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'labels.csv'
            with path.open('w',newline='') as f:
                w=csv.writer(f)
                w.writerow(['cve','cvss','epss_percentile','kev_status','exploited_label'])
                w.writerow(['TEST-1',9.8,.9,'not_listed',1])
                w.writerow(['TEST-2',2.0,.1,'not_listed',0])
            r=evaluate_labeled_csv(path)
            self.assertEqual(r['base_auc'],1)
            self.assertEqual(r['threat_auc'],1)
    def test_reject_invalid_labels(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.csv'
            path.write_text('cve,cvss,epss_percentile,kev_status,exploited_label\nX,8,.5,listed,2\n')
            with self.assertRaises(ValueError): evaluate_labeled_csv(path)
