import csv
import io
import json
import unittest
from phase5_reporting import build_snapshot, build_trend, export_csv, export_html, export_json, export_trend_csv


def assessment(**changes):
    record = {'assessment_id': 'VX-1', 'target_type': 'host', 'target_name': '127.0.0.1', 'status': 'Completed',
              'created_at': '2026-11-01T12:00:00',
              'scanners': [{'scanner': 'Nmap', 'status': 'Completed'}],
              'findings': [{'finding_id': 'f1', 'source': 'Trivy', 'finding_type': 'vulnerability',
                            'severity': 'HIGH', 'risk_score': 75, 'asset': 'image1', 'title': 'Old package'},
                           {'finding_id': 'p1', 'source': 'Nmap', 'finding_type': 'network_exposure_observation',
                            'severity': 'HIGH', 'asset': 'localhost', 'title': 'Open port'}]}
    record.update(changes)
    return record


class Phase5ReportingTests(unittest.TestCase):
    def test_scored_vulnerabilities_and_observations_separated(self):
        s = build_snapshot(assessment())
        self.assertEqual((s['metrics']['vulnerabilities'], s['metrics']['exposure_observations']), (1, 1))
        self.assertEqual(s['severity']['HIGH'], 1)
        self.assertEqual(s['metrics']['average_risk'], 75)

    def test_partial_coverage_is_visible(self):
        s = build_snapshot(assessment(status='Partial', scanners=[{'scanner': 'ZAP', 'status': 'Failed'}]))
        self.assertFalse(s['scanner_coverage_complete'])
        self.assertIn('ZAP', s['incomplete_scanners'])
        self.assertIn('Partial/incomplete', export_html(s))

    def test_no_scores_returns_na_not_zero(self):
        s = build_snapshot(assessment(findings=[]))
        self.assertIsNone(s['metrics']['average_risk'])
        self.assertIn('N/A', export_html(s))

    def test_active_assessment_rejected(self):
        with self.assertRaises(ValueError):
            build_snapshot(assessment(status='Running'))

    def test_ticket_status_counts(self):
        s = build_snapshot(assessment(), [{'status': 'Resolved'}, {'status': 'Open'}])
        self.assertEqual(s['remediation']['unresolved'], 1)

    def test_trend_rejects_mixed_targets(self):
        with self.assertRaises(ValueError):
            build_trend([assessment(), assessment(target_name='different')])

    def test_trend_excludes_running_and_sorts(self):
        rows = build_trend([assessment(assessment_id='b', created_at='2026-11-02'),
                            assessment(assessment_id='a', created_at='2026-11-01'),
                            assessment(assessment_id='c', status='Running')])
        self.assertEqual([r['assessment_id'] for r in rows], ['a', 'b'])

    def test_html_escapes_untrusted_scanner_data(self):
        s = build_snapshot(assessment(target_name='<script>alert(1)</script>'))
        report = export_html(s)
        self.assertNotIn('<script>', report)
        self.assertIn('&lt;script&gt;', report)

    def test_csv_escapes_formula_strings(self):
        s = build_snapshot(assessment(findings=[{'source': 'Trivy', 'title': '=HYPERLINK("evil")', 'severity': 'HIGH'}]))
        self.assertIn("'=HYPERLINK", export_csv(s))

    def test_json_is_valid_and_versioned(self):
        data = json.loads(export_json(build_snapshot(assessment())))
        self.assertEqual(data['schema_version'], 'phase5-v1')

    def test_csv_has_headers_and_rows(self):
        s = build_snapshot(assessment())
        self.assertEqual(len(list(csv.DictReader(io.StringIO(export_csv(s))))), 1)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(export_trend_csv(build_trend([assessment()])))))), 1)


if __name__ == '__main__':
    unittest.main()
