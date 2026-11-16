import json
import unittest
from phase3_analysis import analyze_findings, summarize, correlation_summary, export_csv, export_report

FINDING = {'finding_id': 'a', 'source': 'Trivy', 'finding_type': 'package_vulnerability', 'asset': 'image:test', 'cve': 'CVE-2025-12345', 'package': 'libx', 'installed_version': '1.0', 'severity': 'HIGH', 'title': 'Affected library', 'cvss': 8.0}
OBS = {'finding_id': 'p', 'source': 'Nmap', 'finding_type': 'network_exposure_observation', 'asset': '127.0.0.1', 'title': 'Port 3000 open', 'severity': 'INFO', 'evidence': {'port': 3000}}

class Phase3AnalysisTests(unittest.TestCase):
    def test_image_only_scan_has_severity_triage_without_fabricated_context(self):
        result = analyze_findings([FINDING], exposure='unknown')[0]
        self.assertEqual(result['risk_score'], 80)
        self.assertEqual(result['scoring_confidence'], 'Provisional')
        self.assertEqual(result['triage_priority'], 'High')

    def test_network_observation_has_no_severity_triage(self):
        result = analyze_findings([OBS], exposure='unknown')[0]
        self.assertEqual(result['triage_priority'], 'Exposure observation')
        self.assertIsNone(result['risk_score'])

    def test_context_increases_risk(self):
        low = analyze_findings([FINDING], exposure='internal', criticality='Low')[0]
        high = analyze_findings([FINDING], exposure='internal', criticality='High')[0]
        self.assertGreater(high['risk_score'], low['risk_score'])
        self.assertIn('business criticality', high['risk_explanation'])
    def test_unknown_exposure_does_not_fabricate_score(self):
        self.assertEqual(analyze_findings([FINDING])[0]['risk_score'], 80)
    def test_observations_not_vulnerabilities(self):
        scored = analyze_findings([FINDING, OBS], exposure='loopback')
        summary = summarize(scored)
        self.assertEqual(summary['scored_vulnerabilities'], 1)
        self.assertEqual(summary['exposure_observations'], 1)
        self.assertIsNone(next(x for x in scored if x['source']=='Nmap')['risk_score'])
    def test_no_mutation(self):
        original = dict(FINDING)
        analyze_findings([FINDING], exposure='internal')
        self.assertEqual(FINDING, original)
    def test_conservative_correlation(self):
        group = correlation_summary([FINDING, dict(FINDING), OBS])
        self.assertEqual(group['unique_count'], 2)
        self.assertEqual(len(group['duplicate_groups']), 1)
    def test_report_and_csv(self):
        findings = analyze_findings([FINDING], exposure='internal')
        report = json.loads(export_report('abc', findings, exposure='internal', criticality='Normal'))
        self.assertEqual(report['assessment_id'], 'abc')
        self.assertIn('CVE-2025-12345', export_csv(findings))
        self.assertIn('limitations', report)
    def test_bad_context_rejected(self):
        with self.assertRaises(ValueError):
            analyze_findings([FINDING], exposure='internet')
