import unittest
from risk_model import score_assessment_finding, image_risk

class AssessmentRiskModelTests(unittest.TestCase):
    def test_base_and_unknown_exposure(self):
        x=score_assessment_finding({'source':'Trivy','cvss':9.8},None,1)
        self.assertEqual(x['base_risk'],98)
        self.assertEqual(x['risk_score'],98)
        self.assertEqual(x['scoring_confidence'],'Provisional')
    def test_verified_context(self):
        x=score_assessment_finding({'source':'Trivy','cvss':8},.8,1.2)
        self.assertEqual(x['contextual_risk'],76.8)
    def test_zap_proxy_is_not_cvss(self):
        x=score_assessment_finding({'source':'OWASP ZAP','severity':'MEDIUM'},None,1)
        self.assertIsNone(x.get('cvss'))
        self.assertIn('proxy',x['base_score_source'])
        self.assertEqual(x['base_risk'],50)
    def test_nmap_is_observation(self):
        x=score_assessment_finding({'source':'Nmap','finding_type':'network_exposure_observation'},None,1)
        self.assertIsNone(x['risk_score'])
    def test_preserves_scanner_cvss(self):
        x=score_assessment_finding({'source':'Trivy','cvss':8},1,1,{'status':'enriched','cvss_score':9})
        self.assertEqual(x['cvss'],8)
    def test_kev_floor_and_threat_score(self):
        x=score_assessment_finding({'source':'Trivy','cvss':3,'epss_percentile':.2,'kev_status':'listed'},None,1)
        self.assertAlmostEqual(x['threat_priority'],59.4)
        self.assertEqual(x['risk_label'],'High')
    def test_image_deduplication(self):
        finding={'asset':'img','cve':'CVE-2026-1234','package':'p','threat_priority':80}
        self.assertEqual(image_risk([finding,finding]),80)
    def test_missing_evidence(self):
        x=score_assessment_finding({'source':'Trivy','severity':'UNKNOWN'},None,1)
        self.assertIsNone(x['risk_score'])
    def test_zero_and_ten(self):
        self.assertEqual(score_assessment_finding({'source':'Trivy','cvss':0},None,1)['risk_score'],0)
        self.assertEqual(score_assessment_finding({'source':'Trivy','cvss':10},None,1)['risk_score'],100)

if __name__=='__main__': unittest.main()
