import unittest
from asset_criticality_engine import automatic_assessment, FACTORS

class AutomaticAssessmentTests(unittest.TestCase):
    def test_configured_lab_is_provisional(self):
        r = automatic_assessment({'configured_training_lab': True})
        self.assertEqual(r['risk_level'], 1)
        self.assertEqual(r['assessment_status'], 'Provisional')
    def test_unknown_is_unassigned(self):
        self.assertIsNone(automatic_assessment({'name':'juice-shop'})['risk_level'])
    def test_labels(self):
        labels = {'com.vulnx.'+k.replace('_','-'): '4' for k in FACTORS}
        r = automatic_assessment({}, [{'labels':labels}])
        self.assertEqual(r['risk_level'], 4)
        self.assertEqual(r['average_score'], 4)
    def test_partial(self):
        self.assertIsNone(automatic_assessment({}, [{'labels':{'environment':'production'}}])['risk_level'])
    def test_conflicting_assets(self):
        self.assertIsNone(automatic_assessment({}, [{'labels':{}},{'labels':{}}])['risk_level'])
    def test_risk_uses_auto_and_preserves_unknown(self):
        from vulngraph_core import score_finding_canonical
        f = {'cvss': 9.8, 'epss': .8, 'source':'Trivy'}
        auto = automatic_assessment({'configured_training_lab':True})
        r = score_finding_canonical(dict(f, automatic_criticality=auto), exposure_kind='loopback')
        self.assertAlmostEqual(r['risk_score'], .854)
        self.assertEqual(r['contextual_status'], 'Provisional')
        r = score_finding_canonical(dict(f, automatic_criticality=automatic_assessment({})), exposure_kind='loopback')
        self.assertIsNone(r['risk_score'])
        self.assertIsNone(r['criticality_level'])
        self.assertIsNone(score_finding_canonical(r, criticality='Normal')['risk_score'])
