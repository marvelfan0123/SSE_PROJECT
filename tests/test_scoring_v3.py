import unittest
from risk_model import score_assessment_finding

class ScoringV3Tests(unittest.TestCase):
    def score(self, **kwargs):
        return score_assessment_finding(dict(source="Trivy", cvss=8.0, **kwargs), None, 1.)
    def test_kev_only_keeps_signal(self):
        x=self.score(kev_status="listed")
        self.assertGreater(x["threat_priority"],80)
        self.assertEqual(x["scoring_evidence"]["epss_status"],"unavailable")
    def test_epss_only_keeps_signal(self):
        self.assertGreater(self.score(epss_percentile=.9)["threat_priority"],80)
    def test_low_threat_does_not_reduce_base(self):
        self.assertGreaterEqual(self.score(epss_percentile=.01,kev_status="not_listed")["threat_priority"],80)
    def test_missing_never_becomes_measured_zero(self):
        self.assertEqual(self.score()["scoring_evidence"]["kev_status"],"unavailable")
    def test_unverified_mitigation_ignored(self):
        self.assertEqual(self.score(verified_mitigation_factor=.2)["contextual_risk"],80)
    def test_verified_mitigation_applies(self):
        self.assertEqual(self.score(verified_mitigation_factor=.5,mitigation_verified=True)["contextual_risk"],40)
    def test_monotonic_epss(self):
        self.assertLess(self.score(epss_percentile=.2)["threat_priority"],self.score(epss_percentile=.9)["threat_priority"])
    def test_keV_policy_is_separate(self):
        x=score_assessment_finding(dict(source="Trivy",cvss=2.0,kev_status="listed"),None,1.)
        self.assertEqual(x["risk_label"],"High")
        self.assertLess(x["risk_score"],50)
