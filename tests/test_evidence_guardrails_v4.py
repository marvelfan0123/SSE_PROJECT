import unittest
from unittest.mock import patch
from risk_model import score_assessment_finding, image_risk
import threat_intelligence

class EvidenceGuardrailsTests(unittest.TestCase):
    def test_stale_epss_does_not_boost(self):
        x=score_assessment_finding(dict(source='Trivy',cvss=8,epss_percentile=.99,epss_status='stale'))
        self.assertEqual(x['threat_priority'],80)
        self.assertEqual(x['scoring_evidence']['epss_status'],'stale')
    def test_stale_kev_does_not_trigger_policy(self):
        x=score_assessment_finding(dict(source='Trivy',cvss=2,kev_status='listed',kev_evidence_status='stale'))
        self.assertEqual(x['risk_label'],'Low')
        self.assertEqual(x['kev_status'],'unavailable')
    def test_completeness_is_not_verification(self):
        x=score_assessment_finding(dict(source='Trivy',cvss=8,epss_percentile=.5,kev_status='not_listed'),1,1)
        self.assertNotEqual(x['scoring_confidence'],'Verified')
    def test_distinct_locations_remain_distinct(self):
        f=dict(asset='image',cve='CVE-2026-12345',package='lib',threat_priority=80)
        a=image_risk([dict(f,path='/a'),dict(f,path='/a')])
        b=image_risk([dict(f,path='/a'),dict(f,path='/b')])
        self.assertGreater(b,a)
    def test_expired_cache_not_trusted(self):
        old={'fetched_at':'2020-01-01T00:00:00+00:00', 'epss':{'CVE-2026-12345':{'percentile':.99,'probability':.9}},'kev':{'CVE-2026-12345':'2020-01-01'}}
        with patch.object(threat_intelligence,'_read_cache',return_value=old), patch.dict('os.environ',{'VULNX_THREAT_ENRICHMENT':'0', 'VULNGRAPH_THREAT_ENRICHMENT':'0'}):
            x=threat_intelligence.enrich_findings([{'cve':'CVE-2026-12345'}])[0]
        self.assertEqual(x['kev_status'],'unavailable')
        self.assertEqual(x['epss_status'],'stale')
        self.assertNotIn('epss_percentile',x)

if __name__=='__main__': unittest.main()
