import unittest
from assessment_comparison import compare_assessment_findings, finding_match_key

class AssessmentComparisonTests(unittest.TestCase):
    def test_trivy_matches_same_asset_cve_package_even_if_version_changes(self):
        a={"source":"Trivy","asset":"juice-shop:latest","cve":"CVE-2025-1","package":"openssl","installed_version":"1.0"}
        b={**a,"installed_version":"1.1"}
        self.assertEqual(finding_match_key(a),finding_match_key(b))
    def test_nmap_matches_host_port_service(self):
        a={"source":"Nmap","asset":"127.0.0.1","evidence":{"port":"3000","service":"http","version":"v1"}}
        b={**a,"evidence":{"port":"3000","service":"http","version":"v2"}}
        self.assertEqual(finding_match_key(a),finding_match_key(b))
    def test_zap_matches_alert_and_url(self):
        a={"source":"OWASP ZAP","evidence":{"plugin_id":"10020","instances":[{"uri":"http://localhost/a"}]}}
        b={"source":"OWASP ZAP","evidence":{"plugin_id":"10020","instances":[{"uri":"http://localhost/b"}]}}
        self.assertNotEqual(finding_match_key(a),finding_match_key(b))
    def test_classifies_new_persistent_and_no_longer_detected(self):
        old=[{"source":"Trivy","asset":"img","cve":"CVE-1","package":"p"},{"source":"Nmap","asset":"host","evidence":{"port":"80","service":"http"}}]
        new=[{"source":"Trivy","asset":"img","cve":"CVE-1","package":"p"},{"source":"OWASP ZAP","evidence":{"plugin_id":"1","instances":[{"uri":"http://localhost"}]}}]
        result=compare_assessment_findings(old,new)
        self.assertEqual(len(result["new"]),1); self.assertEqual(len(result["persistent"]),1); self.assertEqual(len(result["no_longer_detected"]),1)

if __name__=="__main__": unittest.main()
