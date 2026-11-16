import unittest

from finding_normalization import (
    normalize_nmap_result,
    normalize_trivy_report,
    to_legacy_trivy_finding,
)


class FindingNormalizationTests(unittest.TestCase):
    def test_trivy_record_has_common_schema_and_legacy_adapter(self):
        report = {
            "Results": [{
                "Target": "sample-image",
                "Type": "debian",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2025-1234",
                    "PkgName": "sample-package",
                    "Severity": "HIGH",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                    "Title": "Sample issue",
                    "PrimaryURL": "https://example.invalid/cve",
                    "References": ["https://example.invalid/reference"],
                }],
            }]
        }
        records = normalize_trivy_report(report, "sample-trivy.json")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["source"], "Trivy")
        self.assertEqual(record["finding_type"], "package_vulnerability")
        self.assertTrue(record["is_vulnerability"])
        self.assertEqual(record["severity"], "HIGH")
        self.assertEqual(record["cve"], "CVE-2025-1234")
        self.assertEqual(record["evidence"]["result_type"], "debian")
        legacy = to_legacy_trivy_finding(record)
        self.assertEqual(legacy["Package"], "sample-package")
        self.assertEqual(legacy["Fixed Version"], "1.1")

    def test_missing_trivy_fields_receive_safe_defaults(self):
        records = normalize_trivy_report({"Results": [{"Vulnerabilities": [{}]}]})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["asset"], "Unknown")
        self.assertEqual(records[0]["severity"], "UNKNOWN")
        self.assertEqual(records[0]["finding_type"], "package_vulnerability")

    def test_nmap_open_port_is_not_a_confirmed_vulnerability(self):
        result = {
            "target": "127.0.0.1",
            "ports_checked": "3000,8081",
            "host_status": "up",
            "open_ports": [{
                "port": "8081", "protocol": "tcp", "state": "open",
                "service": "http", "version": "Apache httpd 2.4.25 (Debian)",
            }],
        }
        records = normalize_nmap_result(result)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["source"], "Nmap")
        self.assertEqual(record["finding_type"], "network_exposure_observation")
        self.assertFalse(record["is_vulnerability"])
        self.assertEqual(record["severity"], "INFO")
        self.assertEqual(record["evidence"]["port"], "8081")

    def test_finding_id_is_stable_for_same_finding(self):
        report = {"Results": [{"Target": "image", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2025-1", "PkgName": "pkg", "InstalledVersion": "1",
        }]}]}
        first = normalize_trivy_report(report)[0]
        second = normalize_trivy_report(report)[0]
        self.assertEqual(first["finding_id"], second["finding_id"])

    def test_trivy_cwe_extraction(self):
        report = {
            "Results": [{
                "Target": "sample-image",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2025-5678",
                    "PkgName": "sample-lib",
                    "CweIDs": ["CWE-79", "CWE-89"],
                }],
            }]
        }
        records = normalize_trivy_report(report)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cwe"], "CWE-79")
        self.assertEqual(records[0]["cwe_ids"], ["CWE-79", "CWE-89"])
        self.assertEqual(records[0]["evidence"]["cwe_ids"], ["CWE-79", "CWE-89"])

    def test_zap_cwe_extraction(self):
        from finding_normalization import normalize_zap_report
        zap_data = {
            "site": [{
                "@name": "http://127.0.0.1:3000",
                "alerts": [{
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "cweid": "693",
                    "riskcode": "2",
                }]
            }]
        }
        records = normalize_zap_report(zap_data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cwe"], "CWE-693")
        self.assertEqual(records[0]["cwe_ids"], ["CWE-693"])
        self.assertEqual(records[0]["evidence"]["cwe_id"], "693")


if __name__ == "__main__":
    unittest.main()
