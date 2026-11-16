import unittest
from finding_correlation import correlate_findings


def record(fid, kind="package_vulnerability", asset="app", cve="CVE-1", package="pkg", version="1.0", port="", service=""):
    return {
        "finding_id": fid, "finding_type": kind, "asset": asset,
        "cve": cve, "package": package, "installed_version": version,
        "title": fid, "source": "Trivy" if kind == "package_vulnerability" else "Nmap",
        "severity": "HIGH", "fixed_version": "2.0",
        "evidence": {"protocol": "tcp", "port": port, "service": service, "version": version},
    }


class FindingCorrelationTests(unittest.TestCase):
    def test_exact_package_duplicates_are_grouped(self):
        unique, duplicates = correlate_findings([record("a"), record("b")])
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0]["correlated_record_count"], 2)
        self.assertEqual(len(duplicates), 1)

    def test_different_assets_are_not_merged(self):
        unique, duplicates = correlate_findings([record("a"), record("b", asset="other")])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_different_versions_are_not_merged(self):
        unique, duplicates = correlate_findings([record("a"), record("b", version="1.1")])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_nmap_observations_group_by_port_identity(self):
        a = record("a", kind="network_exposure_observation", port="443", service="https")
        b = record("b", kind="network_exposure_observation", port="443", service="https")
        unique, duplicates = correlate_findings([a, b])
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0]["correlated_record_count"], 2)

    def test_different_finding_types_do_not_merge(self):
        unique, duplicates = correlate_findings([
            record("a"), record("b", kind="network_exposure_observation")
        ])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])


    def test_different_cves_are_not_merged(self):
        unique, duplicates = correlate_findings([record("a"), record("b", cve="CVE-2")])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_missing_cve_does_not_merge(self):
        unique, duplicates = correlate_findings([record("a", cve=""), record("b", cve="")])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_missing_package_identity_does_not_merge(self):
        unique, duplicates = correlate_findings([record("a", package=""), record("b", package="")])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_network_observations_with_missing_port_do_not_merge(self):
        a = record("a", kind="network_exposure_observation", port="", service="https")
        b = record("b", kind="network_exposure_observation", port="", service="https")
        unique, duplicates = correlate_findings([a, b])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])

    def test_unknown_records_without_ids_do_not_merge(self):
        unique, duplicates = correlate_findings([
            {"finding_type": "unknown"}, {"finding_type": "unknown"}
        ])
        self.assertEqual(len(unique), 2)
        self.assertEqual(duplicates, [])


if __name__ == "__main__":
    unittest.main()
