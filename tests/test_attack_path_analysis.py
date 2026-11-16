import unittest
from attack_path_analysis import build_attack_paths, summarize_attack_paths, build_attack_path_graphviz


class AttackPathAnalysisTests(unittest.TestCase):
    def test_open_local_port_is_not_assumed_internet_exposed(self):
        paths = build_attack_paths([], [{"asset": "127.0.0.1", "port": "3000", "service": "http", "state": "open"}])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].confidence, "Low")
        self.assertIn("public Internet exposure is not established", paths[0].caveat)

    def test_closed_port_is_ignored(self):
        paths = build_attack_paths([], [{"asset": "127.0.0.1", "port": "3000", "service": "http", "state": "closed"}])
        self.assertEqual(paths, [])

    def test_relationship_needs_high_or_critical_cve_finding(self):
        findings = [{"Target": "web-app", "CVE": "CVE-2024-1234", "Severity": "HIGH"}]
        rel = [{"source": "web-app", "destination": "database", "evidence": "Docker network config"}]
        paths = build_attack_paths(findings, [], rel)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].confidence, "Medium")
        self.assertIn("Candidate attack path only", paths[0].caveat)

    def test_arbitrary_short_relationship_text_does_not_raise_confidence(self):
        findings = [{"Target": "web-app", "CVE": "CVE-2024-1234", "Severity": "HIGH"}]
        rel = [{"source": "web-app", "destination": "database", "evidence": "okaok"}]
        paths = build_attack_paths(findings, [], rel)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].confidence, "Low")

    def test_substantive_relationship_evidence_can_support_medium_confidence(self):
        findings = [{"Target": "web-app", "CVE": "CVE-2024-1234", "Severity": "HIGH"}]
        rel = [{"source": "web-app", "destination": "database", "evidence": "Docker network config verified"}]
        paths = build_attack_paths(findings, [], rel)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].confidence, "Medium")

    def test_relationship_without_matching_cve_is_not_created(self):
        findings = [{"Target": "web-app", "CVE": "", "Severity": "HIGH"}]
        rel = [{"source": "web-app", "destination": "database", "evidence": "known link"}]
        self.assertEqual(build_attack_paths(findings, [], rel), [])


    def test_explicit_report_endpoint_mapping_handles_scanner_specific_targets(self):
        findings = [
            {"Target": "Node.js", "CVE": "CVE-2024-1234", "Severity": "HIGH"},
            {"Target": "debian 13.7", "CVE": "CVE-2024-5678", "Severity": "CRITICAL"},
        ]
        rel = [{
            "source": "Juice Shop container",
            "destination": "DVWA container",
            "evidence": "Both containers share docker-lab_default; HTTP request returned 302 from Juice Shop network namespace.",
            "finding_endpoint": "Juice Shop container",
        }]
        paths = build_attack_paths(findings, [], rel)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].confidence, "Medium")
        self.assertTrue(any("explicitly associated by the user" in item for item in paths[0].evidence))
        self.assertIn("user-supplied", paths[0].caveat)

    def test_report_mapping_is_not_inferred_when_not_supplied(self):
        findings = [{"Target": "Node.js", "CVE": "CVE-2024-1234", "Severity": "HIGH"}]
        rel = [{
            "source": "Juice Shop container",
            "destination": "DVWA container",
            "evidence": "Shared Docker network",
        }]
        self.assertEqual(build_attack_paths(findings, [], rel), [])

    def test_graphviz_contains_candidate_steps_and_confidence(self):
        paths = build_attack_paths([], [{"asset": "127.0.0.1", "port": "3000", "service": "http"}])
        dot = build_attack_path_graphviz(paths)
        self.assertIn("digraph VulnXAttackPaths", dot)
        self.assertIn("127.0.0.1:3000 (http)", dot)
        self.assertIn("AP-001 · Low", dot)

    def test_graphviz_escapes_quotes_in_labels(self):
        paths = build_attack_paths([], [{"asset": 'host "one"', "port": "80", "service": "http"}])
        dot = build_attack_path_graphviz(paths)
        self.assertIn(r'host \"one\"', dot)

    def test_graphviz_empty_paths_returns_empty_string(self):
        self.assertEqual(build_attack_path_graphviz([]), "")

    def test_summary_counts_confidence(self):
        paths = build_attack_paths([], [{"asset": "localhost", "port": "8081", "service": "http"}])
        summary = summarize_attack_paths(paths)
        self.assertEqual(summary["candidate_paths"], 1)
        self.assertEqual(summary["low_confidence"], 1)


if __name__ == "__main__":
    unittest.main()
