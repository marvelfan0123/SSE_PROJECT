import unittest
from unittest.mock import patch
import authorized_actions

class AuthorizedActionTests(unittest.TestCase):
    def test_approver_cannot_start_any_scanner(self):
        with patch("authorized_actions.run_trivy_image_scan") as trivy, \
             patch("authorized_actions.scan_target") as nmap, \
             patch("authorized_actions.run_zap_baseline_scan") as zap:
            with self.assertRaises(PermissionError):
                authorized_actions.run_trivy_scan("Approver", "python:3.12", ".")
            with self.assertRaises(PermissionError):
                authorized_actions.run_nmap_scan("Approver", "127.0.0.1", "80")
            with self.assertRaises(PermissionError):
                authorized_actions.run_zap_scan("Approver", "OWASP Juice Shop", ".")
            trivy.assert_not_called(); nmap.assert_not_called(); zap.assert_not_called()

    def test_admin_and_analyst_can_start_scanners(self):
        with patch("authorized_actions.run_trivy_image_scan", return_value={"ok": True}) as trivy:
            self.assertEqual(authorized_actions.run_trivy_scan("Analyst", "python:3.12", "."), {"ok": True})
            self.assertEqual(authorized_actions.run_trivy_scan("Admin", "python:3.12", "."), {"ok": True})
            self.assertEqual(trivy.call_count, 2)

    def test_approver_cannot_trigger_nvd_enrichment(self):
        with patch("authorized_actions.enrich_cve_batch") as enrich:
            with self.assertRaises(PermissionError):
                authorized_actions.enrich_cves("Approver", ["CVE-2025-0001"], "cache.json")
            enrich.assert_not_called()

if __name__ == "__main__":
    unittest.main()
