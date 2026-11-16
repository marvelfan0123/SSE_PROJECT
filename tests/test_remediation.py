import tempfile
import unittest
from pathlib import Path

import remediation


class RemediationQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = remediation.DB_PATH
        remediation.DB_PATH = Path(self.temp_dir.name) / "test_scan_history.db"
        remediation.initialize_remediation_table()
        self.finding = {
            "Target": "Juice Shop",
            "Package": "example-package",
            "CVE": "CVE-2025-1234",
            "Installed Version": "1.0",
            "Severity": "HIGH",
            "Risk Score": 85,
            "Fixed Version": "1.2",
        }

    def tearDown(self):
        remediation.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_add_finding_creates_pending_queue_item(self):
        self.assertTrue(remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin"))
        items = remediation.get_remediation_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["status"], "Pending")
        self.assertEqual(items[0]["target"], "Juice Shop")

    def test_adding_same_finding_twice_does_not_duplicate(self):
        self.assertTrue(remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin"))
        self.assertFalse(remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin"))
        self.assertEqual(len(remediation.get_remediation_items()), 1)

    def test_update_records_owner_notes_and_approval(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        updated = remediation.update_remediation_item(
            item_id, "In Progress", "Rahul", "Preparing a patch plan", "Reviewer A", actor_role="Admin", actor_username="admin"
        )
        self.assertTrue(updated)
        item = remediation.get_remediation_items()[0]
        self.assertEqual(item["status"], "In Progress")
        self.assertEqual(item["owner"], "Rahul")
        self.assertEqual(item["approver"], "Reviewer A")

    def test_verification_evidence_and_status_persist(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        evidence = "Validation test only; no real remediation or rescan performed."
        updated = remediation.update_remediation_item(
            item_id,
            "Approved",
            "Rahul",
            "Prepared a remediation plan",
            "Reviewer A",
            evidence,
            "Still present",
            actor_role="Admin", actor_username="admin",
        )
        self.assertTrue(updated)

        # Re-read from SQLite to confirm values survive beyond the update call.
        saved_item = remediation.get_remediation_items()[0]
        self.assertEqual(saved_item["verification_status"], "Still present")
        self.assertEqual(saved_item["verification_evidence"], evidence)
        self.assertEqual(saved_item["owner"], "Rahul")
        self.assertEqual(saved_item["approver"], "admin")

    def test_invalid_status_is_rejected(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(item_id, "Patched Automatically", "", "", actor_role="Admin", actor_username="admin")

    def test_invalid_verification_status_is_rejected(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(
                item_id, "Pending", "", "", verification_status="Unknown", actor_role="Admin", actor_username="admin"
            )

    def test_backend_rejects_pass_without_evidence_on_any_status(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(item_id, "Approved", "a", "", "Reviewer", "", "Pass", actor_role="Admin", actor_username="admin")
        self.assertEqual(remediation.get_remediation_items()[0]["verification_status"], "Not verified")

    def test_backend_rejects_approval_without_approver(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(item_id, "In Progress", "a", "", "", actor_role="Admin", actor_username="admin")

    def test_backend_rejects_resolved_without_verification(self):
        remediation.add_finding(self.finding, actor_role="Admin", actor_username="admin")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(item_id, "Resolved", "a", "", "R", "", "Not verified", actor_role="Admin", actor_username="admin")
        self.assertTrue(remediation.update_remediation_item(item_id, "Resolved", "a", "", "R", "rescan-42.json", "Pass", actor_role="Admin", actor_username="admin"))

    def test_update_nonexistent_item_returns_false(self):
        self.assertFalse(remediation.update_remediation_item(999, "Pending", "", "", actor_role="Admin", actor_username="admin"))


    def test_analyst_can_create_and_update_work_but_cannot_approve(self):
        self.assertTrue(remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst"))
        item_id = remediation.get_remediation_items()[0]["id"]
        self.assertTrue(remediation.update_remediation_item(
            item_id, "Approved", "", "Reviewed and approved", "", actor_role="Approver", actor_username="approver"
        ))
        self.assertTrue(remediation.update_remediation_item(
            item_id, "In Progress", "Analyst A", "Investigating fix", "approver", actor_role="Analyst", actor_username="analyst"
        ))
        with self.assertRaises(PermissionError):
            remediation.update_remediation_item(
                item_id, "Approved", "Analyst A", "Investigating fix", actor_role="Analyst", actor_username="analyst"
            )

    def test_approver_cannot_create_remediation_or_reassign_owner(self):
        with self.assertRaises(PermissionError):
            remediation.add_finding(self.finding, actor_role="Approver", actor_username="approver")
        remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(PermissionError):
            remediation.update_remediation_item(
                item_id, "Approved", "Changed owner", "Reviewed", "", actor_role="Approver", actor_username="approver"
            )

    def test_approver_can_approve_as_authenticated_user(self):
        remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst")
        item_id = remediation.get_remediation_items()[0]["id"]
        self.assertTrue(remediation.update_remediation_item(
            item_id, "Approved", "", "Looks appropriate", "", actor_role="Approver", actor_username="approver"
        ))
        saved = remediation.get_remediation_items()[0]
        self.assertEqual(saved["approver"], "approver")
        self.assertEqual(saved["status"], "Approved")

    def test_approver_cannot_resolve_without_fresh_pass_evidence(self):
        remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst")
        item_id = remediation.get_remediation_items()[0]["id"]
        remediation.update_remediation_item(item_id, "Approved", "", "Approved", "", actor_role="Approver", actor_username="approver")
        with self.assertRaises(ValueError):
            remediation.update_remediation_item(
                item_id, "Resolved", "", "Fix checked", "", "old report", "Still present",
                actor_role="Approver", actor_username="approver"
            )
        self.assertTrue(remediation.update_remediation_item(
            item_id, "Resolved", "", "Fresh scan confirms finding absent", "", "rescan-2026-10-31.json", "Pass",
            actor_role="Approver", actor_username="approver"
        ))

    def test_missing_role_is_denied(self):
        with self.assertRaises(PermissionError):
            remediation.add_finding(self.finding)
        with self.assertRaises(PermissionError):
            remediation.update_remediation_item(1, "Pending", "", "")


    def test_full_analyst_approver_remediation_lifecycle(self):
        # Analyst discovers a finding and queues it as Pending.
        self.assertTrue(remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst"))
        item_id = remediation.get_remediation_items()[0]["id"]
        # Analyst cannot start work until approval.
        with self.assertRaises(PermissionError):
            remediation.update_remediation_item(
                item_id, "In Progress", "Analyst", "Starting fix", "",
                actor_role="Analyst", actor_username="analyst"
            )
        # Approver approves; identity is taken from the logged-in account.
        remediation.update_remediation_item(
            item_id, "Approved", "", "Approved for the lab", "",
            actor_role="Approver", actor_username="approver"
        )
        # Analyst can now start work and record progress.
        remediation.update_remediation_item(
            item_id, "In Progress", "Analyst", "Updated package in test image", "approver",
            actor_role="Analyst", actor_username="analyst"
        )
        # Approver records a passing rescan reference and resolves the task.
        remediation.update_remediation_item(
            item_id, "Resolved", "Analyst", "Reviewed rescan evidence", "",
            "fresh-trivy-report.json", "Pass",
            actor_role="Approver", actor_username="approver"
        )
        saved = remediation.get_remediation_items()[0]
        self.assertEqual(saved["status"], "Resolved")
        self.assertEqual(saved["approver"], "approver")
        self.assertEqual(saved["verification_status"], "Pass")
        self.assertEqual(saved["verification_evidence"], "fresh-trivy-report.json")

    def test_analyst_cannot_change_verification_evidence(self):
        remediation.add_finding(self.finding, actor_role="Analyst", actor_username="analyst")
        item_id = remediation.get_remediation_items()[0]["id"]
        with self.assertRaises(PermissionError):
            remediation.update_remediation_item(
                item_id, "Pending", "Analyst", "notes", "", "fake-rescan.json", "Pass",
                actor_role="Analyst", actor_username="analyst"
            )


if __name__ == "__main__":
    unittest.main()
