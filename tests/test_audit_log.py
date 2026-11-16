import tempfile
import unittest
from pathlib import Path

import audit_log


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_db = audit_log.DB_PATH
        audit_log.DB_PATH = Path(self.tempdir.name) / "audit_test.db"

    def tearDown(self):
        audit_log.DB_PATH = self.original_db
        self.tempdir.cleanup()

    def test_event_round_trip(self):
        audit_log.log_event("admin", "Admin", "login_success", "session", details={"method": "local"})
        events = audit_log.get_audit_events(actor_role="Admin")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "admin")
        self.assertEqual(events[0]["action"], "login_success")
        self.assertEqual(events[0]["details"], {"method": "local"})

    def test_limit_is_bounded_and_positive(self):
        for index in range(3):
            audit_log.log_event("analyst", "Analyst", f"action_{index}")
        self.assertEqual(len(audit_log.get_audit_events(limit=2, actor_role="Admin")), 2)
        self.assertEqual(len(audit_log.get_audit_events(limit=0, actor_role="Admin")), 1)

    def test_scan_activity_returns_only_completed_scanner_events(self):
        audit_log.log_event("admin", "Admin", "login_success", "session")
        audit_log.log_event("admin", "Admin", "trivy_image_scan_completed", "container_image", "nginx", {"report": "nginx-trivy.json"})
        audit_log.log_event("analyst", "Analyst", "nmap_scan_completed", "asset_scan", "127.0.0.1")
        events = audit_log.get_scan_activity()
        self.assertEqual([event["action"] for event in events], ["nmap_scan_completed", "trivy_image_scan_completed"])
        self.assertEqual(events[1]["details"]["report"], "nginx-trivy.json")

    def test_no_password_field_is_added_by_logger(self):
        audit_log.log_event("admin", "Admin", "login_failed", details={"reason": "invalid_credentials"})
        event = audit_log.get_audit_events(actor_role="Admin")[0]
        self.assertNotIn("password", event["details"])

    def test_non_admin_cannot_read_audit_events(self):
        with self.assertRaises(PermissionError):
            audit_log.get_audit_events(actor_role="Analyst")
        with self.assertRaises(PermissionError):
            audit_log.get_audit_events(actor_role="Approver")

    def test_modified_audit_entry_fails_verification(self):
        audit_log.log_event("admin", "Admin", "action_1", "session")
        audit_log.log_event("analyst", "Analyst", "action_2", "ticket", "1")
        self.assertTrue(audit_log.verify_audit_chain("Admin")["valid"])

        with audit_log._connection() as conn:
            conn.execute("UPDATE audit_events SET action = 'tampered_action' WHERE id = 2")
        res = audit_log.verify_audit_chain("Admin")
        self.assertFalse(res["valid"])
        self.assertEqual(res["reason"], "Audit record modified")

    def test_deleted_or_reordered_audit_entry_fails_verification(self):
        audit_log.log_event("admin", "Admin", "action_1", "session")
        audit_log.log_event("analyst", "Analyst", "action_2", "ticket", "1")
        audit_log.log_event("approver", "Approver", "action_3", "ticket", "1")
        self.assertTrue(audit_log.verify_audit_chain("Admin")["valid"])

        with audit_log._connection() as conn:
            conn.execute("DELETE FROM audit_events WHERE id = 2")
        res = audit_log.verify_audit_chain("Admin")
        self.assertFalse(res["valid"])
        self.assertEqual(res["reason"], "Broken predecessor hash")


if __name__ == "__main__":
    unittest.main()
