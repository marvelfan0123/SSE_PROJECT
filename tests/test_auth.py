import tempfile
import unittest
from pathlib import Path
from auth import (
    authenticate, bootstrap_initial_admin, create_user, is_initial_setup_required,
    can_manage_approvals, can_scan, allowed_remediation_statuses,
    has_permission, require_permission,
)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth_unit.db"
        bootstrap_initial_admin("admin", "TestFixture#Admin99", db_path=self.db_path)
        create_user("analyst", "TestFixture#Analyst99", "Analyst", actor_role="Admin", db_path=self.db_path)
        create_user("approver", "TestFixture#Approver99", "Approver", actor_role="Admin", db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_demo_accounts_authenticate(self):
        self.assertEqual(authenticate("admin", "TestFixture#Admin99", db_path=self.db_path)["role"], "Admin")
        self.assertEqual(authenticate("analyst", "TestFixture#Analyst99", db_path=self.db_path)["role"], "Analyst")
        self.assertEqual(authenticate("approver", "TestFixture#Approver99", db_path=self.db_path)["role"], "Approver")

    def test_bad_credentials_rejected(self):
        self.assertIsNone(authenticate("admin", "wrong-password", db_path=self.db_path))
        self.assertIsNone(authenticate("missing", "TestFixture#Admin99", db_path=self.db_path))

    def test_scan_permissions(self):
        self.assertTrue(can_scan("Admin"))
        self.assertTrue(can_scan("Analyst"))
        self.assertFalse(can_scan("Approver"))

    def test_approval_permissions(self):
        self.assertTrue(can_manage_approvals("Admin"))
        self.assertTrue(can_manage_approvals("Approver"))
        self.assertFalse(can_manage_approvals("Analyst"))

    def test_role_matrix_for_remediation_and_audit(self):
        self.assertTrue(has_permission("Analyst", "create_remediation"))
        self.assertFalse(has_permission("Approver", "create_remediation"))
        self.assertTrue(has_permission("Approver", "verify_remediation"))
        self.assertFalse(has_permission("Analyst", "verify_remediation"))
        self.assertTrue(has_permission("Admin", "view_audit_logs"))
        self.assertFalse(has_permission("Approver", "view_audit_logs"))

    def test_require_permission_denies_unknown_or_insufficient_role(self):
        with self.assertRaises(PermissionError):
            require_permission("Approver", "run_scans")
        with self.assertRaises(PermissionError):
            require_permission("Unknown", "view_dashboard")
        require_permission("Analyst", "run_scans")

    def test_allowed_remediation_statuses(self):
        self.assertEqual(allowed_remediation_statuses("Analyst", "Pending"), ["Pending"])
        self.assertEqual(allowed_remediation_statuses("Analyst", "Approved"), ["Approved", "In Progress"])
        self.assertEqual(allowed_remediation_statuses("Analyst", "Resolved"), ["Resolved"])
        self.assertEqual(allowed_remediation_statuses("Approver", "Pending"), ["Pending", "Approved", "Rejected"])
        self.assertIn("Resolved", allowed_remediation_statuses("Approver", "In Progress"))


if __name__ == "__main__":
    unittest.main()
