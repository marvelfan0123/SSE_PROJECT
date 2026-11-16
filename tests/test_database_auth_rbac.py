"""Unit and security regression tests for database-backed authentication, first-run bootstrap, RBAC, and Maker-Checker."""
import re
import tempfile
import unittest
from pathlib import Path
import auth
from remediation_workflow import create_ticket, change_ticket
import assessment_manager as manager


class DatabaseAuthRBACTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.orig_db = manager.DB_PATH
        manager.DB_PATH = self.db_path
        manager.initialize()

    def tearDown(self):
        manager.DB_PATH = self.orig_db
        self.temp_dir.cleanup()

    def test_first_run_bootstrap_and_duplicate_prevention(self):
        # Initially, no administrator exists
        self.assertTrue(auth.is_initial_setup_required(self.db_path))

        # Weak passwords rejected during bootstrap
        for weak in ("short1!", "alllowercase123!", "ALLUPPERCASE123!", "NoDigitsHere!!", "NoSpecialChar123"):
            with self.assertRaises(ValueError):
                auth.bootstrap_initial_admin("admin", weak, db_path=self.db_path)

        # Establish initial administrator
        created = auth.bootstrap_initial_admin("admin_ops", "StrongAdmin#2026", db_path=self.db_path)
        self.assertEqual(created["username"], "admin_ops")
        self.assertEqual(created["role"], "Admin")
        self.assertFalse(auth.is_initial_setup_required(self.db_path))

        # Prevent second automatic/manual initial bootstrap once an Admin exists
        with self.assertRaises(RuntimeError):
            auth.bootstrap_initial_admin("second_admin", "AnotherStrong#2026", db_path=self.db_path)

    def test_database_user_creation_and_authentication(self):
        auth.bootstrap_initial_admin("admin", "StrongAdmin#2026", db_path=self.db_path)
        user = auth.create_user("bob_analyst", "SecurePassword123!", "Security Analyst", actor_role="Admin", db_path=self.db_path)
        self.assertEqual(user["username"], "bob_analyst")
        self.assertEqual(user["role"], "Security Analyst")

        # Authenticate with correct credentials
        identity = auth.authenticate("bob_analyst", "SecurePassword123!", db_path=self.db_path)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["username"], "bob_analyst")
        self.assertEqual(identity["role"], "Security Analyst")

        # Bad password rejected
        self.assertIsNone(auth.authenticate("bob_analyst", "WrongPassword!", db_path=self.db_path))

    def test_duplicate_user_rejected(self):
        auth.bootstrap_initial_admin("admin", "StrongAdmin#2026", db_path=self.db_path)
        auth.create_user("charlie", "Password12345!", "Approver", actor_role="Admin", db_path=self.db_path)
        with self.assertRaises(ValueError):
            auth.create_user("charlie", "Password12345!", "Approver", actor_role="Admin", db_path=self.db_path)

    def test_account_activation_and_deactivation(self):
        auth.bootstrap_initial_admin("admin", "StrongAdmin#2026", db_path=self.db_path)
        auth.create_user("dan", "Password12345!", "Analyst", is_active=True, actor_role="Admin", db_path=self.db_path)
        self.assertIsNotNone(auth.authenticate("dan", "Password12345!", db_path=self.db_path))

        # Deactivate
        auth.set_user_status("dan", False, "Admin", db_path=self.db_path)
        self.assertIsNone(auth.authenticate("dan", "Password12345!", db_path=self.db_path))

        # Reactivate
        auth.set_user_status("dan", True, "Admin", db_path=self.db_path)
        self.assertIsNotNone(auth.authenticate("dan", "Password12345!", db_path=self.db_path))

    def test_password_change_lifecycle(self):
        auth.bootstrap_initial_admin("admin", "StrongAdmin#2026", db_path=self.db_path)
        auth.create_user("eve", "OldPassword123!", "Approver", actor_role="Admin", db_path=self.db_path)

        # Wrong old password rejected
        with self.assertRaises(ValueError):
            auth.change_password("eve", "WrongOldPassword!", "NewPassword123!", db_path=self.db_path)

        # Successful change
        self.assertTrue(auth.change_password("eve", "OldPassword123!", "NewPassword123!", db_path=self.db_path))
        self.assertIsNone(auth.authenticate("eve", "OldPassword123!", db_path=self.db_path))
        self.assertIsNotNone(auth.authenticate("eve", "NewPassword123!", db_path=self.db_path))

    def test_maker_checker_enforced_in_backend(self):
        aid = manager.create_assessment("analyst", "Docker image", {"name": "test"}, "Normal")
        manager.save_findings(aid, [{"finding_id": "f_test", "source": "Trivy", "severity": "HIGH", "title": "Test Vuln"}])

        tid = create_ticket(aid, "f_test", "analyst", "Analyst", notes="Need patch")
        self.assertIsInstance(tid, int)

        change_ticket(tid, "Pending Approval", "analyst", "Analyst")

        with self.assertRaises(PermissionError) as ctx_role:
            change_ticket(tid, "Approved", "analyst", "Analyst", notes="Self approving")
        self.assertIn("Only an approver or admin", str(ctx_role.exception))

        with self.assertRaises(PermissionError) as ctx_mc:
            change_ticket(tid, "Approved", "analyst", "Admin", notes="Self approving as admin")
        self.assertIn("Maker-Checker", str(ctx_mc.exception))

        updated = change_ticket(tid, "Approved", "approver", "Approver", evidence="Independent verification approved")
        self.assertIsNotNone(updated)

    def test_no_hardcoded_default_credentials_in_tracked_files(self):
        """Scan tracked non-test source, config, script, and doc files for prohibited default password patterns."""
        project_root = Path(__file__).resolve().parents[1]
        forbidden_patterns = [
            re.compile(r"VulnXAdmin!\d*", re.I),
            re.compile(r"VulnXAnalyst!\d*", re.I),
            re.compile(r"VulnXApprover!\d*", re.I),
            re.compile(r"Admin@VulnGraph\d*!", re.I),
            re.compile(r"Analyst@VulnGraph\d*!", re.I),
            re.compile(r"Approver@VulnGraph\d*!", re.I),
        ]
        skip_dirs = {".venv", "venv", "__pycache__", ".pytest_cache", ".git", "tests", "assessment_reports"}
        skip_files = {"FINAL_REPAIR_PLAN.md", "AUTHENTICATION_SECURITY_REPORT.md"}

        violations = []
        for path in project_root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.name in skip_files:
                continue
            if path.suffix.lower() not in {".py", ".md", ".ps1", ".toml", ".cfg", ".ini", ".example"} and path.name != ".env.example":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pat in forbidden_patterns:
                if pat.search(text):
                    violations.append(f"{path.relative_to(project_root)} matched {pat.pattern}")

        self.assertEqual(violations, [], f"Found hardcoded default credentials in tracked files: {violations}")


if __name__ == "__main__":
    unittest.main()
