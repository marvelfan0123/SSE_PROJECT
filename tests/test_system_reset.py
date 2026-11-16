"""Unit and integration tests for System Reset feature in VulnX."""
import json
import sqlite3
import unittest
from pathlib import Path
import tempfile
import shutil

from db_utils import connect_sqlite, initialize_all_tables
from system_reset import (
    reset_all_assessment_data,
    get_assessment_data_summary,
    terminate_active_assessment_workers,
    ASSESSMENT_TABLES_TO_CLEAR,
)
from audit_log import verify_audit_chain, get_audit_events, initialize_audit_table


class SystemResetTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db = Path(self.temp_dir) / "test_reset.db"
        initialize_all_tables(self.test_db)

        # Seed sample user
        con = connect_sqlite(self.test_db)
        con.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", "pbkdf2:sha256:dummyhash", "Admin", 1, "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
        )
        # Seed sample assessment and findings
        con.execute(
            "INSERT INTO assessments (assessment_id, created_at, updated_at, created_by, target_type, target_name, target_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("VX-TEST-001", "2026-01-01T00:00:00", "2026-01-01T00:00:00", "admin", "Docker image", "test:latest", "{}", "Completed"),
        )
        con.execute(
            "INSERT INTO assessment_findings (assessment_id, finding_id, source, finding_type, severity, title, asset, finding_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("VX-TEST-001", "F-001", "Trivy", "vulnerability", "HIGH", "Test Finding", "test:latest", "{}"),
        )
        con.execute(
            "INSERT INTO remediation_tickets (id, assessment_id, finding_id, status, requested_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1, "VX-TEST-001", "F-001", "Open", "admin", "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
        )
        con.execute(
            "INSERT INTO remediation_ticket_events (id, ticket_id, actor, actor_role, old_status, new_status, detail, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (1, 1, "admin", "Admin", "", "Open", "Initial ticket creation", "2026-01-01T00:00:00"),
        )
        con.commit()
        con.close()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_non_admin_cannot_execute_reset(self):
        """Verify non-admin roles are rejected with PermissionError."""
        with self.assertRaises(PermissionError):
            reset_all_assessment_data(
                actor="analyst",
                actor_role="Security Analyst",
                confirmation_token="RESET",
                db_path=self.test_db,
                clean_reports=False,
            )

        with self.assertRaises(PermissionError):
            reset_all_assessment_data(
                actor="approver",
                actor_role="Approver",
                confirmation_token="RESET",
                db_path=self.test_db,
                clean_reports=False,
            )

    def test_invalid_confirmation_token_rejected(self):
        """Verify tokens other than exact 'RESET' are rejected."""
        with self.assertRaises(ValueError):
            reset_all_assessment_data(
                actor="admin",
                actor_role="Admin",
                confirmation_token="reset",  # lowercase
                db_path=self.test_db,
                clean_reports=False,
            )

        with self.assertRaises(ValueError):
            reset_all_assessment_data(
                actor="admin",
                actor_role="Admin",
                confirmation_token="CONFIRM",
                db_path=self.test_db,
                clean_reports=False,
            )

    def test_successful_reset_clears_assessment_data_and_preserves_users(self):
        """Verify all assessment tables are cleared, while users table is preserved intact."""
        summary_before = get_assessment_data_summary(self.test_db)
        self.assertEqual(summary_before["total_assessments"], 1)
        self.assertEqual(summary_before["total_findings"], 1)
        self.assertEqual(summary_before["total_tickets"], 1)

        result = reset_all_assessment_data(
            actor="admin",
            actor_role="Admin",
            confirmation_token="RESET",
            db_path=self.test_db,
            clean_reports=False,
        )

        self.assertTrue(result["success"])
        self.assertGreater(result["records_deleted"], 0)

        # Verify summary after reset
        summary_after = get_assessment_data_summary(self.test_db)
        self.assertEqual(summary_after["total_assessments"], 0)
        self.assertEqual(summary_after["total_findings"], 0)
        self.assertEqual(summary_after["total_tickets"], 0)
        self.assertEqual(summary_after["grand_total_records"], 0)

        # Verify users table was preserved
        con = connect_sqlite(self.test_db)
        user_row = con.execute("SELECT username, role, is_active FROM users WHERE username='admin'").fetchone()
        self.assertIsNotNone(user_row)
        self.assertEqual(user_row[0], "admin")
        self.assertEqual(user_row[1], "Admin")
        self.assertEqual(user_row[2], 1)
        con.close()

    def test_reset_records_audit_event_and_preserves_audit_chain(self):
        """Verify system_reset action is logged and audit hash chain is intact."""
        result = reset_all_assessment_data(
            actor="admin",
            actor_role="Admin",
            confirmation_token="RESET",
            db_path=self.test_db,
            clean_reports=False,
        )
        self.assertTrue(result["success"])

        # Check audit event
        con = connect_sqlite(self.test_db)
        events = con.execute("SELECT action, role, username FROM audit_events WHERE action='system_reset'").fetchall()
        self.assertGreater(len(events), 0)
        self.assertEqual(events[0][0], "system_reset")
        self.assertEqual(events[0][1], "Admin")
        self.assertEqual(events[0][2], "admin")
        con.close()


class ResetPreservesAuditCheckpointTests(unittest.TestCase):
    def test_clean_reports_keeps_audit_checkpoint_file(self):
        """A reset must delete generated reports but never the audit checkpoint."""
        import os
        from unittest.mock import patch
        from system_reset import clean_reports_directory

        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            checkpoint = reports / "vulnx_audit_checkpoint.json"
            checkpoint.write_text("{}", encoding="utf-8")
            (reports / "VX-1").mkdir()
            (reports / "VX-1" / "report.json").write_text("{}", encoding="utf-8")
            (reports / "stray.html").write_text("x", encoding="utf-8")
            with patch.dict(os.environ, {"VULNGRAPH_AUDIT_CHECKPOINT_FILE": str(checkpoint)}):
                deleted = clean_reports_directory(reports)
            self.assertEqual(deleted, 2)
            self.assertTrue(checkpoint.exists())
            self.assertFalse((reports / "VX-1").exists())
            self.assertFalse((reports / "stray.html").exists())


class AuditCheckpointConfigTests(unittest.TestCase):
    def test_generated_key_is_random_persistent_and_not_hardcoded(self):
        import os
        from unittest.mock import patch
        import config

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(config, "PROTECTED_DIR", Path(tmp) / "prot"):
                env = {k: v for k, v in os.environ.items()
                       if k not in {"VULNGRAPH_AUDIT_CHECKPOINT_KEY", "AUDIT_CHECKPOINT_SECRET",
                                    "VULNGRAPH_AUDIT_CHECKPOINT_FILE"}}
                with patch.dict(os.environ, env, clear=True):
                    config.ensure_audit_checkpoint_config()
                    first = os.environ["VULNGRAPH_AUDIT_CHECKPOINT_KEY"]
                    self.assertGreaterEqual(len(first), 32)
                    self.assertNotIn("vulnx_enterprise", first)
                    self.assertTrue(os.environ["VULNGRAPH_AUDIT_CHECKPOINT_FILE"].startswith(str(Path(tmp))))
                    os.environ.pop("VULNGRAPH_AUDIT_CHECKPOINT_KEY")
                    config.ensure_audit_checkpoint_config()
                    self.assertEqual(os.environ["VULNGRAPH_AUDIT_CHECKPOINT_KEY"], first)


if __name__ == "__main__":
    unittest.main()

