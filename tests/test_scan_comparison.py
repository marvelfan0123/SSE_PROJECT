import json
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scan_comparison


class ScanComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.db"
        self.patch = patch.object(scan_comparison, "DB_PATH", self.db)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def record(self, finding_id, severity="HIGH", package="pkg", version="1.0"):
        return {"finding_id": finding_id, "severity": severity, "package": package,
                "cve": "CVE-2025-0001", "installed_version": version, "asset": "image"}

    def test_classifies_resolved_persistent_and_new(self):
        old = [self.record("a"), self.record("b"), self.record("version-1", version="1.0")]
        new = [self.record("b"), self.record("c"), self.record("version-2", version="2.0")]
        old_text, new_text = json.dumps({"old": True}), json.dumps({"new": True})
        scan_comparison.save_finding_snapshot(old_text, "report.json", old)
        current_hash = scan_comparison.save_finding_snapshot(new_text, "report.json", new)
        result = scan_comparison.compare_with_previous(current_hash, "report.json")
        self.assertEqual({x["finding_id"] for x in result["resolved"]}, {"a", "version-1"})
        self.assertEqual({x["finding_id"] for x in result["persistent"]}, {"b"})
        self.assertEqual({x["finding_id"] for x in result["new"]}, {"c", "version-2"})

    def test_same_report_name_is_required(self):
        scan_comparison.save_finding_snapshot("one", "first.json", [self.record("a")])
        current_hash = scan_comparison.save_finding_snapshot("two", "second.json", [self.record("b")])
        self.assertIsNone(scan_comparison.compare_with_previous(current_hash, "second.json"))

    def test_duplicate_snapshot_does_not_create_new_version(self):
        text = "same report"
        scan_comparison.save_finding_snapshot(text, "report.json", [self.record("a")])
        scan_comparison.save_finding_snapshot(text, "report.json", [self.record("a")])
        # sqlite3 connection context managers do not close connections; use closing
        # so Windows can remove the temporary database during tearDown.
        with closing(scan_comparison.sqlite3.connect(self.db)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM finding_snapshots").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
