"""Safe, repeatable end-to-end validation of VulnX scan comparison.

Uses a temporary SQLite database and never modifies scan_history.db.
Run from the project root: python tools/validate_scan_comparison.py
"""
import json
import tempfile
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import scan_comparison
from finding_normalization import normalize_trivy_report


def load_normalized(filename):
    path = ROOT / filename
    with path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    return path.read_text(encoding="utf-8"), normalize_trivy_report(report, filename)


def main():
    baseline_text, baseline = load_normalized("juice-shop-trivy-backup.json")
    current_text, current = load_normalized("juice-shop-trivy.json")

    print("VulnX Scan Comparison Validation")
    print("================================")
    print(f"Baseline report: juice-shop-trivy-backup.json ({len(baseline)} findings)")
    print(f"Current report:  juice-shop-trivy.json ({len(current)} findings)")
    baseline_ids = {item["finding_id"] for item in baseline}
    current_ids = {item["finding_id"] for item in current}
    print(f"Actual report identity diff: {len(current_ids - baseline_ids)} new, "
          f"{len(baseline_ids - current_ids)} no longer detected, "
          f"{len(current_ids & baseline_ids)} persistent")

    # Controlled fixture verifies all three outcomes without touching user data.
    stable = {"finding_id": "DEMO-PERSISTENT-001", "severity": "HIGH", "package": "demo", "cve": "CVE-DEMO-1"}
    removed = {"finding_id": "DEMO-REMOVED-001", "severity": "MEDIUM", "package": "old-demo", "cve": "CVE-DEMO-2"}
    added = {"finding_id": "DEMO-NEW-001", "severity": "CRITICAL", "package": "new-demo", "cve": "CVE-DEMO-3"}
    with tempfile.TemporaryDirectory(prefix="vulnx_compare_check_") as temp_dir:
        temp_db = Path(temp_dir) / "comparison_test.db"
        with patch.object(scan_comparison, "DB_PATH", temp_db):
            scan_comparison.save_finding_snapshot(baseline_text, "demo-report.json", [stable, removed])
            current_hash = scan_comparison.save_finding_snapshot(current_text, "demo-report.json", [stable, added])
            result = scan_comparison.compare_with_previous(current_hash, "demo-report.json")
            assert result is not None, "Expected two distinct snapshots to compare"
            assert [x["finding_id"] for x in result["new"]] == ["DEMO-NEW-001"]
            assert [x["finding_id"] for x in result["resolved"]] == ["DEMO-REMOVED-001"]
            assert [x["finding_id"] for x in result["persistent"]] == ["DEMO-PERSISTENT-001"]
            print("\nControlled comparison fixture: PASS")
            print(f"  New:              {len(result['new'])}")
            print(f"  Persistent:       {len(result['persistent'])}")
            print(f"  No longer detected: {len(result['resolved'])}")
            print("Temporary database removed; project scan_history.db was not modified.")


if __name__ == "__main__":
    main()
