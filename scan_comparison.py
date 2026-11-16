from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
"""Compare distinct Trivy report snapshots using stable normalized finding IDs."""
from contextlib import contextmanager
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = SHARED_DB_PATH


@contextmanager
def _database_connection():
    """Commit/rollback transactions and always close SQLite handles (Windows-safe)."""
    connection = connect_sqlite(DB_PATH)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def report_digest(report_text):
    return hashlib.sha256(report_text.encode("utf-8")).hexdigest()


def save_finding_snapshot(report_text, report_name, findings):
    """Persist normalized findings for each distinct report; safe on Streamlit reruns."""
    digest = report_digest(report_text)
    scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
    payload = json.dumps(findings, sort_keys=True)
    with _database_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS finding_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_hash TEXT NOT NULL UNIQUE,
                report_name TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT OR IGNORE INTO finding_snapshots (report_hash, report_name, scanned_at, findings_json) VALUES (?, ?, ?, ?)",
            (digest, report_name, scanned_at, payload),
        )
    return digest


def compare_with_previous(report_hash, report_name):
    """Compare the current report to the latest different snapshot of the same filename."""
    with _database_connection() as connection:
        connection.row_factory = sqlite3.Row
        current = connection.execute(
            "SELECT * FROM finding_snapshots WHERE report_hash = ?", (report_hash,)
        ).fetchone()
        previous = connection.execute(
            "SELECT * FROM finding_snapshots WHERE report_name = ? AND report_hash != ? ORDER BY id DESC LIMIT 1",
            (report_name, report_hash),
        ).fetchone()
    if current is None or previous is None:
        return None

    current_records = json.loads(current["findings_json"])
    previous_records = json.loads(previous["findings_json"])
    current_by_id = {record.get("finding_id"): record for record in current_records if record.get("finding_id")}
    previous_by_id = {record.get("finding_id"): record for record in previous_records if record.get("finding_id")}
    current_ids, previous_ids = set(current_by_id), set(previous_by_id)
    resolved = [previous_by_id[key] for key in sorted(previous_ids - current_ids)]
    persistent = [current_by_id[key] for key in sorted(current_ids & previous_ids)]
    new = [current_by_id[key] for key in sorted(current_ids - previous_ids)]
    return {
        "previous_scan_id": previous["id"],
        "previous_scanned_at": previous["scanned_at"],
        "current_scanned_at": current["scanned_at"],
        "previous_total": len(previous_records),
        "current_total": len(current_records),
        "resolved": resolved,
        "persistent": persistent,
        "new": new,
        "severity_counts": {
            "previous": _severity_counts(previous_records),
            "current": _severity_counts(current_records),
        },
    }


def _severity_counts(records):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for record in records:
        severity = str(record.get("severity", "UNKNOWN")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def compare_scans(base_scan, target_scan):
    """Compare two assessment dicts or finding lists and return new, resolved, and common findings."""
    from assessment_comparison import compare_assessment_findings
    base_findings = base_scan.get("findings", []) if isinstance(base_scan, dict) else list(base_scan or [])
    target_findings = target_scan.get("findings", []) if isinstance(target_scan, dict) else list(target_scan or [])
    res = compare_assessment_findings(base_findings, target_findings)
    return {
        "new": res["new"],
        "persistent": res["persistent"],
        "no_longer_detected": res["no_longer_detected"],
        "new_findings": res["new"],
        "resolved_findings": res["no_longer_detected"],
        "common_findings": res["persistent"],
    }
