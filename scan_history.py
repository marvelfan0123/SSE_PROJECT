from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
"""SQLite persistence for scan snapshots in the Scanning and Vulnerability Management Platform."""
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


def initialize_database():
    with _database_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                report_hash TEXT NOT NULL UNIQUE,
                report_name TEXT NOT NULL,
                targets TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                unknown_count INTEGER NOT NULL
            )"""
        )


def save_scan_snapshot(report_text, report_name, targets, counts, total_findings):
    """Save each distinct report once so Streamlit reruns don't create duplicate history."""
    report_hash = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
    target_text = ", ".join(sorted(set(targets))) or "Unknown"

    with _database_connection() as connection:
        cursor = connection.execute(
            """INSERT OR IGNORE INTO scans (
                scanned_at, report_hash, report_name, targets, total_findings,
                critical_count, high_count, medium_count, low_count, unknown_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scanned_at, report_hash, report_name, target_text, total_findings,
                counts.get("CRITICAL", 0), counts.get("HIGH", 0),
                counts.get("MEDIUM", 0), counts.get("LOW", 0),
                counts.get("UNKNOWN", 0),
            ),
        )
        return cursor.rowcount == 1


def get_scan_history(limit=50):
    with _database_connection() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, scanned_at, report_name, targets, total_findings,
                      critical_count, high_count, medium_count, low_count, unknown_count
               FROM scans ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
