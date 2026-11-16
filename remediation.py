from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
"""SQLite-backed remediation queue for the Scanning and Vulnerability Management Platform."""
from contextlib import contextmanager
import sqlite3
from pathlib import Path

from remediation_guidance import validate_approval, validate_resolution, validate_verification_record
from auth import require_permission, allowed_remediation_statuses

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
STATUSES = ["Pending", "Approved", "In Progress", "Resolved", "Rejected"]


def initialize_remediation_table():
    with _database_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS remediation_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                package TEXT NOT NULL,
                cve TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                fixed_version TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                owner TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        # Additive migrations preserve existing remediation records and databases.
        existing_columns = {row[1] for row in connection.execute("PRAGMA table_info(remediation_items)")}
        for column, definition in {
            "approver": "TEXT NOT NULL DEFAULT ''",
            "verification_evidence": "TEXT NOT NULL DEFAULT ''",
            "verification_status": "TEXT NOT NULL DEFAULT 'Not verified'",
        }.items():
            if column not in existing_columns:
                connection.execute(f"ALTER TABLE remediation_items ADD COLUMN {column} {definition}")


def finding_key(finding):
    return "|".join(str(finding.get(field, "")) for field in ("Target", "Package", "CVE", "Installed Version"))


def add_finding(finding, actor_role=None, actor_username=""):
    """Add a finding only for roles allowed to create remediation work."""
    require_permission(actor_role, "create_remediation")
    initialize_remediation_table()
    key = finding_key(finding)
    with _database_connection() as connection:
        cursor = connection.execute(
            """INSERT OR IGNORE INTO remediation_items
            (finding_key, target, package, cve, severity, risk_score, fixed_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (key, str(finding.get("Target", "Unknown")), str(finding.get("Package", "Unknown")),
             str(finding.get("CVE", "Unknown")), str(finding.get("Severity", "UNKNOWN")),
             int(finding.get("Risk Score", 0)), str(finding.get("Fixed Version", "No fix listed")))
        )
        return cursor.rowcount == 1


def get_remediation_items():
    initialize_remediation_table()
    with _database_connection() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, target, package, cve, severity, risk_score, fixed_version,
                      status, owner, notes, approver, verification_evidence, verification_status,
                      created_at, updated_at
               FROM remediation_items ORDER BY risk_score DESC, id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def update_remediation_item(
    item_id, status, owner, notes, approver="", verification_evidence="",
    verification_status="Not verified", actor_role=None, actor_username="",
):
    """Update a queue item with role- and transition-level authorization.

    Admin: full workflow control.
    Analyst: may edit owner/work notes and keep work Pending/In Progress.
    Approver: may approve/reject or verify resolution, but cannot reassign owner.
    """
    require_permission(actor_role, "update_remediation_work")
    if status not in STATUSES:
        raise ValueError("Unsupported remediation status")
    if verification_status not in {"Not verified", "Pass", "Still present", "Not applicable"}:
        raise ValueError("Unsupported verification status")

    initialize_remediation_table()
    with _database_connection() as connection:
        connection.row_factory = sqlite3.Row
        existing = connection.execute("SELECT * FROM remediation_items WHERE id = ?", (int(item_id),)).fetchone()
        if existing is None:
            return False
        old = dict(existing)

        if status not in allowed_remediation_statuses(actor_role, old["status"]):
            raise PermissionError(f"Role '{actor_role}' cannot change status from {old['status']} to {status}.")

        if actor_role == "Analyst":
            # Analyst can work the ticket but cannot approve or record verification.
            if approver.strip() != (old.get("approver") or ""):
                raise PermissionError("Analysts cannot change the approver field.")
            if verification_status != old.get("verification_status", "Not verified"):
                raise PermissionError("Analysts cannot change verification status.")
            if verification_evidence.strip() != (old.get("verification_evidence") or ""):
                raise PermissionError("Analysts cannot change verification evidence.")
        elif actor_role == "Approver":
            # Approval identity comes from the authenticated session, never a free-text identity.
            if owner.strip() != (old.get("owner") or ""):
                raise PermissionError("Approvers cannot reassign the remediation owner.")
            if old["status"] not in {"Approved", "In Progress", "Resolved"} and (
                verification_status != old.get("verification_status", "Not verified")
                or verification_evidence.strip() != (old.get("verification_evidence") or "")
            ):
                raise PermissionError("Approvers can record verification only after a remediation item has been approved or work has started.")
            if status in {"Approved", "Rejected", "Resolved"} and status != old["status"]:
                approver = actor_username or "Approver"
            else:
                approver = old.get("approver", "")
        elif actor_role != "Admin":
            raise PermissionError("Unknown role cannot update remediation items.")

        if actor_role == "Admin" and status in {"Approved", "Rejected", "Resolved"} and status != old["status"]:
            approver = actor_username or "Admin"
        if actor_role == "Approver" and status in {"Approved", "Rejected", "Resolved"}:
            approver = actor_username or "Approver"
        validate_approval(status, approver)
        validate_verification_record(verification_status, verification_evidence)
        if status == "Resolved":
            validate_resolution(verification_status, verification_evidence)

        cursor = connection.execute(
            """UPDATE remediation_items
               SET status = ?, owner = ?, notes = ?, approver = ?,
                   verification_evidence = ?, verification_status = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (status, owner.strip(), notes.strip(), approver.strip(), verification_evidence.strip(),
             verification_status, int(item_id))
        )
        return cursor.rowcount == 1
