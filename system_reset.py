"""System Reset Module for VulnX: Scanning and Vulnerability Management Platform.

Provides secure, administrator-only transactional reset capabilities for all
assessment-related data, preserving user credentials, roles, permissions, audit
history, and database schema.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
from audit_log import log_event

# Ordered to respect foreign-key constraints
ASSESSMENT_TABLES_TO_CLEAR = [
    # 1. Remediation child events & tickets
    "remediation_ticket_events",
    "remediation_tickets",
    "remediation_actions",
    "remediation_items",
    # 2. Attack graph & calculations
    "vg_owasp_classifications",
    "vg_asset_relationships",
    "vg_containers",
    "assessment_risk_calculations",
    "assessment_findings",
    # 3. Discovered inventory & dependencies
    "assessment_dependencies",
    "assessment_images",
    "assessment_services",
    "assessment_ports",
    "assessment_hosts",
    "asset_profiles",
    "asset_scans",
    # 4. Scanners, attempts, snapshots & parent assessments
    "assessment_attempts",
    "assessment_scanners",
    "assessment_vulnerabilities",
    "assessment_epss_snapshots",
    "assessment_nvd_cache",
    "assessment_nvd_queue",
    "finding_snapshots",
    "scans",
    "assessments",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_assessment_data_summary(db_path: str | Path | None = None) -> dict[str, int]:
    """Return record counts across assessment-related tables."""
    con = connect_sqlite(db_path or SHARED_DB_PATH)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        summary: dict[str, int] = {}
        for tbl in ASSESSMENT_TABLES_TO_CLEAR:
            if tbl in tables:
                cnt = con.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()[0]
                summary[tbl] = cnt
            else:
                summary[tbl] = 0

        return {
            "total_assessments": summary.get("assessments", 0),
            "total_findings": summary.get("assessment_findings", 0),
            "total_hosts": summary.get("assessment_hosts", 0),
            "total_ports": summary.get("assessment_ports", 0),
            "total_services": summary.get("assessment_services", 0),
            "total_containers": summary.get("vg_containers", 0),
            "total_images": summary.get("assessment_images", 0),
            "total_dependencies": summary.get("assessment_dependencies", 0),
            "total_tickets": summary.get("remediation_tickets", 0),
            "total_risk_calculations": summary.get("assessment_risk_calculations", 0),
            "total_cached_records": summary.get("assessment_nvd_cache", 0),
            "grand_total_records": sum(summary.values()),
        }
    finally:
        con.close()


def terminate_active_assessment_workers(db_path: str | Path | None = None) -> list[int]:
    """Terminate any background workers for active assessments to prevent concurrent writes."""
    con = connect_sqlite(db_path or SHARED_DB_PATH)
    terminated_pids: list[int] = []
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "assessments" not in tables:
            return terminated_pids

        con.row_factory = sqlite3.Row
        active_rows = con.execute(
            "SELECT assessment_id, worker_pid, status FROM assessments WHERE status IN ('Queued', 'Running', 'Discovering assets', 'Processing findings')"
        ).fetchall()

        for row in active_rows:
            pid = row["worker_pid"]
            if pid:
                try:
                    pid_int = int(pid)
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(pid_int)],
                            capture_output=True,
                            timeout=5,
                            check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                    else:
                        os.kill(pid_int, 15)
                    terminated_pids.append(pid_int)
                except Exception:
                    pass
        return terminated_pids
    finally:
        con.close()


def _protected_paths() -> list[Path]:
    """Paths that a reset must never delete (audit checkpoint file and key)."""
    paths: list[Path] = []
    for env_name in ("VULNGRAPH_AUDIT_CHECKPOINT_FILE",):
        value = os.environ.get(env_name, "")
        if value:
            try:
                paths.append(Path(value).expanduser().resolve())
            except OSError:
                pass
    try:
        from config import PROTECTED_DIR
        paths.append(PROTECTED_DIR.resolve())
    except Exception:
        pass
    return paths


def clean_reports_directory(reports_dir: str | Path | None = None) -> int:
    """Safely delete generated report files and worker logs, preserving the parent directory."""
    from assessment_manager import REPORT_DIR

    target_dir = Path(reports_dir) if reports_dir is not None else REPORT_DIR
    deleted_count = 0
    protected = _protected_paths()
    if target_dir.exists() and target_dir.is_dir():
        for item in list(target_dir.iterdir()):
            try:
                resolved = item.resolve()
                # Never delete the audit checkpoint/key (tamper-evidence must survive a reset),
                # nor any directory that contains one.
                if any(p == resolved or resolved in p.parents for p in protected):
                    continue
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    deleted_count += 1
                elif item.is_file():
                    item.unlink(missing_ok=True)
                    deleted_count += 1
            except Exception:
                pass
    return deleted_count


def reset_all_assessment_data(
    actor: str,
    actor_role: str,
    confirmation_token: str,
    db_path: str | Path | None = None,
    clean_reports: bool = True,
) -> dict[str, Any]:
    """Execute transactional administrator-only platform reset for all assessment data.

    Preserves:
    - User accounts and login credentials (users table)
    - Roles, permissions, and authentication configuration
    - Application settings and scanner integrations
    - Database schema and migrations
    - Audit logs (appends cryptographic system_reset event)

    Requires:
    - actor_role == 'Admin'
    - confirmation_token == 'RESET'
    """
    # 1. Authorization check
    if str(actor_role).strip() != "Admin":
        raise PermissionError("Access denied: Administrator role is required to perform system reset.")

    # 2. Server-side confirmation token validation
    if str(confirmation_token).strip() != "RESET":
        raise ValueError("Confirmation token mismatch: Server requires confirmation_token='RESET'.")

    target_db = Path(db_path) if db_path is not None else SHARED_DB_PATH
    start_time = _now()

    # 3. Terminate active background workers to prevent concurrent writes
    terminated_pids = terminate_active_assessment_workers(target_db)

    # 4. Atomic Database Transaction
    con = connect_sqlite(target_db)
    cleared_tables: dict[str, int] = {}
    total_records_deleted = 0

    try:
        # SQLite ignores PRAGMA foreign_keys inside an open transaction, so enable it first.
        con.execute("PRAGMA foreign_keys = ON")
        with con:
            # Discover existing tables
            existing_tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

            for tbl in ASSESSMENT_TABLES_TO_CLEAR:
                if tbl in existing_tables:
                    # Count rows before deletion
                    cnt = con.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()[0]
                    if cnt > 0:
                        con.execute(f'DELETE FROM "{tbl}"')
                        cleared_tables[tbl] = cnt
                        total_records_deleted += cnt
                    else:
                        cleared_tables[tbl] = 0

            # Reset autoincrement sequence counters for cleared tables
            if "sqlite_sequence" in existing_tables:
                placeholders = ",".join(["?" for _ in cleared_tables])
                if placeholders:
                    con.execute(
                        f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                        list(cleared_tables.keys()),
                    )

            # Verification: Ensure zero rows remain in any of the cleared tables
            for tbl in ASSESSMENT_TABLES_TO_CLEAR:
                if tbl in existing_tables:
                    remaining = con.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()[0]
                    if remaining != 0:
                        raise RuntimeError(f"Reset validation failed: table '{tbl}' still contains {remaining} rows after deletion.")

            # Verification: Ensure users table was preserved and untouched
            if "users" in existing_tables:
                user_count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                if user_count == 0:
                    raise RuntimeError("Critical error: Users table was inadvertently modified during reset! Rolling back transaction.")

    finally:
        con.close()

    # 5. Clean report files on disk if requested
    deleted_report_files = 0
    if clean_reports:
        deleted_report_files = clean_reports_directory()

    end_time = _now()

    # 6. Cryptographically record reset event in audit log (preserves chain)
    audit_details = {
        "status": "success",
        "scope": "all_assessment_data",
        "total_records_deleted": total_records_deleted,
        "tables_cleared": {k: v for k, v in cleared_tables.items() if v > 0},
        "report_files_removed": deleted_report_files,
        "workers_terminated": terminated_pids,
        "initiated_at": start_time,
        "completed_at": end_time,
    }

    try:
        # If running against the primary DB, log via standard audit_log
        if not db_path or Path(db_path).resolve() == SHARED_DB_PATH.resolve():
            log_event(
                username=actor,
                role=actor_role,
                action="system_reset",
                entity_type="system",
                entity_id="all_assessments",
                details=audit_details,
            )
        else:
            # If running against a custom db path in tests
            con_audit = connect_sqlite(target_db)
            try:
                with con_audit:
                    # Append audit record to custom db
                    last = con_audit.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
                    prev_hash = last[0] if last and last[0] else "GENESIS"
                    import hashlib
                    vals = (end_time, str(actor)[:120], str(actor_role)[:80], "system_reset", "system", "all_assessments", json.dumps(audit_details, sort_keys=True))
                    payload = json.dumps([prev_hash, *vals], ensure_ascii=False, separators=(",", ":"))
                    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    con_audit.execute(
                        "INSERT INTO audit_events (occurred_at, username, role, action, entity_type, entity_id, details_json, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (*vals, prev_hash, digest),
                    )
            finally:
                con_audit.close()
    except Exception as exc:
        audit_details["audit_logging_warning"] = str(exc)

    return {
        "success": True,
        "records_deleted": total_records_deleted,
        "tables_cleared": cleared_tables,
        "report_files_removed": deleted_report_files,
        "workers_terminated": terminated_pids,
        "initiated_at": start_time,
        "completed_at": end_time,
    }

