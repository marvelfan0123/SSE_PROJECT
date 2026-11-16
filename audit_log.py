from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
"""SQLite-backed SHA-256 hash-chained audit trail for VulnX.

VulnX: Scanning and Vulnerability Management Platform.
Provides append-only cryptographic hash chaining and external HMAC-SHA256 checkpoint verification.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import hashlib
import hmac
import sqlite3
from pathlib import Path

from auth import require_permission
from security_controls import redact_audit_details

DB_PATH = SHARED_DB_PATH


@contextmanager
def _connection():
    connection = connect_sqlite(DB_PATH)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_audit_table():
    with _connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT 'anonymous',
                role TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL DEFAULT '',
                entity_id TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        existing = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
        for column in ("previous_hash", "event_hash"):
            if column not in existing:
                connection.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at DESC)"
        )


def log_event(username, role, action, entity_type="", entity_id="", details=None):
    """Append one audit event; never store passwords or secret values here."""
    initialize_audit_table()
    details_json = json.dumps(redact_audit_details(details or {}), sort_keys=True, ensure_ascii=False, default=str)
    with _connection() as connection:
        # IMMEDIATE transaction serializes writers, preventing forked hash chains.
        connection.execute("BEGIN IMMEDIATE")
        last = connection.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = last[0] if last and last[0] else "GENESIS"
        values = (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  str(username or "anonymous")[:120], str(role or "")[:80],
                  str(action)[:120], str(entity_type)[:120], str(entity_id)[:120], details_json[:4000])
        payload = json.dumps([previous, *values], ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        connection.execute(
            """INSERT INTO audit_events
               (occurred_at, username, role, action, entity_type, entity_id, details_json, previous_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (*values, previous, digest))


def verify_audit_chain(actor_role):
    """Verify app-level chaining. Legacy unchained events are reported, never silently trusted."""
    require_permission(actor_role, "view_audit_logs")
    initialize_audit_table()
    with _connection() as connection:
        rows = connection.execute("SELECT id,occurred_at,username,role,action,entity_type,entity_id,details_json,previous_hash,event_hash FROM audit_events ORDER BY id").fetchall()
    previous = "GENESIS"
    for row in rows:
        event_id, *data = row
        values = data[:7]
        prev, digest = data[7:]
        if not prev or not digest:
            return {"valid":False,"event_id":event_id,"reason":"Legacy or unchained audit record"}
        if prev != previous:
            return {"valid":False,"event_id":event_id,"reason":"Broken predecessor hash"}
        expected = hashlib.sha256(json.dumps([prev,*values],ensure_ascii=False,separators=(",", ":")).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected, digest):
            return {"valid":False,"event_id":event_id,"reason":"Audit record modified"}
        previous = digest
    return {"valid":True,"checked":len(rows),"last_hash":previous}


def get_audit_events(limit=200, actor_role=None):
    require_permission(actor_role, "view_audit_logs")
    initialize_audit_table()
    limit = max(1, min(int(limit), 1000))
    with _connection() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, occurred_at, username, role, action, entity_type, entity_id, details_json
               FROM audit_events ORDER BY id DESC LIMIT ?""", (limit,)
        ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json"))
        except (TypeError, json.JSONDecodeError):
            item["details"] = {}
        events.append(item)
    return events


def get_scan_activity(limit=1000):
    """Return scanner-completion events for dashboard readiness and latest-scan context.

    This intentionally exposes only scan activity, not the full audit log, so
    ordinary signed-in roles can determine whether the workspace has scan data.
    """
    initialize_audit_table()
    limit = max(1, min(int(limit), 5000))
    scan_actions = (
        "trivy_image_scan_completed",
        "nmap_scan_completed",
        "zap_baseline_scan_completed",
    )
    placeholders = ", ".join("?" for _ in scan_actions)
    with _connection() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"SELECT id, occurred_at, username, role, action, entity_type, entity_id, details_json "
            f"FROM audit_events WHERE action IN ({placeholders}) ORDER BY id DESC LIMIT ?",
            (*scan_actions, limit),
        ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json"))
        except (TypeError, json.JSONDecodeError):
            item["details"] = {}
        events.append(item)
    return events
