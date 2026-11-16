"""Database-backed authentication, secure first-run bootstrap, and RBAC for VulnX.

VulnX: Scanning and Vulnerability Management Platform.
Implements:
- Bcrypt password hashing (rounds=12) with zero hardcoded or fallback credentials
- Password complexity validation
- First-run administrator bootstrap workflow (prevents duplicate initial bootstrap)
- Role-based access control (Admin, Security Analyst, Approver)
- Account lifecycle management (creation, password rotation, admin reset, activation/deactivation)
"""
from __future__ import annotations
import argparse
import getpass
import re
import sqlite3
from datetime import datetime, timezone
import bcrypt

from db_utils import connect_sqlite, initialize_all_tables, DB_PATH

# Role definitions
ROLES = ("Admin", "Security Analyst", "Approver")

# Role permissions matrix
ROLE_PERMISSIONS = {
    "Admin": frozenset({
        "view_dashboard", "view_findings", "view_scan_history", "view_scan_comparison",
        "view_assets", "view_zap_reports", "view_attack_paths", "manage_attack_path_relationships",
        "view_cve_intelligence", "enrich_cves", "run_scans", "create_remediation",
        "update_remediation_work", "approve_remediation", "verify_remediation",
        "view_audit_logs", "export_reports", "view_access_roles", "manage_users", "manage_config",
    }),
    "Security Analyst": frozenset({
        "view_dashboard", "view_findings", "view_scan_history", "view_scan_comparison",
        "view_assets", "view_zap_reports", "view_attack_paths", "manage_attack_path_relationships",
        "view_cve_intelligence", "enrich_cves", "run_scans", "create_remediation",
        "update_remediation_work", "export_reports", "view_access_roles",
    }),
    "Analyst": frozenset({  # Alias for Security Analyst
        "view_dashboard", "view_findings", "view_scan_history", "view_scan_comparison",
        "view_assets", "view_zap_reports", "view_attack_paths", "manage_attack_path_relationships",
        "view_cve_intelligence", "enrich_cves", "run_scans", "create_remediation",
        "update_remediation_work", "export_reports", "view_access_roles",
    }),
    "Approver": frozenset({
        "view_dashboard", "view_findings", "view_scan_history", "view_scan_comparison",
        "view_assets", "view_zap_reports", "view_attack_paths", "view_cve_intelligence",
        "approve_remediation", "verify_remediation", "update_remediation_work", "export_reports", "view_access_roles",
    }),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_password_strength(password: str) -> None:
    """Validate password complexity requirements before hashing."""
    if not isinstance(password, str) or len(password) < 10:
        raise ValueError("Password must be at least 10 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one numeric digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must contain at least one special character.")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with cost factor rounds=12."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def check_password(password: str, hashed: str) -> bool:
    """Verify candidate password against stored bcrypt hash."""
    if not isinstance(password, str) or not isinstance(hashed, str) or not hashed:
        return False
    try:
        if hashed.startswith(("$2b$", "$2a$", "$2y$")):
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False
    return False


def is_initial_setup_required(db_path=None) -> bool:
    """Return True if no active administrator account exists in the database."""
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        cur = con.cursor()
        count = cur.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND is_active = 1"
        ).fetchone()[0]
        return count == 0
    finally:
        con.close()


def bootstrap_initial_admin(username: str, password: str, db_path=None) -> dict:
    """Establish the initial administrator account during first-run setup.
    
    Raises RuntimeError if an active administrator already exists, preventing
    any automatic or duplicate initial bootstrap.
    """
    initialize_all_tables(db_path)
    username = (username or "").strip().lower()
    if not username or len(username) < 3 or not re.fullmatch(r"[a-z0-9_.-]+", username):
        raise ValueError("Administrator username must be at least 3 characters (letters, digits, '_', '.', '-').")
    validate_password_strength(password)

    con = connect_sqlite(db_path)
    try:
        with con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.cursor()
            admin_count = cur.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND is_active = 1"
            ).fetchone()[0]
            if admin_count > 0:
                raise RuntimeError("Initial setup is already complete; an administrator account already exists.")
            existing = cur.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                raise ValueError(f"Username '{username}' already exists.")
            now = _now()
            p_hash = hash_password(password)
            cur.execute(
                "INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at) VALUES (?, ?, 'Admin', 1, ?, ?)",
                (username, p_hash, now, now),
            )
            return {"username": username, "role": "Admin", "is_active": True, "created_at": now}
    finally:
        con.close()


def authenticate(username: str, password: str, db_path=None) -> dict | None:
    """Authenticate user against database-backed accounts.
    
    Returns safe user dict {'username': str, 'role': str} on success, else None.
    Never creates default or fallback accounts.
    """
    username = (username or "").strip().lower()
    if not username or not isinstance(password, str) or not password:
        return None
    
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        row = cur.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or not row["is_active"]:
            return None
        
        if not check_password(password, row["password_hash"]):
            return None
        
        now = _now()
        cur.execute("UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?", (now, now, row["id"]))
        con.commit()
        return {"username": row["username"], "role": row["role"]}
    finally:
        con.close()


def create_user(username: str, password: str, role: str, is_active: bool = True, actor_role: str | None = None, db_path=None) -> dict:
    """Create a new database user. Requires Admin permission if actor_role is supplied."""
    if actor_role is not None:
        require_permission(actor_role, "manage_users")
    username = (username or "").strip().lower()
    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if role not in ROLES and role != "Analyst":
        raise ValueError(f"Invalid role '{role}'. Must be one of {ROLES}.")
    validate_password_strength(password)
    
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        with con:
            cur = con.cursor()
            existing = cur.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                raise ValueError(f"Username '{username}' already exists.")
            now = _now()
            p_hash = hash_password(password)
            cur.execute(
                "INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, p_hash, role, 1 if is_active else 0, now, now),
            )
            return {"username": username, "role": role, "is_active": is_active, "created_at": now}
    finally:
        con.close()


def change_password(username: str, old_password: str, new_password: str, db_path=None) -> bool:
    """Change user password after verifying old password and new password strength."""
    username = (username or "").strip().lower()
    if not username or not old_password or not new_password:
        raise ValueError("Username, old password, and new password are required.")
    validate_password_strength(new_password)
    
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        with con:
            cur = con.cursor()
            row = cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
            if not row or not check_password(old_password, row[1]):
                raise ValueError("Current password verification failed.")
            now = _now()
            new_hash = hash_password(new_password)
            cur.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (new_hash, now, row[0]))
            return True
    finally:
        con.close()


def admin_set_password(username: str, new_password: str, actor_role: str, db_path=None) -> bool:
    """Admin-only password reset for any user."""
    require_permission(actor_role, "manage_users")
    username = (username or "").strip().lower()
    validate_password_strength(new_password)
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        with con:
            cur = con.cursor()
            row = cur.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                raise ValueError("User not found.")
            now = _now()
            new_hash = hash_password(new_password)
            cur.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (new_hash, now, row[0]))
            return True
    finally:
        con.close()


def set_user_status(username: str, is_active: bool, actor_role: str, db_path=None) -> bool:
    """Admin-only activation or deactivation of user accounts."""
    require_permission(actor_role, "manage_users")
    username = (username or "").strip().lower()
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        with con:
            cur = con.cursor()
            row = cur.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                raise ValueError("User not found.")
            now = _now()
            cur.execute("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?", (1 if is_active else 0, now, row[0]))
            return True
    finally:
        con.close()


def list_users(actor_role: str | None = None, db_path=None) -> list[dict]:
    """List all registered users without sensitive password hashes."""
    if actor_role is not None:
        require_permission(actor_role, "manage_users")
    initialize_all_tables(db_path)
    con = connect_sqlite(db_path)
    try:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        rows = cur.execute("SELECT id, username, role, is_active, created_at, updated_at, last_login FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def has_permission(role: str, permission: str) -> bool:
    """Check whether role grants specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def require_permission(role: str, permission: str) -> None:
    """Raise PermissionError unless role has requested permission."""
    if not has_permission(role, permission):
        raise PermissionError(f"Role '{role or 'Unknown'}' is not allowed to perform '{permission}'.")


def permissions_for_role(role: str):
    return ROLE_PERMISSIONS.get(role, frozenset())


def can_manage_approvals(role: str) -> bool:
    return has_permission(role, "approve_remediation")


def can_verify_remediation(role: str) -> bool:
    return has_permission(role, "verify_remediation")


def can_scan(role: str) -> bool:
    return has_permission(role, "run_scans")


def can_create_remediation(role: str) -> bool:
    return has_permission(role, "create_remediation")


def can_enrich_cves(role: str) -> bool:
    return has_permission(role, "enrich_cves")


def can_manage_attack_paths(role: str) -> bool:
    return has_permission(role, "manage_attack_path_relationships")


def allowed_remediation_statuses(role: str, current_status: str):
    """Return status transitions permitted for role."""
    if role == "Admin":
        return ["Pending", "Approved", "In Progress", "Resolved", "Rejected"]
    if role in ("Analyst", "Security Analyst"):
        transitions = {
            "Pending": ["Pending"],
            "Approved": ["Approved", "In Progress"],
            "In Progress": ["In Progress"],
            "Rejected": ["Rejected"],
            "Resolved": ["Resolved"],
        }
        return transitions.get(current_status, [current_status])
    if role == "Approver":
        transitions = {
            "Pending": ["Pending", "Approved", "Rejected"],
            "Approved": ["Approved", "Rejected", "Resolved"],
            "In Progress": ["In Progress", "Rejected", "Resolved"],
            "Rejected": ["Rejected"],
            "Resolved": ["Resolved"],
        }
        return transitions.get(current_status, [current_status])
    return [current_status]


def _cli_init_admin() -> int:
    parser = argparse.ArgumentParser(description="VulnX Secure First-Run Administrator Initialization")
    parser.add_argument("--init-admin", metavar="USERNAME", required=True, help="Administrator username to establish")
    parser.add_argument("--password", default=None, help="Optional password for automated headless environments (prefer VULNX_ADMIN_PASSWORD or interactive prompt)")
    parser.add_argument("--db", default=None, help="Optional SQLite database path")
    args = parser.parse_args()

    if not is_initial_setup_required(args.db):
        print("Error: Initial setup is already complete. An active administrator account already exists.")
        return 1

    pw1 = args.password or os.getenv("VULNX_ADMIN_PASSWORD")
    if not pw1:
        pw1 = getpass.getpass(f"Enter strong password for initial Admin '{args.init_admin}': ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Error: Passwords do not match.")
            return 1
    try:
        user = bootstrap_initial_admin(args.init_admin, pw1, db_path=args.db)
        print(f"Success: Initial administrator '{user['username']}' established.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(_cli_init_admin())
