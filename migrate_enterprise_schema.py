"""Additive Enterprise Schema Migration for VulnX.

Preserves 100% of existing assessment records, user accounts, findings, and audit events.
"""
import sqlite3
import sys
from pathlib import Path
from db_utils import DB_PATH

def migrate_database(db_path: Path = DB_PATH):
    print(f"Connecting to database: {db_path}")
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON;")
    
    with con:
        # 1. AI Recommendations Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS ai_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            assessment_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            playbook_json TEXT NOT NULL DEFAULT '{}',
            change_risk TEXT NOT NULL DEFAULT 'Unknown',
            virtual_patch_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_rec_finding ON ai_recommendations(finding_id);")

        # 2. Attack Paths Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            source_node TEXT NOT NULL,
            target_cve TEXT NOT NULL,
            length INTEGER NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            path_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 3. Staging Evidence Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS staging_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            filename TEXT NOT NULL,
            evidence_type TEXT NOT NULL DEFAULT 'log',
            content_summary TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES remediation_tickets(id) ON DELETE CASCADE
        );
        """)

        # 4. Assessment Comparisons Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS assessment_comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_assessment_id TEXT NOT NULL,
            rescan_assessment_id TEXT NOT NULL,
            fixed_count INTEGER NOT NULL DEFAULT 0,
            persistent_count INTEGER NOT NULL DEFAULT 0,
            new_count INTEGER NOT NULL DEFAULT 0,
            comparison_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 5. System Settings Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT NOT NULL DEFAULT 'Admin'
        );
        """)

        # 6. Roles Table
        con.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            role_name TEXT PRIMARY KEY,
            description TEXT NOT NULL
        );
        """)
        # Populate roles idempotently
        con.execute("INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Admin', 'Full administrative authority and audit management');")
        con.execute("INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Security Analyst', 'Launches assessments and proposes remediation');")
        con.execute("INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Approver', 'Independent Maker-Checker ticket authorization');")
        con.execute("INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Viewer', 'Read-only access to findings and reports');")

        # 7. Default System Settings
        con.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('threat_enrichment_enabled', '1', 'System');")
        con.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('ai_provider_mode', 'auto', 'System');")
        con.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('maker_checker_enforced', '1', 'System');")

    print("Enterprise schema migration applied successfully.")
    con.close()

if __name__ == "__main__":
    migrate_database()

