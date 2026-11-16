"""Shared SQLite connection and schema policy for VulnX.

VulnX: Scanning and Vulnerability Management Platform.
Configures WAL mode, busy timeout, foreign-key enforcement, and manages
schema initialization and migrations across all assessment data tables.
"""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.getenv("VULNX_DATABASE_PATH") or
    os.getenv("DATABASE_PATH") or
    os.getenv("VULNGRAPH_DATABASE_PATH") or
    str(PROJECT_DIR / "scan_history.db")
).expanduser()
SQLITE_BUSY_TIMEOUT_MS = max(1000, min(int(os.getenv("VULNX_SQLITE_BUSY_TIMEOUT_MS") or os.getenv("VULNGRAPH_SQLITE_BUSY_TIMEOUT_MS") or "15000"), 120000))


def connect_sqlite(path: str | Path | None = None) -> sqlite3.Connection:
    """Open a consistently configured SQLite connection with WAL and Foreign Keys."""
    target = Path(path) if path is not None else DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target), timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def initialize_all_tables(path: str | Path | None = None) -> None:
    """Initialize all 16 VulnX relational schema tables with foreign keys and indexes."""
    con = connect_sqlite(path)
    try:
        with con:
            con.executescript("""
            -- 1. Users & Authentication
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT
            );

            -- 2. Assessments
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                target_json TEXT NOT NULL,
                criticality TEXT NOT NULL DEFAULT 'Normal',
                status TEXT NOT NULL,
                stage TEXT NOT NULL DEFAULT 'Queued',
                error TEXT NOT NULL DEFAULT '',
                worker_pid INTEGER,
                heartbeat_at TEXT
            );

            -- 3. Assessment Scanners
            CREATE TABLE IF NOT EXISTS assessment_scanners (
                assessment_id TEXT NOT NULL,
                scanner TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                message TEXT NOT NULL DEFAULT '',
                result_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (assessment_id, scanner),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 4. Assessment Scanner Execution Attempts
            CREATE TABLE IF NOT EXISTS assessment_attempts (
                assessment_id TEXT NOT NULL,
                scanner TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (assessment_id, scanner, attempt),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 5. Discovered Hosts
            CREATE TABLE IF NOT EXISTS assessment_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'up',
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 6. Discovered Ports
            CREATE TABLE IF NOT EXISTS assessment_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL DEFAULT 'open',
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 7. Discovered Services
            CREATE TABLE IF NOT EXISTS assessment_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 8. Discovered Containers
            CREATE TABLE IF NOT EXISTS vg_containers (
                assessment_id TEXT NOT NULL,
                container_id TEXT NOT NULL,
                container_json TEXT NOT NULL,
                PRIMARY KEY (assessment_id, container_id),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 9. Container Images
            CREATE TABLE IF NOT EXISTS assessment_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                image_name TEXT NOT NULL,
                image_id TEXT NOT NULL DEFAULT '',
                digest TEXT NOT NULL DEFAULT '',
                container_id TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 10. Package Dependencies
            CREATE TABLE IF NOT EXISTS assessment_dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                image_name TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                fixed_version TEXT NOT NULL DEFAULT '',
                ecosystem TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 11. Assessment Findings (Normalized across Trivy, Nmap, ZAP)
            CREATE TABLE IF NOT EXISTS assessment_findings (
                assessment_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                source TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                asset TEXT NOT NULL,
                cve TEXT NOT NULL DEFAULT '',
                package TEXT NOT NULL DEFAULT '',
                cvss REAL,
                exposure_factor REAL,
                criticality_factor REAL,
                risk_score REAL,
                risk_label TEXT NOT NULL DEFAULT 'Unscored',
                finding_json TEXT NOT NULL,
                PRIMARY KEY (assessment_id, finding_id),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 12. Vulnerabilities Knowledge Base
            CREATE TABLE IF NOT EXISTS assessment_vulnerabilities (
                cve TEXT PRIMARY KEY,
                cvss REAL,
                severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                description TEXT NOT NULL DEFAULT '',
                published_date TEXT NOT NULL DEFAULT '',
                last_modified TEXT NOT NULL DEFAULT ''
            );

            -- 13. EPSS Snapshots
            CREATE TABLE IF NOT EXISTS assessment_epss_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT NOT NULL,
                epss_score REAL NOT NULL,
                percentile REAL NOT NULL,
                retrieved_at TEXT NOT NULL
            );

            -- 14. Contextual Risk Calculations (Audit & Provenance)
            CREATE TABLE IF NOT EXISTS assessment_risk_calculations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                model_version TEXT NOT NULL,
                cvss REAL,
                epss REAL,
                reachability REAL,
                criticality INTEGER,
                calculated_risk REAL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                calculated_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 15. Graph Asset Relationships
            CREATE TABLE IF NOT EXISTS vg_asset_relationships (
                assessment_id TEXT NOT NULL,
                relationship_id TEXT NOT NULL,
                relationship_json TEXT NOT NULL,
                PRIMARY KEY (assessment_id, relationship_id),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 16. OWASP Classifications
            CREATE TABLE IF NOT EXISTS vg_owasp_classifications (
                assessment_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                classification_json TEXT NOT NULL,
                PRIMARY KEY (assessment_id, finding_id),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 17. Remediation Tickets / Recommendations
            CREATE TABLE IF NOT EXISTS remediation_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                owner TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                requested_by TEXT NOT NULL,
                approved_by TEXT NOT NULL DEFAULT '',
                verified_by TEXT NOT NULL DEFAULT '',
                verification_assessment TEXT NOT NULL DEFAULT '',
                verification_evidence TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (assessment_id, finding_id),
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            );

            -- 18. Remediation Approval Decisions & Events
            CREATE TABLE IF NOT EXISTS remediation_ticket_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                actor TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                old_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                detail TEXT NOT NULL,
                at TEXT NOT NULL,
                FOREIGN KEY (ticket_id) REFERENCES remediation_tickets(id) ON DELETE CASCADE
            );

            -- 19. Audit Events (SHA-256 Hash Chain)
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT 'anonymous',
                role TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL DEFAULT '',
                entity_id TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                previous_hash TEXT,
                event_hash TEXT
            );

            -- 20. NVD Cache
            CREATE TABLE IF NOT EXISTS assessment_nvd_cache (
                cve TEXT PRIMARY KEY,
                cached_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            );

            -- 21. Persistent Background NVD Enrichment Queue
            CREATE TABLE IF NOT EXISTS assessment_nvd_queue (
                cve TEXT PRIMARY KEY,
                assessment_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt_at TEXT,
                next_attempt_at TEXT,
                error TEXT,
                enqueued_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- 22. AI Recommendations
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
            CREATE INDEX IF NOT EXISTS idx_ai_rec_finding ON ai_recommendations(finding_id);

            -- 23. Attack Paths
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

            -- 24. Staging Evidence
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

            -- 25. Assessment Comparisons
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

            -- 26. System Settings
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT NOT NULL DEFAULT 'Admin'
            );

            -- 27. Roles
            CREATE TABLE IF NOT EXISTS roles (
                role_name TEXT PRIMARY KEY,
                description TEXT NOT NULL
            );
            INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Admin', 'Full administrative authority and audit management');
            INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Security Analyst', 'Launches assessments and proposes remediation');
            INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Approver', 'Independent Maker-Checker ticket authorization');
            INSERT OR IGNORE INTO roles (role_name, description) VALUES ('Viewer', 'Read-only access to findings and reports');

            INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('threat_enrichment_enabled', '1', 'System');
            INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('ai_provider_mode', 'auto', 'System');
            INSERT OR IGNORE INTO system_settings (key, value, updated_by) VALUES ('maker_checker_enforced', '1', 'System');

            -- Performance Indexes
            CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_assessment_findings_assessment ON assessment_findings(assessment_id, source);
            CREATE INDEX IF NOT EXISTS idx_assessment_findings_cve ON assessment_findings(cve);
            CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_epss_cve ON assessment_epss_snapshots(cve);
            CREATE INDEX IF NOT EXISTS idx_risk_calc_assessment ON assessment_risk_calculations(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_nvd_queue_status ON assessment_nvd_queue(status, next_attempt_at);
            """)
            existing_cols = {row[1] for row in con.execute("PRAGMA table_info(assessments)")}
            if "worker_pid" not in existing_cols:
                con.execute("ALTER TABLE assessments ADD COLUMN worker_pid INTEGER")
            if "heartbeat_at" not in existing_cols:
                con.execute("ALTER TABLE assessments ADD COLUMN heartbeat_at TEXT")
    finally:
        con.close()
