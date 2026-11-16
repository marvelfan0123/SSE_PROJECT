# VulnX project layout

- `app.py`: Streamlit entry point and page routing.
- `config.py`: Loads `.env` before database configuration is evaluated.
- `core` responsibilities currently live in `assessment_manager.py`, `assessment_worker.py`, `db_utils.py`, `auth.py`, and `audit_log.py` at the project root to avoid risky import-path migrations.
- Scanner integrations: `trivy_scanner.py`, `asset_discovery.py` (Nmap), and `zap_scanner.py`.
- Analysis: `finding_normalization.py`, `finding_correlation.py`, `nvd_enrichment.py`, `risk_model.py`, and `assessment_comparison.py`.
- Other feature modules: `remediation.py`, `asset_criticality.py`, `asset_criticality_engine.py`, and `attack_path_analysis.py`.
- `tests/`: automated unit and integration-style mocked tests.
- `data/scan_history.db`: persistent SQLite database (WAL enabled).
- `data/cache/`: legacy report-view NVD cache. Assessment NVD cache is in SQLite.
- `data/legacy_reports/`: historical Trivy/ZAP JSON reports retained for the legacy report viewer; these are not current assessment results.
- `data/backups/`: historical database backup retained for recovery/reference only.
- `assessment_reports/`: generated per-assessment scanner reports and worker logs.
- `docs/`: current setup, architecture, demo and historical update notes.

The application modules remain at the root in this release because moving them into Python packages without a full import migration would create more risk than benefit. The data and documentation clutter has been separated without changing the existing database contents.
