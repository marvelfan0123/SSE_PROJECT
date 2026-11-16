# VulnX Project Structure

## Application entry point
- `app.py` — Streamlit application, authentication gate, navigation, dashboard, and page rendering.

## Scanner integrations
- `trivy_scanner.py` — Trivy container-image scan execution and report validation.
- `zap_scanner.py` — OWASP ZAP Docker execution and report parsing.
- `asset_discovery.py` — Nmap asset/port discovery and scan history access.
- `docker_lab.py` — Docker lab status and local target checks.
- `authorized_actions.py` — Role-checked entry points for scans and enrichment.

## Finding and intelligence pipeline
- `report_loader.py` — Safe JSON report loading.
- `finding_normalization.py` — Common finding representation for Trivy, Nmap, and ZAP.
- `finding_correlation.py` — Conservative duplicate grouping.
- `nvd_enrichment.py` — NVD lookup, parsing, and local cache.
- `risk_engine.py` — Explainable CVSS/severity and baseline exposure prioritization.
- `attack_path_analysis.py` — Evidence-based candidate attack-path analysis.

## Workflow and persistence
- `scan_history.py` — Scan snapshot persistence.
- `scan_comparison.py` — New/persistent/resolved finding comparisons.
- `remediation.py` — Remediation queue and verification workflow.
- `remediation_guidance.py` — Finding-specific remediation guidance.
- `db_utils.py` — Shared SQLite connection configuration.
- `data/data/scan_history.db` — Local project database (backed up before changes).

## Identity and governance
- `auth.py` — Authentication and role permissions.
- `audit_log.py` — Audit event persistence and retrieval.
- `asset_criticality.py` — Asset metadata and optional criticality records; not used as an assumed input to the simplified risk formula.

## Tests and supporting material
- `tests/` — Unit tests for scanner wrappers, parsing, normalization, risk, remediation, access control, and history.
- `tools/` — Project validation utilities.
- `zap_reports/`, `*.json` — Scanner reports and lab evidence.
- `README.md`, `DEMO_GUIDE.md`, `ROLE_BASED_ACCESS_CONTROL.md` — Setup, demo, and design documentation.
