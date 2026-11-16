# VulnX repair and validation report

## Changes made in this repair

1. Centralized `.env` loading in `config.py` and load it before database modules initialize.
2. Made relative `VULNX_DATABASE_PATH` values resolve from the project directory, so the app and detached worker use the same SQLite file.
3. Moved the active SQLite database to `data/scan_history.db`. Its SHA-256 and byte size were checked against the source ZIP; the database contents were preserved byte-for-byte.
4. Retained SQLite WAL, busy timeout, foreign keys and normal synchronous mode through the shared connection helper.
5. Unified the legacy report-driven risk API as an adapter to `risk_model.py`; there is now one canonical scoring policy.
6. Preserved Trivy-provided CVSS when present. NVD CVSS is a fallback only when scanner CVSS is absent; NVD remains supplemental enrichment.
7. Kept ZAP High/Medium/Low/Informational base scores and kept Nmap open ports as unscored exposure observations.
8. Added dynamic local ZAP target URL validation for verified Docker-published ports, while rejecting non-local URLs.
9. Changed Docker application mapping to use the container's internal port and application identity rather than assuming the published host port equals the app port.
10. Scoped worker log file handles correctly when launching the detached worker.
11. Moved historical Trivy/ZAP JSON files, the legacy NVD JSON cache, and the old DB backup into clearly labelled `data/` subfolders.
12. Moved historical update notes and project reference documents into `docs/` and added `docs/PROJECT_LAYOUT.md`.
13. Updated README, `.env.example`, UI labels and tests to match the configuration, data paths and risk policy.

## Validation performed

- Python compilation: passed (`python -m compileall -q .`).
- Unit tests: 138 passed.
- ZIP integrity: checked after packaging.
- SQLite integrity: `PRAGMA integrity_check` returned `ok`.
- Existing SQLite database preservation: verified byte-for-byte against the source archive.
- Streamlit UI and live Docker/Trivy/Nmap/ZAP execution: not run in this environment. Streamlit and the scanner runtimes are not installed here. A real Juice Shop end-to-end scan must still be run on the user's Windows/Docker Desktop setup.

## Important boundaries

- Existing Python modules remain at the project root to avoid a risky package/import migration. Data and documentation have been organized without a disruptive rewrite.
- Historical reports remain available in `data/legacy_reports/` for the legacy report viewer. They are not current assessment results and are not mixed into assessment-scoped Dashboard results.
- NVD enrichment attempts up to 10 uncached CVEs per assessment to bound the initial demo duration. Remaining CVEs are not represented as enriched; they can be attempted in later assessments.
- ZAP remains a passive Baseline scan with bounded spider duration and timeout.
- Docker socket access remains a privileged operation; do not expose the Docker socket in shared or untrusted deployments.
