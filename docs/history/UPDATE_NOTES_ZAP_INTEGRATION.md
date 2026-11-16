# Update Notes – OWASP ZAP Integration (Version 2)

## Added
- Added `zap_scanner.py` to run the official OWASP ZAP Docker image.
- Added allow-listed targets for the local Juice Shop (port 3000) and DVWA (port 8081) lab applications only.
- Uses `zap-baseline.py` passive checks, with a configurable 1–10 minute spider duration (default 3 minutes).
- Saves timestamped JSON reports under `zap_reports/`.
- Validates ZAP report structure and reports scanner execution errors clearly.
- Added `normalize_zap_report()` to map ZAP alerts into the common source-aware finding schema.
- Added the **Web Application Scanning (ZAP)** dashboard page, role-gated to Admin/Analyst for starting scans.
- Added audit events for completed ZAP scans.
- Added unit tests for target allow-listing, Docker requirement, command construction, report validation, and finding normalization.

## Safety and scope
- The integration uses ZAP Baseline mode, not active scanning.
- It does not exploit, patch, or modify the target application.
- It only accepts the two configured local lab targets.
- Docker must be running; the first run may pull `ghcr.io/zaproxy/zaproxy:stable`.
- ZAP alerts are web-application findings, not Trivy package CVEs. They remain distinct in the normalized schema.

## Validation
- Automated test suite: 89 tests passed.
- ZAP execution was tested with mocked Docker subprocess output in unit tests.
- A live ZAP scan was not run in this build environment; verify on the user's Windows machine with Docker Desktop and the lab apps running.
