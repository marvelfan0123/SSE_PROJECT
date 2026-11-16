# Phase 1 — Assessment Wizard progress

## Implemented in this increment
- Added custom Docker image references to the New Assessment wizard.
- Added conservative input validation and compatibility routing to Trivy only.
- Preserved predefined Juice Shop and DVWA assessment workflows.
- Added tests for custom image acceptance and invalid input rejection.

## Still outstanding
- General authorized host targets and network boundaries.
- General web targets and safe ZAP integration.
- Local filesystem scanning, scanner configuration and final acceptance tests.

## Important
- Do not scan images without authorization.
- Trivy must be installed on PATH for the worker to execute the image scan.
- This increment does not mark Phase 1 complete.
