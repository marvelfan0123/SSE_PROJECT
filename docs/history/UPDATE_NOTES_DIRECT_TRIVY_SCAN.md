# Update: Direct Trivy Image Scanning

## Added
- Added `trivy_scanner.py` to invoke the locally installed Trivy CLI safely without a shell.
- Added dashboard controls for image reference, severity filters, and inclusion of unfixed vulnerabilities.
- Added JSON output validation and safe report replacement only after a successful scan.
- Generated reports use a stable filename per image so distinct scans can be compared by the existing history/comparison workflow.
- Added audit events for completed Trivy image scans.
- Newly generated reports are automatically selected in the dashboard.
- Valid zero-finding reports remain usable rather than stopping the application.
- Added four unit tests for image validation, missing Trivy, successful scans, and invalid output.

## Usage
1. Install Trivy and ensure `trivy --version` works in the terminal used to start Streamlit.
2. Start Docker Desktop if scanning a local image.
3. Sign in as Admin or Analyst.
4. Expand **Run a new Trivy container-image scan**.
5. Enter an image reference, choose severity filters, and click **Run Trivy scan**.
6. The generated JSON report is saved beside `app.py` and selected automatically.
7. Re-scan the same image later to create a distinct snapshot for comparison.

## Scope and limitations
- This runs Trivy image vulnerability scanning only (`--scanners vuln`).
- It does not run Trivy misconfiguration or secret scanning.
- It does not patch, rebuild, start, stop, or modify containers.
- The Trivy CLI must be installed separately and available on PATH.
- A successful scan records the report and scan event; it does not establish that a remediation was successful.

## Validation
- `python -m unittest discover -s tests -v`
- Result: 83 tests passed.
- `python -m py_compile app.py trivy_scanner.py`
- The live Trivy CLI scan was not run in this build environment because Trivy is not installed here; perform the first live scan on the user's Docker/Trivy setup.
