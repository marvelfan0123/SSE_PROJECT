# VulnX — Scan-first workflow

## User journey

Login → Select Target → Configure Assessment → Scan Progress → Processing → Assessment Dashboard → Remediation → Verification → Report.

### Before a scan
- First-time users land on Select Target, not Overview.
- Sidebar shows Select Target and My Assessments; result sections are not visible.
- Select a local lab target, then configure assessment name, criticality, and scanners.
- Scanning requires explicit confirmation of authorization.

### During a scan
- After submission the app switches to Scan Progress, with per-scanner statuses.
- Assessment data remains private to the logged-in owner (or Admin).
- A native Streamlit fragment polls every 3 seconds and redirects to Overview when results are saved.
- Scanning errors remain on Scan Progress; they never unlock result sections.

### After a scan
- Completed or partially completed assessments unlock result navigation.
- Every result page uses the selected assessment ID and its persisted SQLite findings.
- A completed scan with zero findings shows zero, rather than invented example findings.
- Partial scanner coverage is explicitly warned about.
- A new scan is independent of prior saved assessments.

### Run on Windows PowerShell

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```

Use Docker Desktop and the locally authorized Juice Shop / DVWA lab. Trivy, Nmap and ZAP executables/images must be installed and reachable for live scanning. Streamlit 1.50+ is required for automatic progress polling.

## Scope and limitations

- Target selection is intentionally limited to the configured local labs.
- Scanner output and SQLite data are generated at runtime, not bundled as sample findings.
- Existing remediation guidance and comparison-based verification are preserved; automated patch deployment is not provided.
- Live Windows, Docker, and browser behavior have not been validated in this environment.
- Missing scanner evidence is not proof of safety.
