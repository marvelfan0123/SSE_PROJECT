# VulnX scan-first workflow — fixes

## Intended user journey
Login → Select Target → Configure → Scan Progress → Process → Saved Assessment Dashboard → Findings/Risk/Remediation/Verification/Reports.

- No sample findings are loaded. Result navigation is hidden for queued/running/failed assessments.
- Select Target and My Assessments remain accessible during scans, allowing concurrent assessment creation.
- Automatic progress polling uses `st.fragment(run_every="3s")`, supported by the pinned `streamlit>=1.50,<2` requirement. On completion the UI reroutes to Overview.
- Partial results carry an explicit scanner-coverage warning. Failed scans never unlock result pages.
- Remediation records are stored in SQLite, scoped by assessment and finding; statuses are Open, In Progress and Ready for Rescan, never automatically Verified.
- Verification comparisons require completed scans of the same target with matching successfully completed scanners and no failed/in-progress scanners. Even then, absent findings are candidates, not proven fixes.
- The project retains its local lab scope; arbitrary file uploads and EPSS/KEV are not implemented.

## Setup
In the extracted VulnX folder:

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```

Use only lab targets you own or are authorized to assess. Keep any existing SQLite DB in a backup; this ZIP deliberately excludes runtime databases and credentials.

## Validation
158 Python unit tests passed in the build environment. Python modules compiled. Live Streamlit browser and Windows Docker scanning were not available in this environment; test these on the deployment machine before demonstration.
