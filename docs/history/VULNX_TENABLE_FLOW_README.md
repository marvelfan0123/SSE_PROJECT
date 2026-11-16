# VulnX — Tenable-inspired assessment flow

## What changed

- After login, the **Dashboard** opens, even without a saved assessment.
- Before scanning, vulnerability counters are **0**, risk is **N/A**, charts have explicit empty states, and a **Not Scanned** warning prevents false assurance.
- All sidebar destinations remain visible; results-only pages display locked empty states until a selected assessment is **Completed** or **Partial**.
- The existing two-step New Assessment wizard still runs the authorized **Juice Shop/DVWA local labs** through existing Trivy/Nmap/ZAP workers. The scanner processing and risk algorithms have not been replaced.
- A **Trivy JSON report import** is supported separately. It validates a bounded JSON document and persists normalized findings under a new assessment. It is explicitly an import, **not** a new live scan. Imported findings are **not** assigned invented contextual risk scores.
- My Scans lists saved assessments. The scan progress page polls status and redirects to the Dashboard when saved results are ready. Failed assessments never unlock results.
- Existing remediation tracking, verification comparison, audit logging and JSON/CSV exports remain in the project.
- The scanning screen no longer uses a fake completion percentage.

## Important limits

- Live scanning remains restricted to the existing configured **local Juice Shop/DVWA** labs. Arbitrary public URL/IP scanning, arbitrary file vulnerability scanning, filesystem/archive scanning, PDF reports, EPSS/KEV and full patch management are **not implemented**.
- The Attack Paths page is a conservative empty/evidence-gated page. The existing analysis module is retained, but a new assessment-scoped attack-path UI is not integrated.
- Asset counts on the dashboard reflect **observed finding-linked asset identities**, not a comprehensive independent inventory.
- Authentication uses existing academic demo identities; do not deploy as production IAM.
- A zero-finding completed scan does **not** imply security.
- Automated unit tests run in this environment; live Streamlit and Windows Docker scanning were not tested here.

## Windows run instructions

From the extracted project directory:

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```

For previously created authorized lab containers:

```powershell
docker start juice-shop dvwa
docker ps
trivy --version
nmap --version
```

Open http://localhost:8501. Preserve your old SQLite data separately if migrating from an existing installation. Do not overwrite your current project without a backup.

## Validation

`python -m unittest discover -s tests -q` — **164 tests passed** on the supplied project, with a Python SQLite ResourceWarning in one test. `python -m compileall -q .` — passed. Streamlit was not installed in the execution environment, so live UI and scanner integration remain unverified.
