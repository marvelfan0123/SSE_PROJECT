# VulnX — scan-driven assessment workspace

## What changed

- **Login first**. Authentication and existing RBAC stay in place.
- A real **sidebar navigation** replaces anchor links and the all-sections-at-once screen.
- **New Assessment** is the only primary entry point for launching scans.
- **Before a scan**, Overview, Findings, Risk, Remediation, Verification and Reports show empty states rather than bundled JSON demo data.
- **While scanning**, the selected assessment shows scanner states and the current worker stage; click Refresh to update.
- **After a completed or partial scan**, all pages read only from the same selected `assessment_id` in SQLite.
- **On restart**, assessments persist in SQLite; select any permitted assessment from the assessment picker.
- **Reports** export JSON and CSV derived from the selected assessment, never from a default bundled report.
- The original dashboard is preserved in `legacy_workspace.py` for reference, but it is **not executed** by the new `app.py`.

## Target support and constraints

The existing detached worker and `assessment_portal.make_plan` support the authorized **local Juice Shop/DVWA lab** through Docker image, local host, web application or running lab container modes. Arbitrary file uploads, arbitrary external targets and EPSS/KEV enrichment are **not implemented** by this redesign. The UI does not claim otherwise. ZAP is a passive baseline scan. Nmap open ports are not treated as confirmed CVEs.

The existing risk engine remains in place. This change improves **assessment scoping and navigation**, not the mathematical scoring model. Remediation suggestions require review; verification comparisons are indicative only and do not claim a fix without comparable rescan evidence.

## Windows PowerShell

```powershell
# Open PowerShell in the extracted VulnX folder (the one containing app.py)
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```

Start Docker Desktop and your already-created lab containers in another terminal:

```powershell
docker start juice-shop dvwa
docker ps
```

For full scans, install and verify Trivy, Nmap, and Docker. ZAP runs via Docker per existing project configuration. Open `http://localhost:8501`, sign in using your **existing** VulnX account, create an assessment, and use **My Assessments → Refresh scan progress** until it completes.

## Notes

- Existing `.env`, SQLite databases, and saved assessment reports were deliberately excluded from the distribution ZIP to avoid shipping personal credentials and stale data. Keep backups of your original project and copy your own `.env` only if needed.
- The new ZIP is a clean application distribution. Its UI will be empty until you create an assessment.
- An existing database can be retained locally if desired; previously saved assessments will remain selectable. This ZIP intentionally ships without them.
- Run scans only against targets you are authorized to test.
