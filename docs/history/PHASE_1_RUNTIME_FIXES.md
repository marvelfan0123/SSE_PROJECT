# Phase 1 custom-target fixes (November 2, 2026)

Changes made from the user-provided project archive:
- The **Local host** wizard now collects an explicit IP and a comma-separated list of 1–30 TCP ports, instead of selecting a training lab.
- The **Local web application** wizard now collects an explicit local lab URL, limited to `http://localhost:3000/` (Juice Shop) and `http://localhost:8081/` (DVWA). The existing Docker-based ZAP scanner still uses its fixed Docker-reachable URLs.
- `make_plan` validates custom host/ports/URL and applies scanner compatibility.
- Worker revalidates host and ports before invoking Nmap. Loopback is enabled by default; an exact private IP may be enabled with `VULNX_ALLOWED_HOSTS=192.168.1.10` in the app environment or `.env`. Only scan authorized assets. Public IPs are not supported.
- Assessment title is stored separately as `assessment_name` and is no longer used as the actual scan target. The progress screen displays the target IP/URL. The scan still persists its actual target name in the database.
- Added eight regression tests. All 176 automated unit tests passed in the packaging environment.

## Run on Windows
1. Stop Streamlit, back up your existing project directory and database/scan reports.
2. Extract the entire new project directory, without mixing old Python modules.
3. Run `python -m venv .venv`, activate `.venv`, `python -m pip install -r requirements.txt`, then `python -m streamlit run app.py`.
4. Confirm Docker Desktop is running and run `docker start juice-shop dvwa`.
5. New Assessment > Local host: `127.0.0.1`, ports `3000,8081`, Nmap only. Expect two open ports if both lab services are running.
6. New Assessment > Local web application: `http://localhost:3000/`, Nmap + ZAP. Confirm both complete.
7. New Assessment > Docker image: custom `python:3.11-slim`, Trivy only.
8. Verify My Scans, Vulnerability Findings and Audit Logs after restarting Streamlit.

## Limits and follow-up
Live Windows scanner execution has not been run in this packaging environment. Only the code-level test suite passed. Asset alias reconciliation (`127.0.0.1` vs `host.docker.internal`) remains future work. Context-aware risk scoring and remediation improvements remain in later phases. Existing scans/data are not bundled into this source-only ZIP.
