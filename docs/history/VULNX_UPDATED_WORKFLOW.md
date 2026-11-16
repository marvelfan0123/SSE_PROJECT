# VulnX — Guided assessment update

## User journey

1. Open `http://localhost:8501` and sign in with an existing local demo account.
2. In the sidebar, choose **New Assessment**.
3. Select the authorized local lab target (**Juice Shop** or **DVWA**), target type, criticality, and applicable scanners.
4. Confirm authorization and click **Start assessment**. A detached assessment worker runs the selected scans; the Streamlit page does not block.
5. Under **My Assessments**, refresh to see scanner statuses, normalized findings, contextual risk scores and a CSV export.
6. Continue to the existing lower sections for enrichment, correlation, prioritization, remediation, verification, reporting and audit.

The existing detailed 9-stage pipeline is retained, not removed. The guided assessment is the primary entry point. The older scanner-specific controls remain available for compatibility.

## Supported target types (this release)

- **Running lab container:** known local Juice Shop/DVWA lab with Trivy image scan, Nmap localhost port scan and ZAP baseline scan. The scanner plan uses known lab image/port mappings; it does not dynamically discover arbitrary running containers.
- **Docker image:** one of the two configured lab images, Trivy only.
- **Local web application:** known lab endpoint, Nmap and ZAP.
- **Local host:** known lab endpoint, Nmap only.

Arbitrary file uploads, external websites, arbitrary hosts, generic image names, and EPSS/CISA KEV enrichment are **not implemented** by this update. The existing risk model is CVSS/severity + exposure + criticality; it is not the proposed five-factor EPSS/KEV formula. Only scan targets you control or are authorized to test.

## Local setup (Windows PowerShell)

```powershell
cd ".\Scanning and Vulnerability Management Platform\Scanning and Vulnerability Management Platform"
& "..\.venv\Scripts\python.exe" -m pip install -r requirements.txt
& "..\.venv\Scripts\python.exe" -m unittest discover -s tests -v
& "..\.venv\Scripts\python.exe" -m streamlit run app.py
```

If you extract the new ZIP into a different directory, adjust the Python path or create a new virtual environment (`py -m venv .venv`).

Start Docker Desktop and the existing containers:

```powershell
docker start juice-shop dvwa
docker ps
trivy --version
nmap --version
docker pull ghcr.io/zaproxy/zaproxy:stable
```

ZAP uses the Docker image and `host.docker.internal` fixed URLs; the worker's ZAP call has been corrected to match the existing scanner function signature.

## Test evidence

`python -m unittest discover -s tests -v`: **143 tests passed** in the code-execution environment (including 5 new assessment-plan tests). Python source compiled successfully. This environment did not run Docker Desktop, live Trivy/Nmap/ZAP scans or a browser-based Streamlit acceptance test; validate these on Windows before the final presentation.

## Next priorities

1. Run a real full assessment and inspect `assessment_reports/<assessment-id>-worker.log` for any scanner failures.
2. Verify findings, target mappings and remediation actions on the laptop.
3. Integrate EPSS/KEV with caching and missing-data treatment, then compare against a CVSS-only baseline.
4. Add uploaded report import only after validating file type, size and schema.
