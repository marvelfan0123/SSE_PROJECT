# VulnX — 15-Minute Demo Guide

## Goal
Demonstrate an end-to-end local vulnerability-management workflow: ingest scan reports, prioritize findings, compare snapshots, assign remediation work, discover local listening services, and explain evidence-backed candidate attack paths.

## Before the demo (10 minutes earlier)

1. Open PowerShell in this project folder.
2. Activate the same Python environment that has the project dependencies installed.
3. Run `python -m unittest discover -s tests -v` and confirm all tests pass.
4. Start the dashboard with `python -m streamlit run app.py`.
5. Confirm the bundled Trivy JSON reports are present and the dashboard loads.
6. If demonstrating Nmap, confirm Nmap is installed and available on `PATH`. Use only localhost or a system you have permission to scan.
7. Keep a backup of `data/data/scan_history.db`. Do not delete the database during the demo.
8. Avoid live NVD enrichment unless internet access and time are available; cached enrichment or the feature explanation is sufficient.

## Suggested talk track (15 minutes)

### 0:00–1:00 — Problem and objective
"Vulnerability scanners can produce large lists of findings. VulnX brings findings into one dashboard, prioritizes them using a transparent project-defined score, keeps scan history, and tracks remediation evidence. It is a management and analysis layer; it does not automatically patch systems or exploit targets."

### 1:00–3:00 — Overall Security Summary
Show the total findings and severity overview. Explain that counts depend on the selected bundled report and that scanner severity is preserved. Do not describe a reported finding as proof of successful exploitation.

### 3:00–5:00 — Scan History and Before-and-After Comparison
Show the previous and current report snapshots. The bundled Juice Shop reports currently contain 105 findings each with matching stable finding identities, so the expected result is 105 persistent, 0 new, and 0 no-longer-detected. Explain that "no longer detected" means absent from the newer report; it is not, by itself, proof of successful remediation. The controlled automated fixture separately tests one new, one persistent, and one no-longer-detected finding.

### 5:00–7:00 — Risk Prioritization and Remediation Guidance
Select a finding and explain the factors that contribute to the VulnX score. The score is a project-defined heuristic, not CVSS and not proof of exploitability. Show the suggested remediation guidance and fixed-version information only where present in the scanner data; do not invent a fixed version.

### 7:00–9:30 — Remediation Management Workflow
Show the persistent queue, owner, notes, status, reviewer/approver, verification status, and evidence. Explain that an item cannot be marked Resolved until its verification requirements are met. For the demo, use a test item or existing record without falsely claiming a real vulnerability was fixed. A genuine rescan or documented exception should support verification.

### 9:30–11:30 — Asset Discovery (Nmap)
If the local lab is available, scan only `127.0.0.1` or another explicitly authorized private lab target. Show the open ports and service/version evidence and the saved scan history. Explain that an open port is an observation, not automatically a vulnerability; service identification may be incomplete.

### 11:30–13:00 — Evidence-Based Attack-Path Analysis
Show candidate paths generated from available Trivy findings and Nmap observations. Explain the confidence levels and any manually confirmed lab relationship. Candidate paths are hypotheses for manual validation; they do not prove Internet exposure or exploitability.

### 13:00–14:00 — Correlation, normalization, and optional NVD enrichment
Briefly explain that source-aware normalization makes Trivy findings and Nmap observations share a common record structure while preserving their different meanings. Show correlation/deduplication if useful. NVD enrichment is optional and needs internet access; CVSS is supplemental severity information, not the same as the VulnX risk score.

### 14:00–15:00 — Tests, limits, and conclusion
Report the automated test result from the run performed immediately before the demo. The reviewed package's recorded validation was 46 tests passed. Explain limits: local MVP, scanner reports are inputs, Nmap availability depends on local installation and permissions, attack paths need manual validation, and remediation actions are tracked rather than automatically applied.

## Commands

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/validate_scan_comparison.py
python -m streamlit run app.py
```

## Likely faculty questions

**Q: Does VulnX discover every vulnerability by itself?**
A: It ingests Trivy JSON reports and adds local Nmap service observations. It orchestrates and analyzes evidence from those tools; it is not a replacement for every scanner.

**Q: Is the risk score CVSS?**
A: No. It is an explainable project heuristic using scanner severity and, when available, NVD CVSS and selected contextual factors. The UI labels it as a VulnX risk score.

**Q: Does an open port prove the target is vulnerable or publicly reachable?**
A: No. It proves only that the scan observed that port as open from the scan vantage point. Exposure and exploitability require separate evidence.

**Q: Does "no longer detected" mean fixed?**
A: Not automatically. It means the finding identity is absent from the newer report. A valid rescan and environment confirmation are needed to substantiate remediation.

**Q: Does the system patch machines automatically?**
A: No. It tracks remediation ownership, status, approvals, notes, and verification evidence; the actual change is performed and validated separately.

**Q: How did you test the comparison feature?**
A: Automated unit tests include new/persistent/no-longer-detected classification, and a controlled fixture exercises one example of each while using a temporary database so the project's scan history is not altered.

**Q: What would you improve next?**
A: Add authenticated multi-user roles, richer asset inventory, signed/auditable verification evidence, scheduled scans, richer report provenance, and deployment hardening. These are future work, not claims about the current MVP.

## Demo safety and honesty checklist

- Use only systems you own or are authorized to assess.
- Do not claim a vulnerability was fixed without verification evidence.
- Do not present candidate paths as confirmed attacks.
- Do not present the heuristic score as CVSS.
- State the test result actually observed on the demo machine.


## OWASP ZAP web application scan (new)

1. Start Docker Desktop and the local Juice Shop/DVWA lab containers.
2. Open **Web Application Scanning (ZAP)** from the sidebar.
3. Select one of the two configured local applications.
4. Run the ZAP Baseline scan and wait for the JSON report.
5. Explain that ZAP tests the running HTTP application with spidering and passive checks, while Trivy checks packages in the image and Nmap discovers ports/services.
6. Review severity, CWE, confidence, evidence and suggested solution.

Do not describe this baseline scan as an active penetration test or as proof that the application is secure.
