# VulnX Version 3.1 Implementation Notes

## Agreed UX decisions
- Login redirects to Security Assessment Center.
- First milestone: one Juice Shop container, real scanner execution, assessment-specific Dashboard.
- Core navigation: Security Assessment, Scan Progress, Dashboard, Findings.
- Second-phase navigation: Asset Inventory, Remediation, Scan Comparison, Reports & Audit.
- Bonus: Advanced Attack Path Analysis and Access & Roles.
- Scanner-specific findings stay distinct in the three Findings tabs.

## Execution architecture
- `assessment_manager.py` owns assessment records, scanner status records, findings, and SQLite NVD cache.
- `assessment_worker.py` is launched as a detached process so Streamlit reruns do not cancel scans.
- Each assessment has a unique ID. Trivy/ZAP reports are stored in an assessment-specific subdirectory.
- Scan Progress polls persisted records using `st.fragment(run_every="3s")` where available.
- `db_utils.py` enables SQLite WAL mode, foreign keys, NORMAL synchronous mode and a bounded busy timeout.

## Scanner applicability
- Running Docker container: Trivy if an image is identified; Nmap if published ports are verified; ZAP only for configured Juice Shop/DVWA port mappings.
- Container image: Trivy only.
- Web application: configured local Juice Shop or DVWA; Nmap and ZAP are run only against the corresponding loopback endpoint. Trivy is skipped unless a container image is separately associated.
- Non-applicable scanners are Skipped with a reason. Failures are retained separately from successful scanner results.

## Risk model
`risk = base_score × exposure_factor × criticality_factor`

`risk_0_100 = min(100, raw_risk / 14.4 × 100)`

- Trivy: Trivy-provided CVSS first, NVD CVSS only as fallback, then a labelled severity proxy.
- ZAP: High 8, Medium 5, Low 3, Informational 1 when CVSS is absent.
- Nmap: open ports remain exposure observations and do not receive a CVSS vulnerability score.
- Exposure: loopback 0.8; internal 1.0; all interfaces 1.2; unknown is unscored.
- Criticality: Low 0.8; Normal 1.0; High 1.2; selected by the assessor, default Normal.
- `0.0.0.0` means all IPv4 interfaces, not proof of Internet exposure.

## NVD
- SQLite table `assessment_nvd_cache` stores records.
- Up to 10 new CVEs are attempted per assessment.
- Without an API key, requests are paced; with a key, set `NVD_API_KEY` in a local `.env` copied from `.env.example`.

## Comparison keys
- Trivy: asset + CVE + package.
- Nmap: host + port + service.
- ZAP: plugin/alert ID + affected URL.
- “No longer detected” is not equivalent to “fixed”.

## Docker notes
- On the host, local Nmap target is `127.0.0.1`.
- If VulnX itself runs in Docker, set `VULNX_DOCKERIZED=1` so the local host target uses `host.docker.internal` (validated to resolve privately/loopback).
- ZAP's Docker runner uses `host.docker.internal` for the configured lab URLs.
- Mounting Docker socket grants powerful daemon control and can expose host-level privileges. Avoid it in shared/untrusted deployments.

## Known boundaries
- This is a single-host academic/demo worker model, not a distributed queue.
- ZAP uses Baseline/passive checks with a bounded spider and timeout.
- Full report export polish, full user management, and attack-path enhancements remain later/bonus work.
- Live scanner integration requires the user's Windows environment, Docker Desktop, Trivy, Nmap, internet access for NVD, and the local lab. Automated tests do not run live scans.
