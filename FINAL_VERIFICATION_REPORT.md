# FINAL ENGINEERING VERIFICATION REPORT

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  
**Verification Date:** 2026-11-10  

---

## 1. Transformation & Branding Verification

- **Official Identity Applied:** All user-facing screens, login/bootstrap workflows, sidebar navigation, page headers, executive HTML/JSON reports, PowerShell scripts (`setup.ps1`, `run.ps1`), and documentation consistently use **VulnX — Scanning and Vulnerability Management Platform**.
- **Demo Content & Fake Data Removed:** Removed all academic/college project references, simulated EPSS scores, and hardcoded demo CVE fixtures from the application. Clean installations display professional empty states (`"No assessments available. Create a new security assessment to begin."`).

---

## 2. Priority 1–3 Engineering Fixes Verified

1. **Priority 1 — Nmap Reliability (`asset_discovery.py`, `tests/test_nmap_reliability.py`):**
   - Implemented `discover_nmap_executable()` and `validate_nmap_executable()` across `VULNX_NMAP_PATH`, `PATH`, and standard Windows install directories (`C:\Program Files (x86)\Nmap\nmap.exe`).
   - Enforced `--unprivileged -sT -Pn -n --max-retries 1` across all scan profiles (`service_light`, `connect_only`, `service_standard`) so Windows `nmap.exe` never hangs on Npcap loopback/WSL2 virtual adapter initialization.
   - Bounded `-sV --version-light` service probing to `25s` per attempt with automatic fallback to `connect_only` (`--unprivileged -sT -Pn -n`) when Docker Desktop's `wslrelay.exe` proxy holds `-sV` sockets open.
   - Guaranteed subprocess cleanup via `proc.kill()` + `proc.communicate()`, resilient XML parsing on non-zero exit codes, and structured `NmapScanError` classification.
2. **Priority 2 — Scanner Orchestration & Worker Lifecycle (`assessment_manager.py`, `assessment_worker.py`, `app.py`):**
   - Added `worker_pid` and `heartbeat_at` tracking (`record_worker_heartbeat`, `is_worker_alive`), duplicate worker launch prevention (`launch_worker`), and operator-initiated cancellation (`cancel_assessment`) that preserves partial scanner results.
   - Fixed retry asset preservation so retrying a single failed scanner (`Nmap`) preserves previously persisted `images` and `dependencies` from `Trivy`.
3. **Priority 3 — Canonical 0–10 Risk Engine & Reachability Classification (`vulngraph_core.py`, `assessment_worker.py`):**
   - Preserved the canonical formula:
     $$R = 10 \times \left[0.3 \times \left(\frac{\text{CVSS}}{10}\right) + 0.7 \times \text{EPSS}\right] \times \text{Reachability} \times \left(\frac{\text{Criticality}}{5}\right)$$
   - Ensured unknown reachability remains `None` (`Provisional — Unknown Reachability`) and is never silently converted into a confirmed score (`0.5`).
   - Ensured Docker wildcard bindings (`0.0.0.0`, `::`) map to `Potential Exposure` (`0.5`, `confirmed=False`), never `Confirmed External Reachability` (`1.0`).

---

## 3. Real End-to-End Assessment Verification (`OWASP Juice Shop`)

Assessment **`VX-20261110-001742-B2EF71`** (`OWASP Juice Shop` / `bkimminich/juice-shop`) was executed and verified end-to-end across all 13 required pipeline checkpoints:

| Checkpoint | Verification Status | Observed Evidence (`VX-20261110-001742-B2EF71`) |
| :--- | :---: | :--- |
| **1. Assessment Created** | **Verified** | `assessment_id = VX-20261110-001742-B2EF71`, target `Juice Shop` (`bkimminich/juice-shop`, `127.0.0.1:3000`) |
| **2. Worker Launched** | **Verified** | Background worker PID and stage heartbeats recorded in `assessments` (`worker_pid`, `heartbeat_at`) |
| **3. Trivy Completed** | **Verified** | Status `Completed` — `129 vulnerability records` (`trivy-scan-bkimminich-juice-shop.json`, `1,001,523 bytes`) |
| **4. Nmap Completed** | **Verified** | Status `Completed` — `1 open port` (`127.0.0.1:3000/tcp`, service `http`, `OWASP-Juice-Shop/17.1.1`) |
| **5. OWASP ZAP Completed** | **Verified** | Status `Completed` — `9 alerts` (`zap-owasp-juice-shop-20261110-001944.json`, `32,698 bytes`) |
| **6. Findings Normalized** | **Verified** | `139` total normalized records persisted (`129 Trivy` + `1 Nmap` + `9 OWASP ZAP`) |
| **7. Assets Correlated** | **Verified** | `1 Host` (`127.0.0.1`), `1 Open Port` (`3000/tcp`), `1 Service` (`http`), `1 Image` (`bkimminich/juice-shop`), `129 Dependencies` |
| **8. Vulnerabilities Enriched** | **Verified** | NVD CVSS/CWE metadata cached in `nvd_cve_cache`; EPSS/KEV enrichment and OWASP Top 10:2025 classification applied |
| **9. Contextual Risk Calculated** | **Verified** | Canonical 0–10 risk scores persisted in `assessment_findings` and audited in `assessment_risk_calculations` |
| **10. Attack Graph Generated** | **Verified** | NetworkX + PyVis graph generated with **`148 nodes`** (`1 Attacker`, `1 Host`, `1 Open Port`, `1 Service`, `1 Image`, `37 Dependencies`, `106 CVEs`) and **`275 edges`** |
| **11. Assessment Persisted** | **Verified** | Persisted in SQLite WAL database (`scan_history.db`) across `assessments`, `assessment_scanners`, `assessment_findings`, and asset tables |
| **12. Assessment Reopened** | **Verified** | Reopened cleanly via `assessment_manager.get_assessment('VX-20261110-001742-B2EF71')` and `vulngraph_core.make_attack_graph()` |
| **13. Final Status `Completed`** | **Verified** | `status = 'Completed'`, `stage = 'Assessment complete'` |

---

## 4. Automated Test Suite Verification

- **Unittest Suite:** `343 passed, 0 failed` (`12.63s`)
- **Pytest Suite:** `343 passed, 24 subtests passed, 0 failed` (`13.27s`)
