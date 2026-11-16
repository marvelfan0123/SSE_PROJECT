# SYSTEM ARCHITECTURE

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  

---

## 1. Architectural Overview

VulnX is structured into six cohesive layers:

1. **Presentation & Operations Layer (`app.py`, `phase5_reporting.py`):**
   - Midnight Security dark-themed Streamlit interface (`#0B1220` primary background, `#111C2F` panels, `#17243A` cards, `#2563EB` primary accent, `#22D3EE` cyan highlight).
   - State-driven **Security Assessment** workspace separating persistent target configuration keys (`vx_target_mode`, `vx_saved_*`) from ephemeral widget keys (`vx_ui_*`).
   - Real-time **Scanner & Runtime Health** telemetry and 15-stage pipeline progress tracking.

2. **Assessment Orchestration & Worker Layer (`assessment_manager.py`, `assessment_worker.py`, `docker_lab.py`):**
   - Detached background subprocess execution (`python assessment_worker.py <assessment_id>`).
   - Duplicate launch prevention (`find_recent_active_assessment`), per-scanner attempt tracking, failed-scanner retry, and stale-worker recovery (`recover_stale_assessments`).

3. **Scanner Integration & Normalization Layer (`asset_discovery.py`, `trivy_scanner.py`, `zap_scanner.py`, `finding_correlation.py`):**
   - Executes real `nmap`, `trivy`, `docker inspect`, and `OWASP ZAP` commands or ingests uploaded Trivy JSON reports.
   - Normalizes heterogeneous scanner outputs into a unified finding schema and correlates multi-scanner evidence across assets.

4. **Threat Intelligence & Classification Layer (`nvd_enrichment.py`, `threat_intelligence.py`, `owasp_classifier.py`):**
   - Enriches CVEs with NVD CVSS/CWE metadata, FIRST.org EPSS 30-day exploitation probability, and CISA KEV status.
   - Classifies findings into **OWASP Top 10:2025** (`A01`–`A10`, `UNCLASSIFIED`) strictly from verified CWE evidence.

5. **Canonical 0–10 Contextual Risk & Attack Graph Layer (`vulngraph_core.py`, `risk_model.py`):**
   - Computes canonical 0–10 contextual risk:
     $$R = 10 \times \left[0.3 \times \left(\frac{\text{CVSS}}{10}\right) + 0.7 \times \text{EPSS}\right] \times \text{Reachability} \times \left(\frac{\text{Criticality}}{5}\right)$$
   - Builds an interactive **NetworkX + PyVis** directed attack graph across 8 node types (**Attacker**, **Host**, **Open Port**, **Service**, **Container**, **Image**, **Dependency**, **CVE**).

6. **Security, Governance & Persistence Layer (`db_utils.py`, `auth.py`, `remediation_workflow.py`, `audit_log.py`):**
   - SQLite WAL database (`scan_history.db`) with foreign keys and busy timeouts.
   - Bcrypt (`rounds=12`) authentication, RBAC (**Admin**, **Security Analyst**, **Approver**), Maker-Checker remediation workflow, and SHA-256 hash-chained audit logs.
