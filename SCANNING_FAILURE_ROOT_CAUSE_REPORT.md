# SCANNING FAILURE ROOT CAUSE REPORT

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  
**Report Date:** 2026-11-10  

---

## 1. Executive Summary

During engineering evaluation and production hardening of **VulnX — Scanning and Vulnerability Management Platform**, three critical categories of defects were diagnosed, reproduced, and resolved:

1. **Priority 1 — Nmap 120-Second Timeout on Windows / Docker Desktop (`asset_discovery.py`):**
   - In historical assessment `VX-20261110-001742-B2EF71` (`OWASP Juice Shop`), Trivy (`129 findings`) and OWASP ZAP (`9 alerts`) completed cleanly, whereas Nmap failed after a `120s` timeout.
   - Investigation revealed two compounding causes on Windows with Docker Desktop:
     1. **Npcap Loopback/WSL2 Interface Initialization:** Invoking `nmap.exe` without `--unprivileged` caused Nmap 7.80 on Windows to attempt Npcap raw packet capture initialization (`WARNING: Could not import all necessary Npcap functions... Resorting to connect() mode`) across virtual adapters (`\Device\NPF_Loopback`, `vEthernet (WSL)`).
     2. **Docker Desktop `wslrelay.exe` Userland Proxy Holding `-sV` Service Probes Open:** Docker Desktop forwards `127.0.0.1:3000` through its host proxy (`com.docker.backend.exe` / `wslrelay.exe`), which immediately accepts TCP connections (`-sT` completes in `0.05s`) but holds sockets open during Nmap's `-sV` non-HTTP protocol probes (`NULL` 6s wait, `GenericLines`, `SSLSessionReq`, etc.). Without a bounded `-sV` attempt budget and automatic fallback to a pure TCP connect profile (`--unprivileged -sT -Pn -n`), `-sV` stalled until the 120s subprocess timeout killed Nmap and discarded the open port evidence.
2. **Priority 2 — Assessment Wizard Step Reset & Worker Lifecycle Management (`app.py`, `assessment_manager.py`, `assessment_worker.py`):**
   - Step 1 conditional widget keys (`vx_target_mode`, etc.) were garbage-collected by Streamlit when Step 2 rendered, causing any interaction on Step 2 to bounce back to Step 1 (`Step -1`).
   - Added worker PID tracking (`worker_pid`), stage heartbeats (`heartbeat_at`, `record_worker_heartbeat`), live worker process verification (`is_worker_alive`), duplicate worker launch prevention, and operator-initiated assessment cancellation (`cancel_assessment`) that preserves partial scanner results.
   - Fixed asset-preservation on scanner retry so retrying a single failed scanner (`Nmap`) never overwrites previously persisted `images` or `dependencies` from completed scanners (`Trivy`).
3. **Priority 3 — Canonical 0–10 Risk Engine Reachability & Docker Wildcard Exposure (`vulngraph_core.py`, `assessment_worker.py`):**
   - Previously, `REACHABILITY_MAP["unknown"]` mapped to `0.5` and `resolve_reachability(None)` returned `0.5`, silently converting unknown reachability into a confirmed numerical risk score.
   - Furthermore, Docker wildcard port bindings (`0.0.0.0`, `::`) were previously mapped to `"all_interfaces"` (`1.0`), treating a local container wildcard bind as proof of public internet exposure.
   - Both defects were resolved so unknown reachability remains `None` (`Provisional — Unknown Reachability`) and Docker wildcard bindings map to `"potential_exposure"` (`0.5`, `Potential Exposure`, `confirmed=False`).

---

## 2. Detailed Root Cause Analysis

### Root Cause 1: Windows Nmap 120-Second Timeout on Docker Desktop Ports (`asset_discovery.py`)
- **Affected Files:** [`asset_discovery.py`](asset_discovery.py), [`docker_lab.py`](docker_lab.py)
- **Historical Evidence (`scan_history.db`):**
  - Assessment `VX-20261110-001742-B2EF71` (`Juice Shop`):
    - `Trivy`: `Completed` (`129 vulnerability records`, `00:17:44`)
    - `Nmap`: `Failed` (`Nmap scan timed out after 120 seconds. Try fewer ports.`, `00:17:44` $\rightarrow$ `00:19:44`)
    - `OWASP ZAP`: `Completed` (`9 alerts`, `00:19:44` $\rightarrow$ `00:21:07`)
- **Engineering Fixes Implemented:**
  1. **Executable Discovery & Validation (`discover_nmap_executable`, `validate_nmap_executable`):** Checks `VULNX_NMAP_PATH` / `VULNGRAPH_NMAP_PATH`, `PATH`, and standard Windows installation directories (`C:\Program Files (x86)\Nmap\nmap.exe`, `C:\Program Files\Nmap\nmap.exe`, `%LOCALAPPDATA%\Programs\Nmap\nmap.exe`), and verifies execution via `nmap --version`.
  2. **Unprivileged Connect Scan Profiles (`SCAN_PROFILES`):** Enforces `--unprivileged -sT -Pn -n --max-retries 1` across all profiles (`service_light`, `connect_only`, `service_standard`) so Windows `nmap.exe` bypasses Npcap raw packet capture on loopback/WSL interfaces.
  3. **Bounded `-sV` Attempt Timeout with Automatic `connect_only` Fallback:** Caps the initial `service_light` (`-sV --version-light`) attempt to `25s` (`DEFAULT_SERVICE_PROBE_TIMEOUT_SECONDS`) and automatically retries using `connect_only` (`--unprivileged -sT -Pn -n` without `-sV`) when a Docker Desktop `wslrelay.exe` proxy port stalls version probes, completing port discovery in `<0.5s`.
  4. **Guaranteed Subprocess Termination & Resilient XML Parsing:** Uses `subprocess.Popen` with `CREATE_NO_WINDOW` and explicit `proc.kill()` + `proc.communicate()` cleanup on timeout, and parses valid `<nmaprun>` XML output even when Nmap exits non-zero due to Npcap stderr warnings.
  5. **Structured Error Classification (`NmapScanError`):** Classifies failures into `binary_missing`, `invalid_target`, `invalid_ports`, `timeout`, `permission_denied`, `xml_parse_error`, and `execution_failed` with explicit `.retryable` flags.

### Root Cause 2: Unknown Reachability & Docker Wildcard Binding Misclassification (`vulngraph_core.py`, `assessment_worker.py`)
- **Affected Files:** [`vulngraph_core.py`](vulngraph_core.py), [`assessment_worker.py`](assessment_worker.py)
- **Engineering Fixes Implemented:**
  1. Set `REACHABILITY_MAP["unknown"] = None` and updated `resolve_reachability()` to return `None` whenever reachability is unknown or unverified, causing `contextual_risk()` to return `value = None, status = "Provisional"` (`Manual Review Required`) rather than fabricating a confirmed score with `0.5`.
  2. Added `classify_reachability()` to explicitly distinguish all 5 reachability categories:
     - `Confirmed External Reachability` (`1.0`, `confirmed=True`)
     - `Confirmed Internal Exposure` (`0.5`, `confirmed=True`)
     - `Potential Exposure` (`0.5`, `confirmed=False`)
     - `Unknown Reachability` (`None`, `confirmed=False`)
     - `No Identified Path` (`0.0`, `confirmed=True`)
  3. Updated `assessment_worker.py` and `correlate_ports()` so Docker wildcard bindings (`0.0.0.0`, `::`) map to `"potential_exposure"` (`0.5`, `Potential Exposure`), never `"all_interfaces"` (`1.0`).

### Root Cause 3: Streamlit Unmounted Widget Key Garbage Collection & Live Progress Bar TypeError (`app.py`)
- **Affected File:** [`app.py`](app.py)
- **Engineering Fixes Implemented:**
  1. Decoupled persistent wizard state keys (`vx_target_mode`, `vx_saved_*`) from Step 1 conditional widget keys (`vx_ui_*`) so Step 2 never resets to Step 1 when Step 1 unmounts.
  2. Replaced passive `st.tabs` with a state-driven view switcher (`vx_assessment_subview`) that transitions immediately to **Live Execution & Scanner Telemetry** on launch.
  3. Fixed `scanner_progress(selected)` dictionary handling (`int(prog_info.get("percent", 0))`) and added a **🛑 Cancel Assessment** control (`cancel_assessment`) on the Live Execution view.

---

## 3. Verification Summary

- **Automated Regression Suite:** `343 passed, 0 failed` (`unittest` and `pytest`), including all 13 Nmap reliability tests in [`tests/test_nmap_reliability.py`](tests/test_nmap_reliability.py), 17 canonical risk engine and reachability tests in [`tests/test_vulngraph_risk_unification.py`](tests/test_vulngraph_risk_unification.py), and 6 wizard/worker lifecycle tests in [`tests/test_wizard_state_recovery.py`](tests/test_wizard_state_recovery.py).
