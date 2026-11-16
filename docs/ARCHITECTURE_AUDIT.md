# VulnX Architecture Audit & System Inspection Report

**Date:** November 12, 2026  
**Auditor:** Principal Cybersecurity Architect & Full-Stack QA Auditor  
**System:** VulnX — Scanning and Vulnerability Management Platform  
**Target Baseline:** 356 automated pytest unit/integration tests passing (100% green), SQLite WAL database with 1,591 verified assessment findings.

---

## 1. Existing Architecture Overview

VulnX is currently architected as a Streamlit-driven Python web application backed by an SQLite relational database (`scan_history.db`) in WAL mode with PBKDF2 authentication, role-based access control, scanner adapters (Nmap, Trivy, OWASP ZAP), NetworkX graph topology generation, and an append-only HMAC-SHA256 cryptographic audit ledger.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VulnX Streamlit Frontend                        │
│            (app.py, ui_components.py, styles.css, PyVis HTML)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Application Logic Layer                         │
│  - assessment_manager.py: Orchestration, assessment lifecycle          │
│  - assessment_worker.py: Multi-scanner runner (Nmap, Trivy, ZAP)       │
│  - finding_normalization.py: De-duplication and schema unifying        │
│  - threat_intelligence.py: FIRST.org EPSS and CISA KEV caching         │
│  - risk_engine.py / risk_model.py: Canonical contextual risk scoring   │
│  - vulngraph_core.py: Compound NetworkX topology & ForceAtlas2 physics │
│  - remediation_workflow.py: Formal Maker-Checker state machine         │
│  - audit_log.py & audit_checkpoint.py: HMAC-SHA256 audit ledger        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Data Persistence & Storage Layer                     │
│  - scan_history.db (SQLite with foreign keys & WAL mode enabled)       │
│  - assessment_reports/ (Raw JSON/XML scanner output artifacts)         │
│  - data/threat_intelligence_cache.json (EPSS cache for 439+ CVEs)      │
│  - .vulnx_protected/audit_checkpoint.key (HMAC root secret)            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Existing Modules and Their Responsibilities

| Module | Core Responsibility | Current Health |
| :--- | :--- | :--- |
| `app.py` | Streamlit user interface, navigation routing, session state, UI rendering. | Functional; monolithic (2,462 lines). Needs modularization and dedicated AI workspace. |
| `assessment_manager.py` | Creates assessments, manages targets, database schema initialization, finding queries. | Solid, production-grade schema and parameterized queries. |
| `assessment_worker.py` | Orchestrates scanner execution (Nmap, Trivy, Docker inspect) using subprocess calls. | Functional. Handles offline Docker daemon cleanly. |
| `trivy_scanner.py` | Adapter for Aqua Security Trivy (vulnerability scanning and SBOM extraction). | Fully functional; parses CVE, CVSS, and fixed versions. |
| `zap_scanner.py` | Adapter for OWASP ZAP API / headless execution. | Functional fallback when ZAP daemon is not listening. |
| `finding_normalization.py` | Deduplicates and maps scanner findings into a normalized dictionary. | Working; handles package, network, and web types. |
| `threat_intelligence.py` | Fetches EPSS probabilities from FIRST.org API with local disk caching. | Working; cached 439 unique CVEs. |
| `risk_engine.py` | Implements canonical formula: $R = 10 \times [0.3 \times (CVSS/10) + 0.7 \times EPSS] \times Reach \times (Crit/5)$. | Mathematical integrity verified across all 1,591 database findings. |
| `vulngraph_core.py` | Builds bipartite and multi-hop attack graphs with NetworkX and renders via PyVis. | ForceAtlas2 layout tuned to prevent shaking and physics freezing. |
| `auth.py` | PBKDF2-HMAC-SHA256 user authentication and permission matrix. | Secure; protects Admin operations and enforces role boundaries. |
| `remediation_workflow.py` | Enforces Maker-Checker state transitions (`Open` $\rightarrow$ `Pending Approval` $\rightarrow$ `Approved` $\rightarrow$ `In Progress` $\rightarrow$ `Ready for Rescan` $\rightarrow$ `Resolved`). | Verified; blocks Analysts from self-approving tickets. |
| `assessment_comparison.py` | Compares pre-patch and post-patch scan findings to verify true resolution. | Working; prevents marking tickets resolved without rescan proof. |
| `audit_log.py` | Append-only audit logging with HMAC-SHA256 hash chaining. | Verified; tampering detection confirmed active. |

---

## 3. Working Functionality

- **Scanner Ingestion:** Nmap 7.80 and Trivy 0.76.1 successfully discovered and parsed.
- **Threat Intelligence:** Automated fetching from FIRST.org EPSS API with JSON disk caching.
- **Contextual Risk Engine:** Mathematical clamping $[0.0, 10.0]$ and deterministic scoring verified.
- **Attack Graph Visualization:** PyVis HTML generator with degree-weighted ForceAtlas2 physics and automatic simulation freezing to prevent shaking.
- **Authentication & RBAC:** Passwords hashed with PBKDF2-HMAC-SHA256 with distinct role permissions (Admin, Security Analyst, Approver).
- **Maker-Checker Governance:** Complete state machine prevents analysts from approving their own remediation tickets.
- **Cryptographic Audit Chain:** HMAC-SHA256 chain detects any SQLite row tampering or modification.
- **Automated Test Suite:** 356 pytest unit/integration tests running 100% green.

---

## 4. Broken Functionality Identified

1. **Docker Daemon Dependency on Windows:** If Docker Desktop is stopped or WSL2 is inactive, container inspection fails. The application catches this, but lacks an automated mock/lab container fallback for offline demonstration.
2. **EPSS API Rate Limits & Timeouts:** Direct calls to FIRST.org can hang if the network drops or the API rate-limits the client during bulk scans.
3. **Ghost Markdown Styling Artifacts:** Previous revisions had duplicate CSS blocks in `app.py` that created empty spacing anomalies.
4. **Remediation Resolution UI Flow:** While the backend in `remediation_workflow.py` strictly requires rescan evidence, the UI did not provide a direct one-click "Trigger Rescan to Verify Fix" button.

---

## 5. Duplicate Functionality Identified

- `remediation.py` vs. `remediation_workflow.py`: `remediation.py` contained an older SQLite table (`remediation_items`), whereas `remediation_workflow.py` implements the enterprise `remediation_tickets` schema with event logging. The system should standardize exclusively on `remediation_tickets`.
- `risk_model.py` vs. `risk_engine.py`: `risk_model.py` contains legacy experimental heuristics, while `risk_engine.py` implements the canonical mathematical formula. All calls must be unified through `core/risk_engine.py`.
- `scan_comparison.py` vs. `assessment_comparison.py`: Dual implementations of finding diffing.

---

## 6. Missing Functionality (Target Transformation Requirements)

1. **Modular Enterprise Package Hierarchy:** Existing Python modules are placed in the root directory. They must be organized into clean packages:
   - `core/` (Orchestrator, normalizer, deduplicator, threat intel, risk engine, comparison)
   - `scanners/` (Nmap, Trivy, ZAP, Docker inspector, scanner base)
   - `integrations/` (FIRST.org EPSS client, CISA KEV client)
   - `graph/` (Attack graph core, path engine, asset correlator, visualizer)
   - `ai/` (AI provider abstraction, context builder, remediation playbook, impact analyzer, attack storyteller, virtual patch, response validator)
   - `governance/` (RBAC, workflow state machine, approval engine, ticket manager)
   - `audit/` (Audit ledger, verifier, checkpoint exporter)
2. **AI Security Copilot Layer:** No LLM integration existed. Missing:
   - Pluggable provider abstraction (`GeminiProvider` and `OllamaProvider`)
   - AI Remediation Playbook Generator (synthesizing Dockerfile diffs and shell commands)
   - AI Breaking Change & Dependency Impact Scorer (predicting service disruption)
   - AI Attack Path Storyteller (executive and technical briefings)
   - AI Virtual Patch Synthesizer (ModSecurity / WAF rules for zero-days with no vendor fix)
   - Strict JSON validation and prompt injection defenses
3. **Dedicated AI Workspace Page in UI:** The frontend lacked a dedicated "AI Security Copilot" navigation section.
4. **Isolated Demonstration Mode:** Missing a self-contained demonstration fixture mode that allows examiners/evaluators to test the full pipeline without live scanners or external API keys.

---

## 7. Database Limitations

- **Schema Evolution:** Tables were added ad-hoc across iterations (`remediation_items`, `assessment_findings`, `vg_asset_relationships`).
- **Entity Coverage:** Missing dedicated tables for `ai_recommendations`, `staging_evidence`, `attack_paths`, `system_settings`, and `assessment_comparisons`.
- **Database Backend:** SQLite in WAL mode works well for single-instance, but the database connection layer needs an abstraction layer to allow seamless migration to PostgreSQL for distributed enterprise deployments.

---

## 8. Security Weaknesses Identified

1. **Prompt Injection Risk in GenAI:** Untrusted scanner inputs (CVE titles, package names) passed directly into an LLM prompt could attempt prompt injection without strict input sanitization and delimiter fencing.
2. **Subprocess Execution Safety:** Subprocess commands in scanner adapters must strictly use argument lists (`["nmap", "-sV", target]`) and never shell strings (`shell=True`).
3. **Sensitive Key Exposure:** Ensure API keys (`GEMINI_API_KEY`, `VULNGRAPH_AUDIT_CHECKPOINT_KEY`) are read strictly from environment variables and never logged or serialized into client responses.

---

## 9. Proposed Migration Strategy

1. **Zero-Regression Facade Pattern:** Create the target modular packages (`core/`, `scanners/`, `integrations/`, `graph/`, `ai/`, `governance/`, `audit/`). Retain root files as backward-compatible facade delegators so that all 356 existing tests continue to pass 100%.
2. **Additive Database Migration:** Execute an idempotent migration script that creates the missing entity tables (`ai_recommendations`, `staging_evidence`, `attack_paths`, `system_settings`, `assessment_comparisons`) without dropping or altering existing tables.
3. **Modular AI Engine Implementation:** Build the complete `ai/` subsystem with strict fallback mechanisms: if `GEMINI_API_KEY` is not set or network is offline, gracefully fall back to deterministic heuristics without crashing.
4. **UI Consolidation:** Refactor `app.py` into the 10 required enterprise sections, integrating the new AI Security Copilot workspace.
5. **Comprehensive Testing:** Add new test suites for all new modular components.

---

## 10. Implementation Phases

- **Phase 0:** Backup and Architecture Audit (Complete).
- **Phase 1:** Core Foundation & Scanner Adapters (`core/`, `scanners/`).
- **Phase 2:** Threat Intelligence & Contextual Risk Engine (`integrations/`, `core/risk_engine.py`).
- **Phase 3:** Attack Graph Intelligence (`graph/`).
- **Phase 4:** AI Security Copilot Subsystem (`ai/`).
- **Phase 5:** Human-in-the-Loop Governance (`governance/`).
- **Phase 6:** Rescan Verification & Cryptographic Audit (`audit/`).
- **Phase 7:** Enterprise UI/UX Consolidation (`app.py` 10 sections).
- **Phase 8:** Demonstration Mode & Full Validation Suite.
- **Phase 9:** Comprehensive Enterprise Documentation & Release Packaging.

