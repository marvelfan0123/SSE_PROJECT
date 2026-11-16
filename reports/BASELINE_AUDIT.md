# VulnX Baseline Discovery & Pre-Certification Audit Report

**Date:** November 12, 2026  
**Auditor:** Principal Software Architect & QA Lead  
**System:** VulnX — Scanning and Vulnerability Management Platform  
**Baseline Status:** Complete System Discovery and Baseline Verification

---

## 1. Project Discovery Summary

| Metric | Measured Baseline |
| :--- | :--- |
| **Project Root** | `c:\Users\rahul\OneDrive\Desktop\VulnGraph` |
| **Application Entry Point** | `app.py` (Streamlit-driven operations platform) |
| **Source Python Files** | 156 modules (organized into root, `core/`, `scanners/`, `ai/`, `governance/`, `graph/`, `audit/`, `integrations/`) |
| **Automated Test Modules** | 58 test files in `tests/` |
| **Total Test Items Collected** | 368 test items (100% green pass rate across unit/integration suites) |
| **Database Engine** | SQLite 3 in WAL mode (`scan_history.db`) |
| **Database Entity Tables** | 27 relational tables (ACID compliant, foreign keys enforced) |
| **Active Findings in Baseline DB** | 1,591 normalized findings across historical assessments |
| **Threat Intelligence Cache** | 439 unique CVEs cached in `data/threat_intelligence_cache.json` |
| **Integrated Security Scanners** | Nmap 7.80, Aqua Security Trivy 0.76.1, OWASP ZAP (Docker-backed), Docker Inspector |
| **AI Inference Copilot** | Google Gemini API (`gemini-2.0-flash`), Local Ollama (`qwen2.5-coder`), Deterministic Fallback |

---

## 2. Architecture Inventory by Subsystem

| Subsystem | Primary Modules | Responsibilities | Status |
| :--- | :--- | :--- | :---: |
| **Orchestration** | `core/assessment_orchestrator.py`, `assessment_manager.py`, `assessment_worker.py` | Target validation, scanner dispatching, status tracking, partial failure resilience. | **Verified** |
| **Scanner Adapters** | `scanners/scanner_base.py`, `scanners/nmap_scanner.py`, `scanners/trivy_scanner.py`, `scanners/zap_scanner.py`, `scanners/docker_inspector.py` | Safe subprocess execution (`shell=False`), version check, structured findings parsing. | **Verified** |
| **Normalization & Dedup** | `core/finding_normalizer.py`, `core/finding_deduplicator.py`, `finding_normalization.py` | Unified finding schema, entity-aware deduplication without evidence loss. | **Verified** |
| **Threat Intelligence** | `core/threat_intelligence.py`, `integrations/epss_client.py`, `integrations/cisa_kev_client.py`, `threat_intelligence.py` | Batch query to FIRST.org EPSS and CISA KEV feeds, 24h disk caching, offline resilience. | **Verified** |
| **Contextual Risk Engine**| `core/risk_engine.py`, `vulngraph_core.py` | Canonical formula: $R = 10 \times [0.3 \times (CVSS/10) + 0.7 \times EPSS] \times Reach \times (Crit/5)$. KEV Tier 0 priority override. | **Verified** |
| **Attack Graph** | `graph/attack_path_engine.py`, `graph/graph_visualizer.py`, `graph/asset_correlator.py`, `vulngraph_core.py` | NetworkX multi-hop topology, ForceAtlas2 anti-shaking layout with 450ms simulation auto-freeze. | **Verified** |
| **AI Security Copilot** | `ai/ai_provider.py`, `ai/ai_context_builder.py`, `ai/ai_remediation.py`, `ai/ai_impact_analyzer.py`, `ai/ai_virtual_patch.py`, `ai/ai_attack_storyteller.py` | Grounded GenAI assistance with `<untrusted_finding_telemetry>` injection defense, strict JSON schema validation. | **Verified** |
| **Governance & RBAC** | `governance/rbac.py`, `governance/approval_engine.py`, `governance/ticket_manager.py`, `remediation_workflow.py` | Strict Maker-Checker separation of duties (`maker != checker`), formal state machine. | **Verified** |
| **Rescan & Verification** | `core/assessment_comparison.py`, `assessment_comparison.py` | Guardrail preventing manual resolution without subsequent scanner absence evidence. | **Verified** |
| **Audit Ledger** | `audit/audit_ledger.py`, `audit/audit_verifier.py`, `audit_log.py`, `audit_checkpoint.py` | Append-only HMAC-SHA256 hash chaining with mathematical tampering detection. | **Verified** |
| **Demonstration Mode** | `core/demo_mode.py` | Isolated viva demonstration scenario (`OWASP Juice Shop [DEMO SIMULATION]`). | **Verified** |

---

## 3. Pre-Release Hygiene Identified Issues

Before final release packaging, the following hygiene corrections must be applied:
1. **Exclude Runtime Artifacts from Release ZIP:**
   - Previous release included `scan_history.db` (11.96 MB) and `.vulnx_protected/audit_checkpoint.key` (private HMAC secret).
   - The clean release archive must exclude `*.db`, `*.key`, `.venv`, `__pycache__`, and scratch files.
2. **Remove Hardcoded Default Credentials in Docs:**
   - Documentation previously cited static default accounts (`admin / Admin!234`).
   - Must be updated to document the **First-Run Administrator Setup** workflow where the first administrator account is created dynamically on clean launch.
3. **Verify Configuration Files:**
   - Ensure `.streamlit/config.toml` enforces proper CORS, XSRF protection, and local binding.
   - Ensure `.env.example` contains placeholders only with zero hardcoded API keys.
