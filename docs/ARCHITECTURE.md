# VulnX Enterprise Architecture Specification

## 1. System Overview

**VulnX** is an enterprise-grade, AI-assisted scanning, contextual vulnerability management, attack path analysis, and human-governed remediation platform.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VulnX Streamlit Frontend                        │
│            (app.py, ui_components.py, styles.css, PyVis HTML)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Core Modules   │      │ AI Copilot Layer │      │ Governance/Audit │
│  - orchestrator  │      │  - provider      │      │  - rbac          │
│  - normalizer    │      │  - context_build │      │  - approvals     │
│  - deduplicator  │      │  - remediation   │      │  - ticket_mgr    │
│  - risk_engine   │      │  - impact_eval   │      │  - audit_ledger  │
│  - threat_intel  │      │  - virtual_patch │      │  - audit_verify  │
│  - comparator    │      │  - storyteller   │      │  - rescan_guard  │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         │                         │                         │
         ▼                         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ Scanner Adapters │      │ Threat Intel API │      │ Relational DB    │
│  - NmapScanner   │      │  - FIRST EPSS    │      │  - SQLite WAL    │
│  - TrivyScanner  │      │  - CISA KEV      │      │  - 22 Entities   │
│  - ZAPScanner    │      │  - Disk Cache    │      │  - Hash-Chain    │
│  - DockerInspect │      │  - 24h Freshness │      │  - HMAC Ledger   │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

---

## 2. Core Subsystems

### A. Assessment Orchestrator (`core/assessment_orchestrator.py`)
- Manages scan execution across Nmap, Trivy, and OWASP ZAP.
- Validates targets against shell metacharacters and private IP policies.
- Handles partial scanner failures: if ZAP is offline, Nmap and Trivy findings are preserved.

### B. Scanner Integration Layer (`scanners/`)
- Unified `ScannerBase` interface with explicit `ScannerResult` schema.
- Safe subprocess execution using argument arrays (strictly `shell=False`).
- Concrete adapters for Trivy 0.76.1, Nmap 7.80, OWASP ZAP, and Docker Inspect.

### C. Contextual Risk Engine (`core/risk_engine.py`)
- Computes canonical contextual risk score:
  $$R = 10 \times \left[0.3 \times \left(\frac{\text{CVSS}}{10}\right) + 0.7 \times \text{EPSS}\right] \times \text{Reachability} \times \left(\frac{\text{Criticality}}{5}\right)$$
- Incorporates CISA KEV as Tier 0 directive urgency.
- Provides plain-English mathematical explainability for every score.

### D. Attack Graph Intelligence (`graph/`)
- NetworkX bipartite and multi-hop graph topology.
- Connects `Internet Attacker` $\rightarrow$ `Port` $\rightarrow$ `Service` $\rightarrow$ `Container` $\rightarrow$ `Package` $\rightarrow$ `CVE`.
- ForceAtlas2 physics solver with automatic simulation freezing at 450ms.

### E. AI Security Copilot (`ai/`)
- Provider abstraction supporting Google Gemini API (`gemini-2.0-flash`) and local Ollama (`qwen2.5-coder`).
- Prompt injection protection via `<untrusted_finding_telemetry>` fences.
- 4 Core Capabilities:
  1. Remediation Playbook Generator (commands, Dockerfile diffs, rollback).
  2. Breaking Change & Impact Analyzer (predicting runtime breaks).
  3. Virtual Patch Synthesizer (ModSecurity / WAF rules for zero-days).
  4. Attack Path Storyteller (Executive and Technical briefings).

### F. Human-in-the-Loop Governance (`governance/`)
- Enforces strict Maker-Checker separation of duties (Analysts cannot approve their own tickets).
- State transitions: `Open` $\rightarrow$ `Pending Approval` $\rightarrow$ `Approved` $\rightarrow$ `In Progress` $\rightarrow$ `Ready for Rescan` $\rightarrow$ `Resolved`.

### G. Cryptographic Audit & Rescan Verification (`audit/`, `core/assessment_comparison.py`)
- Append-only HMAC-SHA256 hash-chaining ledger.
- Guardrail: tickets cannot be resolved manually; requires verified scanner absence in follow-up assessment.

