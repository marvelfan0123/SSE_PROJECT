# VulnX — Scanning and Vulnerability Management Platform

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Brand:** VulnX  
**System Architecture:** Enterprise AI-Assisted Vulnerability Management, Attack Graph Topology & Human-Governed Remediation  

VulnX is a complete, enterprise-grade cybersecurity platform that orchestrates multi-scanner assessments (Nmap, Trivy, OWASP ZAP), performs finding normalization and de-duplication, enriches vulnerabilities with live FIRST.org EPSS and CISA KEV intelligence, computes canonical contextual risk scores, visualizes multi-hop attack graphs, provides an AI Security Copilot for remediation and virtual patching, and enforces compliance-grade Maker-Checker ticket governance backed by an HMAC-SHA256 cryptographic audit ledger.

---

## 1. Enterprise Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VulnX Streamlit Frontend                        │
│          (Overview · Assessments · Findings · Graph · AI Copilot)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Core Modules   │      │ AI Copilot Layer │      │ Governance/Audit │
│  - orchestrator  │      │  - Gemini / Ollama│     │  - rbac          │
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

## 2. Core Capabilities & Target Modules

1. **Module 1: Assessment Orchestrator (`core/assessment_orchestrator.py`)**
   - Centralized assessment lifecycle management with target validation (IP, hostname, container).
   - Independent scanner job tracking (Pending, Running, Completed, Failed, Timed Out, Skipped).
   - Partial failure resilience: failures in one scanner do not crash the assessment.
2. **Module 2: Scanner Integration Engine (`scanners/`)**
   - Safe subprocess execution using argument arrays (strictly `shell=False`).
   - Adapters for **Aqua Security Trivy 0.76.1**, **Nmap 7.80**, **OWASP ZAP**, and **Docker Inspector**.
3. **Module 3: Finding Normalization & Threat Intelligence (`core/`, `integrations/`)**
   - Unified finding schema with distinct handling for package vulnerabilities, web flaws, and network observations.
   - Live **FIRST.org EPSS API** client and **CISA Known Exploited Vulnerabilities (KEV)** catalog integration.
4. **Module 4: Canonical Contextual Risk Engine (`core/risk_engine.py`)**
   - Mathematical formula: $R = 10 \times [0.3 \times (CVSS/10) + 0.7 \times EPSS] \times Reachability \times (Criticality/5)$.
   - CISA KEV Tier 0 directive priority override and transparent explainability breakdowns.
5. **Module 5: Attack Graph Intelligence (`graph/`)**
   - NetworkX multi-hop relational graph topology connecting Attacker $\rightarrow$ Port $\rightarrow$ Service $\rightarrow$ Container $\rightarrow$ Package $\rightarrow$ CVE.
   - Degree-weighted ForceAtlas2 physics solver with automatic simulation freezing (0% idle CPU, zero shaking).
6. **Module 6: AI Security Copilot (`ai/`)**
   - Pluggable provider abstraction for **Google Gemini API** (`gemini-2.0-flash`), **Local Ollama** (`qwen2.5-coder`), and Deterministic Fallback.
   - Grounded prompt context builder with prompt injection defense (`<untrusted_finding_telemetry>` fences).
   - 4 Features: Remediation Playbook Generator, Breaking Change & Impact Analyzer, Virtual Patch Synthesizer (WAF rules), and Attack Path Storyteller.
7. **Module 7: Human-in-the-Loop Governance (`governance/`)**
   - Strict **Maker-Checker separation of duties** (Analyst proposes, independent Approver authorizes).
   - Formal ticket lifecycle: `Open` $\rightarrow$ `Pending Approval` $\rightarrow$ `Approved` $\rightarrow$ `In Progress` $\rightarrow$ `Ready for Rescan` $\rightarrow$ `Resolved`.
8. **Module 8: Rescan Verification & Cryptographic Audit (`audit/`, `core/assessment_comparison.py`)**
   - Append-only HMAC-SHA256 hash-chained audit ledger with mathematical tampering detection.
   - Resolution Guardrail: tickets cannot be resolved manually without verified scanner absence in a follow-up assessment.

---

## 3. Quickstart & Installation (PowerShell / Windows)

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run schema migrations
python migrate_enterprise_schema.py

# 3. Launch VulnX Streamlit Interface
streamlit run app.py --server.port 8501
```

Access the application in your browser at: **`http://localhost:8501`**

---

## 4. Secure First-Run Administrator Initialization

VulnX does not ship with universal or static default credentials.

Upon first launch on a clean installation, the application automatically detects that no administrator account exists and presents the **Administrator Setup** interface:

1. Launch VulnX (`streamlit run app.py`).
2. The browser automatically navigates to the **Administrator Setup** wizard.
3. Enter your chosen Administrator username (e.g. `admin`) and a strong master password (minimum 10 characters containing uppercase, lowercase, digit, and special character).
4. The system securely hashes the credential using **PBKDF2-HMAC-SHA256** and establishes the primary administrator.
5. First-run setup is permanently deactivated once the administrator is established. Subsequent accounts (Security Analyst, Approver) are provisioned through the role-governed **User Management** panel.

---

## 5. Viva / Presentation Demonstration Mode

For examiners, evaluators, and demonstrations without live scanners:
1. Sign in as `admin`.
2. Navigate to **⚙️ Settings**.
3. Under **🎭 Viva & Presentation Demonstration Mode**, click **"🚀 Activate Viva / Presentation Demo Scenario"**.
4. The system injects a self-contained, isolated simulation (`OWASP Juice Shop [DEMO SIMULATION]`) with CVE-2021-3517 (CVSS 8.6, verified cached EPSS 0.17 / 97th percentile, KEV not listed), dynamically scored by the canonical engine (Risk 3.02 / 10 with Important asset factor 0.8), multi-hop attack path, pre-grounded AI playbook, and Maker-Checker ticket.
5. Demonstrate the complete end-to-end workflow cleanly. Click **"🗑️ Deactivate Demo Scenario"** when finished.

---

## 6. Automated Verification & Quality Assurance

Run the comprehensive automated test suite (374 tests + 24 subtests / 362 unittest methods across 59 test modules):

```powershell
python -m pytest tests -v
```

All 374 tests execute with **100% green pass rate (0 failures, 0 errors)**, verifying mathematical risk calculations, scanner parsing, NVD background queuing, EPSS threat intelligence, AI schema enforcement, Maker-Checker rules, and HMAC tampering detection.

---

## 7. Documentation Index

- [Architecture Specification](docs/ARCHITECTURE.md)
- [Architecture Audit & Inspection Report](docs/ARCHITECTURE_AUDIT.md)
- [Database Schema & 22 Entity Catalog](docs/DATABASE_SCHEMA.md)
- [Canonical Contextual Risk Engine](docs/RISK_SCORING.md)
- [Attack Graph & Topology Specification](docs/ATTACK_GRAPH.md)
- [AI Copilot Integration & Safeguards](docs/AI_INTEGRATION.md)
- [Remediation & Maker-Checker Governance](docs/REMEDIATION_WORKFLOW.md)
- [Cryptographic Audit Ledger & HMAC Verification](docs/AUDIT_LEDGER.md)
- [Testing & Quality Assurance Guide](docs/TESTING_GUIDE.md)
- [Deployment & Operations Guide](docs/DEPLOYMENT_GUIDE.md)
