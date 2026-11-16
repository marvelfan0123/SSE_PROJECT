# VulnX — Viva & Final Presentation Demonstration Guide

**Project Name:** Scanning and Vulnerability Management Platform  
**Product Brand:** VulnX  
**Target Audience:** Academic Examiners, Project Evaluators & Technical Viva Panel  

---

## 1. Demonstration Scenario Overview

To ensure a seamless, reproducible demonstration without relying on external internet connectivity or live container daemons during your presentation, VulnX includes a dedicated **Demonstration Mode**:
- **Target Asset:** `OWASP Juice Shop [DEMO SIMULATION]`
- **Container Instance:** `juice-shop` (IP: `172.18.0.2`, Port 3000 mapped to host)
- **Vulnerable Library:** `libxml2` (Installed: `2.9.10-0ubuntu0.20.04.1`, Fixed: `2.9.10-0ubuntu0.20.04.2`)
- **Vulnerability:** `CVE-2021-3517` (Heap-based buffer overflow in `xmlBufferAdd`)
- **Threat Intelligence:** CVSS 8.6, EPSS Probability 0.724 (High likelihood of wild exploitation), CISA KEV Listed.
- **Contextual Risk Score:** **8.12 / 10** (Clamped canonical calculation)

---

## 2. Step-by-Step Viva Walkthrough Script

### Step 1: System Login & Role-Based Access Control (1 Minute)
1. Launch the platform: `streamlit run app.py --server.port 8501`.
2. Sign in with your administrator credentials created during first-run setup.
3. **Talking Point for Evaluators:**  
   *"VulnX implements strict Role-Based Access Control (RBAC) where Administrators govern users and policies, Security Analysts launch scans and propose fixes, and Approvers independently authorize production changes."*

### Step 2: Activating the Viva Demo Scenario (1 Minute)
1. In the sidebar, navigate to **⚙️ Settings**.
2. Under **🎭 Viva & Presentation Demonstration Mode**, click **"🚀 Activate Viva / Presentation Demo Scenario"**.
3. Notice that the active scope at the top of the sidebar immediately selects `OWASP Juice Shop [DEMO SIMULATION]`.
4. **Talking Point for Evaluators:**  
   *"To guarantee zero failure during demonstrations, VulnX isolates synthetic simulation fixtures from real production scans, clearly tagging all simulated records with `[DEMO SIMULATION]`."*

### Step 3: Overview Dashboard & Real-Time Metrics (1 Minute)
1. Click **📊 Overview** in the workspace navigation.
2. Highlight the KPI metric cards:
   - Total Assets: 1
   - Critical / High Vulnerabilities
   - Contextual Risk Distribution (0-10 scale)
   - EPSS Enrichment Coverage
   - Open Remediation Tickets
3. **Talking Point for Evaluators:**  
   *"Unlike static dashboards, every number displayed in VulnX is computed dynamically via SQL queries against underlying SQLite records."*

### Step 4: Vulnerability Findings & Canonical Risk Explainability (2 Minutes)
1. Click **🔍 Findings** in the workspace navigation.
2. Locate `CVE-2021-3517` in `libxml2`.
3. Expand **Details & Remediation Guidance**:
   - Show the mathematical formula breakdown:
     $$R = 10 \times [0.3 \times (8.6 / 10) + 0.7 \times 0.724] \times 1.0 \times (4 / 5) = 8.12$$
   - Show the **FIRST.org EPSS** score (0.724) and **CISA KEV** directive status.
4. **Talking Point for Evaluators:**  
   *"Traditional scanners like Nessus rely only on static CVSS. VulnX computes contextual risk by factoring in real-world exploitability (EPSS), network reachability, and asset business criticality."*

### Step 5: Interactive Attack Graph & Reachability Topology (2 Minutes)
1. Click **🕸️ Attack Graph** in the workspace navigation.
2. Demonstrate the multi-hop attack path:
   `Internet Attacker` $\longrightarrow$ `Port 3000/TCP` $\longrightarrow$ `Node.js Web App` $\longrightarrow$ `Container juice-shop` $\longrightarrow$ `libxml2` $\longrightarrow$ `CVE-2021-3517`.
3. Highlight that the physics engine is completely stable (0% idle CPU, zero shaking) using ForceAtlas2.
4. **Talking Point for Evaluators:**  
   *"The graph proves that this vulnerability is reachable from the public internet through exposed port 3000, justifying why its risk score was elevated to 8.12/10."*

### Step 6: Grounded AI Security Copilot (2 Minutes)
1. Click **🤖 AI Security Copilot** in the workspace navigation.
2. Select `CVE-2021-3517`.
3. Explore the 4 tabs:
   - **🛠️ Remediation Playbook:** Exact shell commands (`apt-get install --only-upgrade libxml2`) and Dockerfile patch.
   - **⚠️ Breaking Change Analyzer:** Evaluates ABI compatibility and downtime risk.
   - **🛡️ Virtual Patch (WAF):** ModSecurity / Nginx rule to block exploit payloads if no vendor patch was available.
   - **🎙️ Attack Storyteller:** Dual narrative with an Executive Briefing for CISOs and Technical Adversary Chain for Red Teams.
4. Click **"➕ Create Remediation Ticket with this AI Draft"**.
5. **Talking Point for Evaluators:**  
   *"VulnX treats AI as a force multiplier, not an autonomous agent. The AI proposes the playbook, but human engineers validate and authorize it under strict Maker-Checker governance."*

### Step 7: Maker-Checker Governance & Rescan Verification (2 Minutes)
1. Click **🛡️ Remediation Center** in the workspace navigation.
2. Show the newly created ticket under **Active Tickets & Decisioning**.
3. Demonstrate Maker-Checker separation of duties:
   - The creator (Maker) cannot approve their own ticket.
   - The Approver (Checker) reviews the AI impact score and enters a mandatory written justification to authorize the ticket.
4. Explain the **Resolution Guardrail**:
   - Tickets cannot be marked `Resolved` manually.
   - The backend strictly requires a follow-up rescan confirming that `CVE-2021-3517` is absent on the target asset.

### Step 8: Cryptographic Audit Ledger & Tamper Proofing (1 Minute)
1. In Administration, click **🔐 Audit Logs**.
2. Show that every action (assessment start, finding creation, AI playbook generation, ticket proposal, approval) is recorded in an immutable **HMAC-SHA256 hash chain**.
3. Click **"Verify Audit Log Integrity"** to demonstrate that the cryptographic chain is intact.
4. **Talking Point for Evaluators:**  
   *"VulnX maintains an append-only cryptographic ledger. If any record in SQLite is modified out-of-band by an attacker, the system immediately flags tampering and identifies the altered record."*

