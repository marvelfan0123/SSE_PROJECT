# VulnX AI Security Copilot Architecture & Governance

## 1. Architectural Philosophy: AI as an Assistant, Not an Autonomous Actor

In VulnX, generative AI functions strictly as a **force multiplier and decision-support copilot**. It accelerates the security analyst's research from hours to seconds while strictly adhering to the **Human-in-the-Loop (HITL)** paradigm:
- AI **NEVER** executes commands on production targets.
- AI **NEVER** automatically approves remediation tickets.
- AI **NEVER** overrides mathematical contextual risk scores.
- All AI recommendations are recorded in the audit trail as unverified drafts until reviewed by humans.

---

## 2. Pluggable Provider Abstraction (`ai/ai_provider.py`)

VulnX abstracts inference behind the `AIProvider` interface:

| Provider | Configuration Key | Strengths | Deployment Context |
| :--- | :--- | :--- | :--- |
| **Google Gemini API** | `GEMINI_API_KEY` | `gemini-2.0-flash`: sub-second latency, structured JSON mode, high reasoning accuracy. | Cloud enterprise deployments. |
| **Local Ollama** | `OLLAMA_HOST` | `qwen2.5-coder:7b` / `llama3.1:8b`: 100% offline, zero network leakage. | Air-gapped / Classified SOC environments. |
| **Deterministic Fallback** | Automatic | Rule-based engine extracting package metadata without AI. | Offline fallback when APIs are unavailable. |

---

## 3. The 4 Core Copilot Capabilities

### Feature A: DevSecOps Remediation Playbook Generator
- Synthesizes exact package manager upgrade commands (`apt-get install --only-upgrade <pkg>=<fix>`).
- Generates a `git diff` patch for the project `Dockerfile`.
- Outlines rollback procedures and verification tests.

### Feature B: Breaking Change & Regression Analyzer
- Evaluates ABI compatibility and library conflicts.
- Predicts whether service downtime or daemon restart is required.
- Assigns a **Change Risk: Low / Medium / High / Unknown**.

### Feature C: Virtual Patch Synthesizer (Compensating Controls)
- For zero-day vulnerabilities where no official package fix exists (`Fixed Version: None listed`).
- Generates **ModSecurity SecRules** or **Nginx Ingress** rate/payload filtering rules to protect the perimeter while waiting for upstream patches.
- Explicitly flags all output as unverified drafts requiring staging testing.

### Feature D: Attack Path Storyteller
- Translates multi-hop NetworkX graphs into two distinct narratives:
  1. **Executive Briefing:** Non-technical business risk statement and CISO priority.
  2. **Technical Briefing:** MITRE-style step-by-step adversary exploitation sequence.

---

## 4. Prompt Injection Defense & Grounding
- All scanner outputs, package descriptions, and CVE texts are treated as untrusted data and enclosed in `<untrusted_finding_telemetry>` delimiters.
- The system instructions explicitly instruct the model to ignore any instruction or override contained within the telemetry payload.
- All outputs are validated against strict JSON schemas before being rendered in the UI.

