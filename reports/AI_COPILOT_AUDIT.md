# VulnX AI Security Copilot Verification Audit Report

**Date:** November 12, 2026  
**Auditor:** AI Systems Architect & Application Security Engineer  
**Status:** **GROUNDED & VALIDATED (ZERO AUTONOMOUS EXECUTION)**

---

## 1. Provider Layer Architecture

The AI copilot layer in `ai/` uses an abstract `AIProvider` supporting:
- **Google Gemini API** (`gemini-2.0-flash`): High-speed structured JSON inference via official `google-genai` SDK.
- **Local Ollama** (`qwen2.5-coder:7b`): Air-gapped offline inference via HTTP REST (`http://localhost:11434/api/generate`).
- **Deterministic Rule Fallback**: Rule-based engine extracting package metadata when offline or without API keys.

---

## 2. Guardrails & Prompt Injection Protection

1. **Grounded Telemetry Enclosure:**
   - Raw scanner findings are enclosed in `<untrusted_finding_telemetry>` fences.
   - System prompts explicitly instruct the model to treat all finding text as raw evidence and ignore embedded instructions.
2. **Strict Schema Validation:**
   - `AIResponseValidator` parses and validates outputs against strict JSON schemas before passing data to UI components.
3. **No Autonomous Changes:**
   - AI outputs are strictly treated as **unverified drafts**.
   - AI cannot execute production commands, approve tickets, or resolve vulnerabilities.
   - All ticket proposals require explicit human review by a Security Analyst and authorization by an Approver.
