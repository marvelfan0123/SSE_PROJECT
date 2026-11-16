"""Feature D: AI Virtual Patch Generator (Compensating Controls)."""
from __future__ import annotations
from typing import Any, Dict, Optional
from ai.ai_provider import get_ai_provider, AIProvider
from ai.ai_context_builder import AIContextBuilder
from ai.ai_response_validator import AIResponseValidator


class AIVirtualPatchGenerator:
    """Synthesizes perimeter compensating controls (ModSecurity, WAF, Nginx) for zero-day findings."""

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or get_ai_provider()

    def generate_virtual_patch(self, finding: Dict[str, Any], asset_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate virtual patch rules when no official upstream package fix is yet available."""
        context = AIContextBuilder.build_finding_context(finding, asset_info)
        prompt_block = AIContextBuilder.format_prompt_block(context)

        system_prompt = """You are an Application Security Architect specializing in Web Application Firewalls and Perimeter Defense.
Generate a compensating virtual patch (ModSecurity SecRule, Nginx ingress rule, or iptables rule) to mitigate the described vulnerability.
Do NOT claim that a generic WAF rule can solve low-level kernel or memory corruption flaws; explain limitations clearly.
All generated virtual patches must be explicitly marked as unverified drafts requiring staging testing.

Respond in strict JSON with the following keys:
{
  "control_type": "ModSecurity WAF | Nginx Ingress | iptables / Network Filter | Header Sanitization",
  "rule_syntax": "Exact configuration or SecRule syntax snippet",
  "implementation_location": "/etc/modsecurity/rules/ or nginx.conf",
  "mitigation_mechanism": "How this rule blocks the attack pattern without modifying source code",
  "false_positive_risk": "Low | Medium | High",
  "verification_curl_test": "Exact curl command to test if the rule successfully blocks malicious requests",
  "unverified_warning": "This virtual patch is an unverified compensating control draft. Mandatory staging testing required before production rollout."
}"""

        prompt = f"""Synthesize a compensating virtual patch control for this vulnerability:
{prompt_block}
"""

        try:
            raw_response = self.provider.generate(prompt, system_prompt=system_prompt, json_mode=True)
            result = AIResponseValidator.parse_and_validate_json(
                raw_response,
                required_keys=["control_type", "rule_syntax", "mitigation_mechanism"]
            )
            if "error" in result:
                return self._fallback_virtual_patch(context)
            if "unverified_warning" not in result or not result.get("unverified_warning"):
                result["unverified_warning"] = "Unverified compensating control draft. Mandatory staging testing required before production rollout."
            return {
                "source": getattr(self.provider, "model_name", "AI Copilot"),
                "patch": result
            }
        except Exception:
            return self._fallback_virtual_patch(context)

    def _fallback_virtual_patch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cve = context.get("cve", "CVE-XXXX")
        return {
            "source": "Compensating Control Engine (Fallback)",
            "patch": {
                "control_type": "Nginx Ingress / Rate Limit Rule",
                "rule_syntax": f"# Compensating control for {cve}\nlocation / {{\n    limit_req zone=vulnx_protect burst=10 nodelay;\n    client_body_buffer_size 128k;\n}}",
                "implementation_location": "/etc/nginx/conf.d/security.conf",
                "mitigation_mechanism": f"Applies strict request limiting and payload buffer restrictions while vendor patch for {cve} is pending.",
                "false_positive_risk": "Low",
                "verification_curl_test": "curl -i -X POST http://localhost:8080/ -d 'test payload'",
                "unverified_warning": "This virtual patch is an unverified compensating control draft. Mandatory staging testing required before production rollout."
            }
        }
