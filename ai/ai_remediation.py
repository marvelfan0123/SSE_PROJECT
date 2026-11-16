"""Feature A: AI Remediation Playbook Generator."""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from ai.ai_provider import get_ai_provider, AIProvider
from ai.ai_context_builder import AIContextBuilder
from ai.ai_response_validator import AIResponseValidator
from remediation_guidance import build_remediation_guidance


class AIRemediationGenerator:
    """Generates structured DevSecOps remediation playbooks from verified findings."""

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or get_ai_provider()

    def generate_playbook(self, finding: Dict[str, Any], asset_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate remediation playbook with shell commands, Dockerfile patch, and rollback plan."""
        context = AIContextBuilder.build_finding_context(finding, asset_info)
        prompt_block = AIContextBuilder.format_prompt_block(context)

        system_prompt = """You are a Senior DevSecOps Architect and Incident Response Engineer.
Analyze the provided vulnerability telemetry and generate an exact, actionable remediation playbook.
Do NOT invent package versions. If fixed_version is 'None listed', state that no official fix exists and suggest compensating controls.
Never output destructive commands like 'rm -rf' without explicit safety warnings.

Respond in strict JSON with the following keys:
{
  "finding_summary": "1-2 sentence technical summary",
  "root_cause": "Underlying software vulnerability mechanism",
  "fix_strategy": "Upgrade | Base Image Update | Compensating Control | Reconfiguration",
  "terminal_commands": ["Exact shell or package manager upgrade commands"],
  "dockerfile_patch": "Dockerfile snippet or git diff",
  "verification_command": "Command to verify the fix succeeded",
  "rollback_procedure": "Safe rollback instructions if deployment fails",
  "references": ["Vendor advisory URLs or NVD links"]
}"""

        prompt = f"""Generate a DevSecOps remediation playbook for this finding:
{prompt_block}
"""

        try:
            raw_response = self.provider.generate(prompt, system_prompt=system_prompt, json_mode=True)
            result = AIResponseValidator.parse_and_validate_json(
                raw_response,
                required_keys=["finding_summary", "fix_strategy", "terminal_commands", "dockerfile_patch"]
            )
            if "error" in result:
                # Fallback to deterministic guidance
                det = build_remediation_guidance(finding)
                return {
                    "source": "Deterministic Heuristic Engine (AI Parse Fallback)",
                    "playbook": {
                        "finding_summary": f"Remediate {context['cve']} in {context['package']}",
                        "root_cause": "Package vulnerability identified by scanner",
                        "fix_strategy": "Upgrade to " + context['fixed_version'],
                        "terminal_commands": [f"Review update to {context['fixed_version']}"],
                        "dockerfile_patch": None,
                        "verification_command": "Re-scan asset in VulnX",
                        "rollback_procedure": "Revert to prior image tag",
                        "steps": det.get("steps", [])
                    }
                }
            
            # Ground package and CVE into summary if generic
            if not result.get("finding_summary") or "Identified security finding" in result.get("finding_summary", ""):
                result["finding_summary"] = f"Remediate {context['cve']} in {context['package']} ({context['installed_version']} -> {context['fixed_version']})"

            return {
                "source": getattr(self.provider, "model_name", "AI Copilot"),
                "playbook": result
            }
        except Exception as exc:
            det = build_remediation_guidance(finding)
            return {
                "source": f"Deterministic Engine (API Offline: {exc})",
                "playbook": {
                    "finding_summary": f"Remediate {context['cve']} in {context['package']}",
                    "root_cause": "Package vulnerability identified by scanner",
                    "fix_strategy": "Vendor Patch",
                    "terminal_commands": [f"Apply fix {context['fixed_version']}"],
                    "dockerfile_patch": None,
                    "verification_command": "Re-scan asset in VulnX",
                    "rollback_procedure": "Revert image version",
                    "steps": det.get("steps", [])
                }
            }
