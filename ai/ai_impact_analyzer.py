"""Feature B: AI Breaking Change and Impact Analyzer."""
from __future__ import annotations
from typing import Any, Dict, Optional
from ai.ai_provider import get_ai_provider, AIProvider
from ai.ai_context_builder import AIContextBuilder
from ai.ai_response_validator import AIResponseValidator


class AIImpactAnalyzer:
    """Analyzes regression risk and service downtime implications of proposed patches."""

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or get_ai_provider()

    def analyze_change_impact(self, finding: Dict[str, Any], asset_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Assess the likelihood of breaking changes or service disruption."""
        context = AIContextBuilder.build_finding_context(finding, asset_info)
        prompt_block = AIContextBuilder.format_prompt_block(context)

        system_prompt = """You are an Enterprise System Reliability and Change Management Engineer.
Evaluate whether upgrading the specified component introduces breaking changes, library ABI incompatibilities, or service downtime.
Categorize change_risk strictly as 'Low', 'Medium', 'High', or 'Unknown'.

Respond in strict JSON with the following keys:
{
  "change_risk": "Low | Medium | High | Unknown",
  "downtime_required": true | false,
  "breaking_change_details": "Explanation of potential runtime or ABI breaks",
  "affected_dependencies": ["Dependent packages or services that might be affected"],
  "recommended_precautions": ["Pre-deployment checks and staging tests"],
  "confidence_level": "High | Medium | Low"
}"""

        prompt = f"""Assess the change impact and regression risk for updating this component:
{prompt_block}
"""

        try:
            raw_response = self.provider.generate(prompt, system_prompt=system_prompt, json_mode=True)
            result = AIResponseValidator.parse_and_validate_json(
                raw_response,
                required_keys=["change_risk", "breaking_change_details", "downtime_required"]
            )
            if "error" in result:
                return {
                    "source": "Heuristic Rule Fallback",
                    "impact": {
                        "change_risk": "Medium" if any(t in context['package'].lower() for t in ("libc", "ssl", "apache", "kernel")) else "Low",
                        "downtime_required": False,
                        "breaking_change_details": "Point release package update. Run standard staging regression tests.",
                        "affected_dependencies": [context['package']],
                        "recommended_precautions": ["Deploy in staging environment prior to production rollout."],
                        "confidence_level": "Medium"
                    }
                }
            return {
                "source": getattr(self.provider, "model_name", "AI Copilot"),
                "impact": result
            }
        except Exception:
            return {
                "source": "Heuristic Fallback (API Offline)",
                "impact": {
                    "change_risk": "Medium" if any(t in context['package'].lower() for t in ("libc", "ssl", "apache", "kernel")) else "Low",
                    "downtime_required": False,
                    "breaking_change_details": "Standard package upgrade. Verify in staging.",
                    "affected_dependencies": [context['package']],
                    "recommended_precautions": ["Test in isolated container before production."],
                    "confidence_level": "Medium"
                }
            }

