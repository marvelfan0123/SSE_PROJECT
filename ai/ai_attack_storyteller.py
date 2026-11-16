"""Feature C: AI Attack Path Storyteller."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from ai.ai_provider import get_ai_provider, AIProvider
from ai.ai_response_validator import AIResponseValidator


class AIAttackStoryteller:
    """Translates multi-hop attack graphs into executive and technical security narratives."""

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or get_ai_provider()

    def generate_briefing(self, attack_path_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate dual-perspective security briefings based strictly on graph paths."""
        nodes = attack_path_data.get("nodes", [])
        cves = attack_path_data.get("critical_cves", [])
        confidence = attack_path_data.get("confidence", 1.0)
        target = attack_path_data.get("target_name", "Target Infrastructure")

        system_prompt = """You are a Principal Threat Modeler and Red Team Operations Director.
Analyze the provided multi-hop attack path derived directly from the VulnX Attack Graph.
Do NOT invent nodes, hops, or CVEs not listed in the telemetry.
Generate two distinct narratives:
1. Executive Briefing: High-level business risk statement, potential impact, and strategic priority for the Board/CISO.
2. Technical Briefing: Step-by-step adversary exploitation sequence, required preconditions, and mitigation steps for the Blue Team.

Respond in strict JSON with the following keys:
{
  "executive_briefing": {
    "business_risk_summary": "2-3 sentences explaining enterprise risk in business terms",
    "potential_financial_operational_impact": "Operational disruption or data exposure risk",
    "ciso_priority": "Immediate Attention | Scheduled Maintenance | Low Concern"
  },
  "technical_briefing": {
    "exploitation_chain": [
      {
        "hop_number": 1,
        "source_node": "node A",
        "destination_node": "node B",
        "technique": "T1190 or description",
        "preconditions": "Exposure or credentials"
      }
    ],
    "adversary_entry_point": "Initial external point of entry",
    "critical_pivot_point": "Internal pivot point (e.g. exposed port or container)",
    "target_impact_vulnerability": "Final CVE exploited",
    "technical_mitigations": ["Firewall rule, port closure, or patch"]
  }
}"""

        prompt = f"""Generate executive and technical attack narratives for this verified graph path:
Target Asset: {target}
Attack Path Hops: {' -> '.join(str(n) for n in nodes)}
Associated Critical CVEs: {', '.join(cves)}
Path Confidence Score: {confidence}
"""

        try:
            raw_response = self.provider.generate(prompt, system_prompt=system_prompt, json_mode=True)
            result = AIResponseValidator.parse_and_validate_json(
                raw_response,
                required_keys=["executive_briefing", "technical_briefing"]
            )
            if "error" in result:
                return self._fallback_narrative(nodes, cves, target)
            return {
                "source": getattr(self.provider, "model_name", "AI Copilot"),
                "narrative": result
            }
        except Exception:
            return self._fallback_narrative(nodes, cves, target)

    def _fallback_narrative(self, nodes: List[str], cves: List[str], target: str) -> Dict[str, Any]:
        hops_str = " -> ".join(str(n) for n in nodes)
        return {
            "source": "Deterministic Graph Storyteller (Fallback)",
            "narrative": {
                "executive_briefing": {
                    "business_risk_summary": f"Attack path identified to {target} involving {len(nodes)} hops and critical CVEs ({', '.join(cves)}).",
                    "potential_financial_operational_impact": "Potential service compromise or unauthorized remote access.",
                    "ciso_priority": "Immediate Attention" if cves else "Scheduled Maintenance"
                },
                "technical_briefing": {
                    "exploitation_chain": [
                        {"hop_number": idx + 1, "source_node": str(nodes[idx]), "destination_node": str(nodes[idx + 1]), "technique": "Network Traversal", "preconditions": "Network Reachability"}
                        for idx in range(len(nodes) - 1)
                    ],
                    "adversary_entry_point": str(nodes[0]) if nodes else "Internet",
                    "critical_pivot_point": str(nodes[1]) if len(nodes) > 1 else "Unknown",
                    "target_impact_vulnerability": ", ".join(cves) if cves else "Unspecified Finding",
                    "technical_mitigations": ["Restrict firewall inbound ports", "Apply vendor security updates", "Enforce container network segmentation"]
                }
            }
        }

