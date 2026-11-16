"""Centralized Assessment Orchestration Engine for VulnX."""
from __future__ import annotations
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import assessment_manager
import assessment_worker
from scanners.nmap_scanner import NmapScanner
from scanners.trivy_scanner import TrivyScanner
from scanners.zap_scanner import ZAPScanner
from scanners.docker_inspector import DockerInspector
from core.finding_normalizer import FindingNormalizer, NormalizedFinding
from core.finding_deduplicator import FindingDeduplicator
from core.threat_intelligence import ThreatIntelligenceService
from core.risk_engine import RiskEngine

logger = logging.getLogger("vulnx.orchestrator")


@dataclass
class AssessmentJob:
    assessment_id: str
    target_type: str
    target_name: str
    target_config: Dict[str, Any]
    criticality: int = 3
    created_by: str = "Admin"
    status: str = "Queued"
    scanners_status: Dict[str, str] = field(default_factory=dict)
    findings: List[NormalizedFinding] = field(default_factory=list)


class AssessmentOrchestrator:
    """Manages the full lifecycle of an integrated security assessment."""

    def __init__(self):
        self.nmap = NmapScanner()
        self.trivy = TrivyScanner()
        self.zap = ZAPScanner()
        self.docker = DockerInspector()
        self.threat_intel = ThreatIntelligenceService()

    def validate_target(self, target_type: str, target_val: str) -> tuple[bool, str]:
        """Validate the target format and safety before starting scan."""
        clean = (target_val or "").strip()
        if not clean:
            return False, "Target address or container identifier cannot be empty."
        
        # Prevent shell metacharacters
        for char in (";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"):
            if char in clean:
                return False, f"Invalid character '{char}' in target. Command injection blocked."

        if target_type == "Host / IP":
            import ipaddress
            try:
                ipaddress.ip_address(clean)
                return True, "Valid IP address"
            except ValueError:
                # Hostname check
                if len(clean) > 255 or not clean.replace(".", "").replace("-", "").isalnum():
                    return False, "Invalid hostname or IP address format."
                return True, "Valid hostname"

        elif target_type in ("Docker container", "Running lab container"):
            return True, "Valid container reference"

        elif target_type == "Web application":
            if not (clean.startswith("http://") or clean.startswith("https://") or clean in ("OWASP Juice Shop", "DVWA")):
                return False, "Web application must start with http:// or https://, or be a lab target."
            return True, "Valid web application URL"

        return True, "Target accepted"

    def create_assessment(
        self,
        created_by: str,
        target_type: str,
        target_name: str,
        target_config: Dict[str, Any],
        criticality: int = 3,
        scanners: Optional[List[str]] = None
    ) -> str:
        """Create assessment record and schedule worker execution."""
        selected_scanners = scanners or ["Nmap", "Trivy"]
        scanner_plan = []
        for s in ["Nmap", "Trivy", "OWASP ZAP"]:
            st = "Pending" if s in selected_scanners else "Skipped"
            msg = "Scheduled for execution" if st == "Pending" else "Not selected by operator"
            scanner_plan.append((s, st, msg))

        cfg = dict(target_config)
        cfg["name"] = target_name
        cfg["scanner_plan"] = scanner_plan

        crit_label = {1: "Low", 2: "Normal", 3: "Normal", 4: "Important", 5: "Critical"}.get(criticality, "Normal")

        assessment_id = assessment_manager.create_assessment(
            created_by=created_by,
            target_type=target_type,
            target=cfg,
            criticality=crit_label
        )
        return assessment_id

    def execute_inline(self, assessment_id: str) -> Dict[str, Any]:
        """Execute the assessment pipeline synchronously and return results."""
        return assessment_worker.run_assessment(assessment_id)

