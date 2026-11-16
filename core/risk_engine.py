"""Canonical Contextual Risk Engine for VulnX."""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import vulngraph_core


@dataclass
class RiskBreakdown:
    score: Optional[float]
    label: str
    status: str
    calculation_method: str
    cvss: Optional[float]
    epss: Optional[float]
    reachability: Optional[float]
    criticality: int
    kev_status: str
    priority_tier: str
    explanation: str


class RiskEngine:
    """Deterministic and explainable contextual risk engine."""

    # Reachability policies
    REACHABILITY_FACTORS = {
        "external_verified": 1.0,
        "internal_verified": 0.7,
        "restricted_path": 0.4,
        "no_path": 0.1,
        "unknown": None
    }

    # Asset Criticality Levels (1-5)
    CRITICALITY_LEVELS = {
        1: "Low-impact development asset",
        2: "Standard internal application",
        3: "Important business application",
        4: "Critical production service",
        5: "Mission-critical infrastructure"
    }

    # Severity bands based on CVSS
    SEVERITY_BANDS = [
        (9.0, 10.0, "Critical"),
        (7.0, 8.9, "High"),
        (4.0, 6.9, "Medium"),
        (0.1, 3.9, "Low"),
        (0.0, 0.0, "None"),
    ]

    @staticmethod
    def calculate_canonical_risk(
        cvss: Optional[float],
        epss: Optional[float],
        reachability: Optional[float],
        criticality: int = 3,
        kev_status: str = "Not Listed"
    ) -> RiskBreakdown:
        """
        Calculate canonical contextual risk score:
        R = 10 * [0.3 * (CVSS / 10) + 0.7 * EPSS] * Reachability * (Criticality / 5)
        Clamped to [0.0, 10.0].
        """
        res = vulngraph_core.contextual_risk(
            cvss=cvss,
            epss=epss,
            reachability=reachability,
            criticality=criticality
        )

        score = res.get("risk")
        status = res.get("status", "Confirmed")
        method = res.get("calculation_method", "canonical")

        # Determine priority tier taking KEV into account
        is_kev = kev_status in ("Listed", "Known Exploited", "Active Exploitation")
        if is_kev:
            priority_tier = "Tier 0 - Immediate KEV Directive"
        elif score is not None:
            if score >= 8.0:
                priority_tier = "Tier 1 - Critical Risk"
            elif score >= 5.0:
                priority_tier = "Tier 2 - High Risk"
            elif score >= 2.0:
                priority_tier = "Tier 3 - Medium Risk"
            else:
                priority_tier = "Tier 4 - Low Risk"
        else:
            priority_tier = "Tier 0 - Immediate Review" if is_kev else "Tier 5 - Manual Triage Required"

        # Generate explainable breakdown
        expl_parts = []
        if score is not None:
            expl_parts.append(
                f"Calculated Score: {score:.2f}/10 via '{method}'. "
                f"CVSS: {cvss if cvss is not None else 'N/A'}, "
                f"EPSS: {epss if epss is not None else 'N/A'}, "
                f"Reachability: {reachability if reachability is not None else 'N/A'}, "
                f"Criticality: {criticality}/5."
            )
        else:
            expl_parts.append(
                f"Provisional state ({status}). Insufficient inputs for confirmed canonical score."
            )

        if is_kev:
            expl_parts.append("ELEVATED: Vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) Catalog.")

        return RiskBreakdown(
            score=score,
            label=f"{score:.2f} / 10" if score is not None else "Manual Review",
            status=status,
            calculation_method=method,
            cvss=cvss,
            epss=epss,
            reachability=reachability,
            criticality=criticality,
            kev_status=kev_status,
            priority_tier=priority_tier,
            explanation=" ".join(expl_parts)
        )

    @classmethod
    def get_cvss_severity(cls, cvss: Optional[float]) -> str:
        if cvss is None:
            return "UNKNOWN"
        for low, high, sev in cls.SEVERITY_BANDS:
            if low <= cvss <= high:
                return sev
        return "UNKNOWN"

