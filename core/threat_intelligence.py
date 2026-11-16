"""Central Threat Intelligence Orchestrator for VulnX."""
from __future__ import annotations
import os
from typing import Any, Dict, List
import threat_intelligence as legacy_ti
from integrations.epss_client import EPSSClient
from integrations.cisa_kev_client import CISAKEVClient


class ThreatIntelligenceService:
    """Coordinates EPSS and CISA KEV enrichment with caching and resilience."""

    def __init__(self):
        self.epss_client = EPSSClient()
        self.kev_client = CISAKEVClient()

    def enrich(self, findings: List[Dict[str, Any]], force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Enriches a list of findings with EPSS probabilities and KEV status.
        Delegates to the battle-tested cached engine in threat_intelligence.py.
        """
        # Ensure network enrichment is enabled if not set
        if not os.environ.get("VULNX_THREAT_ENRICHMENT"):
            os.environ["VULNX_THREAT_ENRICHMENT"] = "1"
        return legacy_ti.enrich_findings(findings, force_refresh=force_refresh)

    def get_cve_intel(self, cve: str) -> Dict[str, Any]:
        """Retrieve EPSS and KEV intelligence for a single CVE."""
        clean_cve = cve.strip().upper()
        cached_epss = legacy_ti.get_cached_epss(clean_cve)
        cache = legacy_ti._read_cache()
        norm_cache = legacy_ti._normalize_cache(cache)
        kev_data = norm_cache.get("kev", {}).get("data", {}) or {}
        
        is_kev = clean_cve in kev_data
        if cached_epss and cached_epss.get("status") == "available":
            epss_prob = cached_epss.get("probability")
            epss_perc = cached_epss.get("percentile")
            epss_status = "Available"
        elif cached_epss and cached_epss.get("status") == "stale":
            epss_prob = None
            epss_perc = cached_epss.get("percentile")
            epss_status = "Stale"
        else:
            epss_prob = None
            epss_perc = None
            epss_status = "Unavailable"

        return {
            "cve": clean_cve,
            "epss_probability": epss_prob,
            "epss_percentile": epss_perc,
            "epss_status": epss_status,
            "kev_status": "Listed" if is_kev else "Not Listed",
            "kev_date_added": kev_data.get(clean_cve) if is_kev else None
        }

