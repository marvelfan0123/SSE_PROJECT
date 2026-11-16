"""FIRST.org Exploit Prediction Scoring System (EPSS) Client."""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("vulnx.integrations.epss")

EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EPSSRecord:
    cve: str
    probability: float
    percentile: float
    status: str  # 'Available', 'Unavailable', 'Cached'
    fetched_at: str


class EPSSClient:
    """Client for retrieving exploit prediction scores from FIRST.org API."""

    def __init__(self, timeout_seconds: int = 15, max_retries: int = 2):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def fetch_batch(self, cves: List[str]) -> Dict[str, EPSSRecord]:
        """Fetch EPSS probabilities for a list of CVE identifiers in batches."""
        clean_cves = [c.strip().upper() for c in cves if c and c.strip().upper().startswith("CVE-")]
        if not clean_cves:
            return {}

        results: Dict[str, EPSSRecord] = {}
        batch_size = 100
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for i in range(0, len(clean_cves), batch_size):
            batch = clean_cves[i:i + batch_size]
            url = f"{EPSS_API_URL}?{urlencode({'cve': ','.join(batch)})}"
            req = Request(
                url,
                headers={
                    "User-Agent": "VulnX-Vulnerability-Management/3.0",
                    "Accept": "application/json"
                }
            )

            success = False
            for attempt in range(self.max_retries + 1):
                try:
                    with urlopen(req, timeout=self.timeout_seconds) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            for item in data.get("data", []):
                                cve_id = str(item.get("cve", "")).upper()
                                prob = float(item.get("epss", 0.0))
                                perc = float(item.get("percentile", 0.0))
                                results[cve_id] = EPSSRecord(
                                    cve=cve_id,
                                    probability=prob,
                                    percentile=perc,
                                    status="Available",
                                    fetched_at=now_str
                                )
                            success = True
                            break
                except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                    if attempt < self.max_retries:
                        time.sleep(1.0 * (attempt + 1))
                    else:
                        logger.warning(f"EPSS batch fetch failed for batch {i}: {exc}")

            if not success:
                for cve_id in batch:
                    if cve_id not in results:
                        results[cve_id] = EPSSRecord(
                            cve=cve_id,
                            probability=0.0,
                            percentile=0.0,
                            status="Unavailable",
                            fetched_at=now_str
                        )

        return results

