"""CISA Known Exploited Vulnerabilities (KEV) Catalog Client."""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

logger = logging.getLogger("vulnx.integrations.cisa_kev")

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KEVRecord:
    cve: str
    vulnerability_name: str
    date_added: str
    required_action: str
    due_date: str
    status: str  # 'Listed', 'Not Listed', 'Unavailable'


class CISAKEVClient:
    """Client for retrieving and parsing CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, cache_path: Optional[Path] = None, timeout_seconds: int = 15):
        self.cache_path = cache_path or Path(__file__).resolve().parent.parent / "data" / "cisa_kev_cache.json"
        self.timeout_seconds = timeout_seconds

    def fetch_catalog(self) -> Dict[str, KEVRecord]:
        """Fetch the full CISA KEV catalog or read from local cache on network failure."""
        req = Request(
            KEV_CATALOG_URL,
            headers={
                "User-Agent": "VulnX-Vulnerability-Management/3.0",
                "Accept": "application/json"
            }
        )

        try:
            with urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status == 200:
                    raw_data = json.loads(resp.read().decode("utf-8"))
                    records = self._parse_catalog(raw_data)
                    self._save_cache(records)
                    return records
        except Exception as exc:
            logger.warning(f"Failed to fetch live CISA KEV catalog ({exc}). Falling back to cache.")

        return self._load_cache()

    def _parse_catalog(self, raw_data: dict) -> Dict[str, KEVRecord]:
        results: Dict[str, KEVRecord] = {}
        for item in raw_data.get("vulnerabilities", []):
            cve_id = str(item.get("cveID", "")).strip().upper()
            if cve_id:
                results[cve_id] = KEVRecord(
                    cve=cve_id,
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded", ""),
                    required_action=item.get("requiredAction", ""),
                    due_date=item.get("dueDate", ""),
                    status="Listed"
                )
        return results

    def _save_cache(self, records: Dict[str, KEVRecord]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            serializable = {
                k: {
                    "cve": v.cve,
                    "vulnerability_name": v.vulnerability_name,
                    "date_added": v.date_added,
                    "required_action": v.required_action,
                    "due_date": v.due_date,
                    "status": v.status
                }
                for k, v in records.items()
            }
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(serializable), encoding="utf-8")
            tmp.replace(self.cache_path)
        except OSError:
            pass

    def _load_cache(self) -> Dict[str, KEVRecord]:
        if not self.cache_path.is_file():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return {
                k: KEVRecord(
                    cve=v["cve"],
                    vulnerability_name=v.get("vulnerability_name", ""),
                    date_added=v.get("date_added", ""),
                    required_action=v.get("required_action", ""),
                    due_date=v.get("due_date", ""),
                    status="Listed"
                )
                for k, v in data.items()
            }
        except Exception:
            return {}

