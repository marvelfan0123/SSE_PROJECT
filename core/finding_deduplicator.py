"""Finding Deduplicator for VulnX."""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from core.finding_normalizer import NormalizedFinding


class FindingDeduplicator:
    """Deduplicates findings according to type-specific entity keys while preserving evidence."""

    @staticmethod
    def get_dedup_key(finding: NormalizedFinding | dict) -> Tuple[str, ...]:
        f = finding.to_dict() if isinstance(finding, NormalizedFinding) else finding
        ftype = f.get("finding_type", "package_vulnerability")

        if ftype == "package_vulnerability":
            return (
                "pkg",
                str(f.get("cve_id") or f.get("cve", "")).strip().upper(),
                str(f.get("package_name") or f.get("package", "")).strip().lower(),
                str(f.get("asset_id") or f.get("target", "")).strip()
            )
        elif ftype == "web_vulnerability":
            return (
                "web",
                str(f.get("url") or "").strip(),
                str(f.get("title") or "").strip().lower(),
                str(f.get("cwe_id") or "").strip()
            )
        elif ftype == "network_observation":
            return (
                "net",
                str(f.get("host") or f.get("asset_id", "")).strip(),
                str(f.get("port") or "").strip(),
                str(f.get("service") or "").strip().lower()
            )
        else:
            return (
                "generic",
                str(f.get("finding_id") or f.get("title", "")).strip()
            )

    @classmethod
    def deduplicate(cls, findings: List[NormalizedFinding | dict]) -> List[NormalizedFinding | dict]:
        """Deduplicate a collection of findings, merging scanner sources and evidence."""
        seen: Dict[Tuple[str, ...], NormalizedFinding | dict] = {}
        for f in findings:
            key = cls.get_dedup_key(f)
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                # Merge sources and evidence if distinct
                if isinstance(existing, NormalizedFinding) and isinstance(f, NormalizedFinding):
                    if f.source not in existing.source:
                        existing.source = f"{existing.source}, {f.source}"
                elif isinstance(existing, dict) and isinstance(f, dict):
                    src1 = existing.get("source", "")
                    src2 = f.get("source", "")
                    if src2 and src2 not in src1:
                        existing["source"] = f"{src1}, {src2}"
        return list(seen.values())

