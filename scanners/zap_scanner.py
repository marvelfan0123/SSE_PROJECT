"""OWASP ZAP Scanner Adapter implementing ScannerBase."""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanners.scanner_base import ScannerBase, ScannerResult
import zap_scanner as legacy_zap


class ZAPScanner(ScannerBase):
    """Adapter for OWASP ZAP Web Application Security Scanner."""

    def __init__(self, default_timeout: int = 900):
        super().__init__("OWASP ZAP", default_timeout)

    def is_available(self) -> bool:
        return legacy_zap.docker_available()

    def get_version(self) -> str:
        if not self.is_available():
            return "Not Installed (Docker required)"
        return legacy_zap.ZAP_DOCKER_IMAGE

    def scan(
        self,
        target: str,
        output_dir: str | Path = "zap_reports",
        max_spider_minutes: int = 2,
        **kwargs
    ) -> ScannerResult:
        """Run OWASP ZAP baseline passive scan against target application."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error="Docker is required to run OWASP ZAP container."
            )

        timeout_sec = kwargs.get("timeout_seconds", self.default_timeout)
        try:
            res = legacy_zap.run_zap_baseline_scan(
                app_name=target,
                output_dir=output_dir,
                timeout_seconds=timeout_sec,
                max_spider_minutes=max_spider_minutes
            )
            # Parse alerts if report exists
            findings = []
            rep_path = Path(res.get("report_path", ""))
            if rep_path.is_file():
                import json
                try:
                    data = json.loads(rep_path.read_text(encoding="utf-8-sig"))
                    site = data.get("site", [])
                    if isinstance(site, list) and site:
                        alerts = site[0].get("alerts", [])
                        for a in alerts:
                            findings.append({
                                "title": a.get("alert"),
                                "severity": a.get("riskdesc", "Informational").split(" ")[0].upper(),
                                "confidence": a.get("confidence"),
                                "description": a.get("desc"),
                                "solution": a.get("solution"),
                                "target": target,
                                "source": "OWASP ZAP",
                                "cwe_id": a.get("cweid"),
                            })
                except Exception:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                status="Completed",
                target=target,
                findings=findings,
                raw_output=res,
                execution_time=float(res.get("scan_duration_seconds", 0.0)),
                scanner_version=self.get_version(),
                metadata={"alerts_count": len(findings)}
            )
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error=str(exc),
                scanner_version=self.get_version()
            )

