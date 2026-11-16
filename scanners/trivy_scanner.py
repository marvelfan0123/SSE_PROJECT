"""Trivy Scanner Adapter implementing ScannerBase."""
from __future__ import annotations
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanners.scanner_base import ScannerBase, ScannerResult
import trivy_scanner as legacy_trivy


class TrivyScanner(ScannerBase):
    """Adapter for Aqua Security Trivy container & package vulnerability scanner."""

    def __init__(self, default_timeout: int = 600):
        super().__init__("Trivy", default_timeout)

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def get_version(self) -> str:
        exe = shutil.which("trivy")
        if not exe:
            return "Not Installed"
        code, out, _, _ = self.run_command([exe, "--version"], timeout=10)
        if code == 0 and out:
            lines = out.strip().splitlines()
            return lines[0] if lines else "Installed"
        return "Unknown"

    def scan(
        self,
        target: str,
        output_dir: str | Path = "assessment_reports",
        severities: Optional[List[str]] = None,
        include_unfixed: bool = True,
        **kwargs
    ) -> ScannerResult:
        """Scan a container image or filesystem using Trivy."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error="Trivy CLI is not installed or not found on system PATH."
            )

        try:
            metadata = legacy_trivy.run_trivy_image_scan(
                image=target,
                output_dir=output_dir,
                severities=severities,
                include_unfixed=include_unfixed,
                timeout_seconds=kwargs.get("timeout_seconds", self.default_timeout)
            )
            # Load parsed findings
            findings = []
            raw_path = Path(metadata.get("report_path", ""))
            if raw_path.is_file():
                import json
                try:
                    raw_data = json.loads(raw_path.read_text(encoding="utf-8-sig"))
                    results = raw_data.get("Results", [])
                    for res in results:
                        for vuln in res.get("Vulnerabilities", []) or []:
                            findings.append({
                                "cve": vuln.get("VulnerabilityID"),
                                "package": vuln.get("PkgName"),
                                "installed_version": vuln.get("InstalledVersion"),
                                "fixed_version": vuln.get("FixedVersion", "None listed"),
                                "severity": vuln.get("Severity", "UNKNOWN"),
                                "title": vuln.get("Title") or vuln.get("Description", ""),
                                "target": res.get("Target", target),
                                "source": "Trivy"
                            })
                except Exception:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                status="Completed",
                target=target,
                findings=findings,
                raw_output=metadata,
                execution_time=float(metadata.get("scan_duration_seconds", 0.0)),
                scanner_version=self.get_version(),
                metadata=metadata
            )
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error=str(exc),
                scanner_version=self.get_version()
            )

