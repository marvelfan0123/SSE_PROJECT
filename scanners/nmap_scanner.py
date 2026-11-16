"""Nmap Scanner Adapter implementing ScannerBase."""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanners.scanner_base import ScannerBase, ScannerResult
import asset_discovery


class NmapScanner(ScannerBase):
    """Adapter for Nmap network mapper and service detection."""

    def __init__(self, default_timeout: int = 180):
        super().__init__("Nmap", default_timeout)

    def is_available(self) -> bool:
        return asset_discovery._find_nmap_executable() is not None

    def get_version(self) -> str:
        exe = asset_discovery._find_nmap_executable()
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
        ports: Optional[str] = None,
        profile: str = "service_light",
        **kwargs
    ) -> ScannerResult:
        """Execute Nmap service and port scan on target."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error="Nmap executable not found on system PATH."
            )

        ports_to_scan = ports or "80,443,8080,3000,8081,3306,5432"
        timeout_sec = kwargs.get("timeout_seconds", self.default_timeout)

        try:
            raw_res = asset_discovery.scan_target(
                host=target,
                ports=ports_to_scan,
                profile=profile,
                timeout_seconds=timeout_sec
            )
            open_ports = raw_res.get("open_ports", [])
            findings = []
            for p in open_ports:
                port_num = p.get("port")
                service = p.get("service", "unknown")
                version = p.get("version", "")
                findings.append({
                    "port": port_num,
                    "service": service,
                    "version": version,
                    "protocol": p.get("protocol", "tcp"),
                    "state": p.get("state", "open"),
                    "title": f"Open Port {port_num}/{p.get('protocol', 'tcp')} ({service})",
                    "target": target,
                    "source": "Nmap"
                })

            return ScannerResult(
                scanner_name=self.name,
                status="Completed",
                target=target,
                findings=findings,
                raw_output=raw_res,
                execution_time=float(raw_res.get("scan_duration_seconds", 0.0)),
                scanner_version=self.get_version(),
                metadata={"open_ports_count": len(open_ports), "profile": profile}
            )
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error=str(exc),
                scanner_version=self.get_version()
            )

