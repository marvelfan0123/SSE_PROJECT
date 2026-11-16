"""Docker Container Inspector implementing ScannerBase."""
from __future__ import annotations
import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from scanners.scanner_base import ScannerBase, ScannerResult
import docker_lab


class DockerInspector(ScannerBase):
    """Adapter for Docker Container Inspection and Topology Discovery."""

    def __init__(self, default_timeout: int = 30):
        super().__init__("Docker Inspector", default_timeout)

    def is_available(self) -> bool:
        return docker_lab.docker_available()

    def get_version(self) -> str:
        st = docker_lab.docker_daemon_status()
        return st.get("server_version") or "Docker CLI available (daemon offline)"

    def scan(self, target: str, **kwargs) -> ScannerResult:
        """Inspect a Docker container ID or name and extract asset metadata."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error="Docker CLI is not available."
            )

        code, stdout, stderr, elapsed = self.run_command(
            ["docker", "inspect", target],
            timeout=kwargs.get("timeout_seconds", self.default_timeout)
        )
        if code != 0:
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error=stderr.strip() or f"Failed to inspect container {target}",
                execution_time=elapsed
            )

        try:
            parsed = json.loads(stdout)
            if not parsed or not isinstance(parsed, list):
                return ScannerResult(
                    scanner_name=self.name,
                    status="Failed",
                    target=target,
                    error="Malformed Docker inspect JSON output.",
                    execution_time=elapsed
                )

            data = parsed[0]
            cfg = data.get("Config", {})
            net = data.get("NetworkSettings", {})
            state = data.get("State", {})

            # Extract IP
            ip_address = net.get("IPAddress", "")
            networks = list(net.get("Networks", {}).keys())
            if not ip_address and networks:
                first_net = net.get("Networks", {}).get(networks[0], {})
                ip_address = first_net.get("IPAddress", "")

            # Extract ports
            ports = []
            port_bindings = net.get("Ports", {}) or {}
            for container_port, bindings in port_bindings.items():
                host_port = bindings[0].get("HostPort") if bindings else None
                ports.append({
                    "container_port": container_port,
                    "host_port": host_port,
                    "host_ip": bindings[0].get("HostIp") if bindings else None
                })

            container_info = {
                "container_id": data.get("Id", "")[:12],
                "container_name": (data.get("Name", "")).lstrip("/"),
                "image_name": cfg.get("Image", ""),
                "ip_address": ip_address,
                "status": state.get("Status", "unknown"),
                "running": state.get("Running", False),
                "networks": networks,
                "ports": ports,
                "labels": cfg.get("Labels", {})
            }

            return ScannerResult(
                scanner_name=self.name,
                status="Completed",
                target=target,
                findings=[],
                raw_output=container_info,
                execution_time=elapsed,
                scanner_version=self.get_version(),
                metadata=container_info
            )
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="Failed",
                target=target,
                error=f"Error parsing Docker inspect: {exc}",
                execution_time=elapsed
            )

