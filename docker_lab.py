"""Read-only status checks for the local VulnX Docker demo lab.

This module never starts, stops, removes, or modifies containers. It only reads
`docker ps` output and probes explicitly allow-listed loopback HTTP endpoints.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

EXPECTED_SERVICES = {
    "juice-shop": {"port": 3000, "url": "http://127.0.0.1:3000/"},
    "dvwa": {"port": 8081, "url": "http://127.0.0.1:8081/"},
}


def docker_available() -> bool:
    """Return whether the Docker CLI is installed and available on PATH."""
    return shutil.which("docker") is not None


def docker_daemon_status() -> dict:
    """Check whether both the Docker CLI and the Docker Engine daemon are reachable."""
    if not docker_available():
        return {
            "cli_available": False,
            "daemon_running": False,
            "server_version": "",
            "detail": "Docker CLI not found on PATH.",
        }
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "cli_available": True,
            "daemon_running": False,
            "server_version": "",
            "detail": f"Docker daemon check timed out or failed: {exc}",
        }
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "Docker daemon is not responding.").strip()
        return {
            "cli_available": True,
            "daemon_running": False,
            "server_version": "",
            "detail": f"Docker Engine daemon is not running ({err.splitlines()[-1][:180]})",
        }
    ver = (completed.stdout or "").strip()
    return {
        "cli_available": True,
        "daemon_running": True,
        "server_version": ver,
        "detail": f"Docker Engine v{ver} online" if ver else "Docker Engine online",
    }


def scanner_health_summary() -> list[dict]:
    """Return real operational status for Nmap, Trivy, Docker Engine, and OWASP ZAP."""
    from asset_discovery import discover_nmap_executable
    nmap_bin = discover_nmap_executable()
    trivy_bin = shutil.which("trivy")
    d_status = docker_daemon_status()
    return [
        {
            "scanner": "Nmap",
            "ready": bool(nmap_bin),
            "status": "Available" if nmap_bin else "Unavailable",
            "detail": f"CLI detected ({nmap_bin})" if nmap_bin else "Nmap CLI not found on PATH or standard Windows install directories.",
        },
        {
            "scanner": "Trivy",
            "ready": bool(trivy_bin),
            "status": "Available" if trivy_bin else "Unavailable",
            "detail": f"CLI detected ({trivy_bin})" if trivy_bin else "Trivy CLI not found on PATH.",
        },
        {
            "scanner": "Docker Inspect",
            "ready": bool(d_status["daemon_running"]),
            "status": "Available" if d_status["daemon_running"] else ("Daemon Offline" if d_status["cli_available"] else "Unavailable"),
            "detail": d_status["detail"],
        },
        {
            "scanner": "OWASP ZAP",
            "ready": bool(d_status["daemon_running"]),
            "status": "Available" if d_status["daemon_running"] else "Requires Docker Daemon",
            "detail": "Ready via Docker Engine (ghcr.io/zaproxy/zaproxy:stable)" if d_status["daemon_running"] else d_status["detail"],
        },
    ]


def _parse_container_lines(output: str | None) -> list[dict]:
    """Parse Docker JSON-lines output; tolerate absent or undecodable output."""
    containers = []
    if not output:
        return containers
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        containers.append({
            "id": str(item.get("ID", "")),
            "name": str(item.get("Names", "")),
            "image": str(item.get("Image", "")),
            "status": str(item.get("Status", "unknown")),
            "ports": str(item.get("Ports", "")),
            "state": str(item.get("State", "unknown")),
        })
    return containers


def list_containers() -> list[dict]:
    """Read Docker's container inventory without invoking a shell."""
    if not docker_available():
        raise RuntimeError("Docker CLI was not found on PATH.")
    command = ["docker", "ps", "-a", "--format", "{{json .}}"]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=15, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Docker status check timed out after 15 seconds.") from error
    except OSError as error:
        raise RuntimeError(f"Could not run Docker status check: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Docker returned an unknown error.").strip()
        raise RuntimeError(f"Docker status check failed: {detail[:400]}")
    return _parse_container_lines(completed.stdout)


def check_local_http(url: str, timeout: float = 2.5) -> dict:
    """Probe a known local lab URL; only loopback URLs are permitted."""
    if url not in {service["url"] for service in EXPECTED_SERVICES.values()}:
        raise ValueError("Only the configured local Docker lab URLs can be checked.")
    request = Request(url, headers={"User-Agent": "VulnX-local-lab-health-check/1.0"}, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return {"url": url, "reachable": True, "status_code": int(response.status), "detail": "HTTP response received"}
    except HTTPError as error:
        # HTTP 4xx/5xx still proves that the local web server responded.
        return {"url": url, "reachable": True, "status_code": int(error.code), "detail": "HTTP error response received"}
    except (URLError, TimeoutError, OSError) as error:
        return {"url": url, "reachable": False, "status_code": None, "detail": str(error)[:180]}


def get_lab_status() -> dict:
    """Return Docker inventory and HTTP reachability for the known lab apps."""
    containers = list_containers()
    services = []
    for name, config in EXPECTED_SERVICES.items():
        matching = [
            container for container in containers
            if name in container["name"].lower() or name in container["image"].lower()
        ]
        endpoint = check_local_http(config["url"])
        services.append({
            "service": name,
            "port": config["port"],
            "container_found": bool(matching),
            "containers": matching,
            "http_reachable": endpoint["reachable"],
            "http_status": endpoint["status_code"],
            "http_detail": endpoint["detail"],
        })
    return {
        "docker_available": True,
        "container_count": len(containers),
        "running_count": sum(1 for item in containers if item["state"].lower() == "running"),
        "containers": containers,
        "services": services,
    }


def inspect_asset_evidence(asset_name: str) -> dict:
    """Collect read-only Docker metadata for a discovered image/container.

    Environment-variable VALUES are deliberately never collected because they
    may contain credentials. Only names/labels/configuration metadata are used.
    """
    if not docker_available():
        raise RuntimeError("Docker CLI was not found on PATH.")
    try:
        ps = subprocess.run(
            ["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Could not read Docker containers: {error}") from error
    if ps.returncode != 0:
        raise RuntimeError((ps.stderr or "Docker container listing failed.")[:400])
    matches = []
    wanted = asset_name.strip().lower()
    for line in ps.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        container_id, image, name = parts
        if wanted in {image.lower(), name.lower(), name.lstrip("/").lower()} or wanted in image.lower():
            matches.append((container_id, image, name))
    collected = []
    for container_id, image, name in matches:
        try:
            inspected = subprocess.run(
                ["docker", "inspect", container_id], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if inspected.returncode != 0:
            continue
        try:
            raw = json.loads(inspected.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            continue
        config = raw.get("Config") or {}
        host = raw.get("HostConfig") or {}
        network = raw.get("NetworkSettings") or {}
        collected.append({
            "container_id": container_id[:12], "container_name": name, "image": image,
            "state": (raw.get("State") or {}).get("Status", "unknown"),
            "labels": config.get("Labels") or {},
            "networks": sorted((network.get("Networks") or {}).keys()),
            "published_ports": sorted((network.get("Ports") or {}).keys()),
            "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys()),
            "restart_policy": (host.get("RestartPolicy") or {}).get("Name", "no"),
            "has_healthcheck": bool(config.get("Healthcheck")),
            # Do not collect Config.Env values; they may contain secrets.
            "environment_variable_names": sorted(
                str(item).split("=", 1)[0] for item in (config.get("Env") or []) if "=" in str(item)
            ),
        })
    return {"asset_name": asset_name, "containers": collected, "container_count": len(collected),
            "evidence_source": "Docker inspect (read-only)"}
