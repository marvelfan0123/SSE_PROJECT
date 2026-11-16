"""Nmap asset and service discovery for authorized local and RFC1918 lab targets.

VulnX: Scanning and Vulnerability Management Platform.
Implements:
- Reliable Nmap executable discovery across PATH, environment overrides, and Windows install directories
- Pre-scan executable validation
- Safe subprocess argument arrays (shell=False) with Windows CREATE_NO_WINDOW support
- Unprivileged Winsock TCP connect profiles (--unprivileged -sT -Pn -n) preventing Npcap loopback hangs
- Configurable connect timeouts, host timeouts, and scan profiles (service_light, connect_only, service_standard)
- Guaranteed process termination (proc.kill()) on timeout
- Resilient XML parsing (preserves usable XML reports even on non-zero exit codes with stderr warnings)
- Structured error classification (executable_unavailable, invalid_target, permission_error,
  target_unreachable, timeout, malformed_xml, execution_error)
- Bounded retry strictly for retryable errors (stepping down from service_light to connect_only on timeout)
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
from typing import Any
import xml.etree.ElementTree as ET

from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH

DB_PATH = SHARED_DB_PATH

SCAN_PROFILES: dict[str, list[str]] = {
    "service_light": ["--unprivileged", "-sT", "-Pn", "-n", "-sV", "--version-light", "--max-retries", "1"],
    "connect_only": ["--unprivileged", "-sT", "-Pn", "-n", "--max-retries", "1"],
    "service_standard": ["--unprivileged", "-sT", "-Pn", "-n", "-sV", "--version-intensity", "5", "--max-retries", "2"],
}


class NmapScanError(RuntimeError):
    """Structured Nmap execution error with root-cause category and retry eligibility."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "execution_error",
        retryable: bool = False,
        exit_code: int | None = None,
        duration_seconds: float = 0.0,
        stderr: str = "",
    ):
        super().__init__(message)
        self.category = category
        self.retryable = bool(retryable)
        self.exit_code = exit_code
        self.duration_seconds = round(float(duration_seconds or 0.0), 3)
        self.stderr = str(stderr or "")


@contextmanager
def _db():
    """Commit/rollback and always close the SQLite handle."""
    connection = connect_sqlite(DB_PATH)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _candidate_nmap_paths() -> list[Path]:
    """Return ordered candidate paths for the Nmap executable, including Windows install locations."""
    candidates: list[Path] = []
    for env_key in ("VULNX_NMAP_PATH", "VULNGRAPH_NMAP_PATH"):
        env_val = os.getenv(env_key, "").strip()
        if env_val:
            candidates.append(Path(env_val))

    for binary_name in ("nmap", "nmap.exe"):
        which_hit = shutil.which(binary_name)
        if which_hit:
            candidates.append(Path(which_hit))

    win_dirs = [
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        r"C:\Program Files (x86)",
        r"C:\Program Files",
    ]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        win_dirs.append( str(Path(local_app_data) / "Programs") )

    seen: set[str] = set()
    for base in win_dirs:
        if not base:
            continue
        p = Path(base) / "Nmap" / "nmap.exe"
        norm = str(p).lower()
        if norm not in seen:
            seen.add(norm)
            candidates.append(p)
    return candidates


def discover_nmap_executable() -> str | None:
    """Discover the installed Nmap executable from env, PATH, or standard Windows directories."""
    for candidate in _candidate_nmap_paths():
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def nmap_available() -> bool:
    """Return True if a usable Nmap executable is installed on the host."""
    return discover_nmap_executable() is not None


def validate_nmap_executable(executable: str | None = None) -> str:
    """Validate that the Nmap executable exists and is runnable before starting a scan."""
    exe = executable or discover_nmap_executable()
    if not exe:
        raise NmapScanError(
            "Nmap was not found on PATH or in standard installation directories. Install Nmap and restart the application.",
            category="executable_unavailable",
            retryable=False,
        )
    exe_path = Path(exe)
    try:
        is_file = exe_path.is_file()
    except OSError as exc:
        raise NmapScanError(
            f"Nmap executable path could not be accessed ({exe}): {exc}",
            category="permission_error",
            retryable=False,
        ) from exc
    if not is_file:
        raise NmapScanError(
            f"Configured Nmap executable does not exist: {exe}",
            category="executable_unavailable",
            retryable=False,
        )
    return str(exe_path)


def _validate_target(target: str) -> str:
    target = str(target or "").strip()
    if not target:
        raise ValueError("Enter a target IP or hostname.")
    if target.lower() in {"localhost", "127.0.0.1", "::1"}:
        return "127.0.0.1" if target.lower() == "localhost" else target
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("For safety, enter localhost or a private IP address from your authorized lab.") from exc
    if not (address.is_private or address.is_loopback):
        raise ValueError("Public IP targets are not allowed. Use localhost or an authorized private lab IP.")
    return str(address)


def _validate_ports(port_text: str) -> str:
    parts = [part.strip() for part in str(port_text or "").split(",") if part.strip()]
    if not parts or len(parts) > 30:
        raise ValueError("Enter between 1 and 30 comma-separated TCP ports.")
    ports: list[int] = []
    for part in parts:
        if not (part.isascii() and part.isdigit()) or not 1 <= int(part) <= 65535:
            raise ValueError(f"Invalid TCP port: {part}")
        port_num = int(part)
        if port_num not in ports:
            ports.append(port_num)
    return ",".join(map(str, ports))


def build_nmap_command(
    executable: str,
    target: str,
    ports: str,
    *,
    profile: str = "service_light",
    connect_timeout_ms: int = 2000,
) -> list[str]:
    """Construct a safe, shell-free Nmap command array for the specified scan profile."""
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unsupported Nmap scan profile: {profile}")
    connect_ms = max(250, min(int(connect_timeout_ms or 2000), 15000))
    init_rtt_ms = max(150, min(connect_ms // 2, 2000))

    cmd = [executable]
    if ":" in target:
        cmd.append("-6")
    cmd.extend(SCAN_PROFILES[profile])
    cmd.extend([
        "--initial-rtt-timeout", f"{init_rtt_ms}ms",
        "--max-rtt-timeout", f"{connect_ms}ms",
        "-p", ports,
        "-oX", "-",
        target,
    ])
    return cmd


def _run_nmap_process(command: list[str], timeout_seconds: int) -> tuple[int, str, str, float]:
    """Execute Nmap subprocess safely with Windows CREATE_NO_WINDOW and guaranteed kill on timeout."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
    except PermissionError as exc:
        raise NmapScanError(
            f"Permission denied when launching Nmap: {exc}",
            category="permission_error",
            retryable=False,
        ) from exc
    except FileNotFoundError as exc:
        raise NmapScanError(
            f"Nmap executable was not found: {exc}",
            category="executable_unavailable",
            retryable=False,
        ) from exc
    except OSError as exc:
        raise NmapScanError(
            f"Could not launch Nmap: {exc}",
            category="execution_error",
            retryable=False,
        ) from exc

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            out_tail, err_tail = proc.communicate(timeout=5)
        except Exception:
            out_tail, err_tail = "", ""
        elapsed = time.monotonic() - t0
        raise NmapScanError(
            f"Nmap scan timed out after {timeout_seconds} seconds. Try fewer ports.",
            category="timeout",
            retryable=True,
            exit_code=proc.returncode,
            duration_seconds=elapsed,
            stderr=str(err_tail or getattr(exc, "stderr", "") or ""),
        ) from exc

    elapsed = time.monotonic() - t0
    return int(proc.returncode or 0), stdout or "", stderr or "", elapsed


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Validate and parse Nmap XML output into host status and port states."""
    if not xml_text or not xml_text.strip():
        raise NmapScanError(
            "Nmap returned empty output instead of an XML report.",
            category="malformed_xml",
            retryable=False,
        )
    if len(xml_text) > 5_000_000:
        raise NmapScanError(
            "Nmap XML output exceeded the 5 MB safety limit.",
            category="malformed_xml",
            retryable=False,
        )
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapScanError(
            "Nmap returned output that could not be parsed as XML.",
            category="malformed_xml",
            retryable=False,
        ) from exc

    if root.tag != "nmaprun":
        raise NmapScanError(
            f"Unexpected XML root element '{root.tag}' (expected 'nmaprun').",
            category="malformed_xml",
            retryable=False,
        )

    host = root.find("host")
    runstats = root.find("runstats")
    if host is None and runstats is None:
        raise NmapScanError(
            "Nmap XML output is incomplete (missing <host> and <runstats> elements).",
            category="malformed_xml",
            retryable=False,
        )

    host_status = "unknown"
    status_reason = ""
    open_ports: list[dict[str, Any]] = []
    closed_ports: list[dict[str, Any]] = []
    filtered_ports: list[dict[str, Any]] = []

    if host is not None:
        status_el = host.find("status")
        if status_el is not None:
            host_status = status_el.get("state", "unknown")
            status_reason = status_el.get("reason", "")

        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            if state_el is None:
                continue
            port_state = state_el.get("state", "unknown")
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version_str = " ".join(filter(None, [
                product,
                service_el.get("version", "") if service_el is not None else "",
                service_el.get("extrainfo", "") if service_el is not None else "",
            ])).strip() or "Not identified"

            entry = {
                "port": port_id,
                "protocol": protocol,
                "state": port_state,
                "service": service_name,
                "product": product,
                "version": version_str,
            }
            if port_state == "open":
                open_ports.append(entry)
            elif port_state == "closed":
                closed_ports.append(entry)
            elif "filtered" in port_state:
                filtered_ports.append(entry)
    elif runstats is not None:
        hosts_el = runstats.find("hosts")
        if hosts_el is not None and hosts_el.get("up") == "0" and int(hosts_el.get("down", "0") or 0) > 0:
            host_status = "down"

    return {
        "host_status": host_status,
        "status_reason": status_reason,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "filtered_ports": filtered_ports,
    }


def _classify_nonzero_failure(exit_code: int, stderr: str, stdout: str, duration: float) -> NmapScanError:
    """Classify a non-zero Nmap process exit when no valid XML report was produced."""
    message = (stderr.strip() or stdout.strip() or f"Nmap exited with status {exit_code}.")[:700]
    lower = message.lower()
    if any(tok in lower for tok in ("permission denied", "access is denied", "operation not permitted", "requires root")):
        return NmapScanError(
            f"Nmap permission error: {message}",
            category="permission_error",
            retryable=False,
            exit_code=exit_code,
            duration_seconds=duration,
            stderr=stderr,
        )
    if any(tok in lower for tok in ("failed to resolve", "no route to host", "network is unreachable", "host seems down")):
        return NmapScanError(
            f"Target unreachable: {message}",
            category="target_unreachable",
            retryable=False,
            exit_code=exit_code,
            duration_seconds=duration,
            stderr=stderr,
        )
    if "timed out" in lower or "host timeout" in lower:
        return NmapScanError(
            f"Nmap scan timed out: {message}",
            category="timeout",
            retryable=True,
            exit_code=exit_code,
            duration_seconds=duration,
            stderr=stderr,
        )
    return NmapScanError(
        f"Nmap failed: {message}",
        category="execution_error",
        retryable=False,
        exit_code=exit_code,
        duration_seconds=duration,
        stderr=stderr,
    )


def _initialize_table():
    with _db() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS asset_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            target TEXT NOT NULL,
            ports_checked TEXT NOT NULL,
            host_status TEXT NOT NULL,
            open_ports INTEGER NOT NULL,
            results_json TEXT NOT NULL
        )""")


def scan_target(
    target: str,
    port_text: str,
    timeout_seconds: int = 120,
    *,
    profile: str = "service_light",
    connect_timeout_ms: int = 2000,
    max_retries: int = 1,
    executable: str | None = None,
) -> dict[str, Any]:
    """Run an authorized Nmap scan with profile fallback on retryable timeouts."""
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("Nmap timeout must be a whole number of seconds.") from exc
    if not 10 <= timeout_seconds <= 600:
        raise ValueError("Nmap timeout must be between 10 and 600 seconds.")

    normalized_target = _validate_target(target)
    normalized_ports = _validate_ports(port_text)
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unsupported Nmap scan profile: {profile}")

    resolved_exe = validate_nmap_executable(executable)
    max_attempts = 1 + max(0, min(int(max_retries or 0), 2))
    profiles_to_try = [profile]
    if max_attempts > 1:
        for _ in range(max_attempts - 1):
            profiles_to_try.append("connect_only")

    last_error: NmapScanError | None = None
    total_duration = 0.0
    warnings: list[str] = []

    for attempt_idx, current_profile in enumerate(profiles_to_try, start=1):
        # Allocate a bounded per-attempt timeout so a stalled -sV probe fails over quickly to connect_only
        attempt_timeout = timeout_seconds if max_attempts == 1 else max(10, min(timeout_seconds, 25))
        if attempt_idx > 1:
            attempt_timeout = max(10, min(timeout_seconds, 30))

        cmd = build_nmap_command(
            resolved_exe,
            normalized_target,
            normalized_ports,
            profile=current_profile,
            connect_timeout_ms=connect_timeout_ms,
        )
        try:
            exit_code, stdout, stderr, elapsed = _run_nmap_process(cmd, attempt_timeout)
            total_duration += elapsed
        except NmapScanError as exc:
            total_duration += exc.duration_seconds
            last_error = exc
            if exc.retryable and attempt_idx < max_attempts:
                warnings.append(f"Attempt {attempt_idx} ({current_profile}) timed out after {exc.duration_seconds:.1f}s; retrying with fast connect_only profile.")
                continue
            raise

        if stderr.strip():
            for line in stderr.strip().splitlines():
                clean_line = line.strip()
                if clean_line and clean_line not in warnings:
                    warnings.append(clean_line[:240])

        # Parse valid XML even if exit_code != 0 (e.g., Npcap warning on Windows)
        if exit_code != 0 and "<nmaprun" not in stdout:
            err = _classify_nonzero_failure(exit_code, stderr, stdout, total_duration)
            if err.retryable and attempt_idx < max_attempts:
                warnings.append(f"Attempt {attempt_idx} ({current_profile}) timed out; retrying with fast connect_only profile.")
                last_error = err
                continue
            raise err

        try:
            parsed = parse_nmap_xml(stdout)
        except NmapScanError as xml_err:
            if exit_code != 0:
                raise _classify_nonzero_failure(exit_code, stderr, stdout, total_duration) from xml_err
            raise xml_err

        if exit_code != 0:
            warnings.append(f"Nmap exited with non-zero code {exit_code}, but produced a valid XML report.")

        if parsed["host_status"] == "down" and not parsed["open_ports"] and not parsed["closed_ports"]:
            raise NmapScanError(
                f"Target {normalized_target} is unreachable (host status: down).",
                category="target_unreachable",
                retryable=False,
                exit_code=exit_code,
                duration_seconds=total_duration,
                stderr=stderr,
            )

        result = {
            "target": normalized_target,
            "ports_checked": normalized_ports,
            "host_status": parsed["host_status"],
            "open_ports": parsed["open_ports"],
            "closed_ports": parsed["closed_ports"],
            "filtered_ports": parsed["filtered_ports"],
            "duration_seconds": round(total_duration, 3),
            "exit_code": exit_code,
            "profile": current_profile,
            "attempts": attempt_idx,
            "warnings": warnings,
            "executable": resolved_exe,
        }
        _initialize_table()
        with _db() as connection:
            connection.execute(
                "INSERT INTO asset_scans (scanned_at, target, ports_checked, host_status, open_ports, results_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().astimezone().isoformat(timespec="seconds"),
                    normalized_target,
                    normalized_ports,
                    parsed["host_status"],
                    len(parsed["open_ports"]),
                    json.dumps(result),
                ),
            )
        return result

    if last_error is not None:
        raise last_error
    raise NmapScanError("Nmap scan did not complete.", category="execution_error", retryable=False)


def get_asset_scan_history(limit: int = 10) -> list[dict[str, Any]]:
    _initialize_table()
    with _db() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT scanned_at, target, ports_checked, open_ports FROM asset_scans ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [dict(row) for row in rows]


def get_latest_asset_scan_result() -> dict[str, Any] | None:
    """Return the complete latest saved Nmap result for cross-rerun analysis."""
    _initialize_table()
    with _db() as connection:
        row = connection.execute(
            "SELECT results_json FROM asset_scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not row or not row[0]:
        return None
    try:
        result = json.loads(row[0])
    except (TypeError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None
