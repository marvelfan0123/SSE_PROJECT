"""Run Trivy image vulnerability scans and save machine-readable JSON reports.

The dashboard invokes the locally installed Trivy CLI directly. Commands are
passed as argument lists (never through a shell), image references are
validated, and the scan is limited to vulnerability detection.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

IMAGE_REFERENCE_RE = re.compile(
    r"^(?=.{1,255}$)[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$"
)
ALLOWED_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def validate_image_reference(image: str) -> str:
    """Validate a Docker/OCI image reference before passing it to Trivy."""
    image = (image or "").strip()
    if not image or not IMAGE_REFERENCE_RE.fullmatch(image):
        raise ValueError("Enter a valid Docker image reference, for example python:3.12-slim.")
    if image.startswith("-") or ".." in image or "://" in image or any(char.isspace() for char in image):
        raise ValueError("The image reference contains unsupported characters.")
    return image


def _safe_report_name(image: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", image).strip("-").lower()
    slug = (slug[:70] or "container-image").strip("-")
    return f"trivy-scan-{slug}.json"


def _is_docker_available() -> bool:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        res = subprocess.run([docker_bin, "--version"], capture_output=True, timeout=5, check=False)
        return res.returncode == 0
    except Exception:
        return False


def _run_docker_trivy(
    image: str,
    selected: list[str],
    include_unfixed: bool,
    timeout_seconds: int,
    temporary_path: Path,
) -> subprocess.CompletedProcess:
    docker_bin = shutil.which("docker") or "docker"
    cmd = [
        docker_bin, "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "trivy_cache:/root/.cache/",
        "aquasec/trivy:latest",
        "image",
        "--quiet",
        "--scanners", "vuln",
        "--format", "json",
        "--severity", ",".join(selected),
    ]
    if not include_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(image)

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        temporary_path.unlink(missing_ok=True)
        raise RuntimeError(f"Trivy scan exceeded the {timeout_seconds}-second time limit.") from error
    except OSError as error:
        temporary_path.unlink(missing_ok=True)
        raise RuntimeError(f"Could not start Docker-based Trivy: {error}") from error

    if completed.returncode != 0:
        temporary_path.unlink(missing_ok=True)
        detail = (completed.stderr or completed.stdout or "Docker Trivy returned an unknown error.").strip()
        raise RuntimeError(f"Trivy scan failed: {detail[-1200:]}")

    temporary_path.write_text(completed.stdout or "{}", encoding="utf-8")
    return completed


def run_trivy_image_scan(
    image: str,
    output_dir: str | Path,
    severities: list[str] | tuple[str, ...] | None = None,
    include_unfixed: bool = True,
    timeout_seconds: int = 1800,
) -> dict:
    """Run `trivy image` and return report metadata.

    Supports both local native Trivy CLI and Docker-based containerized Trivy.
    Automatically falls back to Docker-based Trivy if native Trivy is blocked
    by host security controls (such as Windows Application Control policy WinError 4551).
    """
    image = validate_image_reference(image)
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        raise ValueError("Trivy timeout must be a whole number of seconds.")
    if not 30 <= timeout_seconds <= 3600:
        raise ValueError("Trivy timeout must be between 30 and 3600 seconds.")

    selected = list(severities or ALLOWED_SEVERITIES)
    selected = [str(value).upper() for value in selected]
    if not selected or any(value not in ALLOWED_SEVERITIES for value in selected):
        raise ValueError("Choose one or more valid Trivy severity levels.")

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / _safe_report_name(image)
    temporary_path = report_path.with_suffix(".json.tmp")

    executable = shutil.which("trivy")
    if not executable:
        if _is_docker_available():
            completed = _run_docker_trivy(
                image=image,
                selected=selected,
                include_unfixed=include_unfixed,
                timeout_seconds=timeout_seconds,
                temporary_path=temporary_path,
            )
        else:
            raise RuntimeError(
                "Trivy CLI was not found on PATH. Install Trivy, restart the terminal/Streamlit, and try again."
            )
    else:
        command = [
            executable, "image", "--scanners", "vuln", "--format", "json",
            "--output", str(temporary_path), "--severity", ",".join(selected),
        ]
        if not include_unfixed:
            command.append("--ignore-unfixed")
        command.append(image)

        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as error:
            temporary_path.unlink(missing_ok=True)
            raise RuntimeError(f"Trivy scan exceeded the {timeout_seconds}-second time limit.") from error
        except OSError as error:
            if _is_docker_available():
                completed = _run_docker_trivy(
                    image=image,
                    selected=selected,
                    include_unfixed=include_unfixed,
                    timeout_seconds=timeout_seconds,
                    temporary_path=temporary_path,
                )
            else:
                temporary_path.unlink(missing_ok=True)
                raise RuntimeError(f"Could not start Trivy: {error}") from error

        if completed.returncode != 0:
            if _is_docker_available():
                completed = _run_docker_trivy(
                    image=image,
                    selected=selected,
                    include_unfixed=include_unfixed,
                    timeout_seconds=timeout_seconds,
                    temporary_path=temporary_path,
                )
            else:
                temporary_path.unlink(missing_ok=True)
                detail = (completed.stderr or completed.stdout or "Trivy returned an unknown error.").strip()
                raise RuntimeError(f"Trivy scan failed: {detail[-1200:]}")

    try:
        report_text = temporary_path.read_text(encoding="utf-8-sig")
        report_data = json.loads(report_text)
        if not isinstance(report_data, dict) or "Results" not in report_data or not isinstance(report_data.get("Results"), list):
            raise ValueError("Trivy output did not contain the expected Results array.")
        # Replace the prior report only after a successful scan and JSON validation.
        temporary_path.replace(report_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        temporary_path.unlink(missing_ok=True)
        raise RuntimeError(f"Trivy produced an invalid report: {error}") from error

    vulnerability_count = sum(
        len(result.get("Vulnerabilities") or [])
        for result in report_data.get("Results", [])
        if isinstance(result, dict)
    )
    return {
        "image": image,
        "report_path": report_path,
        "report_name": report_path.name,
        "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "vulnerability_count": vulnerability_count,
        "severity_filter": selected,
        "include_unfixed": bool(include_unfixed),
        "stdout": (completed.stdout or "")[-2000:],
    }
