"""Run OWASP ZAP passive baseline scans against the two local Docker lab apps.

The scanner runs in the official ZAP Docker image. Targets are deliberately
allow-listed to the local Juice Shop and DVWA services; arbitrary URLs are not
accepted. Baseline mode spiders the app and runs passive checks only. It does
not perform an active attack scan or modify the target application.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

ZAP_DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_TARGETS = {
    "OWASP Juice Shop": "http://host.docker.internal:3000/",
    "DVWA": "http://host.docker.internal:8081/",
}


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _safe_report_name(app_name: str, scanned_at: datetime) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-") or "web-app"
    return f"zap-{slug}-{scanned_at.strftime('%Y%m%d-%H%M%S')}.json"


def validate_zap_target(app_name: str) -> tuple[str, str]:
    """Return the fixed local-lab target; reject arbitrary hostnames and URLs."""
    if app_name not in ZAP_TARGETS:
        raise ValueError("Choose OWASP Juice Shop or DVWA from the configured local lab.")
    return app_name, ZAP_TARGETS[app_name]


def run_zap_baseline_scan(
    app_name: str,
    output_dir: str | Path,
    timeout_seconds: int = 900,
    max_spider_minutes: int = 3,
) -> dict:
    """Run ZAP's passive baseline scan in Docker and save its JSON report."""
    app_name, target_url = validate_zap_target(app_name)
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        raise ValueError("ZAP timeout must be a whole number of seconds.")
    if not 60 <= timeout_seconds <= 3600:
        raise ValueError("ZAP timeout must be between 60 and 3600 seconds.")
    executable = shutil.which("docker")
    if not executable:
        raise RuntimeError("Docker CLI was not found on PATH. Start Docker Desktop and restart the terminal/Streamlit.")
    if not 1 <= int(max_spider_minutes) <= 10:
        raise ValueError("Spider duration must be between 1 and 10 minutes.")

    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    scanned_at = datetime.now().astimezone()
    report_name = _safe_report_name(app_name, scanned_at)
    report_path = destination / report_name
    # Docker Desktop accepts forward-slash Windows paths with --mount.
    mount_source = destination.as_posix()
    command = [
        executable, "run", "--rm",
        "--mount", f"type=bind,source={mount_source},target=/zap/wrk",
        ZAP_DOCKER_IMAGE,
        "zap-baseline.py",
        "-t", target_url,
        "-J", report_name,
        "-I",
        "-m", str(int(max_spider_minutes)),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"OWASP ZAP scan exceeded the {timeout_seconds}-second time limit.") from error
    except OSError as error:
        raise RuntimeError(f"Could not start the Docker/ZAP scan: {error}") from error

    # ZAP baseline uses 0 for success, 1 for FAIL alerts, 2 for WARN alerts,
    # and 3 for an execution error. A valid report is useful for codes 0–2.
    if completed.returncode not in (0, 1, 2):
        detail = (completed.stderr or completed.stdout or "Docker/ZAP returned an unknown error.").strip()
        raise RuntimeError(f"OWASP ZAP scan failed (exit {completed.returncode}): {detail[-1400:]}")
    if not report_path.is_file():
        detail = (completed.stderr or completed.stdout or "No JSON report was generated.").strip()
        raise RuntimeError(f"OWASP ZAP did not create its JSON report. {detail[-1000:]}")
    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        report_path.unlink(missing_ok=True)
        raise RuntimeError(f"OWASP ZAP produced an unreadable JSON report: {error}") from error
    if not isinstance(report_data, dict) or not isinstance(report_data.get("site"), list):
        report_path.unlink(missing_ok=True)
        raise RuntimeError("OWASP ZAP report has an unexpected structure (expected a site array).")

    alert_count = sum(
        len(site.get("alerts") or [])
        for site in report_data["site"] if isinstance(site, dict)
    )
    return {
        "app_name": app_name,
        "target_url": target_url,
        "report_path": report_path,
        "report_name": report_name,
        "scanned_at": scanned_at.isoformat(timespec="seconds"),
        "alert_count": alert_count,
        "exit_code": completed.returncode,
        "stdout": (completed.stdout or "")[-3000:],
        "stderr": (completed.stderr or "")[-1500:],
    }


def load_zap_report(path: str | Path) -> dict:
    """Load and validate a ZAP JSON report from disk."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read ZAP JSON report: {error}") from error
    if not isinstance(data, dict) or not isinstance(data.get("site"), list):
        raise ValueError("This JSON file is not a ZAP report (expected a 'site' array).")
    return data
