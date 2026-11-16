"""Phase 6 local deployment safeguards; not a replacement for an identity provider."""
from __future__ import annotations
import os
import re
import time
from collections import defaultdict
from threading import Lock

_LOCK = Lock()
_FAILURES = defaultdict(list)
_BLOCKED = {}
MAX_FAILURES = 5
WINDOW_SECONDS = 300
LOCK_SECONDS = 300
SECRET_PATTERN = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)")


def login_allowed(identity: str, now: float | None = None) -> bool:
    """Best-effort process-local login throttling for demo deployment."""
    key = str(identity or '').strip().casefold()[:120]
    now = time.monotonic() if now is None else now
    with _LOCK:
        if _BLOCKED.get(key, 0) > now:
            return False
        _BLOCKED.pop(key, None)
        _FAILURES[key] = [t for t in _FAILURES[key] if now - t < WINDOW_SECONDS]
        return True


def record_login_attempt(identity: str, success: bool, now: float | None = None) -> None:
    key = str(identity or '').strip().casefold()[:120]
    now = time.monotonic() if now is None else now
    with _LOCK:
        if success:
            _FAILURES.pop(key, None)
            _BLOCKED.pop(key, None)
        else:
            recent = [t for t in _FAILURES[key] if now - t < WINDOW_SECONDS]
            recent.append(now)
            _FAILURES[key] = recent
            if len(recent) >= MAX_FAILURES:
                _BLOCKED[key] = now + LOCK_SECONDS


def redact_audit_details(details, depth=0):
    """Redact sensitive field names recursively and limit depth/size."""
    if depth >= 6:
        return '[truncated]'
    if isinstance(details, dict):
        return {str(k)[:100]: ('[REDACTED]' if SECRET_PATTERN.search(str(k)) else redact_audit_details(v, depth + 1))
                for k, v in list(details.items())[:60]}
    if isinstance(details, (list, tuple)):
        return [redact_audit_details(v, depth + 1) for v in details[:60]]
    return str(details)[:1000] if not isinstance(details, (int, float, bool, type(None))) else details


def csv_cell(value) -> str:
    """Prevent spreadsheet formula execution when CSV is opened in Excel."""
    value = '' if value is None else str(value)
    if value.lstrip('\t\r\n ').startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def deployment_warnings():
    warnings = []
    if os.getenv('VULNX_DEMO_MODE', '1') != '0':
        warnings.append('Demo accounts are enabled; do not expose this service publicly.')
    if os.getenv('VULNX_ALLOW_PUBLIC_BIND') != '1':
        warnings.append('Bind Streamlit to 127.0.0.1 for local use; use TLS and external IAM for shared deployment.')
    warnings.append('SQLite and the audit trail are local, not tamper-proof or multi-node safe.')
    warnings.append('Login throttling is per Python process; use a reverse-proxy rate limiter for deployment.')
    return warnings
