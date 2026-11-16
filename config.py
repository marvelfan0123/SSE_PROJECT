"""Central configuration loader. Loads project .env before DB/scanner modules initialize."""
from __future__ import annotations
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def load_environment(env_path: str | Path | None = None) -> None:
    path = Path(env_path) if env_path else BASE_DIR / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_environment()


PROTECTED_DIR = BASE_DIR / ".vulnx_protected"


def ensure_audit_checkpoint_config() -> None:
    """Make sure the audit checkpoint key/file are configured without any hardcoded secret.

    If the operator did not provide VULNGRAPH_AUDIT_CHECKPOINT_KEY (or AUDIT_CHECKPOINT_SECRET)
    a random 256-bit key is generated once and persisted in an untracked, protected
    directory so it survives restarts. The checkpoint file defaults to the same protected
    directory, which is outside assessment_reports/ and therefore never touched by Reset.
    """
    import secrets

    if not (os.environ.get("VULNGRAPH_AUDIT_CHECKPOINT_KEY") or os.environ.get("AUDIT_CHECKPOINT_SECRET")):
        key_file = PROTECTED_DIR / "audit_checkpoint.key"
        key = ""
        try:
            if key_file.is_file():
                key = key_file.read_text(encoding="utf-8").strip()
        except OSError:
            key = ""
        if len(key) < 32:
            key = secrets.token_hex(32)
            PROTECTED_DIR.mkdir(parents=True, exist_ok=True)
            key_file.write_text(key, encoding="utf-8")
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
        os.environ["VULNGRAPH_AUDIT_CHECKPOINT_KEY"] = key
    if not os.environ.get("VULNGRAPH_AUDIT_CHECKPOINT_FILE"):
        os.environ["VULNGRAPH_AUDIT_CHECKPOINT_FILE"] = str(PROTECTED_DIR / "audit_checkpoint.json")
