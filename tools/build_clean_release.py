"""Clean Release Packaging Script for VulnX.

Enforces strict exclusion of runtime databases, private HMAC keys, virtual environments,
caches, browser profiles, and temporary test artifacts.
"""
import os
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_ZIP = BASE_DIR / "Scanning_and_Vulnerability_Management_Platform_Final.zip"

EXCLUDE_DIRS = {
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".git", ".github", ".vulnx_protected", "scratch", "backups", "VulnX_Test_Evidence"
}

EXCLUDE_EXTENSIONS = {
    ".pyc", ".pyo", ".tmp", ".db", ".sqlite", ".sqlite3",
    ".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm",
    ".bak", ".backup", ".key", ".zip"
}

EXCLUDE_EXACT_FILES = {
    ".env", "audit_checkpoint.key", "audit_checkpoint.json"
}


def build_clean_release():
    print(f"Building clean release archive: {OUTPUT_ZIP.name}")
    if OUTPUT_ZIP.is_file():
        OUTPUT_ZIP.unlink()

    included_count = 0
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(BASE_DIR):
            # Prune excluded directories
            dirs[:] = [
                d for d in dirs
                if d not in EXCLUDE_DIRS and not d.startswith("backups_") and not d.startswith(".tmp")
            ]

            for file in sorted(files):
                filepath = Path(root) / file
                rel_path = filepath.relative_to(BASE_DIR)

                # Check extensions and exact filenames
                if filepath.suffix.lower() in EXCLUDE_EXTENSIONS:
                    continue
                if file in EXCLUDE_EXACT_FILES or file.endswith("_backup.db"):
                    continue
                if "audit_checkpoint.key" in file:
                    continue

                zipf.write(filepath, rel_path)
                included_count += 1

    size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"Clean release generated: {included_count} files, {size_mb:.2f} MB")
    return OUTPUT_ZIP, included_count, size_mb


if __name__ == "__main__":
    build_clean_release()
