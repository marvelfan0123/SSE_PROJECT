"""Package VulnX into a clean distribution ZIP archive."""
import os
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_ZIP = BASE_DIR / "Scanning_and_Vulnerability_Management_Platform_Final.zip"

EXCLUDE_DIRS = {".venv", "__pycache__", ".pytest_cache", ".git", ".github"}
EXCLUDE_EXTS = {".pyc", ".pyo", ".tmp"}

def create_archive():
    print(f"Creating release archive: {OUTPUT_ZIP}")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(BASE_DIR):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith("backups_")]
            
            for file in files:
                filepath = Path(root) / file
                if filepath.suffix in EXCLUDE_EXTS:
                    continue
                if file.endswith(".zip") or file.endswith("_backup.db"):
                    continue
                
                arcname = filepath.relative_to(BASE_DIR)
                zipf.write(filepath, arcname)

    size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"Archive created successfully: {size_mb:.2f} MB")

if __name__ == "__main__":
    create_archive()

