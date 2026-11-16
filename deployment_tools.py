"""Offline deployment checks and consistent SQLite backups for local VulnX."""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
SCANNERS = {'nmap': 'nmap', 'trivy': 'trivy', 'docker': 'docker'}


def preflight(*, project_root: Path = ROOT, tool_lookup=shutil.which, python_version=None) -> dict:
    """Read-only checks; no scanner launch, DB initialization or network traffic."""
    root = Path(project_root)
    version = python_version or sys.version_info
    results = {
        'python': {'ok': tuple(version[:2]) >= (3, 10), 'version': f'{version[0]}.{version[1]}'},
        'app': {'ok': (root / 'app.py').is_file()},
        'requirements': {'ok': (root / 'requirements.txt').is_file()},
        'streamlit': {'ok': importlib.util.find_spec('streamlit') is not None},
        'scanners': {name: {'installed_on_path': bool(tool_lookup(command)), 'optional': True}
                     for name, command in SCANNERS.items()},
    }
    # Do not print environment variable contents or credentials.
    results['ready_for_ui'] = all(results[key]['ok'] for key in ('python', 'app', 'requirements', 'streamlit'))
    results['note'] = 'Scanner presence does not verify Docker daemon availability or live scan success.'
    return results


def backup_database(source: str | Path, destination: str | Path) -> Path:
    """Make a transactionally consistent snapshot, including committed WAL data."""
    src = Path(source).expanduser().resolve()
    dst = Path(destination).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f'Database does not exist: {src}')
    if src == dst:
        raise ValueError('Backup destination must differ from source')
    if dst.exists():
        raise FileExistsError(f'Refusing to overwrite existing backup: {dst}')
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with closing(sqlite3.connect(f'{src.as_uri()}?mode=ro', uri=True)) as source_connection:
            with closing(sqlite3.connect(str(dst))) as backup_connection:
                source_connection.backup(backup_connection)
                integrity = backup_connection.execute('PRAGMA integrity_check').fetchone()[0]
                if integrity != 'ok':
                    raise RuntimeError('Backup integrity check failed')
    except Exception:
        dst.unlink(missing_ok=True)
        raise
    return dst


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='VulnX local deployment utilities')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('preflight', help='Read-only environment check')
    backup = sub.add_parser('backup', help='Consistent, non-overwriting SQLite backup')
    backup.add_argument('--database', default=os.getenv('VULNX_DATABASE_PATH', str(ROOT / 'scan_history.db')))
    backup.add_argument('--output', help='Destination .db path (default timestamped backups folder)')
    args = parser.parse_args(argv)
    if args.command == 'preflight':
        result = preflight()
        print(json.dumps(result, indent=2))
        return 0 if result['ready_for_ui'] else 1
    output = args.output or str(ROOT / 'backups' / ('vulnx_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.db'))
    result = backup_database(args.database, output)
    print(f'Backup created: {result}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
