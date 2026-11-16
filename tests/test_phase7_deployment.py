import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deployment_tools import backup_database, preflight


class DeploymentToolsTests(unittest.TestCase):
    def test_preflight_missing_project_files(self):
        with tempfile.TemporaryDirectory() as directory:
            result = preflight(project_root=Path(directory), tool_lookup=lambda _: None)
            self.assertFalse(result['ready_for_ui'])
            self.assertFalse(result['scanners']['docker']['installed_on_path'])

    def test_preflight_scanners_are_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').touch()
            (root / 'requirements.txt').touch()
            with patch('deployment_tools.importlib.util.find_spec', return_value=object()):
                result = preflight(project_root=root, tool_lookup=lambda _: None, python_version=(3, 11))
            self.assertTrue(result['ready_for_ui'])

    def test_preflight_rejects_old_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').touch()
            (root / 'requirements.txt').touch()
            with patch('deployment_tools.importlib.util.find_spec', return_value=object()):
                result = preflight(project_root=root, python_version=(3, 9))
            self.assertFalse(result['ready_for_ui'])

    def test_backup_copies_committed_data(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'source.db', Path(directory) / 'backup.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE samples (value TEXT)')
                db.execute('INSERT INTO samples VALUES (?)', ('hello',))
                db.commit()
            backup_database(source, target)
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(db.execute('SELECT value FROM samples').fetchone()[0], 'hello')

    def test_backup_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'source.db', Path(directory) / 'backup.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE samples (value TEXT)')
            target.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                backup_database(source, target)
            self.assertEqual(target.read_bytes(), b'keep')

    def test_backup_refuses_same_path(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE samples (value TEXT)')
            with self.assertRaises(ValueError):
                backup_database(source, source)

    def test_backup_missing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                backup_database(Path(directory) / 'missing.db', Path(directory) / 'out.db')


if __name__ == '__main__':
    unittest.main()
