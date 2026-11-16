import json
import tempfile
import unittest
from pathlib import Path

from report_loader import load_report


class ReportLoaderTests(unittest.TestCase):
    def test_loads_utf8_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text('{"Results": []}', encoding="utf-8")
            text, data = load_report(path)
        self.assertEqual(data, {"Results": []})
        self.assertEqual(json.loads(text), data)

    def test_loads_utf8_bom_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text('{"Results": []}', encoding="utf-8-sig")
            _, data = load_report(path)
        self.assertEqual(data, {"Results": []})

    def test_loads_utf16le_powershell_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text('{"Results": []}', encoding="utf-16")
            _, data = load_report(path)
        self.assertEqual(data, {"Results": []})

    def test_invalid_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text("not json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                load_report(path)


if __name__ == "__main__":
    unittest.main()
