"""Read Trivy JSON reports with common Windows and Unix text encodings."""
from pathlib import Path
import json


def read_report_text(path):
    """Read a report as text, detecting UTF-16 BOMs and UTF-8 (with/without BOM).

    PowerShell redirection can produce UTF-16LE files on Windows, while Trivy's
    native JSON output is typically UTF-8. Normalize both to a Python string.
    """
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def load_report(path):
    """Return (text, parsed_json) for a UTF-8/UTF-16 JSON report."""
    text = read_report_text(path)
    return text, json.loads(text)
