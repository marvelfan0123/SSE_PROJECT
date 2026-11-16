# UI Cleanup and Navigation Update

- Removed the standalone **Selected image** metric/card from the main findings summary. Image-to-asset association remains in the data pipeline so findings retain their asset identity.
- Removed the manual **Verified exposure level** selector. The UI no longer asks users to assert external exposure manually. The existing risk engine baseline remains in effect unless a future evidence-backed exposure integration is implemented.
- Reorganized sidebar navigation into Overview, Scanning, Vulnerability Management, Analysis, and Administration groups.
- Kept all existing pages, scanner integrations, database tables, reports, and remediation workflows.
- Validation: `python -m py_compile app.py` passed; `python -m unittest discover -s tests -v` passed (119 tests).
