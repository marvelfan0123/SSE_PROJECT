# Validation results

- Unit tests: 77 passed (`python -m unittest discover -s tests -v`).
- Python compilation: passed for all top-level Python modules and tests.
- Docker lab tests cover inventory parsing, subprocess invocation without a shell, endpoint allow-listing, and service summary logic.
- The tests mock Docker and HTTP responses; they do not claim the live Docker Desktop environment was exercised here.
- Scan-comparison validation should be rerun on the user's actual report history before a demo.
