# VulnX Repair Notes — Docker Lab Runtime Crash

## Fixes
- `docker_lab.list_containers()` now decodes subprocess output explicitly as UTF-8 with replacement for invalid bytes. This avoids Windows CP1252 reader-thread `UnicodeDecodeError` crashes when Docker CLI output contains unsupported characters.
- `_parse_container_lines()` now safely handles `None`, byte strings, and unexpected output types instead of calling `.splitlines()` on `None`.
- Docker error output is normalized to a string before formatting.
- Added regression tests for missing output, byte output, and explicit safe decoding settings.

## Validation
- `python -m unittest discover -s tests -v`: 79 tests passed.
- Compiled all 30 Python source/test files successfully.
- The live Streamlit dashboard and Docker Desktop were not launched in this environment; please verify on the Windows machine.

## Apply
Extract this ZIP to a new folder and run:
```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```
