# VulnX — Windows installation and launch

1. Extract the final ZIP to a folder you control. Open PowerShell **inside the folder containing `app.py`**.
2. Install Python 3.11+ and ensure `python --version` works. Recommended: use a new virtual environment, not one copied from another machine.
3. Run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python deployment_tools.py preflight
python -m unittest discover -s tests -p 'test_*.py' -v
python -m streamlit run app.py
```

4. Open `http://localhost:8501` (not a public URL). For scanning, install Docker Desktop, Nmap and Trivy and verify `docker info`, `nmap --version`, `trivy --version` independently.
5. Keep `.env` private; use `.env.example` as a reference. If upgrading an existing installation, **back up the database before replacing files**:

```powershell
python deployment_tools.py backup --database .\scan_history.db --output .\backups\before_upgrade.db
```

Run the backup command only if the database already exists. Do not replace your current database with the sample or an empty database.

**Safety:** Only scan owned/authorized lab targets. Do not expose the demonstration Streamlit server to the internet; the demo authentication and process-local rate limiting are not suitable for production.
