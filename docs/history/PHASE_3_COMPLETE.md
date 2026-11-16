# VulnX — Phase 3: Vulnerability Analysis and Contextual Prioritization

## Build baseline
Phase 2 Iteration 4, including the Windows SQLite cleanup fix.

## Iteration 1 — Findings and normalization
- Uses persisted assessment findings and existing scanner normalization.
- Keeps network exposure observations separate from scored vulnerabilities.
- Uses the existing conservative `finding_correlation.py` identity rules.

## Iteration 2 — Contextual risk prioritization
- Added `phase3_analysis.py`, using the existing assessment `risk_model.py`.
- Supports explicitly selected exposure context: unknown, loopback, internal, all_interfaces.
- Supports Low / Normal / High business criticality.
- Explains each scored finding using base severity/CVSS, exposure and criticality factors.
- Unknown exposure remains unscored; network observations never receive a vulnerability risk score.
- Changing view context does **not** overwrite persisted assessment results.

## Iteration 3 — Analysis presentation and exports
- Updated Risk Prioritization page with context controls, sortable findings, explanation, correlation summary, and CSV/JSON downloads.
- Existing remediation guidance and human approval / verification workflow retained.
- Existing optional NVD enrichment module retained; this Phase 3 page does not make live NVD requests.
- No EPSS, CISA KEV, automatic exploitation, or verified remediation claim.

## Iteration 4 — Regression validation
- Added seven targeted Phase 3 tests (context sensitivity, missing evidence, observation separation, no mutation, correlation, exports, invalid context).
- Entire automated suite: **204 tests passed** in the build environment.
- Python compilation passed.
- Windows Streamlit UI, live scanner operations, and real-world remediation verification **not tested in this environment**.

## How to run on Windows
```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
python -m streamlit run app.py
```
Open an existing completed assessment, then navigate to **Risk Prioritization**. Choose an evidence-supported exposure and business criticality. Compare risk scores for Low and High criticality, inspect the explanation, and export CSV/JSON.

## Important limitations
- The selected context is user-provided and not independently verified.
- Risk scores prioritize attention; they do not prove exploitability or impact.
- Severity proxies are not a substitute for verified CVSS.
- Deduplication is conservative and does not merge ambiguous web findings automatically.
- No findings is not evidence that the target is secure.
- Re-test the latest ZIP on Windows and with authorized local Docker labs before declaring the overall project fully validated.
