# Review changes (Oct 2026)

- remediation.py / remediation_guidance.py: approval, Pass/N-A evidence and Resolved rules are now enforced in the backend, not only the UI. Fixes item #11 (Pass saved with empty evidence while status was Approved).
- app.py: warns on legacy items with Pass but no evidence; "Scanned At" relabelled "Imported At" (it is when VulnX first saw the file, not when Trivy ran); non-Trivy JSON no longer crashes the app.
- risk_engine.py: ties broken by real severity rank (was alphabetical) and made deterministic.
- asset_discovery.py: SQLite handles now closed (Windows locking); non-ASCII digits rejected cleanly; -6 added for IPv6 targets.
- nvd_enrichment.py: batch stops on HTTP 429 instead of burning the rest of the batch; remaining count corrected.
- finding_normalization.py: tolerates non-object JSON.
- requirements.txt: streamlit>=1.50 (code uses width="stretch").
- attack_path_analysis.py: arbitrary short text (for example, `okaok`) no longer upgrades a candidate path to Medium confidence; relationship evidence must be sufficiently descriptive and contain a technical evidence term. This is a quality gate, not proof of truth.
- tests: 46 -> 57, all passing after the evidence-quality regression tests.

- report_loader.py / app.py: Trivy reports now load from UTF-8 (with or without BOM) and UTF-16 BOM files. This fixes Windows PowerShell redirection reports that begin with `FF FE` and previously caused `UnicodeDecodeError`.
- tests/test_report_loader.py: added regression coverage for UTF-8, UTF-8 BOM, UTF-16 BOM, and malformed JSON handling.
- Validation after this change: 61 unit tests pass; 23 Python source files compile; scan-comparison validation passes (105 persistent findings for the bundled Juice Shop reports, plus a controlled 1-new/1-persistent/1-no-longer-detected fixture).

- Updated risk prioritization to CVSS × criticality weight × exposure weight, with an explicit severity-proxy fallback when NVD CVSS is unavailable. Added a manual verified-exposure selector and documented normalized 0–100 scoring.

## Attack-path visualization update

- Added `build_attack_path_graphviz()` to render the existing evidence-based candidate paths as a Graphviz DOT diagram.
- Added a graph to the Streamlit attack-path section, while retaining the detailed evidence table and CSV export.
- Edge colors reflect the existing High/Medium/Low evidence-confidence label only; they do not represent exploit probability. The existing caveat that paths are candidates, not confirmed attacks, remains visible.
- Added tests for graph contents, quote escaping, and empty input.

- risk_engine.py: corrected priority thresholds to match the 0-100 normalization denominator; previous thresholds made medium/internal critical findings P4. Added regression coverage and visible threshold explanation. See UPDATE_NOTES_RISK_PRIORITY_FIX.md.

- Docker lab integration: force UTF-8 subprocess decoding with replacement and safely handle missing output to prevent Windows console-encoding crashes.
- 2026-10-26: Remediation verification selector now defaults to the record's saved verification status rather than always selecting “Not verified”.
