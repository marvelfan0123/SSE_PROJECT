# Asset-Level Criticality Management Update

## What changed
- Added `asset_criticality.py`, a SQLite-backed asset profile registry using the existing `scan_history.db` database.
- Automatically discovers logical container-image assets from the `ArtifactName` and metadata in available Trivy JSON reports.
- Assigns a stable VulnX asset ID to each logical image reference.
- Added an Asset Criticality Management section to the Asset Discovery page.
- Admin and Analyst roles can set Low/Medium/High/Critical criticality, environment, owner/team, and business-impact notes. Approver can view profiles but cannot edit them.
- Image metadata is refreshed on later report discovery without overwriting manually assigned criticality, environment, owner, or notes.
- Trivy findings now carry the image asset ID/name, and `risk_engine.prioritize_findings` uses the saved criticality for each finding's asset ID.
- Preserved the previous `asset_criticality` argument as a backward-compatible fallback for findings without an asset mapping.
- Added tests for image discovery, profile persistence, validation, criticality mapping, and per-asset risk scoring.

## How to use
1. Start the app and sign in as Admin or Analyst.
2. Open **Asset Discovery**.
3. Scroll to **Asset Criticality Management**.
4. Choose a discovered container image and set its criticality, environment, owner/team, and business-impact notes.
5. Save the profile.
6. Open **Vulnerability Findings** and select a report for that image. Its saved criticality is displayed and used automatically in the risk score.
7. Select another report for a different image to see that its own profile is applied.

## Important scope notes
- This version manages criticality per logical Trivy container-image asset, keyed from the report's image reference. It does not yet distinguish multiple running container instances created from the same image.
- Environment and owner are recorded for business context but do not currently change the risk formula.
- Nmap open-port observations remain distinct from Trivy package vulnerabilities and are not assigned a Trivy CVE risk score by this feature.
- Criticality weights (Low 0.5, Medium 1.0, High 1.25, Critical 1.5) are project-defined assumptions and should be justified/evaluated, not described as an official standard.
- The existing SQLite database is retained; the new profile table is created additively on first use.

## Validation
- Full unit test suite: 109 tests passed.
- Python compilation: all project Python files passed.
- Per-asset risk-engine test confirms the same CVSS finding receives different scores when associated with assets of different criticality.
- Profile persistence test confirms that rediscovering an image does not reset user-assigned business context.
- Streamlit UI runtime was not executed in this build environment because Streamlit is not installed here; run the app locally to verify the interactive UI.
