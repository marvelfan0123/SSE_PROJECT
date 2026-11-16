# VulnX Phase 3 scoring repair — 2026-11-05

## Changes
- Trivy CVSS numeric score, vendor, version, and vector are preserved in normalized findings.
- Base vulnerability score is always computed when usable scanner CVSS or severity is available, independently of deployment exposure. Missing CVSS uses a labeled severity estimate; it is not presented as verified CVSS.
- Contextual risk remains unscored when deployment exposure is unknown. No exposure is fabricated.
- Findings and Risk Prioritization pages display base score and evidence provenance. Dashboard shows average base score and session-context recalculated risk separately from saved historical contextual risk.
- Phase 3 CSV includes base-score and CVSS provenance.
- Added tests for image-only triage, verified loopback scoring, CVSS preservation, invalid CVSS.

## How to test
1. Extract ZIP, install dependencies, and run `python -m unittest discover -s tests -p "test_*.py" -q`.
2. Launch Streamlit and open an existing completed Trivy assessment.
3. For undeployed node/python images, keep exposure `unknown`. Confirm base score and severity triage appear; contextual risk remains N/A by design.
4. For the *matching* running Juice Shop image bound to localhost, select `loopback` on Vulnerability Findings. Confirm contextual scores appear and dashboard's `Contextual Risk (selected context)` updates in the same session.
5. Previously normalized historical assessments may not contain Trivy's original CVSS provenance. Rescan to capture source CVSS; severity-based estimates remain available for old assessments.

## Known limits
- Context selection is session-scoped; raw scanner evidence is immutable and old saved risk values are not rewritten. A durable versioned risk snapshot remains a future enhancement.
- Scoring multipliers are a project-specific heuristic, not calibrated exploit probability.
- Automated tests passed in the build environment, not independently on the user's Windows Docker/Trivy installation.
