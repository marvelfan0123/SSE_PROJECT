# VulnX update: evidence-based asset criticality assessment

## What changed

- Newly discovered Trivy container-image assets start as **Unassigned**, not Medium.
- Added a four-factor business-impact assessment: data sensitivity, business importance, availability impact, and dependency impact.
- Each factor is scored from 1 (very limited impact) to 5 (severe impact).
- VulnX calculates a transparent average and suggests a level using project-defined thresholds:
  - 1.00–1.99: Low
  - 2.00–2.99: Medium
  - 3.00–3.99: High
  - 4.00–5.00: Critical
- An Admin/Analyst must confirm or deliberately override the suggestion. The app stores factor scores, suggestion, confirmed level, confirmation identity, environment, owner, notes, and timestamp.
- Confirmation/override is written to the audit log.
- Existing automatically-defaulted Medium records with no editor identity are migrated to Unassigned. Previously edited records retain their saved criticality.
- Unassigned assets use a neutral 1.0 multiplier only to produce a provisional risk score. The finding explicitly identifies the assessment as unassessed/provisional; it is not presented as a confirmed Medium classification.

## Important methodology note

The factor weights are equal and the thresholds are a transparent **VulnX project policy**, not an official industry standard. The assessment must be based on organizational knowledge and documented evidence. VulnX does not infer business importance from a Docker image name, CVE severity, open port, or environment label. Exposure remains a separate risk-engine input to avoid double-counting it in asset criticality.

## Where to use it

1. Open **Asset Discovery**.
2. Go to **Asset Criticality Assessment**.
3. Select a discovered Trivy container-image asset.
4. Score all four business-impact factors from 1 to 5.
5. Review the average and VulnX suggestion.
6. Confirm the suggestion or choose a justified override.
7. Save the assessment. Vulnerability Findings uses the confirmed criticality for findings associated with that image.

Assets not yet assessed remain Unassigned and their scores are marked provisional.

## Validation

- Automated tests: 116 passing.
- Python compilation: passed.
- Streamlit UI was not launched in this build environment because Streamlit is not installed here; run it locally using the project's requirements file.
