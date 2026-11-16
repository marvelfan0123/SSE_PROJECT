> Historical note: this report-level implementation has been superseded by `UPDATE_NOTES_ASSET_LEVEL_CRITICALITY.md`, which introduces persistent per-image profiles.

# Asset Criticality Update

## What changed
- Corrected the report-level asset criticality weights so all four options are distinct and monotonic: Low 0.5, Medium 1.0, High 1.25, Critical 1.5.
- Added a dashboard comparison table that scores the same representative finding at all four criticality levels while holding exposure constant.
- Clarified in the dashboard that the selector currently applies to the entire selected Trivy report. It does not yet assign separate criticality values to individual Docker assets.
- Updated the README and risk-engine tests.

## Why
Previously, High and Critical both had a weight of 1.5, so choosing between those options did not change the score. The revised weights make each option produce a distinct score while keeping the existing maximum normalization value and priority bands unchanged.

## Validation
- Full automated test suite: 104 tests passed.
- Python compilation: `app.py` and `risk_engine.py` passed.
- Real-report check using `trivy-scan-python-3-12-slim.json`: a HIGH-severity finding (CVE-2026-76642) produced increasing contextual scores as criticality increased: Low 18, Medium 36, High 44, Critical 53 (severity-derived proxy because NVD CVSS was unavailable for this finding).

## Limitation
Criticality is still selected once per report. Asset-specific criticality mapping is not included in this update.
