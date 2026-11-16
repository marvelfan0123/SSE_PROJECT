# Simplified Risk Prioritization Update

- Removed the multi-factor Asset Criticality Assessment interface and automatic assessment engine.
- Removed asset criticality from the risk formula and vulnerability findings table.
- Kept the Asset Inventory so discovered container images remain visible.
- Simplified risk calculation to NVD CVSS (or an explicitly labelled severity-derived proxy) multiplied by verified exposure weight.
- Kept Internal (1.0) and Exposed (1.5) exposure choices.
- Updated README and tests to reflect the simplified model.
- Existing SQLite database and scan reports are retained; historical asset-profile data is not deleted.
