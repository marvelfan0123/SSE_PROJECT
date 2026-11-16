# Baseline audit — VulnX V3 incremental repair

Source: `Scanning and Vulnerability Management Platform - Scoring Validation.zip`.

## Confirmed defects in original risk_model.py
- Threat calculation reverted to CVSS-only when either EPSS or KEV was missing, losing valid partial evidence.
- CVSS 9.8 could drop from 98 to 59.05 when low EPSS and non-KEV status were available.
- Mitigation factor could reduce contextual risk without an explicit verified mitigation flag.
- No distinct fully verified scoring-confidence branch.

## Scope of review
This is a targeted scoring-module audit, **not** a complete security audit of all application modules. Historical data migrations, centralized immutable snapshots, full UI simplification, real-world CVE accuracy benchmarking and live Trivy/Nmap/ZAP integration remain unverified/unimplemented in this increment.
