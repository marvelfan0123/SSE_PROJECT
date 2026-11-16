# VulnX Phase 5 — Reporting, Analytics and Executive Dashboard

Built on the complete Phase 4 project; prior functionality retained.

## Iteration 1 — Assessment analytics
- Assessment-scoped metrics, vulnerability severity distribution, distinct exposure observations, assets, average risk and unscored counts.
- Unscored risk is displayed as N/A, never misleading zero.

## Iteration 2 — Executive reporting
- New Reports page with KPI cards, severity chart, scanner coverage, remediation status and highest-risk findings.
- Printable self-contained HTML executive report, escaping untrusted scanner text.

## Iteration 3 — Historical trends
- Chronological trend table/chart for the *same named and typed target* among assessments visible to the signed-in user.
- Running/failed scans excluded; partial coverage clearly marked.
- Historical count changes are **not** proof of verified remediation; target names alone do not establish equivalent scope.

## Iteration 4 — Exports and regression
- Versioned JSON analytics report, top-findings CSV, trend CSV and printable HTML.
- CSV formula injection mitigated for scanner-controlled text.
- Eleven new tests cover report correctness, scoping, partial coverage, escaping, exports and empty cases.

## Limitations
- Reports are derived from saved scanner evidence, not fresh live scans.
- HTML is printable to PDF via browser; no server-side PDF export in this phase.
- Highest-priority findings CSV is limited to top 20 (as labeled), not a complete finding export. Full findings CSV remains available in Vulnerability Findings.
- Scanner coverage and target identity must be reviewed before comparing counts.
- Local-demo authentication and SQLite are not production-ready for untrusted deployments.
- Windows/Docker/Nmap/Trivy/ZAP live testing deferred to final integration phase as requested.

## Run automated tests
`python -m unittest discover -s tests -p "test_*.py" -v`
