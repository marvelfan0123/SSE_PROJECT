# Dashboard after-scan behavior

- The Dashboard remains accessible from the sidebar at all times.
- Before the first recorded Trivy, Nmap, or OWASP ZAP completion event, it shows a welcome/empty state and directs the user to Asset Discovery or Security Scanning instead of presenting bundled report data as completed scan results.
- After a scanner completes, the Dashboard displays the security summary and latest completed scan timestamp.
- The Trivy report selector defaults to the report recorded by the latest completed Trivy scan when that report is available. Users can still select another bundled/imported JSON report for review.
- Nmap and ZAP trigger a Streamlit rerun after successful completion so the Dashboard refreshes immediately.
- Scan readiness is derived from scanner-completion audit events; the presence of a JSON file alone does not count as a completed scan.


## Follow-up fix: stale Streamlit report selection

- The Trivy report selector now uses a widget key tied to the latest completed Trivy audit-event ID.
- When a newer Trivy scan completes, Streamlit creates a fresh selector state and defaults to that scan's report.
- Manual report selection remains available between scans.
- The Dashboard explicitly labels the Trivy report backing its metrics.
