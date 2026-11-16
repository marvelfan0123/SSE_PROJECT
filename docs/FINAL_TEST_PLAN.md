# Final Windows end-to-end acceptance plan (pending)

Complete this plan **after** all phases are implemented. Record screenshots, assessment IDs, timestamps and observed outputs.

- [ ] Clean Windows virtual environment; run offline regression suite and preflight.
- [ ] Streamlit launches, login succeeds and invalid login is rejected; check role restrictions for Admin, Analyst and Approver.
- [ ] Docker Desktop is running; local Juice Shop is reachable on localhost:3000.
- [ ] Authorized Nmap localhost scan shows port exposure, not an invented CVE.
- [ ] Trivy image scan produces normalized CVEs and retains scanner evidence.
- [ ] ZAP scans only approved local lab URL and stores alert evidence.
- [ ] Simulate a scanner failure/timeout; verify partial results, retry only failed scanner, and no duplicates.
- [ ] Compare contextual scores for the same CVE at Low and High confirmed asset criticality; inspect explanation and evidence.
- [ ] Verify correlation does not merge distinct assets/packages/versions.
- [ ] Create remediation ticket, assign owner, request approval, reject/approve, and verify RBAC.
- [ ] Complete rescan with comparable coverage; verify a finding cannot be marked resolved without evidence.
- [ ] Generate executive report, trends, CSV, JSON and HTML; verify counts, coverage warnings and CSV escaping.
- [ ] Restart app; verify persistence and audit entries without secrets.
- [ ] Create backup and verify its integrity; restore only to a **separate** test environment.
- [ ] Record known limitations and any failures; re-run full regression suite after fixes.

Do not mark the product production-ready on the strength of automated tests alone.
