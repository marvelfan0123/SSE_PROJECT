# Phase 1 restored target selection and dashboard

Restores custom **Local host** IP and TCP port inputs, plus custom **Local web application** URL input, from the Fixed Custom Targets release.

Adds dashboard exposure observations counter and N/A when no scored vulnerabilities exist.

Local host testing: select Local host, enter 127.0.0.1 and 3000,8081, run Nmap.

For web lab testing: select Local web application and http://localhost:3000/, then run ZAP.

Only scan authorized assets. Existing user database/scan history should be backed up before replacing project files.
