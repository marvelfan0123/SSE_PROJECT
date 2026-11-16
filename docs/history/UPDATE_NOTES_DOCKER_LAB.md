# VulnX update: Docker lab integration

## Added
- Read-only Docker CLI inventory using `docker ps -a --format '{{json .}}'`.
- Local HTTP reachability checks for the configured Juice Shop and DVWA loopback endpoints only.
- Dashboard summary of container count, running count, expected service presence, and HTTP status.
- Audit event when the dashboard checks Docker lab status.
- Unit tests for parsing, safe subprocess invocation, URL allow-listing, and summary behavior.

## Safety and interpretation
- The feature never starts/stops/removes containers or runs a shell command.
- HTTP checks are limited to `http://127.0.0.1:3000/` and `http://127.0.0.1:8081/`.
- HTTP reachability is not evidence that an application is secure or vulnerable.
- This status integration does not replace Trivy image scanning or Nmap service discovery.

## Validation
- `python -m unittest discover -s tests -v`: 77 tests passed.
- Python source compilation: passed.
- Interactive Windows/Streamlit launch still needs verification on the user's computer.
