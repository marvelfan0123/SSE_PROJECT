# KNOWN LIMITATIONS & OPERATIONAL BOUNDARIES

**Official Project Name:** Scanning and Vulnerability Management Platform  
**Product Branding:** VulnX  

---

## 1. External Scanner & Daemon Dependencies

1. **Docker Desktop Daemon Requirement for Container Inspection & OWASP ZAP:**
   - Live container runtime inspection (`docker inspect`) and containerized OWASP ZAP baseline scanning (`ghcr.io/zaproxy/zaproxy:stable`) require the **Docker Desktop Engine** daemon (`//./pipe/dockerDesktopLinuxEngine`) to be running on the host machine.
   - When the Docker CLI binary is installed on `PATH` but the Docker Desktop daemon is stopped, VulnX detects and reports **`Daemon Offline`** / **`Requires Docker Daemon`** in the **Scanner & Runtime Health** telemetry panel and records the exact daemon diagnostic message rather than fabricating scan results.

2. **Network Connectivity for Live Trivy Image Pulls & Threat Intelligence APIs:**
   - Live `trivy image` scans of uncached remote images require outbound registry access and Trivy vulnerability database connectivity.
   - When operating in an air-gapped or restricted environment, operators can use **Import Scanner JSON Report (Trivy)** in Step 1 of the **Security Assessment** wizard to ingest real `trivy image --format json` outputs through the full normalization, OWASP Top 10:2025 classification, and canonical 0–10 contextual risk pipeline.
   - Live FIRST.org EPSS and NVD API lookups are opt-in via `VULNX_THREAT_ENRICHMENT=1` (or `VULNGRAPH_THREAT_ENRICHMENT=1`). When offline or unenriched, the canonical risk engine transparently applies its documented CVSS-only fallback (`status = "Provisional"`).

3. **Authorized Target Scope Enforcement:**
   - Network discovery (`Nmap`) and web baseline scanning (`OWASP ZAP`) enforce target validation (`assessment_portal.py`) restricting scans to authorized loopback, RFC1918 private network, or local lab endpoints.
