# VulnX Threat Intelligence Integration Audit Report

**Date:** November 12, 2026  
**Auditor:** Vulnerability Intelligence Specialist  
**Status:** **VERIFIED (LIVE LOOKUP + LOCAL CACHING)**

---

## 1. Threat Intelligence Coverage

| Feed Source | Integration Endpoint | Query Mechanism | Caching Strategy | Provenance Status |
| :--- | :--- | :--- | :--- | :---: |
| **FIRST.org EPSS** | `https://api.first.org/data/v1/epss` | Batch queries (up to 100 CVEs/batch) | Atomic write to `data/threat_intelligence_cache.json` (24h TTL) | **LIVE / CACHED** |
| **CISA KEV Catalog**| `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` | Catalog ingest & JSON parsing | Local mirror cache in `data/` | **LIVE / CACHED** |
| **NVD CVSS** | National Vulnerability Database API | On-demand CVE lookup | SQLite cache table `assessment_nvd_cache` | **CACHED** |

---

## 2. Integrity & Resilience Verification

1. **EPSS Probability Representation:**
   - Values are strictly bounded in $[0.00000, 1.00000]$.
   - Percentiles and probabilities are tracked as distinct metrics.
2. **Missing Intelligence Fallback:**
   - If an unknown CVE is queried or the network is air-gapped, status is explicitly recorded as `Unavailable`.
   - The platform never fabricates or hallucinates an EPSS score.
3. **CISA KEV Matching:**
   - CVE membership is matched directly against official catalog records.
   - Identified KEV findings trigger Tier 0 priority overrides in the contextual risk engine.
