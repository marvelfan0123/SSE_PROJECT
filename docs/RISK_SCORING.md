# VulnX Canonical Contextual Risk Engine Specification

## 1. The Canonical Risk Formula

VulnX prioritizes vulnerabilities based on real-world exploitability, network topology reachability, and business asset criticality:

$$\text{Risk Score} = 10 \times \left[0.3 \times \left(\frac{\text{CVSS}}{10}\right) + 0.7 \times \text{EPSS}\right] \times \text{Reachability} \times \left(\frac{\text{Criticality}}{5}\right)$$

The final score is mathematically clamped to $[0.0, 10.0]$.

---

## 2. Parameter Definitions & Value Ranges

### A. CVSS (0.0 to 10.0)
* Base vulnerability severity derived directly from NVD or scanner SBOM metadata.
* Represents intrinsic technical severity (Impact and Exploitability metrics).

### B. EPSS (0.00000 to 1.00000)
* Exploit Prediction Scoring System probability from **FIRST.org API**.
* Represents the empirical probability that a vulnerability will be actively exploited in the wild within the next 30 days.

### C. Reachability Factor (0.1 to 1.0)
Determined dynamically from Nmap port exposures and Docker network bindings:

| Network Reachability State | Factor Value | Description |
| :--- | :---: | :--- |
| **Externally Reachable** | `1.0` | Port is published on `0.0.0.0` or public interface; service confirmed running. |
| **Internally Reachable** | `0.7` | Service is reachable from internal corporate / RFC1918 subnets. |
| **Restricted / Indirect Path** | `0.4` | Container is on private Docker bridge with no direct external port published. |
| **Isolated / No Path** | `0.1` | No network route exists; local access only. |
| **Unknown Exposure** | `0.5` | Conservative default when topology discovery is inconclusive. |

### D. Asset Criticality (1 to 5)
Configured by system administrators to reflect business impact:
1. Low-impact development / sandbox asset
2. Standard internal tooling
3. Important business application
4. Critical production service (Customer-facing)
5. Mission-critical infrastructure / Financial data store

---

## 3. CISA KEV Priority Override (Tier 0 Directive)

A vulnerability listed in the **CISA Known Exploited Vulnerabilities (KEV) Catalog** receives elevated prioritization (**Tier 0 - Immediate KEV Directive**) regardless of whether its numerical contextual score is lower, reflecting active adversary weaponization in enterprise environments.

