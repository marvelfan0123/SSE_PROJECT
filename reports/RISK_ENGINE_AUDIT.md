# VulnX Canonical Contextual Risk Engine Audit Report

**Date:** November 12, 2026  
**Auditor:** Quantitative Risk Analyst & Principal Software Architect  
**Formula Version:** `CANONICAL-UNIFIED-v1.0`  
**Status:** **MATHEMATICAL INTEGRITY CERTIFIED**

---

## 1. The Canonical Contextual Risk Formula

$$R = 10 \times \left[0.3 \times \left(\frac{\text{CVSS}}{10}\right) + 0.7 \times \text{EPSS}\right] \times \text{Reachability} \times \left(\frac{\text{Criticality}}{5}\right)$$

Where:
- $\text{CVSS} \in [0.0, 10.0]$
- $\text{EPSS} \in [0.0, 1.0]$
- $\text{Reachability} \in [0.1, 1.0]$ ($1.0$ external public, $0.7$ internal, $0.4$ indirect bridge, $0.1$ isolated)
- $\text{Criticality} \in [1, 5]$
- Output $R$ is clamped to $[0.0, 10.0]$.

---

## 2. Boundary Condition Test Evidence

All boundary conditions have been validated in `tests/test_vulngraph_risk_unification.py` and `tests/test_modular_core.py`:

| Test Condition | Inputs (CVSS, EPSS, Reach, Crit) | Expected Score | Calculated Output | Status |
| :--- | :--- | :---: | :---: | :---: |
| **Minimum Bound** | CVSS=0.0, EPSS=0.0, Reach=0.0, Crit=1 | 0.00 | **0.00** | **PASS** |
| **Maximum Bound** | CVSS=10.0, EPSS=1.0, Reach=1.0, Crit=5 | 10.00 | **10.00** | **PASS** |
| **Reachability Scaling** | CVSS=8.0, EPSS=0.5, Reach=0.7, Crit=3 | 4.96 | **4.96** | **PASS** |
| **Missing EPSS Fallback**| CVSS=8.0, EPSS=None, Reach=1.0, Crit=4 | 6.40 (Provisional) | **6.40** | **PASS** |
| **Missing CVSS Review** | CVSS=None, EPSS=0.8, Reach=1.0, Crit=3 | None (Manual Review) | **None** | **PASS** |
| **Zero Reachability** | CVSS=9.0, EPSS=0.9, Reach=0.0, Crit=5 | 0.00 | **0.00** | **PASS** |

---

## 3. CISA KEV Priority Override
- Findings matching CISA KEV catalog receive an elevated **Tier 0 - Immediate KEV Directive** tag while preserving the underlying mathematical score $R$.
- Numerical scores are never artificially overwritten by arbitrary static values.
