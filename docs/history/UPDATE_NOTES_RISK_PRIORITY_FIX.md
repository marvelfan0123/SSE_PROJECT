# VulnX Risk Priority Threshold Fix

## Problem
The risk score was normalized using a maximum raw risk of 22.5, but the priority labels used thresholds of 90/75/50. Under medium/internal context, even a CVSS 10 finding can only score about 44/100, so high and critical findings were incorrectly labelled P4 - Low.

## Change
Priority thresholds now align with the normalized formula:
- P1 - Urgent: score >= 40
- P2 - High: score >= 30
- P3 - Moderate: score >= 20
- P4 - Low: score < 20

The dashboard explains these bands. Added regression tests verify critical severity proxies are not labelled low priority. Risk scores remain contextual prioritization estimates and do not prove exploitability.
