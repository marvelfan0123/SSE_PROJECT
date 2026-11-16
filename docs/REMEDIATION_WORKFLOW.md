# VulnX Maker-Checker Remediation Governance Workflow

## 1. Compliance Mandates (SOC 2, ISO 27001, PCI-DSS)

Enterprise compliance standards legally prohibit unmonitored or autonomous patching of production infrastructure:
- **PCI-DSS (Req 6.4):** Requires formal change control procedures and independent authorization before applying security updates.
- **SOC 2 (Criteria CC6.8 / CC7.2):** Mandates separation of duties (no single entity can propose and deploy changes without oversight).
- **ISO 27001 (Control A.8.32):** Requires documented change management sign-offs.

VulnX implements this through an automated, cryptographically audited **Maker-Checker State Machine**.

---

## 2. Ticket State Lifecycle

```
[ OPEN ] ──▶ [ PENDING APPROVAL ] ──▶ [ APPROVED ] ──▶ [ IN PROGRESS ] ──▶ [ READY FOR RESCAN ] ──▶ [ RESOLVED ]
     │                │                     │                                                            ▲
     ▼                ▼                     ▼                                                            │
 [ REJECTED ] ◀───────┴─────────────────────┴────────────────────────────────────────────────────────────┤
                                                                                                         │
                                                           Requires Proof of Scanner Absence ────────────┘
```

1. **OPEN:** Finding identified by scanner; eligible for remediation work.
2. **PENDING APPROVAL:** The Security Analyst (Maker) has tested the fix in staging and submitted the proposed change with staging logs.
3. **APPROVED:** An independent Approver (Checker) has reviewed the change impact and authorized the maintenance window.
4. **REJECTED:** Approver rejected the proposal with mandatory written justification.
5. **IN PROGRESS:** DevOps / infrastructure team is deploying the patch to the target asset.
6. **READY FOR RESCAN:** Deployment is complete; asset is flagged for automated rescan verification.
7. **RESOLVED:** A subsequent assessment confirmed that the vulnerability is absent on the target.

---

## 3. Separation of Duties (Maker-Checker Backend Guardrail)

```python
# Enforced in governance/approval_engine.py and remediation_workflow.py:
if maker.strip().lower() == approver.strip().lower():
    raise PermissionError("Maker-Checker Violation: You cannot approve a ticket you requested.")
```
An Analyst attempting to approve their own ticket is rejected at the API/database layer with an auditable security event.

