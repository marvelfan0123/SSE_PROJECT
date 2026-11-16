# VulnX Cryptographic Audit Ledger & Integrity Verification

## 1. Append-Only Cryptographic Architecture

VulnX maintains an append-only audit trail backed by **HMAC-SHA256 hash chaining**. Every auditable operation (assessment initiation, scanner completion, AI playbook generation, ticket proposal, ticket approval, and rescan verification) is written as an immutable ledger block.

```
Block N-1: [ Event Data ] ──▶ Hash: 7a9f...
                                 │
                                 ▼
Block N:   [ Event Data + Previous Hash: 7a9f... ] ──▶ HMAC-SHA256(Key, Data) ──▶ Hash: 3c1b...
```

---

## 2. Mathematical Chain Formulation

$$\text{Current Hash} = \text{HMAC-SHA256}\left(K_{\text{secret}}, \text{Previous Hash} \parallel \text{Canonical JSON Payload}\right)$$

Where:
- $K_{\text{secret}}$ is stored outside the database in `.vulnx_protected/audit_checkpoint.key` with restricted `0600` permissions.
- $\text{Canonical JSON Payload}$ is deterministically serialized (`sort_keys=True`, `ensure_ascii=False`).

---

## 3. Tamper Detection & Verification

The verification engine (`audit/audit_verifier.py`) recomputes the expected hash chain from genesis ($H_0 = \text{None}$) through the entire ledger:
- If an attacker directly modifies a row in SQLite (e.g. changing an actor, timestamp, or justification), the recomputed hash diverges immediately:
  $$\text{Expected Hash} \neq \text{Stored Hash}$$
- The verification action returns `valid: False` and identifies the exact event ID and timestamp where tampering occurred.

---

## 4. External Checkpoint Export

Authorized Administrators can export a signed JSON checkpoint containing:
- `last_event_id`
- `last_event_hash`
- `total_events_count`
- `checkpoint_signature` (HMAC over checkpoint summary)

This checkpoint file can be stored in an offline vault or submitted to compliance auditors (SOC 2 / ISO 27001) as mathematical proof of log continuity.

