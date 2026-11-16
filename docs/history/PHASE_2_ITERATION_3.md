# Phase 2 — Iteration 3: Retry and recovery

- Retry failed scanner tasks from Scan Progress, preserving successful scanner results.
- Track each scanner attempt with timestamps, outcomes, and error messages.
- Replace findings for successfully retried scanners to prevent duplicate stale findings.
- Manually mark a stale assessment interrupted after 10 minutes of inactivity; then retry.

**Important limitation:** Stale recovery is manual and based on the last database update, not an OS-level worker liveness probe. Do not recover a long-running active scan. This build does not automatically resume after a machine reboot. Live Docker/Windows testing remains necessary.
