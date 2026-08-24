# CachyOS Evidence

This directory contains the CachyOS planning, baseline, and verification records for the EnVisione Xodus fork. The plan remains the authoritative product contract. These files record observed state and must not be read as a local Game Pass compatibility claim.

- [Audit](./audit.md) records the pre-implementation environment and codebase findings.
- [Plan](./plan.md) defines the mandatory requirements and phase order.
- [Baseline manifest](./baseline.json) freezes the audited repository, platform, hardware, graphics stack, and runtime candidates.
- [Upstream overlap matrix](./upstream-overlap.json) records the decision for each active upstream item that overlaps future work.
- [Phase 001 verification](./phase-001-verification.md) records the reproduced baseline checks and their known boundaries.
- [Baseline verifier](../../scripts/cachyos/verify-baseline.sh) validates the frozen source and environment, and can reproduce the audit workspace checks.

The baseline verifier is read only. Run `scripts/cachyos/verify-baseline.sh --all` from a clean descendant of the frozen source revision whose source-sensitive paths still match the baseline. A mismatch marks affected evidence stale; it does not alter system configuration or account state.
