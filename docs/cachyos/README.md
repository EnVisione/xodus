# CachyOS Evidence

This directory contains the CachyOS planning, baseline, and verification records for the EnVisione Xodus fork. The plan remains the authoritative product contract. These files record observed state and must not be read as a local Game Pass compatibility claim.

- [Audit](./audit.md) records the pre-implementation environment and codebase findings.
- [Plan](./plan.md) defines the mandatory requirements and phase order.
- [Baseline manifest](./baseline.json) freezes the audited repository, platform, hardware, graphics stack, and runtime candidates.
- [Upstream overlap matrix](./upstream-overlap.json) records the decision for each active upstream item that overlaps future work.
- [Phase 001 verification](./phase-001-verification.md) records the reproduced baseline checks and their known boundaries.
- [Baseline verifier](../../scripts/cachyos/verify-baseline.sh) validates the frozen source and environment, and can reproduce the audit workspace checks.
- [Login renderer recovery](../xodus/login.md#cachyos-hyprland-and-nvidia-renderer-recovery) documents the process local WebKitGTK workaround for the observed Tier 1 blank login surface.
- [Login rendering verification](./login-rendering-verification.md) records the isolated runtime and workspace checks without retaining sign in data.
- [Target package discovery](./target-package-discovery.md) records the sanitized authenticated package metadata available before package acquisition.
- [MSIXVC2 fixture corpus](./fixture-corpus.md) records the currently reviewed synthetic package fixtures and their remaining evidence gaps.
- [Runtime readiness](./runtime-readiness.md) records the current CachyOS, Hyprland, NVIDIA, display, and runtime prerequisite evidence without accessing account state.
- [Local verification record](../verification/local-gates-2026-08-26.md) records the latest local test, lint, build, fuzz, and baseline results with their evidence boundaries.

The baseline verifier is read only. Run `scripts/cachyos/verify-baseline.sh --all` from a clean descendant of the frozen source revision whose source-sensitive paths still match the baseline. A mismatch marks affected evidence stale; it does not alter system configuration or account state.
