# Phase 001 Verification

## Record

| Field | Value |
| --- | --- |
| Phase | XODUS-PHASE-001 |
| Requirement | XODUS-REQ-001 |
| Baseline manifest | [`baseline.json`](./baseline.json) |
| Upstream decision matrix | [`upstream-overlap.json`](./upstream-overlap.json) |
| Source commit | `b3d7fb210301aac66b8aaef16c0450dcfadd451c` |
| Verification date | August 24, 2026 |
| Environment | Sanitized Tier 1 CachyOS baseline recorded in `baseline.json` |

## Commands and Results

The following commands passed against the frozen source revision. They are read only except for Cargo build output under the ignored `target/` directory.

```bash
bash -n scripts/cachyos/verify-baseline.sh
scripts/cachyos/verify-baseline.sh --manifest
scripts/cachyos/verify-baseline.sh --source
scripts/cachyos/verify-baseline.sh --environment
scripts/cachyos/verify-baseline.sh --all
```

`--all` reproduced these audit workspace checks:

```bash
cargo fmt --check --all
cargo metadata --format-version 1 --no-deps
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-targets --no-run
cargo test --workspace --all-targets -- --skip test_get_xbox_live_dev_token --skip test_minecraft_win_auth
cargo build --release --workspace
```

Formatting, metadata, compilation, test compilation, 17 offline tests, and the release build passed. The account-backed tests remain excluded because they require the bounded authorization and prerequisites specified by DEC-004 and EXT-001.

A disposable local change to `Cargo.toml` caused `scripts/cachyos/verify-baseline.sh --source` to fail with `source-sensitive paths differ from the frozen baseline`. The change was reverted before the final passing verification run.

## Known Result Boundaries

Clippy completed with exit status zero and four warnings at the frozen source revision. They remain unfinished work under XODUS-REQ-020 and do not establish warning-free release quality. This phase records the result without weakening the later continuous verification requirement.

No account login, entitlement, package, Game Runtime, game launch, performance, Tier 2, release, or cloud fallback verification ran in this phase. The baseline manifests are not local compatibility evidence.

## Phase 001 Exit Evidence

- The machine-readable baseline binds source, dependency, CachyOS, hardware, display, graphics, and runtime candidate identities.
- The upstream matrix records a permitted decision for every active upstream item named by the audit and requires reassessment before overlapping local work.
- The verifier accepts a descendant of the frozen source commit only while the recorded source-sensitive paths, package, graphics, and display identities still match. Any mismatch fails and defines the required evidence invalidation recovery.
- The audit build and test commands reproduce on the frozen baseline.

The phase remains open until the implementation branch, tracking issue, documentation changes, and required review workflow are complete. Later phases cannot start until this phase is merged and its evidence is still valid.
