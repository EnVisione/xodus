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

## Current Baseline Refresh

On August 25, 2026, `baseline.json` was refreshed at signed source checkpoint `49c3711575ba8a640b14b7ef804e9455731b5b2f`, binding that source revision after the verified parser fuzz, MSIXVC2 capacity, direct package download capacity, remote streaming capacity, XSP update capacity, and package metadata length binding coverage. The refresh binds the current branch, fork and upstream heads, Cargo lock and metadata digests, package database digest, and observed CachyOS graphics state. The original Phase 001 record above remains historical evidence for the merged baseline and is not changed into a Phase 2 completion claim.

The refreshed verifier passed `--source`, `--environment`, and `--all`. The complete workspace reproduction includes the current parser, transaction, install capacity, direct download capacity, remote streaming capacity, XSP update capacity, package metadata length binding, and recovery tests, zero warning workspace Clippy, and the release build. Workspace tests run with one test thread so subprocess crash and transaction-lock fixtures cannot race each other. These results refresh baseline evidence only and do not establish account, retail package, target runtime, performance, Tier 2, or release completion.

Hosted run [32922577083](https://github.com/EnVisione/xodus/actions/runs/32922577083) passed the repository formatter, Linux x86_64 check, and macOS arm64 check against the prior pushed source checkpoint `32e9514720673c372e467753d0af1997f24e7f5f`. A fresh hosted run is required for the current source checkpoint `49c3711575ba8a640b14b7ef804e9455731b5b2f`. The hosted result confirms cross-target build coverage for its recorded checkpoint only and does not establish account, retail package, target runtime, performance, Tier 2, or release completion.

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
cargo test --workspace --all-targets -- --test-threads=1 --skip test_get_xbox_live_dev_token --skip test_minecraft_win_auth
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
