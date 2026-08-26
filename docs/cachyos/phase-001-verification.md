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

On August 25, 2026, `baseline.json` was refreshed at signed source checkpoint `05e9a30c8dac2b876815d42c51b2e4f85efeb12a`, binding that source revision after the verified parser fuzz, MSIXVC2 capacity, direct package download capacity, remote streaming capacity, XSP update capacity, package metadata length binding, and early direct download file size validation coverage. The refresh binds the current branch, fork and upstream heads, Cargo lock and metadata digests, package database digest, and observed CachyOS graphics state. The original Phase 001 record above remains historical evidence for the merged baseline and is not changed into a Phase 2 completion claim.

The refreshed verifier passed `--source`, `--environment`, and `--all`. The complete workspace reproduction includes the current parser, transaction, install capacity, direct download capacity and early file size validation, remote streaming capacity, XSP update capacity, package metadata length binding, and recovery tests, zero warning workspace Clippy, and the release build. Workspace tests run with one test thread so subprocess crash and transaction-lock fixtures cannot race each other. These results refresh baseline evidence only and do not establish account, retail package, target runtime, performance, Tier 2, or release completion.

Hosted run [32924183997](https://github.com/EnVisione/xodus/actions/runs/32924183997) passed the repository formatter, Linux x86_64 check, and macOS arm64 check against pushed branch checkpoint `21cece19b62e79dc6f249665d54f0519bc3b1727`, which contains source checkpoint `05e9a30c8dac2b876815d42c51b2e4f85efeb12a`. The hosted result confirms cross-target build coverage for that recorded checkpoint only and does not establish account, retail package, target runtime, performance, Tier 2, or release completion.

The package response validation checkpoint `fb97bc474b40fe33f2413507c5cfbee8ba7ce66b` is signed, pushed, and passes the local full workspace gate. It adds latest and exact-version response identity checks plus file metadata and CDN safety validation before file selection or URL construction. Hosted run [32926270780](https://github.com/EnVisione/xodus/actions/runs/32926270780) passed formatting, Linux x86_64, and macOS arm64 checks against documentation checkpoint `08e3710b79482e5d4aed1a92b1a2c4d93189b7d1`, which contains source checkpoint `fb97bc474b40fe33f2413507c5cfbee8ba7ce66b`. This cross-target result confirms build and lint coverage for the package validation slice only and does not establish account, retail package, target runtime, performance, Tier 2, or release completion.

Checkpoint `7d56e1523d8305ac5426f2bde549876241d19179` extends that boundary by rejecting duplicate package file names before selection. The source checkpoint is signed, pushed, and passes the targeted package tests and zero-warning targeted Clippy. The baseline manifest is refreshed to bind this checkpoint; hosted verification remains pending.

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
