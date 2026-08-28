# Local Verification Record

Date: 2026-08-26

Repository: `EnVisione/xodus`

Branch: `envy/target-metadata-evidence`

Baseline commit under test: `c24293f`

This record captures verification performed in the local workspace. It includes a bounded live account and metadata check, but it is not evidence of package acquisition, target runtime compatibility, or a stable release.

## Passing Gates

The following commands completed successfully:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | passed |
| `cargo test --workspace --all-targets --all-features -- --test-threads=1` | 478 passed, 2 authorized account tests ignored |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed with zero warnings |
| `cargo build --workspace --release` | passed |
| `cargo deny check` | passed. duplicate dependency warnings remain |
| `cargo audit --no-fetch --stale` | passed. twelve allowed GTK and unmaintained warnings remain |
| `RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_inputs -- -runs=10000 -timeout=5 -print_final_stats=1` | passed. 10,000 executions, no crash artifact, peak RSS 276 MiB |
| `bash scripts/cachyos/verify-baseline.sh --manifest` | passed |
| `bash scripts/cachyos/verify-baseline.sh --environment` | passed |
| `bash scripts/cachyos/verify-baseline.sh --workspace` | passed |
| `target/debug/xodus-cli --help` | passed |
| `target/debug/xodus-cli --version` | passed. `xodus-cli 0.1.0` |
| `git diff --check` | passed |

The remaining account tests remain explicitly opt in because they require authorized Xbox service access and local keychain state. The Minecraft authorization test was run separately after the persisted sign in state became available and passed.

## Live Account and Metadata Checks

The previously ignored account test was run once with the persisted local sign in state:

```text
cargo test -p xodus auth::test_minecraft_win_auth -- --ignored
```

Result: one test passed. No token or account data was printed or retained.

Fresh release binary metadata checks reached the Microsoft package service for both targets:

```text
target/release/xodus-cli download 9NBLGGH2JHXJ --market neutral --dry-run
target/release/xodus-cli download 9NNX1VVR3KNQ --market neutral --dry-run
```

Both returned `package CDN root rejected, requires HTTPS` before file selection or package transfer. No package bytes, signed URLs, or credentials were retained. This confirms current account access and isolates the remaining acquisition failure to the service supplied CDN route.

An additional bounded TLS and routing probe used the Microsoft wildcard endpoint `23.36.184.7` with the advertised asset hostnames. The certificate matched `*.xboxlive.com`, but every host returned `503 Service Unavailable`. No package path was requested or retained, and no supported replacement route was found.

## Expected Baseline Result

`bash scripts/cachyos/verify-baseline.sh --all` fails at the source comparison with `source-sensitive paths differ from the frozen baseline`. This is an expected stale baseline signal because the current branch contains verified changes after the frozen source revision. The manifest, environment, and workspace portions pass independently.

## Evidence Boundary

These checks cover local parsing, validation, transaction recovery, bounded fuzzing, build quality, and command wiring. They do not prove a real source to target update, Microsoft package CDN availability, xgameruntime or WineGDK service completeness, live login or entitlement, game launch or save behavior, Forza performance, independent Tier 2 hardware compatibility, or public release readiness.
