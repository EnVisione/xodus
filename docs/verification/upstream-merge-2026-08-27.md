# Upstream Merge Verification

## Scope

This record covers the merge of upstream `xodus-gaming/xodus` main into the active CachyOS phase branch `envy/target-metadata-evidence`. The default branch was not modified. No credentials, keyring contents, browser storage, or package content were accessed.

## Source decision

- Shared merge base: `b3d7fb210301aac66b8aaef16c0450dcfadd451c`
- Local origin main before merge: `5b77e06eaa5e3cea78af122436d35a9b02992834`
- Upstream main adopted: `4959309675151bef759b25a270044fd12bf42cf1`
- Upstream pull requests represented by the adopted commits: 158, 159, 162, and 163

The dependency refresh and CI additions were adopted. The XTS cryptography refactor was adopted with the local checked XVD arithmetic retained. The XStore license token route was adopted with bounded response decoding, successful status validation, and the existing secure URL policy retained. The upstream license token endpoint is an implementation route only. It is not evidence of an authorized package CDN route.

## Conflict adaptations

The merge required manual reconciliation in `Cargo.lock`, the two MSIXVC Cargo manifests, `crates/msixvc/src/math.rs`, `crates/msixvc/src/xvd.rs`, `crates/xodus/Cargo.toml`, and `crates/xodus/src/licensing/content.rs`. The local arithmetic error type and checked hash tree calculations were preserved after the upstream math refactor. The local XVD tests and eight byte Vduid compatibility field were preserved while adopting upstream `TweakGenerator`, `Aes128Enc`, and `Aes128Dec`. License token response decoding remains bounded and rejects non successful responses and insecure redirects.

## Verification gates

The following commands completed successfully on 2026-08-27.

- `cargo fmt --check --all`
- `cargo check --workspace --all-targets`
- `cargo clippy --workspace --all-targets --all-features --message-format short`
- `cargo test --workspace --all-targets --no-run`
- `cargo test --workspace --all-targets -- --test-threads=1 --skip test_get_xbox_live_dev_token --skip test_minecraft_win_auth`
- `cargo build --release --workspace`

The serialized test run passed 211 MSIXVC tests, 6 MSIXVC common tests, 24 vendored XAL tests, 83 Xodus tests, 143 CLI tests, and 15 service tests. The first parallel test run exposed a test only destination lock collision. The affected test passed when rerun alone and in the serialized workspace run. The only compiler warnings are the existing vendored XAL `GenericArray::as_slice` deprecation warnings.

## Boundary

The merge is code and dependency integration only. It does not close the Phase 2 retail package integrity gate, produce a supported Microsoft source to target update pair, or make the existing Game Pass package metadata limitation disappear. Those remain tracked as unfinished phase work.
