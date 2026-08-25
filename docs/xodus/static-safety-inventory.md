# Static Safety Inventory

## Scope

This inventory covers Rust production sources under `crates/` and supports the Phase 2 requirement that remotely influenced parser, package, service, and environment paths do not contain placeholder macros or unconditional process aborts.

The inventory was refreshed on August 25, 2026 after the parser hardening checkpoints `070eb42`, `658beef`, `e9eab1a`, `7f9d68e`, `65b9274`, `59b37c5`, and `c7e6347`.

## Scan

The baseline search was:

```text
rg -n --glob '*.rs' '(TODO|todo!|unimplemented!|panic!|unwrap\(|expect\()' crates
```

The result contains no `TODO`, `todo!`, or `unimplemented!` match in the current source tree. The remaining `panic!` and `expect` matches are in `#[cfg(test)]` modules and are assertion failures for synthetic fixtures, test setup, or authorized opt in account tests. They are not reachable from production command, service, parser, package, or environment paths.

## Reviewed production boundaries

| Boundary | Result | Evidence |
| --- | --- | --- |
| XVD header and metadata parsing | Typed failures for invalid content type, unsupported XVC versions and keys, bounds, arithmetic, I/O, and allocation. Invalid content type is rejected before metadata access. | `crates/msixvc/src/xvd.rs`, `XvdFileParseError`, `parse_rejects_invalid_content_type_before_metadata_access` |
| XVD enum wire parsing | Four byte wire values are validated at their full width, so out of domain values cannot alias valid one byte enum values. | `crates/msixvc/src/models/xvd/enums.rs`, `xvd_type_rejects_values_outside_the_wire_domain`, `xvd_content_type_rejects_values_outside_the_wire_domain` |
| XSP parsing and apply | Typed header, record, range, hash, ordering, space, and I/O failures. Mutated inputs return a result without a process panic. | `crates/msixvc/src/xsp.rs`, `mutated_xsp_fixture_never_panics` |
| MSIXVC2 inspection and install | Typed ZIP, path, duplicate, symbolic link, compression, metadata, size, and transaction failures. Mutated archives return a result without a process panic. | `crates/msixvc/src/msixvc2.rs`, `mutated_msixvc2_fixture_never_panics` |
| Package paths and promotion | Hostile paths fail before output creation, metadata file hashes and transaction journals are bounded before collection, Linux writes stay beneath the transaction root, and promotion rollback preserves the prior verified state. | `crates/xodus-cli/src/commands/streaming.rs` tests, `crates/xodus-cli/src/commands/download.rs` |
| HTTP and cache readers | Typed status, range, position, length, retry, and premature EOF failures with bounded retry budgets. | `crates/msixvc/src/streaming.rs` tests |
| HTTP extent properties | A deterministic seeded sweep covers 4,096 bounded position, active-offset, and response-extent cases, including valid sums and invalid overlong or mismatched extents. | `http_read_extent_properties_hold_for_seeded_inputs` |
| Parser fuzz harness | An explicit `cargo-fuzz` target drives the MSIXVC2, XSP, and XVD parsers from bounded arbitrary bytes without credentials, network access, filesystem writes, or executable loading. A nightly coverage-guided campaign completed 10,000 executions over 11 tracked MSIXVC2 and XSP fixture files, reached 1,633 inline coverage counters and 4,336 feature counters, added 279 new units, and produced no sanitizer failure or crash artifact. | `fuzz/fuzz_targets/parse_inputs.rs`; `RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_inputs corpus ../crates/msixvc/testdata/msixvc2 ../crates/msixvc/testdata/xsp -- -runs=10000 -timeout=5 -print_final_stats=1` |
| Account and licensing responses | Typed HTTP, schema, empty collection, token conversion, key, license, and UTF 8 failures. Test-only assertions remain outside production paths. | `crates/xodus/src/api`, `crates/xodus/src/models`, `crates/xodus/src/licensing` |
| SPLicense binary decoding | Base64 input and TLV payloads are bounded before allocation, short signature blocks fail without subtraction underflow, packed content key identifiers and 40 byte key lengths are validated, and malformed SOAP token fragment references fail instead of indexing. | `crates/xodus/src/licensing/splicense.rs`, `crates/xodus/src/api/live/rst/request.rs` |
| RST request construction | Empty scope policy input returns a typed builder error before token removal, so malformed or incomplete callers cannot trigger an empty vector panic. | `crates/xodus/src/api/live/rst/builder.rs`, `RSTBuilderError::MissingScopePolicy` |
| Hardware probing | Linux SMBIOS command output is bounded before collection, and malformed headers, string indexes, and UUID ranges return typed I/O errors. | `crates/xodus/src/hardware.rs`, `read_bounded_smbios`, `parse_smbios` |
| Service IPC | Bounded payloads, deadlines, connection and rate limits, peer identity checks, absolute private runtime directory validation, explicit unsupported operations, and escaped machine-readable errors. | `crates/xodus-service/src/connection`, `crates/xodus-service/src/main.rs`, and startup code |

## Test-only matches

The scan still reports `panic!` and `expect` in test modules. These intentionally fail a test when a synthetic fixture violates the test's expected contract. They are not used as production fallback behavior. The ignored account-backed tests also retain assertions because they are opt in and require authorized external state; they are excluded from ordinary offline verification and do not authorize a release claim.

## Limits

This is a static inventory. It does not prove dynamic behavior, external service compatibility, protected executable launch, or target game lifecycle completion. Mutation regressions, bounded fixture tests, the fuzz harness runtime, workspace Clippy, account-backed verification, runtime traces, and real target exercises remain separate required evidence. The bounded campaign produced no crash corpus, so no crash-specific regression is claimed beyond the existing deterministic parser and transaction tests.
