# Static Safety Inventory

## Scope

This inventory covers Rust production sources under `crates/` and supports the Phase 2 requirement that remotely influenced parser, package, service, and environment paths do not contain placeholder macros or unconditional process aborts.

The inventory was refreshed on August 25, 2026 at checkpoint `f6fc444638b84b6d498146dc6eccf973fd11dbc7`.

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
| XSP parsing and apply | Typed header, record, range, hash, ordering, space, and I/O failures. Mutated inputs return a result without a process panic. | `crates/msixvc/src/xsp.rs`, `mutated_xsp_fixture_never_panics` |
| MSIXVC2 inspection and install | Typed ZIP, path, duplicate, symbolic link, compression, metadata, size, and transaction failures. Mutated archives return a result without a process panic. | `crates/msixvc/src/msixvc2.rs`, `mutated_msixvc2_fixture_never_panics` |
| Package paths and promotion | Hostile paths fail before output creation, Linux writes stay beneath the transaction root, and promotion rollback preserves the prior verified state. | `crates/xodus-cli/src/commands/streaming.rs` tests |
| HTTP and cache readers | Typed status, range, position, length, retry, and premature EOF failures with bounded retry budgets. | `crates/msixvc/src/streaming.rs` tests |
| HTTP extent properties | A deterministic seeded sweep covers 4,096 bounded position, active-offset, and response-extent cases, including valid sums and invalid overlong or mismatched extents. | `http_read_extent_properties_hold_for_seeded_inputs` |
| Account and licensing responses | Typed HTTP, schema, empty collection, token conversion, key, license, and UTF 8 failures. Test-only assertions remain outside production paths. | `crates/xodus/src/api`, `crates/xodus/src/models`, `crates/xodus/src/licensing` |
| Service IPC | Bounded payloads, deadlines, connection and rate limits, peer identity checks, explicit unsupported operations, and escaped machine-readable errors. | `crates/xodus-service/src/connection` and startup code |

## Test-only matches

The scan still reports `panic!` and `expect` in test modules. These intentionally fail a test when a synthetic fixture violates the test's expected contract. They are not used as production fallback behavior. The ignored account-backed tests also retain assertions because they are opt in and require authorized external state; they are excluded from ordinary offline verification and do not authorize a release claim.

## Limits

This is a static inventory. It does not prove dynamic behavior, external service compatibility, protected executable launch, or target game lifecycle completion. Mutation regressions, bounded fixture tests, workspace Clippy, account-backed verification, runtime traces, and real target exercises remain separate required evidence.
