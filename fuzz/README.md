# Fuzz Harness

The parser fuzz target accepts arbitrary bytes and exercises the MSIXVC2, XSP, and XVD parsers without credentials, network access, filesystem writes, or executable loading.

The reviewed synthetic MSIXVC2 and XSP fixtures are used as seed inputs. XVD synthetic generators and byte fixtures remain in the `crates/msixvc/src/xvd.rs` tests. Fixture provenance, redistribution boundaries, and limitations are recorded in [`docs/cachyos/fixture-corpus.md`](../docs/cachyos/fixture-corpus.md). The 8 MiB input cap is a harness resource bound and does not change production parser limits.

Run a bounded coverage guided campaign with the nightly toolchain:

```text
RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_inputs corpus ../crates/msixvc/testdata/msixvc2 ../crates/msixvc/testdata/xsp -- -runs=10000 -timeout=5 -print_final_stats=1
```

Discovered crashes must be copied into the corpus, reduced to a deterministic regression test under `crates/msixvc`, and retained with the sanitized fixture manifest.

The verified campaign used cargo fuzz 0.13.2 and nightly rustc 1.100.0 nightly. The campaign at signed checkpoint `2717b7f` completed 10,000 coverage guided executions against 11 tracked MSIXVC2 and XSP fixture files, reached 1,652 inline coverage counters and 4,346 feature counters, added 324 new units, retained no crash artifact, and exited without a sanitizer failure. Generated non-crash corpus inputs were removed after the run.
