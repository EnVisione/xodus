# Fuzz Corpus

The parser fuzz target accepts arbitrary bytes and exercises the MSIXVC2, XSP, and XVD parsers without credentials, network access, filesystem writes, or executable loading.

Seed the corpus with the reviewed synthetic fixtures before a fuzzing run:

- `crates/msixvc/testdata/msixvc2/`
- `crates/msixvc/testdata/xsp/`
- XVD synthetic generators and byte fixtures in `crates/msixvc/src/xvd.rs` tests

The fixture provenance, redistribution boundary, and limitations are recorded in [`docs/cachyos/fixture-corpus.md`](../../docs/cachyos/fixture-corpus.md). The 8 MiB input cap is a harness resource bound and does not change production parser limits.

Run with cargo fuzz after installing the cargo fuzz subcommand:

```text
cargo fuzz run parse_inputs fuzz/corpus
```

Discovered crashes must be copied into the corpus, reduced to a deterministic regression test under `crates/msixvc`, and retained with the sanitized fixture manifest.

The local `libfuzzer-sys` binary was smoke-run for 100 generated executions with `-runs=100`. It exited cleanly without a crash. The binary was not built with coverage instrumentation because the `cargo-fuzz` subcommand is unavailable locally, so this is not a coverage-guided campaign result.
