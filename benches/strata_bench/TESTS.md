# Tests: `strata_bench`

```bash
cargo test -p strata_bench --all-features
```

## Suites
1. **Unit Tests (`src/{main,stats,report}.rs` — 4 tests):** Exact percentile/throughput stats (`summarize_samples`), empty-sample boundary behavior, Markdown/JSON report round-trip, and CLI flag parsing/validation.
2. **Pre-Timing Differential Gate (`runtime_bench.rs`):** Every runtime benchmark run asserts bit-identical SHA-256 and FNV-1a hashes across `native`, `jit`, `c99:release`, and `rust_guest:release` before measuring latency.
