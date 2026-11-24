# Tests & Formal Verification: `strata_lsp`

```bash
cargo test -p strata_lsp --all-features
cargo xtask kani --crate strata_lsp --timeout 120
cargo bench -p strata_lsp --bench lsp_bench
```

## Suites
1. **Unit Tests (`src/{telemetry,server}.rs`):** Truncated packet / invalid magic (`!= b"BAMT"`) / invalid version / invalid BRP payload rejection, monotonic `frame_seq` ordering, `TelemetryStore` digest & BRP ingest, canonical formatting no-op check, and live CodeLens telemetry formatting.
2. **Integration Tests (`tests/lsp_tests.rs`):** Diagnostics/hover/formatting/CodeLens end-to-end, `strata/graphTelemetry` & `strata/ingestTelemetry`, live socket telemetry subscription, and BRP HTTP/chunked schema fetching.
3. **Property-Based (`tests/proptest_lsp.rs`):** Arbitrary 64-byte `"BAMT"` payload codec round-trip and corrupt frame rejection across random byte vectors.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S8`, 1 harness):** Exhaustive symbolic 64-byte `"BAMT"` wire codec bijection and wrong-magic / wrong-length rejection.
