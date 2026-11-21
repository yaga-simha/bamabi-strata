# Tests & Formal Verification: `strata_lsp`

```bash
cargo test -p strata_lsp --all-features
cargo kani -p strata_lsp -j
```

## Suites
1. **Unit Tests (`src/{telemetry,server}.rs` — 4 tests):** Truncated packet / invalid magic / invalid BRP method rejection, `TelemetryStore` digest & BRP ingest, canonical formatting no-op check, and live CodeLens telemetry formatting.
2. **Integration Tests (`tests/lsp_tests.rs` — 2 tests):** Diagnostics/hover/formatting/CodeLens end-to-end + `SystemTelemetryDigest64` BRP round-trip.
3. **Property-Based (`tests/proptest_lsp.rs` — 2 tests):** Arbitrary 64-byte payload codec round-trip and corrupt frame rejection across random byte vectors.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S8`):** Exhaustive symbolic 64-byte wire codec bijection and wrong-magic / wrong-length rejection.
