# Tests & Formal Verification: `strata_mir`

```bash
cargo test -p strata_mir --all-features
cargo kani -p strata_mir -j
```

## Suites
1. **Unit Tests (`src/{ir,verify,passes/*}.rs` — 9 tests):** `alloc_local`/`alloc_block` indexing, negative verifier checks (`InvalidBlockTarget`, `InvalidLocalRef`, `NonDeterministicOp`), `csr_cell_range` monotonic & adversarial lookups, `atomic_tx`, `optional_split`, `tick_coalesce`, `determinism`, and `fsm` priority sorting.
2. **Integration Tests (`tests/mir_tests.rs` — 7 tests):** Pass verification + end-to-end cookbook MIR lowering & verification.
3. **Property-Based (`tests/proptest_mir.rs` — 2 tests):** CSR partition conservation + random valid module lowering & verification.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S10`):** Exact monotonic CSR partition equivalence and panic-free rejection of arbitrary/corrupted offsets & cell indices.
