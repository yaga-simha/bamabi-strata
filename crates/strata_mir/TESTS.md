# Tests & Formal Verification: `strata_mir`

```bash
cargo test -p strata_mir --all-features
cargo xtask kani --crate strata_mir --timeout 120
cargo bench -p strata_mir --bench mir_bench
```

## Suites
1. **Unit Tests (`src/{ir,verify,passes/*}.rs`):** `alloc_local`/`alloc_block` indexing, negative verifier checks (`InvalidBlockTarget`, `InvalidLocalRef`, `NonDeterministicOp`, `InvalidCfgInvariant` on TX `RowPtr` loops), `csr_cell_range` monotonic & adversarial lookups, `atomic_tx`, `optional_split`, `tick_coalesce`, `determinism`, and `fsm` priority sorting.
2. **Integration Tests (`tests/mir_tests.rs`):** Pass verification, pre-image `atomic_tx` multi-entity undo log, 2-pass `spatial_csr` geometry & instructions, `MirPlace` LValue / `ArrayStore` / `IterUpCascade` / `OptionalWrite` lowering, and cookbook MIR lowering & verification.
3. **Property-Based (`tests/proptest_mir.rs`):** CSR partition conservation + random valid `atomic` and `spatial` module lowering & verification.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S10`, `PO-S14`, `PO-S15`, 3 harnesses):** Monotonic CSR partition & panic-free OOB rejection (`PO-S10`), `atomic_tx` pre-image undo log restoration (`PO-S14`), and 2-pass CSR partition + query disc cell clamping (`PO-S15`).
