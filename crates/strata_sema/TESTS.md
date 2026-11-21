# Tests & Formal Verification: `strata_sema`

```bash
cargo test -p strata_sema --all-features
cargo kani -p strata_sema -j
```

## Suites
1. **Unit Tests (`src/{types,layout,access,diagnostics}.rs` — 7 tests):** Dimensional algebra, unit literals, overflow-safe `align_up` & `compute_field_placement`, `_strata_pad_*` gap filling, `modes_conflict` symmetry matrix, `@soa` key overlap, and 1-based line/column spans.
2. **Integration Tests (`tests/sema_tests.rs` — 6 tests):** Bit-exact `ComponentUuid` & `SCHEMA_FINGERPRINT` parity, Theorem 0.1 disjoint `assert_par`, Salsa early-cutoff on body edits, `MAX_TERMS_PER_QUERY` violation check, error/lint diagnostics, and clean analysis of all 6 cookbooks.
3. **Property-Based (`tests/proptest_sema.rs` — 2 tests):** Zero-implicit-padding & alignment invariants over random `AbiPod` structs; Theorem 0.1 filter mask symmetry & soundness.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S6`, `PO-S7`):** Overflow-free checked alignment/placement (`PO-S6`) and exhaustive `u8` Theorem 0.1 bitmask soundness & conflict symmetry (`PO-S7`).
