# Tests & Formal Verification: `strata_sema`

```bash
cargo test -p strata_sema --all-features
cargo xtask kani --crate strata_sema --timeout 120
cargo bench -p strata_sema --bench sema_bench
```

## Suites
1. **Unit Tests (`src/{types,layout,access,diagnostics}.rs`):** Dimensional algebra, unit literals, overflow-safe `align_up` & `compute_field_placement`, `_strata_pad_*` gap filling, `modes_conflict` symmetry matrix, `@soa` key overlap, and 1-based line/column spans.
2. **Integration Tests (`tests/sema_tests.rs`):** Bit-exact `ComponentUuid` & `SCHEMA_FINGERPRINT` parity, Theorem 0.1 disjoint `assert_par`, per-item Salsa early-cutoff on body edits (`resolve_layouts == 0`, `module_env_summary == 0`, sibling `analyze_item` skipped), `MAX_TERMS_PER_QUERY` enforcement, Class A/B inference & `authority.rs` soundness, `verify_effects` (`despawns`, `triggers`, `emits`), and clean analysis of all 8 cookbooks.
3. **Property-Based (`tests/proptest_sema.rs`):** Zero-implicit-padding & alignment invariants over random `AbiPod` structs, Theorem 0.1 filter mask symmetry & soundness, and nested `Option`/record/authority panic-freedom.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S6`, `PO-S7`, `PO-S11`, `PO-S12`, 4 harnesses):** Overflow-free checked alignment/placement (`PO-S6`), exhaustive `u8` Theorem 0.1 bitmask soundness & symmetry (`PO-S7`), `AuthoritySet`/`PlaceOrigin` lattice soundness (`PO-S11`), and compound `Ty` preservation without erasure (`PO-S12`).
