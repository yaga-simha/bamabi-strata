# Architecture: `strata_sema`

## Modules
- `src/db.rs`: `SemaDb` (`salsa::Database`) with `schema_signature` early-cutoff memoization skipping `resolve_layouts_json` on body-only edits.
- `src/types.rs`: Static Strata `Ty` and SI physical unit exponents `UnitDim` (`sec`, `meters`, `rad`, `frames`).
- `src/layout.rs`: `#[repr(C)]` `align_up`, `compute_field_placement`, `_strata_pad_N` insertion (`solve_pod_layout`), `@soa` hot/cold splitting, and `compute_wire_identity` matching `bamabi_macros` bit-for-bit.
- `src/access.rs`: Theorem 0.1 `FilteredAccessSet`, `modes_conflict`, `archetype_masks_disjoint`, `MAX_TERMS_PER_QUERY` / `MAX_QUERIES_PER_SYSTEM` checks, and `ConcurrencyGraph`.
- `src/hir.rs`, `src/checks.rs`, `src/diagnostics.rs`: Frozen HIR structures, module checks, and structured span diagnostics (`E01xx`..`W04xx`).
- `src/kani_proofs.rs`: Symbolic Kani proofs `PO-S6` and `PO-S7`.
