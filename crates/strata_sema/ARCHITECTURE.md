# Architecture: `strata_sema`

## Modules
- `src/db.rs`: `SemaDb` (`salsa::Database`) with `schema_signature` early-cutoff (`resolve_layouts`, `module_env_summary`), `parse_file`, `item_green_trees`, interned `ItemSlot`, `item_green`, `analyze_item`, `analyze_module`, and `concurrency_graph` so body-only edits skip layout recomputation and untouched sibling items.
- `src/types.rs` & `src/infer.rs`: Static Strata `Ty` (preserving `Option`, `Result`, `Borrow`, `Trigger`, `QueryRow`, `Record`), SI unit exponents `UnitDim` (`sec`, `meters`, `rad`, `frames`), and bidirectional inference (`unify_branch_tys`, `build_array_lit`, `coerce_binary_operands`, `infer_call_ty`, `infer_query_ty`, `resolve_index_ty`, divergence checks).
- `src/layout.rs`: `#[repr(C)]` `align_up`, `compute_field_placement`, `_strata_pad_N` insertion (`solve_pod_layout`), `@soa` hot/cold splitting, and `compute_wire_identity` matching `bamabi_macros` bit-for-bit.
- `src/access.rs` & `src/authority.rs`: Theorem 0.1 `FilteredAccessSet`, `modes_conflict`, `archetype_masks_disjoint`, `MAX_TERMS_PER_QUERY` / `MAX_QUERIES_PER_SYSTEM`, `ConcurrencyGraph`, and unified CFG/loop/helper-fn `Provenance` + `AuthoritySet` + `PlaceOrigin` abstract interpreter (`E0501`).
- `src/checks/{mod,schema,attrs,effects,items}.rs`: Modular schema header extraction & `item_fields` building (`Component`, `Struct`, `Resource`), attribute parsing, `verify_effects` (`reads`, `writes`, `spawns`, `despawns`, `triggers`, `emits`), and item lowering/validation (including `HirSpatialIndex` geometry).
- `src/hir.rs`, `src/hir_lower.rs`, `src/diagnostics.rs`: Frozen `AnalyzedModule` HIR structures, HIR lowering, and structured span diagnostics (`E00xx`..`W04xx`).
- `src/kani_proofs.rs`: Symbolic Kani proofs `PO-S6`, `PO-S7`, `PO-S11`, and `PO-S12`.
- `benches/sema_bench.rs`: Criterion `0.8` (+ optional `hotpath-alloc`) microbench for cold cookbooks, Salsa body-edit caching, and `@authority` provenance.
