# Architecture: `strata_mir`

## Pipeline & Passes
1. `src/lower.rs`: Lowers analyzed `AnalyzedModule` HIR into CFG `MirFunction`s (`src/ir.rs`) and runs all 6 MIR passes before running `verify_mir`.
2. `src/passes/optional_split.rs`: Hoists `?T` chunk presence checks outside inner loops.
3. `src/passes/tick_coalesce.rs`: Rewrites `&mut? T` writes to `IterColWriteUntracked` + `DirtyRunInit` / `DirtyRunRecordRow` / `IterMarkChangedRange`.
4. `src/passes/state_machines.rs`: Lowers `timeline`, `task`, and priority-sorted `fsm` items into sparse state components + tick functions.
5. `src/passes/spatial_csr.rs`: Synthesizes counting-sort CSR rebuild systems ordered prior to the earliest reader + `csr_cell_range` bounds validator.
6. `src/passes/atomic_tx.rs`: Lowers `atomic { ... } on_rollback { ... }` into `CmdCheckpoint`, stack shadow slots, and rollback edges.
7. `src/passes/determinism.rs`: Enforces `@deterministic` (`allow_fma = false`, deterministic transcendentals/reductions).
8. `src/verify.rs`: Validates entry blocks, CFG branch targets, SSA `LocalId` bounds, zero implicit padding, and `@deterministic` invariants.
9. `src/kani_proofs.rs`: Symbolic Kani proof `PO-S10`.
