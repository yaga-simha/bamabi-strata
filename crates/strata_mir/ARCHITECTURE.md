# Architecture: `strata_mir`

## Pipeline & Passes
1. `src/lower.rs`: Lowers `AnalyzedModule` HIR into CFG `MirFunction`s (`src/ir.rs`) with `MirPlace` recursive LValue lowering (`ArrayStore`, `VecInsert`), structured `Insert` lowering, numeric `Inst::Cast` coercions, optional query methods (`.is_some()`, `.is_none()`, `.unwrap()`), per-row `IterUpCascade`, and runs all 6 MIR passes before `verify_mir`.
2. `src/passes/optional_split.rs`: Hoists `?T` chunk presence checks outside inner loops.
3. `src/passes/tick_coalesce.rs`: Rewrites `&mut? T` and `OptionalWrite` (`opt_present_*` blocks) writes to `IterColWriteUntracked` + `DirtyRunInit` / `DirtyRunRecordRow` / `IterMarkChangedRange`.
4. `src/passes/state_machines.rs`: Lowers `timeline`, `task`, and priority-sorted `fsm` items into sparse state components + tick functions.
5. `src/passes/spatial_csr.rs`: Synthesizes 2-pass counting-sort CSR rebuild systems (`SpatialCsrBegin` -> `SpatialCsrCount` -> `SpatialCsrPrefixSum` + `IterReset` -> `SpatialCsrScatter`) ordered prior to the earliest reader + `csr_cell_range` bounds validator.
6. `src/passes/atomic_tx.rs`: Runs after `tick_coalesce`, lowering `atomic { ... } on_rollback { ... }` into `CmdCheckpoint`, pre-image `(saved_flag, undo_slot)` undo logs, and reverse-order restoration before `on_rollback`.
7. `src/passes/determinism.rs`: Enforces `@deterministic` (`allow_fma = false`, deterministic transcendentals/reductions).
8. `src/verify.rs`: Validates entry blocks, CFG branch targets, SSA `LocalId` bounds, zero implicit padding, `@deterministic` invariants, and `verify_atomic_tx_no_row_ptr_loops`.
9. `src/kani_proofs.rs`: Symbolic Kani proofs `PO-S10`, `PO-S14`, and `PO-S15`.
10. `benches/mir_bench.rs`: Criterion `0.8` (+ optional `hotpath-alloc`) microbench for `mir_lower_verify` and `mir_spatial_csr_scaling`.
