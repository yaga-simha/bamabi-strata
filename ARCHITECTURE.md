# Architecture of `bamabi-strata` (Strata v2.0)

`bamabi-strata` sits at **Layer 3** of the `bamabi` ecosystem above **Layer 2** `bamabi-core`, consuming the **Layer 0** wire ABI contract (`bamabi_sys`, `bamabi_sdk_gen`, `bamabi_guest`, `ABI 0.3.0` / `0x0003_0000`, `73` `BamHostApi` slots) and **Layer 1** signing/manifest crates (`bamabi_manifest`, `bamabi_trust`).

---

## 1. Crate Dependency DAG & Isolation Boundaries (12 Workspace Crates)

```text
                        ┌─────────────────────────────────────────┐
                        │                 stratac                 │  CLI + headless sim_test / net_sim_test
                        └───────┬─────────┬──────────┬────────┬───┘
                                │         │          │        │
            ┌───────────────────┘         │          │        └──────────────────────┐
            ▼                             ▼          ▼                               ▼
   ┌─────────────────┐          ┌─────────────┐ ┌────────────┐           ┌──────────────────────┐
   │  strata_codegen │          │  strata_jit │ │ strata_lsp │           │   bamabi_native_rt   │
   │  C99 / RG / BN  │          │  Cranelift  │ │  tower-lsp │           │  Bevy 0.20 / Static  │
   └────────┬────────┘          └──────┬──────┘ └─────┬──────┘           └──────────────────────┘
            │                          │              │                     ▲ Uses Bevy 0.20 (optional bamabi_host)
            └──────────────┬───────────┘              │
                           ▼                          │
                  ┌─────────────────┐                 │
                  │   strata_mir    │                 │
                  │ SSA CFG +Passes │                 │
                  └────────┬────────┘                 │
                           │                          │
                           ▼                          ▼
                  ┌───────────────────────────────────────┐
                  │              strata_sema              │  Salsa 0.28.5, Layouts, Theorem 0.1, Authority
                  └───────────────────┬───────────────────┘
                                      │
                                      ▼
                  ┌───────────────────────────────────────┐
                  │             strata_syntax             │  logos + rowan + stratafmt + graph_ir
                  └───────────────────────────────────────┘

  Independent tooling & benchmarking crates:
  - `xtask`          : Zero external deps, zero Bevy deps (`#![forbid(unsafe_code)]`)
  - `strata_docs`    : Zero external deps, `#![no_std]`, zero Bevy deps (`#![forbid(unsafe_code)]`)
  - `strata_bench`   : Compiler & 4-tier Bevy runtime throughput harness (`benches/strata_bench`)
  - `strata_profile` : Headless Bevy 0.20 + `bamabi_host` + `hotpath-rs` stress suite (`benches/strata_profile`)
```

### Non-Negotiable Isolation Rules

1. **8/12 Zero-Bevy Crates:** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, and `xtask` contain zero transitive `bevy*` dependencies. This keeps compiler, IDE, and verification builds lightweight and guarantees guest artifact emitters cannot leak host Bevy internals.
2. **Universal `#![forbid(unsafe_code)]`:** Every workspace crate forbids `unsafe` and warns on missing docs (`14` checked entrypoints across `12` crates). C-ABI struct layouts and slot tables are constructed symbolically (`bamabi_sys::offsets::*`, `core::mem::offset_of!`, `BAM_HOST_API_SLOT_COUNT`) or generated as source/object files (`strata_codegen`, `strata_jit`).
3. **`static-console` Graduation Path:** Applications compiled with `--target bevy-native --static-console` link `bamabi_native_rt` with `--no-default-features --features static-console`, stripping `libloading` and `bamabi_host` completely for consoles or static targets that forbid dynamic loading.
4. **Allocator Isolation:** `benches/strata_profile` avoids depending on `stratac/sim-runner` so `SIM_GLOBAL_ALLOC` never collides with `hotpath-alloc`'s `#[global_allocator]` during `--workspace --all-targets --all-features` builds.

---

## 2. Compilation Pipeline (Frontend -> 3 Tiers + Cranelift JIT)

1. **Lexing, Lossless CST & Graph IR (`strata_syntax`):**
   - `lexer.rs`: `logos` DFA tokenizer covering every input UTF-8 byte without gaps (preserving range tokens next to unit literals like `0..10_m`).
   - `parser.rs` & `ast.rs`: LL(2) + Pratt error-recovering parser producing an immutable `rowan` green/red CST with lossless round-trip guarantees (`parse(s).syntax().text() == s`) and typed AST wrappers.
   - `fmt.rs`: Idempotent `stratafmt` whitespace and comment normalizer.
   - `graph_ir.rs`: Lossless CST <-> Graph IR JSON projection and hash-isolated `.strata.graph.json` layout sidecars.

2. **Incremental Semantic Analysis (`strata_sema`):**
   - `db.rs`: Backed by `salsa` `0.28.5` (`SemaDb`) with schema early cutoff (`schema_signature`, `resolve_layouts`, `module_env_summary`) and per-item caching (`parse_file`, `item_green_trees`, `item_green`, `analyze_item`) so body-only edits skip layout resolution and untouched sibling items.
   - `types.rs` & `infer.rs`: SI dimensional algebra (`UnitDim`: `sec`, `meters`, `rad`, `frames`) and bidirectional type inference (`unify_branch_tys`, `build_array_lit`, `coerce_binary_operands`, `infer_call_ty`, `infer_query_ty`, `resolve_index_ty`, explicit `HirExpr::Cast` insertion).
   - `layout.rs`: `AbiPod` solver inserting explicit zero-initialized `_strata_pad_N` `[u8; K]` fields at every alignment/tail gap and computing bit-exact `ComponentUuid` (SipHash-2-4-128) and FNV-1a `SCHEMA_FINGERPRINT` values matching `bamabi_macros`.
   - `access.rs`: Theorem 0.1 `FilteredAccessSet` concurrency prover (`With<T>` / `Without<T>`, `@soa` disjoint hot/cold strata, sub-field projections) enforcing `bamabi_sys::MAX_TERMS_PER_QUERY` (`32`) and `bamabi_sys::MAX_QUERIES_PER_SYSTEM` (`16`).
   - `checks/{mod,schema,attrs,effects,items}.rs` & `authority.rs`: Modular schema/attribute/effects checking (`despawns`, `triggers`, `emits`, `reads`, `writes`, `spawns`) and unified `Provenance` + `AuthoritySet` + `PlaceOrigin` abstract interpreter (`E0501_AUTHORITY_VIOLATION`).

3. **Backend-Neutral SSA CFG IR & Passes (`strata_mir`):**
   - `lower.rs` lowers typed HIR into `MirModule` CFGs (`ir.rs`) with recursive `MirPlace` LValue lowering, `ArrayStore`, `IterUpCascade`, and numeric coercions, executing six passes before `verify.rs`:
     - `passes/optional_split.rs`: hoists `?T` chunk presence checks (`OptionalChunkIsPresent`) out of per-row inner loops.
     - `passes/tick_coalesce.rs`: rewrites `&mut? T` and `OptionalWrite` writes to `IterColWriteUntracked` + register-held dirty-run tracking (`DirtyRunInit`/`DirtyRunRecordRow`/`IterMarkChangedRange`).
     - `passes/state_machines.rs`: expands `timeline`, stackless `task`, and priority-ordered `fsm` declarations into sparse-set components + tick systems.
     - `passes/spatial_csr.rs`: synthesizes deterministic 2-pass counting-sort CSR rebuild systems (`SpatialCsrBegin`/`Count`/`PrefixSum`/`IterReset`/`Scatter`) ordered before the earliest scheduled reader, plus `csr_cell_range`.
     - `passes/atomic_tx.rs`: rewrites `atomic { ... } on_rollback { ... }` into `CmdCheckpoint`, pre-image undo slots, and reverse-order rollback restoration.
     - `passes/determinism.rs`: clears FMA contraction (`allow_fma = false`) and enforces deterministic math / reduction ordering under `@deterministic`.

4. **Direct MIR Backends (Zero `expr.rs` / `SystemPlan`):**
   - **Tier 1a — Cranelift PIC JIT (`strata_jit`):** `abi_offsets.rs` derives all 73 `BamHostApi` slots and descriptor offsets from `bamabi_sys::offsets::*` and `core::mem::offset_of!`. `emitter/{mod,rodata,init,fn_lower,inst,spatial,net}.rs` lowers `MirFunction` CFGs directly to `cranelift-object` relocatable object code, and `linker.rs` links a platform shared library (`.dylib`/`.so`/`.dll`) for sub-35ms hot reloads.
   - **Tier 1b — Strict ISO C99 (`strata_codegen::c99`):** `c99/{mod,prelude,decls,fn_emit,inst_emit,net_emit}.rs` emits standalone `-std=c99 -Wall -Wextra -Wpedantic -Werror` C99 (`-ffp-contract=off`) against `bamabi_sdk_gen`-generated `bamabi.h`.
   - **Tier 2 — Safe Rust Guest `.cdylib` (`strata_codegen::rust_guest`):** `rust_guest/{mod,prelude,items,fn_emit,inst_emit,export_mod}.rs` emits `#![forbid(unsafe_code)]`, zero-Bevy `bamabi_guest` crates packaged into Ed25519-signed `.bampack` bundles via `bamabi_trust`.
   - **Tier 3 — Static Bevy Native (`strata_codegen::bevy_native`):** `bevy_native/{mod,items,analysis,fn_emit,places_ops}.rs` graduates modules into `#![forbid(unsafe_code)]` Bevy `0.20.1` `Plugin` crates backed by `bamabi_native_rt` (`DirtyRunCoalescer` / `SelectiveMutSlice` + `ChunkSliceQueryExt` + `SharedBridgeAppExt` + `net::StrataNetPacket`).
   - **Shared POD Networking (`strata_codegen::net` & `bamabi_native_rt::net`):** 184-byte `#[repr(C)]` `StrataNetPacket` (`"STNP"`) with bit-packed quantization and handshake `SCHEMA_FINGERPRINT` validation over `Messages<StrataNetPacket>` (ABI Slots 30–32).

---

## 3. Live Tooling (`strata_lsp` & `stratac`)

- **`strata-lsp` (`crates/strata_lsp`):** `server.rs` and `telemetry.rs` provide incremental Salsa diagnostics, hover cards (`#[repr(C)]` sizes/offsets/UUIDs/SI dimensions), canonical formatting, `strata/graphTelemetry` & `strata/ingestTelemetry` JSON-RPC endpoints, and CodeLenses enriched by Layer-0 64-byte `bamabi_sys::telemetry::SystemTelemetryDigest64` (`*b"BAMT"`) IPC frames (`Unix`/`Tcp`) and `bam/*` BRP JSON-RPC schema responses.
- **`stratac` (`crates/stratac`):** `cli.rs`, `commands.rs`, `graph_cmd.rs`, `sim_runner.rs`, and `net_sim_runner.rs` unify `check`, `fmt`, `layout`, `explain-par`, `test` (headless Bevy `sim_test` + virtual multi-world `net_sim_test`), `build`, `watch`, `onboard`, and `graph export|apply` with deterministic exit codes (`0`..`3`) and JSON output (`--format=json`).
