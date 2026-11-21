# Architecture of `bamabi-strata` (Strata v2.0)

`bamabi-strata` sits at **Layer 2** of the `bamabi` ecosystem alongside `bamabi-core`, consuming the **Layer 0** wire ABI contract (`bamabi_sys`, `bamabi_sdk_gen`, `bamabi_guest`, `ABI 0.3.0` / `0x0003_0000`) and **Layer 1** signing/manifest crates (`bamabi_manifest`, `bamabi_trust`).

---

## 1. Crate Dependency DAG & Isolation Boundaries

```text
                        ┌─────────────────────────────────────────┐
                        │                 stratac                 │  CLI + headless sim_test
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
                  │              strata_sema              │  Salsa 0.28.5, Layouts, Theorem 0.1
                  └───────────────────┬───────────────────┘
                                      │
                                      ▼
                  ┌───────────────────────────────────────┐
                  │             strata_syntax             │  logos + rowan + stratafmt
                  └───────────────────────────────────────┘

  Independent tooling crates:
  - `xtask`        : Zero external deps, zero Bevy deps (#![forbid(unsafe_code)])
  - `strata_docs`  : Zero external deps, #![no_std], zero Bevy deps (#![forbid(unsafe_code)])
  - `strata_bench` : Compiler & 4-tier Bevy runtime throughput harness
```

### Non-Negotiable Isolation Rules

1. **8/11 Zero-Bevy Crates:** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, and `xtask` contain zero transitive `bevy*` dependencies. This keeps compiler, IDE, and verification builds lightweight and guarantees guest artifact emitters cannot leak host Bevy internals.
2. **Universal `#![forbid(unsafe_code)]`:** Every workspace crate forbids `unsafe`. C-ABI struct layouts and slot tables are constructed symbolically (`bamabi_sys::offsets::*`, `core::mem::offset_of!`, `BAM_HOST_API_SLOT_COUNT`) or generated as source/object files (`strata_codegen`, `strata_jit`).
3. **`static-console` Graduation Path:** Applications compiled with `--target bevy-native --static-console` link `bamabi_native_rt` with `--no-default-features --features static-console`, stripping `libloading` and `bamabi_host` completely for consoles or static targets that forbid dynamic loading.

---

## 2. Compilation Pipeline (Frontend -> 3 Tiers)

1. **Lexing & Lossless CST (`strata_syntax`):**
   - `logos` DFA tokenizer covers every input UTF-8 byte without gaps (preserving range tokens next to unit literals like `0..10_m`).
   - LL(2) + Pratt error-recovering parser produces an immutable `rowan` green/red tree with lossless round-trip guarantees (`parse(s).syntax().text() == s`).
   - `stratafmt` normalizes whitespace and comments idempotently.

2. **Incremental Semantic Analysis (`strata_sema`):**
   - Backed by `salsa` `0.28.5` (`SemaDb`): extracts item schema signatures first (`schema_signature`) so body-only edits inside `sys`/`obs`/`fn`/`sim_test` hit early cutoff without invalidating downstream `#[repr(C)]` layout resolution or UUID derivation.
   - **SI Dimensional Algebra (`types.rs`):** Statically verifies unit exponents (`sec`, `meters`, `rad`, `frames`).
   - **AbiPod Layout Solver (`layout.rs`):** Inserts explicit zero-initialized `_strata_pad_N` `[u8; K]` fields at every alignment/tail gap and computes bit-exact `ComponentUuid` (SipHash-2-4-128) and FNV-1a `SCHEMA_FINGERPRINT` values matching `bamabi_macros`.
   - **Theorem 0.1 Concurrency Prover (`access.rs`):** Computes `FilteredAccessSet` masks (`With<T>` / `Without<T>`, `@soa` disjoint hot/cold strata, sub-field projections) and enforces `bamabi_sys::MAX_TERMS_PER_QUERY` / `MAX_QUERIES_PER_SYSTEM`.

3. **Backend-Neutral SSA CFG IR & Passes (`strata_mir`):**
   - Lowers typed HIR into `MirModule` CFGs and runs six verified transformation passes:
     - `optional_split`: hoists `?T` chunk presence checks (`OptionalChunkIsPresent`) out of per-row inner loops.
     - `tick_coalesce`: rewrites `&mut? T` writes to `IterColWriteUntracked` + register-held dirty-run tracking (`DirtyRunInit`/`DirtyRunRecordRow`/`IterMarkChangedRange`).
     - `state_machines`: expands `timeline`, stackless `task`, and priority-ordered `fsm` declarations into sparse-set components + tick systems.
     - `spatial_csr`: synthesizes deterministic 2-pass counting-sort CSR rebuild systems ordered immediately prior to the earliest scheduled reader.
     - `atomic_tx`: rewrites `atomic { ... } on_rollback { ... }` into `CmdCheckpoint`, shadowed writes, and rollback blocks.
     - `determinism`: clears FMA contraction (`allow_fma = false`) and enforces deterministic math / reduction ordering under `@deterministic`.

4. **Three Execution Tiers + Live Cranelift JIT:**
   - **Tier 1a — Cranelift PIC JIT (`strata_jit`):** Lowers `MirFunction` plans directly to `cranelift-object` relocatable object code using programmatic `bamabi_sys::offsets::*` and `core::mem::offset_of!` offsets, then links a platform shared library (`.dylib`/`.so`/`.dll`). Supports sub-35ms hot reloads in `stratac watch`.
   - **Tier 1b — Strict ISO C99 (`strata_codegen::c99`):** Emits standalone `-std=c99 -Wall -Wextra -Wpedantic -Werror` C99 (`-ffp-contract=off` for cross-backend IEEE-754 bit parity) against `bamabi_sdk_gen`-generated `bamabi.h`.
   - **Tier 2 — Safe Rust Guest `.cdylib` (`strata_codegen::rust_guest`):** Emits `#![forbid(unsafe_code)]`, zero-Bevy `bamabi_guest` crates packaged into Ed25519-signed `.bampack` bundles via `bamabi_trust`.
   - **Tier 3 — Static Bevy Native (`strata_codegen::bevy_native`):** Graduates modules into `#![forbid(unsafe_code)]` Bevy `0.20.1` `Plugin` crates backed by `bamabi_native_rt` (`DirtyRunCoalescer` / `SelectiveMutSlice` + `ChunkSliceQueryExt`).

---

## 3. Live Tooling (`strata_lsp` & `stratac`)

- **`strata-lsp`** provides live diagnostics, hover cards showing solved `#[repr(C)]` sizes/offsets/UUIDs/unit dimensions, canonical formatting edits, and CodeLenses enriched by 64-byte `SystemTelemetryDigest64` frames and `bam/*` BRP JSON-RPC schema responses.
- **`stratac`** unifies `check`, `fmt`, `layout`, `explain-par`, `test` (headless Bevy `sim_test` runner), `build`, `watch`, and `onboard` with deterministic process exit codes (`0`..`3`) and JSON machine output (`--format=json`).
