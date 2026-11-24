# Testing & Formal Verification Strategy (`bamabi-strata`)

`bamabi-strata` uses a 6-tier correctness and formal verification pyramid orchestrated locally and in GitHub Actions (`.github/workflows/ci.yml` and `.github/workflows/nightly.yml`) via `cargo xtask`.

---

## 1. Quick Commands

```bash
# Default CI gate (fmt, benchmark docs check, lint/isolation, full test matrix, quick bench)
cargo xtask ci

# Full gate including security/spellcheck audit and all 15 Kani formal proofs (PO-S1..PO-S12, PO-S14..PO-S16)
cargo xtask ci --full

# Selective test tiers
cargo xtask test --unit
cargo xtask test --integration
cargo xtask test --proptest --cases 256
cargo xtask kani

# Opaque-box Phase 3 E2E suite (Tiers 1..4)
python3 fixtures/e2e_phase3/run_e2e.py --tier all
```

---

## 2. Verification Tiers

### Tier 1: Formatting, Safety Policy, Isolation & Strict Lints (`cargo xtask fmt`, `cargo xtask lint`)
1. `cargo fmt --all -- --check` across every workspace member.
2. `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` verification on all 14 crate entrypoints across all 12 workspace crates (`crates/*`, `benches/strata_bench`, `benches/strata_profile`, `xtask`).
3. Transitive `cargo tree` zero-Bevy isolation check on all 8 Bevy-free crates (`strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, `xtask`).
4. `bamabi_native_rt --no-default-features --features static-console` check confirming zero `libloading` / `bamabi_host` dependencies.
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`.

### Tier 2: Module Unit Tests (`#[cfg(test)] mod tests`)
Co-located inside source modules across workspace crates (`bamabi_native_rt`, `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `stratac`, `strata_bench`, `strata_profile`, `xtask`) testing edge cases, overflow behavior, negative MIR/codec rejections, CLI error handling, and statistical summarizers.

### Tier 3: Integration, Cookbook, 4-Way Parity & Opaque E2E Suites
- `crates/strata_syntax/tests/cookbook_cst.rs` & `tests/graph_ir_roundtrip.rs` — lossless parse & idempotent format on all 8 cookbooks (`fixtures/cookbooks/01..08`), plus Graph IR JSON & `.strata.graph.json` CST round-trips.
- `crates/strata_sema/tests/sema_tests.rs` — bit-exact `ComponentUuid` / FNV-1a parity, Theorem 0.1 disjointness, per-item Salsa early-cutoff memoization verification (`SemaDb::take_executed_queries`), `MAX_TERMS_PER_QUERY` enforcement, bidirectional `infer.rs` / `authority.rs` soundness, and `verify_effects` (`despawns`, `triggers`, `emits`).
- `crates/strata_mir/tests/mir_tests.rs` — all 6 MIR lowering passes (pre-image `atomic_tx`, 2-pass `spatial_csr`, `tick_coalesce` `OptionalWrite`, `IterUpCascade`, `ArrayStore`) + cookbook MIR verification.
- `crates/strata_codegen/tests/codegen_tests.rs` & `tests/net_codegen_tests.rs` — strict ISO C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`), Safe Rust Guest, Tier 3 Bevy Native live execution (2-pass CSR, `IterUpCascade`, `ArrayStore`, `OptionalWrite`, `atomic`, `NB-1`/`NB-2`/`NB-3`, named-object arrays), and `StrataNetPacket` codecs.
- `crates/strata_jit/tests/jit_tests.rs` & `tests/net_jit_tests.rs` — Cranelift PIC emission + linker symbol export verification + live C99 vtable host execution (`Fix64` restoring division, 2-pass CSR, `IterUpCascade`, `atomic` rollback) + 73-slot ABI & `StrataNetPacket` checks.
- `crates/strata_lsp/tests/lsp_tests.rs` — diagnostics, hover layout cards, formatting, CodeLens timings, `strata/graphTelemetry`, `"BAMT"` `SystemTelemetryDigest64`, and BRP JSON-RPC ingestion.
- `crates/stratac/tests/{cli_and_cookbooks,graph_cli,net_sim_tests}.rs` — all 9 CLI subcommands (`check`, `fmt`, `layout`, `explain-par`, `test`, `build`, `watch`, `onboard`, `graph`), headless `sim_test` & `net_sim_test`, 50-cycle hot reload, `.bampack` Ed25519 signing, `--static-console` onboarding (plus ignored 10,000-cycle soak test).
- `crates/stratac/tests/parity_4way.rs` — 9 tests booting 4 independent Bevy `0.20` `World`s (Cranelift JIT, ISO C99, Safe Rust Guest `.cdylib`, Tier 3 Native `bamabi_native_rt`), asserting bit-exact SHA-256 and FNV-1a world digests across 500 `FixedUpdate` frames, live `v1 -> v2` reloads, `v1 -> v2` Slot 67 migrations, `atomic` rollbacks, 2-pass CSR spatial grids, Slot 58 `iter_up_cascade`, `fix64` division, and `Option` queries.
- `fixtures/e2e_phase3/run_e2e.py` — opaque-box CLI & LSP E2E runner across Tiers 1–4.

### Tier 4: Property-Based Tests (`proptest`)
- `crates/bamabi_native_rt/tests/proptest_native_rt.rs` — `DirtyRunCoalescer` interval oracle equivalence, `BitSet` boolean model, UTF-8 `InlineStr` truncation, `Fixed32`/`Fixed64` round-trips.
- `crates/strata_syntax/tests/proptest_syntax.rs` — arbitrary UTF-8 lossless lexing & panic-free parsing + semi-structured `stratafmt` idempotency.
- `crates/strata_sema/tests/proptest_sema.rs` — random `AbiPod` struct zero-implicit-padding invariants, Theorem 0.1 disjointness symmetry/soundness, and nested `Option`/record/authority panic-freedom.
- `crates/strata_mir/tests/proptest_mir.rs` — monotonic CSR cell partitioning + random valid `atomic`/`spatial` module lowering/verification.
- `crates/strata_lsp/tests/proptest_lsp.rs` — 64-byte `"BAMT"` binary wire codec round-trips and malformed frame rejection.

### Tier 5: Formal Verification with Kani (`PO-S1`..`PO-S12`, `PO-S14`..`PO-S16`, `cargo xtask kani`)

| Proof ID | Crate | Harness | Property Discharged (CBMC `0.68.0`) |
| :--- | :--- | :--- | :--- |
| **PO-S1** | `bamabi_native_rt` | `po_s1_grace_window_nonnegative_countdown` | 4-byte `#[repr(C)]` layout; `GraceWindow::tick` never produces `< 0.0` for finite inputs |
| **PO-S2** | `bamabi_native_rt` | `po_s2_input_buffer_and_timeline_cursor_soundness` | Exact `InputBuffer<4>` (`32 B`) & `TimelineCursor` (`16 B`) layouts; panic-free push/peek/window/stop |
| **PO-S3** | `bamabi_native_rt` | `po_s3_bounded_containers_reject_oob_safely` | `BitSet<2>`, `InlineStr<4>`, and `SmallVecPod<u32, 8>` stay strictly bounds-safe under corrupted lengths/OOB indices |
| **PO-S4** | `bamabi_native_rt` | `po_s4_fixed_point_total_arithmetic` | Total wrapping `Add`/`Sub`/`Mul`/`Neg` and non-zero `Div` freedom from overflow panics on `Fixed32`/`Fixed64` |
| **PO-S5** | `bamabi_native_rt` | `po_s5_dirty_run_coalescer_exact_oracle_parity` | All flushed `[s, e)` ranges satisfy `s < e <= row_count` and equal exact 16-bit dirty oracle mask |
| **PO-S6** | `strata_sema` | `po_s6_align_up_and_field_placement_zero_gap_invariants` | Checked alignment rounding & field placement produce strictly zero alignment gaps and clean overflow handling |
| **PO-S7** | `strata_sema` | `po_s7_theorem01_disjointness_and_conflict_symmetry` | `modes_conflict` symmetry + Theorem 0.1 bitmask disjointness soundness over all `u8` archetypes |
| **PO-S8** | `strata_lsp` | `po_s8_system_telemetry_digest64_wire_roundtrip_and_rejection` | Exact 64-byte `"BAMT"` `SystemTelemetryDigest64` codec bijection & wrong-magic/version/length rejection |
| **PO-S9** | `strata_jit` | `po_s9_jit_abi_offsets_and_bounds` | All 73 `BamHostApi` slot offsets pointer-aligned, distinct, and `< HOST_API_SLOTS * ptr_sz`; descriptors in-bounds |
| **PO-S10** | `strata_mir` | `po_s10_csr_cell_range_monotonic_partition_and_safety` | Monotonic CSR bucket partition exactness + panic-free out-of-bounds/corrupted offset rejection |
| **PO-S11** | `strata_sema` | `po_s11_authority_lattice_and_place_origin_soundness` | `AuthoritySet` / `PlaceOrigin` lattice soundness & provenance join invariants |
| **PO-S12** | `strata_sema` | `po_s12_compound_ty_preservation_without_erasure` | Compound `Ty` (`Option`, `Result`, `Borrow`, `Trigger`, `QueryRow`, `Record`) equality & tag preservation |
| **PO-S14** | `strata_mir` | `po_s14_atomic_tx_preimage_undo_log_restores_on_rollback` | Pre-image undo log restores exact pre-transaction state across repeated field writes and rollback |
| **PO-S15** | `strata_mir` | `po_s15_spatial_csr_2pass_partition_and_query_disc_clamping` | 2-pass CSR bucket partition exactness and query disc cell-window clamping soundness |
| **PO-S16** | `bamabi_native_rt` | `po_s16_fixed64_preshifted_division_parity_and_totality` | `Fixed64` preshifted `i128` division parity with `div_restoring` & zero-divisor totality |

### Tier 6: Supply-Chain, Lockfile & Spelling Audit (`cargo xtask audit`)
Verifies `abi-lock.toml` parity against `Cargo.toml`, checks `bamabi-wire` revision/overlay parity in `Cargo.lock`, runs `typos` spellcheck (configured in `.typos.toml`), and runs `cargo deny check` (`deny.toml`) for RustSec advisories, SPDX license compliance, duplicate Bevy bans, and allowed registries/git sources.
