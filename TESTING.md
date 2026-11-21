# Testing & Formal Verification Strategy (`bamabi-strata`)

`bamabi-strata` uses a 6-tier correctness and formal verification pyramid orchestrated locally and in GitHub Actions (`.github/workflows/ci.yml` and `.github/workflows/nightly.yml`) via `cargo xtask`.

---

## 1. Quick Commands

```bash
# Default CI gate (fmt, benchmark docs check, lint/isolation, full test matrix, quick bench)
cargo xtask ci

# Full gate including security/spellcheck audit and all Kani formal proofs (PO-S1..PO-S10)
cargo xtask ci --full

# Selective test tiers
cargo xtask test --unit
cargo xtask test --integration
cargo xtask test --proptest --cases 256
cargo xtask kani
```

---

## 2. Verification Tiers

### Tier 1: Formatting, Safety Policy, Isolation & Strict Lints (`cargo xtask fmt`, `cargo xtask lint`)
1. `cargo fmt --all -- --check` across every workspace member.
2. `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` verification on every crate entrypoint (`crates/*`, `benches/strata_bench`, `xtask`).
3. Transitive `cargo tree` zero-Bevy isolation check on all 8 Bevy-free crates (`strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, `xtask`).
4. `bamabi_native_rt --no-default-features --features static-console` check confirming zero `libloading` / `bamabi_host` dependencies.
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`.

### Tier 2: Module Unit Tests (`#[cfg(test)] mod tests`)
Co-located inside source modules across all 11 crates (`bamabi_native_rt`, `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `stratac`, `strata_bench`, `xtask`) testing edge cases, overflow behavior, negative MIR/codec rejections, CLI error handling, and statistical summarizers.

### Tier 3: Integration, Cookbook & 4-Way Differential Parity Tests
- `crates/strata_syntax/tests/cookbook_cst.rs` — lossless parse & idempotent format on all 6 cookbook games (`fixtures/cookbooks/01..06`), error recovery, operator tokenization.
- `crates/strata_sema/tests/sema_tests.rs` — bit-exact `ComponentUuid` / FNV-1a parity, Theorem 0.1 disjointness, Salsa early-cutoff memoization verification (`SemaDb::take_executed_queries`), `MAX_TERMS_PER_QUERY` enforcement, diagnostic error codes.
- `crates/strata_mir/tests/mir_tests.rs` — all 6 MIR lowering passes + end-to-end cookbook MIR verification.
- `crates/strata_codegen/tests/codegen_tests.rs` — strict ISO C99 compilation (`-std=c99 -Wall -Wextra -Wpedantic -Werror -fsyntax-only`), zero-unsafe Rust Guest, Tier 3 Bevy Native, and cross-target schema fingerprint parity.
- `crates/strata_jit/tests/jit_tests.rs` — Cranelift PIC emission + linker symbol export verification (`bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`).
- `crates/strata_lsp/tests/lsp_tests.rs` — diagnostics, hover layout cards, formatting, CodeLens timings, and BRP JSON-RPC ingestion.
- `crates/stratac/tests/cli_and_cookbooks.rs` — all 8 CLI subcommands, headless `sim_test`, 50-cycle hot reload, `.bampack` Ed25519 signing, `--static-console` onboarding (plus ignored 10,000-cycle soak test).
- `crates/stratac/tests/parity_4way.rs` — boots 4 independent Bevy `0.20` `World`s (Cranelift JIT, ISO C99, Safe Rust Guest `.cdylib`, Tier 3 Native `bamabi_native_rt`), runs 500 `FixedUpdate` frames + live `v1 -> v2` `reload_mod_from`, asserting bit-exact SHA-256 and FNV-1a world digests at frames `0`, `1`, `249`, `499`, `500`, `599`.

### Tier 4: Property-Based Tests (`proptest`)
- `crates/bamabi_native_rt/tests/proptest_native_rt.rs` — `DirtyRunCoalescer` interval oracle equivalence, `BitSet` boolean model, UTF-8 `InlineStr` truncation, `Fixed32`/`Fixed64` round-trips.
- `crates/strata_syntax/tests/proptest_syntax.rs` — arbitrary UTF-8 lossless lexing & panic-free parsing + semi-structured `stratafmt` idempotency.
- `crates/strata_sema/tests/proptest_sema.rs` — random `AbiPod` struct zero-implicit-padding invariants & Theorem 0.1 disjointness symmetry/soundness.
- `crates/strata_mir/tests/proptest_mir.rs` — monotonic CSR cell partitioning + random valid module lowering/verification.
- `crates/strata_lsp/tests/proptest_lsp.rs` — 64-byte binary wire codec round-trips and malformed frame rejection.

### Tier 5: Formal Verification with Kani (`PO-S1`..`PO-S10`, `cargo xtask kani`)

| Proof ID | Crate | Harness | Property Discharged (CBMC `0.68.0`) |
| :--- | :--- | :--- | :--- |
| **PO-S1** | `bamabi_native_rt` | `po_s1_grace_window_nonnegative_countdown` | 4-byte `#[repr(C)]` layout; `GraceWindow::tick` never produces `< 0.0` for finite inputs |
| **PO-S2** | `bamabi_native_rt` | `po_s2_input_buffer_and_timeline_cursor_soundness` | Exact `InputBuffer<4>` (`32 B`) & `TimelineCursor` (`16 B`) layouts; panic-free push/peek/window/stop |
| **PO-S3** | `bamabi_native_rt` | `po_s3_bounded_containers_reject_oob_safely` | `BitSet<2>`, `InlineStr<4>`, and `SmallVecPod<u32, 8>` stay strictly bounds-safe under corrupted lengths/OOB indices |
| **PO-S4** | `bamabi_native_rt` | `po_s4_fixed_point_total_arithmetic` | Total wrapping `Add`/`Sub`/`Mul`/`Neg` and non-zero `Div` freedom from overflow panics on `Fixed32`/`Fixed64` |
| **PO-S5** | `bamabi_native_rt` | `po_s5_dirty_run_coalescer_exact_oracle_parity` | All flushed `[s, e)` ranges satisfy `s < e <= row_count` and equal exact 16-bit dirty oracle mask |
| **PO-S6** | `strata_sema` | `po_s6_align_up_and_field_placement_zero_gap_invariants` | Checked alignment rounding & field placement produce strictly zero alignment gaps and clean overflow handling |
| **PO-S7** | `strata_sema` | `po_s7_theorem01_disjointness_and_conflict_symmetry` | `modes_conflict` symmetry + Theorem 0.1 bitmask disjointness soundness over all `u8` archetypes |
| **PO-S8** | `strata_lsp` | `po_s8_telemetry_digest64_wire_codec_bijection` | Exact 64-byte `SystemTelemetryDigest64` codec bijection & wrong-magic/length rejection |
| **PO-S9** | `strata_jit` | `po_s9_jit_abi_offsets_and_bounds` | All `BamHostApi` slot offsets pointer-aligned, distinct, and `< HOST_API_SLOTS * ptr_sz`; descriptors in-bounds |
| **PO-S10** | `strata_mir` | `po_s10_csr_cell_range_monotonic_partition_and_safety` | Monotonic CSR bucket partition exactness + panic-free out-of-bounds/corrupted offset rejection |

### Tier 6: Supply-Chain, Lockfile & Spelling Audit (`cargo xtask audit`)
Verifies `abi-lock.toml` parity against `Cargo.toml`, checks the pinned `bamabi-wire` revision in `Cargo.lock`, runs `typos` spellcheck (configured in `.typos.toml`), and runs `cargo deny check` (`deny.toml`) for RustSec advisories, SPDX license compliance, duplicate Bevy bans, and allowed registries/git sources.
