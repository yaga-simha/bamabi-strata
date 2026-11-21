# Agent Guide: `strata_sema`

Crate guide for **`strata_sema`** (`v0.3.0`) — `salsa` incremental semantic analyzer, `AbiPod` layout solver, `ComponentUuid` parity, and Theorem 0.1 `FilteredAccessSet` prover.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_sema` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_syntax`, `bamabi_sys`, `salsa`, `indexmap`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **Diagnostics (`diagnostics.rs`):** Structured JSON diagnostics (`E01xx`, `E02xx`, `E03xx`, `W04xx`) with byte spans and machine-applicable fix-its.
- **Types & Units (`types.rs`):** Strata type system and SI dimensional analysis (`sec`, `ms`, `hz`, `frames`, `rad`, `deg`, `meters`, `mps`, `mps2`).
- **Layout & Wire Parity (`layout.rs`):** `@soa` stratum splitting, explicit zero-padding solver (`_strata_pad_N`), `bamabi_sys::ComponentUuid` SipHash-2-4-128 & FNV-1a `SCHEMA_FINGERPRINT` parity, and synthesized `timeline`/`task`/`fsm`/`spatial_grid` layouts.
- **Access & Parallelism (`access.rs`):** Theorem 0.1 `FilteredAccessSet` disjointness prover, intra-system aliasing detection (`E0201`), `MAX_TERMS_PER_QUERY`/`MAX_QUERIES_PER_SYSTEM` limits, `assert_par`, and `ConcurrencyGraph`.
- **HIR & Incremental DB (`hir.rs`, `checks.rs`, `db.rs`):** `salsa` early-cutoff query DB and frozen `AnalyzedModule` consumed by `strata_mir`.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_sema --all-targets --all-features -- -D warnings
cargo test -p strata_sema --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_sema --no-deps --all-features
cargo tree -p strata_sema | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
