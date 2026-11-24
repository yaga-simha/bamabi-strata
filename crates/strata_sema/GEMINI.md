# Agent Guide: `strata_sema`

Crate guide for **`strata_sema`** (`v0.3.0`) — per-item `salsa` incremental semantic analyzer, bidirectional type inference, `AbiPod` layout solver, provenance `@authority` checker, `ComponentUuid` parity, and Theorem 0.1 prover.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_sema` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_syntax`, `bamabi_sys`, `salsa`, `rowan`, `indexmap`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **Diagnostics (`diagnostics.rs`):** Structured JSON diagnostics (`E00xx`..`E06xx`, `W04xx`) with byte spans and fix-its.
- **Types, Units & Inference (`types.rs`, `infer.rs`):** Static `Ty` (including `Option`, `Result`, `Borrow`, `Trigger`, `QueryRow`, `Record`), SI dimensions (`UnitDim`), and bidirectional inference (`infer.rs`) with explicit `HirExpr::Cast` insertion.
- **Layout & Wire Parity (`layout.rs`):** `@soa` splitting, `_strata_pad_N` zero-padding solver, `ComponentUuid` SipHash-2-4-128 & FNV-1a `SCHEMA_FINGERPRINT` parity, and synthesized `timeline`/`task`/`fsm`/`spatial_grid` layouts.
- **Access & Authority (`access.rs`, `authority.rs`):** Theorem 0.1 `FilteredAccessSet` prover (`MAX_TERMS_PER_QUERY = 32`, `MAX_QUERIES_PER_SYSTEM = 16`), `ConcurrencyGraph`, and unified `Provenance`/`AuthoritySet`/`PlaceOrigin` `@authority` verifier (`E0501`).
- **Modular Checks & Per-Item Salsa DB (`checks/*`, `db.rs`, `hir.rs`, `hir_lower.rs`):** `checks/{mod,schema,attrs,effects,items}.rs` + `SemaDb` per-item queries (`parse_file`, `module_env_summary`, `item_green_trees`, `item_green`, `analyze_item`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_sema --all-targets --all-features -- -D warnings
cargo test -p strata_sema --all-features
cargo xtask kani --crate strata_sema --timeout 120
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_sema --no-deps --all-features
cargo tree -p strata_sema | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
