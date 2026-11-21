# Agent Guide: `strata_mir`

Crate guide for **`strata_mir`** (`v0.3.0`) — backend-neutral SSA CFG MIR and lowering passes for Strata v2.0.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_mir` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_sema`, `strata_syntax`, `bamabi_sys`, `indexmap`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **SSA CFG IR (`ir.rs`):** Frozen `StrataMir` (`MirModule`, `MirSystem`, `MirObserver`, `BasicBlock`, `Inst`, `Terminator`) with explicit wire-mapped ECS instructions referencing `bamabi-wire` slots.
- **Lowering & Passes (`lower.rs`, `passes/`):**
  - `optional_split`: Chunk-hoisted `?T` loop splitter.
  - `tick_coalesce`: `&mut?` selective tick-range coalescer (Slots 14–15).
  - `state_machines`: `timeline`, `task` coroutine, and `fsm` desugaring.
  - `spatial_csr`: `spatial_grid` & `spatial_history` CSR `Resource` + 2-pass counting-sort rebuild synthesis.
  - `atomic_tx`: `atomic { ... } on_rollback { ... }` checkpoints (Slots 63–64) + stack-shadowing.
  - `determinism`: `@deterministic` FMA/transcendental enforcement.
- **Verifier (`verify.rs`):** Structural SSA/CFG well-formedness & ABI reference checker.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_mir --all-targets --all-features -- -D warnings
cargo test -p strata_mir --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_mir --no-deps --all-features
cargo tree -p strata_mir | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
