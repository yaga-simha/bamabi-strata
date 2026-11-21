# Agent Guide: `strata_jit`

Crate guide for **`strata_jit`** (`v0.3.0`) — zero-Bevy Cranelift PIC object emitter (`cranelift-object`) and sub-35ms `.dylib`/`.so` linker for `StrataMir` targeting `bamabi` (`ABI 0.3.0`).

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_jit` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_codegen`, `strata_mir`, `strata_sema`, `bamabi_sys`, `cranelift-codegen`, `cranelift-frontend`, `cranelift-module`, `cranelift-object`, `target-lexicon`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` (`cranelift-object` + `cc` shared-library linking emits native machine code safely in memory with zero `unsafe`).

---

## 3. Owned Surface & Frozen Contracts
- **`abi_offsets.rs`:** Programmatic wire offsets derived strictly from `bamabi_sys::offsets::*`, `BAM_HOST_API_SLOT_COUNT`, and `core::mem::offset_of!`. Zero hardcoded offsets.
- **`emitter.rs`:** PIC `ObjectModule` codegen emitting `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`, component/resource descriptors, and dense chunk loops (`KernelStmt`/`KernelExpr` + selective `&mut?` dirty-run coalescing).
- **`linker.rs`:** Platform shared-library linker (`cc -dynamiclib -Wl,-undefined,dynamic_lookup` / `cc -shared`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_jit --all-targets --all-features -- -D warnings
cargo test -p strata_jit --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_jit --no-deps --all-features
cargo tree -p strata_jit | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
