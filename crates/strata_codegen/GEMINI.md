# Agent Guide: `strata_codegen`

Crate guide for **`strata_codegen`** (`v0.3.0`) — zero-Bevy code generator producing strict ISO C99, safe `#![forbid(unsafe_code)]` Rust Guest (`.cdylib`), and Tier 3 static Bevy `Plugin` (`--target bevy-native`) artifacts from `StrataMir`.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_codegen` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_sema`, `strata_mir`, `bamabi_sys`, `bamabi_sdk_gen`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`expr.rs`:** Shared neutral per-row kernel extraction (`SystemPlan`, `KernelStmt`, `KernelExpr`) consumed by `c99`, `rust_guest`, `bevy_native`, and `strata_jit` so all 4 tiers execute bit-identical operations.
- **`c99.rs`:** Strict ISO C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) emitter targeting `bamabi.h` (`bamabi_sdk_gen::render_c99_header()`).
- **`rust_guest.rs`:** Safe `#![forbid(unsafe_code)]` `bamabi_guest` `.cdylib` emitter with bit-exact `ComponentUuid` / `SCHEMA_FINGERPRINT`.
- **`bevy_native.rs`:** Tier 3 static Bevy `Plugin` (`bamabi_native_rt`) emitter supporting both `shared-bridge` and `dlopen`-free `static-console` profiles.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_codegen --all-targets --all-features -- -D warnings
cargo test -p strata_codegen --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_codegen --no-deps --all-features
cargo tree -p strata_codegen | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
