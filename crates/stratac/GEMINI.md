# Agent Guide: `stratac`

Crate guide for **`stratac`** (`v0.3.0`) — Strata v2.0 compiler CLI, incremental Salsa watcher, Ed25519 `.bampack` packager, Tier 3 `--target bevy-native` onboarder, and headless `bamabi_host` `sim_test` runner.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `stratac` (`edition = "2024"`, MSRV `1.95`)
- **Dependencies:** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `bamabi_sys`, `bamabi_sdk_gen`, `bamabi_manifest`, `bamabi_trust`, `clap`, `serde`, `serde_json`, `sha2`, `tempfile`, `thiserror`, and optional `sim-runner` (`bamabi_host`, `bamabi_native_rt`, `bevy_app`, `bevy_ecs`).

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **Deterministic Exit Codes (`exit_codes.rs`):** `0` = pass, `1` = compile/lint error, `2` = `sim_test` failure, `3` = parity/layout assertion failure.
- **Commands (`commands.rs`, `cli.rs`):** `check`, `fmt`, `layout`, `explain-par`, `test`, `build` (C99, Rust Guest, JIT, `--bampack` / `--sign`), `watch` (`--once`, Salsa early-cutoff), `onboard` (`--target bevy-native`).
- **Headless Simulator & Parity (`sim_runner.rs`):** Loads `.dylib`/`.so` via `bamabi_host`, steps `FixedUpdate`, hashes canonical sorted archetype POD columns (SHA-256 + FNV-1a), and executes `sim_test` assertions.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p stratac --all-targets --all-features -- -D warnings
cargo test -p stratac --all-features
cargo check -p stratac --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc -p stratac --no-deps --all-features
```
