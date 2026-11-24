# Agent Guide: `stratac`

Crate guide for **`stratac`** (`v0.3.0`) — Strata v2.0 compiler CLI, incremental Salsa watcher, Ed25519 `.bampack` packager, Graph IR CLI, Tier 3 `--target bevy-native` onboarder, and headless `bamabi_host` `sim_test` / `net_sim_test` runner.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `stratac` (`edition = "2024"`, MSRV `1.95`)
- **Dependencies:** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `bamabi_sys`, `bamabi_sdk_gen`, `bamabi_manifest`, `bamabi_trust`, `clap`, `notify-debouncer-full`, `serde`, `serde_json`, `sha2`, `tempfile`, `thiserror`, and optional `sim-runner` (`bamabi_host`, `bamabi_native_rt`, `bevy_app`, `bevy_ecs`, `stats_alloc`).

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **Deterministic Exit Codes (`exit_codes.rs`):** `0` = pass, `1` = compile/lint error, `2` = `sim_test` failure, `3` = parity/layout assertion failure.
- **Commands (`cli.rs`, `commands.rs`, `graph_cmd.rs`):** `check`, `fmt`, `layout`, `explain-par`, `test`, `build` (`jit`/`c99`/`rust-guest`, `--bampack`, `--sign`, `--key` / `--ephemeral-key`), `watch` (`--once`, `--sign`, `--key` / `--ephemeral-key`), `onboard` (`--target bevy-native`, `--static-console`, `--check`), and `graph {export, apply}`.
- **Headless Simulator & Net Runner (`sim_runner.rs`, `net_sim_runner.rs`):** Executes `sim_test` & multi-world `net_sim_test` over `bamabi_host`, steps `FixedUpdate`, and hashes canonical sorted archetype POD columns (`hash_world_pod_state`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p stratac --all-targets --all-features -- -D warnings
cargo test -p stratac --all-features
cargo test -p stratac --test parity_4way --release --all-features
cargo check -p stratac --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc -p stratac --no-deps --all-features
```
