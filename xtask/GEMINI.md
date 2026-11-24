# Agent Guide: `xtask`

Crate guide for **`xtask`** (`v0.3.0`) — zero-external-dependency, zero-Bevy CI, lint, isolation, test, Kani, audit, and benchmark task runner (`cargo xtask`).

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `xtask` (`edition = "2024"`, MSRV `1.95`, `publish = false`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Allowed Dependencies:** **EMPTY `[dependencies]` table** (`std`-only). NEVER add external, `bamabi*`, or `bevy*` dependencies.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`src/main.rs`:** Implements `fmt`, `lint` (14-entrypoint safety checks, 8-crate zero-Bevy `cargo tree`, `static-console` isolation, `clippy -D warnings`, strict `rustdoc`, `--no-default-features` checks), `test`, `kani` (`PO-S1`..`PO-S12`, `PO-S14`..`PO-S16`), `bench`, `audit` (dynamic `abi-lock.toml` / `Cargo.lock` wire parity, `typos`, `cargo deny check`), `nightly`, and `ci`.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p xtask --all-targets --all-features -- -D warnings
cargo test -p xtask
RUSTDOCFLAGS="-D warnings" cargo doc -p xtask --no-deps --all-features
cargo tree -p xtask | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
