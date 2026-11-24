# Agent Guide: `strata_docs`

Crate guide for **`strata_docs`** (`v0.3.0`) — `#![no_std]`, zero-external-dependency, zero-Bevy rustdoc documentation hub for `bamabi-strata`.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_docs` (`edition = "2024"`, MSRV `1.95`, `publish = false`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Allowed Dependencies:** **EMPTY `[dependencies]` table** (`#![no_std]`). NEVER add external, `bamabi*`, or `bevy*` dependencies.

---

## 2. Safety Policy
- Enforces `#![no_std]`, `#![forbid(unsafe_code)]`, and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`src/lib.rs`:** Compiles zero executable code and includes workspace Markdown guides (`README.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md`, `TESTING.md`, `BENCHMARKS.md`, `CHANGELOG.md`) under `#[cfg(doc)]` modules plus a `crates` index for unified `rustdoc` generation (`RUSTDOCFLAGS="-D warnings"`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_docs --all-targets --all-features -- -D warnings
cargo test -p strata_docs --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_docs --no-deps --all-features
cargo tree -p strata_docs | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
