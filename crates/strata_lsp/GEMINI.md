# Agent Guide: `strata_lsp`

Crate guide for **`strata_lsp`** (`v0.3.0`) — zero-Bevy IDE Language Server (`tower-lsp`) and live IPC subscriber for 64-byte `SystemTelemetryDigest64` frames and `bam/*` BRP JSON-RPC schemas.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_lsp` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Dependencies:** `strata_syntax`, `strata_sema`, `bamabi_sys`, `tower-lsp`, `tokio`, `serde`, `serde_json`, `thiserror`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`telemetry.rs`:** Fixed 64-byte little-endian `SystemTelemetryDigest64` frame codec, `bam/*` BRP JSON-RPC schema ingestion, and thread-safe `TelemetryStore`.
- **`server.rs`:** `StrataLspBackend` (`tower_lsp::LanguageServer`) providing incremental Salsa diagnostics, layout/UUID/SI-unit hover cards, `stratafmt` document formatting, and `@par` + live telemetry CodeLens annotations.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_lsp --all-targets --all-features -- -D warnings
cargo test -p strata_lsp --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_lsp --no-deps --all-features
cargo tree -p strata_lsp | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
