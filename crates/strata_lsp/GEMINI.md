# Agent Guide: `strata_lsp`

Crate guide for **`strata_lsp`** (`v0.3.0`) — zero-Bevy IDE Language Server (`tower-lsp`) and live IPC subscriber for Layer-0 64-byte `SystemTelemetryDigest64` (`*b"BAMT"`) frames and `bam/*` BRP JSON-RPC schemas.

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
- **`telemetry.rs`:** Re-exports Layer-0 `bamabi_sys::{SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64, fnv1a_64_hash_system, fnv1a_64_str, TELEMETRY_FLAG_*}` (`*b"BAMT"`), `SystemTelemetryDigestJson`, `parse_brp_schema_json` (`result.components[]` & `result.schemas[]`), `TelemetryEndpoint` (`Unix`/`Tcp`), `spawn_telemetry_subscriber`, `fetch_brp_component_schemas`, and `TelemetryStore`.
- **`server.rs`:** `StrataLspBackend` (`tower_lsp::LanguageServer`) providing incremental Salsa diagnostics (`db.parse_file` + `analyze_module`), layout/UUID/SI-unit hover cards, `stratafmt` formatting, `@par` + live telemetry CodeLens annotations, and custom JSON-RPC (`strata/graphTelemetry`, `strata/ingestTelemetry`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_lsp --all-targets --all-features -- -D warnings
cargo test -p strata_lsp --all-features
cargo xtask kani --crate strata_lsp --timeout 120
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_lsp --no-deps --all-features
cargo tree -p strata_lsp | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
