# Architecture: `strata_lsp`

## Modules
- `src/server.rs`: `StrataLspBackend` implementing `LanguageServer` and pure helpers (`compute_diagnostics`, `compute_hover`, `compute_formatting`, `compute_code_lenses`) backed by `strata_sema::analyze_source`, UTF-16 position mapping, Theorem 0.1 parallelism summaries, and solved `AbiPod` hover cards.
- `src/telemetry.rs`: 64-byte little-endian `SystemTelemetryDigest64` codec (`TELEMETRY_DIGEST_MAGIC = 0x5354_5254`), `bam/*` BRP JSON-RPC parser (`parse_brp_schema_json`), and thread-safe `TelemetryStore`.
- `src/main.rs`: Async `tokio` stdio LSP server entrypoint (`strata-lsp`).
- `src/kani_proofs.rs`: Symbolic Kani proof `PO-S8`.
