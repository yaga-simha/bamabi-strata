# Architecture: `strata_lsp`

## Modules
- `src/server.rs`: `StrataLspBackend` implementing `LanguageServer` over a persistent incremental `SemaDb` (`LspState` mapping `Url -> SourceFile`) plus pure stateless helpers (`compute_diagnostics`, `compute_hover`, `compute_formatting`, `compute_code_lenses`), custom JSON-RPC handlers (`strata/graphTelemetry`, `strata/ingestTelemetry`), UTF-16 position mapping, Theorem 0.1 parallelism summaries, and solved `AbiPod` hover cards.
- `src/telemetry.rs`: Layer-0 64-byte little-endian `bamabi_sys::SystemTelemetryDigest64` (`SYSTEM_TELEMETRY_MAGIC = *b"BAMT"`) codec, `SystemTelemetryDigestJson` serde mirror, `bam/component_schemas` BRP JSON-RPC parser/HTTP client (`parse_brp_schema_json`, `fetch_brp_component_schemas`), non-blocking `TelemetryEndpoint` (`Unix`/`Tcp`) subscriber (`spawn_telemetry_subscriber`), and monotonic `TelemetryStore`.
- `src/main.rs`: Async `tokio` stdio LSP server entrypoint (`strata-lsp`).
- `src/kani_proofs.rs`: Symbolic Kani proof `PO-S8`.
- `benches/lsp_bench.rs`: Criterion `0.8` (+ optional `hotpath-alloc`) microbench for `"BAMT"` 10k frame decoding, incremental body-edit diagnostics, and graph telemetry queries.
