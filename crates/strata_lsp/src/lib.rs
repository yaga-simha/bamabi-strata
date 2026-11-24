#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Zero-Bevy `tower-lsp` Language Server for **Strata v2.0**.
//!
//! Provides incremental `salsa`-backed semantic diagnostics, hover type/SI-unit/layout popovers,
//! canonical source formatting, Theorem 0.1 concurrency graph JSON-RPC (`strata/graphTelemetry`),
//! live 64-byte [`SystemTelemetryDigest64`] (`"BAMT"`) IPC subscription, and `bam/*` BRP schema
//! CodeLens annotations.

pub mod kani_proofs;
pub mod server;
pub mod telemetry;

pub use server::{
    GraphNodeTelemetry, GraphTelemetryParams, GraphTelemetryResponse, IngestTelemetryParams,
    IngestTelemetryResponse, StrataLspBackend, TelemetryFrameInput, build_lsp_service,
    compute_code_lenses, compute_diagnostics, compute_formatting, compute_hover,
};
pub use telemetry::{
    BRP_METHOD_BAM_COMPONENT_SCHEMAS, BRP_METHOD_BAM_HOT_RELOAD, BRP_METHOD_BAM_LIST_MODS,
    BRP_METHOD_BAM_SYSTEM_METRICS, BrpSchemaEntry, SYSTEM_TELEMETRY_DIGEST_SIZE,
    SYSTEM_TELEMETRY_DIGEST_VERSION, SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64,
    SystemTelemetryDigestJson, TELEMETRY_DIGEST_MAGIC, TELEMETRY_DIGEST_VERSION,
    TELEMETRY_FLAG_BUDGET_BREACHED, TELEMETRY_FLAG_FAULTED, TELEMETRY_FLAG_QUARANTINED,
    TELEMETRY_FLAG_SUMMARY_TICK_ACTIVE, TelemetryEndpoint, TelemetryError, TelemetryFrameError,
    TelemetrySliceError, TelemetryStore, TelemetrySubscription, decode_digest_slice,
    fetch_brp_component_schemas, fnv1a_64_hash_system, fnv1a_64_str, new_digest,
    parse_brp_schema_json, spawn_telemetry_subscriber, system_name_hash,
};
