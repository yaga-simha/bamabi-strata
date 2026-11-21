#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Zero-Bevy `tower-lsp` Language Server (`strata-lsp`) and live IPC telemetry subscriber
//! for Strata v2.0.
//!
//! Integrates `strata_sema::SemaDb` incremental diagnostics, `strata_syntax::fmt` formatting,
//! solved `AbiPod` layout / `ComponentUuid` / SI-unit hover cards, and 64-byte
//! `SystemTelemetryDigest64` + `bam/*` BRP schema CodeLens annotations.

#[cfg(kani)]
mod kani_proofs;
pub mod server;
pub mod telemetry;

pub use server::{
    StrataLspBackend, compute_code_lenses, compute_diagnostics, compute_formatting, compute_hover,
};
pub use telemetry::{
    BrpSchemaEntry, SystemTelemetryDigest64, TELEMETRY_DIGEST_MAGIC, TELEMETRY_DIGEST_VERSION,
    TelemetryError, TelemetryStore, parse_brp_schema_json, system_name_hash,
};
