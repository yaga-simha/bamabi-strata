#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `salsa` incremental semantic analyzer, `AbiPod` padding solver, `ComponentUuid` / FNV-1a
//! wire parity engine, and Theorem 0.1 `FilteredAccessSet` prover for Strata v2.0.
//!
//! This crate enforces `#![forbid(unsafe_code)]` and has ZERO `bevy*` dependencies.

pub mod access;
pub mod checks;
pub mod db;
pub mod diagnostics;
pub mod hir;
#[cfg(kani)]
mod kani_proofs;
pub mod layout;
pub mod types;

pub use access::{
    ConcurrencyGraph, ConflictEdge, FilteredAccessSet, QueryAccessDesc, QueryTerm, TermAccessMode,
};
pub use db::{SemaDb, SourceFile, analyze_source};
pub use diagnostics::{Diagnostic, FixIt, Severity, Span, codes};
pub use hir::AnalyzedModule;
pub use layout::{SolvedField, SolvedLayout, compute_wire_identity, solve_pod_layout};
pub use types::{Ty, UnitDim};
