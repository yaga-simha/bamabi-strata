#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `salsa` incremental semantic analyzer, `AbiPod` padding solver, `ComponentUuid` / FNV-1a
//! wire parity engine, and Theorem 0.1 `FilteredAccessSet` prover for Strata v2.0.
//!
//! This crate enforces `#![forbid(unsafe_code)]` and has ZERO `bevy*` dependencies.

pub mod access;
pub(crate) mod authority;
pub mod checks;
pub mod db;
pub mod diagnostics;
pub mod hir;
pub mod hir_lower;
pub(crate) mod infer;
#[cfg(kani)]
mod kani_proofs;
pub mod layout;
pub mod types;

pub use access::{
    ConcurrencyGraph, ConflictEdge, FilteredAccessSet, QueryAccessDesc, QueryTerm, TermAccessMode,
};
pub use db::{SemaDb, SourceFile, analyze_source};
pub use diagnostics::{Diagnostic, FixIt, Severity, Span, codes};
pub use hir::{
    AnalyzedModule, AuthorityKind, HirAssignOp, HirAtomic, HirBinOp, HirCall, HirCompInit, HirExpr,
    HirFn, HirFor, HirForIter, HirFsmTransition, HirLValue, HirMatch, HirMatchArm, HirNetConfig,
    HirNetRpcMeta, HirNetSimTest, HirParam, HirParamKind, HirQuantizeSpec, HirQuery, HirQueryTerm,
    HirReduceEntry, HirRpc, HirSpawn, HirStmt, HirUnOp, NetComponentMeta, NetDirection,
    NetReliability,
};
pub use layout::{
    SolvedField, SolvedLayout, compute_net_schema_fingerprint, compute_wire_identity,
    solve_pod_layout,
};
pub use types::{QueryRowTerm, Ty, UnitDim};
