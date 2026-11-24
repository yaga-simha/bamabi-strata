#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Lossless green/red CST, `logos` DFA lexer, error-recovering LL(2)/Pratt parser, and canonical
//! `stratafmt` formatter for Strata v2.0.
//!
//! This crate enforces `#![forbid(unsafe_code)]` and carries zero `bevy*` or `bamabi*`
//! dependencies.

pub mod ast;
pub mod fmt;
pub mod graph_ir;
pub mod lexer;
pub mod parser;
pub mod syntax_kind;

pub use fmt::format_source;
pub use graph_ir::{
    GRAPH_IR_VERSION, GraphApplyResult, GraphAttrArg, GraphAttribute, GraphIrDelta,
    GraphIrDocument, GraphIrEdge, GraphIrError, GraphIrNode, GraphIrPatch, GraphIrSpan,
    GraphLayoutSidecar, GraphNodeKind, GraphNodePayload, NodeLayout, apply_graph_document,
    apply_graph_patch, export_graph_ir, export_graph_ir_with_sidecar, fallback_schema_fingerprint,
    load_sidecar, merge_sidecar, save_sidecar, sidecar_path_for,
};
pub use lexer::{Token, lex};
pub use parser::{Parse, ParseError, parse};
pub use rowan::{NodeOrToken, TextRange, TextSize};
pub use syntax_kind::{StrataLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};
