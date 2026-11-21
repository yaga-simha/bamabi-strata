#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Lossless green/red CST, `logos` DFA lexer, error-recovering LL(2)/Pratt parser, and canonical
//! `stratafmt` formatter for Strata v2.0.
//!
//! This crate enforces `#![forbid(unsafe_code)]` and carries zero `bevy*` or `bamabi*`
//! dependencies.

pub mod ast;
pub mod fmt;
pub mod lexer;
pub mod parser;
pub mod syntax_kind;

pub use fmt::format_source;
pub use lexer::{Token, lex};
pub use parser::{Parse, ParseError, parse};
pub use rowan::{NodeOrToken, TextRange, TextSize};
pub use syntax_kind::{StrataLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};
