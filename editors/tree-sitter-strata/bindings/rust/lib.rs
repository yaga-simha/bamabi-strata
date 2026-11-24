#![warn(missing_docs)]

//! Rust bindings for the [`tree-sitter`](https://tree-sitter.github.io/) Strata v2.0 grammar.

use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn tree_sitter_strata() -> *const ();
}

/// The tree-sitter [`LanguageFn`] for Strata v2.0.
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_strata) };

/// The content of the [`node-types.json`] file for Strata v2.0.
pub const NODE_TYPES: &str = include_str!("../../src/node-types.json");

/// Reference syntax highlighting query (`queries/highlights.scm`) for Strata v2.0.
pub const HIGHLIGHTS_QUERY: &str = include_str!("../../queries/highlights.scm");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_fn_and_metadata_are_non_empty() {
        let _lang = LANGUAGE;
        assert!(NODE_TYPES.contains("component_declaration"));
        assert!(HIGHLIGHTS_QUERY.contains("@keyword"));
    }
}
