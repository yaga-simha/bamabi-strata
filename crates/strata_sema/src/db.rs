//! Incremental `salsa` query database with early-cutoff equality for sub-35ms live-dev reloads.

use crate::access::ConcurrencyGraph;
use crate::checks::{analyze_module_full, extract_schema_signature_text, solve_module_layouts};
use crate::hir::AnalyzedModule;
use crate::layout::SolvedLayout;
use indexmap::IndexMap;
use std::sync::{Arc, Mutex};

/// Salsa input and tracked query definitions (isolated module scoping `missing_docs` to Salsa macro
/// expansions).
#[allow(missing_docs)]
pub mod queries {
    use super::*;

    /// Incremental input representing one `.strata` source file.
    #[salsa::input]
    pub struct SourceFile {
        #[returns(ref)]
        pub path: String,
        #[returns(ref)]
        pub text: String,
    }

    /// Extracts only item/schema headers (stripping `sys`/`obs`/`fn`/`sim_test` bodies) so body-only
    /// edits trigger early-cutoff and skip downstream layout/UUID re-computation.
    #[salsa::tracked]
    pub fn schema_signature(db: &dyn salsa::Database, file: SourceFile) -> String {
        extract_schema_signature_text(file.text(db))
    }

    /// Computes serialized JSON of all solved `#[repr(C)]` layouts and `ComponentUuid` / FNV-1a
    /// fingerprints; skipped entirely on body-only edits via `schema_signature` early cutoff.
    #[salsa::tracked]
    pub fn resolve_layouts_json(db: &dyn salsa::Database, file: SourceFile) -> String {
        let sig = schema_signature(db, file);
        let path = file.path(db);
        let solved = solve_module_layouts(path, sig);
        serde_json::to_string(&solved.layouts).unwrap_or_default()
    }

    /// Full incremental semantic analysis serialized with early-cutoff equality.
    #[salsa::tracked]
    pub fn analyze_module_json(db: &dyn salsa::Database, file: SourceFile) -> String {
        // Depend on `resolve_layouts_json` so Salsa tracks schema-level invalidation cleanly.
        let _layouts = resolve_layouts_json(db, file);
        let analyzed = analyze_module_full(file.path(db), file.text(db));
        serde_json::to_string(&analyzed).unwrap_or_default()
    }

    /// Extracts serialized Theorem 0.1 [`ConcurrencyGraph`] for `stratac explain-par`.
    #[salsa::tracked]
    pub fn concurrency_graph_json(db: &dyn salsa::Database, file: SourceFile) -> String {
        let mod_json = analyze_module_json(db, file);
        let parsed: AnalyzedModule =
            serde_json::from_str(mod_json).expect("valid analyzed module JSON");
        serde_json::to_string(&parsed.concurrency_graph).unwrap_or_default()
    }
}

pub use queries::SourceFile;

/// Concrete incremental semantic database implementing `salsa::Database`.
#[salsa::db]
#[derive(Clone)]
pub struct SemaDb {
    storage: salsa::Storage<Self>,
    executed_queries: Arc<Mutex<Vec<String>>>,
}

impl Default for SemaDb {
    fn default() -> Self {
        Self::new()
    }
}

impl SemaDb {
    /// Creates an empty incremental semantic database with optional query execution logging.
    pub fn new() -> Self {
        let executed_queries = Arc::new(Mutex::new(Vec::new()));
        let log_sink = Arc::clone(&executed_queries);
        let storage = salsa::Storage::new(Some(Box::new(move |event: salsa::Event| {
            if let salsa::EventKind::WillExecute { database_key } = event.kind
                && let Ok(mut guard) = log_sink.lock()
            {
                guard.push(format!("{database_key:?}"));
            }
        })));
        Self {
            storage,
            executed_queries,
        }
    }

    /// Creates a new [`SourceFile`] input inside this database.
    pub fn new_source(&self, path: impl Into<String>, text: impl Into<String>) -> SourceFile {
        SourceFile::new(self, path.into(), text.into())
    }

    /// Clears and returns all recorded `WillExecute` query names since the last call (used to
    /// verify early-cutoff incremental memoization).
    pub fn take_executed_queries(&self) -> Vec<String> {
        self.executed_queries
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    /// Queries all solved component/stratum layouts with Salsa incremental memoization.
    pub fn resolve_layouts(&self, file: SourceFile) -> IndexMap<String, SolvedLayout> {
        let json = queries::resolve_layouts_json(self, file);
        serde_json::from_str(json).unwrap_or_default()
    }

    /// Runs incremental semantic analysis for `file`, returning the frozen [`AnalyzedModule`] HIR.
    pub fn analyze_file(&self, file: SourceFile) -> AnalyzedModule {
        let json = queries::analyze_module_json(self, file);
        serde_json::from_str(json).expect("valid analyzed module JSON")
    }

    /// Computes the incremental Theorem 0.1 [`ConcurrencyGraph`] for `file`.
    pub fn concurrency_graph(&self, file: SourceFile) -> ConcurrencyGraph {
        let json = queries::concurrency_graph_json(self, file);
        serde_json::from_str(json).unwrap_or_default()
    }
}

#[salsa::db]
impl salsa::Database for SemaDb {}

/// One-shot convenience helper analyzing `src` without retaining a persistent [`SemaDb`].
pub fn analyze_source(path: impl Into<String>, src: impl Into<String>) -> AnalyzedModule {
    let db = SemaDb::new();
    let file = db.new_source(path, src);
    db.analyze_file(file)
}
