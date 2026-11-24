//! Incremental `salsa` query database with early-cutoff equality for sub-35ms live-dev reloads.

use crate::access::ConcurrencyGraph;
use crate::checks::{
    ModuleEnvSummary, SingleItemAnalysis, analyze_item_from_green, assemble_analyzed_module,
    compute_module_env_summary, extract_schema_signature_text, solve_module_layouts,
};
use crate::hir::AnalyzedModule;
use crate::layout::SolvedLayout;
use indexmap::IndexMap;
use std::collections::HashMap;
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

    /// Extracts only item/schema headers (stripping `sys`/`obs`/`fn`/`sim_test`/`net_sim_test`
    /// bodies) so body-only edits trigger early-cutoff and skip downstream layout/UUID re-computation.
    #[salsa::tracked]
    pub fn schema_signature(db: &dyn salsa::Database, file: SourceFile) -> String {
        extract_schema_signature_text(file.text(db))
    }

    /// Computes solved `#[repr(C)]` layouts and `ComponentUuid` / FNV-1a fingerprints; skipped
    /// entirely on body-only edits via `schema_signature` early cutoff.
    #[salsa::tracked]
    pub fn resolve_layouts(
        db: &dyn salsa::Database,
        file: SourceFile,
    ) -> Arc<IndexMap<String, SolvedLayout>> {
        let sig = schema_signature(db, file);
        let path = file.path(db);
        let solved = solve_module_layouts(path, sig);
        Arc::new(solved.layouts)
    }

    /// Parses `file` into a CST [`strata_syntax::Parse`] (memoized per file revision).
    #[salsa::tracked]
    pub fn parse_file(db: &dyn salsa::Database, file: SourceFile) -> Arc<strata_syntax::Parse> {
        Arc::new(strata_syntax::parse(file.text(db)))
    }

    /// Computes module-level environment summary strictly from [`schema_signature`],
    /// preserving Salsa early-cutoff on body-only edits.
    #[salsa::tracked]
    pub(crate) fn module_env_summary(
        db: &dyn salsa::Database,
        file: SourceFile,
    ) -> Arc<ModuleEnvSummary> {
        let sig = schema_signature(db, file);
        let path = file.path(db);
        Arc::new(compute_module_env_summary(path, sig))
    }

    /// Extracts `(item_key, byte_start, GreenNode)` tuples for each top-level item in `file`.
    #[salsa::tracked]
    pub(crate) fn item_green_trees(
        db: &dyn salsa::Database,
        file: SourceFile,
    ) -> Arc<Vec<(String, u32, rowan::GreenNode)>> {
        use strata_syntax::ast::{self, AstNode, SourceFile as AstSourceFile};
        let parsed = parse_file(db, file);
        let Some(sf) = AstSourceFile::cast(parsed.syntax()) else {
            return Arc::new(Vec::new());
        };
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut items = Vec::new();
        for item in sf.items() {
            let base = match &item {
                ast::Item::Fn(f) => format!(
                    "fn:{}",
                    f.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::Sys(s) => format!(
                    "sys:{}",
                    s.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::Obs(o) => format!(
                    "obs:{}",
                    o.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::SimTest(st) => {
                    let hdr = st
                        .syntax()
                        .children_with_tokens()
                        .filter_map(|el| el.into_token())
                        .find(|t| {
                            t.kind() == strata_syntax::SyntaxKind::StringLit
                                || t.kind() == strata_syntax::SyntaxKind::Ident
                        })
                        .map(|t| t.text().to_owned())
                        .unwrap_or_default();
                    format!("sim_test:{hdr}")
                }
                ast::Item::NetSimTest(nt) => {
                    format!("net_sim_test:{}", nt.name().unwrap_or_default())
                }
                ast::Item::Fsm(f) => format!(
                    "fsm:{}",
                    f.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::Task(t) => format!(
                    "task:{}",
                    t.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::Timeline(tl) => format!(
                    "timeline:{}",
                    tl.name().map(|n| n.text().to_string()).unwrap_or_default()
                ),
                ast::Item::Schedule(sc) => {
                    format!("schedule:{}", sc.label_text().unwrap_or_default())
                }
                ast::Item::Migrate(m) => {
                    let sig_hdr: String = m
                        .syntax()
                        .descendants_with_tokens()
                        .filter_map(|el| el.into_token())
                        .take_while(|t| t.kind() != strata_syntax::SyntaxKind::LBrace)
                        .filter(|t| !t.kind().is_trivia())
                        .map(|t| t.text().to_owned())
                        .collect();
                    format!("migrate:{sig_hdr}")
                }
                ast::Item::AssertLayout(_) => "assert_layout".to_owned(),
                _ => continue,
            };
            let idx = counts.entry(base.clone()).or_insert(0);
            let key = if *idx == 0 {
                base
            } else {
                format!("{base}#{idx}")
            };
            *idx += 1;
            let byte_start: u32 = item.syntax().text_range().start().into();
            items.push((key, byte_start, item.syntax().green().into_owned()));
        }
        Arc::new(items)
    }

    /// Interned key for a single top-level item slot within `file`.
    #[salsa::interned]
    pub(crate) struct ItemSlot<'db> {
        pub file: SourceFile,
        #[returns(ref)]
        pub key: String,
    }

    /// Returns the [`rowan::GreenNode`] for a single `ItemSlot`, enabling per-item Salsa early cutoff.
    #[salsa::tracked]
    pub(crate) fn item_green(
        db: &dyn salsa::Database,
        slot: ItemSlot<'_>,
    ) -> Option<rowan::GreenNode> {
        let trees = item_green_trees(db, *slot.file(db));
        let target = slot.key(db);
        trees
            .iter()
            .find(|(k, _, _)| k == target)
            .map(|(_, _, green)| green.clone())
    }

    /// Lowers and lints a single top-level item [`ItemSlot`] against [`module_env_summary`].
    #[salsa::tracked]
    pub(crate) fn analyze_item(
        db: &dyn salsa::Database,
        slot: ItemSlot<'_>,
    ) -> Arc<SingleItemAnalysis> {
        let file = *slot.file(db);
        let env = module_env_summary(db, file);
        let Some(green) = item_green(db, slot) else {
            return Arc::new(SingleItemAnalysis::Other);
        };
        Arc::new(analyze_item_from_green(file.path(db), green, env))
    }

    /// Full incremental semantic analysis returning a shared frozen [`AnalyzedModule`] HIR.
    #[salsa::tracked]
    pub fn analyze_module(db: &dyn salsa::Database, file: SourceFile) -> Arc<AnalyzedModule> {
        // Depend on `resolve_layouts` so Salsa tracks schema-level invalidation cleanly.
        let _layouts = resolve_layouts(db, file);
        let parsed = parse_file(db, file);
        let env_summary = module_env_summary(db, file);
        let trees = item_green_trees(db, file);
        let per_item_refs: Vec<(u32, &SingleItemAnalysis)> = trees
            .iter()
            .map(|(key, byte_start, _)| {
                let slot = ItemSlot::new(db, file, key.clone());
                (*byte_start, analyze_item(db, slot).as_ref())
            })
            .collect();
        Arc::new(assemble_analyzed_module(
            file.path(db),
            file.text(db),
            parsed,
            env_summary,
            &per_item_refs,
        ))
    }

    /// Extracts the Theorem 0.1 [`ConcurrencyGraph`] for `stratac explain-par` and LSP lenses.
    #[salsa::tracked]
    pub fn concurrency_graph(db: &dyn salsa::Database, file: SourceFile) -> Arc<ConcurrencyGraph> {
        let analyzed = analyze_module(db, file);
        Arc::new(analyzed.concurrency_graph.clone())
    }
}

pub use queries::SourceFile;
/// Re-export of `salsa::Setter` so downstream crates can mutate [`SourceFile`] inputs via
/// `.set_text(&mut db).to(...)` without adding a direct `salsa` dependency.
pub use salsa::Setter;

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
        (**queries::resolve_layouts(self, file)).clone()
    }

    /// Queries all solved component/stratum layouts as a memoized [`Arc`] without cloning.
    pub fn resolve_layouts_arc(&self, file: SourceFile) -> Arc<IndexMap<String, SolvedLayout>> {
        Arc::clone(queries::resolve_layouts(self, file))
    }

    /// Parses `file` into a memoized [`strata_syntax::Parse`] CST [`Arc`].
    pub fn parse_file(&self, file: SourceFile) -> Arc<strata_syntax::Parse> {
        Arc::clone(queries::parse_file(self, file))
    }

    /// Runs incremental semantic analysis for `file`, returning a memoized [`Arc`] to the frozen
    /// [`AnalyzedModule`] HIR.
    pub fn analyze_file(&self, file: SourceFile) -> Arc<AnalyzedModule> {
        Arc::clone(queries::analyze_module(self, file))
    }

    /// Computes the incremental Theorem 0.1 [`ConcurrencyGraph`] for `file`.
    pub fn concurrency_graph(&self, file: SourceFile) -> Arc<ConcurrencyGraph> {
        Arc::clone(queries::concurrency_graph(self, file))
    }
}

#[salsa::db]
impl salsa::Database for SemaDb {}

/// One-shot convenience helper analyzing `src` without retaining a persistent [`SemaDb`].
pub fn analyze_source(path: impl Into<String>, src: impl Into<String>) -> AnalyzedModule {
    let analyzed = {
        let db = SemaDb::new();
        let file = db.new_source(path, src);
        db.analyze_file(file)
    };
    Arc::unwrap_or_clone(analyzed)
}
