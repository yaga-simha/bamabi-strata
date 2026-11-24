//! `tower-lsp` [`LanguageServer`] implementation backed by `strata_sema` and `strata_syntax`.

use crate::ide::{
    DeclEntry, DocCommentIndex, DotCompletionIndex, IndexedWorkspaceSymbol, LineIndex,
    build_all_inlay_hints, build_dot_completion_index, build_ident_token_index,
    build_symbols_and_decls, build_workspace_symbols_for_doc, byte_offset_to_position,
    compute_completions_cached, compute_definition_cached, compute_document_highlights_cached,
    compute_references_cached, compute_rich_hover_with_index, filter_inlay_hints,
    filter_workspace_symbols, needs_dot_completion_index, parse_telemetry_endpoint,
    position_to_byte_offset,
};
use crate::telemetry::{
    SystemTelemetryDigest64, SystemTelemetryDigestJson, TELEMETRY_FLAG_QUARANTINED, TelemetryError,
    TelemetryStore, TelemetrySubscription, decode_digest_slice, spawn_telemetry_subscriber,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use strata_sema::db::Setter;
use strata_sema::{AnalyzedModule, SemaDb, Severity, SourceFile, analyze_source};
use strata_syntax::fmt::format_source;
use tower_lsp::jsonrpc::{Error as JsonRpcError, Result as LspResult};
use tower_lsp::lsp_types::{
    CodeLens, Command, CompletionOptions, CompletionParams, CompletionResponse, Diagnostic,
    DiagnosticSeverity, DidChangeConfigurationParams, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    DocumentFormattingParams, DocumentHighlight, DocumentHighlightParams, DocumentSymbol,
    DocumentSymbolParams, DocumentSymbolResponse, GotoDefinitionParams, GotoDefinitionResponse,
    Hover, HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
    InlayHint, InlayHintParams, Location, MessageType, NumberOrString, OneOf, Position, Range,
    ReferenceParams, SaveOptions, ServerCapabilities, ServerInfo, SymbolInformation,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, TextEdit, Url, WorkspaceSymbolParams,
};
use tower_lsp::{Client, ClientSocket, LanguageServer, LspService};

/// Input frame accepted by `strata/graphTelemetry` and `strata/ingestTelemetry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TelemetryFrameInput {
    /// Raw 64-byte little-endian `"BAMT"` wire frame (`[u8; 64]`).
    Bytes(Vec<u8>),
    /// Pre-decoded `SystemTelemetryDigest64` JSON object.
    Digest(SystemTelemetryDigestJson),
}

impl TelemetryFrameInput {
    /// Validates and decodes this input frame into a [`SystemTelemetryDigest64`].
    pub fn decode(self) -> Result<SystemTelemetryDigest64, TelemetryError> {
        match self {
            Self::Bytes(bytes) => decode_digest_slice(&bytes),
            Self::Digest(digest) => SystemTelemetryDigest64::try_from(digest),
        }
    }
}

/// Request parameters for custom JSON-RPC method `strata/graphTelemetry`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphTelemetryParams {
    /// Optional document URI (`file:///...`).
    #[serde(default, alias = "textDocument")]
    pub uri: Option<String>,
    /// Optional list of canonical node IDs (`"module::symbol"`) to query.
    #[serde(default, alias = "nodeIds")]
    pub node_ids: Option<Vec<String>>,
    /// Optional inline 64-byte `"BAMT"` frames (or digest structs) to validate and ingest first.
    #[serde(default)]
    pub frames: Vec<TelemetryFrameInput>,
}

/// Telemetry metrics resolved for a single canonical graph or system node ID from Layer-0
/// [`SystemTelemetryDigest64`] (`"BAMT"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNodeTelemetry {
    /// Canonical node ID (`"module::symbol"`).
    pub node_id: String,
    /// 64-bit FNV-1a system identifier hash from the matched frame.
    pub system_hash: u64,
    /// Owning `ModId.0` (`0` for unscoped / host-owned systems).
    pub mod_id: u64,
    /// Monotonic simulation frame sequence number.
    pub frame_seq: u64,
    /// Rolling median (`p50`) execution duration in microseconds.
    pub p50_us: u32,
    /// Rolling 99th-percentile (`p99`) execution duration in microseconds.
    pub p99_us: u32,
    /// Number of entities matched/visited by the system on the latest sample.
    pub matched_entities: u32,
    /// Number of ECS tables matched by the system's query.
    pub matched_tables: u32,
    /// Number of matched tables skipped via Bevy `0.20` `summary_tick` acceleration.
    pub skipped_summary_tick_tables: u32,
    /// Number of contiguous chunk iterations executed by the system.
    pub chunks: u32,
    /// Number of deferred host commands queued on the latest sample.
    pub commands_queued: u32,
    /// Raw status bitflags (`TELEMETRY_FLAG_*`).
    pub flags: u16,
    /// `true` iff [`TELEMETRY_FLAG_QUARANTINED`] bit is set.
    pub quarantined: bool,
    /// Whether the digest matched via `"canonical"` or `"bare"` name hash.
    pub matched_by: String,
}

/// Response payload for custom JSON-RPC method `strata/graphTelemetry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphTelemetryResponse {
    /// Requested document URI if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Resolved module path if the document is currently open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_path: Option<String>,
    /// Per-node telemetry map keyed by canonical node ID.
    pub nodes: BTreeMap<String, GraphNodeTelemetry>,
}

/// Request parameters for custom JSON-RPC method `strata/ingestTelemetry`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestTelemetryParams {
    /// Raw 64-byte `"BAMT"` frames (or digest structs) to validate and record.
    #[serde(default)]
    pub frames: Vec<TelemetryFrameInput>,
}

/// Response payload for custom JSON-RPC method `strata/ingestTelemetry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestTelemetryResponse {
    /// Number of valid frames ingested.
    pub ingested: usize,
    /// Highest `frame_seq` among the ingested frames, if any.
    pub latest_frame_seq: Option<u64>,
}

fn qualify_node_id(module_path: &str, name: &str) -> String {
    if name.contains("::") {
        name.to_owned()
    } else {
        format!("{module_path}::{name}")
    }
}

fn collect_document_node_ids(source: &str, analyzed: &AnalyzedModule) -> BTreeSet<String> {
    let mp = analyzed.module_path.as_str();
    let mut ids = BTreeSet::new();

    for c in &analyzed.callables {
        ids.insert(qualify_node_id(mp, &c.name));
    }
    for f in &analyzed.fns {
        ids.insert(qualify_node_id(mp, &f.name));
    }
    for t in &analyzed.timelines {
        ids.insert(qualify_node_id(mp, &t.name));
        ids.insert(qualify_node_id(mp, &t.canonical_name));
    }
    for t in &analyzed.tasks {
        ids.insert(qualify_node_id(mp, &t.name));
    }
    for f in &analyzed.fsms {
        ids.insert(qualify_node_id(mp, &f.name));
    }
    for t in &analyzed.tables {
        ids.insert(qualify_node_id(mp, &t.name));
    }
    for c in &analyzed.curves {
        ids.insert(qualify_node_id(mp, &c.name));
    }
    for s in &analyzed.schedules {
        ids.insert(qualify_node_id(mp, &s.label));
    }
    for l in analyzed.layouts.values() {
        ids.insert(qualify_node_id(mp, &l.canonical_name));
    }
    for r in &analyzed.rpcs {
        ids.insert(qualify_node_id(mp, &r.canonical_name));
    }

    if let Ok(doc) = strata_syntax::graph_ir::export_graph_ir(source, None) {
        for node in doc.nodes {
            ids.insert(node.id);
        }
    }

    ids
}

struct DocEntry {
    sf: SourceFile,
    line_index: Option<Arc<LineIndex>>,
    symbols_and_decls: Option<(Arc<Vec<DocumentSymbol>>, Arc<Vec<DeclEntry>>)>,
    workspace_symbols: Option<(String, Arc<Vec<IndexedWorkspaceSymbol>>)>,
    ident_tokens: Option<Arc<HashMap<String, Vec<(Range, bool)>>>>,
    dot_index: Option<Arc<DotCompletionIndex>>,
    doc_comments: Option<Arc<DocCommentIndex>>,
    inlay_hints: Option<Arc<Vec<InlayHint>>>,
    graph_node_ids: Option<(String, Arc<BTreeSet<String>>)>,
}

impl DocEntry {
    fn new(sf: SourceFile) -> Self {
        Self {
            sf,
            line_index: None,
            symbols_and_decls: None,
            workspace_symbols: None,
            ident_tokens: None,
            dot_index: None,
            doc_comments: None,
            inlay_hints: None,
            graph_node_ids: None,
        }
    }

    fn invalidate(&mut self) {
        self.line_index = None;
        self.symbols_and_decls = None;
        self.workspace_symbols = None;
        self.ident_tokens = None;
        self.dot_index = None;
        self.doc_comments = None;
        self.inlay_hints = None;
        self.graph_node_ids = None;
    }
}

struct LspState {
    db: SemaDb,
    files: HashMap<Url, DocEntry>,
}

impl LspState {
    fn upsert_document(&mut self, uri: &Url, text: String) -> SourceFile {
        if let Some(entry) = self.files.get_mut(uri) {
            let sf = entry.sf;
            if sf.text(&self.db) != &text {
                sf.set_text(&mut self.db).to(text);
                entry.invalidate();
            }
            sf
        } else {
            let sf = self.db.new_source(uri.to_string(), text);
            self.files.insert(uri.clone(), DocEntry::new(sf));
            sf
        }
    }

    fn ensure_line_index(&mut self, uri: &Url) -> Option<(SourceFile, Arc<LineIndex>)> {
        let entry = self.files.get_mut(uri)?;
        let sf = entry.sf;
        if let Some(ref li) = entry.line_index {
            return Some((sf, Arc::clone(li)));
        }
        let li = Arc::new(LineIndex::new(sf.text(&self.db)));
        entry.line_index = Some(Arc::clone(&li));
        Some((sf, li))
    }

    fn ensure_symbols_and_decls(
        &mut self,
        uri: &Url,
    ) -> Option<(Arc<Vec<DocumentSymbol>>, Arc<Vec<DeclEntry>>)> {
        if let Some(ref cached) = self.files.get(uri)?.symbols_and_decls {
            return Some((Arc::clone(&cached.0), Arc::clone(&cached.1)));
        }
        let (sf, line_index) = self.ensure_line_index(uri)?;
        let parsed = self.db.parse_file(sf);
        let analyzed = self.db.analyze_file(sf);
        let (syms, decls) =
            build_symbols_and_decls(sf.text(&self.db), &line_index, &parsed.syntax(), &analyzed);
        let pair = (Arc::new(syms), Arc::new(decls));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.symbols_and_decls = Some((Arc::clone(&pair.0), Arc::clone(&pair.1)));
        }
        Some(pair)
    }

    fn ensure_workspace_symbols(
        &mut self,
        uri: &Url,
    ) -> Option<(String, Arc<Vec<IndexedWorkspaceSymbol>>)> {
        if let Some(ref cached) = self.files.get(uri)?.workspace_symbols {
            return Some((cached.0.clone(), Arc::clone(&cached.1)));
        }
        let (_, decls) = self.ensure_symbols_and_decls(uri)?;
        let sf = self.files.get(uri)?.sf;
        let analyzed = self.db.analyze_file(sf);
        let lower_mod = analyzed.module_path.to_ascii_lowercase();
        let indexed = Arc::new(build_workspace_symbols_for_doc(
            uri,
            &analyzed.module_path,
            &decls,
        ));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.workspace_symbols = Some((lower_mod.clone(), Arc::clone(&indexed)));
        }
        Some((lower_mod, indexed))
    }

    fn ensure_ident_tokens(
        &mut self,
        uri: &Url,
    ) -> Option<Arc<HashMap<String, Vec<(Range, bool)>>>> {
        if let Some(ref cached) = self.files.get(uri)?.ident_tokens {
            return Some(Arc::clone(cached));
        }
        let (sf, line_index) = self.ensure_line_index(uri)?;
        let parsed = self.db.parse_file(sf);
        let tokens = Arc::new(build_ident_token_index(
            sf.text(&self.db),
            &line_index,
            &parsed.syntax(),
        ));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.ident_tokens = Some(Arc::clone(&tokens));
        }
        Some(tokens)
    }

    fn ensure_dot_index(&mut self, uri: &Url) -> Option<Arc<DotCompletionIndex>> {
        if let Some(ref cached) = self.files.get(uri)?.dot_index {
            return Some(Arc::clone(cached));
        }
        let sf = self.files.get(uri)?.sf;
        let parsed = self.db.parse_file(sf);
        let idx = Arc::new(build_dot_completion_index(&parsed.syntax()));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.dot_index = Some(Arc::clone(&idx));
        }
        Some(idx)
    }

    fn ensure_doc_comments(&mut self, uri: &Url) -> Option<Arc<DocCommentIndex>> {
        if let Some(ref cached) = self.files.get(uri)?.doc_comments {
            return Some(Arc::clone(cached));
        }
        let sf = self.files.get(uri)?.sf;
        let parsed = self.db.parse_file(sf);
        let idx = Arc::new(DocCommentIndex::build(&parsed.syntax()));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.doc_comments = Some(Arc::clone(&idx));
        }
        Some(idx)
    }

    fn ensure_inlay_hints(&mut self, uri: &Url) -> Option<Arc<Vec<InlayHint>>> {
        if let Some(ref cached) = self.files.get(uri)?.inlay_hints {
            return Some(Arc::clone(cached));
        }
        let (sf, line_index) = self.ensure_line_index(uri)?;
        let parsed = self.db.parse_file(sf);
        let analyzed = self.db.analyze_file(sf);
        let hints = Arc::new(build_all_inlay_hints(
            sf.text(&self.db),
            &line_index,
            &parsed.syntax(),
            &analyzed,
        ));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.inlay_hints = Some(Arc::clone(&hints));
        }
        Some(hints)
    }

    fn ensure_graph_node_ids(&mut self, uri: &Url) -> Option<(String, Arc<BTreeSet<String>>)> {
        if let Some(ref cached) = self.files.get(uri)?.graph_node_ids {
            return Some((cached.0.clone(), Arc::clone(&cached.1)));
        }
        let sf = self.files.get(uri)?.sf;
        let analyzed = self.db.analyze_file(sf);
        let mp = analyzed.module_path.clone();
        let ids = Arc::new(collect_document_node_ids(sf.text(&self.db), &analyzed));
        if let Some(entry) = self.files.get_mut(uri) {
            entry.graph_node_ids = Some((mp.clone(), Arc::clone(&ids)));
        }
        Some((mp, ids))
    }
}

/// `tower-lsp` backend for Strata v2.0 `.strata` source files.
pub struct StrataLspBackend {
    client: Option<Client>,
    state: Arc<Mutex<LspState>>,
    telemetry: TelemetryStore,
    telemetry_sub: Mutex<Option<TelemetrySubscription>>,
}

impl StrataLspBackend {
    /// Creates an LSP backend wired to a connected `tower-lsp` client handle.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self {
            client: Some(client),
            state: Arc::new(Mutex::new(LspState {
                db: SemaDb::default(),
                files: HashMap::new(),
            })),
            telemetry: TelemetryStore::new(),
            telemetry_sub: Mutex::new(None),
        }
    }

    /// Creates a headless [`StrataLspBackend`] suitable for in-process testing without stdio.
    #[must_use]
    pub fn headless(telemetry: TelemetryStore) -> Self {
        Self {
            client: None,
            state: Arc::new(Mutex::new(LspState {
                db: SemaDb::default(),
                files: HashMap::new(),
            })),
            telemetry,
            telemetry_sub: Mutex::new(None),
        }
    }

    fn apply_telemetry_config(&self, settings: &serde_json::Value) {
        let Some(endpoint) = parse_telemetry_endpoint(settings) else {
            return;
        };
        if let Ok(mut guard) = self.telemetry_sub.lock() {
            if let Some(prev) = guard.take() {
                prev.signal_stop();
            }
            *guard = Some(spawn_telemetry_subscriber(endpoint, self.telemetry.clone()));
        }
    }

    /// Returns a shared handle to the live [`TelemetryStore`].
    #[must_use]
    pub fn telemetry(&self) -> &TelemetryStore {
        &self.telemetry
    }

    /// Clears and returns all Salsa `WillExecute` query names recorded by the backend's
    /// incremental [`SemaDb`] since the previous call.
    #[must_use]
    pub fn take_executed_queries(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|state| state.db.take_executed_queries())
            .unwrap_or_default()
    }

    async fn publish_diagnostics(&self, uri: Url, diags: Vec<Diagnostic>) {
        if let Some(client) = &self.client {
            client.publish_diagnostics(uri, diags, None).await;
        }
    }

    /// Custom JSON-RPC method `strata/graphTelemetry` mapping `SystemTelemetryDigest64`
    /// (`"STRT"`) frames onto canonical node IDs (`"{module_path}::{name}"`).
    pub async fn graph_telemetry(
        &self,
        params: GraphTelemetryParams,
    ) -> LspResult<GraphTelemetryResponse> {
        let parsed_uri = match params.uri.as_deref() {
            Some(raw) => match Url::parse(raw) {
                Ok(u) => Some(u),
                Err(err) => {
                    return Err(JsonRpcError::invalid_params(format!(
                        "invalid document URI `{raw}`: {err}"
                    )));
                }
            },
            None => None,
        };

        let mut decoded = Vec::with_capacity(params.frames.len());
        for frame in params.frames {
            match frame.decode() {
                Ok(digest) => decoded.push(digest),
                Err(err) => return Err(JsonRpcError::invalid_params(err.to_string())),
            }
        }
        if !decoded.is_empty() {
            self.telemetry.record_digests(decoded);
        }

        let (module_path, known_ids) = if let Some(ref uri) = parsed_uri {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| JsonRpcError::internal_error())?;
            if let Some((mp, ids)) = guard.ensure_graph_node_ids(uri) {
                (Some(mp), Some(ids))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let mut nodes = BTreeMap::new();
        let mp_ref = module_path.as_deref();
        let mut record_node = |node_id: &str| {
            let bare = mp_ref
                .and_then(|mp| node_id.strip_prefix(mp)?.strip_prefix("::"))
                .or_else(|| node_id.rsplit("::").next());
            if let Some((digest, matched_by)) = self.telemetry.get_for_node(node_id, bare) {
                let owned_id = node_id.to_owned();
                nodes.insert(
                    owned_id.clone(),
                    GraphNodeTelemetry {
                        node_id: owned_id,
                        system_hash: digest.system_hash,
                        mod_id: digest.mod_id,
                        frame_seq: digest.frame_seq,
                        p50_us: digest.p50_us,
                        p99_us: digest.p99_us,
                        matched_entities: digest.matched_entities,
                        matched_tables: digest.matched_tables,
                        skipped_summary_tick_tables: digest.skipped_summary_tick_tables,
                        chunks: digest.chunks,
                        commands_queued: digest.commands_queued,
                        flags: digest.flags,
                        quarantined: (digest.flags & TELEMETRY_FLAG_QUARANTINED) != 0,
                        matched_by: matched_by.to_owned(),
                    },
                );
            }
        };

        match (params.node_ids, known_ids) {
            (Some(requested), Some(known)) => {
                for id in &requested {
                    if known.contains(id) {
                        record_node(id);
                    }
                }
            }
            (Some(requested), None) => {
                for id in &requested {
                    record_node(id);
                }
            }
            (None, Some(known)) => {
                for id in known.iter() {
                    record_node(id);
                }
            }
            (None, None) => {}
        }

        Ok(GraphTelemetryResponse {
            uri: params.uri,
            module_path,
            nodes,
        })
    }

    /// Custom JSON-RPC method `strata/ingestTelemetry` validating and recording 64-byte `"BAMT"`
    /// telemetry frames into the live [`TelemetryStore`].
    pub async fn ingest_telemetry(
        &self,
        params: IngestTelemetryParams,
    ) -> LspResult<IngestTelemetryResponse> {
        let mut decoded = Vec::with_capacity(params.frames.len());
        for frame in params.frames {
            match frame.decode() {
                Ok(digest) => decoded.push(digest),
                Err(err) => return Err(JsonRpcError::invalid_params(err.to_string())),
            }
        }
        let ingested = decoded.len();
        let latest_frame_seq = decoded.iter().map(|d| d.frame_seq).max();
        if !decoded.is_empty() {
            self.telemetry.record_digests(decoded);
        }
        Ok(IngestTelemetryResponse {
            ingested,
            latest_frame_seq,
        })
    }
}

/// Builds the `tower-lsp` [`LspService`] and [`ClientSocket`] with custom Strata methods
/// (`strata/graphTelemetry`, `strata/ingestTelemetry`) registered.
#[must_use]
pub fn build_lsp_service() -> (LspService<StrataLspBackend>, ClientSocket) {
    LspService::build(StrataLspBackend::new)
        .custom_method("strata/graphTelemetry", StrataLspBackend::graph_telemetry)
        .custom_method("strata/ingestTelemetry", StrataLspBackend::ingest_telemetry)
        .finish()
}

fn diagnostics_from_analyzed(source: &str, analyzed: &AnalyzedModule) -> Vec<Diagnostic> {
    if analyzed.diagnostics.is_empty() {
        return Vec::new();
    }
    let line_index = LineIndex::new(source);
    analyzed
        .diagnostics
        .iter()
        .map(|d| {
            let start = line_index.byte_offset_to_position(source, d.span.byte_start);
            let end = line_index
                .byte_offset_to_position(source, d.span.byte_end.max(d.span.byte_start + 1));
            let severity = match d.severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
                Severity::Info => DiagnosticSeverity::INFORMATION,
            };
            Diagnostic {
                range: Range::new(start, end),
                severity: Some(severity),
                code: Some(NumberOrString::String(d.code.clone())),
                code_description: None,
                source: Some("strata".to_owned()),
                message: d.message.clone(),
                related_information: None,
                tags: None,
                data: None,
            }
        })
        .collect()
}

/// Computes LSP diagnostics from `strata_sema::analyze_source`.
#[must_use]
pub fn compute_diagnostics(source: &str) -> Vec<Diagnostic> {
    let analyzed = analyze_source("buffer.strata", source);
    diagnostics_from_analyzed(source, &analyzed)
}

/// Computes Markdown hover information showing solved `size`, `align`, `ComponentUuid`,
/// `SCHEMA_FINGERPRINT`, explicit padding, field offsets, doc comments, `@attributes`,
/// built-in types, keywords, or callable/function/enum/RPC summaries.
#[must_use]
pub fn compute_hover(source: &str, pos: Position) -> Option<Hover> {
    let line_index = LineIndex::new(source);
    let _ = line_index.word_at_position(source, pos)?;
    let parsed = strata_syntax::parse(source);
    let root = parsed.syntax();
    let doc_comments = DocCommentIndex::build(&root);
    let analyzed = analyze_source("buffer.strata", source);
    let empty_telemetry = TelemetryStore::new();
    compute_rich_hover_with_index(
        source,
        &line_index,
        pos,
        &analyzed,
        &empty_telemetry,
        Some(&doc_comments),
        Some(&root),
    )
}

/// Computes full-document `stratafmt` formatting edits when source differs from canonical output.
#[must_use]
pub fn compute_formatting(source: &str) -> Vec<TextEdit> {
    let Ok(formatted) = format_source(source) else {
        return Vec::new();
    };
    if formatted == source {
        return Vec::new();
    }
    let end = byte_offset_to_position(source, source.len() as u32);
    vec![TextEdit {
        range: Range::new(Position::new(0, 0), end),
        new_text: formatted,
    }]
}

fn compute_code_lenses_from_analyzed(
    source: &str,
    line_index: &LineIndex,
    analyzed: &AnalyzedModule,
    telemetry: &TelemetryStore,
) -> Vec<CodeLens> {
    let mut lenses = Vec::with_capacity(analyzed.callables.len());

    for callable in &analyzed.callables {
        let pos = line_index.byte_offset_to_position(source, callable.byte_range.0);
        let range = Range::new(pos, pos);

        let mut title = String::with_capacity(96);
        if let Some((t, _)) = telemetry.get_for_module_system(&analyzed.module_path, &callable.name)
        {
            write_par_tag(
                &mut title,
                callable.par_chunk,
                callable.par_read_only,
                &callable.name,
                analyzed,
            );
            let q_tag = if (t.flags & TELEMETRY_FLAG_QUARANTINED) != 0 {
                " [QUARANTINED]"
            } else {
                ""
            };
            let _ = write!(
                title,
                " | p50: {} us | p99: {} us | entities: {} | tables: {} | skipped: {} | cmds: {}{q_tag}",
                t.p50_us,
                t.p99_us,
                t.matched_entities,
                t.matched_tables,
                t.skipped_summary_tick_tables,
                t.commands_queued
            );
        } else {
            title.push_str("strata: ");
            write_par_tag(
                &mut title,
                callable.par_chunk,
                callable.par_read_only,
                &callable.name,
                analyzed,
            );
            title.push_str(" (no live telemetry)");
        }

        lenses.push(CodeLens {
            range,
            command: Some(Command {
                title,
                command: "strata.inspectSystem".to_owned(),
                arguments: None,
            }),
            data: None,
        });
    }

    lenses
}

fn write_par_tag(
    out: &mut String,
    par_chunk: Option<u32>,
    par_read_only: bool,
    callable_name: &str,
    analyzed: &AnalyzedModule,
) {
    match par_chunk {
        Some(c) if par_read_only => {
            let _ = write!(out, "@par(read_only, chunk={c})");
        }
        Some(c) => {
            let _ = write!(out, "@par(chunk={c})");
        }
        None => {
            let conflict_cnt = analyzed
                .concurrency_graph
                .conflicts
                .iter()
                .filter(|e| e.system_a == callable_name || e.system_b == callable_name)
                .count();
            let _ = write!(out, "seq (conflicts={conflict_cnt})");
        }
    }
}

/// Computes CodeLens annotations showing Theorem 0.1 `@par` concurrency and live
/// `SystemTelemetryDigest64` frame timings / heap allocation counters.
#[must_use]
pub fn compute_code_lenses(source: &str, telemetry: &TelemetryStore) -> Vec<CodeLens> {
    let analyzed = analyze_source("buffer.strata", source);
    let line_index = LineIndex::new(source);
    compute_code_lenses_from_analyzed(source, &line_index, &analyzed, telemetry)
}

#[tower_lsp::async_trait]
impl LanguageServer for StrataLspBackend {
    async fn initialize(&self, params: InitializeParams) -> LspResult<InitializeResult> {
        if let Some(opts) = params.initialization_options.as_ref() {
            self.apply_telemetry_config(opts);
        }
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(true),
                        })),
                        ..TextDocumentSyncOptions::default()
                    },
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![".".to_owned(), ":".to_owned(), "@".to_owned()]),
                    resolve_provider: Some(false),
                    ..CompletionOptions::default()
                }),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_highlight_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                code_lens_provider: Some(tower_lsp::lsp_types::CodeLensOptions {
                    resolve_provider: Some(false),
                }),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "strata-lsp".to_owned(),
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        if let Some(client) = &self.client {
            client
                .log_message(MessageType::INFO, "strata-lsp initialized")
                .await;
        }
    }

    async fn shutdown(&self) -> LspResult<()> {
        if let Ok(mut guard) = self.telemetry_sub.lock()
            && let Some(sub) = guard.take()
        {
            sub.signal_stop();
        }
        Ok(())
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        self.apply_telemetry_config(&params.settings);
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let diags = self
            .state
            .lock()
            .map(|mut state| {
                let sf = state.upsert_document(&uri, text);
                let analyzed = state.db.analyze_file(sf);
                diagnostics_from_analyzed(sf.text(&state.db), &analyzed)
            })
            .unwrap_or_default();
        self.publish_diagnostics(uri, diags).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if params.content_changes.is_empty() {
            return;
        }
        let uri = params.text_document.uri;
        let diags = self
            .state
            .lock()
            .map(|mut state| {
                let has_range = params.content_changes.iter().any(|c| c.range.is_some());
                let new_text = if !has_range && params.content_changes.len() == 1 {
                    params
                        .content_changes
                        .into_iter()
                        .next()
                        .map(|c| c.text)
                        .unwrap_or_default()
                } else {
                    let mut buf = state
                        .files
                        .get(&uri)
                        .map(|entry| entry.sf.text(&state.db).clone())
                        .unwrap_or_default();
                    for change in params.content_changes {
                        if let Some(range) = change.range {
                            let start = position_to_byte_offset(&buf, range.start);
                            let end = position_to_byte_offset(&buf, range.end).max(start);
                            buf.replace_range(start..end, &change.text);
                        } else {
                            buf = change.text;
                        }
                    }
                    buf
                };

                let sf = state.upsert_document(&uri, new_text);
                let analyzed = state.db.analyze_file(sf);
                diagnostics_from_analyzed(sf.text(&state.db), &analyzed)
            })
            .unwrap_or_default();
        self.publish_diagnostics(uri, diags).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;
        let diags = self.state.lock().ok().and_then(|mut state| {
            if let Some(text) = params.text {
                let sf = state.upsert_document(&uri, text);
                let analyzed = state.db.analyze_file(sf);
                return Some(diagnostics_from_analyzed(sf.text(&state.db), &analyzed));
            }
            let sf = state.files.get(&uri)?.sf;
            let analyzed = state.db.analyze_file(sf);
            Some(diagnostics_from_analyzed(sf.text(&state.db), &analyzed))
        });
        if let Some(diags) = diags {
            self.publish_diagnostics(uri, diags).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Ok(mut state) = self.state.lock() {
            state.files.remove(&params.text_document.uri);
        }
    }

    async fn hover(&self, params: tower_lsp::lsp_types::HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let _ = line_index.word_at_position(sf.text(&state.db), pos)?;
            let doc_comments = state.ensure_doc_comments(uri)?;
            let parsed = state.db.parse_file(sf);
            let root = parsed.syntax();
            let analyzed = state.db.analyze_file(sf);
            compute_rich_hover_with_index(
                sf.text(&state.db),
                &line_index,
                pos,
                &analyzed,
                &self.telemetry,
                Some(doc_comments.as_ref()),
                Some(&root),
            )
        });
        Ok(result)
    }

    async fn completion(&self, params: CompletionParams) -> LspResult<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let need_dot = needs_dot_completion_index(sf.text(&state.db), &line_index, pos);
            let dot_index = if need_dot {
                state.ensure_dot_index(uri)
            } else {
                None
            };
            let _cst = state.db.parse_file(sf);
            let analyzed = state.db.analyze_file(sf);
            let items = compute_completions_cached(
                sf.text(&state.db),
                &line_index,
                pos,
                &analyzed,
                dot_index.as_deref(),
            );
            Some(CompletionResponse::Array(items))
        });
        Ok(result)
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> LspResult<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let (_, active_decls) = state.ensure_symbols_and_decls(uri)?;
            let parsed = state.db.parse_file(sf);
            let root = parsed.syntax();
            if let Some(loc) = compute_definition_cached(
                uri,
                sf.text(&state.db),
                &line_index,
                &root,
                &active_decls,
                &[],
                pos,
            ) {
                return Some(GotoDefinitionResponse::Scalar(loc));
            }
            if state.files.len() <= 1 {
                return None;
            }
            let other_uris: Vec<Url> = state
                .files
                .keys()
                .filter(|other_uri| *other_uri != uri)
                .cloned()
                .collect();
            let mut other_decls_owned: Vec<(Url, Arc<Vec<DeclEntry>>)> =
                Vec::with_capacity(other_uris.len());
            for other_uri in other_uris {
                if let Some((_, decls)) = state.ensure_symbols_and_decls(&other_uri) {
                    other_decls_owned.push((other_uri, decls));
                }
            }
            let other_refs: Vec<(&Url, &[DeclEntry])> = other_decls_owned
                .iter()
                .map(|(u, d)| (u, d.as_slice()))
                .collect();
            compute_definition_cached(
                uri,
                sf.text(&state.db),
                &line_index,
                &root,
                &active_decls,
                &other_refs,
                pos,
            )
            .map(GotoDefinitionResponse::Scalar)
        });
        Ok(result)
    }

    async fn document_highlight(
        &self,
        params: DocumentHighlightParams,
    ) -> LspResult<Option<Vec<DocumentHighlight>>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let ident_tokens = state.ensure_ident_tokens(uri)?;
            let highlights = compute_document_highlights_cached(
                sf.text(&state.db),
                &line_index,
                &ident_tokens,
                pos,
            );
            Some(highlights)
        });
        Ok(result)
    }

    async fn references(&self, params: ReferenceParams) -> LspResult<Option<Vec<Location>>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let include_decl = params.context.include_declaration;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let active_tokens = state.ensure_ident_tokens(uri)?;
            let other_uris: Vec<Url> = state
                .files
                .keys()
                .filter(|other_uri| *other_uri != uri)
                .cloned()
                .collect();
            let mut other_tokens_owned: Vec<(Url, Arc<HashMap<String, Vec<(Range, bool)>>>)> =
                Vec::with_capacity(other_uris.len());
            for other_uri in other_uris {
                if let Some(tokens) = state.ensure_ident_tokens(&other_uri) {
                    other_tokens_owned.push((other_uri, tokens));
                }
            }
            let other_refs: Vec<(&Url, &HashMap<String, Vec<(Range, bool)>>)> = other_tokens_owned
                .iter()
                .map(|(u, t)| (u, t.as_ref()))
                .collect();
            Some(compute_references_cached(
                uri,
                sf.text(&state.db),
                &line_index,
                &active_tokens,
                &other_refs,
                pos,
                include_decl,
            ))
        });
        Ok(result)
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> LspResult<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (syms, _) = state.ensure_symbols_and_decls(uri)?;
            Some(DocumentSymbolResponse::Nested(syms.as_ref().clone()))
        });
        Ok(result)
    }

    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> LspResult<Option<Vec<SymbolInformation>>> {
        let result = self.state.lock().ok().map(|mut state| {
            let uris: Vec<Url> = state.files.keys().cloned().collect();
            let mut docs_owned: Vec<(String, Arc<Vec<IndexedWorkspaceSymbol>>)> =
                Vec::with_capacity(uris.len());
            for uri in &uris {
                if let Some(entry) = state.ensure_workspace_symbols(uri) {
                    docs_owned.push(entry);
                }
            }
            let doc_refs: Vec<(&str, &[IndexedWorkspaceSymbol])> = docs_owned
                .iter()
                .map(|(mp, syms)| (mp.as_str(), syms.as_slice()))
                .collect();
            filter_workspace_symbols(&doc_refs, &params.query)
        });
        Ok(result)
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> LspResult<Option<Vec<InlayHint>>> {
        let uri = &params.text_document.uri;
        let range = params.range;
        let result = self.state.lock().ok().and_then(|mut state| {
            let hints = state.ensure_inlay_hints(uri)?;
            Some(filter_inlay_hints(&hints, range))
        });
        Ok(result)
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> LspResult<Option<Vec<TextEdit>>> {
        let uri = &params.text_document.uri;
        let result = self.state.lock().ok().and_then(|state| {
            let sf = state.files.get(uri)?.sf;
            Some(compute_formatting(sf.text(&state.db)))
        });
        Ok(result)
    }

    async fn code_lens(
        &self,
        params: tower_lsp::lsp_types::CodeLensParams,
    ) -> LspResult<Option<Vec<CodeLens>>> {
        let uri = &params.text_document.uri;
        let result = self.state.lock().ok().and_then(|mut state| {
            let (sf, line_index) = state.ensure_line_index(uri)?;
            let _cst = state.db.parse_file(sf);
            let analyzed = state.db.analyze_file(sf);
            Some(compute_code_lenses_from_analyzed(
                sf.text(&state.db),
                &line_index,
                &analyzed,
                &self.telemetry,
            ))
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{
        SYSTEM_TELEMETRY_DIGEST_VERSION, SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64,
        fnv1a_64_hash_system,
    };

    /// Verifies `compute_formatting` omits no-op edits on canonical code and fixes unformatted text.
    #[test]
    fn compute_formatting_handles_unformatted_and_clean_buffers() {
        let dirty = "module  a::b @version(1.0.0);\ncomponent  Pos{ x:f32=0.0 }\n";
        let edits = compute_formatting(dirty);
        assert_eq!(edits.len(), 1);
        assert!(compute_formatting(&edits[0].new_text).is_empty());
    }

    /// Verifies `compute_code_lenses` formats live telemetry timings when present.
    #[test]
    fn code_lens_renders_telemetry_when_populated() {
        let src = "module d::l @version(1.0.0);\ncomponent Pos { x: f32 = 0.0 }\nsys step() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n";
        let store = TelemetryStore::new();
        assert!(
            compute_code_lenses(src, &store)[0]
                .command
                .as_ref()
                .unwrap()
                .title
                .contains("no live telemetry")
        );

        store.record_digest(SystemTelemetryDigest64 {
            magic: SYSTEM_TELEMETRY_MAGIC,
            version: SYSTEM_TELEMETRY_DIGEST_VERSION,
            flags: 0,
            mod_id: 1,
            system_hash: fnv1a_64_hash_system("d::l", "step"),
            frame_seq: 5,
            matched_entities: 64,
            matched_tables: 4,
            skipped_summary_tick_tables: 1,
            chunks: 2,
            p50_us: 25,
            p99_us: 40,
            commands_queued: 0,
            reserved: 0,
        });
        let lenses = compute_code_lenses(src, &store);
        let title = &lenses[0].command.as_ref().unwrap().title;
        assert!(title.contains("p50: 25 us") && title.contains("entities: 64"));
    }
}
