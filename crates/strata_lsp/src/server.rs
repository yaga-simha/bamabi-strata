//! `tower-lsp` [`LanguageServer`] implementation backed by `strata_sema` and `strata_syntax`.

use crate::telemetry::{
    SystemTelemetryDigest64, SystemTelemetryDigestJson, TELEMETRY_FLAG_QUARANTINED, TelemetryError,
    TelemetryStore, decode_digest_slice,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use strata_sema::db::Setter;
use strata_sema::{AnalyzedModule, SemaDb, Severity, SourceFile, analyze_source};
use strata_syntax::fmt::format_source;
use tower_lsp::jsonrpc::{Error as JsonRpcError, Result as LspResult};
use tower_lsp::lsp_types::{
    CodeLens, Command, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentFormattingParams, Hover,
    HoverContents, HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
    MarkupContent, MarkupKind, MessageType, NumberOrString, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url,
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

struct LspState {
    db: SemaDb,
    files: HashMap<Url, SourceFile>,
}

/// `tower-lsp` backend for Strata v2.0 `.strata` source files.
pub struct StrataLspBackend {
    client: Option<Client>,
    state: Arc<Mutex<LspState>>,
    telemetry: TelemetryStore,
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
            let guard = self
                .state
                .lock()
                .map_err(|_| JsonRpcError::internal_error())?;
            if let Some(&sf) = guard.files.get(uri) {
                let analyzed = guard.db.analyze_file(sf);
                let ids = collect_document_node_ids(sf.text(&guard.db), &analyzed);
                (Some(analyzed.module_path.clone()), Some(ids))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let targets: Vec<String> = match (params.node_ids, known_ids) {
            (Some(requested), Some(known)) => requested
                .into_iter()
                .filter(|id| known.contains(id))
                .collect(),
            (Some(requested), None) => requested,
            (None, Some(known)) => known.into_iter().collect(),
            (None, None) => Vec::new(),
        };

        let mut nodes = BTreeMap::new();
        let mod_prefix = module_path.as_deref().map(|mp| format!("{mp}::"));
        for node_id in targets {
            let bare = mod_prefix
                .as_deref()
                .and_then(|prefix| node_id.strip_prefix(prefix))
                .or_else(|| node_id.rsplit("::").next());
            if let Some((digest, matched_by)) = self.telemetry.get_for_node(&node_id, bare) {
                nodes.insert(
                    node_id.clone(),
                    GraphNodeTelemetry {
                        node_id,
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

/// Maps UTF-8 byte offsets into LSP `(line, utf16_col)` coordinates.
fn byte_offset_to_position(source: &str, byte_offset: u32) -> Position {
    let clamped = (byte_offset as usize).min(source.len());
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if idx >= clamped {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    Position::new(line, col)
}

fn position_to_byte_offset(source: &str, pos: Position) -> usize {
    let mut cur_line = 0u32;
    let mut cur_col = 0u32;
    for (idx, ch) in source.char_indices() {
        if cur_line == pos.line && cur_col >= pos.character {
            return idx;
        }
        if cur_line > pos.line {
            return idx;
        }
        if ch == '\n' {
            if cur_line == pos.line {
                return idx;
            }
            cur_line += 1;
            cur_col = 0;
        } else {
            cur_col += ch.len_utf16() as u32;
        }
    }
    source.len()
}

fn word_at_position(source: &str, pos: Position) -> Option<String> {
    let off = position_to_byte_offset(source, pos);
    let bytes = source.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let idx = off.min(bytes.len() - 1);
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let pivot = if is_ident(bytes[idx]) {
        idx
    } else if idx > 0 && is_ident(bytes[idx - 1]) {
        idx - 1
    } else {
        return None;
    };
    let mut start = pivot;
    while start > 0 && is_ident(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = pivot + 1;
    while end < bytes.len() && is_ident(bytes[end]) {
        end += 1;
    }
    Some(source[start..end].to_owned())
}

fn diagnostics_from_analyzed(source: &str, analyzed: &AnalyzedModule) -> Vec<Diagnostic> {
    analyzed
        .diagnostics
        .iter()
        .map(|d| {
            let start = byte_offset_to_position(source, d.span.byte_start);
            let end = byte_offset_to_position(source, d.span.byte_end.max(d.span.byte_start + 1));
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

fn compute_hover_from_analyzed(
    source: &str,
    pos: Position,
    analyzed: &AnalyzedModule,
) -> Option<Hover> {
    let ident = word_at_position(source, pos)?;

    if let Some((_, layout)) = analyzed.layouts.iter().find(|(k, l)| {
        *k == &ident
            || l.canonical_name == ident
            || l.canonical_name.rsplit("::").next() == Some(ident.as_str())
    }) {
        let md = format!(
            "### `{}` (`{:?}`)\n\n\
             - **Size:** `{} B` (`align {} B`)\n\
             - **AbiPod:** `{}` (explicit padding: `{} B`)\n\
             - **ComponentUuid:** `{}`\n\
             - **Schema Fingerprint:** `0x{:016X}`",
            layout.canonical_name,
            layout.item_kind,
            layout.size,
            layout.align,
            layout.is_abi_pod,
            layout.explicit_pad_bytes,
            layout.uuid_hex,
            layout.schema_fingerprint
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: None,
        });
    }

    if let Some(callable) = analyzed.callables.iter().find(|c| c.name == ident) {
        let par_info = callable.par_chunk.map_or_else(
            || "sequential".to_owned(),
            |c| format!("`@par(chunk = {c})`"),
        );
        let md = format!(
            "### `{} {}`\n\n\
             - **Scheduling:** {}\n\
             - **Queries:** `{}` | **Resources:** `{}` reads / `{}` writes",
            if callable.is_observer { "obs" } else { "sys" },
            callable.name,
            par_info,
            callable.access.queries.len(),
            callable.access.res_reads.len(),
            callable.access.res_writes.len(),
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: None,
        });
    }

    None
}

/// Computes Markdown hover information showing solved `size`, `align`, `ComponentUuid`,
/// `SCHEMA_FINGERPRINT`, explicit padding, or callable concurrency summary.
#[must_use]
pub fn compute_hover(source: &str, pos: Position) -> Option<Hover> {
    let _ = word_at_position(source, pos)?;
    let analyzed = analyze_source("buffer.strata", source);
    compute_hover_from_analyzed(source, pos, &analyzed)
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
    analyzed: &AnalyzedModule,
    telemetry: &TelemetryStore,
) -> Vec<CodeLens> {
    let mut lenses = Vec::new();

    for callable in &analyzed.callables {
        let pos = byte_offset_to_position(source, callable.byte_range.0);
        let range = Range::new(pos, pos);

        let par_tag = match callable.par_chunk {
            Some(c) if callable.par_read_only => format!("@par(read_only, chunk={c})"),
            Some(c) => format!("@par(chunk={c})"),
            None => {
                let conflict_cnt = analyzed
                    .concurrency_graph
                    .conflicts
                    .iter()
                    .filter(|e| e.system_a == callable.name || e.system_b == callable.name)
                    .count();
                format!("seq (conflicts={conflict_cnt})")
            }
        };

        let canonical_id = qualify_node_id(&analyzed.module_path, &callable.name);
        let title = if let Some((t, _)) =
            telemetry.get_for_node(&canonical_id, Some(&callable.name))
        {
            let q_tag = if (t.flags & TELEMETRY_FLAG_QUARANTINED) != 0 {
                " [QUARANTINED]"
            } else {
                ""
            };
            format!(
                "{par_tag} | p50: {} us | p99: {} us | entities: {} | tables: {} | skipped: {} | cmds: {}{q_tag}",
                t.p50_us,
                t.p99_us,
                t.matched_entities,
                t.matched_tables,
                t.skipped_summary_tick_tables,
                t.commands_queued
            )
        } else {
            format!("strata: {par_tag} (no live telemetry)")
        };

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

/// Computes CodeLens annotations showing Theorem 0.1 `@par` concurrency and live
/// `SystemTelemetryDigest64` frame timings / heap allocation counters.
#[must_use]
pub fn compute_code_lenses(source: &str, telemetry: &TelemetryStore) -> Vec<CodeLens> {
    let analyzed = analyze_source("buffer.strata", source);
    compute_code_lenses_from_analyzed(source, &analyzed, telemetry)
}

#[tower_lsp::async_trait]
impl LanguageServer for StrataLspBackend {
    async fn initialize(&self, _: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_formatting_provider: Some(tower_lsp::lsp_types::OneOf::Left(true)),
                code_lens_provider: Some(tower_lsp::lsp_types::CodeLensOptions {
                    resolve_provider: Some(false),
                }),
                ..ServerCapabilities::default()
            },
            ..InitializeResult::default()
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
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let diags = self
            .state
            .lock()
            .map(|mut state| {
                let sf = if let Some(&existing) = state.files.get(&uri) {
                    if existing.text(&state.db) != &text {
                        existing.set_text(&mut state.db).to(text);
                    }
                    existing
                } else {
                    let sf = state.db.new_source(uri.to_string(), text);
                    state.files.insert(uri.clone(), sf);
                    sf
                };
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
                        .map(|&sf| sf.text(&state.db).clone())
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

                let sf = if let Some(&existing) = state.files.get(&uri) {
                    if existing.text(&state.db) != &new_text {
                        existing.set_text(&mut state.db).to(new_text);
                    }
                    existing
                } else {
                    let sf = state.db.new_source(uri.to_string(), new_text);
                    state.files.insert(uri.clone(), sf);
                    sf
                };
                let analyzed = state.db.analyze_file(sf);
                diagnostics_from_analyzed(sf.text(&state.db), &analyzed)
            })
            .unwrap_or_default();
        self.publish_diagnostics(uri, diags).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Ok(mut state) = self.state.lock() {
            state.files.remove(&params.text_document.uri);
        }
    }

    async fn hover(&self, params: tower_lsp::lsp_types::HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let result = self.state.lock().ok().and_then(|state| {
            let sf = state.files.get(uri).copied()?;
            let text = sf.text(&state.db);
            let _ = word_at_position(text, pos)?;
            let _cst = state.db.parse_file(sf);
            let analyzed = state.db.analyze_file(sf);
            compute_hover_from_analyzed(text, pos, &analyzed)
        });
        Ok(result)
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> LspResult<Option<Vec<TextEdit>>> {
        let uri = &params.text_document.uri;
        let result = self.state.lock().ok().and_then(|state| {
            let sf = state.files.get(uri).copied()?;
            Some(compute_formatting(sf.text(&state.db)))
        });
        Ok(result)
    }

    async fn code_lens(
        &self,
        params: tower_lsp::lsp_types::CodeLensParams,
    ) -> LspResult<Option<Vec<CodeLens>>> {
        let uri = &params.text_document.uri;
        let result = self.state.lock().ok().and_then(|state| {
            let sf = state.files.get(uri).copied()?;
            let _cst = state.db.parse_file(sf);
            let analyzed = state.db.analyze_file(sf);
            Some(compute_code_lenses_from_analyzed(
                sf.text(&state.db),
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
