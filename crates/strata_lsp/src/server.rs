//! `tower-lsp` [`LanguageServer`] implementation backed by `strata_sema` and `strata_syntax`.

use crate::telemetry::TelemetryStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use strata_sema::{SemaDb, Severity, analyze_source};
use strata_syntax::fmt::format_source;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::{
    CodeLens, Command, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentFormattingParams, Hover,
    HoverContents, HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
    MarkupContent, MarkupKind, MessageType, NumberOrString, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url,
};
use tower_lsp::{Client, LanguageServer};

/// `tower-lsp` backend for Strata v2.0 `.strata` source files.
pub struct StrataLspBackend {
    client: Option<Client>,
    docs: Arc<Mutex<HashMap<Url, String>>>,
    db: Arc<Mutex<SemaDb>>,
    telemetry: TelemetryStore,
}

impl StrataLspBackend {
    /// Creates an LSP backend wired to a connected `tower-lsp` client handle.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self {
            client: Some(client),
            docs: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(SemaDb::default())),
            telemetry: TelemetryStore::new(),
        }
    }

    /// Creates a headless [`StrataLspBackend`] suitable for in-process testing without stdio.
    #[must_use]
    pub fn headless(telemetry: TelemetryStore) -> Self {
        Self {
            client: None,
            docs: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(SemaDb::default())),
            telemetry,
        }
    }

    /// Returns a shared handle to the live [`TelemetryStore`].
    #[must_use]
    pub fn telemetry(&self) -> &TelemetryStore {
        &self.telemetry
    }

    async fn publish_doc_diagnostics(&self, uri: Url, text: &str) {
        let diags = {
            let _guard = self.db.lock().ok();
            compute_diagnostics(text)
        };
        if let Some(client) = &self.client {
            client.publish_diagnostics(uri, diags, None).await;
        }
    }
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

/// Computes LSP diagnostics from `strata_sema::analyze_source`.
#[must_use]
pub fn compute_diagnostics(source: &str) -> Vec<Diagnostic> {
    let analyzed = analyze_source("buffer.strata", source);
    analyzed
        .diagnostics
        .into_iter()
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
                code: Some(NumberOrString::String(d.code.to_owned())),
                code_description: None,
                source: Some("strata".to_owned()),
                message: d.message,
                related_information: None,
                tags: None,
                data: None,
            }
        })
        .collect()
}

/// Computes Markdown hover information showing solved `size`, `align`, `ComponentUuid`,
/// `SCHEMA_FINGERPRINT`, explicit padding, or callable concurrency summary.
#[must_use]
pub fn compute_hover(source: &str, pos: Position) -> Option<Hover> {
    let ident = word_at_position(source, pos)?;
    let analyzed = analyze_source("buffer.strata", source);

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

/// Computes CodeLens annotations showing Theorem 0.1 `@par` concurrency and live
/// `SystemTelemetryDigest64` frame timings / heap allocation counters.
#[must_use]
pub fn compute_code_lenses(source: &str, telemetry: &TelemetryStore) -> Vec<CodeLens> {
    let analyzed = analyze_source("buffer.strata", source);
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

        let title = if let Some(t) = telemetry.get_for_system(&callable.name) {
            format!(
                "{par_tag} | avg: {:.2} us | p99: {:.2} us | entities: {} | dirty: {} | alloc: {} B",
                t.avg_ns as f64 / 1000.0,
                t.p99_ns as f64 / 1000.0,
                t.entity_count,
                t.dirty_rows,
                t.alloc_bytes
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
        if let Ok(mut guard) = self.docs.lock() {
            guard.insert(uri.clone(), text.clone());
        }
        self.publish_doc_diagnostics(uri, &text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        if let Some(change) = params.content_changes.into_iter().last() {
            if let Ok(mut guard) = self.docs.lock() {
                guard.insert(uri.clone(), change.text.clone());
            }
            self.publish_doc_diagnostics(uri, &change.text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Ok(mut guard) = self.docs.lock() {
            guard.remove(&params.text_document.uri);
        }
    }

    async fn hover(&self, params: tower_lsp::lsp_types::HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let text = self.docs.lock().ok().and_then(|g| g.get(uri).cloned());
        Ok(text.and_then(|src| compute_hover(&src, pos)))
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> LspResult<Option<Vec<TextEdit>>> {
        let uri = &params.text_document.uri;
        let text = self.docs.lock().ok().and_then(|g| g.get(uri).cloned());
        Ok(text.map(|src| compute_formatting(&src)))
    }

    async fn code_lens(
        &self,
        params: tower_lsp::lsp_types::CodeLensParams,
    ) -> LspResult<Option<Vec<CodeLens>>> {
        let uri = &params.text_document.uri;
        let text = self.docs.lock().ok().and_then(|g| g.get(uri).cloned());
        Ok(text.map(|src| compute_code_lenses(&src, &self.telemetry)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{
        SystemTelemetryDigest64, TELEMETRY_DIGEST_MAGIC, TELEMETRY_DIGEST_VERSION, system_name_hash,
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
            magic: TELEMETRY_DIGEST_MAGIC,
            version: TELEMETRY_DIGEST_VERSION,
            flags: 0,
            system_name_hash: system_name_hash("step"),
            frame_index: 5,
            avg_ns: 2500,
            p99_ns: 4000,
            entity_count: 64,
            dirty_rows: 4,
            alloc_bytes: 0,
        });
        let lenses = compute_code_lenses(src, &store);
        let title = &lenses[0].command.as_ref().unwrap().title;
        assert!(title.contains("2.50 us") && title.contains("alloc: 0 B"));
    }
}
