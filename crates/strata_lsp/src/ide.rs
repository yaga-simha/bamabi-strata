//! Rich IDE Language Server features for Strata v2.0 (Zed & LSP clients).
//!
//! Provides CST- and `strata_sema`-backed:
//! - Hierarchical document symbols (`textDocument/documentSymbol`) and workspace symbol search
//!   (`workspace/symbol`).
//! - Go-to-definition (`textDocument/definition`) across local bindings, top-level items, fields,
//!   enum variants, `@soa` strata, FSM states, and open workspace documents.
//! - Token-accurate document highlights (`textDocument/documentHighlight`) and workspace-wide
//!   find-references (`textDocument/references`) that ignore comments and string literals.
//! - Context-aware autocompletion (`textDocument/completion`) for `@attributes`, `.field`
//!   projections, `::` enum variants / `@soa` strata, declared symbols, built-in types, and
//!   keywords.
//! - Compact inline inlay hints (`textDocument/inlayHint`) showing solved `AbiPod` size/alignment
//!   and Theorem 0.1 `@par` / conflict summaries.
//! - Rich Markdown hover cards (`textDocument/hover`) covering layouts (with field offset tables),
//!   systems/observers (with live `"BAMT"` telemetry), functions, enums, RPCs, FSMs, timelines,
//!   tasks, tables, curves, schedules, and constants.

use crate::telemetry::{TELEMETRY_FLAG_QUARANTINED, TelemetryEndpoint, TelemetryStore};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use strata_sema::{AnalyzedModule, SolvedLayout, Ty, analyze_source};
use strata_syntax::ast::{self, AstNode, Item};
use strata_syntax::{SyntaxKind, SyntaxNode, SyntaxToken, TextRange};
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, DocumentHighlight, DocumentHighlightKind, DocumentSymbol,
    Documentation, Hover, HoverContents, InlayHint, InlayHintKind, InlayHintLabel,
    InlayHintTooltip, InsertTextFormat, Location, MarkupContent, MarkupKind, Position, Range,
    SymbolInformation, SymbolKind, Url,
};

/// Precomputed O(log L) line-start index with an O(1) ASCII fast path for UTF-8 <-> LSP UTF-16
/// position conversions.
#[derive(Debug, Clone)]
pub(crate) struct LineIndex {
    line_starts: Vec<u32>,
    is_ascii: bool,
    len: usize,
}

impl LineIndex {
    /// Builds a [`LineIndex`] in a single linear byte pass over `source`.
    #[must_use]
    pub(crate) fn new(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut line_starts = Vec::with_capacity((bytes.len() / 32).max(16));
        line_starts.push(0);
        let mut is_ascii = true;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            } else if b >= 0x80 {
                is_ascii = false;
            }
        }
        Self {
            line_starts,
            is_ascii,
            len: bytes.len(),
        }
    }

    /// Maps a UTF-8 byte offset in `source` into an LSP `(line, utf16_col)` [`Position`]
    /// in O(log L) time (with O(1) column calculation for ASCII documents).
    #[inline]
    #[must_use]
    pub(crate) fn byte_offset_to_position(&self, source: &str, byte_offset: u32) -> Position {
        let clamped = (byte_offset as usize).min(self.len);
        let line = self
            .line_starts
            .partition_point(|&start| (start as usize) <= clamped)
            .saturating_sub(1);
        let line_start = self.line_starts[line] as usize;
        if self.is_ascii {
            return Position::new(line as u32, (clamped - line_start) as u32);
        }
        let mut col = 0u32;
        if let Some(slice) = source.get(line_start..clamped) {
            for ch in slice.chars() {
                col += ch.len_utf16() as u32;
            }
        }
        Position::new(line as u32, col)
    }

    /// Maps an LSP `(line, utf16_col)` [`Position`] into a UTF-8 byte offset in `source`
    /// in O(1) time for ASCII documents and O(line_len) for non-ASCII lines.
    #[inline]
    #[must_use]
    pub(crate) fn position_to_byte_offset(&self, source: &str, pos: Position) -> usize {
        let line = pos.line as usize;
        let Some(&line_start_u32) = self.line_starts.get(line) else {
            return self.len;
        };
        let line_start = line_start_u32 as usize;
        let line_end = self
            .line_starts
            .get(line + 1)
            .map_or(self.len, |&next| (next as usize).saturating_sub(1));
        if self.is_ascii {
            return (line_start + pos.character as usize).min(line_end);
        }
        let Some(slice) = source.get(line_start..line_end) else {
            return line_end;
        };
        let mut cur_col = 0u32;
        for (rel_idx, ch) in slice.char_indices() {
            if cur_col >= pos.character {
                return line_start + rel_idx;
            }
            cur_col += ch.len_utf16() as u32;
        }
        line_end
    }

    /// Converts a `rowan` byte [`TextRange`] to an LSP [`Range`].
    #[inline]
    #[must_use]
    pub(crate) fn text_range_to_lsp_range(&self, source: &str, range: TextRange) -> Range {
        Range::new(
            self.byte_offset_to_position(source, u32::from(range.start())),
            self.byte_offset_to_position(source, u32::from(range.end())),
        )
    }

    /// Extracts the borrowed identifier slice and its LSP/byte span under `pos` without allocating.
    #[must_use]
    pub(crate) fn word_range_at_position<'a>(
        &self,
        source: &'a str,
        pos: Position,
    ) -> Option<(&'a str, Range, usize, usize)> {
        let off = self.position_to_byte_offset(source, pos);
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
        let range = Range::new(
            self.byte_offset_to_position(source, start as u32),
            self.byte_offset_to_position(source, end as u32),
        );
        Some((&source[start..end], range, start, end))
    }

    /// Extracts the borrowed identifier slice at `pos`, if any.
    #[inline]
    #[must_use]
    pub(crate) fn word_at_position<'a>(&self, source: &'a str, pos: Position) -> Option<&'a str> {
        self.word_range_at_position(source, pos)
            .map(|(word, _, _, _)| word)
    }
}

/// Maps a UTF-8 byte offset in `source` into an LSP `(line, utf16_col)` [`Position`].
pub(crate) fn byte_offset_to_position(source: &str, byte_offset: u32) -> Position {
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

/// Maps an LSP `(line, utf16_col)` [`Position`] into a UTF-8 byte offset in `source`.
pub(crate) fn position_to_byte_offset(source: &str, pos: Position) -> usize {
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

/// Extracts an optional `Qualifier::Ident` pair if `start` is immediately preceded by `::`.
fn qualifier_before_double_colon(source: &str, ident_start: usize) -> Option<&str> {
    let before = source.get(..ident_start)?.trim_end();
    let before_sep = before.strip_suffix("::")?.trim_end();
    let bytes = before_sep.as_bytes();
    let end = bytes.len();
    if end == 0 {
        return None;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if !is_ident(bytes[end - 1]) {
        return None;
    }
    let mut start = end;
    while start > 0 && is_ident(bytes[start - 1]) {
        start -= 1;
    }
    (start < end).then(|| &before_sep[start..end])
}

/// Constructs a [`DocumentSymbol`] without referencing the deprecated `deprecated` field.
fn make_document_symbol(
    name: String,
    detail: Option<String>,
    kind: SymbolKind,
    range: Range,
    selection_range: Range,
    children: Vec<DocumentSymbol>,
) -> Option<DocumentSymbol> {
    let mut map = serde_json::Map::with_capacity(6);
    map.insert("name".to_owned(), Value::String(name));
    if let Some(d) = detail {
        map.insert("detail".to_owned(), Value::String(d));
    }
    map.insert("kind".to_owned(), serde_json::to_value(kind).ok()?);
    map.insert("range".to_owned(), serde_json::to_value(range).ok()?);
    map.insert(
        "selectionRange".to_owned(),
        serde_json::to_value(selection_range).ok()?,
    );
    if !children.is_empty() {
        map.insert("children".to_owned(), serde_json::to_value(children).ok()?);
    }
    serde_json::from_value(Value::Object(map)).ok()
}

/// Constructs a [`SymbolInformation`] without referencing the deprecated `deprecated` field.
fn make_symbol_information(
    name: String,
    kind: SymbolKind,
    location: Location,
    container_name: Option<String>,
) -> Option<SymbolInformation> {
    let mut map = serde_json::Map::with_capacity(4);
    map.insert("name".to_owned(), Value::String(name));
    map.insert("kind".to_owned(), serde_json::to_value(kind).ok()?);
    map.insert("location".to_owned(), serde_json::to_value(location).ok()?);
    if let Some(container) = container_name {
        map.insert("containerName".to_owned(), Value::String(container));
    }
    serde_json::from_value(Value::Object(map)).ok()
}

/// A flat indexed declaration extracted from a Strata CST for go-to-definition and symbol search.
#[derive(Debug, Clone)]
pub(crate) struct DeclEntry {
    pub(crate) name: String,
    pub(crate) parent: Option<String>,
    pub(crate) kind: SymbolKind,
    pub(crate) lsp_range: Range,
}

/// Pre-built workspace symbol entry with lowercase search keys for fast `workspace/symbol` queries.
#[derive(Debug, Clone)]
pub(crate) struct IndexedWorkspaceSymbol {
    pub(crate) lower_name: String,
    pub(crate) lower_qualified: String,
    pub(crate) info: SymbolInformation,
}

/// Pre-indexed receiver type map and query aliases for O(1) `.` member completion.
#[derive(Debug, Clone, Default)]
pub(crate) struct DotCompletionIndex {
    pub(crate) receiver_types: HashMap<String, String>,
    pub(crate) query_aliases: Vec<(String, String)>,
}

/// Cached documentation comments extracted from leading `///`, `//!`, and `/** ... */` CST
/// trivia for top-level constructs and their nested members.
#[derive(Debug, Clone, Default)]
pub(crate) struct DocCommentIndex {
    pub(crate) items: HashMap<String, String>,
    pub(crate) item_kinds: HashMap<String, &'static str>,
    pub(crate) members: HashMap<(String, String), String>,
}

fn clean_line_doc(text: &str, allow_inner: bool) -> Option<String> {
    let is_doc = (text.starts_with("///") && !text.starts_with("////"))
        || (allow_inner && text.starts_with("//!"));
    if !is_doc {
        return None;
    }
    let raw = &text[3..];
    let trimmed_cr = raw.strip_suffix('\r').unwrap_or(raw);
    let stripped = trimmed_cr.strip_prefix(' ').unwrap_or(trimmed_cr);
    Some(stripped.to_owned())
}

fn clean_block_doc(text: &str, allow_inner: bool) -> Option<String> {
    let is_outer = text.starts_with("/**") && !text.starts_with("/***");
    let is_inner = allow_inner && text.starts_with("/*!") && !text.starts_with("/*!*");
    if !(is_outer || is_inner) || !text.ends_with("*/") || text.len() < 5 {
        return None;
    }
    let inner = &text[3..text.len() - 2];

    let mut lines: Vec<&str> = inner
        .lines()
        .map(|line| {
            let trimmed_cr = line.strip_suffix('\r').unwrap_or(line);
            let leading = trimmed_cr.trim_start();
            if let Some(after_star) = leading.strip_prefix('*') {
                after_star.strip_prefix(' ').unwrap_or(after_star)
            } else {
                trimmed_cr
            }
        })
        .collect();

    while lines.first().is_some_and(|l| l.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return None;
    }
    Some(lines.join("\n"))
}

enum TriviaStep {
    Doc(String),
    Continue,
    Stop,
}

fn classify_doc_trivia_token(tok: &SyntaxToken, allow_inner: bool) -> TriviaStep {
    match tok.kind() {
        SyntaxKind::Whitespace => {
            let newlines = tok.text().bytes().filter(|&b| b == b'\n').count();
            if newlines >= 2 {
                TriviaStep::Stop
            } else {
                TriviaStep::Continue
            }
        }
        SyntaxKind::LineComment => match clean_line_doc(tok.text(), allow_inner) {
            Some(line) => TriviaStep::Doc(line),
            None => TriviaStep::Stop,
        },
        SyntaxKind::BlockComment => match clean_block_doc(tok.text(), allow_inner) {
            Some(block) => TriviaStep::Doc(block),
            None => TriviaStep::Stop,
        },
        _ => TriviaStep::Stop,
    }
}

/// Extracts contiguous leading doc comments (`///`, `/** ... */`, and `//!` when `allow_inner`)
/// attached to `node`, checking both leading trivia inside `node` and preceding sibling tokens
/// in its parent, stopping at any non-doc token or blank line (`>= 2` newlines).
#[must_use]
pub(crate) fn extract_doc_comment(node: &SyntaxNode, allow_inner: bool) -> Option<String> {
    let mut chunks = Vec::new();
    let mut inner_leading = Vec::new();
    for el in node.children_with_tokens() {
        if let Some(tok) = el.into_token() {
            if tok.kind().is_trivia() {
                inner_leading.push(tok);
            } else {
                break;
            }
        } else {
            break;
        }
    }

    let mut stopped = false;
    for tok in inner_leading.iter().rev() {
        match classify_doc_trivia_token(tok, allow_inner) {
            TriviaStep::Doc(s) => chunks.push(s),
            TriviaStep::Continue => {}
            TriviaStep::Stop => {
                stopped = true;
                break;
            }
        }
    }

    if !stopped {
        let mut cursor = node.prev_sibling_or_token();
        while let Some(el) = cursor {
            let next = el.prev_sibling_or_token();
            let Some(tok) = el.into_token() else {
                break;
            };
            match classify_doc_trivia_token(&tok, allow_inner) {
                TriviaStep::Doc(s) => chunks.push(s),
                TriviaStep::Continue => {}
                TriviaStep::Stop => break,
            }
            cursor = next;
        }
    }

    if chunks.is_empty() && allow_inner {
        let mut cursor = node.next_sibling_or_token();
        while let Some(el) = cursor {
            let next = el.next_sibling_or_token();
            let Some(tok) = el.into_token() else {
                break;
            };
            match tok.kind() {
                SyntaxKind::Whitespace => {
                    if tok.text().bytes().filter(|&b| b == b'\n').count() >= 2 {
                        break;
                    }
                }
                SyntaxKind::LineComment => match clean_line_doc(tok.text(), true) {
                    Some(s) if tok.text().starts_with("//!") => chunks.push(s),
                    _ => break,
                },
                SyntaxKind::BlockComment => match clean_block_doc(tok.text(), true) {
                    Some(s) if tok.text().starts_with("/*!") => chunks.push(s),
                    _ => break,
                },
                _ => break,
            }
            cursor = next;
        }
        if !chunks.is_empty() {
            let joined = chunks.join("\n");
            return (!joined.trim().is_empty()).then_some(joined);
        }
    }

    if chunks.is_empty() {
        return None;
    }
    chunks.reverse();
    let joined = chunks.join("\n");
    (!joined.trim().is_empty()).then_some(joined)
}

fn index_field_docs(
    members: &mut HashMap<(String, String), String>,
    parent_name: &str,
    fields: &[ast::FieldDecl],
) {
    for field in fields {
        if let Some(tok) = field.name()
            && let Some(doc) = extract_doc_comment(field.syntax(), false)
        {
            members.insert((parent_name.to_owned(), tok.text().to_owned()), doc);
        }
    }
}

impl DocCommentIndex {
    /// Extracts and indexes doc comments for all top-level items and nested members in `root`.
    #[must_use]
    pub(crate) fn build(root: &SyntaxNode) -> Self {
        let mut idx = Self::default();
        let Some(sf) = ast::SourceFile::cast(root.clone()) else {
            return idx;
        };

        for item in sf.items() {
            match item {
                Item::Module(m) => {
                    if let Some(path) = m.path() {
                        let name = ast::path_text(&path);
                        idx.item_kinds.insert(name.clone(), "module");
                        if let Some(doc) = extract_doc_comment(m.syntax(), true) {
                            idx.items.insert(name, doc);
                        }
                    }
                }
                Item::Component(c) => {
                    if let Some(tok) = c.name() {
                        let name = tok.text().to_owned();
                        idx.item_kinds.insert(name.clone(), "component");
                        if let Some(doc) = extract_doc_comment(c.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        let strata = c.strata();
                        if strata.is_empty() {
                            index_field_docs(&mut idx.members, &name, &c.fields());
                        } else {
                            for s in &strata {
                                let s_name = s.stratum_name();
                                if let Some(doc) = extract_doc_comment(s.syntax(), false) {
                                    idx.members.insert((name.clone(), s_name.clone()), doc);
                                }
                                let fields = s.fields();
                                index_field_docs(&mut idx.members, &name, &fields);
                                index_field_docs(
                                    &mut idx.members,
                                    &format!("{name}::{s_name}"),
                                    &fields,
                                );
                                index_field_docs(
                                    &mut idx.members,
                                    &format!("{name}__{s_name}"),
                                    &fields,
                                );
                            }
                        }
                    }
                }
                Item::Struct(s) => {
                    if let Some(tok) = s.name() {
                        let name = tok.text().to_owned();
                        idx.item_kinds.insert(name.clone(), "struct");
                        if let Some(doc) = extract_doc_comment(s.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        index_field_docs(&mut idx.members, &name, &s.fields());
                    }
                }
                Item::Resource(r) => {
                    if let Some(tok) = r.name() {
                        let name = tok.text().to_owned();
                        idx.item_kinds.insert(name.clone(), "resource");
                        if let Some(doc) = extract_doc_comment(r.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        index_field_docs(&mut idx.members, &name, &r.fields());
                    }
                }
                Item::Event(e) => {
                    if let Some((name, _)) = first_ident_or_path(e.syntax()) {
                        idx.item_kinds.insert(name.clone(), "event");
                        if let Some(doc) = extract_doc_comment(e.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        let fields: Vec<ast::FieldDecl> = ast::children(e.syntax()).collect();
                        index_field_docs(&mut idx.members, &name, &fields);
                    }
                }
                Item::Stream(s) => {
                    if let Some((name, _)) = first_ident_or_path(s.syntax()) {
                        idx.item_kinds.insert(name.clone(), "stream");
                        if let Some(doc) = extract_doc_comment(s.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        let fields: Vec<ast::FieldDecl> = ast::children(s.syntax()).collect();
                        index_field_docs(&mut idx.members, &name, &fields);
                    }
                }
                Item::Rpc(r) => {
                    if let Some((name, _)) = first_ident_or_path(r.syntax()) {
                        idx.item_kinds.insert(name.clone(), "rpc");
                        if let Some(doc) = extract_doc_comment(r.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        let fields: Vec<ast::FieldDecl> = ast::children(r.syntax()).collect();
                        index_field_docs(&mut idx.members, &name, &fields);
                    }
                }
                Item::Relation(r) => {
                    if let Some((name, _)) = first_ident_or_path(r.syntax()) {
                        idx.item_kinds.insert(name.clone(), "relation");
                        if let Some(doc) = extract_doc_comment(r.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        let fields: Vec<ast::FieldDecl> = ast::children(r.syntax()).collect();
                        index_field_docs(&mut idx.members, &name, &fields);
                    }
                }
                Item::Enum(e) => {
                    if let Some(tok) = e.name() {
                        let name = tok.text().to_owned();
                        idx.item_kinds.insert(name.clone(), "enum");
                        if let Some(doc) = extract_doc_comment(e.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        for v in e.variants() {
                            if let Some(vtok) = ast::first_ident(v.syntax())
                                && let Some(doc) = extract_doc_comment(v.syntax(), false)
                            {
                                idx.members
                                    .insert((name.clone(), vtok.text().to_owned()), doc);
                            }
                        }
                    }
                }
                Item::Tag(t) => {
                    let doc = extract_doc_comment(t.syntax(), false);
                    for el in t.syntax().children_with_tokens() {
                        if let Some(tok) = el.into_token()
                            && tok.kind() == SyntaxKind::Ident
                        {
                            let name = tok.text().to_owned();
                            idx.item_kinds.insert(name.clone(), "tag");
                            if let Some(ref d) = doc {
                                idx.items.insert(name, d.clone());
                            }
                        }
                    }
                }
                Item::Timeline(t) => {
                    if let Some((name, _)) = first_ident_or_path(t.syntax()) {
                        idx.item_kinds.insert(name.clone(), "timeline");
                        if let Some(doc) = extract_doc_comment(t.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        for w in ast::children::<ast::TimelineWindow>(t.syntax()) {
                            if let Some(wtok) = ast::first_ident(w.syntax())
                                && let Some(doc) = extract_doc_comment(w.syntax(), false)
                            {
                                idx.members
                                    .insert((name.clone(), wtok.text().to_owned()), doc);
                            }
                        }
                    }
                }
                Item::Fsm(f) => {
                    if let Some((name, _)) = first_ident_or_path(f.syntax()) {
                        idx.item_kinds.insert(name.clone(), "fsm");
                        if let Some(doc) = extract_doc_comment(f.syntax(), false) {
                            idx.items.insert(name.clone(), doc);
                        }
                        for st in ast::children::<ast::StateDecl>(f.syntax()) {
                            if let Some(stok) = ast::first_ident(st.syntax())
                                && let Some(doc) = extract_doc_comment(st.syntax(), false)
                            {
                                idx.members
                                    .insert((name.clone(), stok.text().to_owned()), doc);
                            }
                        }
                    }
                }
                _ => {
                    let kind_label = match &item {
                        Item::Const(_) => Some("const"),
                        Item::Table(_) => Some("table"),
                        Item::Curve(_) => Some("curve"),
                        Item::SpatialGrid(_) => Some("spatial_grid"),
                        Item::SpatialHistory(_) => Some("spatial_history"),
                        Item::HashIndex(_) => Some("hash_index"),
                        Item::Aspect(_) => Some("aspect"),
                        Item::Prefab(_) => Some("prefab"),
                        Item::Object(_) => Some("object"),
                        Item::Zone(_) => Some("zone"),
                        Item::Task(_) => Some("task"),
                        Item::Sys(_) => Some("sys"),
                        Item::Obs(_) => Some("obs"),
                        Item::Fn(_) => Some("fn"),
                        Item::Schedule(_) => Some("schedule"),
                        _ => None,
                    };
                    if let Some(kind_str) = kind_label
                        && let Some((name, _)) = first_ident_or_path(item.syntax())
                    {
                        idx.item_kinds.insert(name.clone(), kind_str);
                        if let Some(doc) = extract_doc_comment(item.syntax(), false) {
                            idx.items.insert(name, doc);
                        }
                    }
                }
            }
        }
        idx
    }
}

fn find_layout<'a>(analyzed: &'a AnalyzedModule, short_name: &str) -> Option<&'a SolvedLayout> {
    analyzed.layouts.iter().find_map(|(k, l)| {
        if k == short_name
            || l.canonical_name == short_name
            || l.canonical_name.rsplit("::").next() == Some(short_name)
        {
            Some(l)
        } else {
            None
        }
    })
}

fn format_layout_summary(layout: &SolvedLayout) -> String {
    if layout.explicit_pad_bytes > 0 {
        format!(
            "{} B, align {}, +{} B pad",
            layout.size, layout.align, layout.explicit_pad_bytes
        )
    } else if layout.is_abi_pod {
        format!("{} B, align {}, AbiPod", layout.size, layout.align)
    } else {
        format!("{} B, align {}", layout.size, layout.align)
    }
}

fn format_ty_short(ty: &Ty) -> String {
    match ty {
        Ty::U8 => "u8".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::U32 => "u32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::I32 => "i32".to_owned(),
        Ty::I64 => "i64".to_owned(),
        Ty::F32 => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Fix32 => "fix32".to_owned(),
        Ty::Fix64 => "fix64".to_owned(),
        Ty::Bool => "bool".to_owned(),
        Ty::Sym => "sym".to_owned(),
        Ty::UnitScalar { name, .. } | Ty::Named(name) => name.clone(),
        Ty::Vec2 => "vec2".to_owned(),
        Ty::Vec3 => "vec3".to_owned(),
        Ty::Vec3a => "vec3a".to_owned(),
        Ty::Vec4 => "vec4".to_owned(),
        Ty::IVec2 => "ivec2".to_owned(),
        Ty::IVec3 => "ivec3".to_owned(),
        Ty::UVec2 => "uvec2".to_owned(),
        Ty::Quat => "quat".to_owned(),
        Ty::Mat3 => "mat3".to_owned(),
        Ty::Mat4 => "mat4".to_owned(),
        Ty::Rgba8 => "rgba8".to_owned(),
        Ty::Rgba => "rgba".to_owned(),
        Ty::Unit => "()".to_owned(),
        Ty::InlineStr(n) => format!("InlineStr<{n}>"),
        Ty::SmallVec { elem, cap } => format!("SmallVec<{}, {cap}>", format_ty_short(elem)),
        Ty::BitSet(n) => format!("BitSet<{n}>"),
        Ty::Array { elem, len } => format!("[{}; {len}]", format_ty_short(elem)),
        Ty::Option(inner) => format!("Option<{}>", format_ty_short(inner)),
        Ty::Result { ok, err } => {
            format!("Result<{}, {}>", format_ty_short(ok), format_ty_short(err))
        }
        Ty::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(format_ty_short).collect();
            format!("({})", parts.join(", "))
        }
        other => format!("{other:?}"),
    }
}

fn node_string_lit(node: &SyntaxNode) -> Option<(String, TextRange)> {
    node.children_with_tokens()
        .filter_map(|el| el.into_token())
        .find(|t| t.kind() == SyntaxKind::StringLit)
        .map(|t| (ast::unquote_string_lit(t.text()), t.text_range()))
}

fn first_ident_or_path(node: &SyntaxNode) -> Option<(String, TextRange)> {
    if let Some(tok) = ast::first_ident(node) {
        return Some((tok.text().to_owned(), tok.text_range()));
    }
    ast::child::<ast::Path>(node).map(|p| (ast::path_text(&p), p.text_range()))
}

fn collect_field_symbols(
    source: &str,
    line_index: &LineIndex,
    fields: &[ast::FieldDecl],
    parent_name: &str,
    decls: &mut Vec<DeclEntry>,
) -> Vec<DocumentSymbol> {
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        let Some(name_tok) = field.name() else {
            continue;
        };
        let name = name_tok.text().to_owned();
        let ty_detail = field
            .type_node()
            .map(|t| t.text().to_string().trim().to_owned());
        let sel_lsp = line_index.text_range_to_lsp_range(source, name_tok.text_range());
        decls.push(DeclEntry {
            name: name.clone(),
            parent: Some(parent_name.to_owned()),
            kind: SymbolKind::FIELD,
            lsp_range: sel_lsp,
        });
        if let Some(sym) = make_document_symbol(
            name,
            ty_detail,
            SymbolKind::FIELD,
            line_index.text_range_to_lsp_range(source, field.text_range()),
            sel_lsp,
            Vec::new(),
        ) {
            out.push(sym);
        }
    }
    out
}

/// Builds hierarchical [`DocumentSymbol`]s and flat [`DeclEntry`]s in one pass over a pre-parsed
/// CST `root` using a precomputed [`LineIndex`].
pub(crate) fn build_symbols_and_decls(
    source: &str,
    line_index: &LineIndex,
    root: &SyntaxNode,
    analyzed: &AnalyzedModule,
) -> (Vec<DocumentSymbol>, Vec<DeclEntry>) {
    let Some(sf) = ast::SourceFile::cast(root.clone()) else {
        return (Vec::new(), Vec::new());
    };

    let mut symbols = Vec::new();
    let mut decls = Vec::new();

    for item in sf.items() {
        let item_range = item.syntax().text_range();
        let (name, sel_range, kind, detail, children) = match item {
            Item::Module(m) => {
                let Some(path) = m.path() else { continue };
                let name = ast::path_text(&path);
                let detail = analyzed
                    .version
                    .as_ref()
                    .map(|v| format!("module @version({}.{}.{})", v.major, v.minor, v.patch))
                    .or_else(|| Some("module".to_owned()));
                (
                    name,
                    path.text_range(),
                    SymbolKind::MODULE,
                    detail,
                    Vec::new(),
                )
            }
            Item::Component(c) => {
                let Some(tok) = c.name() else { continue };
                let name = tok.text().to_owned();
                let detail = find_layout(analyzed, &name)
                    .map(|l| format!("component ({})", format_layout_summary(l)))
                    .or_else(|| Some("component".to_owned()));
                let mut children = Vec::new();
                let strata = c.strata();
                if strata.is_empty() {
                    children.extend(collect_field_symbols(
                        source,
                        line_index,
                        &c.fields(),
                        &name,
                        &mut decls,
                    ));
                } else {
                    for s in &strata {
                        let s_name = s.stratum_name();
                        let s_sel = s
                            .name_token()
                            .map(|t| t.text_range())
                            .unwrap_or_else(|| s.text_range());
                        let s_children = collect_field_symbols(
                            source,
                            line_index,
                            &s.fields(),
                            &format!("{name}::{s_name}"),
                            &mut decls,
                        );
                        let s_sel_lsp = line_index.text_range_to_lsp_range(source, s_sel);
                        decls.push(DeclEntry {
                            name: s_name.clone(),
                            parent: Some(name.clone()),
                            kind: SymbolKind::NAMESPACE,
                            lsp_range: s_sel_lsp,
                        });
                        if let Some(sym) = make_document_symbol(
                            s_name,
                            Some(if s.is_hot() { "hot" } else { "cold" }.to_owned()),
                            SymbolKind::NAMESPACE,
                            line_index.text_range_to_lsp_range(source, s.text_range()),
                            s_sel_lsp,
                            s_children,
                        ) {
                            children.push(sym);
                        }
                    }
                }
                (name, tok.text_range(), SymbolKind::STRUCT, detail, children)
            }
            Item::Struct(s) => {
                let Some(tok) = s.name() else { continue };
                let name = tok.text().to_owned();
                let detail = find_layout(analyzed, &name)
                    .map(|l| format!("struct ({})", format_layout_summary(l)))
                    .or_else(|| Some("struct".to_owned()));
                let children =
                    collect_field_symbols(source, line_index, &s.fields(), &name, &mut decls);
                (name, tok.text_range(), SymbolKind::STRUCT, detail, children)
            }
            Item::Resource(r) => {
                let Some(tok) = r.name() else { continue };
                let name = tok.text().to_owned();
                let detail = find_layout(analyzed, &name)
                    .map(|l| format!("resource ({})", format_layout_summary(l)))
                    .or_else(|| Some("resource".to_owned()));
                let children =
                    collect_field_symbols(source, line_index, &r.fields(), &name, &mut decls);
                (name, tok.text_range(), SymbolKind::OBJECT, detail, children)
            }
            Item::Event(e) => {
                let Some((name, sel)) = first_ident_or_path(e.syntax()) else {
                    continue;
                };
                let detail = find_layout(analyzed, &name)
                    .map(|l| format!("event ({})", format_layout_summary(l)))
                    .or_else(|| Some("event".to_owned()));
                let fields: Vec<ast::FieldDecl> = ast::children(e.syntax()).collect();
                let children =
                    collect_field_symbols(source, line_index, &fields, &name, &mut decls);
                (name, sel, SymbolKind::EVENT, detail, children)
            }
            Item::Stream(s) => {
                let Some((name, sel)) = first_ident_or_path(s.syntax()) else {
                    continue;
                };
                let detail = find_layout(analyzed, &name)
                    .map(|l| format!("stream ({})", format_layout_summary(l)))
                    .or_else(|| Some("stream".to_owned()));
                let fields: Vec<ast::FieldDecl> = ast::children(s.syntax()).collect();
                let children =
                    collect_field_symbols(source, line_index, &fields, &name, &mut decls);
                (name, sel, SymbolKind::EVENT, detail, children)
            }
            Item::Rpc(r) => {
                let Some((name, sel)) = first_ident_or_path(r.syntax()) else {
                    continue;
                };
                let detail = analyzed
                    .rpcs
                    .iter()
                    .find(|h| h.name == name)
                    .map(|h| {
                        format!(
                            "rpc ({:?}, {:?}, {})",
                            h.direction,
                            h.reliability,
                            format_layout_summary(&h.payload_layout)
                        )
                    })
                    .or_else(|| Some("rpc".to_owned()));
                let fields: Vec<ast::FieldDecl> = ast::children(r.syntax()).collect();
                let children =
                    collect_field_symbols(source, line_index, &fields, &name, &mut decls);
                (name, sel, SymbolKind::INTERFACE, detail, children)
            }
            Item::Enum(e) => {
                let Some(tok) = e.name() else { continue };
                let name = tok.text().to_owned();
                let detail = analyzed
                    .enums
                    .get(&name)
                    .map(|ed| format!("enum (repr {})", ed.rust_repr()))
                    .or_else(|| Some("enum".to_owned()));
                let mut children = Vec::new();
                for v in e.variants() {
                    if let Some(vtok) = ast::first_ident(v.syntax()) {
                        let vname = vtok.text().to_owned();
                        let v_sel_lsp =
                            line_index.text_range_to_lsp_range(source, vtok.text_range());
                        decls.push(DeclEntry {
                            name: vname.clone(),
                            parent: Some(name.clone()),
                            kind: SymbolKind::ENUM_MEMBER,
                            lsp_range: v_sel_lsp,
                        });
                        if let Some(sym) = make_document_symbol(
                            vname,
                            None,
                            SymbolKind::ENUM_MEMBER,
                            line_index.text_range_to_lsp_range(source, v.text_range()),
                            v_sel_lsp,
                            Vec::new(),
                        ) {
                            children.push(sym);
                        }
                    }
                }
                (name, tok.text_range(), SymbolKind::ENUM, detail, children)
            }
            Item::Tag(t) => {
                let Some((name, sel)) = first_ident_or_path(t.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::STRUCT,
                    Some("tag".to_owned()),
                    Vec::new(),
                )
            }
            Item::Relation(r) => {
                let Some((name, sel)) = first_ident_or_path(r.syntax()) else {
                    continue;
                };
                let fields: Vec<ast::FieldDecl> = ast::children(r.syntax()).collect();
                let children =
                    collect_field_symbols(source, line_index, &fields, &name, &mut decls);
                (
                    name,
                    sel,
                    SymbolKind::INTERFACE,
                    Some("relation".to_owned()),
                    children,
                )
            }
            Item::Const(c) => {
                let Some((name, sel)) = first_ident_or_path(c.syntax()) else {
                    continue;
                };
                let detail = analyzed
                    .consts
                    .iter()
                    .find(|hc| hc.name == name)
                    .map(|hc| format!("const: {}", format_ty_short(&hc.ty)))
                    .or_else(|| Some("const".to_owned()));
                (name, sel, SymbolKind::CONSTANT, detail, Vec::new())
            }
            Item::Table(t) => {
                let Some((name, sel)) = first_ident_or_path(t.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::CONSTANT,
                    Some("table".to_owned()),
                    Vec::new(),
                )
            }
            Item::Curve(c) => {
                let Some((name, sel)) = first_ident_or_path(c.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::CONSTANT,
                    Some("curve".to_owned()),
                    Vec::new(),
                )
            }
            Item::SpatialGrid(s) => {
                let Some((name, sel)) = first_ident_or_path(s.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::STRUCT,
                    Some("spatial_grid".to_owned()),
                    Vec::new(),
                )
            }
            Item::SpatialHistory(s) => {
                let Some((name, sel)) = first_ident_or_path(s.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::STRUCT,
                    Some("spatial_history".to_owned()),
                    Vec::new(),
                )
            }
            Item::HashIndex(h) => {
                let Some((name, sel)) = first_ident_or_path(h.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::STRUCT,
                    Some("hash_index".to_owned()),
                    Vec::new(),
                )
            }
            Item::Aspect(a) => {
                let Some((name, sel)) = first_ident_or_path(a.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::INTERFACE,
                    Some("aspect".to_owned()),
                    Vec::new(),
                )
            }
            Item::Prefab(p) => {
                let Some((name, sel)) = first_ident_or_path(p.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::OBJECT,
                    Some("prefab".to_owned()),
                    Vec::new(),
                )
            }
            Item::Object(o) => {
                let Some((name, sel)) = first_ident_or_path(o.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::OBJECT,
                    Some("object".to_owned()),
                    Vec::new(),
                )
            }
            Item::Zone(z) => {
                let Some((name, sel)) = first_ident_or_path(z.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::NAMESPACE,
                    Some("zone".to_owned()),
                    Vec::new(),
                )
            }
            Item::Timeline(t) => {
                let Some((name, sel)) = first_ident_or_path(t.syntax()) else {
                    continue;
                };
                let mut children = Vec::new();
                for w in ast::children::<ast::TimelineWindow>(t.syntax()) {
                    if let Some(wtok) = ast::first_ident(w.syntax()) {
                        let wname = wtok.text().to_owned();
                        let w_sel_lsp =
                            line_index.text_range_to_lsp_range(source, wtok.text_range());
                        decls.push(DeclEntry {
                            name: wname.clone(),
                            parent: Some(name.clone()),
                            kind: SymbolKind::EVENT,
                            lsp_range: w_sel_lsp,
                        });
                        if let Some(sym) = make_document_symbol(
                            wname,
                            Some("window".to_owned()),
                            SymbolKind::EVENT,
                            line_index.text_range_to_lsp_range(source, w.text_range()),
                            w_sel_lsp,
                            Vec::new(),
                        ) {
                            children.push(sym);
                        }
                    }
                }
                (
                    name,
                    sel,
                    SymbolKind::CLASS,
                    Some("timeline".to_owned()),
                    children,
                )
            }
            Item::Task(t) => {
                let Some((name, sel)) = first_ident_or_path(t.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::FUNCTION,
                    Some("task".to_owned()),
                    Vec::new(),
                )
            }
            Item::Fsm(f) => {
                let Some((name, sel)) = first_ident_or_path(f.syntax()) else {
                    continue;
                };
                let mut children = Vec::new();
                for st in ast::children::<ast::StateDecl>(f.syntax()) {
                    if let Some(stok) = ast::first_ident(st.syntax()) {
                        let sname = stok.text().to_owned();
                        let st_sel_lsp =
                            line_index.text_range_to_lsp_range(source, stok.text_range());
                        decls.push(DeclEntry {
                            name: sname.clone(),
                            parent: Some(name.clone()),
                            kind: SymbolKind::ENUM_MEMBER,
                            lsp_range: st_sel_lsp,
                        });
                        if let Some(sym) = make_document_symbol(
                            sname,
                            Some("state".to_owned()),
                            SymbolKind::ENUM_MEMBER,
                            line_index.text_range_to_lsp_range(source, st.text_range()),
                            st_sel_lsp,
                            Vec::new(),
                        ) {
                            children.push(sym);
                        }
                    }
                }
                (
                    name,
                    sel,
                    SymbolKind::CLASS,
                    Some("fsm".to_owned()),
                    children,
                )
            }
            Item::Sys(s) => {
                let Some(tok) = s.name() else { continue };
                let name = tok.text().to_owned();
                let detail = analyzed
                    .callables
                    .iter()
                    .find(|c| c.name == name)
                    .map(|c| match c.par_chunk {
                        Some(chunk) if c.par_read_only => {
                            format!("sys @par(read_only, chunk = {chunk})")
                        }
                        Some(chunk) => format!("sys @par(chunk = {chunk})"),
                        None => "sys".to_owned(),
                    })
                    .or_else(|| Some("sys".to_owned()));
                (
                    name,
                    tok.text_range(),
                    SymbolKind::FUNCTION,
                    detail,
                    Vec::new(),
                )
            }
            Item::Obs(o) => {
                let Some(tok) = o.name() else { continue };
                let name = tok.text().to_owned();
                (
                    name,
                    tok.text_range(),
                    SymbolKind::EVENT,
                    Some("obs".to_owned()),
                    Vec::new(),
                )
            }
            Item::Fn(f) => {
                let Some((name, sel)) = first_ident_or_path(f.syntax()) else {
                    continue;
                };
                let detail = analyzed
                    .fns
                    .iter()
                    .find(|hf| hf.name == name)
                    .map(|hf| {
                        let params: Vec<String> = hf
                            .params
                            .iter()
                            .map(|p| format!("{}: {}", p.name, format_ty_short(&p.ty)))
                            .collect();
                        format!(
                            "fn({}) -> {}",
                            params.join(", "),
                            format_ty_short(&hf.ret_ty)
                        )
                    })
                    .or_else(|| Some("fn".to_owned()));
                (name, sel, SymbolKind::FUNCTION, detail, Vec::new())
            }
            Item::Schedule(s) => {
                let Some((name, sel)) = first_ident_or_path(s.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::NAMESPACE,
                    Some("schedule".to_owned()),
                    Vec::new(),
                )
            }
            Item::SimTest(t) => {
                let Some((name, sel)) = node_string_lit(t.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::METHOD,
                    Some("sim_test".to_owned()),
                    Vec::new(),
                )
            }
            Item::NetSimTest(t) => {
                let Some((name, sel)) = node_string_lit(t.syntax()) else {
                    continue;
                };
                (
                    name,
                    sel,
                    SymbolKind::METHOD,
                    Some("net_sim_test".to_owned()),
                    Vec::new(),
                )
            }
            Item::Import(_) | Item::Migrate(_) | Item::AssertLayout(_) | Item::AssertPar(_) => {
                continue;
            }
        };

        let sel_lsp = line_index.text_range_to_lsp_range(source, sel_range);
        decls.push(DeclEntry {
            name: name.clone(),
            parent: None,
            kind,
            lsp_range: sel_lsp,
        });

        if let Some(sym) = make_document_symbol(
            name,
            detail,
            kind,
            line_index.text_range_to_lsp_range(source, item_range),
            sel_lsp,
            children,
        ) {
            symbols.push(sym);
        }
    }

    (symbols, decls)
}

/// Computes hierarchical LSP [`DocumentSymbol`] entries for `source`.
#[must_use]
pub fn compute_document_symbols(source: &str) -> Vec<DocumentSymbol> {
    let analyzed = analyze_source("buffer.strata", source);
    let line_index = LineIndex::new(source);
    let parsed = strata_syntax::parse(source);
    build_symbols_and_decls(source, &line_index, &parsed.syntax(), &analyzed).0
}

/// Pre-builds searchable [`IndexedWorkspaceSymbol`] entries for a single document revision.
#[must_use]
pub(crate) fn build_workspace_symbols_for_doc(
    uri: &Url,
    module_path: &str,
    decls: &[DeclEntry],
) -> Vec<IndexedWorkspaceSymbol> {
    let mut out = Vec::with_capacity(decls.len());
    for d in decls {
        let lower_name = d.name.to_ascii_lowercase();
        let lower_qualified = match &d.parent {
            Some(p) => {
                let mut s = String::with_capacity(p.len() + 2 + d.name.len());
                s.push_str(&p.to_ascii_lowercase());
                s.push_str("::");
                s.push_str(&lower_name);
                s
            }
            None => lower_name.clone(),
        };
        let container = d
            .parent
            .clone()
            .or_else(|| (!module_path.is_empty()).then(|| module_path.to_owned()));
        let location = Location::new(uri.clone(), d.lsp_range);
        if let Some(info) = make_symbol_information(d.name.clone(), d.kind, location, container) {
            out.push(IndexedWorkspaceSymbol {
                lower_name,
                lower_qualified,
                info,
            });
        }
    }
    out
}

/// Filters pre-built workspace symbol indices across open documents matching `query`.
#[must_use]
pub(crate) fn filter_workspace_symbols(
    docs: &[(&str, &[IndexedWorkspaceSymbol])],
    query: &str,
) -> Vec<SymbolInformation> {
    let q = query.trim().to_ascii_lowercase();
    let mut results = Vec::new();
    for &(lower_mod_path, entries) in docs {
        let mod_matches = q.is_empty() || lower_mod_path.contains(&q);
        for entry in entries {
            if mod_matches || entry.lower_name.contains(&q) || entry.lower_qualified.contains(&q) {
                results.push(entry.info.clone());
            }
        }
    }
    results
}

/// Finds a local binding (`let`, `uniform let`, `Param`, `SysParam`, `ForExpr`, `ProjTerm`)
/// inside the enclosing top-level item that declares `ident` before or at `cursor_offset`.
fn find_local_binding(root: &SyntaxNode, cursor_offset: u32, ident: &str) -> Option<TextRange> {
    let enclosing = root.children().find(|child| {
        let r = child.text_range();
        u32::from(r.start()) <= cursor_offset && cursor_offset <= u32::from(r.end())
    })?;

    let mut best: Option<TextRange> = None;
    for node in enclosing.descendants() {
        let start = u32::from(node.text_range().start());
        if start > cursor_offset {
            continue;
        }
        let decl_tok: Option<SyntaxToken> = match node.kind() {
            SyntaxKind::Param
            | SyntaxKind::SysParam
            | SyntaxKind::LetStmt
            | SyntaxKind::UniformLetStmt
            | SyntaxKind::ForExpr
            | SyntaxKind::ProjTerm => ast::first_ident(&node),
            _ => None,
        };
        if let Some(tok) = decl_tok
            && tok.text() == ident
        {
            best = Some(tok.text_range());
        }
    }
    best
}

/// Computes go-to-definition [`Location`] across the active file and other open workspace files
/// using precomputed [`LineIndex`], Salsa-cached CST `active_root`, and cached [`DeclEntry`] slices.
#[must_use]
pub(crate) fn compute_definition_cached(
    active_uri: &Url,
    active_source: &str,
    active_line_index: &LineIndex,
    active_root: &SyntaxNode,
    active_decls: &[DeclEntry],
    other_decls: &[(&Url, &[DeclEntry])],
    pos: Position,
) -> Option<Location> {
    let (ident, _, ident_start, _) =
        active_line_index.word_range_at_position(active_source, pos)?;
    let qualifier = qualifier_before_double_colon(active_source, ident_start);

    // 1. Qualified lookup (`Enum::Variant` or `Component::stratum`) in current document & workspace.
    if let Some(qual) = qualifier {
        if let Some(d) = active_decls
            .iter()
            .find(|d| d.name == ident && d.parent.as_deref() == Some(qual))
        {
            return Some(Location::new(active_uri.clone(), d.lsp_range));
        }
        for &(uri, decls) in other_decls {
            if let Some(d) = decls
                .iter()
                .find(|d| d.name == ident && d.parent.as_deref() == Some(qual))
            {
                return Some(Location::new(uri.clone(), d.lsp_range));
            }
        }
    }

    // 2. Local parameter / `let` / query binding in enclosing item.
    if qualifier.is_none()
        && let Some(local_range) = find_local_binding(active_root, ident_start as u32, ident)
    {
        return Some(Location::new(
            active_uri.clone(),
            active_line_index.text_range_to_lsp_range(active_source, local_range),
        ));
    }

    // 3. Top-level declaration in active document.
    if let Some(d) = active_decls
        .iter()
        .find(|d| d.parent.is_none() && d.name == ident)
    {
        return Some(Location::new(active_uri.clone(), d.lsp_range));
    }

    // 4. Nested member (field / variant / stratum / state) in active document.
    if let Some(d) = active_decls.iter().find(|d| d.name == ident) {
        return Some(Location::new(active_uri.clone(), d.lsp_range));
    }

    // 5. Top-level declaration in any other open workspace document.
    for &(uri, decls) in other_decls {
        if let Some(d) = decls.iter().find(|d| d.parent.is_none() && d.name == ident) {
            return Some(Location::new(uri.clone(), d.lsp_range));
        }
    }

    None
}

/// Computes single-file go-to-definition [`Location`] for `source` at `pos`.
#[must_use]
pub fn compute_definition(source: &str, uri: &Url, pos: Position) -> Option<Location> {
    let analyzed = analyze_source("buffer.strata", source);
    let line_index = LineIndex::new(source);
    let parsed = strata_syntax::parse(source);
    let root = parsed.syntax();
    let (_, decls) = build_symbols_and_decls(source, &line_index, &root, &analyzed);
    compute_definition_cached(uri, source, &line_index, &root, &decls, &[], pos)
}

/// Returns `true` when `tok` is the declared name token of its parent CST node.
fn is_declaration_token(tok: &SyntaxToken) -> bool {
    let Some(parent) = tok.parent() else {
        return false;
    };
    let is_decl_kind = matches!(
        parent.kind(),
        SyntaxKind::ComponentDecl
            | SyntaxKind::StructDecl
            | SyntaxKind::EnumDecl
            | SyntaxKind::VariantDecl
            | SyntaxKind::ResourceDecl
            | SyntaxKind::EventDecl
            | SyntaxKind::StreamDecl
            | SyntaxKind::RpcDecl
            | SyntaxKind::RelationDecl
            | SyntaxKind::TagDecl
            | SyntaxKind::ConstDecl
            | SyntaxKind::TableDecl
            | SyntaxKind::CurveDecl
            | SyntaxKind::SpatialGridDecl
            | SyntaxKind::SpatialHistoryDecl
            | SyntaxKind::HashIndexDecl
            | SyntaxKind::AspectDecl
            | SyntaxKind::PrefabDecl
            | SyntaxKind::ObjectDecl
            | SyntaxKind::ZoneDecl
            | SyntaxKind::TimelineDecl
            | SyntaxKind::TimelineWindow
            | SyntaxKind::TaskDecl
            | SyntaxKind::FsmDecl
            | SyntaxKind::StateDecl
            | SyntaxKind::SysDecl
            | SyntaxKind::ObsDecl
            | SyntaxKind::FnDecl
            | SyntaxKind::FieldDecl
            | SyntaxKind::StratumBlock
            | SyntaxKind::Param
            | SyntaxKind::SysParam
            | SyntaxKind::LetStmt
            | SyntaxKind::UniformLetStmt
            | SyntaxKind::ForExpr
            | SyntaxKind::ProjTerm
    );
    if !is_decl_kind {
        return false;
    }
    ast::first_ident(&parent).is_some_and(|first| first.text_range() == tok.text_range())
}

/// Indexes every CST identifier token in `root` into a map `ident -> Vec<(Range, is_decl)>`
/// in a single pass, skipping comments and string literals.
#[must_use]
pub(crate) fn build_ident_token_index(
    source: &str,
    line_index: &LineIndex,
    root: &SyntaxNode,
) -> HashMap<String, Vec<(Range, bool)>> {
    let mut map: HashMap<String, Vec<(Range, bool)>> = HashMap::new();
    for el in root.descendants_with_tokens() {
        let Some(tok) = el.into_token() else {
            continue;
        };
        if tok.kind() == SyntaxKind::Ident {
            let lsp_range = line_index.text_range_to_lsp_range(source, tok.text_range());
            let is_decl = is_declaration_token(&tok);
            if let Some(list) = map.get_mut(tok.text()) {
                list.push((lsp_range, is_decl));
            } else {
                map.insert(tok.text().to_owned(), vec![(lsp_range, is_decl)]);
            }
        }
    }
    map
}

/// Computes token-accurate LSP [`DocumentHighlight`]s using a precomputed token index.
#[must_use]
pub(crate) fn compute_document_highlights_cached(
    source: &str,
    line_index: &LineIndex,
    ident_tokens: &HashMap<String, Vec<(Range, bool)>>,
    pos: Position,
) -> Vec<DocumentHighlight> {
    let Some(ident) = line_index.word_at_position(source, pos) else {
        return Vec::new();
    };
    let Some(entries) = ident_tokens.get(ident) else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|&(range, is_decl)| DocumentHighlight {
            range,
            kind: Some(if is_decl {
                DocumentHighlightKind::WRITE
            } else {
                DocumentHighlightKind::READ
            }),
        })
        .collect()
}

/// Computes token-accurate LSP [`DocumentHighlight`]s for the identifier at `pos`.
#[must_use]
pub fn compute_document_highlights(source: &str, pos: Position) -> Vec<DocumentHighlight> {
    let line_index = LineIndex::new(source);
    let Some(ident) = line_index.word_at_position(source, pos) else {
        return Vec::new();
    };
    let parsed = strata_syntax::parse(source);
    let root = parsed.syntax();
    let mut out = Vec::new();
    for el in root.descendants_with_tokens() {
        let Some(tok) = el.into_token() else {
            continue;
        };
        if tok.kind() == SyntaxKind::Ident && tok.text() == ident {
            out.push(DocumentHighlight {
                range: line_index.text_range_to_lsp_range(source, tok.text_range()),
                kind: Some(if is_declaration_token(&tok) {
                    DocumentHighlightKind::WRITE
                } else {
                    DocumentHighlightKind::READ
                }),
            });
        }
    }
    out
}

/// Computes workspace-wide LSP [`Location`] references using precomputed token indices.
#[must_use]
pub(crate) fn compute_references_cached(
    active_uri: &Url,
    active_source: &str,
    active_line_index: &LineIndex,
    active_tokens: &HashMap<String, Vec<(Range, bool)>>,
    other_tokens: &[(&Url, &HashMap<String, Vec<(Range, bool)>>)],
    pos: Position,
    include_declaration: bool,
) -> Vec<Location> {
    let Some(ident) = active_line_index.word_at_position(active_source, pos) else {
        return Vec::new();
    };
    let mut locations = Vec::new();
    if let Some(entries) = active_tokens.get(ident) {
        locations.reserve(entries.len());
        for &(range, is_decl) in entries {
            if include_declaration || !is_decl {
                locations.push(Location::new(active_uri.clone(), range));
            }
        }
    }
    for &(uri, tokens) in other_tokens {
        if let Some(entries) = tokens.get(ident) {
            for &(range, is_decl) in entries {
                if include_declaration || !is_decl {
                    locations.push(Location::new(uri.clone(), range));
                }
            }
        }
    }
    locations
}

/// Computes single-file references for `source` at `pos`.
#[must_use]
pub fn compute_references(
    source: &str,
    uri: &Url,
    pos: Position,
    include_declaration: bool,
) -> Vec<Location> {
    let line_index = LineIndex::new(source);
    let Some(ident) = line_index.word_at_position(source, pos) else {
        return Vec::new();
    };
    let parsed = strata_syntax::parse(source);
    let root = parsed.syntax();
    let mut locations = Vec::new();
    for el in root.descendants_with_tokens() {
        let Some(tok) = el.into_token() else {
            continue;
        };
        if tok.kind() == SyntaxKind::Ident && tok.text() == ident {
            let is_decl = is_declaration_token(&tok);
            if include_declaration || !is_decl {
                locations.push(Location::new(
                    uri.clone(),
                    line_index.text_range_to_lsp_range(source, tok.text_range()),
                ));
            }
        }
    }
    locations
}

/// Builds a [`DotCompletionIndex`] in a single pass over a pre-parsed CST `root`.
#[must_use]
pub(crate) fn build_dot_completion_index(root: &SyntaxNode) -> DotCompletionIndex {
    let mut receiver_types = HashMap::new();
    let mut query_aliases = Vec::new();
    for node in root.descendants() {
        let kind = node.kind();
        if !matches!(
            kind,
            SyntaxKind::ProjTerm | SyntaxKind::SysParam | SyntaxKind::Param
        ) {
            continue;
        }
        let Some(name_tok) = ast::first_ident(&node) else {
            continue;
        };
        let name = name_tok.text();
        let ty_name = node
            .descendants_with_tokens()
            .filter_map(|el| el.into_token())
            .find(|tok| {
                tok.kind() == SyntaxKind::Ident
                    && tok.text() != name
                    && tok.text().chars().next().is_some_and(char::is_uppercase)
            })
            .map(|tok| tok.text().to_owned());

        if let Some(ref ty) = ty_name {
            receiver_types
                .entry(name.to_owned())
                .or_insert_with(|| ty.clone());
        }
        if kind == SyntaxKind::ProjTerm {
            query_aliases.push((name.to_owned(), ty_name.unwrap_or_default()));
        }
    }
    DotCompletionIndex {
        receiver_types,
        query_aliases,
    }
}

/// Resolves query alias bindings (`p: &mut Pos2D`) and system/function params so
/// `.` completions after `e.p.` or `clk.` can offer fields of `Pos2D` / `SimClock`.
fn resolve_receiver_type_name(
    receiver: &str,
    analyzed: &AnalyzedModule,
    dot_index: Option<&DotCompletionIndex>,
) -> Option<String> {
    // Direct type / component / resource name (e.g., `Pos2D` or `SimClock`)
    if find_layout(analyzed, receiver).is_some() {
        return Some(receiver.to_owned());
    }
    // Check callable parameters (`clk: &res SimClock`)
    for callable in &analyzed.callables {
        for param in &callable.params {
            if param.name == receiver {
                return Some(format_ty_short(&param.ty));
            }
        }
    }
    for f in &analyzed.fns {
        for param in &f.params {
            if param.name == receiver {
                return Some(format_ty_short(&param.ty));
            }
        }
    }
    // O(1) lookup in pre-indexed CST `ProjTerm` / `SysParam` / `Param` bindings
    dot_index.and_then(|idx| idx.receiver_types.get(receiver).cloned())
}

const STRATA_ATTR_COMPLETIONS: &[(&str, &str, &str)] = &[
    ("soa", "soa", "Split component into hot/cold SoA strata."),
    (
        "par",
        "par(chunk = ${1:256})",
        "Enable Theorem 0.1 chunk-parallel execution.",
    ),
    (
        "summary_tick",
        "summary_tick",
        "Enable Bevy 0.20 summary_tick archetype skipping.",
    ),
    (
        "persist",
        "persist",
        "Mark component/resource/object for persistence.",
    ),
    (
        "rollback",
        "rollback",
        "Include state in rollback snapshots.",
    ),
    (
        "deterministic",
        "deterministic",
        "Enforce deterministic floating-point & schedule ordering.",
    ),
    (
        "authority",
        "authority(${1:server})",
        "Specify network authority (`server`, `client`, `predicted`, `shared`).",
    ),
    (
        "predicted",
        "predicted",
        "Mark component or system as client-predicted.",
    ),
    (
        "net",
        "net(${1:reliable}, rate = ${2:20Hz})",
        "Configure network replication for a component or resource.",
    ),
    (
        "net_rpc",
        "net_rpc(direction = ${1:client_to_server}, ${2:reliable})",
        "Configure RPC wire direction, reliability, and channel.",
    ),
    (
        "quantize",
        "quantize(min = ${1:0.0}, max = ${2:100.0}, bits = ${3:16})",
        "Quantize replicated float/vec field on the wire.",
    ),
    (
        "require",
        "require(${1:Component})",
        "Declare required companion components.",
    ),
    ("sparse", "sparse", "Store component in sparse-set storage."),
    (
        "version",
        "version(${1:1.0.0})",
        "Declare module semantic version.",
    ),
    (
        "node_group",
        "node_group(\"${1:Group}\")",
        "Assign visual graph node group.",
    ),
    (
        "node_pure",
        "node_pure",
        "Mark helper function as pure for visual graph nodes.",
    ),
    ("rate", "rate(${1:60Hz})", "Set fixed tick rate."),
    ("duration", "duration(${1:1.0_s})", "Set timeline duration."),
    ("if_new", "if_new", "Attach component only if absent."),
    (
        "persistent",
        "persistent",
        "Mark entity/zone persistent across transitions.",
    ),
];

const STRATA_BUILTIN_TYPES: &[(&str, &str)] = &[
    ("u8", "Unsigned 8-bit integer"),
    ("u16", "Unsigned 16-bit integer"),
    ("u32", "Unsigned 32-bit integer"),
    ("u64", "Unsigned 64-bit integer"),
    ("i8", "Signed 8-bit integer"),
    ("i16", "Signed 16-bit integer"),
    ("i32", "Signed 32-bit integer"),
    ("i64", "Signed 64-bit integer"),
    ("f32", "32-bit IEEE 754 float"),
    ("f64", "64-bit IEEE 754 float"),
    ("fix32", "32-bit deterministic fixed-point scalar"),
    ("fix64", "64-bit deterministic fixed-point scalar"),
    ("bool", "Boolean scalar"),
    ("sym", "Interned 64-bit symbol identifier"),
    ("vec2", "2D f32 SIMD vector (8 B)"),
    ("vec3", "3D f32 vector (12 B)"),
    ("vec3a", "16-byte aligned 3D f32 SIMD vector (16 B)"),
    ("vec4", "4D f32 SIMD vector (16 B)"),
    ("ivec2", "2D i32 vector (8 B)"),
    ("ivec3", "3D i32 vector (12 B)"),
    ("uvec2", "2D u32 vector (8 B)"),
    ("quat", "Unit quaternion rotation (16 B)"),
    ("mat3", "3x3 f32 matrix"),
    ("mat4", "4x4 f32 matrix"),
    ("rgba8", "Packed 8-bit RGBA color (4 B)"),
    ("rgba", "Linear f32 RGBA color (16 B)"),
    ("Entity", "ECS entity handle"),
    (
        "InlineStr",
        "Fixed-capacity AbiPod inline string `InlineStr<N>`",
    ),
    (
        "SmallVec",
        "Fixed-capacity AbiPod inline vector `SmallVec<T, N>`",
    ),
    ("BitSet", "Fixed-capacity AbiPod bitset `BitSet<N>`"),
    ("InputBuffer", "Fixed-capacity gameplay input ring buffer"),
    ("GraceWindow", "Coyote-time / grace timer window"),
    ("Ref", "Typed entity reference `Ref<T>`"),
    ("Asset", "Typed asset handle `Asset<T>`"),
    ("Trigger", "Observer trigger payload `Trigger<E>`"),
    ("Option", "Optional value `Option<T>`"),
    ("Result", "Fallible result `Result<T, E>`"),
    ("sec", "SI physical time unit (seconds)"),
    ("ms", "SI physical time unit (milliseconds)"),
    ("hz", "SI frequency unit (Hertz)"),
    ("frames", "Discrete simulation frame count"),
    ("rad", "SI angle unit (radians)"),
    ("deg", "Angle unit (degrees)"),
    ("meters", "SI distance unit (meters)"),
    ("mps", "SI velocity unit (meters / second)"),
    ("mps2", "SI acceleration unit (meters / second^2)"),
];

const STRATA_KEYWORDS: &[&str] = &[
    "module",
    "use",
    "pub",
    "component",
    "tag",
    "resource",
    "event",
    "stream",
    "rpc",
    "relation",
    "struct",
    "enum",
    "const",
    "table",
    "curve",
    "spatial_grid",
    "spatial_history",
    "hash_index",
    "aspect",
    "prefab",
    "object",
    "zone",
    "timeline",
    "task",
    "fsm",
    "state",
    "sys",
    "obs",
    "fn",
    "migrate",
    "schedule",
    "sim_test",
    "net_sim_test",
    "assert_layout",
    "assert_par",
    "query",
    "query_one",
    "server_query",
    "client_query",
    "spawn",
    "spawn_batch",
    "despawn",
    "despawn_all",
    "insert",
    "remove",
    "emit",
    "atomic",
    "uniform",
    "let",
    "mut",
    "if",
    "else",
    "match",
    "for",
    "in",
    "while",
    "loop",
    "break",
    "continue",
    "return",
    "true",
    "false",
];

fn extract_prefix_ident(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut start = bytes.len();
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    &s[start..]
}

#[inline]
fn starts_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack.len() >= needle.len()
        && haystack.as_bytes()[..needle.len()].eq_ignore_ascii_case(needle.as_bytes())
}

/// Returns `true` when the cursor at `pos` is positioned for `.` member completion and therefore
/// benefits from a pre-indexed [`DotCompletionIndex`].
#[must_use]
pub(crate) fn needs_dot_completion_index(
    source: &str,
    line_index: &LineIndex,
    pos: Position,
) -> bool {
    let off = line_index
        .position_to_byte_offset(source, pos)
        .min(source.len());
    let before = &source[..off];
    let prefix = extract_prefix_ident(before);
    let before_prefix = &before[..before.len() - prefix.len()];
    before_prefix.ends_with('.')
}

/// Computes context-aware LSP [`CompletionItem`]s from a pre-analyzed module and optional
/// cached [`DotCompletionIndex`].
#[must_use]
pub(crate) fn compute_completions_cached(
    source: &str,
    line_index: &LineIndex,
    pos: Position,
    analyzed: &AnalyzedModule,
    dot_index: Option<&DotCompletionIndex>,
) -> Vec<CompletionItem> {
    let off = line_index
        .position_to_byte_offset(source, pos)
        .min(source.len());
    let before = &source[..off];
    let prefix = extract_prefix_ident(before);
    let before_prefix = &before[..before.len() - prefix.len()];

    // 1. `@` attribute completion
    if before_prefix.ends_with('@') {
        return STRATA_ATTR_COMPLETIONS
            .iter()
            .filter(|(name, _, _)| prefix.is_empty() || name.starts_with(prefix))
            .map(|(name, snippet, doc)| CompletionItem {
                label: (*name).to_owned(),
                kind: Some(CompletionItemKind::PROPERTY),
                detail: Some(format!("@{name}")),
                documentation: Some(Documentation::String((*doc).to_owned())),
                insert_text: Some((*snippet).to_owned()),
                insert_text_format: Some(if snippet.contains("${") {
                    InsertTextFormat::SNIPPET
                } else {
                    InsertTextFormat::PLAIN_TEXT
                }),
                ..CompletionItem::default()
            })
            .collect();
    }

    // 2. `::` scope completion (Enum variants, `@soa` strata, SIMD constants)
    if let Some(before_colons) = before_prefix.strip_suffix("::") {
        let qualifier = extract_prefix_ident(before_colons);
        let mut items = Vec::new();
        if let Some(enum_def) = analyzed.enums.get(qualifier) {
            for (vname, disc) in &enum_def.variants {
                if prefix.is_empty() || vname.starts_with(prefix) {
                    items.push(CompletionItem {
                        label: vname.clone(),
                        kind: Some(CompletionItemKind::ENUM_MEMBER),
                        detail: Some(format!("{qualifier}::{vname} = {disc}")),
                        ..CompletionItem::default()
                    });
                }
            }
        }
        if let Some(strata) = analyzed.soa_strata.get(qualifier) {
            for s in strata {
                let short = s.rsplit("::").next().unwrap_or(s);
                let suffix = short
                    .strip_prefix(qualifier)
                    .and_then(|rest| rest.strip_prefix("__"))
                    .unwrap_or("hot");
                if prefix.is_empty() || suffix.starts_with(prefix) {
                    items.push(CompletionItem {
                        label: suffix.to_owned(),
                        kind: Some(CompletionItemKind::MODULE),
                        detail: Some(format!("@soa stratum of {qualifier}")),
                        ..CompletionItem::default()
                    });
                }
            }
        }
        if matches!(
            qualifier,
            "vec2" | "vec3" | "vec3a" | "vec4" | "ivec2" | "ivec3" | "uvec2"
        ) {
            for (c, d) in [
                ("ZERO", "Zero vector"),
                ("ONE", "Unit vector"),
                ("X", "X axis"),
                ("Y", "Y axis"),
            ] {
                if prefix.is_empty() || c.starts_with(prefix) {
                    items.push(CompletionItem {
                        label: c.to_owned(),
                        kind: Some(CompletionItemKind::CONSTANT),
                        detail: Some(format!("{qualifier}::{c} — {d}")),
                        ..CompletionItem::default()
                    });
                }
            }
        } else if matches!(qualifier, "quat" | "mat3" | "mat4")
            && (prefix.is_empty() || "IDENTITY".starts_with(prefix))
        {
            items.push(CompletionItem {
                label: "IDENTITY".to_owned(),
                kind: Some(CompletionItemKind::CONSTANT),
                detail: Some(format!("{qualifier}::IDENTITY")),
                ..CompletionItem::default()
            });
        }
        return items;
    }

    // 3. `.` member / field completion
    if let Some(before_dot) = before_prefix.strip_suffix('.') {
        let receiver = extract_prefix_ident(before_dot);
        let mut items = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();

        if let Some(type_name) = resolve_receiver_type_name(receiver, analyzed, dot_index)
            && let Some(layout) = find_layout(analyzed, &type_name)
        {
            for field in &layout.fields {
                if field.is_padding {
                    continue;
                }
                if (prefix.is_empty() || field.name.starts_with(prefix))
                    && seen.insert(field.name.as_str())
                {
                    items.push(CompletionItem {
                        label: field.name.clone(),
                        kind: Some(CompletionItemKind::FIELD),
                        detail: Some(format!(
                            "{} (offset {} B, {} B)",
                            format_ty_short(&field.ty),
                            field.offset,
                            field.size
                        )),
                        ..CompletionItem::default()
                    });
                }
            }
        }

        // If cursor is on query row alias `e.`, offer query binding aliases (`p`, `v`, ...)
        if items.is_empty()
            && let Some(idx) = dot_index
        {
            for (alias, comp) in &idx.query_aliases {
                if (prefix.is_empty() || alias.starts_with(prefix)) && seen.insert(alias.as_str()) {
                    let detail = if comp.is_empty() {
                        "query term".to_owned()
                    } else {
                        format!("query term `{comp}`")
                    };
                    items.push(CompletionItem {
                        label: alias.clone(),
                        kind: Some(CompletionItemKind::FIELD),
                        detail: Some(detail),
                        ..CompletionItem::default()
                    });
                }
            }
        }

        // Vector swizzles / common field helpers
        if items.is_empty() {
            for (name, detail) in [
                ("x", "f32 component"),
                ("y", "f32 component"),
                ("z", "f32 component"),
                ("w", "f32 component"),
                ("len", "fn() -> u32"),
                ("is_empty", "fn() -> bool"),
                ("push", "fn(value)"),
                ("clear", "fn()"),
            ] {
                if prefix.is_empty() || name.starts_with(prefix) {
                    items.push(CompletionItem {
                        label: name.to_owned(),
                        kind: Some(CompletionItemKind::FIELD),
                        detail: Some(detail.to_owned()),
                        ..CompletionItem::default()
                    });
                }
            }
        }

        return items;
    }

    // 4. General identifier completion: declared symbols, built-in types, keywords
    let cap = if prefix.is_empty() { 32 } else { 0 };
    let mut items = Vec::with_capacity(cap);
    let mut seen: HashSet<&str> = HashSet::with_capacity(cap);
    let matches_prefix =
        |name: &str| prefix.is_empty() || starts_with_ignore_ascii_case(name, prefix);

    for layout in analyzed.layouts.values() {
        let short = layout
            .canonical_name
            .rsplit("::")
            .next()
            .unwrap_or(&layout.canonical_name);
        if short.contains("__") {
            continue;
        }
        if matches_prefix(short) && seen.insert(short) {
            items.push(CompletionItem {
                label: short.to_owned(),
                kind: Some(CompletionItemKind::STRUCT),
                detail: Some(format!(
                    "{:?} ({})",
                    layout.item_kind,
                    format_layout_summary(layout)
                )),
                ..CompletionItem::default()
            });
        }
    }

    for (ename, edef) in &analyzed.enums {
        if matches_prefix(ename) && seen.insert(ename.as_str()) {
            items.push(CompletionItem {
                label: ename.clone(),
                kind: Some(CompletionItemKind::ENUM),
                detail: Some(format!(
                    "enum ({} variants, repr {})",
                    edef.variants.len(),
                    edef.rust_repr()
                )),
                ..CompletionItem::default()
            });
        }
    }

    for rpc in &analyzed.rpcs {
        if matches_prefix(&rpc.name) && seen.insert(rpc.name.as_str()) {
            items.push(CompletionItem {
                label: rpc.name.clone(),
                kind: Some(CompletionItemKind::INTERFACE),
                detail: Some(format!(
                    "rpc ({:?}, {})",
                    rpc.direction,
                    format_layout_summary(&rpc.payload_layout)
                )),
                ..CompletionItem::default()
            });
        }
    }

    for f in &analyzed.fns {
        if matches_prefix(&f.name) && seen.insert(f.name.as_str()) {
            let mut detail = String::with_capacity(32);
            detail.push_str("fn(");
            for (i, p) in f.params.iter().enumerate() {
                if i > 0 {
                    detail.push_str(", ");
                }
                let _ = write!(detail, "{}: {}", p.name, format_ty_short(&p.ty));
            }
            let _ = write!(detail, ") -> {}", format_ty_short(&f.ret_ty));
            items.push(CompletionItem {
                label: f.name.clone(),
                kind: Some(CompletionItemKind::FUNCTION),
                detail: Some(detail),
                ..CompletionItem::default()
            });
        }
    }

    for c in &analyzed.callables {
        if matches_prefix(&c.name) && seen.insert(c.name.as_str()) {
            let kw = if c.is_observer { "obs" } else { "sys" };
            let detail = c
                .par_chunk
                .map_or_else(|| kw.to_owned(), |ch| format!("{kw} @par(chunk = {ch})"));
            items.push(CompletionItem {
                label: c.name.clone(),
                kind: Some(CompletionItemKind::FUNCTION),
                detail: Some(detail),
                ..CompletionItem::default()
            });
        }
    }

    for c in &analyzed.consts {
        if matches_prefix(&c.name) && seen.insert(c.name.as_str()) {
            items.push(CompletionItem {
                label: c.name.clone(),
                kind: Some(CompletionItemKind::CONSTANT),
                detail: Some(format!("const: {}", format_ty_short(&c.ty))),
                ..CompletionItem::default()
            });
        }
    }

    for fsm in &analyzed.fsms {
        if matches_prefix(&fsm.name) && seen.insert(fsm.name.as_str()) {
            items.push(CompletionItem {
                label: fsm.name.clone(),
                kind: Some(CompletionItemKind::CLASS),
                detail: Some(format!("fsm ({} states)", fsm.states.len())),
                ..CompletionItem::default()
            });
        }
    }

    for tl in &analyzed.timelines {
        if matches_prefix(&tl.name) && seen.insert(tl.name.as_str()) {
            items.push(CompletionItem {
                label: tl.name.clone(),
                kind: Some(CompletionItemKind::CLASS),
                detail: Some(format!("timeline ({} windows)", tl.windows.len())),
                ..CompletionItem::default()
            });
        }
    }

    for task in &analyzed.tasks {
        if matches_prefix(&task.name) && seen.insert(task.name.as_str()) {
            items.push(CompletionItem {
                label: task.name.clone(),
                kind: Some(CompletionItemKind::FUNCTION),
                detail: Some("task".to_owned()),
                ..CompletionItem::default()
            });
        }
    }

    for &(ty_name, doc) in STRATA_BUILTIN_TYPES {
        if matches_prefix(ty_name) && seen.insert(ty_name) {
            items.push(CompletionItem {
                label: ty_name.to_owned(),
                kind: Some(CompletionItemKind::TYPE_PARAMETER),
                detail: Some(doc.to_owned()),
                ..CompletionItem::default()
            });
        }
    }

    for &kw in STRATA_KEYWORDS {
        if matches_prefix(kw) && seen.insert(kw) {
            items.push(CompletionItem {
                label: kw.to_owned(),
                kind: Some(CompletionItemKind::KEYWORD),
                detail: Some("keyword".to_owned()),
                ..CompletionItem::default()
            });
        }
    }

    items
}

/// Computes LSP [`CompletionItem`]s for `source` at `pos`.
#[must_use]
pub fn compute_completions(source: &str, pos: Position) -> Vec<CompletionItem> {
    let analyzed = analyze_source("buffer.strata", source);
    let line_index = LineIndex::new(source);
    let dot_index = if needs_dot_completion_index(source, &line_index, pos) {
        let parsed = strata_syntax::parse(source);
        Some(build_dot_completion_index(&parsed.syntax()))
    } else {
        None
    };
    compute_completions_cached(source, &line_index, pos, &analyzed, dot_index.as_ref())
}

fn pos_in_range(pos: Position, range: Range) -> bool {
    let after_start = pos.line > range.start.line
        || (pos.line == range.start.line && pos.character >= range.start.character);
    let before_end = pos.line < range.end.line
        || (pos.line == range.end.line && pos.character <= range.end.character);
    after_start && before_end
}

/// Precomputes all LSP [`InlayHint`]s for a document revision using a pre-parsed CST `root`
/// and [`LineIndex`].
#[must_use]
pub(crate) fn build_all_inlay_hints(
    source: &str,
    line_index: &LineIndex,
    root: &SyntaxNode,
    analyzed: &AnalyzedModule,
) -> Vec<InlayHint> {
    let Some(sf) = ast::SourceFile::cast(root.clone()) else {
        return Vec::new();
    };

    let mut hints = Vec::new();
    for item in sf.items() {
        match item {
            Item::Component(c) => {
                if let Some(tok) = c.name()
                    && let Some(layout) = find_layout(analyzed, tok.text())
                {
                    let pos = line_index
                        .byte_offset_to_position(source, u32::from(tok.text_range().end()));
                    hints.push(InlayHint {
                        position: pos,
                        label: InlayHintLabel::String(format!(
                            " /* {} */",
                            format_layout_summary(layout)
                        )),
                        kind: Some(InlayHintKind::TYPE),
                        text_edits: None,
                        tooltip: Some(InlayHintTooltip::String(format!(
                            "ComponentUuid: {} | Fingerprint: 0x{:016X}",
                            layout.uuid_hex, layout.schema_fingerprint
                        ))),
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
            Item::Struct(s) => {
                if let Some(tok) = s.name()
                    && let Some(layout) = find_layout(analyzed, tok.text())
                {
                    let pos = line_index
                        .byte_offset_to_position(source, u32::from(tok.text_range().end()));
                    hints.push(InlayHint {
                        position: pos,
                        label: InlayHintLabel::String(format!(
                            " /* {} */",
                            format_layout_summary(layout)
                        )),
                        kind: Some(InlayHintKind::TYPE),
                        text_edits: None,
                        tooltip: Some(InlayHintTooltip::String(format!(
                            "Fingerprint: 0x{:016X}",
                            layout.schema_fingerprint
                        ))),
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
            Item::Resource(r) => {
                if let Some(tok) = r.name()
                    && let Some(layout) = find_layout(analyzed, tok.text())
                {
                    let pos = line_index
                        .byte_offset_to_position(source, u32::from(tok.text_range().end()));
                    hints.push(InlayHint {
                        position: pos,
                        label: InlayHintLabel::String(format!(
                            " /* {} */",
                            format_layout_summary(layout)
                        )),
                        kind: Some(InlayHintKind::TYPE),
                        text_edits: None,
                        tooltip: Some(InlayHintTooltip::String(format!(
                            "ComponentUuid: {} | Fingerprint: 0x{:016X}",
                            layout.uuid_hex, layout.schema_fingerprint
                        ))),
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
            Item::Event(e) => {
                if let Some((name, sel)) = first_ident_or_path(e.syntax())
                    && let Some(layout) = find_layout(analyzed, &name)
                {
                    let pos = line_index.byte_offset_to_position(source, u32::from(sel.end()));
                    hints.push(InlayHint {
                        position: pos,
                        label: InlayHintLabel::String(format!(
                            " /* {} */",
                            format_layout_summary(layout)
                        )),
                        kind: Some(InlayHintKind::TYPE),
                        text_edits: None,
                        tooltip: None,
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
            Item::Sys(s) => {
                if let Some(tok) = s.name()
                    && let Some(callable) = analyzed.callables.iter().find(|c| c.name == tok.text())
                {
                    let pos = line_index
                        .byte_offset_to_position(source, u32::from(tok.text_range().end()));
                    let label = match callable.par_chunk {
                        Some(ch) if callable.par_read_only => {
                            format!(" /* @par(ro, chunk={ch}) */")
                        }
                        Some(ch) => format!(" /* @par(chunk={ch}) */"),
                        None => {
                            let conflicts = analyzed
                                .concurrency_graph
                                .conflicts
                                .iter()
                                .filter(|e| {
                                    e.system_a == callable.name || e.system_b == callable.name
                                })
                                .count();
                            format!(" /* seq, {conflicts} conflicts */")
                        }
                    };
                    hints.push(InlayHint {
                        position: pos,
                        label: InlayHintLabel::String(label),
                        kind: Some(InlayHintKind::PARAMETER),
                        text_edits: None,
                        tooltip: None,
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
            _ => {}
        }
    }
    hints
}

/// Filters precomputed [`InlayHint`]s to those falling inside `range`.
#[must_use]
pub(crate) fn filter_inlay_hints(hints: &[InlayHint], range: Range) -> Vec<InlayHint> {
    hints
        .iter()
        .filter(|h| pos_in_range(h.position, range))
        .cloned()
        .collect()
}

/// Computes LSP [`InlayHint`]s for `source` within `range`.
#[must_use]
pub fn compute_inlay_hints(source: &str, range: Range) -> Vec<InlayHint> {
    let analyzed = analyze_source("buffer.strata", source);
    let line_index = LineIndex::new(source);
    let parsed = strata_syntax::parse(source);
    let all = build_all_inlay_hints(source, &line_index, &parsed.syntax(), &analyzed);
    filter_inlay_hints(&all, range)
}

/// Appends a formatted doc comment block right below the hover header, optionally followed by
/// a horizontal rule when metadata lines follow.
fn append_doc(md: &mut String, doc: Option<&str>, has_trailing_meta: bool) {
    let Some(doc) = doc.map(str::trim).filter(|d| !d.is_empty()) else {
        return;
    };
    md.push_str("\n\n");
    md.push_str(doc);
    if has_trailing_meta {
        md.push_str("\n\n---");
    }
}

/// Returns `(category, markdown_doc)` for every Strata keyword and built-in ECS intrinsic.
#[must_use]
fn keyword_hover_doc(word: &str) -> Option<(&'static str, &'static str)> {
    let entry = match word {
        // --- Module & Visibility ---
        "module" => (
            "keyword",
            "Declares the canonical module namespace (`module ns::name @version(1.0.0);`).",
        ),
        "use" => (
            "keyword",
            "Imports symbols or items from another module namespace.",
        ),
        "as" => (
            "keyword",
            "Performs an explicit scalar/numeric cast or import alias (`x as f32`).",
        ),
        "pub" => (
            "keyword",
            "Exports an item or field outside the current module.",
        ),

        // --- Data & ECS Schema Declarations ---
        "const" => (
            "keyword",
            "Declares a compile-time constant expression (`const MAX_HP: f32 = 100.0;`).",
        ),
        "struct" => (
            "keyword",
            "Declares a `#[repr(C)]` `AbiPod` value struct shared across components, events, and functions.",
        ),
        "enum" => (
            "keyword",
            "Declares a `#[repr(u8|u16|u32|i32)]` `AbiPod` enumeration with explicit or sequential discriminants.",
        ),
        "component" => (
            "keyword",
            "Declares an ECS component (`AbiPod`, `#[repr(C)]`), supporting `@soa` hot/cold strata, `@sparse`, `@persist`, `@rollback`, and `@require(...)`.",
        ),
        "tag" => (
            "keyword",
            "Declares one or more zero-sized ECS marker components (`tag BossEntity, Active;`).",
        ),
        "resource" => (
            "keyword",
            "Declares a global singleton ECS resource borrowed via `&res T` or `&mut res T` in systems.",
        ),
        "event" => (
            "keyword",
            "Declares a typed ECS event or observer trigger payload (`obs on_hit(trg: &Trigger<E>)`).",
        ),
        "stream" => (
            "keyword",
            "Declares a buffered inter-system stream consumed via `&stream_in T`.",
        ),
        "rpc" => (
            "keyword",
            "Declares a typed network RPC message configured with `@net_rpc(direction = ..., reliable|unreliable)`.",
        ),
        "relation" => (
            "keyword",
            "Declares an entity-to-entity ECS relationship with optional flags (`[exclusive, symmetric, acyclic, cascade_despawn, cleanup_remove, self_ok]`) and payload.",
        ),
        "table" => (
            "keyword",
            "Declares a compile-time lookup table keyed by an `enum` (`table Stats by UnitKind { ... } = { ... };`).",
        ),
        "curve" => (
            "keyword",
            "Declares a piecewise-linear response curve sampled deterministically at runtime.",
        ),
        "spatial_grid" => (
            "keyword",
            "Declares a 2-pass CSR spatial hash grid index over a component position field.",
        ),
        "spatial_history" => (
            "keyword",
            "Declares a multi-frame spatial ring-buffer index for rollback / lag-compensated queries.",
        ),
        "hash_index" => (
            "keyword",
            "Declares an O(1) hash lookup index mapping a component field key to matching entities.",
        ),
        "aspect" => (
            "keyword",
            "Declares a reusable query projection / filter aspect over components.",
        ),
        "prefab" => (
            "keyword",
            "Declares a reusable entity archetype template for `spawn` / `spawn_batch`.",
        ),
        "object" => (
            "keyword",
            "Declares a named singleton entity initialized at startup (`@persist object Name { ... }`).",
        ),
        "zone" => (
            "keyword",
            "Declares a spatial/scene zone grouping entities, resources, and lifecycle state.",
        ),
        "timeline" => (
            "keyword",
            "Declares a deterministic fixed-rate timeline with named frame `window` intervals and `at` edge triggers.",
        ),
        "window" => (
            "keyword",
            "Defines a named inclusive/half-open frame interval inside a `timeline` (checked via `.in(name)`).",
        ),
        "task" => (
            "keyword",
            "Declares a stackless ECS coroutine lowered into a `@sparse` state machine supporting `wait`, `wait_until`, `yield_tick`, and `race`.",
        ),
        "fsm" => (
            "keyword",
            "Declares a declarative finite state machine with typed `state` blocks, lifecycle hooks (`on_enter`/`on_tick`/`on_exit`), and `to ... when ...` transitions.",
        ),
        "state" => (
            "keyword",
            "Defines a state inside an `fsm` declaration with optional state-local fields, hooks, and guarded transitions.",
        ),
        "initial" => (
            "keyword",
            "Specifies the entry state of an `fsm` (`initial Patrol;`).",
        ),
        "on_enter" => (
            "keyword",
            "Lifecycle hook executed once when an `fsm` transitions into a `state`.",
        ),
        "on_tick" => (
            "keyword",
            "Lifecycle hook executed each fixed tick while an `fsm` remains in a `state`.",
        ),
        "on_exit" => (
            "keyword",
            "Lifecycle hook executed once when an `fsm` leaves a `state`.",
        ),
        "to" => (
            "keyword",
            "Introduces an `fsm` transition target (`to Attack when in_range;`).",
        ),
        "when" => (
            "keyword",
            "Specifies the boolean guard predicate on an `fsm` `to` transition.",
        ),

        // --- Systems, Functions, Scheduling & Verification ---
        "sys" => (
            "keyword",
            "Declares an ECS system scheduled in `Startup`, `FixedUpdate`, or `Update`; checked by Theorem 0.1 for `@par` chunk parallelism.",
        ),
        "obs" => (
            "keyword",
            "Declares a reactive ECS observer triggered by `trigger(...)` or lifecycle events (`Trigger<Event, Comp>`).",
        ),
        "fn" => (
            "keyword",
            "Declares a helper function (`@node_pure` marks side-effect-free helpers).",
        ),
        "migrate" => (
            "keyword",
            "Declares a schema migration function transforming a persisted component from an older `@version` to the current layout.",
        ),
        "schedule" => (
            "keyword",
            "Defines an execution schedule (`Startup`, `FixedUpdate`, `Update`) with `seq`, `seq_weak`, `par`, `before`, `after`, and `run_if` ordering.",
        ),
        "sim_test" => (
            "keyword",
            "Declares an embedded headless deterministic simulation test (`stratac test`).",
        ),
        "net_sim_test" => (
            "keyword",
            "Declares a virtual multi-world network simulation test with configurable latency, jitter, packet loss, seed, and client count.",
        ),
        "assert_layout" => (
            "keyword",
            "Compile-time assertion verifying a component or stratum's solved `size`, `align`, and `AbiPod` layout.",
        ),
        "assert_par" => (
            "keyword",
            "Compile-time assertion verifying Theorem 0.1 archetype/field disjointness between systems.",
        ),

        // --- SoA, Borrow & Schedule Modifiers ---
        "hot" => (
            "keyword",
            "Declares the hot cache-dense stratum inside an `@soa` component.",
        ),
        "cold" => (
            "keyword",
            "Declares a named cold stratum (`cold caps { ... }`) split out of an `@soa` component.",
        ),
        "res" => (
            "keyword",
            "Resource borrow modifier (`&res T` immutable, `&mut res T` exclusive mutable).",
        ),
        "stream_in" => (
            "keyword",
            "Stream reader parameter modifier (`&stream_in EventStream`).",
        ),
        "effects" => (
            "keyword",
            "Declares explicit command/resource side effects permitted on a system or observer.",
        ),
        "reduce" => (
            "keyword",
            "Declares deterministic parallel loop reductions (`sum`, `min`, `max`) across `@par` chunks.",
        ),
        "run_if" => (
            "keyword",
            "Attaches a boolean run condition to a `schedule` or schedule node.",
        ),
        "before" => (
            "keyword",
            "Constrains a schedule node or system to execute strictly before target system(s).",
        ),
        "after" => (
            "keyword",
            "Constrains a schedule node or system to execute strictly after target system(s).",
        ),
        "seq" => (
            "keyword",
            "Groups schedule items to execute sequentially in strict declaration order.",
        ),
        "seq_weak" => (
            "keyword",
            "Groups schedule items with weak sequential ordering allowing non-conflicting overlap.",
        ),
        "par" => (
            "keyword",
            "Groups non-conflicting schedule items for parallel execution.",
        ),
        "set" => (
            "keyword",
            "Defines a named system set inside a `schedule` block.",
        ),

        // --- Control Flow, Concurrency & Coroutines ---
        "uniform" => (
            "keyword",
            "Marks a loop-invariant `uniform let` binding hoisted outside per-entity chunk iteration.",
        ),
        "let" => (
            "keyword",
            "Introduces a local variable binding (`let x = ...;` or `let mut x = ...;`).",
        ),
        "mut" => (
            "keyword",
            "Mutable binding or borrow modifier (`let mut`, `&mut T`, or `&mut? T` selective tick-coalesced write).",
        ),
        "if" => (
            "keyword",
            "Conditional branch (`if cond { ... } else { ... }`).",
        ),
        "else" => (
            "keyword",
            "Fallback branch for an `if` or `if let` expression.",
        ),
        "match" => (
            "keyword",
            "Exhaustive pattern matching expression over enums, tuples, or literals.",
        ),
        "for" => (
            "keyword",
            "Iterates over an ECS `query(...)`, spatial query, or integer range (`for e in query(...) { ... }`).",
        ),
        "in" => (
            "keyword",
            "Separates the loop binding from the iterator in a `for` loop.",
        ),
        "while" => (
            "keyword",
            "Condition-controlled loop (`while cond { ... }`).",
        ),
        "loop" => (
            "keyword",
            "Unconditional loop exited via `break` or `return`.",
        ),
        "break" => ("keyword", "Exits the innermost loop."),
        "continue" => (
            "keyword",
            "Advances immediately to the next iteration of the innermost loop.",
        ),
        "return" => (
            "keyword",
            "Returns early from the current function, system, or observer.",
        ),
        "atomic" => (
            "keyword",
            "Executes a transaction block with automatic pre-image state rollback if `abort_if` triggers.",
        ),
        "on_rollback" => (
            "keyword",
            "Handler block executed when an `atomic` transaction rolls back.",
        ),
        "race" => (
            "keyword",
            "Runs competing `task` branches concurrently until the first branch completes.",
        ),
        "branch" => (
            "keyword",
            "Defines one concurrent arm inside a `race { ... }` block.",
        ),
        "wait" => (
            "keyword",
            "Suspends a `task` coroutine for a fixed duration or frame count (`wait(0.5_s);`).",
        ),
        "wait_until" => (
            "keyword",
            "Suspends a `task` coroutine until a predicate becomes `true`.",
        ),
        "yield_tick" => (
            "keyword",
            "Suspends a `task` coroutine until the next fixed simulation tick.",
        ),
        "abort_if" => (
            "keyword",
            "Rolls back the enclosing `atomic` transaction (or cancels a `task`) when the condition is `true`.",
        ),

        // --- Built-in ECS Query & Command Intrinsics ---
        "query" => (
            "intrinsic",
            "Iterates matching ECS entities across chunk slices (`query(p: &mut Pos, v: &Vel, With<Tag>, Without<Tag>, Changed<Comp>)`).",
        ),
        "query_one" => (
            "intrinsic",
            "Random-access lookup of components on a specific `Entity` or `Ref<T>` (`query_one(p: &Pos).on(entity)`).",
        ),
        "server_query" => (
            "intrinsic",
            "Runs a server-authority ECS query validated against `@authority(server)` rules.",
        ),
        "client_query" => (
            "intrinsic",
            "Runs a client-authority / predicted ECS query validated against `@authority(client|predicted)` rules.",
        ),
        "spawn" => (
            "intrinsic",
            "Queues creation of a new entity with component initializers (`spawn { Pos3D {}, ... }`).",
        ),
        "spawn_batch" => (
            "intrinsic",
            "Spawns N homogeneous entities in a tight archetype-batched loop (`spawn_batch(count) |i| { ... }`).",
        ),
        "despawn" => (
            "intrinsic",
            "Queues removal of an entity and all of its components from the world.",
        ),
        "despawn_all" => (
            "intrinsic",
            "Queues bulk removal of all entities matching a component or tag (`despawn_all<Component>();`).",
        ),
        "insert" => (
            "intrinsic",
            "Attaches components onto an existing entity (`insert(entity, { Comp { ... } })`).",
        ),
        "remove" => (
            "intrinsic",
            "Removes a component from an entity (`remove<Component>(entity);`).",
        ),
        "emit" => (
            "intrinsic",
            "Emits a buffered ECS `event` or `stream` item.",
        ),
        "trigger" => (
            "intrinsic",
            "Dispatches an immediate targeted observer `event` (`trigger(target_entity, Event { ... });`).",
        ),

        // --- Literals & Self ---
        "true" | "false" => ("literal", "Boolean literal value (`bool`)."),
        "self" => (
            "keyword",
            "Refers to the receiver entity or value in the current scope.",
        ),
        "Self" => (
            "keyword",
            "Refers to the enclosing type in the current scope.",
        ),

        _ => return None,
    };
    Some(entry)
}

/// Renders rich Markdown hover cards for layouts (with field tables), callables (with conflicts
/// & live `"BAMT"` telemetry), functions, enums, RPCs, FSMs, timelines, tasks, tables, curves,
/// schedules, constants, doc comments, `@attributes`, built-in types, and keywords using a
/// precomputed [`LineIndex`].
#[must_use]
pub(crate) fn compute_rich_hover_with_index(
    source: &str,
    line_index: &LineIndex,
    pos: Position,
    analyzed: &AnalyzedModule,
    telemetry: &TelemetryStore,
    doc_comments: Option<&DocCommentIndex>,
    root: Option<&SyntaxNode>,
) -> Option<Hover> {
    let (ident, range, ident_start, _) = line_index.word_range_at_position(source, pos)?;

    if let Some(r) = root {
        let tok_kind = strata_syntax::TextSize::try_from(ident_start)
            .ok()
            .and_then(|off| r.token_at_offset(off).right_biased())
            .map(|t| t.kind());
        if matches!(
            tok_kind,
            Some(
                SyntaxKind::LineComment
                    | SyntaxKind::BlockComment
                    | SyntaxKind::StringLit
                    | SyntaxKind::CharLit
            )
        ) {
            return None;
        }
    }

    let lookup_item_doc = |name: &str| -> Option<&str> {
        doc_comments.and_then(|dc| dc.items.get(name).map(String::as_str))
    };

    // 1. `@attribute` hover
    if ident_start > 0
        && source.as_bytes().get(ident_start - 1) == Some(&b'@')
        && let Some((name, _, doc)) = STRATA_ATTR_COMPLETIONS
            .iter()
            .find(|(name, _, _)| *name == ident)
    {
        let attr_range = Range::new(
            line_index.byte_offset_to_position(source, (ident_start - 1) as u32),
            range.end,
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!("### `@{name}`\n\n{doc}"),
            }),
            range: Some(attr_range),
        });
    }

    // 2. Qualified `Enum::Variant` / `Comp::stratum` / `Timeline::window` doc or info
    if let Some(qual) = qualifier_before_double_colon(source, ident_start) {
        if let Some(edef) = analyzed.enums.get(qual)
            && let Some((vname, disc)) = edef.variants.iter().find(|(v, _)| v == ident)
        {
            let mut md = format!("### `{}::{vname} = {disc}`", edef.canonical_name);
            let member_doc = doc_comments
                .and_then(|dc| dc.members.get(&(qual.to_owned(), ident.to_owned())))
                .map(String::as_str);
            append_doc(&mut md, member_doc, false);
            return Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range: Some(range),
            });
        }
        if let Some(member_doc) = doc_comments
            .and_then(|dc| dc.members.get(&(qual.to_owned(), ident.to_owned())))
            .map(String::as_str)
        {
            let md = format!("### `{qual}::{ident}`\n\n{member_doc}");
            return Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range: Some(range),
            });
        }
    }

    // 3. User-defined constructs (with doc comments)
    if let Some(layout) = find_layout(analyzed, ident) {
        let short_name = layout
            .canonical_name
            .rsplit("::")
            .next()
            .unwrap_or(&layout.canonical_name);
        let doc = lookup_item_doc(ident).or_else(|| lookup_item_doc(short_name));
        let mut md = String::with_capacity(256 + layout.fields.len() * 48);
        let _ = write!(
            md,
            "### `{}` (`{:?}`)",
            layout.canonical_name, layout.item_kind
        );
        append_doc(&mut md, doc, true);
        let _ = write!(
            md,
            "\n\n\
             - **Size:** `{} B` (`align {} B`)\n\
             - **AbiPod:** `{}` (explicit padding: `{} B`)\n\
             - **ComponentUuid:** `{}`\n\
             - **Schema Fingerprint:** `0x{:016X}`",
            layout.size,
            layout.align,
            layout.is_abi_pod,
            layout.explicit_pad_bytes,
            layout.uuid_hex,
            layout.schema_fingerprint
        );
        if !layout.fields.is_empty() {
            md.push_str("\n\n| Offset | Field | Type | Size |\n| ---: | :--- | :--- | ---: |");
            for f in &layout.fields {
                if f.is_padding {
                    let _ = write!(
                        md,
                        "\n| `+{} B` | `{}` | `[u8; {}] (pad)` | `{} B` |",
                        f.offset, f.name, f.size, f.size
                    );
                } else {
                    let _ = write!(
                        md,
                        "\n| `+{} B` | `{}` | `{}` | `{} B` |",
                        f.offset,
                        f.name,
                        format_ty_short(&f.ty),
                        f.size
                    );
                }
            }
        }
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(callable) = analyzed.callables.iter().find(|c| c.name == ident) {
        let mut md = String::with_capacity(256);
        let _ = write!(
            md,
            "### `{} {}`",
            if callable.is_observer { "obs" } else { "sys" },
            callable.name,
        );
        append_doc(&mut md, lookup_item_doc(&callable.name), true);
        md.push_str("\n\n- **Scheduling:** ");
        match callable.par_chunk {
            Some(c) if callable.par_read_only => {
                let _ = write!(md, "`@par(read_only, chunk = {c})`");
            }
            Some(c) => {
                let _ = write!(md, "`@par(chunk = {c})`");
            }
            None => md.push_str("sequential"),
        }
        let _ = write!(
            md,
            "\n- **Authority:** `{:?}`\n\
             - **Queries:** `{}` | **Resources:** `{}` reads / `{}` writes",
            callable.authority,
            callable.access.queries.len(),
            callable.access.res_reads.len(),
            callable.access.res_writes.len(),
        );
        let mut wrote_conflict = false;
        for e in &analyzed.concurrency_graph.conflicts {
            let peer = if e.system_a == callable.name {
                Some(e.system_b.as_str())
            } else if e.system_b == callable.name {
                Some(e.system_a.as_str())
            } else {
                None
            };
            if let Some(peer_name) = peer {
                if !wrote_conflict {
                    md.push_str("\n- **Theorem 0.1 Conflicts:** `");
                    wrote_conflict = true;
                } else {
                    md.push_str("`, `");
                }
                md.push_str(peer_name);
            }
        }
        if wrote_conflict {
            md.push('`');
        }
        if let Some((t, _)) = telemetry.get_for_module_system(&analyzed.module_path, &callable.name)
        {
            let q = if (t.flags & TELEMETRY_FLAG_QUARANTINED) != 0 {
                " **[QUARANTINED]**"
            } else {
                ""
            };
            let _ = write!(
                md,
                "\n- **Live Telemetry (frame #{}):** `p50 = {} us`, `p99 = {} us`, `entities = {}`, `tables = {}` (skipped `{}`){q}",
                t.frame_seq,
                t.p50_us,
                t.p99_us,
                t.matched_entities,
                t.matched_tables,
                t.skipped_summary_tick_tables
            );
        }
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(f) = analyzed.fns.iter().find(|hf| hf.name == ident) {
        let mut md = String::with_capacity(128);
        md.push_str("```strata\nfn ");
        md.push_str(&f.name);
        if !f.generic_params.is_empty() {
            md.push('<');
            for (i, g) in f.generic_params.iter().enumerate() {
                if i > 0 {
                    md.push_str(", ");
                }
                md.push_str(g);
            }
            md.push('>');
        }
        md.push('(');
        for (i, p) in f.params.iter().enumerate() {
            if i > 0 {
                md.push_str(", ");
            }
            let _ = write!(md, "{}: {}", p.name, format_ty_short(&p.ty));
        }
        let _ = write!(md, ") -> {}\n```", format_ty_short(&f.ret_ty));
        append_doc(&mut md, lookup_item_doc(&f.name), f.is_node_pure);
        if f.is_node_pure {
            md.push_str("\n\n- **Pure:** `@node_pure`");
        }
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(edef) = analyzed.enums.get(ident) {
        let mut md = String::with_capacity(128 + edef.variants.len() * 16);
        let _ = write!(md, "### `enum {}`", edef.canonical_name);
        append_doc(&mut md, lookup_item_doc(ident), true);
        let _ = write!(
            md,
            "\n\n\
             - **Repr:** `{}` (`{} B`)\n\
             - **Variants ({}):** ",
            edef.rust_repr(),
            edef.repr_bytes,
            edef.variants.len(),
        );
        for (i, (v, d)) in edef.variants.iter().enumerate() {
            if i > 0 {
                md.push_str(", ");
            }
            let _ = write!(md, "`{v} = {d}`");
        }
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(rpc) = analyzed.rpcs.iter().find(|r| r.name == ident) {
        let mut md = format!("### `rpc {}`", rpc.canonical_name);
        append_doc(&mut md, lookup_item_doc(&rpc.name), true);
        let _ = write!(
            md,
            "\n\n\
             - **Direction:** `{:?}` | **Reliability:** `{:?}` | **Channel:** `{}`\n\
             - **RPC ID:** `0x{:016X}`\n\
             - **Payload:** `{}`",
            rpc.direction,
            rpc.reliability,
            rpc.channel,
            rpc.rpc_id,
            format_layout_summary(&rpc.payload_layout)
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(fsm) = analyzed.fsms.iter().find(|f| f.name == ident) {
        let state_names: Vec<&str> = fsm.states.iter().map(String::as_str).collect();
        let mut md = format!("### `fsm {}`", fsm.name);
        append_doc(&mut md, lookup_item_doc(&fsm.name), true);
        let _ = write!(
            md,
            "\n\n- **States ({}):** `{}`",
            state_names.len(),
            state_names.join("`, `")
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(tl) = analyzed.timelines.iter().find(|t| t.name == ident) {
        let win_names: Vec<&str> = tl.windows.iter().map(|w| w.0.as_str()).collect();
        let mut md = format!("### `timeline {}`", tl.canonical_name);
        append_doc(&mut md, lookup_item_doc(&tl.name), true);
        let _ = write!(
            md,
            "\n\n- **Rate:** `{} Hz` | **Duration:** `{} frames`\n- **Windows ({}):** `{}`",
            tl.rate_hz,
            tl.duration_frames,
            win_names.len(),
            win_names.join("`, `")
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(c) = analyzed.consts.iter().find(|hc| hc.name == ident) {
        let mut md = format!(
            "```strata\nconst {}: {}\n```",
            c.name,
            format_ty_short(&c.ty)
        );
        append_doc(&mut md, lookup_item_doc(&c.name), false);
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    // Remaining analyzed/indexed constructs (`tag`, `table`, `curve`, `spatial_*`, `task`, `object`, `schedule`, etc.)
    if analyzed.tags.iter().any(|t| t == ident) {
        let mut md = format!("### `tag {ident}`");
        append_doc(&mut md, lookup_item_doc(ident), false);
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(t) = analyzed.tables.iter().find(|tb| tb.name == ident) {
        let mut md = format!("### `table {}`", t.name);
        append_doc(&mut md, lookup_item_doc(&t.name), true);
        let _ = write!(
            md,
            "\n\n- **Key:** `{}` | **Rows:** `{}`",
            t.key_enum,
            t.rows.len()
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(cv) = analyzed.curves.iter().find(|c| c.name == ident) {
        let mut md = format!("### `curve {}`", cv.name);
        append_doc(&mut md, lookup_item_doc(&cv.name), true);
        let _ = write!(
            md,
            "\n\n- **Mapping:** `{} -> {}` (`{} points`)",
            format_ty_short(&cv.input_ty),
            format_ty_short(&cv.output_ty),
            cv.points.len()
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(sp) = analyzed.spatial_indices.iter().find(|s| s.name == ident) {
        let kind = if sp.is_history {
            "spatial_history"
        } else {
            "spatial_grid"
        };
        let mut md = format!("### `{kind} {}`", sp.name);
        append_doc(&mut md, lookup_item_doc(&sp.name), true);
        let _ = write!(
            md,
            "\n\n- **Over:** `{}` by `{}` | **Cell:** `{} m` | **Capacity:** `{}`",
            sp.over_component, sp.by_field_path, sp.cell_size, sp.capacity
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(task) = analyzed.tasks.iter().find(|t| t.name == ident) {
        let mut md = format!("### `task {}`", task.name);
        append_doc(&mut md, lookup_item_doc(&task.name), true);
        let _ = write!(
            md,
            "\n\n- **State Layout:** `{}`",
            format_layout_summary(&task.state_layout)
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(obj) = analyzed.objects.iter().find(|o| o.name == ident) {
        let mut md = format!("### `object {}`", obj.name);
        append_doc(&mut md, lookup_item_doc(&obj.name), true);
        let _ = write!(
            md,
            "\n\n- **Persist:** `{}` | **Components:** `{}`",
            obj.is_persist,
            obj.components.join("`, `")
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(sched) = analyzed.schedules.iter().find(|s| s.label == ident) {
        let mut md = format!("### `schedule {}`", sched.label);
        append_doc(&mut md, lookup_item_doc(&sched.label), true);
        let _ = write!(md, "\n\n- **Nodes:** `{}`", sched.nodes.len());
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    if let Some(dc) = doc_comments
        && let Some(kind_str) = dc.item_kinds.get(ident)
    {
        let mut md = format!("### `{kind_str} {ident}`");
        append_doc(&mut md, lookup_item_doc(ident), false);
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    // Check if hovered word matches a unique field across declared layouts
    let mut matching_fields: BTreeMap<&str, (&SolvedLayout, &strata_sema::SolvedField)> =
        BTreeMap::new();
    for layout in analyzed.layouts.values() {
        for f in &layout.fields {
            if !f.is_padding && f.name == ident {
                matching_fields.insert(&layout.canonical_name, (layout, f));
            }
        }
    }
    if matching_fields.len() == 1
        && let Some((owner, (_, f))) = matching_fields.into_iter().next()
    {
        let owner_short = owner.rsplit("::").next().unwrap_or(owner);
        let field_doc = doc_comments
            .and_then(|dc| {
                dc.members
                    .get(&(owner_short.to_owned(), f.name.clone()))
                    .or_else(|| dc.members.get(&(owner.to_owned(), f.name.clone())))
            })
            .map(String::as_str);
        let mut md = format!("### `{owner}.{}`", f.name);
        append_doc(&mut md, field_doc, true);
        let _ = write!(
            md,
            "\n\n- **Type:** `{}`\n- **Offset:** `+{} B` (`{} B`, align `{} B`)",
            format_ty_short(&f.ty),
            f.offset,
            f.size,
            f.align
        );
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: md,
            }),
            range: Some(range),
        });
    }

    // 4. Built-in scalar, SIMD, container, and SI physical unit types
    if let Some((ty_name, doc)) = STRATA_BUILTIN_TYPES.iter().find(|(name, _)| *name == ident) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!("### `{ty_name}` (built-in type)\n\n{doc}"),
            }),
            range: Some(range),
        });
    }

    // 5. Strata keywords & built-in ECS intrinsics
    if let Some((category, doc)) = keyword_hover_doc(ident) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!("### `{ident}` ({category})\n\n{doc}"),
            }),
            range: Some(range),
        });
    }

    None
}

/// Parses an optional `telemetryEndpoint` / `telemetry_endpoint` setting from Zed
/// `initializationOptions` or `workspace/didChangeConfiguration` JSON payloads.
///
/// Accepts:
/// - `"tcp://127.0.0.1:15703"` or `"127.0.0.1:15703"` -> [`TelemetryEndpoint::Tcp`]
/// - `"unix:///tmp/strata.sock"` or `"/tmp/strata.sock"` -> [`TelemetryEndpoint::Unix`]
#[must_use]
pub fn parse_telemetry_endpoint(value: &Value) -> Option<TelemetryEndpoint> {
    let raw = value
        .get("telemetryEndpoint")
        .or_else(|| value.get("telemetry_endpoint"))
        .or_else(|| {
            value.get("strata").and_then(|s| {
                s.get("telemetryEndpoint")
                    .or_else(|| s.get("telemetry_endpoint"))
            })
        })
        .and_then(Value::as_str)?
        .trim();

    if raw.is_empty() {
        return None;
    }
    if let Some(addr_str) = raw.strip_prefix("tcp://") {
        return addr_str
            .parse::<SocketAddr>()
            .ok()
            .map(TelemetryEndpoint::Tcp);
    }
    if let Some(path_str) = raw.strip_prefix("unix://") {
        return (!path_str.is_empty()).then(|| TelemetryEndpoint::Unix(PathBuf::from(path_str)));
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(TelemetryEndpoint::Tcp(addr));
    }
    if raw.starts_with('/') {
        return Some(TelemetryEndpoint::Unix(PathBuf::from(raw)));
    }
    None
}
