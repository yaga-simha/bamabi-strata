//! Error-recovering LL(2) + Pratt parser producing a lossless `rowan` CST.

use crate::lexer::{Token, lex};
use crate::syntax_kind::{StrataLanguage, SyntaxKind, SyntaxNode};
use rowan::{GreenNodeBuilder, TextRange, TextSize};
use serde::{Deserialize, Serialize};

/// A syntax error diagnostic emitted during lossless CST parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    /// Machine-readable diagnostic code (e.g. `"E0001"`).
    pub code: String,
    /// Human-readable description of the syntax error.
    pub message: String,
    /// Byte offset start in source.
    pub byte_start: u32,
    /// Byte offset end in source.
    pub byte_end: u32,
}

impl ParseError {
    fn new(code: &str, message: impl Into<String>, range: TextRange) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            byte_start: u32::from(range.start()),
            byte_end: u32::from(range.end()),
        }
    }
}

/// Complete lossless parse output holding the `rowan` CST root and accumulated errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parse {
    green: rowan::GreenNode,
    errors: Vec<ParseError>,
}

impl Parse {
    /// Returns the typed root [`SyntaxNode`] (`SourceFile`).
    pub fn syntax(&self) -> SyntaxNode {
        SyntaxNode::new_root(self.green.clone())
    }

    /// Returns all syntax errors recorded during parsing.
    pub fn errors(&self) -> &[ParseError] {
        &self.errors
    }

    /// Returns `true` if parsing succeeded with zero syntax errors.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Parses a Strata v2.0 source string into a lossless CST ([`Parse`]).
///
/// The invariant `parse(src).syntax().text().to_string() == src` always holds, even on malformed
/// inputs.
pub fn parse(src: &str) -> Parse {
    let tokens = lex(src);
    let non_trivia: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(idx, tok)| (!tok.kind.is_trivia()).then_some(idx))
        .collect();

    let mut parser = Parser {
        src,
        tokens,
        non_trivia,
        tok_cursor: 0,
        nt_cursor: 0,
        pending_gt: false,
        builder: GreenNodeBuilder::new(),
        errors: Vec::new(),
    };
    parser.parse_source_file();
    let green = parser.builder.finish();
    Parse {
        green,
        errors: parser.errors,
    }
}

struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token<'a>>,
    non_trivia: Vec<usize>,
    tok_cursor: usize,
    nt_cursor: usize,
    pending_gt: bool,
    builder: GreenNodeBuilder<'static>,
    errors: Vec<ParseError>,
}

impl<'a> Parser<'a> {
    #[inline]
    fn cursor_state(&self) -> (usize, bool) {
        (self.nt_cursor, self.pending_gt)
    }

    #[inline]
    fn nth(&self, offset: usize) -> SyntaxKind {
        if self.pending_gt && offset == 0 {
            return SyntaxKind::Gt;
        }
        self.non_trivia
            .get(self.nt_cursor + offset)
            .map_or(SyntaxKind::Eof, |&idx| self.tokens[idx].kind)
    }

    #[inline]
    fn nth_text(&self, offset: usize) -> &'a str {
        if self.pending_gt && offset == 0 {
            return ">";
        }
        self.non_trivia
            .get(self.nt_cursor + offset)
            .map_or("", |&idx| self.tokens[idx].text)
    }

    #[inline]
    fn current_range(&self) -> TextRange {
        if let Some(&idx) = self.non_trivia.get(self.nt_cursor) {
            let range = self.tokens[idx].range;
            if self.pending_gt {
                TextRange::new(range.start() + TextSize::from(1), range.end())
            } else {
                range
            }
        } else {
            let end = TextSize::try_from(self.src.len()).unwrap_or(TextSize::from(0));
            TextRange::new(end, end)
        }
    }

    #[inline]
    fn at(&self, kind: SyntaxKind) -> bool {
        self.nth(0) == kind
    }

    #[inline]
    fn at_eof(&self) -> bool {
        self.nth(0) == SyntaxKind::Eof
    }

    #[inline]
    fn at_ctx(&self, kw: &str) -> bool {
        self.nth(0) == SyntaxKind::Ident && self.nth_text(0) == kw
    }

    #[inline]
    fn nth_is_ctx(&self, offset: usize, kw: &str) -> bool {
        self.nth(offset) == SyntaxKind::Ident && self.nth_text(offset) == kw
    }

    fn eat_trivia(&mut self) {
        if self.pending_gt {
            return;
        }
        let stop = self
            .non_trivia
            .get(self.nt_cursor)
            .copied()
            .unwrap_or(self.tokens.len());
        while self.tok_cursor < stop {
            let tok = self.tokens[self.tok_cursor];
            self.builder.token(tok.kind.into(), tok.text);
            self.tok_cursor += 1;
        }
    }

    fn bump_raw(&mut self, override_kind: Option<SyntaxKind>) {
        if self.pending_gt {
            let kind = override_kind.unwrap_or(SyntaxKind::Gt);
            self.builder.token(kind.into(), ">");
            self.pending_gt = false;
            let target_idx = self.non_trivia[self.nt_cursor];
            self.tok_cursor = target_idx + 1;
            self.nt_cursor += 1;
            return;
        }
        self.eat_trivia();
        if self.nt_cursor >= self.non_trivia.len() {
            return;
        }
        let target_idx = self.non_trivia[self.nt_cursor];
        let tok = self.tokens[target_idx];
        let kind = override_kind.unwrap_or(tok.kind);
        if tok.kind == SyntaxKind::Error {
            self.errors.push(ParseError::new(
                "E0001",
                format!("unexpected character `{}`", tok.text),
                tok.range,
            ));
        }
        self.builder.token(kind.into(), tok.text);
        self.tok_cursor = target_idx + 1;
        self.nt_cursor += 1;
    }

    fn bump_split_shr_gt(&mut self) {
        debug_assert!(self.at(SyntaxKind::Shr) && !self.pending_gt);
        self.eat_trivia();
        self.builder.token(SyntaxKind::Gt.into(), ">");
        self.pending_gt = true;
    }

    #[inline]
    fn bump(&mut self) {
        self.bump_raw(None);
    }

    #[inline]
    fn bump_as(&mut self, kind: SyntaxKind) {
        self.bump_raw(Some(kind));
    }

    fn eat(&mut self, kind: SyntaxKind) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn eat_ctx(&mut self, kw: &str, mapped: SyntaxKind) -> bool {
        if self.at_ctx(kw) {
            self.bump_as(mapped);
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: SyntaxKind) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            let range = self.current_range();
            self.error(
                format!("expected {kind:?}, found `{}`", self.nth_text(0)),
                range,
            );
            false
        }
    }

    fn error(&mut self, message: impl Into<String>, range: TextRange) {
        self.errors.push(ParseError::new("E0002", message, range));
    }

    fn error_and_bump(&mut self, message: impl Into<String>) {
        self.eat_trivia();
        let range = self.current_range();
        self.error(message, range);
        if !self.at_eof() {
            self.builder.start_node(SyntaxKind::Error.into());
            self.bump();
            self.builder.finish_node();
        }
    }

    fn start_node(&mut self, kind: SyntaxKind) {
        self.eat_trivia();
        self.builder.start_node(kind.into());
    }

    fn finish_node(&mut self) {
        self.builder.finish_node();
    }

    #[inline]
    fn checkpoint(&mut self) -> rowan::Checkpoint {
        self.eat_trivia();
        self.builder.checkpoint()
    }

    #[inline]
    fn start_node_at(&mut self, checkpoint: rowan::Checkpoint, kind: SyntaxKind) {
        self.builder.start_node_at(checkpoint, kind.into());
    }

    // --- Helper predicates ---

    #[inline]
    fn at_ident_like(&self) -> bool {
        self.nth(0) == SyntaxKind::Ident
    }

    #[inline]
    fn at_member_ident(&self) -> bool {
        matches!(
            self.nth(0),
            SyntaxKind::Ident
                | SyntaxKind::KwSelfLower
                | SyntaxKind::KwSelfUpper
                | SyntaxKind::KwIn
                | SyntaxKind::KwMatch
        ) || is_keyword_usable_as_member(self.nth(0))
    }

    fn bump_ident_or_ctx(&mut self) {
        if self.at(SyntaxKind::Ident) || is_keyword_usable_as_member(self.nth(0)) {
            self.bump_as(SyntaxKind::Ident);
        } else if matches!(
            self.nth(0),
            SyntaxKind::KwSelfLower | SyntaxKind::KwSelfUpper
        ) {
            self.bump();
        } else {
            let range = self.current_range();
            self.error(
                format!("expected identifier, found `{}`", self.nth_text(0)),
                range,
            );
        }
    }

    // --- Entry point ---

    fn parse_source_file(&mut self) {
        self.builder.start_node(SyntaxKind::SourceFile.into());
        while !self.at_eof() {
            self.eat_trivia();
            if self.at_eof() {
                break;
            }
            let start_nt = self.nt_cursor;
            self.parse_item_decl();
            if self.nt_cursor == start_nt && !self.at_eof() {
                self.error_and_bump(format!(
                    "unexpected token `{}` at top level",
                    self.nth_text(0)
                ));
            }
        }
        self.eat_trivia();
        self.builder.finish_node();
    }

    // --- Attributes & Paths ---

    fn parse_attributes(&mut self) {
        while self.at(SyntaxKind::At) {
            if self.nth_is_ctx(1, "require") {
                break;
            }
            self.parse_attribute();
        }
    }

    fn parse_attribute(&mut self) {
        self.start_node(SyntaxKind::Attribute);
        self.bump(); // @
        self.bump_ident_or_ctx();
        if self.at(SyntaxKind::LParen) {
            self.start_node(SyntaxKind::AttrArgList);
            self.bump(); // (
            while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.parse_attr_arg();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RParen);
            self.finish_node();
        }
        self.finish_node();
    }

    fn looks_like_semver_at(&self, offset: usize) -> bool {
        // Matches `1.0.0` (`FloatLit("1.0") Dot IntLit("0")`) or `IntLit Dot IntLit Dot IntLit`.
        if self.nth(offset) == SyntaxKind::FloatLit
            && self.nth(offset + 1) == SyntaxKind::Dot
            && self.nth(offset + 2) == SyntaxKind::IntLit
        {
            return true;
        }
        self.nth(offset) == SyntaxKind::IntLit
            && self.nth(offset + 1) == SyntaxKind::Dot
            && self.nth(offset + 2) == SyntaxKind::IntLit
            && self.nth(offset + 3) == SyntaxKind::Dot
            && self.nth(offset + 4) == SyntaxKind::IntLit
    }

    fn parse_semver(&mut self) {
        self.start_node(SyntaxKind::SemVer);
        if self.nth(0) == SyntaxKind::FloatLit && self.nth(1) == SyntaxKind::Dot {
            self.bump();
            self.bump();
            self.expect(SyntaxKind::IntLit);
        } else {
            self.expect(SyntaxKind::IntLit);
            self.expect(SyntaxKind::Dot);
            self.expect(SyntaxKind::IntLit);
            self.expect(SyntaxKind::Dot);
            self.expect(SyntaxKind::IntLit);
        }
        self.finish_node();
    }

    fn parse_attr_arg(&mut self) {
        self.start_node(SyntaxKind::AttrArg);
        if self.looks_like_semver_at(0) {
            self.parse_semver();
        } else if self.at_ident_like() && self.nth(1) == SyntaxKind::Eq {
            self.bump();
            self.bump();
            self.parse_expr(true);
        } else {
            self.parse_expr(true);
        }
        self.finish_node();
    }

    fn parse_path(&mut self) {
        self.start_node(SyntaxKind::Path);
        self.bump_ident_or_ctx();
        while self.at(SyntaxKind::ColonColon) {
            if self.nth(1) == SyntaxKind::LBrace || self.nth(1) == SyntaxKind::Star {
                break;
            }
            self.bump(); // ::
            self.bump_ident_or_ctx();
        }
        self.finish_node();
    }

    fn parse_field_path(&mut self) {
        self.start_node(SyntaxKind::Path);
        self.bump_ident_or_ctx();
        while self.at(SyntaxKind::ColonColon) || self.at(SyntaxKind::Dot) {
            self.bump();
            self.bump_ident_or_ctx();
        }
        self.finish_node();
    }

    fn parse_generic_params(&mut self) {
        if !self.at(SyntaxKind::Lt) {
            return;
        }
        self.start_node(SyntaxKind::GenericParams);
        self.bump(); // <
        while !self.at(SyntaxKind::Gt) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.bump_ident_or_ctx();
            if self.eat(SyntaxKind::Colon) {
                self.parse_type();
            }
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::Gt);
        self.finish_node();
    }

    // --- Top-level declarations ---

    fn parse_item_decl(&mut self) {
        let cp = self.checkpoint();
        self.parse_attributes();

        match self.nth(0) {
            SyntaxKind::KwModule => {
                self.start_node_at(cp, SyntaxKind::ModuleDecl);
                self.bump();
                self.parse_path();
                self.parse_attributes();
                self.expect(SyntaxKind::Semi);
                self.finish_node();
            }
            SyntaxKind::KwUse => {
                self.start_node_at(cp, SyntaxKind::ImportDecl);
                self.bump();
                self.parse_path();
                if self.eat(SyntaxKind::ColonColon) && self.at(SyntaxKind::LBrace) {
                    self.start_node(SyntaxKind::ImportList);
                    self.bump();
                    while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
                        let guard = self.nt_cursor;
                        self.bump_ident_or_ctx();
                        if !self.eat(SyntaxKind::Comma) {
                            break;
                        }
                        if self.nt_cursor == guard {
                            break;
                        }
                    }
                    self.expect(SyntaxKind::RBrace);
                    self.finish_node();
                } else if self.eat(SyntaxKind::KwAs) {
                    self.bump_ident_or_ctx();
                }
                self.expect(SyntaxKind::Semi);
                self.finish_node();
            }
            SyntaxKind::KwConst => {
                self.start_node_at(cp, SyntaxKind::ConstDecl);
                self.bump();
                self.bump_ident_or_ctx();
                self.expect(SyntaxKind::Colon);
                self.parse_type();
                self.expect(SyntaxKind::Eq);
                self.parse_expr(true);
                self.expect(SyntaxKind::Semi);
                self.finish_node();
            }
            SyntaxKind::KwStruct => self.parse_struct_decl(cp),
            SyntaxKind::KwEnum => self.parse_enum_decl(cp),
            SyntaxKind::KwComponent => self.parse_component_decl(cp),
            SyntaxKind::KwTag => self.parse_tag_decl(cp),
            SyntaxKind::KwResource => self.parse_resource_decl(cp),
            SyntaxKind::KwEvent => self.parse_event_or_stream_decl(cp, SyntaxKind::EventDecl),
            SyntaxKind::KwStream => self.parse_event_or_stream_decl(cp, SyntaxKind::StreamDecl),
            SyntaxKind::KwRelation => self.parse_relation_decl(cp),
            SyntaxKind::KwTable => self.parse_table_decl(cp),
            SyntaxKind::KwCurve => self.parse_curve_decl(cp),
            SyntaxKind::KwSpatialGrid => self.parse_spatial_decl(cp, SyntaxKind::SpatialGridDecl),
            SyntaxKind::KwSpatialHistory => {
                self.parse_spatial_decl(cp, SyntaxKind::SpatialHistoryDecl)
            }
            SyntaxKind::KwHashIndex => self.parse_hash_index_decl(cp),
            SyntaxKind::KwAspect => self.parse_aspect_decl(cp),
            SyntaxKind::KwPrefab => self.parse_bundle_item_decl(cp, SyntaxKind::PrefabDecl),
            SyntaxKind::KwObject => self.parse_bundle_item_decl(cp, SyntaxKind::ObjectDecl),
            SyntaxKind::Ident if self.at_ctx("zone") => self.parse_zone_decl(cp),
            SyntaxKind::Ident if self.at_ctx("rpc") => self.parse_rpc_decl(cp),
            SyntaxKind::KwTimeline => self.parse_timeline_decl(cp),
            SyntaxKind::KwTask => self.parse_task_decl(cp),
            SyntaxKind::KwFsm => self.parse_fsm_decl(cp),
            SyntaxKind::KwSys => self.parse_sys_decl(cp),
            SyntaxKind::KwObs => self.parse_obs_decl(cp),
            SyntaxKind::KwFn => self.parse_fn_decl(cp),
            SyntaxKind::KwMigrate => self.parse_migrate_decl(cp),
            SyntaxKind::KwSchedule => self.parse_schedule_decl(cp),
            SyntaxKind::KwAssertLayout => self.parse_assert_layout_decl(cp),
            SyntaxKind::KwAssertPar => self.parse_assert_par_decl(cp),
            SyntaxKind::KwSimTest => self.parse_sim_test_decl(cp),
            SyntaxKind::KwNetSimTest => self.parse_net_sim_test_decl(cp),
            _ => {
                // Close any attributes parsed at `cp` under an `Error` node.
                self.start_node_at(cp, SyntaxKind::Error);
                let range = self.current_range();
                self.error(
                    format!(
                        "expected top-level declaration, found `{}`",
                        self.nth_text(0)
                    ),
                    range,
                );
                if !self.at_eof() {
                    self.bump();
                }
                self.finish_node();
            }
        }
    }

    fn parse_struct_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::StructDecl);
        self.bump(); // struct
        self.bump_ident_or_ctx();
        self.parse_generic_params();
        self.parse_attributes();
        self.parse_field_decl_braced();
        self.finish_node();
    }

    fn parse_enum_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::EnumDecl);
        self.bump(); // enum
        self.bump_ident_or_ctx();
        self.parse_attributes();
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::VariantDecl);
            self.bump_ident_or_ctx();
            if self.at(SyntaxKind::LParen) {
                self.bump();
                while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                    let g2 = self.nt_cursor;
                    self.parse_field_decl();
                    if !self.eat(SyntaxKind::Comma) {
                        break;
                    }
                    if self.nt_cursor == g2 {
                        break;
                    }
                }
                self.expect(SyntaxKind::RParen);
            } else if self.at(SyntaxKind::LBrace) {
                self.parse_field_decl_braced();
            } else if self.eat(SyntaxKind::Eq) {
                self.parse_expr(true);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_require_clause(&mut self) {
        if !(self.at(SyntaxKind::At) && self.nth_is_ctx(1, "require")) {
            return;
        }
        self.start_node(SyntaxKind::RequireClause);
        self.bump(); // @
        self.bump_as(SyntaxKind::KwRequire);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::RequireItem);
            self.parse_path();
            if self.eat(SyntaxKind::Eq) {
                self.parse_expr(true);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_inline_modifiers_and_require(&mut self) {
        loop {
            if self.at(SyntaxKind::At) && self.nth_is_ctx(1, "require") {
                self.parse_require_clause();
            } else if self.at(SyntaxKind::At) {
                self.parse_attribute();
            } else {
                break;
            }
        }
    }

    fn parse_component_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::ComponentDecl);
        self.bump(); // component
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        if self.eat(SyntaxKind::Semi) {
            self.finish_node();
            return;
        }
        if self.expect(SyntaxKind::LBrace) {
            while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
                let guard = self.nt_cursor;
                if (self.at_ctx("hot") && self.nth(1) == SyntaxKind::LBrace)
                    || (self.at_ctx("cold")
                        && self.nth(1) == SyntaxKind::Ident
                        && self.nth(2) == SyntaxKind::LBrace)
                {
                    self.start_node(SyntaxKind::StratumBlock);
                    if self.at_ctx("hot") {
                        self.bump_as(SyntaxKind::KwHot);
                    } else {
                        self.bump_as(SyntaxKind::KwCold);
                        self.bump_ident_or_ctx();
                    }
                    self.parse_field_decl_braced();
                    self.finish_node();
                } else {
                    self.parse_field_decl();
                    let _ = self.eat(SyntaxKind::Comma) || self.eat(SyntaxKind::Semi);
                }
                if self.nt_cursor == guard {
                    self.error_and_bump("expected field or stratum in component");
                }
            }
            self.expect(SyntaxKind::RBrace);
        }
        self.finish_node();
    }

    fn parse_tag_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::TagDecl);
        self.bump(); // tag
        loop {
            self.bump_ident_or_ctx();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
        }
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_resource_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::ResourceDecl);
        self.bump(); // resource
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        self.parse_field_decl_braced();
        self.finish_node();
    }

    fn parse_event_or_stream_decl(&mut self, cp: rowan::Checkpoint, kind: SyntaxKind) {
        self.start_node_at(cp, kind);
        self.bump(); // event | stream
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        if !self.eat(SyntaxKind::Semi) {
            self.parse_field_decl_braced();
        }
        self.finish_node();
    }

    fn parse_relation_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::RelationDecl);
        self.bump(); // relation
        self.bump_ident_or_ctx();
        if self.at(SyntaxKind::LBracket) {
            self.start_node(SyntaxKind::RelFlags);
            self.bump();
            while !self.at(SyntaxKind::RBracket) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.bump_ident_or_ctx();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RBracket);
            self.finish_node();
        }
        self.parse_inline_modifiers_and_require();
        if !self.eat(SyntaxKind::Semi) {
            self.parse_field_decl_braced();
            let _ = self.eat(SyntaxKind::Semi);
        }
        self.finish_node();
    }

    fn parse_table_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::TableDecl);
        self.bump(); // table
        self.bump_ident_or_ctx();
        if !self.eat_ctx("by", SyntaxKind::KwBy) {
            let r = self.current_range();
            self.error("expected `by` in table declaration", r);
        }
        self.parse_path();
        self.parse_field_decl_braced();
        self.expect(SyntaxKind::Eq);
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::TableRow);
            self.bump_ident_or_ctx();
            self.expect(SyntaxKind::FatArrow);
            self.expect(SyntaxKind::LBrace);
            self.parse_field_init_list(SyntaxKind::RBrace);
            self.expect(SyntaxKind::RBrace);
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_curve_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::CurveDecl);
        self.bump(); // curve
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::LParen);
        self.parse_type();
        self.expect(SyntaxKind::ThinArrow);
        self.parse_type();
        self.expect(SyntaxKind::RParen);
        self.expect(SyntaxKind::Eq);
        self.expect(SyntaxKind::LBracket);
        while !self.at(SyntaxKind::RBracket) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::CurvePoint);
            self.expect(SyntaxKind::LParen);
            self.parse_expr(true);
            self.expect(SyntaxKind::Comma);
            self.parse_expr(true);
            self.expect(SyntaxKind::RParen);
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBracket);
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_spatial_decl(&mut self, cp: rowan::Checkpoint, kind: SyntaxKind) {
        self.start_node_at(cp, kind);
        self.bump(); // spatial_grid | spatial_history
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::LParen);
        self.parse_field_init_list(SyntaxKind::RParen);
        self.expect(SyntaxKind::RParen);
        if !self.eat_ctx("over", SyntaxKind::KwOver) {
            let r = self.current_range();
            self.error("expected `over`", r);
        }
        self.parse_path();
        if !self.eat_ctx("by", SyntaxKind::KwBy) {
            let r = self.current_range();
            self.error("expected `by`", r);
        }
        self.parse_field_path();
        if self.eat_ctx("cache", SyntaxKind::KwCache) {
            self.expect(SyntaxKind::LParen);
            self.parse_proj_term_list(SyntaxKind::RParen);
            self.expect(SyntaxKind::RParen);
        }
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_hash_index_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::HashIndexDecl);
        self.bump(); // hash_index
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::LParen);
        self.parse_field_init_list(SyntaxKind::RParen);
        self.expect(SyntaxKind::RParen);
        let _ = self.eat_ctx("over", SyntaxKind::KwOver);
        self.parse_path();
        let _ = self.eat_ctx("by", SyntaxKind::KwBy);
        let _ = self.eat_ctx("key", SyntaxKind::KwKey);
        self.expect(SyntaxKind::LParen);
        self.parse_field_path();
        self.expect(SyntaxKind::RParen);
        if self.eat_ctx("cache", SyntaxKind::KwCache) {
            self.expect(SyntaxKind::LParen);
            self.parse_proj_term_list(SyntaxKind::RParen);
            self.expect(SyntaxKind::RParen);
        }
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_aspect_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::AspectDecl);
        self.bump(); // aspect
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::LParen);
        self.parse_proj_term_list(SyntaxKind::RParen);
        self.expect(SyntaxKind::RParen);
        // Optional filter chain (.with<T>() etc.)
        while self.eat(SyntaxKind::Dot) {
            self.bump_ident_or_ctx();
            if self.at(SyntaxKind::Lt) {
                self.parse_generic_args();
            }
            if self.at(SyntaxKind::LParen) {
                self.parse_arg_list();
            }
        }
        if self.eat_ctx("where", SyntaxKind::KwWhere) {
            self.parse_expr(true);
        }
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_bundle_item_decl(&mut self, cp: rowan::Checkpoint, kind: SyntaxKind) {
        self.start_node_at(cp, kind);
        self.bump(); // prefab | object
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        self.expect(SyntaxKind::LBrace);
        self.parse_comp_init_list(SyntaxKind::RBrace);
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_zone_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::ZoneDecl);
        self.bump_as(SyntaxKind::KwZone);
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        self.parse_field_decl_braced();
        self.finish_node();
    }

    fn parse_rpc_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::RpcDecl);
        self.bump_as(SyntaxKind::KwRpc);
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        if !self.eat(SyntaxKind::Semi) {
            self.parse_field_decl_braced();
        }
        self.finish_node();
    }

    fn parse_timeline_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::TimelineDecl);
        self.bump(); // timeline
        self.bump_ident_or_ctx();
        self.parse_inline_modifiers_and_require();
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            if self.at_ctx("window") {
                self.start_node(SyntaxKind::TimelineWindow);
                self.bump_as(SyntaxKind::KwWindow);
                self.bump_ident_or_ctx();
                self.expect(SyntaxKind::Eq);
                self.parse_expr(true);
                self.expect(SyntaxKind::Semi);
                self.finish_node();
            } else if self.at_ctx("at") {
                self.start_node(SyntaxKind::TimelineAt);
                self.bump_as(SyntaxKind::KwAt);
                self.parse_expr(true);
                self.expect(SyntaxKind::FatArrow);
                self.parse_stmt_in_block();
                self.finish_node();
            } else {
                self.error_and_bump("expected `window` or `at` in timeline");
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_task_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::TaskDecl);
        self.bump(); // task
        self.bump_ident_or_ctx();
        self.parse_param_list();
        if self.eat_ctx("on", SyntaxKind::KwOn) {
            self.expect(SyntaxKind::LParen);
            self.parse_proj_term_list(SyntaxKind::RParen);
            self.expect(SyntaxKind::RParen);
        }
        while self.eat(SyntaxKind::Dot) {
            self.bump_ident_or_ctx();
            if self.at(SyntaxKind::Lt) {
                self.parse_generic_args();
            }
            if self.at(SyntaxKind::LParen) {
                self.parse_arg_list();
            }
        }
        if self.eat_ctx("using", SyntaxKind::KwUsing) {
            self.parse_sys_param_list();
        }
        self.parse_block();
        self.finish_node();
    }

    fn parse_fsm_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::FsmDecl);
        self.bump(); // fsm
        self.bump_ident_or_ctx();
        if self.at(SyntaxKind::LParen) {
            self.parse_sys_param_list();
        }
        self.parse_inline_modifiers_and_require();
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            if self.eat_ctx("initial", SyntaxKind::KwInitial) {
                self.bump_ident_or_ctx();
                if self.at(SyntaxKind::LBrace) {
                    self.parse_record_or_field_init_braced();
                }
                self.expect(SyntaxKind::Semi);
            } else if self.at_ctx("state") {
                self.parse_state_decl();
            } else {
                self.error_and_bump("expected `initial` or `state` in fsm");
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_state_decl(&mut self) {
        self.start_node(SyntaxKind::StateDecl);
        self.bump_as(SyntaxKind::KwState);
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::LBrace);
        // Either fields or hooks/transitions; distinguish by checking `ident : Type` vs hook/transition.
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            if self.at_ctx("on_enter") {
                self.bump_as(SyntaxKind::KwOnEnter);
                self.parse_block();
            } else if self.at_ctx("on_tick") {
                self.bump_as(SyntaxKind::KwOnTick);
                self.parse_block();
            } else if self.at_ctx("on_exit") {
                self.bump_as(SyntaxKind::KwOnExit);
                self.parse_block();
            } else if self.at_ctx("to") {
                self.start_node(SyntaxKind::TransitionDecl);
                self.bump_as(SyntaxKind::KwTo);
                self.bump_ident_or_ctx();
                if self.at(SyntaxKind::LBrace) {
                    self.parse_record_or_field_init_braced();
                }
                let _ = self.eat_ctx("when", SyntaxKind::KwWhen);
                self.parse_expr(true);
                self.parse_attributes();
                self.expect(SyntaxKind::Semi);
                self.finish_node();
            } else if self.at_ident_like() && self.nth(1) == SyntaxKind::Colon {
                self.parse_field_decl();
                let _ = self.eat(SyntaxKind::Comma) || self.eat(SyntaxKind::Semi);
            } else {
                self.error_and_bump("expected state hook, transition (`to`), or state field");
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_sys_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::SysDecl);
        self.bump(); // sys
        self.bump_ident_or_ctx();
        self.parse_sys_param_list();
        self.parse_effects_clause();
        self.parse_block();
        self.finish_node();
    }

    fn parse_obs_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::ObsDecl);
        self.bump(); // obs
        self.bump_ident_or_ctx();
        self.parse_sys_param_list();
        self.parse_effects_clause();
        self.parse_block();
        self.finish_node();
    }

    fn parse_fn_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::FnDecl);
        self.bump(); // fn
        self.bump_ident_or_ctx();
        self.parse_generic_params();
        self.parse_param_list();
        if self.eat(SyntaxKind::ThinArrow) {
            self.parse_type();
        }
        self.parse_block();
        self.finish_node();
    }

    fn parse_migrate_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::MigrateDecl);
        self.bump(); // migrate
        self.parse_path();
        let _ = self.eat_ctx("from", SyntaxKind::KwFrom);
        self.parse_semver();
        let _ = self.eat_ctx("to", SyntaxKind::KwTo);
        self.parse_semver();
        self.expect(SyntaxKind::LParen);
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::Colon);
        self.parse_type();
        self.expect(SyntaxKind::RParen);
        self.expect(SyntaxKind::ThinArrow);
        self.parse_path();
        self.parse_block();
        self.finish_node();
    }

    fn parse_effects_clause(&mut self) {
        if !self.at_ctx("effects") {
            return;
        }
        self.start_node(SyntaxKind::EffectsClause);
        self.bump_as(SyntaxKind::KwEffects);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::EffectEntry);
            self.bump_ident_or_ctx();
            self.expect(SyntaxKind::Colon);
            self.expect(SyntaxKind::LBracket);
            while !self.at(SyntaxKind::RBracket) && !self.at_eof() {
                let g2 = self.nt_cursor;
                self.parse_path();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == g2 {
                    break;
                }
            }
            self.expect(SyntaxKind::RBracket);
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_schedule_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::ScheduleDecl);
        self.bump(); // schedule
        self.parse_path();
        self.parse_schedule_mods();
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.parse_schedule_node();
            if self.nt_cursor == guard {
                self.error_and_bump("expected schedule node");
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_schedule_mods(&mut self) {
        while self.at_ctx("run_if") || self.at_ctx("before") || self.at_ctx("after") {
            self.start_node(SyntaxKind::ScheduleMod);
            if self.at_ctx("run_if") {
                self.bump_as(SyntaxKind::KwRunIf);
                self.expect(SyntaxKind::LParen);
                self.parse_expr(true);
                self.expect(SyntaxKind::RParen);
            } else if self.at_ctx("before") {
                self.bump_as(SyntaxKind::KwBefore);
                self.expect(SyntaxKind::LParen);
                self.parse_path();
                self.expect(SyntaxKind::RParen);
            } else {
                self.bump_as(SyntaxKind::KwAfter);
                self.expect(SyntaxKind::LParen);
                self.parse_path();
                self.expect(SyntaxKind::RParen);
            }
            self.finish_node();
        }
    }

    fn parse_schedule_node(&mut self) {
        self.start_node(SyntaxKind::ScheduleNode);
        let is_group = (self.at_ctx("seq")
            || self.at_ctx("seq_weak")
            || self.at_ctx("par")
            || self.at_ctx("set"))
            && self.nth(1) == SyntaxKind::Ident;

        if is_group {
            if self.at_ctx("seq") {
                self.bump_as(SyntaxKind::KwSeq);
            } else if self.at_ctx("seq_weak") {
                self.bump_as(SyntaxKind::KwSeqWeak);
            } else if self.at_ctx("par") {
                self.bump_as(SyntaxKind::KwPar);
            } else {
                self.bump_as(SyntaxKind::KwSet);
            }
            self.bump_ident_or_ctx();
            self.parse_schedule_mods();
            self.expect(SyntaxKind::LBrace);
            while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.parse_schedule_node();
                if self.nt_cursor == guard {
                    self.error_and_bump("expected schedule node");
                }
            }
            self.expect(SyntaxKind::RBrace);
        } else {
            self.parse_path();
            self.parse_schedule_mods();
            let _ = self.eat(SyntaxKind::Comma) || self.eat(SyntaxKind::Semi);
        }
        self.finish_node();
    }

    fn parse_assert_layout_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::AssertLayoutDecl);
        self.bump(); // assert_layout
        self.expect(SyntaxKind::LParen);
        self.parse_path();
        while self.eat(SyntaxKind::Comma) {
            if self.at(SyntaxKind::RParen) {
                break;
            }
            self.parse_expr(true);
        }
        self.expect(SyntaxKind::RParen);
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_assert_par_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::AssertParDecl);
        self.bump(); // assert_par
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.parse_path();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.expect(SyntaxKind::Semi);
        self.finish_node();
    }

    fn parse_sim_test_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::SimTestDecl);
        self.bump(); // sim_test
        self.expect(SyntaxKind::StringLit);
        self.parse_block();
        self.finish_node();
    }

    fn parse_net_sim_test_decl(&mut self, cp: rowan::Checkpoint) {
        self.start_node_at(cp, SyntaxKind::NetSimTestDecl);
        self.bump(); // net_sim_test
        self.expect(SyntaxKind::StringLit);
        if self.at(SyntaxKind::LParen) {
            self.parse_net_sim_param_list();
        }
        self.parse_block();
        self.finish_node();
    }

    fn parse_net_sim_param_list(&mut self) {
        self.start_node(SyntaxKind::NetSimParamList);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::NetSimParam);
            self.bump_ident_or_ctx();
            self.expect(SyntaxKind::Colon);
            if !self.at(SyntaxKind::RParen) && !self.at(SyntaxKind::Comma) {
                self.parse_expr(true);
            } else {
                let r = self.current_range();
                self.error("expected value for net_sim_test parameter", r);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                self.error_and_bump("expected net_sim_test parameter");
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    // --- Fields, Parameters & Projections ---

    fn parse_field_decl_braced(&mut self) {
        if !self.expect(SyntaxKind::LBrace) {
            return;
        }
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.parse_field_decl();
            let _ = self.eat(SyntaxKind::Comma) || self.eat(SyntaxKind::Semi);
            if self.nt_cursor == guard {
                self.error_and_bump("expected field declaration");
            }
        }
        self.expect(SyntaxKind::RBrace);
    }

    fn parse_field_decl(&mut self) {
        self.start_node(SyntaxKind::FieldDecl);
        self.parse_attributes();
        self.bump_ident_or_ctx();
        self.expect(SyntaxKind::Colon);
        self.parse_type();
        if self.eat(SyntaxKind::Eq) {
            self.parse_expr(true);
        }
        self.finish_node();
    }

    fn parse_field_init_list(&mut self, stop: SyntaxKind) {
        self.start_node(SyntaxKind::FieldInitList);
        while !self.at(stop) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::FieldInit);
            self.bump_ident_or_ctx();
            if self.eat(SyntaxKind::Colon) {
                self.parse_expr(true);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.finish_node();
    }

    fn parse_record_or_field_init_braced(&mut self) {
        self.start_node(SyntaxKind::RecordLitExpr);
        self.bump(); // {
        self.parse_field_init_list(SyntaxKind::RBrace);
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_comp_init_list(&mut self, stop: SyntaxKind) {
        self.start_node(SyntaxKind::CompInitList);
        while !self.at(stop) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::CompInit);
            self.parse_path();
            if self.eat(SyntaxKind::LBrace) {
                self.parse_field_init_list(SyntaxKind::RBrace);
                self.expect(SyntaxKind::RBrace);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.finish_node();
    }

    fn parse_param_list(&mut self) {
        self.start_node(SyntaxKind::ParamList);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::Param);
            self.bump_ident_or_ctx();
            self.expect(SyntaxKind::Colon);
            self.parse_type();
            if self.eat(SyntaxKind::Eq) {
                self.parse_expr(true);
            }
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_sys_param_list(&mut self) {
        self.start_node(SyntaxKind::SysParamList);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::SysParam);
            self.bump_ident_or_ctx();
            self.expect(SyntaxKind::Colon);
            self.parse_type();
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_proj_term_list(&mut self, stop: SyntaxKind) {
        self.start_node(SyntaxKind::ProjTermList);
        while !self.at(stop) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::ProjTerm);
            if self.at_ident_like() && self.nth(1) == SyntaxKind::Colon {
                self.bump();
                self.bump();
            }
            self.parse_type();
            self.finish_node();
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.finish_node();
    }

    // --- Types ---

    fn parse_type(&mut self) {
        if self.at(SyntaxKind::Question) && self.nth(1) == SyntaxKind::Amp {
            self.start_node(SyntaxKind::PtrTermType);
            self.bump(); // ?
            self.bump(); // &
            let _ = self.eat(SyntaxKind::KwMut);
            self.parse_type();
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::Amp) {
            self.start_node(SyntaxKind::RefType);
            self.bump(); // &
            let _ = self.eat(SyntaxKind::KwMut);
            let _ = self.eat(SyntaxKind::Question);
            let _ = self.eat_ctx("res", SyntaxKind::KwRes);
            self.parse_type();
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::LBracket) {
            self.start_node(SyntaxKind::ArrayType);
            self.bump(); // [
            self.parse_type();
            self.expect(SyntaxKind::Semi);
            self.parse_expr(true);
            self.expect(SyntaxKind::RBracket);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::LParen) {
            self.start_node(SyntaxKind::TupleType);
            self.bump(); // (
            while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.parse_type();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RParen);
            self.finish_node();
            return;
        }

        self.start_node(SyntaxKind::TypeRef);
        if self.at_ctx("stream_in") {
            self.bump_as(SyntaxKind::KwStreamIn);
        } else {
            self.parse_path();
        }
        // Optional field projection inside query term types, e.g. `Pos3D.xyz`
        while self.eat(SyntaxKind::Dot) {
            self.bump_ident_or_ctx();
        }
        if self.at(SyntaxKind::Lt) {
            self.parse_generic_args();
        }
        self.finish_node();
    }

    fn parse_generic_args(&mut self) {
        self.start_node(SyntaxKind::GenericArgs);
        self.bump(); // <
        let mut depth: usize = 1;
        while depth > 0 && !self.at_eof() {
            let guard = self.cursor_state();
            if self.at(SyntaxKind::Gt) {
                depth -= 1;
                self.bump();
                if depth == 0 {
                    break;
                }
            } else if self.at(SyntaxKind::Shr) {
                // Split `>>` into two `>` tokens so enclosing GenericParams / GenericArgs
                // retain their own closing `Gt` token in the CST.
                depth -= 1;
                self.bump_split_shr_gt();
                if depth == 0 {
                    break;
                }
            } else if self.at(SyntaxKind::Lt) {
                depth += 1;
                self.bump();
            } else if matches!(
                self.nth(0),
                SyntaxKind::IntLit | SyntaxKind::UnitLit | SyntaxKind::FloatLit
            ) {
                self.bump();
                let _ = self.eat(SyntaxKind::Comma);
            } else {
                self.parse_type_no_consume_outer_gt(&mut depth);
                let _ = self.eat(SyntaxKind::Comma);
            }
            if self.cursor_state() == guard && depth > 0 {
                break;
            }
        }
        self.finish_node();
    }

    fn parse_type_no_consume_outer_gt(&mut self, depth: &mut usize) {
        if self.at(SyntaxKind::Question) && self.nth(1) == SyntaxKind::Amp {
            self.start_node(SyntaxKind::PtrTermType);
            self.bump();
            self.bump();
            let _ = self.eat(SyntaxKind::KwMut);
            self.parse_type_no_consume_outer_gt(depth);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::Amp) {
            self.start_node(SyntaxKind::RefType);
            self.bump();
            let _ = self.eat(SyntaxKind::KwMut);
            let _ = self.eat(SyntaxKind::Question);
            let _ = self.eat_ctx("res", SyntaxKind::KwRes);
            self.parse_type_no_consume_outer_gt(depth);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::LBracket) {
            self.start_node(SyntaxKind::ArrayType);
            self.bump();
            self.parse_type();
            self.expect(SyntaxKind::Semi);
            self.parse_expr(true);
            self.expect(SyntaxKind::RBracket);
            self.finish_node();
            return;
        }
        self.start_node(SyntaxKind::TypeRef);
        self.parse_path();
        while self.eat(SyntaxKind::Dot) {
            self.bump_ident_or_ctx();
        }
        if self.at(SyntaxKind::Lt) {
            self.start_node(SyntaxKind::GenericArgs);
            self.bump(); // <
            let target_depth = *depth;
            *depth += 1;
            while *depth > target_depth && !self.at_eof() {
                let guard = self.cursor_state();
                if self.at(SyntaxKind::Gt) {
                    *depth -= 1;
                    self.bump();
                    break;
                } else if self.at(SyntaxKind::Shr) {
                    // Split `>>` so this inner GenericArgs consumes only one `>` and leaves the
                    // second `>` for the enclosing GenericArgs or GenericParams.
                    *depth -= 1;
                    self.bump_split_shr_gt();
                    break;
                } else if matches!(
                    self.nth(0),
                    SyntaxKind::IntLit | SyntaxKind::UnitLit | SyntaxKind::FloatLit
                ) {
                    self.bump();
                    let _ = self.eat(SyntaxKind::Comma);
                } else {
                    self.parse_type_no_consume_outer_gt(depth);
                    let _ = self.eat(SyntaxKind::Comma);
                }
                if self.cursor_state() == guard {
                    break;
                }
            }
            self.finish_node();
        }
        self.finish_node();
    }

    // --- Blocks, Statements & Patterns ---

    fn parse_block(&mut self) {
        self.start_node(SyntaxKind::Block);
        if !self.expect(SyntaxKind::LBrace) {
            self.finish_node();
            return;
        }
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.parse_stmt_in_block();
            if self.nt_cursor == guard {
                self.error_and_bump("expected statement");
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_stmt_in_block(&mut self) {
        if self.at_ctx("uniform") && self.nth(1) == SyntaxKind::KwLet {
            self.start_node(SyntaxKind::UniformLetStmt);
            self.bump_as(SyntaxKind::KwUniform);
            self.bump(); // let
            self.parse_pattern();
            if self.eat(SyntaxKind::Colon) {
                self.parse_type();
            }
            self.expect(SyntaxKind::Eq);
            self.parse_expr(true);
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwLet) {
            self.start_node(SyntaxKind::LetStmt);
            self.bump(); // let
            self.parse_pattern();
            if self.eat(SyntaxKind::Colon) {
                self.parse_type();
            }
            self.expect(SyntaxKind::Eq);
            self.parse_expr(true);
            if self.eat(SyntaxKind::KwElse) {
                self.parse_block();
            }
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwReturn) {
            self.start_node(SyntaxKind::ReturnStmt);
            self.bump();
            if !self.at(SyntaxKind::Semi) && !self.at(SyntaxKind::RBrace) {
                self.parse_expr(true);
            }
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwBreak) {
            self.start_node(SyntaxKind::BreakStmt);
            self.bump();
            if !self.at(SyntaxKind::Semi) && !self.at(SyntaxKind::RBrace) {
                self.parse_expr(true);
            }
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwContinue) {
            self.start_node(SyntaxKind::ContinueStmt);
            self.bump();
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at_ctx("abort_if") {
            self.start_node(SyntaxKind::AbortIfStmt);
            self.bump_as(SyntaxKind::KwAbortIf);
            self.parse_expr(false);
            self.parse_block();
            self.finish_node();
            return;
        }
        if self.at_ctx("race") && self.nth(1) == SyntaxKind::LBrace {
            self.start_node(SyntaxKind::RaceStmt);
            self.bump_as(SyntaxKind::KwRace);
            self.expect(SyntaxKind::LBrace);
            while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
                let guard = self.nt_cursor;
                if self.at_ctx("branch") {
                    self.start_node(SyntaxKind::BranchStmt);
                    self.bump_as(SyntaxKind::KwBranch);
                    self.parse_block();
                    self.finish_node();
                } else {
                    self.error_and_bump("expected `branch` inside `race`");
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RBrace);
            self.finish_node();
            return;
        }
        if self.at_ctx("wait")
            && !matches!(
                self.nth(1),
                SyntaxKind::LParen | SyntaxKind::Dot | SyntaxKind::Colon
            )
        {
            self.start_node(SyntaxKind::WaitStmt);
            self.bump_as(SyntaxKind::KwWait);
            self.parse_expr(true);
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at_ctx("wait_until")
            && !matches!(
                self.nth(1),
                SyntaxKind::LParen | SyntaxKind::Dot | SyntaxKind::Colon
            )
        {
            self.start_node(SyntaxKind::WaitUntilStmt);
            self.bump_as(SyntaxKind::KwWaitUntil);
            self.parse_expr(true);
            self.expect(SyntaxKind::Semi);
            self.finish_node();
            return;
        }
        if self.at_ctx("yield_tick") && self.nth(1) == SyntaxKind::Semi {
            self.start_node(SyntaxKind::YieldTickStmt);
            self.bump_as(SyntaxKind::KwYieldTick);
            self.bump(); // ;
            self.finish_node();
            return;
        }
        if self.at_ctx("atomic") && self.nth(1) == SyntaxKind::LBrace {
            self.start_node(SyntaxKind::AtomicStmt);
            self.bump_as(SyntaxKind::KwAtomic);
            self.parse_block();
            if self.eat_ctx("on_rollback", SyntaxKind::KwOnRollback) {
                self.parse_block();
            }
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwWhile) {
            self.start_node(SyntaxKind::WhileStmt);
            self.bump();
            self.parse_expr(false);
            self.parse_block();
            self.finish_node();
            return;
        }
        if self.at(SyntaxKind::KwLoop) {
            self.start_node(SyntaxKind::LoopStmt);
            self.bump();
            self.parse_block();
            self.finish_node();
            return;
        }

        // Expression statement (or trailing block expression without semicolon).
        let cp = self.checkpoint();
        let starts_block_like = matches!(
            self.nth(0),
            SyntaxKind::KwIf | SyntaxKind::KwFor | SyntaxKind::KwMatch | SyntaxKind::LBrace
        );
        self.parse_expr(true);
        if self.eat(SyntaxKind::Semi) || (starts_block_like && !self.at(SyntaxKind::RBrace)) {
            self.start_node_at(cp, SyntaxKind::ExprStmt);
            self.finish_node();
        }
    }

    fn parse_pattern(&mut self) {
        if self.at(SyntaxKind::LParen) {
            self.start_node(SyntaxKind::TuplePattern);
            self.bump();
            while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.parse_pattern();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RParen);
            self.finish_node();
            return;
        }
        if self.at_ctx("_") {
            self.start_node(SyntaxKind::WildcardPattern);
            self.bump();
            self.finish_node();
            return;
        }
        if matches!(
            self.nth(0),
            SyntaxKind::IntLit
                | SyntaxKind::FloatLit
                | SyntaxKind::UnitLit
                | SyntaxKind::StringLit
                | SyntaxKind::CharLit
                | SyntaxKind::KwTrue
                | SyntaxKind::KwFalse
        ) || (self.at(SyntaxKind::Minus)
            && matches!(
                self.nth(1),
                SyntaxKind::IntLit | SyntaxKind::FloatLit | SyntaxKind::UnitLit
            ))
        {
            self.start_node(SyntaxKind::Pattern);
            let _ = self.eat(SyntaxKind::Minus);
            self.bump();
            self.finish_node();
            return;
        }
        let cp = self.checkpoint();
        let _ = self.eat(SyntaxKind::KwMut);
        self.parse_path();
        if self.at(SyntaxKind::LParen) {
            self.start_node_at(cp, SyntaxKind::TupleStructPattern);
            self.bump();
            while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.parse_pattern();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RParen);
            self.finish_node();
        } else {
            self.start_node_at(cp, SyntaxKind::Pattern);
            self.finish_node();
        }
    }

    // --- Pratt Expression Parser ---

    fn parse_expr(&mut self, allow_struct_lit: bool) {
        self.parse_expr_bp(0, allow_struct_lit);
    }

    fn parse_expr_bp(&mut self, min_bp: u8, allow_struct_lit: bool) {
        let cp = self.checkpoint();
        self.parse_prefix_or_atom(allow_struct_lit);
        self.parse_postfix_loop(cp, allow_struct_lit);

        loop {
            let op = self.nth(0);
            if op == SyntaxKind::KwAs {
                let l_bp = 23;
                if l_bp < min_bp {
                    break;
                }
                self.bump(); // as
                self.parse_type();
                self.start_node_at(cp, SyntaxKind::CastExpr);
                self.finish_node();
                continue;
            }
            let Some((l_bp, r_bp)) = infix_binding_power(op) else {
                break;
            };
            if l_bp < min_bp {
                break;
            }
            self.bump(); // op
            self.parse_expr_bp(r_bp, allow_struct_lit);
            self.start_node_at(cp, SyntaxKind::BinaryExpr);
            self.finish_node();
        }
    }

    fn parse_prefix_or_atom(&mut self, allow_struct_lit: bool) {
        match self.nth(0) {
            SyntaxKind::Minus | SyntaxKind::Bang | SyntaxKind::Tilde | SyntaxKind::Amp => {
                self.start_node(SyntaxKind::PrefixExpr);
                self.bump();
                let _ = self.eat(SyntaxKind::KwMut);
                self.parse_expr_bp(25, allow_struct_lit);
                self.finish_node();
            }
            SyntaxKind::IntLit
            | SyntaxKind::FloatLit
            | SyntaxKind::UnitLit
            | SyntaxKind::StringLit
            | SyntaxKind::CharLit
            | SyntaxKind::KwTrue
            | SyntaxKind::KwFalse => {
                self.start_node(SyntaxKind::LiteralExpr);
                self.bump();
                self.finish_node();
            }
            SyntaxKind::LParen => {
                let paren_cp = self.checkpoint();
                self.bump();
                if self.eat(SyntaxKind::RParen) {
                    self.start_node_at(paren_cp, SyntaxKind::TupleExpr);
                    self.finish_node();
                    return;
                }
                self.parse_expr(true);
                if self.eat(SyntaxKind::Comma) {
                    while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                        let guard = self.nt_cursor;
                        self.parse_expr(true);
                        if !self.eat(SyntaxKind::Comma) {
                            break;
                        }
                        if self.nt_cursor == guard {
                            break;
                        }
                    }
                    self.expect(SyntaxKind::RParen);
                    self.start_node_at(paren_cp, SyntaxKind::TupleExpr);
                    self.finish_node();
                    return;
                }
                self.expect(SyntaxKind::RParen);
                self.start_node_at(paren_cp, SyntaxKind::ParenExpr);
                self.finish_node();
            }
            SyntaxKind::LBracket => {
                self.start_node(SyntaxKind::ArrayLitExpr);
                self.bump();
                while !self.at(SyntaxKind::RBracket) && !self.at_eof() {
                    let guard = self.nt_cursor;
                    self.parse_expr(true);
                    if !self.eat(SyntaxKind::Comma) {
                        break;
                    }
                    if self.nt_cursor == guard {
                        break;
                    }
                }
                self.expect(SyntaxKind::RBracket);
                self.finish_node();
            }
            SyntaxKind::KwIf => self.parse_if_expr(),
            SyntaxKind::KwMatch => self.parse_match_expr(),
            SyntaxKind::KwFor => self.parse_for_expr(),
            SyntaxKind::LBrace => {
                if self.looks_like_record_lit() {
                    self.parse_record_or_field_init_braced();
                } else if self.looks_like_bundle_lit() {
                    self.start_node(SyntaxKind::BundleLitExpr);
                    self.bump();
                    self.parse_comp_init_list(SyntaxKind::RBrace);
                    self.expect(SyntaxKind::RBrace);
                    self.finish_node();
                } else {
                    self.parse_block();
                }
            }
            SyntaxKind::Ident
                if self.at_ctx("spawn")
                    && (self.nth(1) == SyntaxKind::LBrace || self.nth(1) == SyntaxKind::At) =>
            {
                self.start_node(SyntaxKind::SpawnExpr);
                self.bump_as(SyntaxKind::KwSpawn);
                self.parse_attributes();
                self.expect(SyntaxKind::LBrace);
                self.parse_comp_init_list(SyntaxKind::RBrace);
                self.expect(SyntaxKind::RBrace);
                self.finish_node();
            }
            SyntaxKind::Ident
                if self.at_ctx("spawn_batch") && self.nth(1) == SyntaxKind::LParen =>
            {
                self.start_node(SyntaxKind::SpawnBatchExpr);
                self.bump_as(SyntaxKind::KwSpawnBatch);
                self.parse_arg_list();
                self.expect(SyntaxKind::Pipe);
                self.parse_pattern();
                self.expect(SyntaxKind::Pipe);
                self.parse_block();
                self.finish_node();
            }
            SyntaxKind::Ident if self.at_ctx("despawn_all") && self.nth(1) == SyntaxKind::Lt => {
                self.start_node(SyntaxKind::DespawnAllExpr);
                self.bump_as(SyntaxKind::KwDespawnAll);
                self.parse_generic_args();
                self.parse_arg_list();
                self.finish_node();
            }
            SyntaxKind::Ident
                if self.at_ctx("insert")
                    && (self.nth(1) == SyntaxKind::At || self.nth(1) == SyntaxKind::LParen) =>
            {
                self.start_node(SyntaxKind::InsertExpr);
                self.bump_as(SyntaxKind::KwInsert);
                while self.at(SyntaxKind::At) {
                    self.start_node(SyntaxKind::Attribute);
                    self.bump(); // @
                    self.bump_ident_or_ctx();
                    self.finish_node();
                }
                self.parse_arg_list();
                self.finish_node();
            }
            SyntaxKind::Ident if self.at_ctx("remove") && self.nth(1) == SyntaxKind::Lt => {
                self.start_node(SyntaxKind::RemoveExpr);
                self.bump_as(SyntaxKind::KwRemove);
                self.parse_generic_args();
                self.parse_arg_list();
                self.finish_node();
            }
            SyntaxKind::Ident | SyntaxKind::KwSelfLower | SyntaxKind::KwSelfUpper => {
                self.start_node(SyntaxKind::PathExpr);
                self.parse_path();
                self.finish_node();
            }
            _ if is_keyword_usable_as_member(self.nth(0)) => {
                self.start_node(SyntaxKind::PathExpr);
                self.parse_path();
                self.finish_node();
            }
            _ => {
                self.error_and_bump(format!("expected expression, found `{}`", self.nth_text(0)));
            }
        }
    }

    fn parse_postfix_loop(&mut self, cp: rowan::Checkpoint, allow_struct_lit: bool) {
        loop {
            if self.at(SyntaxKind::Dot) {
                self.bump();
                if self.at_member_ident() {
                    self.bump_as(SyntaxKind::Ident);
                } else {
                    self.error_and_bump("expected field or method name after `.`");
                }
                if self.at(SyntaxKind::Lt) && self.looks_like_generic_call_args() {
                    self.parse_generic_args();
                    self.parse_arg_list();
                    self.start_node_at(cp, SyntaxKind::PostfixCallExpr);
                    self.finish_node();
                } else if self.at(SyntaxKind::LParen) {
                    self.parse_arg_list();
                    self.start_node_at(cp, SyntaxKind::PostfixCallExpr);
                    self.finish_node();
                } else {
                    self.start_node_at(cp, SyntaxKind::FieldExpr);
                    self.finish_node();
                }
            } else if self.at(SyntaxKind::LParen) {
                let is_query_call = self.is_query_callee_at(cp);
                if is_query_call {
                    self.parse_query_arg_list();
                } else {
                    self.parse_arg_list();
                }
                self.start_node_at(cp, SyntaxKind::PostfixCallExpr);
                self.finish_node();
            } else if self.at(SyntaxKind::Lt) && self.looks_like_generic_call_args() {
                self.parse_generic_args();
                self.parse_arg_list();
                self.start_node_at(cp, SyntaxKind::PostfixCallExpr);
                self.finish_node();
            } else if self.at(SyntaxKind::LBracket) {
                self.bump();
                self.parse_expr(true);
                self.expect(SyntaxKind::RBracket);
                self.start_node_at(cp, SyntaxKind::IndexExpr);
                self.finish_node();
            } else if allow_struct_lit
                && self.at(SyntaxKind::LBrace)
                && self.looks_like_struct_or_empty_lit()
            {
                self.bump();
                self.parse_field_init_list(SyntaxKind::RBrace);
                self.expect(SyntaxKind::RBrace);
                self.start_node_at(cp, SyntaxKind::StructLitExpr);
                self.finish_node();
            } else if self.eat(SyntaxKind::Question) {
                self.start_node_at(cp, SyntaxKind::PostfixCallExpr);
                self.finish_node();
            } else {
                break;
            }
        }
    }

    fn is_query_callee_at(&self, _cp: rowan::Checkpoint) -> bool {
        // Look at the immediately preceding non-trivia token before `(`.
        if self.nt_cursor == 0 {
            return false;
        }
        let prev = self.tokens[self.non_trivia[self.nt_cursor - 1]].text;
        matches!(prev, "query" | "query_one")
    }

    fn parse_query_arg_list(&mut self) {
        self.start_node(SyntaxKind::ArgList);
        self.bump(); // (
        self.parse_proj_term_list(SyntaxKind::RParen);
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_arg_list(&mut self) {
        self.start_node(SyntaxKind::ArgList);
        self.expect(SyntaxKind::LParen);
        while !self.at(SyntaxKind::RParen) && !self.at_eof() {
            let guard = self.nt_cursor;
            if self.at_ident_like() && self.nth(1) == SyntaxKind::Colon {
                self.start_node(SyntaxKind::FieldInit);
                self.bump();
                self.bump();
                self.parse_expr(true);
                self.finish_node();
            } else {
                self.parse_expr(true);
            }
            if !self.eat(SyntaxKind::Comma) {
                break;
            }
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RParen);
        self.finish_node();
    }

    fn parse_if_expr(&mut self) {
        self.start_node(SyntaxKind::IfExpr);
        self.bump(); // if
        if self.eat(SyntaxKind::KwLet) {
            self.parse_pattern();
            self.expect(SyntaxKind::Eq);
            self.parse_expr(false);
        } else {
            self.parse_expr(false);
        }
        self.parse_block();
        if self.eat(SyntaxKind::KwElse) {
            if self.at(SyntaxKind::KwIf) {
                self.parse_if_expr();
            } else {
                self.parse_block();
            }
        }
        self.finish_node();
    }

    fn parse_match_expr(&mut self) {
        self.start_node(SyntaxKind::MatchExpr);
        self.bump(); // match
        self.parse_expr(false);
        self.expect(SyntaxKind::LBrace);
        while !self.at(SyntaxKind::RBrace) && !self.at_eof() {
            let guard = self.nt_cursor;
            self.start_node(SyntaxKind::MatchArm);
            self.parse_pattern();
            if self.eat(SyntaxKind::KwIf) {
                self.parse_expr(false);
            }
            self.expect(SyntaxKind::FatArrow);
            self.parse_expr(true);
            let _ = self.eat(SyntaxKind::Comma);
            self.finish_node();
            if self.nt_cursor == guard {
                break;
            }
        }
        self.expect(SyntaxKind::RBrace);
        self.finish_node();
    }

    fn parse_for_expr(&mut self) {
        self.start_node(SyntaxKind::ForExpr);
        self.bump(); // for
        self.parse_pattern();
        self.expect(SyntaxKind::KwIn);
        self.parse_expr(false);
        if self.at_ctx("reduce") {
            self.start_node(SyntaxKind::ReduceClause);
            self.bump_as(SyntaxKind::KwReduce);
            self.expect(SyntaxKind::LParen);
            while !self.at(SyntaxKind::RParen) && !self.at_eof() {
                let guard = self.nt_cursor;
                self.start_node(SyntaxKind::ReduceEntry);
                self.bump_ident_or_ctx();
                self.expect(SyntaxKind::Colon);
                self.parse_expr(true);
                self.finish_node();
                if !self.eat(SyntaxKind::Comma) {
                    break;
                }
                if self.nt_cursor == guard {
                    break;
                }
            }
            self.expect(SyntaxKind::RParen);
            self.finish_node();
        } else {
            self.parse_block();
        }
        self.finish_node();
    }

    // --- Speculative lookahead helpers ---

    fn looks_like_generic_call_args(&self) -> bool {
        if self.nth(0) != SyntaxKind::Lt {
            return false;
        }
        let mut depth: usize = 0;
        let mut off = 0usize;
        while self.nt_cursor + off < self.non_trivia.len() {
            let k = self.nth(off);
            match k {
                SyntaxKind::Lt => depth += 1,
                SyntaxKind::Gt => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return self.nth(off + 1) == SyntaxKind::LParen;
                    }
                }
                SyntaxKind::Shr => {
                    if depth == 2 {
                        return self.nth(off + 1) == SyntaxKind::LParen;
                    }
                    if depth < 2 {
                        return false;
                    }
                    depth -= 2;
                }
                SyntaxKind::Ident
                | SyntaxKind::ColonColon
                | SyntaxKind::Comma
                | SyntaxKind::Semi
                | SyntaxKind::LBracket
                | SyntaxKind::RBracket
                | SyntaxKind::Amp
                | SyntaxKind::KwMut
                | SyntaxKind::Question
                | SyntaxKind::IntLit
                | SyntaxKind::Dot => {}
                _ => return false,
            }
            off += 1;
        }
        false
    }

    fn looks_like_struct_or_empty_lit(&self) -> bool {
        if self.nth(0) != SyntaxKind::LBrace {
            return false;
        }
        if self.nth(1) == SyntaxKind::RBrace {
            return true;
        }
        self.nth(1) == SyntaxKind::Ident && self.nth(2) == SyntaxKind::Colon
    }

    fn looks_like_record_lit(&self) -> bool {
        self.nth(0) == SyntaxKind::LBrace
            && self.nth(1) == SyntaxKind::Ident
            && self.nth(2) == SyntaxKind::Colon
    }

    fn looks_like_bundle_lit(&self) -> bool {
        if self.nth(0) != SyntaxKind::LBrace {
            return false;
        }
        let mut off = 1usize;
        if self.nth(off) != SyntaxKind::Ident {
            return false;
        }
        off += 1;
        while self.nth(off) == SyntaxKind::ColonColon && self.nth(off + 1) == SyntaxKind::Ident {
            off += 2;
        }
        matches!(self.nth(off), SyntaxKind::LBrace | SyntaxKind::Comma)
    }
}

fn infix_binding_power(op: SyntaxKind) -> Option<(u8, u8)> {
    let bp = match op {
        SyntaxKind::Eq
        | SyntaxKind::PlusEq
        | SyntaxKind::MinusEq
        | SyntaxKind::StarEq
        | SyntaxKind::SlashEq
        | SyntaxKind::PercentEq
        | SyntaxKind::AmpEq
        | SyntaxKind::PipeEq
        | SyntaxKind::CaretEq
        | SyntaxKind::ShlEq
        | SyntaxKind::ShrEq => (2, 1),
        SyntaxKind::DotDot | SyntaxKind::DotDotEq => (3, 4),
        SyntaxKind::PipePipe => (5, 6),
        SyntaxKind::AmpAmp => (7, 8),
        SyntaxKind::EqEq
        | SyntaxKind::Ne
        | SyntaxKind::Lt
        | SyntaxKind::Le
        | SyntaxKind::Gt
        | SyntaxKind::Ge => (9, 10),
        SyntaxKind::Pipe => (11, 12),
        SyntaxKind::Caret => (13, 14),
        SyntaxKind::Amp => (15, 16),
        SyntaxKind::Shl | SyntaxKind::Shr => (17, 18),
        SyntaxKind::Plus | SyntaxKind::Minus => (19, 20),
        SyntaxKind::Star | SyntaxKind::Slash | SyntaxKind::Percent => (21, 22),
        _ => return None,
    };
    Some(bp)
}

fn is_keyword_usable_as_member(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::KwZone
            | SyntaxKind::KwRpc
            | SyntaxKind::KwBy
            | SyntaxKind::KwOver
            | SyntaxKind::KwKey
            | SyntaxKind::KwCache
            | SyntaxKind::KwWhere
            | SyntaxKind::KwHot
            | SyntaxKind::KwCold
            | SyntaxKind::KwRequire
            | SyntaxKind::KwWindow
            | SyntaxKind::KwAt
            | SyntaxKind::KwOn
            | SyntaxKind::KwUsing
            | SyntaxKind::KwInitial
            | SyntaxKind::KwState
            | SyntaxKind::KwOnEnter
            | SyntaxKind::KwOnTick
            | SyntaxKind::KwOnExit
            | SyntaxKind::KwTo
            | SyntaxKind::KwWhen
            | SyntaxKind::KwEffects
            | SyntaxKind::KwFrom
            | SyntaxKind::KwRunIf
            | SyntaxKind::KwBefore
            | SyntaxKind::KwAfter
            | SyntaxKind::KwSeq
            | SyntaxKind::KwSeqWeak
            | SyntaxKind::KwPar
            | SyntaxKind::KwSet
            | SyntaxKind::KwRes
            | SyntaxKind::KwStreamIn
            | SyntaxKind::KwUniform
            | SyntaxKind::KwReduce
            | SyntaxKind::KwAbortIf
            | SyntaxKind::KwRace
            | SyntaxKind::KwBranch
            | SyntaxKind::KwWait
            | SyntaxKind::KwWaitUntil
            | SyntaxKind::KwYieldTick
            | SyntaxKind::KwAtomic
            | SyntaxKind::KwOnRollback
            | SyntaxKind::KwSpawn
            | SyntaxKind::KwSpawnBatch
            | SyntaxKind::KwDespawnAll
            | SyntaxKind::KwInsert
            | SyntaxKind::KwRemove
    )
}

// Keep StrataLanguage referenced cleanly for downstream AST consumers.
#[allow(dead_code)]
type _DocLangRef = StrataLanguage;

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::SyntaxKind;

    /// Verifies Pratt operator precedence binds `*` tighter than `+`, unary `-` tighter than `*`,
    /// and comparison operators tighter than `&&`.
    #[test]
    fn pratt_operator_precedence_and_cst_roundtrip() {
        let src = "fn f(a: f32, b: f32, c: f32) -> bool { return a + -b * c > 0.0 && a != c; }";
        let p = parse(src);
        assert!(p.errors().is_empty(), "{:?}", p.errors());
        assert_eq!(p.syntax().text().to_string(), src);
        let bins: Vec<_> = p
            .syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::BinaryExpr)
            .collect();
        assert_eq!(bins.len(), 5);
    }

    /// Verifies parser error recovery preserves every input byte and continues past malformed items.
    #[test]
    fn error_recovery_is_lossless_and_parses_following_decl() {
        let src = "component Broken { x: }\ncomponent Good { y: f32 = 1.0 }\n";
        let p = parse(src);
        assert!(!p.errors().is_empty());
        assert_eq!(p.syntax().text().to_string(), src);
        let comp_count = p
            .syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::ComponentDecl)
            .count();
        assert_eq!(comp_count, 2);
    }

    /// Verifies `RpcDecl` parses with attributes, fields, marker form, and contextual `rpc` usage.
    #[test]
    fn rpc_decl_parses_with_attrs_fields_and_contextual_ident() {
        let src = r#"
@net_rpc(direction = client_to_server, reliability = reliable)
@authority(client)
@node_group("net")
rpc MoveInput {
    @quantize(min = -1.0, max = 1.0, bits = 12)
    dx: f32,
    dy: f32,
    seq: u32,
}

rpc Ping {}
rpc Marker;

struct Carrier { rpc: u32 }
fn use_rpc(rpc: u32) -> u32 {
    let x = rpc;
    return x;
}
"#;
        let p = parse(src);
        assert!(p.errors().is_empty(), "{:?}", p.errors());
        assert_eq!(p.syntax().text().to_string(), src);
        let rpc_count = p
            .syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::RpcDecl)
            .count();
        assert_eq!(rpc_count, 3);
    }

    /// Verifies `NetSimTestDecl` parses network parameters and simulation body statements.
    #[test]
    fn net_sim_test_decl_parses_options_and_network_statements() {
        let src = r#"
net_sim_test "reconciles_under_loss"(latency: 50ms, jitter: 10ms, loss: 0.05, seed: 42, clients: 2) {
    clients(2);
    spawn_client(0);
    send_rpc(0, MoveInput { dx: 1.0, dy: 0.0, seq: 1 });
    send_rpc(0, Ping {});
    server_step(1);
    client_step(0, 1);
    step_net(5);
    server_spawn(Pos3D { xyz: vec3(0.0, 0.0, 0.0) });
    client_spawn(0, Pos3D { xyz: vec3(0.0, 0.0, 0.0) });
    let s = server_res<SimClock>();
    let c = client_res<SimClock>(0);
    server_query(pos: &Pos3D);
    client_query(0, pos: &Pos3D);
    assert_converged(0, 0.01);
    assert(true);
    assert_eq(1, 1);
    assert_ne(1, 2);
}

net_sim_test "defaults" {
    step_net(1);
}

net_sim_test "empty_opts"() {
    step_net(1);
}
"#;
        let p = parse(src);
        assert!(p.errors().is_empty(), "{:?}", p.errors());
        assert_eq!(p.syntax().text().to_string(), src);
        let net_tests: Vec<_> = p
            .syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::NetSimTestDecl)
            .collect();
        assert_eq!(net_tests.len(), 3);
    }

    /// Verifies malformed `rpc` and `net_sim_test` declarations recover losslessly.
    #[test]
    fn malformed_rpc_and_net_sim_test_recover_losslessly() {
        let src = "net_sim_test \"bad\"(latency: ) { step_net(1); }\nrpc Broken { x: }\ncomponent Ok { x: f32 }\n";
        let p = parse(src);
        assert!(!p.errors().is_empty());
        assert_eq!(p.syntax().text().to_string(), src);
        let comp_count = p
            .syntax()
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::ComponentDecl)
            .count();
        assert_eq!(comp_count, 1);
    }

    /// Verifies `>>` splits cleanly across `GenericArgs` / `GenericParams` and nested
    /// `GenericArgs` boundaries while preserving lossless CST text and operator contrasts.
    #[test]
    fn generic_params_and_args_split_shr_losslessly() {
        for src in [
            "struct S<T: Box<u32>> { x: T }\n",
            "struct S<T: Box<u32> > { x: T }\n",
            "struct S<T: Box<u32>, U: Box<u32>> { x: T, y: U }\n",
            "fn f<T: Box<Box<u32>>>(x: T) {}\n",
            "struct S<T: Box<Box<Box<u32>>>> { x: T }\n",
            "fn f() { let x = a < b >> (c); }\n",
        ] {
            let p = parse(src);
            assert!(
                p.errors().is_empty(),
                "errors for {src:?}: {:?}",
                p.errors()
            );
            assert_eq!(p.syntax().text().to_string(), src);
            for node in p.syntax().descendants().filter(|n| {
                matches!(
                    n.kind(),
                    SyntaxKind::GenericParams | SyntaxKind::GenericArgs
                )
            }) {
                assert_eq!(
                    node.last_token().map(|t| t.kind()),
                    Some(SyntaxKind::Gt),
                    "expected closing Gt on {:?} in {src:?}",
                    node.kind()
                );
            }
        }

        // Malformed extra `>` after `>>` must recover losslessly without panicking.
        for bad in [
            "struct S<T: Box<u32>>> { x: T }\n",
            "fn f() { let x: Box<u32>>; }\n",
        ] {
            let p = parse(bad);
            assert!(!p.ok(), "expected error on {bad:?}");
            assert_eq!(p.syntax().text().to_string(), bad);
        }
    }
}
