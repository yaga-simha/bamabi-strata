//! Direct `rowan` CST -> typed HIR lowering for Strata v2.0 (`strata_sema`).
//!
//! Lowers statements, expressions, queries, `spawn`, `spawn_batch`, `despawn_all`, `insert`,
//! `remove`, `trigger`, `emit`, `atomic`/`on_rollback`, `timeline`, `task`, `fsm`, `migrate`,
//! `table`, `curve`, `const`, `object`, `sim_test`, `fn`, `schedule`, and `FieldDecl` defaults
//! directly from lossless CST nodes without raw-string splitting or regex heuristics.

use crate::access::{QueryAccessDesc, TermAccessMode};
use crate::hir::{
    HirAssignOp, HirAtomic, HirBinOp, HirCall, HirCompInit, HirExpr, HirFor, HirForIter,
    HirFsmState, HirFsmTransition, HirLValue, HirMatch, HirMatchArm, HirParam, HirParamKind,
    HirPattern, HirQuery, HirQueryTerm, HirReduceEntry, HirSpawn, HirStmt, HirUnOp,
};
use crate::layout::{EnumDef, SolvedLayout};
use crate::types::{Ty, UnitDim, parse_type_node};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{self, AstNode};
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode, SyntaxToken};

/// Module-wide symbol and layout lookup context used while lowering CST nodes to typed HIR.
#[derive(Debug, Clone)]
pub(crate) struct LowerEnv<'a> {
    pub(crate) module_path: &'a str,
    pub(crate) layouts: &'a IndexMap<String, SolvedLayout>,
    pub(crate) field_to_stratum: &'a HashMap<String, String>,
    pub(crate) enums: &'a IndexMap<String, EnumDef>,
    pub(crate) const_tys: HashMap<String, Ty>,
    pub(crate) table_fields: HashMap<String, Vec<(String, Ty)>>,
    pub(crate) curve_ret_tys: HashMap<String, Ty>,
    pub(crate) fn_ret_tys: HashMap<String, Ty>,
    pub(crate) objects: HashSet<String>,
    pub(crate) sparse_components: HashSet<String>,
}

impl<'a> LowerEnv<'a> {
    pub(crate) fn find_layout(&self, name: &str) -> Option<&'a SolvedLayout> {
        let canon = format!("{}::{name}", self.module_path);
        self.layouts
            .get(&canon)
            .or_else(|| self.layouts.get(name))
            .or_else(|| {
                self.layouts
                    .iter()
                    .find(|(k, _)| k.rsplit("::").next() == Some(name) || *k == name)
                    .map(|(_, v)| v)
            })
    }

    pub(crate) fn resolve_canonical_component(&self, storage_key: &str) -> String {
        if let Some(l) = self.find_layout(storage_key) {
            return l.canonical_name.clone();
        }
        if let Some((comp, stratum)) = storage_key.split_once("::") {
            let key = if stratum == "hot" {
                comp.to_owned()
            } else {
                format!("{comp}__{stratum}")
            };
            if let Some(l) = self.find_layout(&key) {
                return l.canonical_name.clone();
            }
        }
        format!("{}::{storage_key}", self.module_path)
    }

    pub(crate) fn is_sparse(&self, storage_key: &str) -> bool {
        let short = storage_key.split("::").next().unwrap_or(storage_key);
        if self.sparse_components.contains(short) || self.sparse_components.contains(storage_key) {
            return true;
        }
        self.find_layout(storage_key)
            .is_some_and(|l| (l.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0)
    }
}

/// Variable binding visible in lexical scope during CST lowering.
#[derive(Debug, Clone)]
pub(crate) enum ScopeBinding {
    Var(Ty),
    QueryRow {
        terms: Vec<HirQueryTerm>,
    },
    SpatialCandidate,
    Trigger {
        event: String,
        target_comp: Option<String>,
    },
    Resource {
        canonical: String,
        ty: Ty,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ScopeStack {
    frames: Vec<HashMap<String, ScopeBinding>>,
}

impl ScopeStack {
    pub(crate) fn new() -> Self {
        Self {
            frames: vec![HashMap::new()],
        }
    }

    pub(crate) fn push(&mut self) {
        self.frames.push(HashMap::new());
    }

    pub(crate) fn pop(&mut self) {
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }

    pub(crate) fn insert(&mut self, name: impl Into<String>, binding: ScopeBinding) {
        if let Some(top) = self.frames.last_mut() {
            top.insert(name.into(), binding);
        }
    }

    pub(crate) fn get(&self, name: &str) -> Option<&ScopeBinding> {
        for frame in self.frames.iter().rev() {
            if let Some(b) = frame.get(name) {
                return Some(b);
            }
        }
        None
    }
}

/// Parses an integer or float or unit-suffixed literal token into [`HirExpr`], normalizing unit
/// literals to SI base units (`_ms` -> `* 0.001`, `_deg` -> `* PI / 180.0`, others -> `* 1.0`).
pub(crate) fn lower_literal_token(tok: &SyntaxToken) -> Option<HirExpr> {
    let text = tok.text();
    match tok.kind() {
        SyntaxKind::KwTrue => Some(HirExpr::BoolLit(true)),
        SyntaxKind::KwFalse => Some(HirExpr::BoolLit(false)),
        SyntaxKind::StringLit => {
            let inner = text
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(text);
            Some(HirExpr::StringLit(unescape_str(inner)))
        }
        SyntaxKind::CharLit => {
            let inner = text
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(text);
            let ch = unescape_str(inner).chars().next().unwrap_or('\0');
            Some(HirExpr::CharLit(ch))
        }
        SyntaxKind::UnitLit => {
            let (stem, factor) = split_unit_literal(text)?;
            let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
            let raw = cleaned.parse::<f64>().ok()?;
            let ty = Ty::unit_from_literal(text).unwrap_or(Ty::F32);
            Some(HirExpr::FloatLit {
                value: raw * factor,
                ty,
            })
        }
        SyntaxKind::FloatLit => {
            let (stem, ty) = if let Some(s) = text.strip_suffix("_f64") {
                (s, Ty::F64)
            } else if let Some(s) = text.strip_suffix("_f32") {
                (s, Ty::F32)
            } else {
                (text, Ty::F32)
            };
            let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
            let value = cleaned.parse::<f64>().ok()?;
            Some(HirExpr::FloatLit { value, ty })
        }
        SyntaxKind::IntLit => {
            let (stem, suffix_ty, is_float) = split_int_suffix(text);
            let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
            if is_float {
                let value = parse_radix_u128(&cleaned)? as f64;
                return Some(HirExpr::FloatLit {
                    value,
                    ty: suffix_ty,
                });
            }
            let raw = parse_radix_u128(&cleaned)?;
            let value = i64::try_from(raw).unwrap_or(raw as i64);
            Some(HirExpr::IntLit {
                value,
                ty: suffix_ty,
            })
        }
        _ => None,
    }
}

fn split_unit_literal(text: &str) -> Option<(&str, f64)> {
    const UNITS: &[(&str, f64)] = &[
        ("_frames", 1.0),
        ("_meters", 1.0),
        ("_mps2", 1.0),
        ("_mps", 1.0),
        ("_sec", 1.0),
        ("_rad", 1.0),
        ("_deg", std::f64::consts::PI / 180.0),
        ("_ms", 0.001),
        ("_hz", 1.0),
        ("_s", 1.0),
        ("_m", 1.0),
        ("_f", 1.0),
    ];
    for &(suf, factor) in UNITS {
        if let Some(stem) = text.strip_suffix(suf) {
            return Some((stem, factor));
        }
    }
    None
}

fn split_int_suffix(text: &str) -> (&str, Ty, bool) {
    const INT_SUFFIXES: &[(&str, Ty, bool)] = &[
        ("_u16", Ty::U16, false),
        ("_u32", Ty::U32, false),
        ("_u64", Ty::U64, false),
        ("_i16", Ty::I16, false),
        ("_i32", Ty::I32, false),
        ("_i64", Ty::I64, false),
        ("_f32", Ty::F32, true),
        ("_f64", Ty::F64, true),
        ("_u8", Ty::U8, false),
        ("_i8", Ty::I8, false),
    ];
    for (suf, ty, is_f) in INT_SUFFIXES {
        if let Some(stem) = text.strip_suffix(suf) {
            return (stem, ty.clone(), *is_f);
        }
    }
    (text, Ty::I32, false)
}

fn parse_radix_u128(s: &str) -> Option<u128> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        u128::from_str_radix(bin, 2).ok()
    } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        u128::from_str_radix(oct, 8).ok()
    } else {
        s.parse::<u128>().ok()
    }
}

fn unescape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('0') => out.push('\0'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Lowers `ParamList` (`fn` / `task` params) directly from CST.
pub(crate) fn lower_param_list(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
) -> Vec<HirParam> {
    let Some(pl) = ast::child::<ast::ParamList>(node) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in ast::children::<ast::Param>(pl.syntax()) {
        let name = ast::first_ident(p.syntax())
            .map_or_else(|| "param".to_owned(), |t| t.text().to_owned());
        let type_node = p.syntax().children().find(|c| is_type_node(c.kind()));
        let (kind, ty, trigger_target) = type_node.as_ref().map_or(
            (HirParamKind::Value, Ty::Unknown, None),
            classify_param_type,
        );
        let default = p
            .syntax()
            .children()
            .find(|c| is_expr_node(c.kind()))
            .map(|e| lower_expr(&e, env, scope, &[]));
        scope.insert(name.clone(), ScopeBinding::Var(ty.clone()));
        out.push(HirParam {
            name,
            ty,
            kind,
            trigger_target,
            default,
        });
    }
    out
}

/// Lowers `SysParamList` (`sys`, `obs`, `fsm`, `task using (...)`) directly from CST.
pub(crate) fn lower_sys_param_list(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
) -> Vec<HirParam> {
    let Some(spl) = ast::child::<ast::SysParamList>(node) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sp in ast::children::<ast::SysParam>(spl.syntax()) {
        let name = ast::first_ident(sp.syntax())
            .map_or_else(|| "param".to_owned(), |t| t.text().to_owned());
        let type_node = sp.syntax().children().find(|c| is_type_node(c.kind()));
        let (kind, ty, trigger_target) = type_node.as_ref().map_or(
            (HirParamKind::Value, Ty::Unknown, None),
            classify_param_type,
        );

        match kind {
            HirParamKind::Trigger => {
                let event = match &ty {
                    Ty::Named(e) => e.clone(),
                    _ => "Event".to_owned(),
                };
                scope.insert(
                    name.clone(),
                    ScopeBinding::Trigger {
                        event,
                        target_comp: trigger_target.clone(),
                    },
                );
            }
            HirParamKind::ResRead | HirParamKind::ResWrite => {
                let canonical = match &ty {
                    Ty::Named(r) => env.resolve_canonical_component(r),
                    _ => String::new(),
                };
                scope.insert(
                    name.clone(),
                    ScopeBinding::Resource {
                        canonical,
                        ty: ty.clone(),
                    },
                );
            }
            _ => {
                scope.insert(name.clone(), ScopeBinding::Var(ty.clone()));
            }
        }

        out.push(HirParam {
            name,
            ty,
            kind,
            trigger_target,
            default: None,
        });
    }
    out
}

pub(crate) fn classify_param_type(node: &SyntaxNode) -> (HirParamKind, Ty, Option<String>) {
    match node.kind() {
        SyntaxKind::RefType => {
            let has_mut = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwMut);
            let has_res = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwRes);
            if let Some(inner) = node.children().find(|c| is_type_node(c.kind())) {
                if inner.kind() == SyntaxKind::TypeRef && typeref_base_name(&inner) == "Trigger" {
                    let args = typeref_generic_type_names(&inner);
                    let ev = args.first().cloned().unwrap_or_else(|| "Event".to_owned());
                    let tgt = args.get(1).cloned();
                    return (HirParamKind::Trigger, Ty::Named(ev), tgt);
                }
                let inner_ty = parse_type_node(&inner);
                let kind = if has_res {
                    if has_mut {
                        HirParamKind::ResWrite
                    } else {
                        HirParamKind::ResRead
                    }
                } else if has_mut {
                    HirParamKind::RefMut
                } else {
                    HirParamKind::Ref
                };
                return (kind, inner_ty, None);
            }
            (HirParamKind::Ref, Ty::Unknown, None)
        }
        SyntaxKind::TypeRef => {
            let is_stream = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwStreamIn);
            if is_stream {
                let args = typeref_generic_type_names(node);
                let inner = args.first().cloned().unwrap_or_else(|| "Msg".to_owned());
                return (HirParamKind::StreamIn, Ty::Named(inner), None);
            }
            if typeref_base_name(node) == "Trigger" {
                let args = typeref_generic_type_names(node);
                let ev = args.first().cloned().unwrap_or_else(|| "Event".to_owned());
                let tgt = args.get(1).cloned();
                return (HirParamKind::Trigger, Ty::Named(ev), tgt);
            }
            (HirParamKind::Value, parse_type_node(node), None)
        }
        _ => (HirParamKind::Value, parse_type_node(node), None),
    }
}

fn typeref_base_name(node: &SyntaxNode) -> String {
    node.children()
        .find(|c| c.kind() == SyntaxKind::Path)
        .and_then(ast::Path::cast)
        .map(|p| ast::path_text(&p))
        .unwrap_or_default()
}

fn typeref_generic_type_names(node: &SyntaxNode) -> Vec<String> {
    let Some(ga) = node
        .children()
        .find(|c| c.kind() == SyntaxKind::GenericArgs)
    else {
        return Vec::new();
    };
    ga.children()
        .filter(|c| is_type_node(c.kind()))
        .map(|c| c.text().to_string().trim().to_owned())
        .collect()
}

/// Lowers `ProjTerm` CST node directly (zero string slicing) into [`HirQueryTerm`].
pub(crate) fn lower_proj_term(pt: &SyntaxNode, env: &LowerEnv<'_>) -> Option<HirQueryTerm> {
    let mut alias_opt = None;
    let mut saw_colon = false;
    for tok in direct_tokens(pt) {
        if tok.kind() == SyntaxKind::Ident && !saw_colon {
            alias_opt = Some(tok.text().to_owned());
        } else if tok.kind() == SyntaxKind::Colon {
            saw_colon = true;
            break;
        }
    }
    if !saw_colon {
        alias_opt = None;
    }

    let type_node = pt.children().find(|c| is_type_node(c.kind()))?;
    let (mode, inner_ref) = extract_proj_mode_and_typeref(&type_node);
    let (comp_path, field_name) = if let Some(tr) = inner_ref {
        extract_typeref_comp_and_field(&tr)
    } else {
        (type_node.text().to_string().trim().to_owned(), None)
    };

    let storage_key = if let Some(ref f) = field_name {
        let lookup = format!("{comp_path}.{f}");
        env.field_to_stratum
            .get(&lookup)
            .cloned()
            .unwrap_or_else(|| comp_path.clone())
    } else {
        comp_path.clone()
    };

    let canonical_component = env.resolve_canonical_component(&storage_key);
    let is_sparse = env.is_sparse(&storage_key) || env.is_sparse(&comp_path);
    let alias = alias_opt.unwrap_or_else(|| {
        comp_path
            .rsplit("::")
            .next()
            .unwrap_or(&comp_path)
            .to_owned()
    });

    Some(HirQueryTerm {
        alias,
        storage_key,
        canonical_component,
        field_name,
        mode,
        is_sparse,
    })
}

fn extract_proj_mode_and_typeref(node: &SyntaxNode) -> (TermAccessMode, Option<SyntaxNode>) {
    match node.kind() {
        SyntaxKind::PtrTermType => {
            let has_mut = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwMut);
            let mode = if has_mut {
                TermAccessMode::OptionalWrite
            } else {
                TermAccessMode::OptionalRead
            };
            let inner = unwrap_inner_typeref(node);
            (mode, inner)
        }
        SyntaxKind::RefType => {
            let has_mut = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwMut);
            let has_q = direct_tokens(node).any(|t| t.kind() == SyntaxKind::Question);
            let has_res = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwRes);
            let mode = if has_res {
                if has_mut {
                    TermAccessMode::ResWrite
                } else {
                    TermAccessMode::ResRead
                }
            } else if has_mut && has_q {
                TermAccessMode::SelectiveWrite
            } else if has_mut {
                TermAccessMode::Write
            } else {
                TermAccessMode::Read
            };
            let inner = unwrap_inner_typeref(node);
            (mode, inner)
        }
        SyntaxKind::TypeRef => (TermAccessMode::Read, Some(node.clone())),
        _ => (TermAccessMode::Read, unwrap_inner_typeref(node)),
    }
}

fn unwrap_inner_typeref(node: &SyntaxNode) -> Option<SyntaxNode> {
    if node.kind() == SyntaxKind::TypeRef {
        return Some(node.clone());
    }
    for ch in node.children() {
        if let Some(found) = unwrap_inner_typeref(&ch) {
            return Some(found);
        }
    }
    None
}

fn extract_typeref_comp_and_field(tr: &SyntaxNode) -> (String, Option<String>) {
    let comp = tr
        .children()
        .find(|c| c.kind() == SyntaxKind::Path)
        .and_then(ast::Path::cast)
        .map(|p| ast::path_text(&p))
        .unwrap_or_default();
    let mut saw_dot = false;
    let mut field_parts = Vec::new();
    for tok in direct_tokens(tr) {
        if tok.kind() == SyntaxKind::Dot {
            saw_dot = true;
        } else if saw_dot && tok.kind() == SyntaxKind::Ident {
            field_parts.push(tok.text().to_owned());
        }
    }
    let field = if field_parts.is_empty() {
        None
    } else {
        Some(field_parts.join("."))
    };
    (comp, field)
}

/// Lowers `CompInitList` (`object`, `spawn`, `BundleLitExpr`) directly from CST.
pub(crate) fn lower_comp_init_list(
    list_node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> Vec<HirCompInit> {
    let mut out = Vec::new();
    for ci in ast::children::<ast::CompInit>(list_node) {
        let component = ast::child::<ast::Path>(ci.syntax())
            .map(|p| ast::path_text(&p))
            .unwrap_or_default();
        let canonical_component = env
            .find_layout(&component)
            .map(|l| l.canonical_name.clone());
        let fields = ast::child::<ast::FieldInitList>(ci.syntax())
            .map(|fil| lower_field_init_list(fil.syntax(), env, scope, queries))
            .unwrap_or_default();
        out.push(HirCompInit {
            component,
            canonical_component,
            fields,
        });
    }
    out
}

pub(crate) fn lower_field_init_list(
    fil: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> Vec<(String, HirExpr)> {
    let mut out = Vec::new();
    for fi in ast::children::<ast::FieldInit>(fil) {
        let fname = ast::first_ident(fi.syntax()).map_or_else(String::new, |t| t.text().to_owned());
        let expr = if let Some(expr_node) = fi.syntax().children().find(|c| is_expr_node(c.kind()))
        {
            lower_expr(&expr_node, env, scope, queries)
        } else {
            let ty = lookup_var_ty(&fname, env, scope);
            HirExpr::Path {
                name: fname.clone(),
                ty,
            }
        };
        out.push((fname, expr));
    }
    out
}

/// Lowers a `Block` CST node into `(stmts, optional_tail_expr)`.
pub(crate) fn lower_block(
    block: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> (Vec<HirStmt>, Option<HirExpr>) {
    scope.push();
    let mut stmts = Vec::new();
    let mut tail = None;

    let children: Vec<SyntaxNode> = block.children().collect();
    for (idx, ch) in children.iter().enumerate() {
        let is_last = idx + 1 == children.len();
        if is_last && is_expr_node(ch.kind()) {
            tail = Some(lower_expr(ch, env, scope, queries));
        } else {
            lower_stmt_node(ch, env, scope, queries, &mut stmts);
        }
    }

    scope.pop();
    (stmts, tail)
}

/// Lowers a `Block` CST node strictly as statements, wrapping any trailing expression in
/// [`HirStmt::Expr`] (or [`HirStmt::Return`] if `trailing_is_return` is true).
pub(crate) fn lower_block_as_stmts(
    block: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    trailing_is_return: bool,
) -> Vec<HirStmt> {
    let (mut stmts, tail) = lower_block(block, env, scope, queries);
    if let Some(t) = tail {
        if trailing_is_return {
            stmts.push(HirStmt::Return(Some(t)));
        } else {
            stmts.push(HirStmt::Expr(t));
        }
    }
    stmts
}

/// Lowers a single statement node (from a `Block` or `TimelineAt` body).
pub(crate) fn lower_stmt_node(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    out: &mut Vec<HirStmt>,
) {
    match node.kind() {
        SyntaxKind::LetStmt | SyntaxKind::UniformLetStmt => {
            let is_uniform = node.kind() == SyntaxKind::UniformLetStmt;
            let pattern = node
                .children()
                .find(|c| is_pattern_node(c.kind()))
                .map_or(HirPattern::Wildcard, |p| lower_pattern(&p));
            let explicit_ty = node
                .children()
                .find(|c| is_type_node(c.kind()))
                .map(|t| parse_type_node(&t));
            let expr_node = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .or_else(|| {
                    // Allow `let x = { ... };` block initializer before any `else` keyword.
                    let else_pos = direct_tokens(node)
                        .find(|t| t.kind() == SyntaxKind::KwElse)
                        .map(|t| t.text_range().start());
                    node.children().find(|c| {
                        c.kind() == SyntaxKind::Block
                            && else_pos.is_none_or(|ep| c.text_range().end() <= ep)
                    })
                });
            let value = expr_node.as_ref().map_or(
                HirExpr::Tuple {
                    elems: Vec::new(),
                    ty: Ty::Unit,
                },
                |e| lower_expr(e, env, scope, queries),
            );

            let else_block = direct_tokens(node)
                .find(|t| t.kind() == SyntaxKind::KwElse)
                .and_then(|etok| {
                    node.children().find(|c| {
                        c.kind() == SyntaxKind::Block
                            && c.text_range().start() >= etok.text_range().end()
                    })
                })
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();

            let bound_ty = explicit_ty.clone().unwrap_or_else(|| value.ty());
            bind_pattern(&pattern, bound_ty, Some(&value), scope);

            out.push(HirStmt::Let {
                pattern,
                ty: explicit_ty,
                value,
                is_uniform,
                else_block,
            });
        }
        SyntaxKind::ReturnStmt => {
            let val = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            out.push(HirStmt::Return(val));
        }
        SyntaxKind::BreakStmt => {
            let val = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            out.push(HirStmt::Break(val));
        }
        SyntaxKind::ContinueStmt => {
            out.push(HirStmt::Continue);
        }
        SyntaxKind::WhileStmt => {
            let cond = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map_or(HirExpr::BoolLit(false), |e| {
                    lower_expr(&e, env, scope, queries)
                });
            let body = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Block)
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            out.push(HirStmt::While { cond, body });
        }
        SyntaxKind::LoopStmt => {
            let body = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Block)
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            out.push(HirStmt::Loop { body });
        }
        SyntaxKind::AtomicStmt => {
            let blocks: Vec<_> = node
                .children()
                .filter(|c| c.kind() == SyntaxKind::Block)
                .collect();
            let body = blocks
                .first()
                .map(|b| lower_block_as_stmts(b, env, scope, queries, false))
                .unwrap_or_default();
            let on_rollback = blocks
                .get(1)
                .map(|b| lower_block_as_stmts(b, env, scope, queries, false))
                .unwrap_or_default();
            out.push(HirStmt::Atomic(HirAtomic { body, on_rollback }));
        }
        SyntaxKind::AbortIfStmt => {
            let cond = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map_or(HirExpr::BoolLit(false), |e| {
                    lower_expr(&e, env, scope, queries)
                });
            let cleanup = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Block)
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            out.push(HirStmt::AbortIf { cond, cleanup });
        }
        SyntaxKind::WaitStmt => {
            let dur = node.children().find(|c| is_expr_node(c.kind())).map_or(
                HirExpr::FloatLit {
                    value: 0.0,
                    ty: Ty::UnitScalar {
                        name: "sec".to_owned(),
                        dim: UnitDim::SEC,
                    },
                },
                |e| lower_expr(&e, env, scope, queries),
            );
            out.push(HirStmt::Wait(dur));
        }
        SyntaxKind::WaitUntilStmt => {
            let cond = node
                .children()
                .find(|c| is_expr_node(c.kind()) || c.kind() == SyntaxKind::Block)
                .map_or(HirExpr::BoolLit(true), |e| {
                    lower_expr(&e, env, scope, queries)
                });
            out.push(HirStmt::WaitUntil(cond));
        }
        SyntaxKind::YieldTickStmt => {
            out.push(HirStmt::YieldTick);
        }
        SyntaxKind::RaceStmt => {
            let branches = ast::children::<ast::BranchStmt>(node)
                .map(|br| {
                    br.syntax()
                        .children()
                        .find(|c| c.kind() == SyntaxKind::Block)
                        .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                        .unwrap_or_default()
                })
                .collect();
            out.push(HirStmt::Race { branches });
        }
        SyntaxKind::ExprStmt => {
            if let Some(expr_node) = node.children().find(|c| is_expr_node(c.kind())) {
                lower_expr_as_stmt(&expr_node, env, scope, queries, out);
            }
        }
        other if is_expr_node(other) => {
            lower_expr_as_stmt(node, env, scope, queries, out);
        }
        _ => {}
    }
}

fn lower_expr_as_stmt(
    expr_node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    out: &mut Vec<HirStmt>,
) {
    // Check assignment expression (`a = b`, `a += b`, etc.)
    if expr_node.kind() == SyntaxKind::BinaryExpr
        && let Some(op) = direct_tokens(expr_node).find_map(token_to_assign_op)
    {
        let exprs: Vec<_> = expr_node
            .children()
            .filter(|c| is_expr_node(c.kind()))
            .collect();
        if exprs.len() >= 2 {
            let target = lower_lvalue(&exprs[0], env, scope, queries);
            let value = lower_expr(&exprs[1], env, scope, queries);
            out.push(HirStmt::Assign { target, op, value });
            return;
        }
    }

    let lowered = lower_expr(expr_node, env, scope, queries);
    if let HirExpr::Call(ref call) = lowered
        && call.receiver.is_none()
    {
        match call.callee.as_str() {
            "require_true" if !call.args.is_empty() => {
                out.push(HirStmt::RequireTrue(call.args[0].clone()));
                return;
            }
            "trigger" if call.args.len() >= 2 => {
                let propagate = call.arg_names.iter().zip(call.args.iter()).any(|(n, a)| {
                    n.as_deref() == Some("propagate") && matches!(a, HirExpr::BoolLit(true))
                });
                out.push(HirStmt::Trigger {
                    target: Box::new(call.args[0].clone()),
                    event: Box::new(call.args[1].clone()),
                    propagate,
                });
                return;
            }
            "emit" if !call.args.is_empty() => {
                out.push(HirStmt::Emit(call.args[0].clone()));
                return;
            }
            "despawn" if !call.args.is_empty() => {
                out.push(HirStmt::Despawn(call.args[0].clone()));
                return;
            }
            "insert_relation" if call.args.len() >= 2 => {
                let rel = call.generic_args.first().cloned().unwrap_or_default();
                let payload = call.args.get(2).cloned().map(Box::new);
                out.push(HirStmt::InsertRelation {
                    relation: rel,
                    entity: Box::new(call.args[0].clone()),
                    target: Box::new(call.args[1].clone()),
                    payload,
                });
                return;
            }
            "remove_relation" if call.args.len() >= 2 => {
                let rel = call.generic_args.first().cloned().unwrap_or_default();
                out.push(HirStmt::RemoveRelation {
                    relation: rel,
                    entity: Box::new(call.args[0].clone()),
                    target: Box::new(call.args[1].clone()),
                });
                return;
            }
            _ => {}
        }
    }
    out.push(HirStmt::Expr(lowered));
}

fn lower_lvalue(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirLValue {
    match node.kind() {
        SyntaxKind::ParenExpr => {
            if let Some(inner) = node.children().find(|c| is_expr_node(c.kind())) {
                return lower_lvalue(&inner, env, scope, queries);
            }
            HirLValue::Local {
                name: "_".to_owned(),
                ty: Ty::Unknown,
            }
        }
        SyntaxKind::PathExpr => {
            let name = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Path)
                .and_then(ast::Path::cast)
                .map(|p| ast::path_text(&p))
                .unwrap_or_default();
            let ty = lookup_var_ty(&name, env, scope);
            HirLValue::Local { name, ty }
        }
        SyntaxKind::FieldExpr => {
            let base_node = node.children().find(|c| is_expr_node(c.kind()));
            let field = direct_tokens(node)
                .filter(|t| {
                    matches!(
                        t.kind(),
                        SyntaxKind::Ident | SyntaxKind::KwSelfLower | SyntaxKind::KwSelfUpper
                    )
                })
                .last()
                .map_or_else(String::new, |t| t.text().to_owned());
            if let Some(bn) = base_node {
                let base = lower_lvalue(&bn, env, scope, queries);
                let field_ty = resolve_lvalue_field_ty(&base, &field, env, scope);
                HirLValue::Field {
                    base: Box::new(base),
                    field,
                    ty: field_ty,
                }
            } else {
                HirLValue::Local {
                    name: field,
                    ty: Ty::Unknown,
                }
            }
        }
        SyntaxKind::IndexExpr => {
            let exprs: Vec<_> = node.children().filter(|c| is_expr_node(c.kind())).collect();
            let base = exprs.first().map_or(
                HirLValue::Local {
                    name: "_".to_owned(),
                    ty: Ty::Unknown,
                },
                |b| lower_lvalue(b, env, scope, queries),
            );
            let index = exprs.get(1).map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |i| lower_expr(i, env, scope, queries),
            );
            let elem_ty = match base.ty() {
                Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => (**elem).clone(),
                _ => Ty::Unknown,
            };
            HirLValue::Index {
                base: Box::new(base),
                index: Box::new(index),
                ty: elem_ty,
            }
        }
        SyntaxKind::PostfixCallExpr => {
            let expr = lower_expr(node, env, scope, queries);
            if let HirExpr::Call(c) = &expr
                && (c.callee == "res_mut" || c.callee == "res")
                && let Some(rname) = c.generic_args.first()
            {
                return HirLValue::ResourceAccess {
                    resource: rname.clone(),
                    is_mut: c.callee == "res_mut",
                    ty: Ty::Named(rname.clone()),
                };
            }
            HirLValue::Local {
                name: node.text().to_string().trim().to_owned(),
                ty: expr.ty(),
            }
        }
        _ => HirLValue::Local {
            name: node.text().to_string().trim().to_owned(),
            ty: Ty::Unknown,
        },
    }
}

fn resolve_lvalue_field_ty(
    base: &HirLValue,
    field: &str,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> Ty {
    if let HirLValue::Local { name, .. } = base
        && let Some(ScopeBinding::QueryRow { terms }) = scope.get(name)
        && let Some(t) = terms.iter().find(|t| t.alias == field)
    {
        return resolve_query_term_ty(t, env);
    }
    resolve_field_ty_from_base_ty(base.ty(), field, env)
}

pub(crate) fn lower_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    match node.kind() {
        SyntaxKind::LiteralExpr => {
            for tok in direct_tokens(node) {
                if let Some(lit) = lower_literal_token(&tok) {
                    return lit;
                }
            }
            HirExpr::IntLit {
                value: 0,
                ty: Ty::I32,
            }
        }
        SyntaxKind::PathExpr => {
            let name = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Path)
                .and_then(ast::Path::cast)
                .map(|p| ast::path_text(&p))
                .unwrap_or_else(|| node.text().to_string().trim().to_owned());
            let ty = lookup_var_ty(&name, env, scope);
            HirExpr::Path { name, ty }
        }
        SyntaxKind::ParenExpr => node.children().find(|c| is_expr_node(c.kind())).map_or(
            HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            },
            |inner| lower_expr(&inner, env, scope, queries),
        ),
        SyntaxKind::TupleExpr => {
            let elems: Vec<_> = node
                .children()
                .filter(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries))
                .collect();
            let ty = if elems.is_empty() {
                Ty::Unit
            } else {
                Ty::Tuple(elems.iter().map(HirExpr::ty).collect())
            };
            HirExpr::Tuple { elems, ty }
        }
        SyntaxKind::ArrayLitExpr => {
            let elems: Vec<_> = node
                .children()
                .filter(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries))
                .collect();
            let elem_ty = elems.first().map_or(Ty::Unknown, HirExpr::ty);
            let ty = Ty::Array {
                elem: Box::new(elem_ty),
                len: elems.len(),
            };
            HirExpr::ArrayLit { elems, ty }
        }
        SyntaxKind::PrefixExpr => {
            let has_mut = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwMut);
            let op = direct_tokens(node)
                .find_map(|t| match t.kind() {
                    SyntaxKind::Minus => Some(HirUnOp::Neg),
                    SyntaxKind::Bang => Some(HirUnOp::Not),
                    SyntaxKind::Tilde => Some(HirUnOp::BitNot),
                    SyntaxKind::Amp => Some(if has_mut {
                        HirUnOp::RefMut
                    } else {
                        HirUnOp::Ref
                    }),
                    _ => None,
                })
                .unwrap_or(HirUnOp::Neg);
            let inner = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map_or(HirExpr::BoolLit(false), |e| {
                    lower_expr(&e, env, scope, queries)
                });
            let ty = match op {
                HirUnOp::Not => {
                    let it = inner.ty();
                    if it == Ty::Unknown { Ty::Bool } else { it }
                }
                _ => inner.ty(),
            };
            HirExpr::Unary {
                op,
                expr: Box::new(inner),
                ty,
            }
        }
        SyntaxKind::BinaryExpr => {
            let exprs: Vec<_> = node.children().filter(|c| is_expr_node(c.kind())).collect();
            let lhs = exprs.first().map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |e| lower_expr(e, env, scope, queries),
            );
            let rhs = exprs.get(1).map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |e| lower_expr(e, env, scope, queries),
            );
            let op = direct_tokens(node)
                .find_map(token_to_bin_op)
                .unwrap_or(HirBinOp::Add);
            let ty = infer_binop_ty(op, &lhs.ty(), &rhs.ty());
            HirExpr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                ty,
            }
        }
        SyntaxKind::CastExpr => {
            let expr = node.children().find(|c| is_expr_node(c.kind())).map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |e| lower_expr(&e, env, scope, queries),
            );
            let target_ty = node
                .children()
                .find(|c| is_type_node(c.kind()))
                .map_or(Ty::Unknown, |t| parse_type_node(&t));
            HirExpr::Cast {
                expr: Box::new(expr),
                target_ty,
            }
        }
        SyntaxKind::FieldExpr => {
            let base = node.children().find(|c| is_expr_node(c.kind())).map_or(
                HirExpr::Tuple {
                    elems: Vec::new(),
                    ty: Ty::Unit,
                },
                |e| lower_expr(&e, env, scope, queries),
            );
            let field = direct_tokens(node)
                .filter(|t| {
                    matches!(
                        t.kind(),
                        SyntaxKind::Ident | SyntaxKind::KwSelfLower | SyntaxKind::KwSelfUpper
                    )
                })
                .last()
                .map_or_else(String::new, |t| t.text().to_owned());
            let ty = resolve_expr_field_ty(&base, &field, env, scope);
            HirExpr::Field {
                base: Box::new(base),
                field,
                ty,
            }
        }
        SyntaxKind::IndexExpr => {
            let exprs: Vec<_> = node.children().filter(|c| is_expr_node(c.kind())).collect();
            let base = exprs.first().map_or(
                HirExpr::Tuple {
                    elems: Vec::new(),
                    ty: Ty::Unit,
                },
                |e| lower_expr(e, env, scope, queries),
            );
            let index = exprs.get(1).map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |e| lower_expr(e, env, scope, queries),
            );
            let ty = match &base {
                HirExpr::Path { name, .. } if env.table_fields.contains_key(name) => {
                    Ty::Named(format!("__table_row::{name}"))
                }
                _ => match base.ty() {
                    Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => *elem,
                    _ => Ty::Unknown,
                },
            };
            HirExpr::Index {
                base: Box::new(base),
                index: Box::new(index),
                ty,
            }
        }
        SyntaxKind::StructLitExpr => {
            let name = node
                .children()
                .find(|c| c.kind() == SyntaxKind::PathExpr)
                .map_or_else(String::new, |p| p.text().to_string().trim().to_owned());
            let fields = ast::child::<ast::FieldInitList>(node)
                .map(|fil| lower_field_init_list(fil.syntax(), env, scope, queries))
                .unwrap_or_default();
            HirExpr::StructLit {
                name: name.clone(),
                fields,
                ty: Ty::Named(name),
            }
        }
        SyntaxKind::RecordLitExpr => {
            let fields = ast::child::<ast::FieldInitList>(node)
                .map(|fil| lower_field_init_list(fil.syntax(), env, scope, queries))
                .unwrap_or_default();
            HirExpr::RecordLit {
                fields,
                ty: Ty::Unknown,
            }
        }
        SyntaxKind::BundleLitExpr => {
            let components = ast::child::<ast::CompInitList>(node)
                .map(|cil| lower_comp_init_list(cil.syntax(), env, scope, queries))
                .unwrap_or_default();
            HirExpr::BundleLit { components }
        }
        SyntaxKind::SpawnExpr => {
            let is_persistent = ast::attrs(node)
                .iter()
                .filter_map(ast::attr_name)
                .any(|a| a == "persistent");
            let components = ast::child::<ast::CompInitList>(node)
                .map(|cil| lower_comp_init_list(cil.syntax(), env, scope, queries))
                .unwrap_or_default();
            HirExpr::Spawn(HirSpawn {
                is_persistent,
                is_batch: false,
                count: None,
                batch_var: None,
                preamble: Vec::new(),
                components,
            })
        }
        SyntaxKind::SpawnBatchExpr => {
            let count = ast::child::<ast::ArgList>(node)
                .and_then(|al| al.syntax().children().find(|c| is_expr_node(c.kind())))
                .map(|e| Box::new(lower_expr(&e, env, scope, queries)));
            let pat = node
                .children()
                .find(|c| is_pattern_node(c.kind()))
                .map(|p| lower_pattern(&p));
            let batch_var = pat.as_ref().and_then(first_pattern_binding);
            scope.push();
            if let Some(ref bv) = batch_var {
                scope.insert(bv.clone(), ScopeBinding::Var(Ty::I32));
            }
            let (preamble, tail) = ast::child::<ast::Block>(node)
                .map(|b| lower_block(b.syntax(), env, scope, queries))
                .unwrap_or_default();
            scope.pop();
            let components = match tail {
                Some(HirExpr::BundleLit { components }) => components,
                _ => Vec::new(),
            };
            HirExpr::Spawn(HirSpawn {
                is_persistent: false,
                is_batch: true,
                count,
                batch_var,
                preamble,
                components,
            })
        }
        SyntaxKind::DespawnAllExpr => {
            let filters = node
                .children()
                .find(|c| c.kind() == SyntaxKind::GenericArgs)
                .map(|ga| {
                    ga.children()
                        .filter(|c| is_type_node(c.kind()))
                        .map(|t| t.text().to_string().trim().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            HirExpr::DespawnAll { filters }
        }
        SyntaxKind::InsertExpr => {
            let if_new = ast::attrs(node)
                .iter()
                .filter_map(ast::attr_name)
                .any(|a| a == "if_new");
            let mut args = Vec::new();
            if let Some(al) = ast::child::<ast::ArgList>(node) {
                for c in al.syntax().children().filter(|c| is_expr_node(c.kind())) {
                    args.push(lower_expr(&c, env, scope, queries));
                }
            }
            let entity = args.first().cloned().unwrap_or(HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            });
            let value = args.get(1).cloned().unwrap_or(HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            });
            HirExpr::Insert {
                if_new,
                entity: Box::new(entity),
                value: Box::new(value),
            }
        }
        SyntaxKind::RemoveExpr => {
            let component = node
                .children()
                .find(|c| c.kind() == SyntaxKind::GenericArgs)
                .and_then(|ga| ga.children().find(|c| is_type_node(c.kind())))
                .map(|t| t.text().to_string().trim().to_owned())
                .unwrap_or_default();
            let entity = ast::child::<ast::ArgList>(node)
                .and_then(|al| al.syntax().children().find(|c| is_expr_node(c.kind())))
                .map_or(
                    HirExpr::Tuple {
                        elems: Vec::new(),
                        ty: Ty::Unit,
                    },
                    |e| lower_expr(&e, env, scope, queries),
                );
            HirExpr::Remove {
                component,
                entity: Box::new(entity),
            }
        }
        SyntaxKind::PostfixCallExpr => lower_postfix_call(node, env, scope, queries),
        SyntaxKind::Block => {
            let (stmts, tail) = lower_block(node, env, scope, queries);
            let ty = tail.as_ref().map_or(Ty::Unit, |t| t.ty());
            HirExpr::Block {
                stmts,
                tail: tail.map(Box::new),
                ty,
            }
        }
        SyntaxKind::IfExpr => lower_if_expr(node, env, scope, queries),
        SyntaxKind::MatchExpr => lower_match_expr(node, env, scope, queries),
        SyntaxKind::ForExpr => lower_for_expr(node, env, scope, queries),
        _ => HirExpr::Tuple {
            elems: Vec::new(),
            ty: Ty::Unit,
        },
    }
}

fn lower_postfix_call(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    // Handle `expr?` postfix try.
    if direct_tokens(node).any(|t| t.kind() == SyntaxKind::Question)
        && ast::child::<ast::ArgList>(node).is_none()
        && let Some(inner) = node.children().find(|c| is_expr_node(c.kind()))
    {
        return lower_expr(&inner, env, scope, queries);
    }

    let first_expr = node.children().find(|c| is_expr_node(c.kind()));
    let has_dot = direct_tokens(node).any(|t| t.kind() == SyntaxKind::Dot);
    let generic_args = node
        .children()
        .find(|c| c.kind() == SyntaxKind::GenericArgs)
        .map(|ga| {
            ga.children()
                .filter(|c| is_type_node(c.kind()))
                .map(|t| t.text().to_string().trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !has_dot {
        // Direct call: `callee(args)` or `query(...)` or `query_one(...)`.
        let callee = first_expr
            .as_ref()
            .map_or_else(String::new, |c| c.text().to_string().trim().to_owned());
        if matches!(callee.as_str(), "query" | "query_one") {
            let is_point_lookup = callee == "query_one";
            let terms = ast::child::<ast::ArgList>(node)
                .and_then(|al| ast::child::<ast::ProjTermList>(al.syntax()))
                .map(|ptl| {
                    ast::children::<ast::ProjTerm>(ptl.syntax())
                        .filter_map(|pt| lower_proj_term(pt.syntax(), env))
                        .collect()
                })
                .unwrap_or_default();
            let byte_start = u32::from(node.text_range().start());
            let byte_end = u32::from(node.text_range().end());
            let query_idx = queries
                .iter()
                .position(|q| q.byte_start == byte_start && q.byte_end == byte_end)
                .map(|i| i as u32);
            return HirExpr::Query(HirQuery {
                is_point_lookup,
                terms,
                with_filters: Vec::new(),
                without_filters: Vec::new(),
                allow_filters: Vec::new(),
                has_filters: Vec::new(),
                where_pred: None,
                on_target: None,
                up_relation: None,
                is_count: false,
                is_unwrap: false,
                query_idx,
            });
        }

        let (args, arg_names) = ast::child::<ast::ArgList>(node)
            .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
            .unwrap_or_default();
        let ty = infer_call_ty(None, &callee, &generic_args, &args, env);
        return HirExpr::Call(HirCall {
            receiver: None,
            callee,
            generic_args,
            args,
            arg_names,
            ty,
        });
    }

    // Method call: `recv.method<G>(args)`.
    let method_name = direct_tokens(node)
        .filter(|t| {
            matches!(
                t.kind(),
                SyntaxKind::Ident | SyntaxKind::KwSelfLower | SyntaxKind::KwSelfUpper
            )
        })
        .last()
        .map_or_else(String::new, |t| t.text().to_owned());

    let recv = first_expr.map(|e| lower_expr(&e, env, scope, queries));
    if let Some(HirExpr::Query(mut q)) = recv {
        match method_name.as_str() {
            "with" => {
                q.with_filters.extend(generic_args);
                return HirExpr::Query(q);
            }
            "without" => {
                q.without_filters.extend(generic_args);
                return HirExpr::Query(q);
            }
            "allow" => {
                q.allow_filters.extend(generic_args);
                return HirExpr::Query(q);
            }
            "has" => {
                q.has_filters.extend(generic_args);
                return HirExpr::Query(q);
            }
            "up" => {
                q.up_relation = generic_args.into_iter().next();
                return HirExpr::Query(q);
            }
            "where" => {
                if let Some(al) = ast::child::<ast::ArgList>(node)
                    && let Some(pred_node) = al.syntax().children().find(|c| is_expr_node(c.kind()))
                {
                    scope.push();
                    for t in &q.terms {
                        let tty = resolve_query_term_ty(t, env);
                        scope.insert(t.alias.clone(), ScopeBinding::Var(tty));
                    }
                    let pred = lower_expr(&pred_node, env, scope, queries);
                    scope.pop();
                    q.where_pred = Some(Box::new(pred));
                }
                return HirExpr::Query(q);
            }
            "on" => {
                if let Some(al) = ast::child::<ast::ArgList>(node)
                    && let Some(tgt_node) = al.syntax().children().find(|c| is_expr_node(c.kind()))
                {
                    q.on_target = Some(Box::new(lower_expr(&tgt_node, env, scope, queries)));
                }
                return HirExpr::Query(q);
            }
            "count" => {
                q.is_count = true;
                return HirExpr::Query(q);
            }
            "unwrap" => {
                q.is_unwrap = true;
                return HirExpr::Query(q);
            }
            _ => {
                let (args, arg_names) = ast::child::<ast::ArgList>(node)
                    .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                    .unwrap_or_default();
                let ty = infer_call_ty(None, &method_name, &generic_args, &args, env);
                return HirExpr::Call(HirCall {
                    receiver: Some(Box::new(HirExpr::Query(q))),
                    callee: method_name,
                    generic_args,
                    args,
                    arg_names,
                    ty,
                });
            }
        }
    }

    let (args, arg_names) = ast::child::<ast::ArgList>(node)
        .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
        .unwrap_or_default();
    let ty = infer_call_ty(recv.as_ref(), &method_name, &generic_args, &args, env);
    HirExpr::Call(HirCall {
        receiver: recv.map(Box::new),
        callee: method_name,
        generic_args,
        args,
        arg_names,
        ty,
    })
}

fn lower_arg_list(
    al: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> (Vec<HirExpr>, Vec<Option<String>>) {
    let mut args = Vec::new();
    let mut names = Vec::new();
    for ch in al.children() {
        if ch.kind() == SyntaxKind::FieldInit {
            let fname = ast::first_ident(&ch).map(|t| t.text().to_owned());
            let expr = ch.children().find(|c| is_expr_node(c.kind())).map_or(
                HirExpr::Tuple {
                    elems: Vec::new(),
                    ty: Ty::Unit,
                },
                |e| lower_expr(&e, env, scope, queries),
            );
            names.push(fname);
            args.push(expr);
        } else if is_expr_node(ch.kind()) {
            names.push(None);
            args.push(lower_expr(&ch, env, scope, queries));
        }
    }
    (args, names)
}

fn lower_if_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    let has_let = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwLet);
    let let_pat = if has_let {
        node.children()
            .find(|c| is_pattern_node(c.kind()))
            .map(|p| lower_pattern(&p))
    } else {
        None
    };

    let cond = node
        .children()
        .find(|c| is_expr_node(c.kind()) && c.kind() != SyntaxKind::IfExpr)
        .map_or(HirExpr::BoolLit(false), |e| {
            lower_expr(&e, env, scope, queries)
        });

    let blocks: Vec<_> = node
        .children()
        .filter(|c| c.kind() == SyntaxKind::Block)
        .collect();

    scope.push();
    if let Some(ref pat) = let_pat {
        bind_pattern(pat, cond.ty(), Some(&cond), scope);
    }
    let (then_stmts, then_tail) = blocks
        .first()
        .map(|b| lower_block(b, env, scope, queries))
        .unwrap_or_default();
    scope.pop();

    let else_if = node.children().find(|c| c.kind() == SyntaxKind::IfExpr);
    let (else_stmts, else_tail) = if let Some(ei) = else_if {
        (Vec::new(), Some(lower_if_expr(&ei, env, scope, queries)))
    } else if let Some(eb) = blocks.get(1) {
        lower_block(eb, env, scope, queries)
    } else {
        (Vec::new(), None)
    };

    let ty = then_tail
        .as_ref()
        .map(HirExpr::ty)
        .or_else(|| else_tail.as_ref().map(HirExpr::ty))
        .unwrap_or(Ty::Unit);

    HirExpr::If {
        let_pat,
        cond: Box::new(cond),
        then_stmts,
        then_tail: then_tail.map(Box::new),
        else_stmts,
        else_tail: else_tail.map(Box::new),
        ty,
    }
}

fn lower_match_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    let scrutinee = node.children().find(|c| is_expr_node(c.kind())).map_or(
        HirExpr::IntLit {
            value: 0,
            ty: Ty::I32,
        },
        |e| lower_expr(&e, env, scope, queries),
    );
    let scrut_ty = scrutinee.ty();
    let mut arms = Vec::new();
    for arm_node in node.children().filter(|c| c.kind() == SyntaxKind::MatchArm) {
        let pattern = arm_node
            .children()
            .find(|c| is_pattern_node(c.kind()))
            .map_or(HirPattern::Wildcard, |p| lower_pattern(&p));
        scope.push();
        bind_pattern(&pattern, scrut_ty.clone(), None, scope);
        let exprs: Vec<_> = arm_node
            .children()
            .filter(|c| is_expr_node(c.kind()) || c.kind() == SyntaxKind::Block)
            .collect();
        let has_guard = direct_tokens(&arm_node).any(|t| t.kind() == SyntaxKind::KwIf);
        let (guard, body) = if has_guard && exprs.len() >= 2 {
            (
                Some(lower_expr(&exprs[0], env, scope, queries)),
                lower_expr(&exprs[1], env, scope, queries),
            )
        } else {
            (
                None,
                exprs.first().map_or(
                    HirExpr::Tuple {
                        elems: Vec::new(),
                        ty: Ty::Unit,
                    },
                    |e| lower_expr(e, env, scope, queries),
                ),
            )
        };
        scope.pop();
        arms.push(HirMatchArm {
            pattern,
            guard,
            body,
        });
    }
    let ty = arms.first().map_or(Ty::Unit, |a| a.body.ty());
    HirExpr::Match(HirMatch {
        scrutinee: Box::new(scrutinee),
        arms,
        ty,
    })
}

fn lower_for_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    let binding = node
        .children()
        .find(|c| is_pattern_node(c.kind()))
        .map_or(HirPattern::Wildcard, |p| lower_pattern(&p));
    let iter_expr = node.children().find(|c| is_expr_node(c.kind())).map_or(
        HirExpr::Tuple {
            elems: Vec::new(),
            ty: Ty::Unit,
        },
        |e| lower_expr(&e, env, scope, queries),
    );

    let iter = match iter_expr {
        HirExpr::Query(q) => HirForIter::Query(q),
        HirExpr::Binary {
            op: op @ (HirBinOp::Range | HirBinOp::RangeInclusive),
            lhs,
            rhs,
            ..
        } => HirForIter::Range {
            start: lhs,
            end: rhs,
            inclusive: op == HirBinOp::RangeInclusive,
        },
        HirExpr::Call(HirCall {
            receiver: Some(recv),
            ref callee,
            ref args,
            ..
        }) if callee == "query_disc" && args.len() >= 2 => {
            let grid = expr_short_name(&recv);
            HirForIter::SpatialDisc {
                grid,
                center: Box::new(args[0].clone()),
                radius: Box::new(args[1].clone()),
            }
        }
        HirExpr::Call(HirCall {
            receiver: Some(recv),
            ref callee,
            ref args,
            ..
        }) if callee == "query_segment_at" && args.len() >= 3 => {
            let history = expr_short_name(&recv);
            HirForIter::SpatialSegmentAt {
                history,
                tick: Box::new(args[0].clone()),
                p0: Box::new(args[1].clone()),
                p1: Box::new(args[2].clone()),
            }
        }
        other => HirForIter::Expr(Box::new(other)),
    };

    scope.push();
    match &iter {
        HirForIter::Query(q) => {
            if let Some(var) = first_pattern_binding(&binding) {
                scope.insert(
                    var,
                    ScopeBinding::QueryRow {
                        terms: q.terms.clone(),
                    },
                );
            }
        }
        HirForIter::Range { start, .. } => {
            if let Some(var) = first_pattern_binding(&binding) {
                scope.insert(var, ScopeBinding::Var(start.ty()));
            }
        }
        HirForIter::SpatialDisc { .. } | HirForIter::SpatialSegmentAt { .. } => {
            if let Some(var) = first_pattern_binding(&binding) {
                scope.insert(var, ScopeBinding::SpatialCandidate);
            }
        }
        HirForIter::Expr(e) => {
            bind_pattern(&binding, e.ty(), None, scope);
        }
    }

    let mut reduce = Vec::new();
    let mut body = Vec::new();
    if let Some(rc) = ast::child::<ast::ReduceClause>(node) {
        for re in ast::children::<ast::ReduceEntry>(rc.syntax()) {
            let name = ast::first_ident(re.syntax())
                .map_or_else(|| "acc".to_owned(), |t| t.text().to_owned());
            let expr = re
                .syntax()
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            if let Some(HirExpr::Call(call)) = expr {
                let op = call.callee.clone();
                let identity = call.args.first().cloned().unwrap_or(HirExpr::FloatLit {
                    value: 0.0,
                    ty: Ty::F32,
                });
                let value = call.args.get(1).cloned().unwrap_or(identity.clone());
                let ty = value.ty();
                reduce.push(HirReduceEntry {
                    name,
                    op,
                    identity,
                    value,
                    ty,
                });
            }
        }
    } else if let Some(blk) = ast::child::<ast::Block>(node) {
        body = lower_block_as_stmts(blk.syntax(), env, scope, queries, false);
    }
    scope.pop();

    let ty = if reduce.is_empty() {
        Ty::Unit
    } else if reduce.len() == 1 {
        reduce[0].ty.clone()
    } else {
        Ty::Tuple(reduce.iter().map(|r| r.ty.clone()).collect())
    };

    HirExpr::For(HirFor {
        binding,
        iter,
        body,
        reduce,
        ty,
    })
}

fn expr_short_name(e: &HirExpr) -> String {
    match e {
        HirExpr::Path { name, .. } => name.clone(),
        HirExpr::Field { field, .. } => field.clone(),
        _ => String::new(),
    }
}

pub(crate) fn lower_pattern(node: &SyntaxNode) -> HirPattern {
    match node.kind() {
        SyntaxKind::TuplePattern => HirPattern::Tuple(
            node.children()
                .filter(|c| is_pattern_node(c.kind()))
                .map(|c| lower_pattern(&c))
                .collect(),
        ),
        SyntaxKind::TupleStructPattern => {
            let path = ast::child::<ast::Path>(node)
                .map(|p| ast::path_text(&p))
                .unwrap_or_default();
            let fields = node
                .children()
                .filter(|c| is_pattern_node(c.kind()))
                .map(|c| lower_pattern(&c))
                .collect();
            HirPattern::TupleStruct { path, fields }
        }
        SyntaxKind::Pattern => {
            if let Some(p) = ast::child::<ast::Path>(node) {
                let name = ast::path_text(&p);
                let mutable = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwMut);
                if name.contains("::") {
                    return HirPattern::Path(name);
                }
                return HirPattern::Binding { name, mutable };
            }
            let neg = direct_tokens(node).any(|t| t.kind() == SyntaxKind::Minus);
            for tok in direct_tokens(node) {
                if let Some(lit) = lower_literal_token(&tok) {
                    let lit = if neg {
                        let ty = lit.ty();
                        HirExpr::Unary {
                            op: HirUnOp::Neg,
                            expr: Box::new(lit),
                            ty,
                        }
                    } else {
                        lit
                    };
                    return HirPattern::Literal(Box::new(lit));
                }
            }
            HirPattern::Wildcard
        }
        _ => HirPattern::Wildcard,
    }
}

fn first_pattern_binding(pat: &HirPattern) -> Option<String> {
    match pat {
        HirPattern::Binding { name, .. } => Some(name.clone()),
        HirPattern::Tuple(items) | HirPattern::TupleStruct { fields: items, .. } => {
            items.iter().find_map(first_pattern_binding)
        }
        _ => None,
    }
}

fn bind_pattern(pat: &HirPattern, ty: Ty, src_expr: Option<&HirExpr>, scope: &mut ScopeStack) {
    match pat {
        HirPattern::Binding { name, .. } => {
            if let Some(HirExpr::Query(q)) = src_expr {
                scope.insert(
                    name.clone(),
                    ScopeBinding::QueryRow {
                        terms: q.terms.clone(),
                    },
                );
            } else {
                scope.insert(name.clone(), ScopeBinding::Var(ty));
            }
        }
        HirPattern::Tuple(items) => {
            let elem_tys = match ty {
                Ty::Tuple(ts) => ts,
                _ => Vec::new(),
            };
            for (idx, p) in items.iter().enumerate() {
                let ety = elem_tys.get(idx).cloned().unwrap_or(Ty::Unknown);
                bind_pattern(p, ety, None, scope);
            }
        }
        HirPattern::TupleStruct { path, fields } => {
            if path == "Some" && fields.len() == 1 {
                if let Some(HirExpr::Query(q)) = src_expr {
                    if let Some(var) = first_pattern_binding(&fields[0]) {
                        scope.insert(
                            var,
                            ScopeBinding::QueryRow {
                                terms: q.terms.clone(),
                            },
                        );
                    }
                } else {
                    bind_pattern(&fields[0], ty, None, scope);
                }
            } else {
                for f in fields {
                    bind_pattern(f, Ty::Unknown, None, scope);
                }
            }
        }
        HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
    }
}

fn lookup_var_ty(name: &str, env: &LowerEnv<'_>, scope: &ScopeStack) -> Ty {
    if let Some(b) = scope.get(name) {
        return match b {
            ScopeBinding::Var(ty) | ScopeBinding::Resource { ty, .. } => ty.clone(),
            ScopeBinding::Trigger { event, .. } => Ty::Named(event.clone()),
            ScopeBinding::QueryRow { .. } | ScopeBinding::SpatialCandidate => {
                Ty::Ref("Entity".to_owned())
            }
        };
    }
    if let Some(cty) = env.const_tys.get(name) {
        return cty.clone();
    }
    if let Some((enum_name, _)) = name.split_once("::") {
        if env.enums.contains_key(enum_name) {
            return Ty::Named(enum_name.to_owned());
        }
        match name {
            "vec2::ZERO" | "vec2::ONE" => return Ty::Vec2,
            "vec3::ZERO" | "vec3::ONE" => return Ty::Vec3,
            "vec4::ZERO" | "vec4::ONE" => return Ty::Vec4,
            _ => {}
        }
    }
    if env.objects.contains(name) {
        return Ty::Ref("Entity".to_owned());
    }
    Ty::Unknown
}

fn resolve_query_term_ty(term: &HirQueryTerm, env: &LowerEnv<'_>) -> Ty {
    if let Some(ref fname) = term.field_name
        && let Some(layout) = env.find_layout(&term.canonical_component)
        && let Some(sf) = layout.fields.iter().find(|f| f.name == *fname)
    {
        return sf.ty.clone();
    }
    Ty::Named(term.storage_key.clone())
}

fn resolve_expr_field_ty(
    base: &HirExpr,
    field: &str,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> Ty {
    match base {
        HirExpr::Path { name, .. } => {
            if let Some(binding) = scope.get(name) {
                match binding {
                    ScopeBinding::QueryRow { terms } => {
                        if field == "id" {
                            return Ty::Ref("Entity".to_owned());
                        }
                        if let Some(t) = terms.iter().find(|t| t.alias == field) {
                            return resolve_query_term_ty(t, env);
                        }
                    }
                    ScopeBinding::SpatialCandidate => {
                        if field == "id" {
                            return Ty::Ref("Entity".to_owned());
                        }
                    }
                    ScopeBinding::Trigger { event, target_comp } => {
                        if field == "payload" {
                            return Ty::Named(event.clone());
                        }
                        if field == "target" {
                            return Ty::Ref(
                                target_comp.clone().unwrap_or_else(|| "Entity".to_owned()),
                            );
                        }
                    }
                    ScopeBinding::Resource { canonical, .. } => {
                        if let Some(l) = env.find_layout(canonical)
                            && let Some(f) = l.fields.iter().find(|f| f.name == field)
                        {
                            return f.ty.clone();
                        }
                    }
                    ScopeBinding::Var(ty) => {
                        return resolve_field_ty_from_base_ty(ty, field, env);
                    }
                }
            }
            resolve_field_ty_from_base_ty(&base.ty(), field, env)
        }
        HirExpr::Query(q) => {
            if field == "id" {
                return Ty::Ref("Entity".to_owned());
            }
            if let Some(t) = q.terms.iter().find(|t| t.alias == field) {
                return resolve_query_term_ty(t, env);
            }
            Ty::Unknown
        }
        _ => resolve_field_ty_from_base_ty(&base.ty(), field, env),
    }
}

fn resolve_field_ty_from_base_ty(base_ty: &Ty, field: &str, env: &LowerEnv<'_>) -> Ty {
    match base_ty {
        Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4 | Ty::Quat => match field.len() {
            1 if matches!(field, "x" | "y" | "z" | "w") => Ty::F32,
            2 => Ty::Vec2,
            3 => Ty::Vec3,
            4 => Ty::Vec4,
            _ => Ty::Unknown,
        },
        Ty::IVec2 | Ty::IVec3 => match field.len() {
            1 if matches!(field, "x" | "y" | "z") => Ty::I32,
            2 => Ty::IVec2,
            3 => Ty::IVec3,
            _ => Ty::Unknown,
        },
        Ty::UVec2 => match field.len() {
            1 if matches!(field, "x" | "y") => Ty::U32,
            2 => Ty::UVec2,
            _ => Ty::Unknown,
        },
        Ty::Named(name) => {
            if let Some(tbl_name) = name.strip_prefix("__table_row::")
                && let Some(fields) = env.table_fields.get(tbl_name)
                && let Some((_, fty)) = fields.iter().find(|(n, _)| n == field)
            {
                return fty.clone();
            }
            if let Some(l) = env.find_layout(name)
                && let Some(f) = l.fields.iter().find(|f| f.name == field)
            {
                return f.ty.clone();
            }
            if let Some(stratum) = env.field_to_stratum.get(&format!("{name}.{field}"))
                && let Some(l) = env.find_layout(stratum)
                && let Some(f) = l.fields.iter().find(|f| f.name == field)
            {
                return f.ty.clone();
            }
            Ty::Unknown
        }
        _ => Ty::Unknown,
    }
}

fn infer_binop_ty(op: HirBinOp, lhs: &Ty, rhs: &Ty) -> Ty {
    match op {
        HirBinOp::Eq
        | HirBinOp::Ne
        | HirBinOp::Lt
        | HirBinOp::Le
        | HirBinOp::Gt
        | HirBinOp::Ge
        | HirBinOp::And
        | HirBinOp::Or => Ty::Bool,
        HirBinOp::Mul => match (lhs, rhs) {
            (Ty::UnitScalar { dim: a, .. }, Ty::UnitScalar { dim: b, .. }) => {
                let d = a.mul(*b);
                if d == UnitDim::NONE {
                    Ty::F32
                } else {
                    Ty::UnitScalar {
                        name: "unit".to_owned(),
                        dim: d,
                    }
                }
            }
            (Ty::Vec2 | Ty::Vec3 | Ty::Vec4, _) => lhs.clone(),
            (_, Ty::Vec2 | Ty::Vec3 | Ty::Vec4) => rhs.clone(),
            _ => unify_numeric(lhs, rhs),
        },
        HirBinOp::Div => match (lhs, rhs) {
            (Ty::UnitScalar { dim: a, .. }, Ty::UnitScalar { dim: b, .. }) => {
                let d = a.div(*b);
                if d == UnitDim::NONE {
                    Ty::F32
                } else {
                    Ty::UnitScalar {
                        name: "unit".to_owned(),
                        dim: d,
                    }
                }
            }
            (Ty::Vec2 | Ty::Vec3 | Ty::Vec4, _) => lhs.clone(),
            _ => unify_numeric(lhs, rhs),
        },
        _ => {
            if matches!(
                lhs,
                Ty::Vec2 | Ty::Vec3 | Ty::Vec4 | Ty::IVec2 | Ty::IVec3 | Ty::UVec2
            ) {
                lhs.clone()
            } else if matches!(
                rhs,
                Ty::Vec2 | Ty::Vec3 | Ty::Vec4 | Ty::IVec2 | Ty::IVec3 | Ty::UVec2
            ) {
                rhs.clone()
            } else {
                unify_numeric(lhs, rhs)
            }
        }
    }
}

fn unify_numeric(lhs: &Ty, rhs: &Ty) -> Ty {
    if *lhs == Ty::Unknown {
        return rhs.clone();
    }
    if *rhs == Ty::Unknown {
        return lhs.clone();
    }
    match (lhs, rhs) {
        (Ty::F64, _) | (_, Ty::F64) => Ty::F64,
        (Ty::UnitScalar { .. }, _) => lhs.clone(),
        (_, Ty::UnitScalar { .. }) => rhs.clone(),
        (Ty::F32, _) | (_, Ty::F32) => Ty::F32,
        (Ty::U64, _) | (_, Ty::U64) => Ty::U64,
        (Ty::I64, _) | (_, Ty::I64) => Ty::I64,
        (Ty::U32, _) | (_, Ty::U32) => Ty::U32,
        _ => lhs.clone(),
    }
}

fn infer_call_ty(
    recv: Option<&HirExpr>,
    callee: &str,
    generic_args: &[String],
    args: &[HirExpr],
    env: &LowerEnv<'_>,
) -> Ty {
    if recv.is_none() {
        match callee {
            "vec2" => return Ty::Vec2,
            "vec3" => return Ty::Vec3,
            "vec3a" => return Ty::Vec3a,
            "vec4" => return Ty::Vec4,
            "ivec2" => return Ty::IVec2,
            "ivec3" => return Ty::IVec3,
            "uvec2" => return Ty::UVec2,
            "quat" => return Ty::Quat,
            "bits" => return Ty::BitSet(32),
            "sec" | "ms" => {
                return Ty::UnitScalar {
                    name: callee.to_owned(),
                    dim: UnitDim::SEC,
                };
            }
            "meters" => {
                return Ty::UnitScalar {
                    name: "meters".to_owned(),
                    dim: UnitDim::METERS,
                };
            }
            "mps" => {
                return Ty::UnitScalar {
                    name: "mps".to_owned(),
                    dim: UnitDim::MPS,
                };
            }
            "mps2" => {
                return Ty::UnitScalar {
                    name: "mps2".to_owned(),
                    dim: UnitDim::MPS2,
                };
            }
            "hz" => {
                return Ty::UnitScalar {
                    name: "hz".to_owned(),
                    dim: UnitDim::HZ,
                };
            }
            "rad" | "deg" => {
                return Ty::UnitScalar {
                    name: callee.to_owned(),
                    dim: UnitDim::RAD,
                };
            }
            "frames" => {
                return Ty::UnitScalar {
                    name: "frames".to_owned(),
                    dim: UnitDim::FRAMES,
                };
            }
            "length" | "length_sq" | "distance" | "distance_sq" | "dot" => return Ty::F32,
            "min" | "max" | "clamp" | "abs" | "floor" | "ceil" | "round" | "sqrt" | "sqr"
            | "sin" | "cos" | "tan" | "atan2" | "pow" | "lerp" | "mix" | "cross" | "normalize" => {
                return args.first().map_or(Ty::F32, HirExpr::ty);
            }
            "Some" => return args.first().map_or(Ty::Unknown, HirExpr::ty),
            "res" | "res_mut" => {
                return generic_args
                    .first()
                    .map_or(Ty::Unknown, |g| Ty::Named(g.clone()));
            }
            "step_fixed" | "assert" | "require_true" | "despawn" | "trigger" | "emit" => {
                return Ty::Unit;
            }
            _ => {
                if let Some((type_name, method)) = callee.split_once("::")
                    && method == "start"
                {
                    return Ty::Named(type_name.to_owned());
                }
                if let Some(rt) = env.fn_ret_tys.get(callee) {
                    return rt.clone();
                }
            }
        }
    } else {
        match callee {
            "raw" | "as_secs" | "as_millis" => return Ty::F32,
            "is_active" | "consume" | "peek" | "get" | "in" => return Ty::Bool,
            "count_ones" => return Ty::U32,
            "arm" | "clear" | "push" | "set" | "tick" => return Ty::Unit,
            "sample" => {
                if let Some(r) = recv {
                    let cname = expr_short_name(r);
                    if let Some(rt) = env.curve_ret_tys.get(&cname) {
                        return rt.clone();
                    }
                }
                return Ty::F32;
            }
            "unwrap" => return recv.map_or(Ty::Unknown, HirExpr::ty),
            _ => {}
        }
    }
    Ty::Unknown
}

/// Lowers `fsm` state blocks (`on_enter`, `on_tick`, `on_exit`, state fields, and typed
/// transitions) directly from CST.
pub(crate) fn lower_fsm_details(
    fsm_node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
) -> (Vec<HirFsmTransition>, Vec<HirFsmState>) {
    let mut typed_transitions = Vec::new();
    let mut state_hooks = Vec::new();

    for st in ast::children::<ast::StateDecl>(fsm_node) {
        let sname = ast::first_ident(st.syntax())
            .map_or_else(|| "State".to_owned(), |t| t.text().to_owned());

        let mut fields = Vec::new();
        for fd in ast::children::<ast::FieldDecl>(st.syntax()) {
            let fname = fd
                .name()
                .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
            let fty = fd.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
            let fdef = fd
                .syntax()
                .children()
                .find(|c| is_expr_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, &[]));
            fields.push((fname, fty, fdef));
        }

        let mut on_enter = Vec::new();
        let mut on_tick = Vec::new();
        let mut on_exit = Vec::new();

        let mut pending_hook: Option<SyntaxKind> = None;
        for el in st.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok)
                    if matches!(
                        tok.kind(),
                        SyntaxKind::KwOnEnter | SyntaxKind::KwOnTick | SyntaxKind::KwOnExit
                    ) =>
                {
                    pending_hook = Some(tok.kind());
                }
                NodeOrToken::Node(n) if n.kind() == SyntaxKind::Block => {
                    let stmts = lower_block_as_stmts(&n, env, scope, &[], false);
                    match pending_hook.take() {
                        Some(SyntaxKind::KwOnEnter) => on_enter = stmts,
                        Some(SyntaxKind::KwOnTick) => on_tick = stmts,
                        Some(SyntaxKind::KwOnExit) => on_exit = stmts,
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        for tr in ast::children::<ast::TransitionDecl>(st.syntax()) {
            let target =
                ast::first_ident(tr.syntax()).map_or_else(String::new, |t| t.text().to_owned());
            let prio = ast::attrs(tr.syntax())
                .iter()
                .find(|a| ast::attr_name(a).as_deref() == Some("priority"))
                .and_then(|a| {
                    a.syntax()
                        .descendants_with_tokens()
                        .filter_map(|e| e.into_token())
                        .find(|t| t.kind() == SyntaxKind::IntLit)
                        .and_then(|t| t.text().parse::<i32>().ok())
                })
                .unwrap_or(0);
            let target_args = tr
                .syntax()
                .children()
                .find(|c| c.kind() == SyntaxKind::RecordLitExpr)
                .and_then(|rl| ast::child::<ast::FieldInitList>(&rl))
                .map(|fil| lower_field_init_list(fil.syntax(), env, scope, &[]))
                .unwrap_or_default();
            let guard = tr
                .syntax()
                .children()
                .find(|c| is_expr_node(c.kind()) && c.kind() != SyntaxKind::RecordLitExpr)
                .map_or(HirExpr::BoolLit(true), |e| lower_expr(&e, env, scope, &[]));
            typed_transitions.push(HirFsmTransition {
                from_state: sname.clone(),
                to_state: target,
                guard,
                priority: prio,
                target_args,
            });
        }

        state_hooks.push(HirFsmState {
            name: sname,
            fields,
            on_enter,
            on_tick,
            on_exit,
        });
    }

    (typed_transitions, state_hooks)
}

fn direct_tokens(node: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> + '_ {
    node.children_with_tokens()
        .filter_map(|el| el.into_token())
        .filter(|t| !t.kind().is_trivia())
}

pub(crate) fn is_type_node(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::TypeRef
            | SyntaxKind::ArrayType
            | SyntaxKind::RefType
            | SyntaxKind::PtrTermType
            | SyntaxKind::TupleType
    )
}

pub(crate) fn is_pattern_node(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Pattern
            | SyntaxKind::TuplePattern
            | SyntaxKind::TupleStructPattern
            | SyntaxKind::WildcardPattern
    )
}

pub(crate) fn is_expr_node(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::IfExpr
            | SyntaxKind::MatchExpr
            | SyntaxKind::ForExpr
            | SyntaxKind::BinaryExpr
            | SyntaxKind::PrefixExpr
            | SyntaxKind::CastExpr
            | SyntaxKind::PostfixCallExpr
            | SyntaxKind::FieldExpr
            | SyntaxKind::IndexExpr
            | SyntaxKind::StructLitExpr
            | SyntaxKind::BundleLitExpr
            | SyntaxKind::RecordLitExpr
            | SyntaxKind::ArrayLitExpr
            | SyntaxKind::TupleExpr
            | SyntaxKind::ParenExpr
            | SyntaxKind::PathExpr
            | SyntaxKind::LiteralExpr
            | SyntaxKind::SpawnExpr
            | SyntaxKind::SpawnBatchExpr
            | SyntaxKind::DespawnAllExpr
            | SyntaxKind::InsertExpr
            | SyntaxKind::RemoveExpr
    )
}

fn token_to_assign_op(tok: SyntaxToken) -> Option<HirAssignOp> {
    match tok.kind() {
        SyntaxKind::Eq => Some(HirAssignOp::Set),
        SyntaxKind::PlusEq => Some(HirAssignOp::AddAssign),
        SyntaxKind::MinusEq => Some(HirAssignOp::SubAssign),
        SyntaxKind::StarEq => Some(HirAssignOp::MulAssign),
        SyntaxKind::SlashEq => Some(HirAssignOp::DivAssign),
        SyntaxKind::PercentEq => Some(HirAssignOp::RemAssign),
        SyntaxKind::AmpEq => Some(HirAssignOp::BitAndAssign),
        SyntaxKind::PipeEq => Some(HirAssignOp::BitOrAssign),
        SyntaxKind::CaretEq => Some(HirAssignOp::BitXorAssign),
        SyntaxKind::ShlEq => Some(HirAssignOp::ShlAssign),
        SyntaxKind::ShrEq => Some(HirAssignOp::ShrAssign),
        _ => None,
    }
}

fn token_to_bin_op(tok: SyntaxToken) -> Option<HirBinOp> {
    match tok.kind() {
        SyntaxKind::Plus => Some(HirBinOp::Add),
        SyntaxKind::Minus => Some(HirBinOp::Sub),
        SyntaxKind::Star => Some(HirBinOp::Mul),
        SyntaxKind::Slash => Some(HirBinOp::Div),
        SyntaxKind::Percent => Some(HirBinOp::Rem),
        SyntaxKind::Amp => Some(HirBinOp::BitAnd),
        SyntaxKind::Pipe => Some(HirBinOp::BitOr),
        SyntaxKind::Caret => Some(HirBinOp::BitXor),
        SyntaxKind::Shl => Some(HirBinOp::Shl),
        SyntaxKind::Shr => Some(HirBinOp::Shr),
        SyntaxKind::EqEq => Some(HirBinOp::Eq),
        SyntaxKind::Ne => Some(HirBinOp::Ne),
        SyntaxKind::Lt => Some(HirBinOp::Lt),
        SyntaxKind::Le => Some(HirBinOp::Le),
        SyntaxKind::Gt => Some(HirBinOp::Gt),
        SyntaxKind::Ge => Some(HirBinOp::Ge),
        SyntaxKind::AmpAmp => Some(HirBinOp::And),
        SyntaxKind::PipePipe => Some(HirBinOp::Or),
        SyntaxKind::DotDot => Some(HirBinOp::Range),
        SyntaxKind::DotDotEq => Some(HirBinOp::RangeInclusive),
        _ => None,
    }
}
