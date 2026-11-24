//! Direct `rowan` CST -> typed HIR lowering for Strata v2.0 (`strata_sema`).
//!
//! Lowers statements, expressions, queries, `spawn`, `spawn_batch`, `despawn_all`, `insert`,
//! `remove`, `trigger`, `emit`, `atomic`/`on_rollback`, `timeline`, `task`, `fsm`, `migrate`,
//! `table`, `curve`, `const`, `object`, `sim_test`, `fn`, `schedule`, and `FieldDecl` defaults
//! directly from lossless CST nodes without raw-string splitting or regex heuristics.

use crate::access::{QueryAccessDesc, TermAccessMode};
use crate::hir::{
    AuthorityKind, HirAssignOp, HirAtomic, HirBinOp, HirCall, HirCompInit, HirExpr, HirFor,
    HirForIter, HirFsmState, HirFsmTransition, HirLValue, HirMatch, HirMatchArm, HirParam,
    HirParamKind, HirPattern, HirQuery, HirQueryTerm, HirReduceEntry, HirSpawn, HirStmt, HirUnOp,
};
use crate::infer::{
    build_array_lit, coerce_binary_operands, coerce_compound_assign_rhs, expr_definitely_diverges,
    infer_call_ty, infer_query_ty, option_call_primary, resolve_index_ty, resolve_query_term_ty,
    stmts_definitely_diverges, unify_branch_tys,
};
use crate::layout::{EnumDef, SolvedLayout};
use crate::types::{Ty, UnitDim, parse_type_node, parse_type_node_with_user_types};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{self, AstNode};
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode, SyntaxToken};

/// Module-wide symbol and layout lookup context used while lowering CST nodes to typed HIR.
#[derive(Debug, Clone)]
pub(crate) struct LowerEnv<'a> {
    pub(crate) module_path: &'a str,
    pub(crate) layouts: &'a IndexMap<String, SolvedLayout>,
    pub(crate) item_fields: &'a IndexMap<String, Vec<(String, Ty)>>,
    pub(crate) user_types: &'a HashSet<String>,
    pub(crate) field_to_stratum: &'a HashMap<String, String>,
    pub(crate) enums: &'a IndexMap<String, EnumDef>,
    pub(crate) const_tys: HashMap<String, Ty>,
    pub(crate) table_fields: HashMap<String, Vec<(String, Ty)>>,
    pub(crate) curve_ret_tys: HashMap<String, Ty>,
    pub(crate) fn_ret_tys: HashMap<String, Ty>,
    pub(crate) objects: HashSet<String>,
    pub(crate) sparse_components: HashSet<String>,
    pub(crate) authorities: IndexMap<String, AuthorityKind>,
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

    pub(crate) fn find_item_fields(&self, name: &str) -> Option<&'a [(String, Ty)]> {
        let canon = format!("{}::{name}", self.module_path);
        self.item_fields
            .get(&canon)
            .or_else(|| self.item_fields.get(name))
            .or_else(|| {
                self.item_fields
                    .iter()
                    .find(|(k, _)| k.rsplit("::").next() == Some(name) || *k == name)
                    .map(|(_, v)| v)
            })
            .map(Vec::as_slice)
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

    pub(crate) fn is_server_authoritative(&self, key: &str) -> bool {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(auth) = self.authorities.get(trimmed) {
            return *auth == AuthorityKind::Server;
        }
        if let Some((prefix, suffix)) = trimmed.rsplit_once("::") {
            if let Some(auth) = self.authorities.get(prefix) {
                return *auth == AuthorityKind::Server;
            }
            if let Some(auth) = self.authorities.get(suffix) {
                return *auth == AuthorityKind::Server;
            }
        }
        if let Some((base, _)) = trimmed.split_once("__")
            && let Some(auth) = self.authorities.get(base)
        {
            return *auth == AuthorityKind::Server;
        }
        false
    }
}

/// Structured query-row provenance shape carried through expressions, tuples, and bindings.
#[derive(Debug, Clone)]
pub(crate) enum QueryShape {
    Row(Vec<HirQueryTerm>),
    Tuple(Vec<Option<QueryShape>>),
}

/// Variable binding visible in lexical scope during CST lowering.
#[derive(Debug, Clone)]
pub(crate) enum ScopeBinding {
    Var(Ty),
    MultiVar(Vec<Ty>),
    QueryRow {
        terms: Vec<HirQueryTerm>,
        extra_tys: Vec<Ty>,
    },
    QueryTuple {
        ty: Ty,
        elems: Vec<Option<QueryShape>>,
        extra_tys: Vec<Ty>,
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

    pub(crate) fn assign(&mut self, name: &str, binding: ScopeBinding) {
        for frame in self.frames.iter_mut().rev() {
            if let Some(slot) = frame.get_mut(name) {
                *slot = binding;
                return;
            }
        }
        self.insert(name.to_owned(), binding);
    }

    pub(crate) fn get(&self, name: &str) -> Option<&ScopeBinding> {
        for frame in self.frames.iter().rev() {
            if let Some(b) = frame.get(name) {
                return Some(b);
            }
        }
        None
    }

    pub(crate) fn merge_from(
        &mut self,
        pre_frames: &[HashMap<String, ScopeBinding>],
        branches: &[Vec<HashMap<String, ScopeBinding>>],
        env: &LowerEnv<'_>,
    ) {
        self.frames = pre_frames.to_vec();
        for (frame_idx, out_frame) in self.frames.iter_mut().enumerate() {
            let mut keys: Vec<String> = pre_frames[frame_idx].keys().cloned().collect();
            for br in branches {
                if let Some(bf) = br.get(frame_idx) {
                    for k in bf.keys() {
                        if !keys.contains(k) {
                            keys.push(k.clone());
                        }
                    }
                }
            }
            for k in keys {
                let mut acc: Option<ScopeBinding> = None;
                for br in branches {
                    let b = br.get(frame_idx).and_then(|bf| bf.get(&k));
                    acc = merge_opt_scope_bindings(acc.as_ref(), b, env);
                }
                if let Some(merged) = acc {
                    out_frame.insert(k, merged);
                }
            }
        }
    }
}

fn push_extra_tys_from_binding(out: &mut Vec<Ty>, binding: &ScopeBinding) {
    match binding {
        ScopeBinding::Var(t) | ScopeBinding::Resource { ty: t, .. } => {
            if !matches!(t, Ty::Ref(s) if s == "Entity") {
                push_unique_ty(out, t.clone());
            }
        }
        ScopeBinding::MultiVar(ts) => {
            for t in ts {
                if !matches!(t, Ty::Ref(s) if s == "Entity") {
                    push_unique_ty(out, t.clone());
                }
            }
        }
        ScopeBinding::QueryRow { extra_tys, .. } => {
            for t in extra_tys {
                push_unique_ty(out, t.clone());
            }
        }
        ScopeBinding::QueryTuple { ty, extra_tys, .. } => {
            push_unique_ty(out, ty.clone());
            for t in extra_tys {
                push_unique_ty(out, t.clone());
            }
        }
        ScopeBinding::SpatialCandidate | ScopeBinding::Trigger { .. } => {}
    }
}

fn merge_opt_scope_bindings(
    a: Option<&ScopeBinding>,
    b: Option<&ScopeBinding>,
    env: &LowerEnv<'_>,
) -> Option<ScopeBinding> {
    match (a, b) {
        (None, None) => None,
        (
            Some(ScopeBinding::QueryRow {
                terms: t1,
                extra_tys: e1,
            }),
            Some(ScopeBinding::QueryRow {
                terms: t2,
                extra_tys: e2,
            }),
        ) => {
            let mut extra_tys = e1.clone();
            for t in e2 {
                push_unique_ty(&mut extra_tys, t.clone());
            }
            Some(ScopeBinding::QueryRow {
                terms: merge_query_terms(t1.clone(), t2.clone()),
                extra_tys,
            })
        }
        (
            Some(ScopeBinding::QueryTuple {
                ty: ty1,
                elems: e1,
                extra_tys: x1,
            }),
            Some(ScopeBinding::QueryTuple {
                ty: ty2,
                elems: e2,
                extra_tys: x2,
            }),
        ) => {
            let elems = match merge_query_shapes(
                Some(QueryShape::Tuple(e1.clone())),
                Some(QueryShape::Tuple(e2.clone())),
            ) {
                Some(QueryShape::Tuple(es)) => es,
                _ => e1.clone(),
            };
            let mut extra_tys = Vec::new();
            push_unique_ty(&mut extra_tys, ty1.clone());
            push_unique_ty(&mut extra_tys, ty2.clone());
            for t in x1.iter().chain(x2.iter()) {
                push_unique_ty(&mut extra_tys, t.clone());
            }
            let ty = pick_authoritative_ty(&extra_tys, env);
            Some(ScopeBinding::QueryTuple {
                ty,
                elems,
                extra_tys,
            })
        }
        (Some(ScopeBinding::QueryRow { terms, extra_tys }), Some(other))
        | (Some(other), Some(ScopeBinding::QueryRow { terms, extra_tys })) => {
            let mut merged_extra = extra_tys.clone();
            push_extra_tys_from_binding(&mut merged_extra, other);
            Some(ScopeBinding::QueryRow {
                terms: terms.clone(),
                extra_tys: merged_extra,
            })
        }
        (
            Some(ScopeBinding::QueryTuple {
                ty,
                elems,
                extra_tys,
            }),
            Some(other),
        )
        | (
            Some(other),
            Some(ScopeBinding::QueryTuple {
                ty,
                elems,
                extra_tys,
            }),
        ) => {
            let mut merged_extra = Vec::new();
            push_unique_ty(&mut merged_extra, ty.clone());
            for t in extra_tys {
                push_unique_ty(&mut merged_extra, t.clone());
            }
            push_extra_tys_from_binding(&mut merged_extra, other);
            let picked = pick_authoritative_ty(&merged_extra, env);
            Some(ScopeBinding::QueryTuple {
                ty: picked,
                elems: elems.clone(),
                extra_tys: merged_extra,
            })
        }
        (Some(ScopeBinding::Var(t1)), Some(ScopeBinding::Var(t2))) => {
            let mut tys = Vec::new();
            push_unique_ty(&mut tys, t1.clone());
            push_unique_ty(&mut tys, t2.clone());
            if tys.len() <= 1 {
                Some(ScopeBinding::Var(
                    tys.into_iter().next().unwrap_or(Ty::Unknown),
                ))
            } else {
                Some(ScopeBinding::MultiVar(tys))
            }
        }
        (Some(ScopeBinding::MultiVar(ts)), Some(ScopeBinding::Var(t)))
        | (Some(ScopeBinding::Var(t)), Some(ScopeBinding::MultiVar(ts))) => {
            let mut tys = ts.clone();
            push_unique_ty(&mut tys, t.clone());
            if tys.len() <= 1 {
                Some(ScopeBinding::Var(
                    tys.into_iter().next().unwrap_or(Ty::Unknown),
                ))
            } else {
                Some(ScopeBinding::MultiVar(tys))
            }
        }
        (Some(ScopeBinding::MultiVar(ts1)), Some(ScopeBinding::MultiVar(ts2))) => {
            let mut tys = ts1.clone();
            for t in ts2 {
                push_unique_ty(&mut tys, t.clone());
            }
            if tys.len() <= 1 {
                Some(ScopeBinding::Var(
                    tys.into_iter().next().unwrap_or(Ty::Unknown),
                ))
            } else {
                Some(ScopeBinding::MultiVar(tys))
            }
        }
        (None, Some(x)) | (Some(x), _) => Some(x.clone()),
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
            let (stem, name, dim, factor) = Ty::split_unit_literal(text)?;
            let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
            let raw = cleaned.parse::<f64>().ok()?;
            let ty = Ty::UnitScalar {
                name: name.to_owned(),
                dim,
            };
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
                    ty: suffix_ty.unwrap_or(Ty::F32),
                });
            }
            let raw = parse_radix_u128(&cleaned)?;
            let value = i64::try_from(raw).unwrap_or(raw as i64);
            let ty = suffix_ty.unwrap_or_else(|| {
                if raw > u32::MAX as u128 {
                    Ty::I64
                } else {
                    Ty::I32
                }
            });
            Some(HirExpr::IntLit { value, ty })
        }
        _ => None,
    }
}

fn split_int_suffix(text: &str) -> (&str, Option<Ty>, bool) {
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
            return (stem, Some(ty.clone()), *is_f);
        }
    }
    (text, None, false)
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
        let (kind, ty, trigger_target) = type_node
            .as_ref()
            .map_or((HirParamKind::Value, Ty::Unknown, None), |n| {
                classify_param_type_with_user_types(n, env.user_types)
            });
        let default = p
            .syntax()
            .children()
            .find(|c| is_expr_or_block_node(c.kind()))
            .map(|e| lower_expr_with_expected(&e, env, scope, &[], Some(&ty)));
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
        let (kind, ty, trigger_target) = type_node
            .as_ref()
            .map_or((HirParamKind::Value, Ty::Unknown, None), |n| {
                classify_param_type_with_user_types(n, env.user_types)
            });

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
    classify_param_type_with_user_types(node, &HashSet::new())
}

pub(crate) fn classify_param_type_with_user_types(
    node: &SyntaxNode,
    user_types: &HashSet<String>,
) -> (HirParamKind, Ty, Option<String>) {
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
                let inner_ty = parse_type_node_with_user_types(&inner, user_types);
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
            (
                HirParamKind::Value,
                parse_type_node_with_user_types(node, user_types),
                None,
            )
        }
        _ => (
            HirParamKind::Value,
            parse_type_node_with_user_types(node, user_types),
            None,
        ),
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
        SyntaxKind::TypeRef => {
            let base = typeref_base_name(node);
            if matches!(base.as_str(), "Option" | "std::option::Option")
                && let Some(ga) = node
                    .children()
                    .find(|c| c.kind() == SyntaxKind::GenericArgs)
                && let Some(ref_node) = ga.children().find(|c| c.kind() == SyntaxKind::RefType)
            {
                let has_mut = direct_tokens(&ref_node).any(|t| t.kind() == SyntaxKind::KwMut);
                let mode = if has_mut {
                    TermAccessMode::OptionalWrite
                } else {
                    TermAccessMode::OptionalRead
                };
                return (mode, unwrap_inner_typeref(&ref_node));
            }
            (TermAccessMode::Read, Some(node.clone()))
        }
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
            .map(|fil| {
                lower_field_init_list_for_owner(fil.syntax(), env, scope, queries, Some(&component))
            })
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
    lower_field_init_list_for_owner(fil, env, scope, queries, None)
}

pub(crate) fn lower_field_init_list_for_owner(
    fil: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    owner: Option<&str>,
) -> Vec<(String, HirExpr)> {
    let owner_fields = owner.and_then(|name| env.find_item_fields(name));
    let mut out = Vec::new();
    for fi in ast::children::<ast::FieldInit>(fil) {
        let fname = ast::first_ident(fi.syntax()).map_or_else(String::new, |t| t.text().to_owned());
        let expected_field_ty =
            owner_fields.and_then(|fs| fs.iter().find(|(k, _)| k == &fname).map(|(_, ty)| ty));
        let expr = if let Some(expr_node) = fi
            .syntax()
            .children()
            .find(|c| is_expr_or_block_node(c.kind()))
        {
            lower_expr_with_expected(&expr_node, env, scope, queries, expected_field_ty)
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
    lower_block_with_expected(block, env, scope, queries, None)
}

/// Lowers a `Block` CST node into `(stmts, optional_tail_expr)` with optional expected tail type.
pub(crate) fn lower_block_with_expected(
    block: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    expected: Option<&Ty>,
) -> (Vec<HirStmt>, Option<HirExpr>) {
    scope.push();
    let mut stmts = Vec::new();
    let mut tail = None;

    let children: Vec<SyntaxNode> = block.children().collect();
    for (idx, ch) in children.iter().enumerate() {
        let is_last = idx + 1 == children.len();
        if is_last && is_expr_or_block_node(ch.kind()) {
            tail = Some(lower_expr_with_expected(ch, env, scope, queries, expected));
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
    if !trailing_is_return {
        scope.push();
        let mut stmts = Vec::new();
        for ch in block.children() {
            lower_stmt_node(&ch, env, scope, queries, &mut stmts);
        }
        scope.pop();
        return stmts;
    }
    let (mut stmts, tail) = lower_block(block, env, scope, queries);
    if let Some(t) = tail {
        stmts.push(HirStmt::Return(Some(t)));
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
                .map(|t| parse_type_node_with_user_types(&t, env.user_types));
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
                |e| lower_expr_with_expected(e, env, scope, queries, explicit_ty.as_ref()),
            );

            let pre_else_frames = scope.frames.clone();
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
            scope.frames = pre_else_frames;

            let bound_ty = explicit_ty.clone().unwrap_or_else(|| value.ty());
            let src_for_bind = explicit_ty
                .as_ref()
                .is_none_or(|t| *t == Ty::Unknown)
                .then_some(&value);
            bind_pattern(&pattern, bound_ty, src_for_bind, env, scope);

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
                .find(|c| is_expr_or_block_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            out.push(HirStmt::Return(val));
        }
        SyntaxKind::BreakStmt => {
            let val = node
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            out.push(HirStmt::Break(val));
        }
        SyntaxKind::ContinueStmt => {
            out.push(HirStmt::Continue);
        }
        SyntaxKind::WhileStmt => {
            let cond_expr_node = node.children().find(|c| is_expr_node(c.kind()));
            let blocks: Vec<_> = node
                .children()
                .filter(|c| c.kind() == SyntaxKind::Block)
                .collect();
            let (cond_node, body_block) = if cond_expr_node.is_none() && blocks.len() >= 2 {
                (Some(blocks[0].clone()), blocks.get(1).cloned())
            } else {
                (cond_expr_node, blocks.first().cloned())
            };
            let cond = cond_node.map_or(HirExpr::BoolLit(false), |e| {
                lower_expr(&e, env, scope, queries)
            });
            let pre_frames = scope.frames.clone();
            let body = body_block
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            let post_frames = scope.frames.clone();
            scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);
            out.push(HirStmt::While { cond, body });
        }
        SyntaxKind::LoopStmt => {
            let pre_frames = scope.frames.clone();
            let body = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Block)
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            let post_frames = scope.frames.clone();
            scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);
            out.push(HirStmt::Loop { body });
        }
        SyntaxKind::AtomicStmt => {
            let blocks: Vec<_> = node
                .children()
                .filter(|c| c.kind() == SyntaxKind::Block)
                .collect();
            let pre_frames = scope.frames.clone();
            let body = blocks
                .first()
                .map(|b| lower_block_as_stmts(b, env, scope, queries, false))
                .unwrap_or_default();
            let body_frames = scope.frames.clone();
            scope.frames = pre_frames.clone();
            let on_rollback = blocks
                .get(1)
                .map(|b| lower_block_as_stmts(b, env, scope, queries, false))
                .unwrap_or_default();
            let rb_frames = scope.frames.clone();
            scope.merge_from(&pre_frames, &[body_frames, rb_frames], env);
            out.push(HirStmt::Atomic(HirAtomic { body, on_rollback }));
        }
        SyntaxKind::AbortIfStmt => {
            let cond_expr_node = node.children().find(|c| is_expr_node(c.kind()));
            let blocks: Vec<_> = node
                .children()
                .filter(|c| c.kind() == SyntaxKind::Block)
                .collect();
            let (cond_node, cleanup_block) = if cond_expr_node.is_none() && blocks.len() >= 2 {
                (Some(blocks[0].clone()), blocks.get(1).cloned())
            } else {
                (cond_expr_node, blocks.first().cloned())
            };
            let cond = cond_node.map_or(HirExpr::BoolLit(false), |e| {
                lower_expr(&e, env, scope, queries)
            });
            let pre_frames = scope.frames.clone();
            let cleanup = cleanup_block
                .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                .unwrap_or_default();
            scope.frames = pre_frames;
            out.push(HirStmt::AbortIf { cond, cleanup });
        }
        SyntaxKind::WaitStmt => {
            let dur = node
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map_or(
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
            let pre_frames = scope.frames.clone();
            let mut branch_frames = Vec::new();
            let branches: Vec<_> = ast::children::<ast::BranchStmt>(node)
                .map(|br| {
                    scope.frames = pre_frames.clone();
                    let stmts = br
                        .syntax()
                        .children()
                        .find(|c| c.kind() == SyntaxKind::Block)
                        .map(|b| lower_block_as_stmts(&b, env, scope, queries, false))
                        .unwrap_or_default();
                    branch_frames.push(scope.frames.clone());
                    stmts
                })
                .collect();
            if branch_frames.is_empty() {
                scope.frames = pre_frames;
            } else {
                scope.merge_from(&pre_frames, &branch_frames, env);
            }
            out.push(HirStmt::Race { branches });
        }
        SyntaxKind::ExprStmt => {
            if let Some(expr_node) = node.children().find(|c| is_expr_or_block_node(c.kind())) {
                lower_expr_as_stmt(&expr_node, env, scope, queries, out);
            }
        }
        other if is_expr_or_block_node(other) => {
            lower_expr_as_stmt(node, env, scope, queries, out);
        }
        _ => {}
    }
}

fn try_lower_assign_binary_expr(
    expr_node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> Option<HirStmt> {
    if expr_node.kind() != SyntaxKind::BinaryExpr {
        return None;
    }
    let op = direct_tokens(expr_node).find_map(token_to_assign_op)?;
    let exprs: Vec<_> = expr_node
        .children()
        .filter(|c| is_expr_or_block_node(c.kind()))
        .collect();
    if exprs.len() < 2 {
        return None;
    }
    let target = lower_lvalue(&exprs[0], env, scope, queries);
    let mut value = lower_expr_with_expected(&exprs[1], env, scope, queries, Some(target.ty()));
    if op != HirAssignOp::Set {
        value = coerce_compound_assign_rhs(target.ty(), value);
    }
    if op == HirAssignOp::Set
        && let HirLValue::Local { ref name, .. } = target
    {
        let cands = resolve_expr_candidate_tys(&value, env, scope);
        if let Some(shape) = resolve_expr_query_shape(&value, env, scope) {
            match shape {
                QueryShape::Row(terms) => {
                    let mut extra_tys = Vec::new();
                    for c in &cands {
                        if !matches!(c, Ty::Ref(s) if s == "Entity") {
                            push_unique_ty(&mut extra_tys, c.clone());
                        }
                    }
                    scope.assign(name, ScopeBinding::QueryRow { terms, extra_tys });
                }
                QueryShape::Tuple(elems) => {
                    let mut extra_tys = Vec::new();
                    for c in &cands {
                        push_unique_ty(&mut extra_tys, c.clone());
                    }
                    push_unique_ty(&mut extra_tys, value.ty());
                    let ty = pick_authoritative_ty(&extra_tys, env);
                    scope.assign(
                        name,
                        ScopeBinding::QueryTuple {
                            ty,
                            elems,
                            extra_tys,
                        },
                    );
                }
            }
        } else {
            let binding = if cands.len() > 1 {
                ScopeBinding::MultiVar(cands)
            } else {
                ScopeBinding::Var(value.ty())
            };
            scope.assign(name, binding);
        }
    }
    Some(HirStmt::Assign { target, op, value })
}

fn lower_expr_as_stmt(
    expr_node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    out: &mut Vec<HirStmt>,
) {
    // Check assignment expression (`a = b`, `a += b`, etc.)
    if let Some(assign_stmt) = try_lower_assign_binary_expr(expr_node, env, scope, queries) {
        out.push(assign_stmt);
        return;
    }

    let lowered = lower_expr(expr_node, env, scope, queries);
    if let HirExpr::Call(ref call) = lowered
        && call.receiver.is_none()
    {
        match call.callee.as_str() {
            "require_true" if !call.args.is_empty() => {
                out.push(HirStmt::RequireTrue(call.args[0].clone()));
                for extra in call.args.iter().skip(1) {
                    out.push(HirStmt::Expr(extra.clone()));
                }
                return;
            }
            "trigger" if !call.args.is_empty() => {
                let propagate = call.arg_names.iter().zip(call.args.iter()).any(|(n, a)| {
                    n.as_deref() == Some("propagate") && matches!(a, HirExpr::BoolLit(true))
                });
                let mut pos_args = Vec::new();
                let mut prop_extras = Vec::new();
                for (i, a) in call.args.iter().enumerate() {
                    let is_prop =
                        call.arg_names.get(i).and_then(|n| n.as_deref()) == Some("propagate");
                    if is_prop {
                        if !matches!(a, HirExpr::BoolLit(_)) {
                            prop_extras.push(a.clone());
                        }
                    } else {
                        pos_args.push(a.clone());
                    }
                }
                if pos_args.len() >= 2 {
                    out.push(HirStmt::Trigger {
                        target: Some(Box::new(pos_args[0].clone())),
                        event: Box::new(pos_args[1].clone()),
                        propagate,
                    });
                    for extra in pos_args.into_iter().skip(2) {
                        out.push(HirStmt::Expr(extra));
                    }
                    for extra in prop_extras {
                        out.push(HirStmt::Expr(extra));
                    }
                    return;
                } else if let Some(ev) = pos_args.into_iter().next() {
                    out.push(HirStmt::Trigger {
                        target: None,
                        event: Box::new(ev),
                        propagate,
                    });
                    for extra in prop_extras {
                        out.push(HirStmt::Expr(extra));
                    }
                    return;
                }
            }
            "emit" if !call.args.is_empty() => {
                out.push(HirStmt::Emit(call.args[0].clone()));
                for extra in call.args.iter().skip(1) {
                    out.push(HirStmt::Expr(extra.clone()));
                }
                return;
            }
            "despawn" if !call.args.is_empty() => {
                out.push(HirStmt::Despawn(call.args[0].clone()));
                for extra in call.args.iter().skip(1) {
                    out.push(HirStmt::Expr(extra.clone()));
                }
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
                for extra in call.args.iter().skip(3) {
                    out.push(HirStmt::Expr(extra.clone()));
                }
                return;
            }
            "remove_relation" if call.args.len() >= 2 => {
                let rel = call.generic_args.first().cloned().unwrap_or_default();
                out.push(HirStmt::RemoveRelation {
                    relation: rel,
                    entity: Box::new(call.args[0].clone()),
                    target: Box::new(call.args[1].clone()),
                });
                for extra in call.args.iter().skip(2) {
                    out.push(HirStmt::Expr(extra.clone()));
                }
                return;
            }
            _ => {}
        }
    }
    out.push(HirStmt::Expr(lowered));
}

fn unwrap_paren_expr(node: &SyntaxNode) -> SyntaxNode {
    let mut cur = node.clone();
    while cur.kind() == SyntaxKind::ParenExpr {
        let Some(inner) = cur.children().find(|c| is_expr_or_block_node(c.kind())) else {
            break;
        };
        cur = inner;
    }
    cur
}

fn lower_lvalue(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirLValue {
    lower_lvalue_candidates(node, env, scope, queries).0
}

fn lower_lvalue_candidates(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> (HirLValue, Vec<Ty>) {
    match node.kind() {
        SyntaxKind::ParenExpr => {
            if let Some(inner) = node.children().find(|c| is_expr_or_block_node(c.kind())) {
                return lower_lvalue_candidates(&inner, env, scope, queries);
            }
            (
                HirLValue::Local {
                    name: "_".to_owned(),
                    ty: Ty::Unknown,
                },
                Vec::new(),
            )
        }
        SyntaxKind::PathExpr => {
            let name = node
                .children()
                .find(|c| c.kind() == SyntaxKind::Path)
                .and_then(ast::Path::cast)
                .map(|p| ast::path_text(&p))
                .unwrap_or_default();
            match scope.get(&name) {
                Some(ScopeBinding::MultiVar(tys)) => {
                    let cands = tys.clone();
                    let ty = pick_authoritative_ty(&cands, env);
                    (HirLValue::Local { name, ty }, cands)
                }
                Some(ScopeBinding::QueryRow { extra_tys, .. }) => {
                    let mut cands = vec![Ty::Ref("Entity".to_owned())];
                    for t in extra_tys {
                        push_unique_ty(&mut cands, t.clone());
                    }
                    let ty = lookup_var_ty(&name, env, scope);
                    (HirLValue::Local { name, ty }, cands)
                }
                Some(ScopeBinding::QueryTuple { ty, extra_tys, .. }) => {
                    let mut cands = Vec::new();
                    push_unique_ty(&mut cands, ty.clone());
                    for t in extra_tys {
                        push_unique_ty(&mut cands, t.clone());
                    }
                    let picked = pick_authoritative_ty(&cands, env);
                    (HirLValue::Local { name, ty: picked }, cands)
                }
                _ => {
                    let ty = lookup_var_ty(&name, env, scope);
                    let cands = if ty != Ty::Unknown {
                        vec![ty.clone()]
                    } else {
                        Vec::new()
                    };
                    (HirLValue::Local { name, ty }, cands)
                }
            }
        }
        SyntaxKind::FieldExpr => {
            let base_node = node.children().find(|c| is_expr_or_block_node(c.kind()));
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
                let unwrapped = unwrap_paren_expr(&bn);
                if !matches!(
                    unwrapped.kind(),
                    SyntaxKind::PathExpr | SyntaxKind::FieldExpr | SyntaxKind::IndexExpr
                ) && is_expr_or_block_node(unwrapped.kind())
                {
                    let expr = lower_expr(&unwrapped, env, scope, queries);
                    let mut field_cands = Vec::new();
                    if is_query_like_expr(&expr)
                        && let Some(terms) = resolve_expr_query_terms(&expr, env, scope)
                    {
                        let matching: Vec<&HirQueryTerm> =
                            terms.iter().filter(|t| t.alias == field).collect();
                        for t in &matching {
                            push_unique_ty(&mut field_cands, resolve_query_term_ty(t, env));
                        }
                        if field == "id" && field_cands.is_empty() {
                            field_cands.push(Ty::Ref("Entity".to_owned()));
                        }
                        let base_cands = resolve_expr_candidate_tys(&expr, env, scope);
                        for bty in &base_cands {
                            push_unique_ty(
                                &mut field_cands,
                                resolve_field_ty_from_base_ty(bty, &field, env),
                            );
                        }
                        let field_ty = pick_authoritative_ty(&field_cands, env);
                        let base = HirLValue::Expr(Box::new(expr));
                        return (
                            HirLValue::Field {
                                base: Box::new(base),
                                field,
                                ty: field_ty,
                            },
                            field_cands,
                        );
                    }
                    let (base, base_cands) = expr_to_lvalue_candidates(&expr, env, scope);
                    if let Some(terms) = resolve_expr_query_terms(&expr, env, scope) {
                        for t in &terms {
                            if t.alias == field {
                                push_unique_ty(&mut field_cands, resolve_query_term_ty(t, env));
                            }
                        }
                        if field == "id" && field_cands.is_empty() {
                            field_cands.push(Ty::Ref("Entity".to_owned()));
                        }
                    }
                    for bty in &base_cands {
                        push_unique_ty(
                            &mut field_cands,
                            resolve_field_ty_from_base_ty(bty, &field, env),
                        );
                    }
                    let field_ty = if field_cands.is_empty() {
                        resolve_lvalue_field_ty(&base, &field, env, scope)
                    } else {
                        pick_authoritative_ty(&field_cands, env)
                    };
                    return (
                        HirLValue::Field {
                            base: Box::new(base),
                            field,
                            ty: field_ty,
                        },
                        field_cands,
                    );
                }
                let (base, base_cands) = lower_lvalue_candidates(&bn, env, scope, queries);
                let mut field_cands = Vec::new();
                if let HirLValue::Local { ref name, .. } = base
                    && let Some(ScopeBinding::QueryRow { terms, extra_tys }) = scope.get(name)
                {
                    for t in terms {
                        if t.alias == field {
                            push_unique_ty(&mut field_cands, resolve_query_term_ty(t, env));
                        }
                    }
                    for ety in extra_tys {
                        push_unique_ty(
                            &mut field_cands,
                            resolve_field_ty_from_base_ty(ety, &field, env),
                        );
                    }
                }
                for bty in &base_cands {
                    push_unique_ty(
                        &mut field_cands,
                        resolve_field_ty_from_base_ty(bty, &field, env),
                    );
                }
                let field_ty = if field_cands.is_empty() {
                    resolve_lvalue_field_ty(&base, &field, env, scope)
                } else {
                    pick_authoritative_ty(&field_cands, env)
                };
                (
                    HirLValue::Field {
                        base: Box::new(base),
                        field,
                        ty: field_ty,
                    },
                    field_cands,
                )
            } else {
                (
                    HirLValue::Local {
                        name: field,
                        ty: Ty::Unknown,
                    },
                    Vec::new(),
                )
            }
        }
        SyntaxKind::IndexExpr => {
            let exprs: Vec<_> = node
                .children()
                .filter(|c| is_expr_or_block_node(c.kind()))
                .collect();
            let (base, base_cands) = exprs.first().map_or_else(
                || {
                    (
                        HirLValue::Local {
                            name: "_".to_owned(),
                            ty: Ty::Unknown,
                        },
                        Vec::new(),
                    )
                },
                |b| lower_lvalue_candidates(b, env, scope, queries),
            );
            let index = exprs.get(1).map_or(
                HirExpr::IntLit {
                    value: 0,
                    ty: Ty::I32,
                },
                |i| lower_expr(i, env, scope, queries),
            );
            let mut elem_cands = Vec::new();
            for bty in &base_cands {
                let mut cur = bty;
                while let Ty::Borrow { inner, .. } = cur {
                    cur = inner.as_ref();
                }
                match cur {
                    Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => {
                        push_unique_ty(&mut elem_cands, (**elem).clone());
                    }
                    Ty::BitSet(_) => push_unique_ty(&mut elem_cands, Ty::Bool),
                    _ => {}
                }
            }
            if elem_cands.is_empty() {
                let mut cur = base.ty();
                loop {
                    match cur {
                        Ty::Borrow { inner, .. } => cur = inner.as_ref(),
                        Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => {
                            push_unique_ty(&mut elem_cands, (**elem).clone());
                            break;
                        }
                        Ty::BitSet(_) => {
                            push_unique_ty(&mut elem_cands, Ty::Bool);
                            break;
                        }
                        _ => break,
                    }
                }
            }
            let elem_ty = pick_authoritative_ty(&elem_cands, env);
            (
                HirLValue::Index {
                    base: Box::new(base),
                    index: Box::new(index),
                    ty: elem_ty,
                },
                elem_cands,
            )
        }
        other if is_expr_or_block_node(other) => {
            let expr = lower_expr(node, env, scope, queries);
            expr_to_lvalue_candidates(&expr, env, scope)
        }
        _ => (
            HirLValue::Local {
                name: node.text().to_string().trim().to_owned(),
                ty: Ty::Unknown,
            },
            Vec::new(),
        ),
    }
}

fn expr_to_lvalue_candidates(
    expr: &HirExpr,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> (HirLValue, Vec<Ty>) {
    match expr {
        HirExpr::Path { name, ty } => match scope.get(name) {
            Some(ScopeBinding::MultiVar(tys)) => {
                let cands = tys.clone();
                let picked = pick_authoritative_ty(&cands, env);
                (
                    HirLValue::Local {
                        name: name.clone(),
                        ty: picked,
                    },
                    cands,
                )
            }
            Some(ScopeBinding::QueryRow {
                terms, extra_tys, ..
            }) => {
                let mut cands = Vec::new();
                if terms.len() == 1 && terms[0].field_name.is_some() {
                    push_unique_ty(&mut cands, resolve_query_term_ty(&terms[0], env));
                } else {
                    cands.push(Ty::Ref("Entity".to_owned()));
                }
                for t in extra_tys {
                    push_unique_ty(&mut cands, t.clone());
                }
                let picked = lookup_var_ty(name, env, scope);
                (
                    HirLValue::Local {
                        name: name.clone(),
                        ty: picked,
                    },
                    cands,
                )
            }
            Some(ScopeBinding::QueryTuple {
                ty: tty, extra_tys, ..
            }) => {
                let mut cands = Vec::new();
                push_unique_ty(&mut cands, tty.clone());
                for t in extra_tys {
                    push_unique_ty(&mut cands, t.clone());
                }
                let picked = pick_authoritative_ty(&cands, env);
                (
                    HirLValue::Local {
                        name: name.clone(),
                        ty: picked,
                    },
                    cands,
                )
            }
            _ => {
                let lvy = lookup_var_ty(name, env, scope);
                let chosen = if lvy != Ty::Unknown { lvy } else { ty.clone() };
                let cands = if chosen != Ty::Unknown {
                    vec![chosen.clone()]
                } else {
                    Vec::new()
                };
                (
                    HirLValue::Local {
                        name: name.clone(),
                        ty: chosen,
                    },
                    cands,
                )
            }
        },
        HirExpr::Field { base, field, ty } => {
            let mut field_cands = Vec::new();
            if is_query_like_expr(base)
                && let Some(terms) = resolve_expr_query_terms(base, env, scope)
            {
                let matching: Vec<&HirQueryTerm> =
                    terms.iter().filter(|t| t.alias == *field).collect();
                for t in &matching {
                    push_unique_ty(&mut field_cands, resolve_query_term_ty(t, env));
                }
                if field == "id" && field_cands.is_empty() {
                    field_cands.push(Ty::Ref("Entity".to_owned()));
                }
                let (_, base_cands) = expr_to_lvalue_candidates(base, env, scope);
                for bty in &base_cands {
                    push_unique_ty(
                        &mut field_cands,
                        resolve_field_ty_from_base_ty(bty, field, env),
                    );
                }
                let matched = matching
                    .iter()
                    .copied()
                    .find(|t| env.is_server_authoritative(&t.storage_key))
                    .or_else(|| {
                        matching.iter().copied().find(|t| {
                            let tty = resolve_query_term_ty(t, env);
                            ty_contains_server_authority(&tty, env, &mut HashSet::new())
                        })
                    })
                    .or_else(|| matching.first().copied());
                let mut base_ty = matched.map_or(Ty::Unknown, |t| Ty::Named(t.storage_key.clone()));
                if !matches!(base_ty, Ty::Named(ref n) if env.is_server_authoritative(n)) {
                    let cand_base_ty = pick_authoritative_ty(&base_cands, env);
                    if cand_base_ty != Ty::Unknown
                        && (base_ty == Ty::Unknown
                            || ty_contains_server_authority(
                                &cand_base_ty,
                                env,
                                &mut HashSet::new(),
                            ))
                    {
                        base_ty = cand_base_ty;
                    }
                }
                let field_ty = if field_cands.is_empty() {
                    ty.clone()
                } else {
                    pick_authoritative_ty(&field_cands, env)
                };
                let base_lv = match base.as_ref() {
                    HirExpr::Path { name, .. } => HirLValue::Local {
                        name: name.clone(),
                        ty: base_ty,
                    },
                    _ => HirLValue::Expr(Box::new((**base).clone())),
                };
                return (
                    HirLValue::Field {
                        base: Box::new(base_lv),
                        field: field.clone(),
                        ty: field_ty,
                    },
                    field_cands,
                );
            }
            let (base_lv, base_cands) = expr_to_lvalue_candidates(base, env, scope);
            for bty in &base_cands {
                push_unique_ty(
                    &mut field_cands,
                    resolve_field_ty_from_base_ty(bty, field, env),
                );
            }
            let field_ty = if field_cands.is_empty() {
                let rty = resolve_lvalue_field_ty(&base_lv, field, env, scope);
                if rty != Ty::Unknown { rty } else { ty.clone() }
            } else {
                pick_authoritative_ty(&field_cands, env)
            };
            (
                HirLValue::Field {
                    base: Box::new(base_lv),
                    field: field.clone(),
                    ty: field_ty,
                },
                field_cands,
            )
        }
        HirExpr::Index { base, index, ty } => {
            let (base_lv, base_cands) = expr_to_lvalue_candidates(base, env, scope);
            let mut elem_cands = Vec::new();
            for bty in &base_cands {
                if let Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } = bty {
                    push_unique_ty(&mut elem_cands, (**elem).clone());
                }
            }
            if elem_cands.is_empty()
                && let Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } = base_lv.ty()
            {
                push_unique_ty(&mut elem_cands, (**elem).clone());
            }
            let elem_ty = if elem_cands.is_empty() {
                ty.clone()
            } else {
                pick_authoritative_ty(&elem_cands, env)
            };
            (
                HirLValue::Index {
                    base: Box::new(base_lv),
                    index: Box::new((**index).clone()),
                    ty: elem_ty,
                },
                elem_cands,
            )
        }
        HirExpr::Call(c) => {
            if c.receiver.is_none()
                && matches!(
                    c.callee.as_str(),
                    "res_mut" | "res" | "server_res" | "client_res"
                )
                && let Some(rname) = c.generic_args.first()
                && (c.callee != "client_res" || !c.args.is_empty())
            {
                let ty = Ty::Named(rname.clone());
                let client_id = if c.callee == "client_res" {
                    c.args.first().cloned().map(Box::new)
                } else {
                    None
                };
                return (
                    HirLValue::ResourceAccess {
                        resource: rname.clone(),
                        is_mut: c.callee != "res",
                        client_id,
                        ty: ty.clone(),
                    },
                    vec![ty],
                );
            }
            let cands = resolve_expr_candidate_tys(expr, env, scope);
            (HirLValue::Expr(Box::new(expr.clone())), cands)
        }
        HirExpr::Block { stmts, tail, .. } => {
            let Some(t) = tail.as_deref() else {
                if !stmts.is_empty() {
                    return (HirLValue::Expr(Box::new(expr.clone())), vec![Ty::Unit]);
                }
                return (
                    HirLValue::Local {
                        name: "_".to_owned(),
                        ty: Ty::Unit,
                    },
                    vec![Ty::Unit],
                );
            };
            if !stmts.is_empty() {
                let cands = resolve_expr_candidate_tys(expr, env, scope);
                return (HirLValue::Expr(Box::new(expr.clone())), cands);
            }
            let mut inner = scope.clone();
            inner.push();
            simulate_stmts_in_scope(stmts, env, &mut inner);
            expr_to_lvalue_candidates(t, env, &inner)
        }
        other => {
            let cands = resolve_expr_candidate_tys(other, env, scope);
            (HirLValue::Expr(Box::new(other.clone())), cands)
        }
    }
}

fn resolve_lvalue_field_ty(
    base: &HirLValue,
    field: &str,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> Ty {
    if let HirLValue::Local { name, .. } = base
        && let Some(ScopeBinding::QueryRow { terms, extra_tys }) = scope.get(name)
    {
        let mut cands = Vec::new();
        for t in terms {
            if t.alias == field {
                push_unique_ty(&mut cands, resolve_query_term_ty(t, env));
            }
        }
        for ety in extra_tys {
            push_unique_ty(&mut cands, resolve_field_ty_from_base_ty(ety, field, env));
        }
        if !cands.is_empty() {
            return pick_authoritative_ty(&cands, env);
        }
    }
    resolve_field_ty_from_base_ty(base.ty(), field, env)
}

pub(crate) fn lower_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
) -> HirExpr {
    lower_expr_with_expected(node, env, scope, queries, None)
}

pub(crate) fn lower_expr_with_expected(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    expected: Option<&Ty>,
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
        SyntaxKind::ParenExpr => node
            .children()
            .find(|c| is_expr_or_block_node(c.kind()))
            .map_or(
                HirExpr::Tuple {
                    elems: Vec::new(),
                    ty: Ty::Unit,
                },
                |inner| lower_expr_with_expected(&inner, env, scope, queries, expected),
            ),
        SyntaxKind::TupleExpr => {
            let expected_elems = match expected {
                Some(Ty::Tuple(ts)) => Some(ts.as_slice()),
                _ => None,
            };
            let elems: Vec<_> = node
                .children()
                .filter(|c| is_expr_or_block_node(c.kind()))
                .enumerate()
                .map(|(i, e)| {
                    let exp = expected_elems.and_then(|ts| ts.get(i));
                    lower_expr_with_expected(&e, env, scope, queries, exp)
                })
                .collect();
            let ty = if elems.is_empty() {
                Ty::Unit
            } else {
                Ty::Tuple(elems.iter().map(HirExpr::ty).collect())
            };
            HirExpr::Tuple { elems, ty }
        }
        SyntaxKind::ArrayLitExpr => {
            let expected_elem = match expected {
                Some(Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }) => Some(elem.as_ref()),
                _ => None,
            };
            let elems: Vec<_> = node
                .children()
                .filter(|c| is_expr_or_block_node(c.kind()))
                .map(|e| lower_expr_with_expected(&e, env, scope, queries, expected_elem))
                .collect();
            build_array_lit(elems, expected)
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
                .find(|c| is_expr_or_block_node(c.kind()))
                .map_or(HirExpr::BoolLit(false), |e| {
                    lower_expr(&e, env, scope, queries)
                });
            let ty = match op {
                HirUnOp::Not => {
                    let it = inner.ty();
                    if it == Ty::Unknown { Ty::Bool } else { it }
                }
                HirUnOp::Ref => Ty::Borrow {
                    mutable: false,
                    inner: Box::new(inner.ty()),
                },
                HirUnOp::RefMut => Ty::Borrow {
                    mutable: true,
                    inner: Box::new(inner.ty()),
                },
                _ => inner.ty(),
            };
            HirExpr::Unary {
                op,
                expr: Box::new(inner),
                ty,
            }
        }
        SyntaxKind::BinaryExpr => {
            if let Some(assign_stmt) = try_lower_assign_binary_expr(node, env, scope, queries) {
                return HirExpr::Block {
                    stmts: vec![assign_stmt],
                    tail: None,
                    ty: Ty::Unit,
                };
            }
            let exprs: Vec<_> = node
                .children()
                .filter(|c| is_expr_or_block_node(c.kind()))
                .collect();
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
            let (lhs, rhs, ty) = coerce_binary_operands(op, lhs, rhs);
            HirExpr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                ty,
            }
        }
        SyntaxKind::CastExpr => {
            let expr = node
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map_or(
                    HirExpr::IntLit {
                        value: 0,
                        ty: Ty::I32,
                    },
                    |e| lower_expr(&e, env, scope, queries),
                );
            let target_ty = node
                .children()
                .find(|c| is_type_node(c.kind()))
                .map_or(Ty::Unknown, |t| {
                    parse_type_node_with_user_types(&t, env.user_types)
                });
            HirExpr::Cast {
                expr: Box::new(expr),
                target_ty,
            }
        }
        SyntaxKind::FieldExpr => {
            let base = node
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map_or(
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
            let exprs: Vec<_> = node
                .children()
                .filter(|c| is_expr_or_block_node(c.kind()))
                .collect();
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
            let ty = resolve_index_ty(&base, env);
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
                .map(|fil| {
                    lower_field_init_list_for_owner(fil.syntax(), env, scope, queries, Some(&name))
                })
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
            let field_tys: Vec<(String, Ty)> =
                fields.iter().map(|(k, e)| (k.clone(), e.ty())).collect();
            HirExpr::RecordLit {
                fields,
                ty: Ty::Record(field_tys),
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
            let (count_args, _) = ast::child::<ast::ArgList>(node)
                .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                .unwrap_or_default();
            let count = if count_args.is_empty() {
                None
            } else if count_args.len() == 1 {
                Some(Box::new(count_args.into_iter().next().unwrap()))
            } else {
                let mut it = count_args.into_iter();
                let first = it.next().unwrap();
                let first_ty = first.ty();
                let stmts: Vec<HirStmt> = it.map(HirStmt::Expr).collect();
                Some(Box::new(HirExpr::Block {
                    stmts,
                    tail: Some(Box::new(first)),
                    ty: first_ty,
                }))
            };
            let pat = node
                .children()
                .find(|c| is_pattern_node(c.kind()))
                .map(|p| lower_pattern(&p));
            let batch_var = pat.as_ref().and_then(first_pattern_binding);
            scope.push();
            if let Some(ref bv) = batch_var {
                scope.insert(bv.clone(), ScopeBinding::Var(Ty::I32));
            }
            let (mut preamble, tail) = ast::child::<ast::Block>(node)
                .map(|b| lower_block(b.syntax(), env, scope, queries))
                .unwrap_or_default();
            scope.pop();
            let components = match tail {
                Some(HirExpr::BundleLit { components }) => components,
                Some(other_tail) => {
                    preamble.push(HirStmt::Expr(other_tail));
                    Vec::new()
                }
                None => Vec::new(),
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
            let (extra_args, _) = ast::child::<ast::ArgList>(node)
                .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                .unwrap_or_default();
            let expr = HirExpr::DespawnAll { filters };
            if extra_args.is_empty() {
                expr
            } else {
                let mut stmts = vec![HirStmt::Expr(expr)];
                for extra in extra_args {
                    stmts.push(HirStmt::Expr(extra));
                }
                HirExpr::Block {
                    stmts,
                    tail: None,
                    ty: Ty::Unit,
                }
            }
        }
        SyntaxKind::InsertExpr => {
            let if_new = ast::attrs(node)
                .iter()
                .filter_map(ast::attr_name)
                .any(|a| a == "if_new");
            let (args, _) = ast::child::<ast::ArgList>(node)
                .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                .unwrap_or_default();
            let mut it = args.into_iter();
            let entity = it.next().unwrap_or(HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            });
            let value = it.next().unwrap_or(HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            });
            let expr = HirExpr::Insert {
                if_new,
                entity: Box::new(entity),
                value: Box::new(value),
            };
            let extras: Vec<HirStmt> = it.map(HirStmt::Expr).collect();
            if extras.is_empty() {
                expr
            } else {
                let mut stmts = vec![HirStmt::Expr(expr)];
                stmts.extend(extras);
                HirExpr::Block {
                    stmts,
                    tail: None,
                    ty: Ty::Unit,
                }
            }
        }
        SyntaxKind::RemoveExpr => {
            let component = node
                .children()
                .find(|c| c.kind() == SyntaxKind::GenericArgs)
                .and_then(|ga| ga.children().find(|c| is_type_node(c.kind())))
                .map(|t| t.text().to_string().trim().to_owned())
                .unwrap_or_default();
            let (args, _) = ast::child::<ast::ArgList>(node)
                .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                .unwrap_or_default();
            let mut it = args.into_iter();
            let entity = it.next().unwrap_or(HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            });
            let expr = HirExpr::Remove {
                component,
                entity: Box::new(entity),
            };
            let extras: Vec<HirStmt> = it.map(HirStmt::Expr).collect();
            if extras.is_empty() {
                expr
            } else {
                let mut stmts = vec![HirStmt::Expr(expr)];
                stmts.extend(extras);
                HirExpr::Block {
                    stmts,
                    tail: None,
                    ty: Ty::Unit,
                }
            }
        }
        SyntaxKind::PostfixCallExpr => lower_postfix_call(node, env, scope, queries),
        SyntaxKind::Block => {
            let (stmts, tail) = lower_block_with_expected(node, env, scope, queries, expected);
            let ty = tail.as_ref().map_or(Ty::Unit, |t| t.ty());
            HirExpr::Block {
                stmts,
                tail: tail.map(Box::new),
                ty,
            }
        }
        SyntaxKind::IfExpr => lower_if_expr(node, env, scope, queries, expected),
        SyntaxKind::MatchExpr => lower_match_expr(node, env, scope, queries, expected),
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
        && let Some(inner) = node.children().find(|c| is_expr_or_block_node(c.kind()))
    {
        return lower_expr(&inner, env, scope, queries);
    }

    let first_expr = node.children().find(|c| is_expr_or_block_node(c.kind()));
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
                changed_filters: Vec::new(),
                added_filters: Vec::new(),
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
    let (mut pre_stmts, query_recv, passthrough_recv) = match recv {
        Some(HirExpr::Query(q)) => (Vec::new(), Some(q), None),
        Some(HirExpr::Block {
            stmts,
            tail: Some(inner),
            ..
        }) if matches!(inner.as_ref(), HirExpr::Query(_)) => {
            let HirExpr::Query(q) = *inner else {
                unreachable!();
            };
            (stmts, Some(q), None)
        }
        other => (Vec::new(), None, other),
    };
    if let Some(mut q) = query_recv {
        let wrap_query = |pre_stmts: Vec<HirStmt>, q: HirQuery| -> HirExpr {
            let ty = infer_query_ty(&q, env);
            if pre_stmts.is_empty() {
                HirExpr::Query(q)
            } else {
                HirExpr::Block {
                    stmts: pre_stmts,
                    tail: Some(Box::new(HirExpr::Query(q))),
                    ty,
                }
            }
        };
        let push_unexpected_args = |pre_stmts: &mut Vec<HirStmt>, scope: &mut ScopeStack| {
            if let Some(al) = ast::child::<ast::ArgList>(node) {
                let (args, _) = lower_arg_list(al.syntax(), env, scope, queries);
                for a in args {
                    pre_stmts.push(HirStmt::Expr(a));
                }
            }
        };
        match method_name.as_str() {
            "with" => {
                q.with_filters.extend(generic_args);
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "without" => {
                q.without_filters.extend(generic_args);
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "allow" => {
                q.allow_filters.extend(generic_args);
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "has" => {
                q.has_filters.extend(generic_args);
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "changed" => {
                if generic_args.is_empty() {
                    for t in &q.terms {
                        if !q.changed_filters.contains(&t.storage_key) {
                            q.changed_filters.push(t.storage_key.clone());
                        }
                    }
                } else {
                    for g in generic_args {
                        if !q.changed_filters.contains(&g) {
                            q.changed_filters.push(g);
                        }
                    }
                }
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "added" => {
                if generic_args.is_empty() {
                    for t in &q.terms {
                        if !q.added_filters.contains(&t.storage_key) {
                            q.added_filters.push(t.storage_key.clone());
                        }
                    }
                } else {
                    for g in generic_args {
                        if !q.added_filters.contains(&g) {
                            q.added_filters.push(g);
                        }
                    }
                }
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "up" => {
                q.up_relation = generic_args.into_iter().next();
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "where" => {
                if let Some(al) = ast::child::<ast::ArgList>(node) {
                    scope.push();
                    for t in &q.terms {
                        let tty = resolve_query_term_ty(t, env);
                        scope.insert(t.alias.clone(), ScopeBinding::Var(tty));
                    }
                    let (args, _) = lower_arg_list(al.syntax(), env, scope, queries);
                    scope.pop();
                    if !args.is_empty() {
                        let mut it = args.into_iter();
                        let first = it.next().unwrap();
                        let extras: Vec<HirStmt> = it.map(HirStmt::Expr).collect();
                        let pred = if extras.is_empty() {
                            first
                        } else {
                            let mut stmts = vec![HirStmt::Expr(first)];
                            stmts.extend(extras);
                            HirExpr::Block {
                                stmts,
                                tail: None,
                                ty: Ty::Bool,
                            }
                        };
                        q.where_pred = Some(Box::new(match q.where_pred.take() {
                            Some(old) => HirExpr::Binary {
                                op: HirBinOp::And,
                                lhs: old,
                                rhs: Box::new(pred),
                                ty: Ty::Bool,
                            },
                            None => pred,
                        }));
                    }
                }
                return wrap_query(pre_stmts, q);
            }
            "on" => {
                if let Some(al) = ast::child::<ast::ArgList>(node) {
                    let (args, _) = lower_arg_list(al.syntax(), env, scope, queries);
                    if !args.is_empty() {
                        let mut it = args.into_iter();
                        let tgt = it.next().unwrap();
                        let tgt_ty = tgt.ty();
                        let mut on_stmts = Vec::new();
                        if let Some(old_tgt) = q.on_target.take() {
                            on_stmts.push(HirStmt::Expr(*old_tgt));
                        }
                        for extra in it {
                            on_stmts.push(HirStmt::Expr(extra));
                        }
                        q.on_target = Some(Box::new(if on_stmts.is_empty() {
                            tgt
                        } else {
                            HirExpr::Block {
                                stmts: on_stmts,
                                tail: Some(Box::new(tgt)),
                                ty: tgt_ty,
                            }
                        }));
                    }
                }
                return wrap_query(pre_stmts, q);
            }
            "count" => {
                q.is_count = true;
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            "unwrap" => {
                q.is_unwrap = true;
                push_unexpected_args(&mut pre_stmts, scope);
                return wrap_query(pre_stmts, q);
            }
            _ => {
                let (args, arg_names) = ast::child::<ast::ArgList>(node)
                    .map(|al| lower_arg_list(al.syntax(), env, scope, queries))
                    .unwrap_or_default();
                let ty = infer_call_ty(None, &method_name, &generic_args, &args, env);
                return HirExpr::Call(HirCall {
                    receiver: Some(Box::new(wrap_query(pre_stmts, q))),
                    callee: method_name,
                    generic_args,
                    args,
                    arg_names,
                    ty,
                });
            }
        }
    }

    let recv = passthrough_recv;

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
            let expr = ch
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map_or(
                    HirExpr::Tuple {
                        elems: Vec::new(),
                        ty: Ty::Unit,
                    },
                    |e| lower_expr(&e, env, scope, queries),
                );
            names.push(fname);
            args.push(expr);
        } else if is_expr_or_block_node(ch.kind()) {
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
    expected: Option<&Ty>,
) -> HirExpr {
    let has_let = direct_tokens(node).any(|t| t.kind() == SyntaxKind::KwLet);
    let let_pat = if has_let {
        node.children()
            .find(|c| is_pattern_node(c.kind()))
            .map(|p| lower_pattern(&p))
    } else {
        None
    };

    let else_pos = direct_tokens(node)
        .find(|t| t.kind() == SyntaxKind::KwElse)
        .map(|t| t.text_range().start());

    let cond_expr_node = node.children().find(|c| {
        is_expr_node(c.kind())
            && (c.kind() != SyntaxKind::IfExpr
                || else_pos.is_none_or(|ep| c.text_range().start() < ep))
    });
    let pre_else_blocks: Vec<_> = node
        .children()
        .filter(|c| {
            c.kind() == SyntaxKind::Block && else_pos.is_none_or(|ep| c.text_range().end() <= ep)
        })
        .collect();
    let (cond_node, then_block_node) = if cond_expr_node.is_none() && pre_else_blocks.len() >= 2 {
        (Some(pre_else_blocks[0].clone()), pre_else_blocks.get(1))
    } else {
        (cond_expr_node, pre_else_blocks.first())
    };

    let cond = cond_node.map_or(HirExpr::BoolLit(false), |e| {
        lower_expr(&e, env, scope, queries)
    });

    let pre_frames = scope.frames.clone();

    scope.push();
    if let Some(ref pat) = let_pat {
        bind_pattern(pat, cond.ty(), Some(&cond), env, scope);
    }
    let (then_stmts, then_tail) = then_block_node
        .map(|b| lower_block_with_expected(b, env, scope, queries, expected))
        .unwrap_or_default();
    scope.pop();
    let then_frames = scope.frames.clone();

    scope.frames = pre_frames.clone();
    let else_if = else_pos.and_then(|ep| {
        node.children()
            .find(|c| c.kind() == SyntaxKind::IfExpr && c.text_range().start() >= ep)
    });
    let else_block = else_pos.and_then(|ep| {
        node.children()
            .find(|c| c.kind() == SyntaxKind::Block && c.text_range().start() >= ep)
    });
    let (else_stmts, else_tail) = if let Some(ref ei) = else_if {
        (
            Vec::new(),
            Some(lower_if_expr(ei, env, scope, queries, expected)),
        )
    } else if let Some(ref eb) = else_block {
        lower_block_with_expected(eb, env, scope, queries, expected)
    } else {
        (Vec::new(), None)
    };
    let else_frames = scope.frames.clone();

    scope.merge_from(&pre_frames, &[then_frames, else_frames], env);

    let mut branch_tys = Vec::new();
    let then_div = stmts_definitely_diverges(&then_stmts)
        || then_tail.as_ref().is_some_and(expr_definitely_diverges);
    if let Some(ref t) = then_tail {
        branch_tys.push((t.ty(), then_div));
    } else if !then_div {
        branch_tys.push((Ty::Unit, false));
    }
    let has_else = else_if.is_some() || else_block.is_some();
    if has_else {
        let else_div = stmts_definitely_diverges(&else_stmts)
            || else_tail.as_ref().is_some_and(expr_definitely_diverges);
        if let Some(ref e) = else_tail {
            branch_tys.push((e.ty(), else_div));
        } else if !else_div {
            branch_tys.push((Ty::Unit, false));
        }
    }
    let ty = unify_branch_tys(&branch_tys, expected);

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

fn is_irrefutable_pattern(pat: &HirPattern) -> bool {
    match pat {
        HirPattern::Wildcard => true,
        HirPattern::Binding { name, .. } => name != "None",
        HirPattern::Tuple(items) => items.iter().all(is_irrefutable_pattern),
        HirPattern::TupleStruct { .. } | HirPattern::Literal(_) | HirPattern::Path(_) => false,
    }
}

pub(crate) fn match_arms_have_catch_all(arms: &[HirMatchArm]) -> bool {
    if arms
        .iter()
        .any(|a| a.guard.is_none() && is_irrefutable_pattern(&a.pattern))
    {
        return true;
    }
    let has_true = arms.iter().any(|a| {
        a.guard.is_none()
            && matches!(
                &a.pattern,
                HirPattern::Literal(e) if matches!(e.as_ref(), HirExpr::BoolLit(true))
            )
    });
    let has_false = arms.iter().any(|a| {
        a.guard.is_none()
            && matches!(
                &a.pattern,
                HirPattern::Literal(e) if matches!(e.as_ref(), HirExpr::BoolLit(false))
            )
    });
    if has_true && has_false {
        return true;
    }
    let has_some = arms.iter().any(|a| {
        a.guard.is_none()
            && matches!(
                &a.pattern,
                HirPattern::TupleStruct { path, fields }
                    if matches!(path.as_str(), "Some" | "Option::Some")
                        && fields.iter().all(is_irrefutable_pattern)
            )
    });
    let has_none = arms.iter().any(|a| {
        a.guard.is_none()
            && (matches!(&a.pattern, HirPattern::Binding { name, .. } if name == "None")
                || matches!(&a.pattern, HirPattern::Path(p) if p == "None" || p == "Option::None"))
    });
    has_some && has_none
}

fn lower_match_expr(
    node: &SyntaxNode,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
    queries: &[QueryAccessDesc],
    expected: Option<&Ty>,
) -> HirExpr {
    let scrutinee = node
        .children()
        .find(|c| is_expr_or_block_node(c.kind()))
        .map_or(
            HirExpr::IntLit {
                value: 0,
                ty: Ty::I32,
            },
            |e| lower_expr(&e, env, scope, queries),
        );
    let scrut_ty = scrutinee.ty();
    let pre_frames = scope.frames.clone();
    let mut arm_frame_sets = Vec::new();
    let mut arms = Vec::new();
    for arm_node in node.children().filter(|c| c.kind() == SyntaxKind::MatchArm) {
        let pattern = arm_node
            .children()
            .find(|c| is_pattern_node(c.kind()))
            .map_or(HirPattern::Wildcard, |p| lower_pattern(&p));
        scope.frames = pre_frames.clone();
        scope.push();
        bind_pattern(&pattern, scrut_ty.clone(), Some(&scrutinee), env, scope);
        let exprs: Vec<_> = arm_node
            .children()
            .filter(|c| is_expr_node(c.kind()) || c.kind() == SyntaxKind::Block)
            .collect();
        let has_guard = direct_tokens(&arm_node).any(|t| t.kind() == SyntaxKind::KwIf);
        let (guard, body) = if has_guard && exprs.len() >= 2 {
            (
                Some(lower_expr(&exprs[0], env, scope, queries)),
                lower_expr_with_expected(&exprs[1], env, scope, queries, expected),
            )
        } else {
            (
                None,
                exprs.first().map_or(
                    HirExpr::Tuple {
                        elems: Vec::new(),
                        ty: Ty::Unit,
                    },
                    |e| lower_expr_with_expected(e, env, scope, queries, expected),
                ),
            )
        };
        scope.pop();
        arm_frame_sets.push(scope.frames.clone());
        arms.push(HirMatchArm {
            pattern,
            guard,
            body,
        });
    }
    if arms.is_empty() {
        scope.frames = pre_frames;
    } else {
        if !match_arms_have_catch_all(&arms) {
            arm_frame_sets.push(pre_frames.clone());
        }
        scope.merge_from(&pre_frames, &arm_frame_sets, env);
    }
    let arm_branches: Vec<(Ty, bool)> = arms
        .iter()
        .map(|a| (a.body.ty(), expr_definitely_diverges(&a.body)))
        .collect();
    let ty = unify_branch_tys(&arm_branches, expected);
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
    let reduce_clause = ast::child::<ast::ReduceClause>(node);
    let expr_iter = node.children().find(|c| is_expr_node(c.kind()));
    let blocks: Vec<_> = node
        .children()
        .filter(|c| c.kind() == SyntaxKind::Block)
        .collect();
    let (iter_node, body_block) = if let Some(e) = expr_iter {
        (
            Some(e),
            if reduce_clause.is_none() {
                blocks.first().cloned()
            } else {
                None
            },
        )
    } else if reduce_clause.is_some() {
        (blocks.first().cloned(), None)
    } else if blocks.len() >= 2 {
        (Some(blocks[0].clone()), blocks.get(1).cloned())
    } else {
        (None, blocks.first().cloned())
    };

    let iter_expr = iter_node.map_or(
        HirExpr::Tuple {
            elems: Vec::new(),
            ty: Ty::Unit,
        },
        |e| lower_expr(&e, env, scope, queries),
    );

    let mut pre_stmts = Vec::new();
    let iter_expr = match iter_expr {
        HirExpr::Block {
            stmts,
            tail: Some(inner),
            ..
        } if matches!(inner.as_ref(), HirExpr::Query(_))
            || matches!(
                inner.as_ref(),
                HirExpr::Call(HirCall {
                    receiver: Some(_),
                    callee,
                    ..
                }) if matches!(callee.as_str(), "query_disc" | "query_segment_at")
            ) =>
        {
            pre_stmts = stmts;
            *inner
        }
        other => other,
    };

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
            if !matches!(recv.as_ref(), HirExpr::Path { .. }) {
                pre_stmts.push(HirStmt::Expr(*recv));
            }
            for extra in args.iter().skip(2) {
                pre_stmts.push(HirStmt::Expr(extra.clone()));
            }
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
            if !matches!(recv.as_ref(), HirExpr::Path { .. }) {
                pre_stmts.push(HirStmt::Expr(*recv));
            }
            let radius = args.get(3).cloned().map(Box::new);
            for extra in args.iter().skip(4) {
                pre_stmts.push(HirStmt::Expr(extra.clone()));
            }
            HirForIter::SpatialSegmentAt {
                history,
                tick: Box::new(args[0].clone()),
                p0: Box::new(args[1].clone()),
                p1: Box::new(args[2].clone()),
                radius,
            }
        }
        other => HirForIter::Expr(Box::new(other)),
    };

    let pre_frames = scope.frames.clone();
    scope.push();
    match &iter {
        HirForIter::Query(q) => {
            let shape = QueryShape::Row(q.terms.clone());
            let pat_name = first_pattern_binding(&binding);
            let row_ty = if q.terms.len() == 1
                && (q.terms[0].field_name.is_some()
                    || matches!(
                        q.terms[0].mode,
                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                    ))
                && pat_name.as_deref() == Some(q.terms[0].alias.as_str())
            {
                resolve_query_term_ty(&q.terms[0], env)
            } else {
                Ty::Ref("Entity".to_owned())
            };
            bind_pattern_with_shape(&binding, row_ty, Some(&shape), &[], env, scope);
        }
        HirForIter::Range { start, .. } => {
            bind_pattern_with_shape(&binding, start.ty(), None, &[], env, scope);
        }
        HirForIter::SpatialDisc { .. } | HirForIter::SpatialSegmentAt { .. } => {
            if let Some(var) = first_pattern_binding(&binding) {
                scope.insert(var, ScopeBinding::SpatialCandidate);
            }
        }
        HirForIter::Expr(e) => {
            bind_pattern(&binding, e.ty(), Some(e), env, scope);
        }
    }

    let mut reduce = Vec::new();
    let mut body = Vec::new();
    if let Some(rc) = reduce_clause {
        for re in ast::children::<ast::ReduceEntry>(rc.syntax()) {
            let name = ast::first_ident(re.syntax())
                .map_or_else(|| "acc".to_owned(), |t| t.text().to_owned());
            let expr = re
                .syntax()
                .children()
                .find(|c| is_expr_or_block_node(c.kind()))
                .map(|e| lower_expr(&e, env, scope, queries));
            if let Some(expr) = expr {
                if let HirExpr::Call(ref call) = expr
                    && call.receiver.is_none()
                    && matches!(
                        call.callee.as_str(),
                        "sum"
                            | "Sum"
                            | "prod"
                            | "Prod"
                            | "min"
                            | "Min"
                            | "max"
                            | "Max"
                            | "any"
                            | "Any"
                            | "all"
                            | "All"
                            | "count"
                            | "Count"
                    )
                    && (1..=2).contains(&call.args.len())
                {
                    let op = call.callee.clone();
                    let identity = call.args[0].clone();
                    let value = call.args.get(1).cloned().unwrap_or(HirExpr::Tuple {
                        elems: Vec::new(),
                        ty: Ty::Unit,
                    });
                    let raw_ty = if call.args.len() >= 2 {
                        value.ty()
                    } else {
                        identity.ty()
                    };
                    let ty = match raw_ty {
                        Ty::Borrow { inner, .. } => *inner,
                        other => other,
                    };
                    reduce.push(HirReduceEntry {
                        name,
                        op,
                        identity,
                        value,
                        ty,
                    });
                } else {
                    let ty = match expr.ty() {
                        Ty::Borrow { inner, .. } => *inner,
                        other => other,
                    };
                    reduce.push(HirReduceEntry {
                        name,
                        op: String::new(),
                        identity: HirExpr::Tuple {
                            elems: Vec::new(),
                            ty: Ty::Unit,
                        },
                        value: expr,
                        ty,
                    });
                }
            }
        }
    } else if let Some(blk) = body_block {
        body = lower_block_as_stmts(&blk, env, scope, queries, false);
    }
    scope.pop();
    let post_frames = scope.frames.clone();
    scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);

    let ty = if reduce.is_empty() {
        Ty::Unit
    } else if reduce.len() == 1 {
        reduce[0].ty.clone()
    } else {
        Ty::Tuple(reduce.iter().map(|r| r.ty.clone()).collect())
    };

    let for_expr = HirExpr::For(HirFor {
        binding,
        iter,
        body,
        reduce,
        ty: ty.clone(),
    });
    if pre_stmts.is_empty() {
        for_expr
    } else {
        HirExpr::Block {
            stmts: pre_stmts,
            tail: Some(Box::new(for_expr)),
            ty,
        }
    }
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
                if name.contains("::") || (!mutable && name == "None") {
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

fn merge_query_terms(mut a: Vec<HirQueryTerm>, b: Vec<HirQueryTerm>) -> Vec<HirQueryTerm> {
    for t in b {
        if !a.iter().any(|existing| {
            existing.alias == t.alias
                && existing.storage_key == t.storage_key
                && existing.canonical_component == t.canonical_component
                && existing.field_name == t.field_name
        }) {
            a.push(t);
        }
    }
    a
}

fn merge_query_shapes(a: Option<QueryShape>, b: Option<QueryShape>) -> Option<QueryShape> {
    match (a, b) {
        (None, None) => None,
        (Some(s), None) | (None, Some(s)) => Some(s),
        (Some(QueryShape::Row(t1)), Some(QueryShape::Row(t2))) => {
            Some(QueryShape::Row(merge_query_terms(t1, t2)))
        }
        (Some(QueryShape::Tuple(e1)), Some(QueryShape::Tuple(e2))) => {
            let len = e1.len().max(e2.len());
            let mut merged = Vec::with_capacity(len);
            for i in 0..len {
                let left = e1.get(i).cloned().flatten();
                let right = e2.get(i).cloned().flatten();
                merged.push(merge_query_shapes(left, right));
            }
            Some(QueryShape::Tuple(merged))
        }
        (Some(QueryShape::Row(t)), Some(QueryShape::Tuple(_)))
        | (Some(QueryShape::Tuple(_)), Some(QueryShape::Row(t))) => Some(QueryShape::Row(t)),
    }
}

fn push_unique_ty(out: &mut Vec<Ty>, ty: Ty) {
    if ty != Ty::Unknown && !out.contains(&ty) {
        out.push(ty);
    }
}

fn ty_contains_server_authority(
    ty: &Ty,
    env: &LowerEnv<'_>,
    visited: &mut HashSet<String>,
) -> bool {
    match ty {
        Ty::Named(n) => {
            if env.is_server_authoritative(n) {
                return true;
            }
            if !visited.insert(n.clone()) {
                return false;
            }
            if let Some(l) = env.find_layout(n) {
                for f in &l.fields {
                    if ty_contains_server_authority(&f.ty, env, visited) {
                        return true;
                    }
                }
            }
            let prefix = format!("{n}.");
            for (k, stratum) in env.field_to_stratum {
                if k.starts_with(&prefix)
                    && let Some(l) = env.find_layout(stratum)
                {
                    for f in &l.fields {
                        if ty_contains_server_authority(&f.ty, env, visited) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => {
            ty_contains_server_authority(elem, env, visited)
        }
        Ty::Tuple(elems) => elems
            .iter()
            .any(|e| ty_contains_server_authority(e, env, visited)),
        _ => false,
    }
}

fn pick_authoritative_ty(tys: &[Ty], env: &LowerEnv<'_>) -> Ty {
    for t in tys {
        if let Ty::Named(n) = t
            && env.is_server_authoritative(n)
        {
            return t.clone();
        }
    }
    for t in tys {
        if *t != Ty::Unknown
            && *t != Ty::Unit
            && ty_contains_server_authority(t, env, &mut HashSet::new())
        {
            return t.clone();
        }
    }
    if let Some(t) = tys.iter().find(|t| **t != Ty::Unknown && **t != Ty::Unit) {
        return t.clone();
    }
    tys.iter()
        .find(|t| **t != Ty::Unknown)
        .cloned()
        .unwrap_or(Ty::Unknown)
}

fn resolve_expr_candidate_tys(expr: &HirExpr, env: &LowerEnv<'_>, scope: &ScopeStack) -> Vec<Ty> {
    match expr {
        HirExpr::Path { name, .. } => {
            match scope.get(name) {
                Some(ScopeBinding::MultiVar(tys)) => return tys.clone(),
                Some(ScopeBinding::QueryRow { extra_tys, .. }) => {
                    let mut out = vec![Ty::Ref("Entity".to_owned())];
                    for t in extra_tys {
                        push_unique_ty(&mut out, t.clone());
                    }
                    return out;
                }
                Some(ScopeBinding::QueryTuple { ty, extra_tys, .. }) => {
                    let mut out = Vec::new();
                    push_unique_ty(&mut out, ty.clone());
                    for t in extra_tys {
                        push_unique_ty(&mut out, t.clone());
                    }
                    return out;
                }
                _ => {}
            }
            let ty = lookup_var_ty(name, env, scope);
            if ty == Ty::Unknown {
                Vec::new()
            } else {
                vec![ty]
            }
        }
        HirExpr::Field { base, field, .. } => {
            let mut out = Vec::new();
            if let Some(terms) = resolve_expr_query_terms(base, env, scope) {
                if field == "id" {
                    push_unique_ty(&mut out, Ty::Ref("Entity".to_owned()));
                }
                for t in terms {
                    if t.alias == *field {
                        push_unique_ty(&mut out, resolve_query_term_ty(&t, env));
                    }
                }
            }
            let base_cands = resolve_expr_candidate_tys(base, env, scope);
            for bty in &base_cands {
                push_unique_ty(&mut out, resolve_field_ty_from_base_ty(bty, field, env));
            }
            if out.is_empty() {
                let fty = expr.ty();
                if fty != Ty::Unknown {
                    out.push(fty);
                }
            }
            out
        }
        HirExpr::Tuple { elems, .. } => {
            if elems.is_empty() {
                return vec![Ty::Unit];
            }
            let per_elem: Vec<Vec<Ty>> = elems
                .iter()
                .map(|e| {
                    let mut c = resolve_expr_candidate_tys(e, env, scope);
                    if c.is_empty() {
                        c.push(Ty::Unknown);
                    }
                    c
                })
                .collect();
            let total: usize = per_elem
                .iter()
                .try_fold(1usize, |acc, v| acc.checked_mul(v.len()))
                .unwrap_or(usize::MAX);
            if total <= 32 {
                let mut tuples = vec![Vec::with_capacity(elems.len())];
                for ecands in &per_elem {
                    let mut next = Vec::with_capacity(tuples.len() * ecands.len());
                    for prefix in &tuples {
                        for ety in ecands {
                            let mut row = prefix.clone();
                            row.push(ety.clone());
                            next.push(row);
                        }
                    }
                    tuples = next;
                }
                let mut out = Vec::with_capacity(tuples.len());
                for t in tuples {
                    push_unique_ty(&mut out, Ty::Tuple(t));
                }
                out
            } else {
                let max_len = per_elem.iter().map(Vec::len).max().unwrap_or(1);
                let mut out = Vec::with_capacity(max_len);
                for idx in 0..max_len {
                    let tuple: Vec<Ty> = per_elem
                        .iter()
                        .map(|ecands| {
                            ecands
                                .get(idx)
                                .cloned()
                                .unwrap_or_else(|| pick_authoritative_ty(ecands, env))
                        })
                        .collect();
                    push_unique_ty(&mut out, Ty::Tuple(tuple));
                }
                out
            }
        }
        HirExpr::ArrayLit { elems, .. } => {
            if elems.is_empty() {
                let ty = expr.ty();
                return if ty == Ty::Unknown {
                    Vec::new()
                } else {
                    vec![ty]
                };
            }
            let mut out = Vec::new();
            for e in elems {
                let ecands = resolve_expr_candidate_tys(e, env, scope);
                if ecands.is_empty() {
                    let ety = e.ty();
                    if ety != Ty::Unknown {
                        push_unique_ty(
                            &mut out,
                            Ty::Array {
                                elem: Box::new(ety),
                                len: elems.len(),
                            },
                        );
                    }
                } else {
                    for ety in ecands {
                        push_unique_ty(
                            &mut out,
                            Ty::Array {
                                elem: Box::new(ety),
                                len: elems.len(),
                            },
                        );
                    }
                }
            }
            if out.is_empty() {
                let ty = expr.ty();
                if ty != Ty::Unknown {
                    out.push(ty);
                }
            }
            out
        }
        HirExpr::Index { base, .. } => {
            if let HirExpr::Path { name, .. } = base.as_ref()
                && env.table_fields.contains_key(name)
            {
                return vec![Ty::Named(format!("__table_row::{name}"))];
            }
            let base_cands = resolve_expr_candidate_tys(base, env, scope);
            let mut out = Vec::new();
            for bty in &base_cands {
                if let Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } = bty {
                    push_unique_ty(&mut out, (**elem).clone());
                }
            }
            out
        }
        HirExpr::Unary {
            op: HirUnOp::Ref | HirUnOp::RefMut,
            expr: inner,
            ..
        } => resolve_expr_candidate_tys(inner, env, scope),
        HirExpr::Cast {
            expr: inner,
            target_ty,
        } => {
            if *target_ty == Ty::Unknown {
                resolve_expr_candidate_tys(inner, env, scope)
            } else {
                vec![target_ty.clone()]
            }
        }
        HirExpr::Call(c) => {
            if let Some(target) = option_call_primary(c) {
                let mut cands = resolve_expr_candidate_tys(target, env, scope);
                if matches!(c.callee.as_str(), "unwrap_or" | "Option::unwrap_or")
                    && let Some(fb) = option_call_fallback(c)
                {
                    for fty in resolve_expr_candidate_tys(fb, env, scope) {
                        push_unique_ty(&mut cands, fty);
                    }
                }
                if !cands.is_empty() {
                    return cands;
                }
            }
            if c.receiver.is_none()
                && matches!(c.callee.as_str(), "Some" | "Option::Some")
                && c.args.len() == 1
            {
                let cands = resolve_expr_candidate_tys(&c.args[0], env, scope);
                if !cands.is_empty() {
                    return cands;
                }
            }
            if c.ty == Ty::Unknown {
                Vec::new()
            } else {
                vec![c.ty.clone()]
            }
        }
        HirExpr::Block { stmts, tail, .. } => {
            let Some(t) = tail.as_deref() else {
                return vec![Ty::Unit];
            };
            let mut inner = scope.clone();
            inner.push();
            simulate_stmts_in_scope(stmts, env, &mut inner);
            resolve_expr_candidate_tys(t, env, &inner)
        }
        HirExpr::If {
            let_pat,
            cond,
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            let mut out = Vec::new();
            if let Some(t) = then_tail.as_deref() {
                let mut then_scope = scope.clone();
                then_scope.push();
                if let Some(pat) = let_pat {
                    bind_pattern(pat, cond.ty(), Some(cond), env, &mut then_scope);
                }
                simulate_stmts_in_scope(then_stmts, env, &mut then_scope);
                for ty in resolve_expr_candidate_tys(t, env, &then_scope) {
                    push_unique_ty(&mut out, ty);
                }
            }
            if let Some(t) = else_tail.as_deref() {
                let mut else_scope = scope.clone();
                else_scope.push();
                simulate_stmts_in_scope(else_stmts, env, &mut else_scope);
                for ty in resolve_expr_candidate_tys(t, env, &else_scope) {
                    push_unique_ty(&mut out, ty);
                }
            }
            out
        }
        HirExpr::Match(m) => {
            let mut out = Vec::new();
            for arm in &m.arms {
                let mut arm_scope = scope.clone();
                arm_scope.push();
                bind_pattern(
                    &arm.pattern,
                    m.scrutinee.ty(),
                    Some(&m.scrutinee),
                    env,
                    &mut arm_scope,
                );
                for ty in resolve_expr_candidate_tys(&arm.body, env, &arm_scope) {
                    push_unique_ty(&mut out, ty);
                }
            }
            out
        }
        other => {
            let ty = other.ty();
            if ty == Ty::Unknown {
                Vec::new()
            } else {
                vec![ty]
            }
        }
    }
}

fn simulate_expr_in_scope(expr: &HirExpr, env: &LowerEnv<'_>, scope: &mut ScopeStack) {
    match expr {
        HirExpr::Block { stmts, tail, .. } => {
            scope.push();
            simulate_stmts_in_scope(stmts, env, scope);
            if let Some(t) = tail {
                simulate_expr_in_scope(t, env, scope);
            }
            scope.pop();
        }
        HirExpr::If {
            let_pat,
            cond,
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            simulate_expr_in_scope(cond, env, scope);
            let pre_frames = scope.frames.clone();
            scope.push();
            if let Some(pat) = let_pat {
                bind_pattern(pat, cond.ty(), Some(cond), env, scope);
            }
            simulate_stmts_in_scope(then_stmts, env, scope);
            if let Some(t) = then_tail {
                simulate_expr_in_scope(t, env, scope);
            }
            scope.pop();
            let then_frames = scope.frames.clone();

            scope.frames = pre_frames.clone();
            scope.push();
            simulate_stmts_in_scope(else_stmts, env, scope);
            if let Some(t) = else_tail {
                simulate_expr_in_scope(t, env, scope);
            }
            scope.pop();
            let else_frames = scope.frames.clone();

            scope.merge_from(&pre_frames, &[then_frames, else_frames], env);
        }
        HirExpr::Match(m) => {
            simulate_expr_in_scope(&m.scrutinee, env, scope);
            let pre_frames = scope.frames.clone();
            let mut arm_frames = Vec::new();
            for arm in &m.arms {
                scope.frames = pre_frames.clone();
                scope.push();
                bind_pattern(
                    &arm.pattern,
                    m.scrutinee.ty(),
                    Some(&m.scrutinee),
                    env,
                    scope,
                );
                if let Some(ref g) = arm.guard {
                    simulate_expr_in_scope(g, env, scope);
                }
                simulate_expr_in_scope(&arm.body, env, scope);
                scope.pop();
                arm_frames.push(scope.frames.clone());
            }
            if m.arms.is_empty() {
                scope.frames = pre_frames;
            } else {
                if !match_arms_have_catch_all(&m.arms) {
                    arm_frames.push(pre_frames.clone());
                }
                scope.merge_from(&pre_frames, &arm_frames, env);
            }
        }
        HirExpr::For(f) => {
            let pre_frames = scope.frames.clone();
            scope.push();
            match &f.iter {
                HirForIter::Query(q) => {
                    let shape = QueryShape::Row(q.terms.clone());
                    let pat_name = first_pattern_binding(&f.binding);
                    let row_ty = if q.terms.len() == 1
                        && (q.terms[0].field_name.is_some()
                            || matches!(
                                q.terms[0].mode,
                                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                            ))
                        && pat_name.as_deref() == Some(q.terms[0].alias.as_str())
                    {
                        resolve_query_term_ty(&q.terms[0], env)
                    } else {
                        Ty::Ref("Entity".to_owned())
                    };
                    bind_pattern_with_shape(&f.binding, row_ty, Some(&shape), &[], env, scope);
                }
                HirForIter::Range { start, .. } => {
                    bind_pattern_with_shape(&f.binding, start.ty(), None, &[], env, scope);
                }
                HirForIter::Expr(e) => {
                    simulate_expr_in_scope(e, env, scope);
                    bind_pattern(&f.binding, e.ty(), Some(e), env, scope);
                }
                HirForIter::SpatialDisc { .. } | HirForIter::SpatialSegmentAt { .. } => {
                    if let Some(var) = first_pattern_binding(&f.binding) {
                        scope.insert(var, ScopeBinding::SpatialCandidate);
                    }
                }
            }
            simulate_stmts_in_scope(&f.body, env, scope);
            scope.pop();
            let post_frames = scope.frames.clone();
            scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);
        }
        HirExpr::Unary { expr: inner, .. }
        | HirExpr::Cast { expr: inner, .. }
        | HirExpr::Field { base: inner, .. } => simulate_expr_in_scope(inner, env, scope),
        HirExpr::Binary { lhs, rhs, .. } => {
            simulate_expr_in_scope(lhs, env, scope);
            simulate_expr_in_scope(rhs, env, scope);
        }
        HirExpr::Index { base, index, .. } => {
            simulate_expr_in_scope(base, env, scope);
            simulate_expr_in_scope(index, env, scope);
        }
        HirExpr::Call(c) => {
            if let Some(ref recv) = c.receiver {
                simulate_expr_in_scope(recv, env, scope);
            }
            for a in &c.args {
                simulate_expr_in_scope(a, env, scope);
            }
        }
        HirExpr::Tuple { elems, .. } | HirExpr::ArrayLit { elems, .. } => {
            for e in elems {
                simulate_expr_in_scope(e, env, scope);
            }
        }
        _ => {}
    }
}

fn simulate_stmts_in_scope(stmts: &[HirStmt], env: &LowerEnv<'_>, scope: &mut ScopeStack) {
    for stmt in stmts {
        match stmt {
            HirStmt::Let {
                pattern, ty, value, ..
            } => {
                simulate_expr_in_scope(value, env, scope);
                let bound_ty = ty.clone().unwrap_or_else(|| value.ty());
                let src_for_bind = ty
                    .as_ref()
                    .is_none_or(|t| *t == Ty::Unknown)
                    .then_some(value);
                bind_pattern(pattern, bound_ty, src_for_bind, env, scope);
            }
            HirStmt::Assign {
                target: HirLValue::Local { name, ty },
                op: HirAssignOp::Set,
                value,
            } => {
                simulate_expr_in_scope(value, env, scope);
                let cands = resolve_expr_candidate_tys(value, env, scope);
                if let Some(shape) = resolve_expr_query_shape(value, env, scope) {
                    match shape {
                        QueryShape::Row(terms) => {
                            let mut extra_tys = Vec::new();
                            for c in &cands {
                                if !matches!(c, Ty::Ref(s) if s == "Entity") {
                                    push_unique_ty(&mut extra_tys, c.clone());
                                }
                            }
                            scope.assign(name, ScopeBinding::QueryRow { terms, extra_tys });
                        }
                        QueryShape::Tuple(elems) => {
                            let mut extra_tys = Vec::new();
                            for c in &cands {
                                push_unique_ty(&mut extra_tys, c.clone());
                            }
                            push_unique_ty(&mut extra_tys, value.ty());
                            let picked = pick_authoritative_ty(&extra_tys, env);
                            scope.assign(
                                name,
                                ScopeBinding::QueryTuple {
                                    ty: picked,
                                    elems,
                                    extra_tys,
                                },
                            );
                        }
                    }
                } else {
                    let binding = if cands.len() > 1 {
                        ScopeBinding::MultiVar(cands)
                    } else {
                        let vty = value.ty();
                        ScopeBinding::Var(if vty != Ty::Unknown { vty } else { ty.clone() })
                    };
                    scope.assign(name, binding);
                }
            }
            HirStmt::Expr(e) => simulate_expr_in_scope(e, env, scope),
            HirStmt::While { cond, body } => {
                simulate_expr_in_scope(cond, env, scope);
                let pre_frames = scope.frames.clone();
                scope.push();
                simulate_stmts_in_scope(body, env, scope);
                scope.pop();
                let post_frames = scope.frames.clone();
                scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);
            }
            HirStmt::Loop { body } => {
                let pre_frames = scope.frames.clone();
                scope.push();
                simulate_stmts_in_scope(body, env, scope);
                scope.pop();
                let post_frames = scope.frames.clone();
                scope.merge_from(&pre_frames, &[pre_frames.clone(), post_frames], env);
            }
            HirStmt::Atomic(at) => {
                let pre_frames = scope.frames.clone();
                scope.push();
                simulate_stmts_in_scope(&at.body, env, scope);
                scope.pop();
                let body_frames = scope.frames.clone();
                scope.frames = pre_frames.clone();
                scope.push();
                simulate_stmts_in_scope(&at.on_rollback, env, scope);
                scope.pop();
                let rb_frames = scope.frames.clone();
                scope.merge_from(&pre_frames, &[body_frames, rb_frames], env);
            }
            HirStmt::Race { branches } => {
                let pre_frames = scope.frames.clone();
                let mut br_frames = Vec::new();
                for br in branches {
                    scope.frames = pre_frames.clone();
                    scope.push();
                    simulate_stmts_in_scope(br, env, scope);
                    scope.pop();
                    br_frames.push(scope.frames.clone());
                }
                if br_frames.is_empty() {
                    scope.frames = pre_frames;
                } else {
                    scope.merge_from(&pre_frames, &br_frames, env);
                }
            }
            _ => {}
        }
    }
}

fn resolve_expr_query_shape(
    expr: &HirExpr,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> Option<QueryShape> {
    match expr {
        HirExpr::Query(q) => Some(QueryShape::Row(q.terms.clone())),
        HirExpr::Path { name, .. } => match scope.get(name) {
            Some(ScopeBinding::QueryRow { terms, .. }) => Some(QueryShape::Row(terms.clone())),
            Some(ScopeBinding::QueryTuple { elems, .. }) => Some(QueryShape::Tuple(elems.clone())),
            _ => None,
        },
        HirExpr::Unary {
            op: HirUnOp::Ref | HirUnOp::RefMut,
            expr: inner,
            ..
        }
        | HirExpr::Cast { expr: inner, .. } => resolve_expr_query_shape(inner, env, scope),
        HirExpr::Call(c) if option_call_primary(c).is_some() => {
            if let Some(target) = option_call_primary(c) {
                let is_unwrap_call = matches!(
                    c.callee.as_str(),
                    "unwrap"
                        | "expect"
                        | "unwrap_or"
                        | "Option::unwrap"
                        | "Option::expect"
                        | "Option::unwrap_or"
                );
                let mut shape = resolve_expr_query_shape(target, env, scope);
                if matches!(c.callee.as_str(), "unwrap_or" | "Option::unwrap_or")
                    && let Some(fb) = option_call_fallback(c)
                {
                    shape = merge_query_shapes(shape, resolve_expr_query_shape(fb, env, scope));
                }
                if is_unwrap_call {
                    let target_ty = target.ty();
                    let is_query_row_opt = matches!(
                        target_ty,
                        Ty::Option(ref inner) if matches!(inner.as_ref(), Ty::QueryRow(_) | Ty::Ref(_))
                    ) || matches!(target_ty, Ty::QueryRow(_) | Ty::Ref(_));
                    if !is_query_row_opt
                        && let Some(QueryShape::Row(ref terms)) = shape
                        && terms.len() == 1
                        && (terms[0].field_name.is_some()
                            || matches!(
                                terms[0].mode,
                                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                            ))
                    {
                        return None;
                    }
                }
                if let Some(s) = shape {
                    return Some(s);
                }
            }
            net_query_terms_from_expr(expr, env).map(QueryShape::Row)
        }
        HirExpr::Call(c)
            if c.receiver.is_none()
                && matches!(c.callee.as_str(), "Some" | "Option::Some")
                && c.args.len() == 1 =>
        {
            resolve_expr_query_shape(&c.args[0], env, scope)
        }
        HirExpr::Tuple { elems, .. } => {
            let shapes: Vec<Option<QueryShape>> = elems
                .iter()
                .map(|e| resolve_expr_query_shape(e, env, scope))
                .collect();
            shapes
                .iter()
                .any(Option::is_some)
                .then_some(QueryShape::Tuple(shapes))
        }
        HirExpr::Block { stmts, tail, .. } => {
            let t = tail.as_deref()?;
            let mut inner = scope.clone();
            inner.push();
            simulate_stmts_in_scope(stmts, env, &mut inner);
            resolve_expr_query_shape(t, env, &inner)
        }
        HirExpr::If {
            let_pat,
            cond,
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            let then_shape = then_tail.as_deref().and_then(|t| {
                let mut then_scope = scope.clone();
                then_scope.push();
                if let Some(pat) = let_pat {
                    bind_pattern(pat, cond.ty(), Some(cond), env, &mut then_scope);
                }
                simulate_stmts_in_scope(then_stmts, env, &mut then_scope);
                resolve_expr_query_shape(t, env, &then_scope)
            });
            let else_shape = else_tail.as_deref().and_then(|t| {
                let mut else_scope = scope.clone();
                else_scope.push();
                simulate_stmts_in_scope(else_stmts, env, &mut else_scope);
                resolve_expr_query_shape(t, env, &else_scope)
            });
            merge_query_shapes(then_shape, else_shape)
        }
        HirExpr::Match(m) => {
            let mut acc: Option<QueryShape> = None;
            for arm in &m.arms {
                let mut arm_scope = scope.clone();
                arm_scope.push();
                bind_pattern(
                    &arm.pattern,
                    m.scrutinee.ty(),
                    Some(&m.scrutinee),
                    env,
                    &mut arm_scope,
                );
                let arm_shape = resolve_expr_query_shape(&arm.body, env, &arm_scope);
                acc = merge_query_shapes(acc, arm_shape);
            }
            acc
        }
        other => net_query_terms_from_expr(other, env).map(QueryShape::Row),
    }
}

fn resolve_expr_query_terms(
    expr: &HirExpr,
    env: &LowerEnv<'_>,
    scope: &ScopeStack,
) -> Option<Vec<HirQueryTerm>> {
    match resolve_expr_query_shape(expr, env, scope)? {
        QueryShape::Row(terms) => Some(terms),
        QueryShape::Tuple(_) => None,
    }
}

fn bind_pattern(
    pat: &HirPattern,
    ty: Ty,
    src_expr: Option<&HirExpr>,
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
) {
    let shape = src_expr.and_then(|e| resolve_expr_query_shape(e, env, scope));
    let cands = src_expr
        .map(|e| resolve_expr_candidate_tys(e, env, scope))
        .unwrap_or_default();
    bind_pattern_with_shape(pat, ty, shape.as_ref(), &cands, env, scope);
}

fn bind_pattern_with_shape(
    pat: &HirPattern,
    ty: Ty,
    shape: Option<&QueryShape>,
    cands: &[Ty],
    env: &LowerEnv<'_>,
    scope: &mut ScopeStack,
) {
    match pat {
        HirPattern::Binding { name, .. } => match shape {
            Some(QueryShape::Row(terms)) => {
                let mut extra_tys = Vec::new();
                for c in cands {
                    if !matches!(c, Ty::Ref(s) if s == "Entity") {
                        push_unique_ty(&mut extra_tys, c.clone());
                    }
                }
                scope.insert(
                    name.clone(),
                    ScopeBinding::QueryRow {
                        terms: terms.clone(),
                        extra_tys,
                    },
                );
            }
            Some(QueryShape::Tuple(elems)) => {
                let mut extra_tys = Vec::new();
                for c in cands {
                    push_unique_ty(&mut extra_tys, c.clone());
                }
                push_unique_ty(&mut extra_tys, ty.clone());
                let picked = if extra_tys.is_empty() {
                    ty
                } else {
                    pick_authoritative_ty(&extra_tys, env)
                };
                scope.insert(
                    name.clone(),
                    ScopeBinding::QueryTuple {
                        ty: picked,
                        elems: elems.clone(),
                        extra_tys,
                    },
                );
            }
            None => {
                let mut all = Vec::new();
                push_unique_ty(&mut all, ty.clone());
                for c in cands {
                    push_unique_ty(&mut all, c.clone());
                }
                if all.len() > 1 {
                    scope.insert(name.clone(), ScopeBinding::MultiVar(all));
                } else {
                    scope.insert(
                        name.clone(),
                        ScopeBinding::Var(all.into_iter().next().unwrap_or(ty)),
                    );
                }
            }
        },
        HirPattern::Tuple(items) => {
            let elem_tys = match ty {
                Ty::Tuple(ts) => ts,
                _ => Vec::new(),
            };
            let elem_shapes = match shape {
                Some(QueryShape::Tuple(es)) => es.as_slice(),
                _ => &[],
            };
            for (idx, p) in items.iter().enumerate() {
                let mut elem_cands = Vec::new();
                if let Some(ety) = elem_tys.get(idx) {
                    push_unique_ty(&mut elem_cands, ety.clone());
                }
                for c in cands {
                    if let Ty::Tuple(ts) = c
                        && let Some(cty) = ts.get(idx)
                    {
                        push_unique_ty(&mut elem_cands, cty.clone());
                    }
                }
                let ety = if elem_cands.is_empty() {
                    Ty::Unknown
                } else {
                    pick_authoritative_ty(&elem_cands, env)
                };
                let eshape = elem_shapes.get(idx).and_then(|s| s.as_ref());
                bind_pattern_with_shape(p, ety, eshape, &elem_cands, env, scope);
            }
        }
        HirPattern::TupleStruct { path, fields } => {
            if matches!(path.as_str(), "Some" | "Option::Some") && fields.len() == 1 {
                let unwrap_opt = |t: &Ty| -> Ty {
                    let mut cur = t;
                    while let Ty::Borrow { inner, .. } = cur {
                        cur = inner.as_ref();
                    }
                    if let Ty::Option(inner) = cur {
                        (**inner).clone()
                    } else {
                        t.clone()
                    }
                };
                let unwrapped_ty = unwrap_opt(&ty);
                let unwrapped_cands: Vec<Ty> = cands.iter().map(unwrap_opt).collect();
                let inner_shape = if matches!(unwrapped_ty, Ty::Borrow { .. })
                    && matches!(
                        shape,
                        Some(QueryShape::Row(terms))
                            if terms.len() == 1
                                && (terms[0].field_name.is_some()
                                    || matches!(
                                        terms[0].mode,
                                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                                    ))
                    ) {
                    None
                } else {
                    shape
                };
                bind_pattern_with_shape(
                    &fields[0],
                    unwrapped_ty,
                    inner_shape,
                    &unwrapped_cands,
                    env,
                    scope,
                );
            } else {
                for f in fields {
                    bind_pattern_with_shape(f, Ty::Unknown, None, &[], env, scope);
                }
            }
        }
        HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
    }
}

fn option_call_fallback(c: &HirCall) -> Option<&HirExpr> {
    if c.receiver.is_some() {
        c.args.first()
    } else {
        c.args.get(1)
    }
}

fn is_query_like_expr(mut expr: &HirExpr) -> bool {
    while let HirExpr::Block { tail: Some(t), .. } = expr {
        expr = t.as_ref();
    }
    find_net_query_call(expr).is_some() || matches!(expr, HirExpr::Query(_))
}

fn find_net_query_call(expr: &HirExpr) -> Option<&HirCall> {
    let mut cur = expr;
    while let HirExpr::Call(c) = cur {
        if c.receiver.is_none() && matches!(c.callee.as_str(), "server_query" | "client_query") {
            return Some(c);
        }
        if matches!(
            c.callee.as_str(),
            "on" | "unwrap" | "with" | "without" | "changed" | "added" | "allow" | "has"
        ) && let Some(ref recv) = c.receiver
        {
            cur = recv.as_ref();
        } else {
            return None;
        }
    }
    None
}

fn net_query_terms_from_expr(expr: &HirExpr, env: &LowerEnv<'_>) -> Option<Vec<HirQueryTerm>> {
    let call = find_net_query_call(expr)?;
    let mut terms = Vec::new();
    for (arg_name, arg) in call.arg_names.iter().zip(call.args.iter()) {
        let Some(alias) = arg_name else { continue };
        let (mode, inner) = match arg {
            HirExpr::Unary {
                op: HirUnOp::RefMut,
                expr,
                ..
            } => (TermAccessMode::Write, expr.as_ref()),
            HirExpr::Unary { expr, .. } => (TermAccessMode::Read, expr.as_ref()),
            other => (TermAccessMode::Read, other),
        };
        let (comp_name, field_name) = match inner {
            HirExpr::Path { name, .. } => (name.clone(), None),
            HirExpr::Field { base, field, .. } => {
                let comp = match base.as_ref() {
                    HirExpr::Path { name, .. } => name.clone(),
                    _ => continue,
                };
                (comp, Some(field.clone()))
            }
            _ => continue,
        };
        let storage_key = if let Some(ref f) = field_name {
            let lookup = format!("{comp_name}.{f}");
            env.field_to_stratum
                .get(&lookup)
                .cloned()
                .unwrap_or_else(|| comp_name.clone())
        } else {
            comp_name.clone()
        };
        let canonical_component = env.resolve_canonical_component(&storage_key);
        terms.push(HirQueryTerm {
            alias: alias.clone(),
            storage_key,
            canonical_component,
            field_name,
            mode,
            is_sparse: env.is_sparse(&comp_name),
        });
    }
    Some(terms)
}

fn lookup_var_ty(name: &str, env: &LowerEnv<'_>, scope: &ScopeStack) -> Ty {
    if matches!(name, "None" | "Option::None") {
        return Ty::Option(Box::new(Ty::Unknown));
    }
    if let Some(b) = scope.get(name) {
        return match b {
            ScopeBinding::Var(ty) | ScopeBinding::Resource { ty, .. } => ty.clone(),
            ScopeBinding::QueryTuple { ty, extra_tys, .. } => {
                let mut cands = Vec::new();
                push_unique_ty(&mut cands, ty.clone());
                for t in extra_tys {
                    push_unique_ty(&mut cands, t.clone());
                }
                pick_authoritative_ty(&cands, env)
            }
            ScopeBinding::MultiVar(tys) => pick_authoritative_ty(tys, env),
            ScopeBinding::Trigger { event, .. } => Ty::Named(event.clone()),
            ScopeBinding::QueryRow {
                terms, extra_tys, ..
            } => {
                let picked = pick_authoritative_ty(extra_tys, env);
                if picked != Ty::Unknown {
                    picked
                } else if terms.len() == 1
                    && (terms[0].field_name.is_some()
                        || matches!(
                            terms[0].mode,
                            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                        ))
                    && terms[0].alias == name
                {
                    resolve_query_term_ty(&terms[0], env)
                } else {
                    Ty::Ref("Entity".to_owned())
                }
            }
            ScopeBinding::SpatialCandidate => Ty::Ref("Entity".to_owned()),
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
            "vec2::ZERO" | "vec2::ONE" | "vec2::X" | "vec2::Y" => return Ty::Vec2,
            "vec3::ZERO" | "vec3::ONE" | "vec3::X" | "vec3::Y" | "vec3::Z" | "vec3::UP" => {
                return Ty::Vec3;
            }
            "vec4::ZERO" | "vec4::ONE" | "vec4::X" | "vec4::Y" | "vec4::Z" | "vec4::W" => {
                return Ty::Vec4;
            }
            "ivec2::ZERO" | "ivec2::ONE" | "ivec2::X" | "ivec2::Y" => return Ty::IVec2,
            "ivec3::ZERO" | "ivec3::ONE" | "ivec3::X" | "ivec3::Y" | "ivec3::Z" => {
                return Ty::IVec3;
            }
            "uvec2::ZERO" | "uvec2::ONE" | "uvec2::X" | "uvec2::Y" => return Ty::UVec2,
            _ => {}
        }
    }
    if env.objects.contains(name) {
        return Ty::Ref("Entity".to_owned());
    }
    Ty::Unknown
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
                    ScopeBinding::QueryRow { terms, extra_tys } => {
                        let mut cands = Vec::new();
                        if field == "id" {
                            push_unique_ty(&mut cands, Ty::Ref("Entity".to_owned()));
                        }
                        for t in terms {
                            if t.alias == field {
                                push_unique_ty(&mut cands, resolve_query_term_ty(t, env));
                            }
                        }
                        if terms.len() == 1 {
                            let tty = resolve_query_term_ty(&terms[0], env);
                            push_unique_ty(
                                &mut cands,
                                resolve_field_ty_from_base_ty(&tty, field, env),
                            );
                        }
                        for ety in extra_tys {
                            push_unique_ty(
                                &mut cands,
                                resolve_field_ty_from_base_ty(ety, field, env),
                            );
                        }
                        if !cands.is_empty() {
                            return pick_authoritative_ty(&cands, env);
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
                        if let Some(fields) = env.find_item_fields(canonical)
                            && let Some((_, fty)) = fields.iter().find(|(n, _)| n == field)
                        {
                            return fty.clone();
                        }
                    }
                    ScopeBinding::MultiVar(tys) => {
                        let mut cands = Vec::new();
                        for ty in tys {
                            push_unique_ty(
                                &mut cands,
                                resolve_field_ty_from_base_ty(ty, field, env),
                            );
                        }
                        return pick_authoritative_ty(&cands, env);
                    }
                    ScopeBinding::QueryTuple { ty, extra_tys, .. } => {
                        let mut cands = Vec::new();
                        push_unique_ty(&mut cands, resolve_field_ty_from_base_ty(ty, field, env));
                        for ety in extra_tys {
                            push_unique_ty(
                                &mut cands,
                                resolve_field_ty_from_base_ty(ety, field, env),
                            );
                        }
                        return pick_authoritative_ty(&cands, env);
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
            let mut cands = Vec::new();
            for t in &q.terms {
                if t.alias == field {
                    push_unique_ty(&mut cands, resolve_query_term_ty(t, env));
                }
            }
            pick_authoritative_ty(&cands, env)
        }
        other => {
            let mut cands = Vec::new();
            if let Some(terms) = resolve_expr_query_terms(other, env, scope) {
                if field == "id" {
                    push_unique_ty(&mut cands, Ty::Ref("Entity".to_owned()));
                }
                for t in &terms {
                    if t.alias == field {
                        push_unique_ty(&mut cands, resolve_query_term_ty(t, env));
                    }
                }
            }
            let base_cands = resolve_expr_candidate_tys(other, env, scope);
            for bty in &base_cands {
                push_unique_ty(&mut cands, resolve_field_ty_from_base_ty(bty, field, env));
            }
            if !cands.is_empty() {
                return pick_authoritative_ty(&cands, env);
            }
            resolve_field_ty_from_base_ty(&base.ty(), field, env)
        }
    }
}

fn resolve_field_ty_from_base_ty(base_ty: &Ty, field: &str, env: &LowerEnv<'_>) -> Ty {
    let mut base_ty = base_ty;
    while let Ty::Borrow { inner, .. } = base_ty {
        base_ty = inner.as_ref();
    }
    match base_ty {
        Ty::Vec2 => {
            if !field.is_empty() && field.bytes().all(|b| matches!(b, b'x' | b'y')) {
                match field.len() {
                    1 => Ty::F32,
                    2 => Ty::Vec2,
                    3 => Ty::Vec3,
                    4 => Ty::Vec4,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::Vec3 | Ty::Vec3a => {
            if !field.is_empty() && field.bytes().all(|b| matches!(b, b'x' | b'y' | b'z')) {
                match field.len() {
                    1 => Ty::F32,
                    2 => Ty::Vec2,
                    3 => Ty::Vec3,
                    4 => Ty::Vec4,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::Vec4 | Ty::Quat => {
            if !field.is_empty()
                && field
                    .bytes()
                    .all(|b| matches!(b, b'x' | b'y' | b'z' | b'w'))
            {
                match field.len() {
                    1 => Ty::F32,
                    2 => Ty::Vec2,
                    3 => Ty::Vec3,
                    4 => Ty::Vec4,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::IVec2 => {
            if !field.is_empty() && field.bytes().all(|b| matches!(b, b'x' | b'y')) {
                match field.len() {
                    1 => Ty::I32,
                    2 => Ty::IVec2,
                    3 => Ty::IVec3,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::IVec3 => {
            if !field.is_empty() && field.bytes().all(|b| matches!(b, b'x' | b'y' | b'z')) {
                match field.len() {
                    1 => Ty::I32,
                    2 => Ty::IVec2,
                    3 => Ty::IVec3,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::UVec2 => {
            if !field.is_empty() && field.bytes().all(|b| matches!(b, b'x' | b'y')) {
                match field.len() {
                    1 => Ty::U32,
                    2 => Ty::UVec2,
                    _ => Ty::Unknown,
                }
            } else {
                Ty::Unknown
            }
        }
        Ty::Record(fields) => fields
            .iter()
            .find(|(n, _)| n == field)
            .map_or(Ty::Unknown, |(_, t)| t.clone()),
        Ty::QueryRow(terms) => {
            if field == "id" {
                return Ty::Ref("Entity".to_owned());
            }
            if let Some(t) = terms.iter().find(|t| t.alias == field) {
                return t.ty.clone();
            }
            Ty::Unknown
        }
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
            if let Some(fields) = env.find_item_fields(name)
                && let Some((_, fty)) = fields.iter().find(|(n, _)| n == field)
            {
                return fty.clone();
            }
            Ty::Unknown
        }
        _ => Ty::Unknown,
    }
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
                .find(|c| is_expr_or_block_node(c.kind()))
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
                .find(|c| is_expr_or_block_node(c.kind()) && c.kind() != SyntaxKind::RecordLitExpr)
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

fn is_expr_or_block_node(kind: SyntaxKind) -> bool {
    is_expr_node(kind) || kind == SyntaxKind::Block
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
