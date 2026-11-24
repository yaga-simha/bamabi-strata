//! Schema layout solving, enum/field collection, and ABI signature hashing.

use crate::diagnostics::{Diagnostic, FixIt, Span, codes};
use crate::hir::{HirBinOp, HirExpr, HirUnOp, SemVerInfo};
use crate::hir_lower::{LowerEnv, ScopeStack, is_expr_node, lower_expr};
use crate::layout::{
    EnumDef, LayoutEnv, SchemaItemKind, SolvedLayout, flags_from_attr_names, solve_pod_layout,
    solve_task_state_layout, solve_timeline_layout,
};
use crate::types::{Ty, UnitDim, parse_type_node, parse_type_node_with_user_types};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{
    self, AstNode, ComponentDecl, EnumDecl, ResourceDecl, SourceFile, StructDecl,
};
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode, TextRange, parse};

/// Extracts only schema/declaration headers (stripping `sys`/`obs`/`fn`/`sim_test`/`net_sim_test`
/// bodies) so Salsa early-cutoff avoids re-running layout resolution on body-only edits.
pub fn extract_schema_signature_text(src: &str) -> String {
    let parsed = parse(src);
    let root = parsed.syntax();
    let mut out = String::new();
    let Some(sf) = SourceFile::cast(root) else {
        return out;
    };
    for item in sf.items() {
        let node = item.syntax().clone();
        match item {
            ast::Item::Sys(s) => {
                // Keep everything before the body block.
                let body_start = s.body().map(|b| u32::from(b.syntax().text_range().start()));
                push_node_prefix(&node, body_start, &mut out);
            }
            ast::Item::Obs(o) => {
                let body_start = o.body().map(|b| u32::from(b.syntax().text_range().start()));
                push_node_prefix(&node, body_start, &mut out);
            }
            ast::Item::Fn(f) => {
                let body_start = ast::child::<ast::Block>(f.syntax())
                    .map(|b| u32::from(b.syntax().text_range().start()));
                push_node_prefix(&node, body_start, &mut out);
            }
            ast::Item::SimTest(_) | ast::Item::NetSimTest(_) => {}
            _ => {
                out.push_str(&node.text().to_string());
                out.push('\n');
            }
        }
    }
    out
}

pub(super) fn push_node_prefix(node: &SyntaxNode, body_start: Option<u32>, out: &mut String) {
    let text = node.text().to_string();
    let node_start = u32::from(node.text_range().start());
    if let Some(bs) = body_start {
        let rel = (bs.saturating_sub(node_start)) as usize;
        out.push_str(&text[..rel.min(text.len())]);
    } else {
        out.push_str(&text);
    }
    out.push('\n');
}

/// Output of schema & layout resolution prior to full body/concurrency analysis.
pub struct SolvedModuleLayouts {
    /// Canonical module path.
    pub module_path: String,
    /// Module `@version(...)`.
    pub version: Option<SemVerInfo>,
    /// `@deterministic` module flag.
    pub is_deterministic: bool,
    /// Solved component/struct/resource/state layouts.
    pub layouts: IndexMap<String, SolvedLayout>,
    /// Mapping from `@soa` logical name to stratum names.
    pub soa_strata: IndexMap<String, Vec<String>>,
    /// Declared enums.
    pub enums: IndexMap<String, EnumDef>,
    /// Mapping `"Comp.field"` -> `"Comp::stratum"`.
    pub field_to_stratum: HashMap<String, String>,
    /// Layout/schema diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Solves all component, `@soa`, resource, event, stream, struct, enum, relation, timeline,
/// task, fsm, and spatial layouts for a source string.
pub fn solve_module_layouts(file: &str, src: &str) -> SolvedModuleLayouts {
    let parsed = parse(src);
    let mut diags: Vec<Diagnostic> = parsed
        .errors()
        .iter()
        .map(|e| {
            Diagnostic::error(
                codes::E0002_PARSE_ERROR,
                Span::from_bytes(file, src, e.byte_start, e.byte_end),
                e.message.clone(),
                None,
            )
        })
        .collect();

    let Some(sf) = SourceFile::cast(parsed.syntax()) else {
        return SolvedModuleLayouts {
            module_path: "anonymous".to_owned(),
            version: None,
            is_deterministic: false,
            layouts: IndexMap::new(),
            soa_strata: IndexMap::new(),
            enums: IndexMap::new(),
            field_to_stratum: HashMap::new(),
            diagnostics: diags,
        };
    };

    let mut module_path = "anonymous".to_owned();
    let mut version = None;
    let mut is_deterministic = false;

    if let Some(md) = sf.module_decl() {
        if let Some(p) = md.path() {
            module_path = ast::path_text(&p);
        }
        for attr in md.attributes() {
            match ast::attr_name(&attr).as_deref() {
                Some("version") => {
                    if let Some(sv) = ast::child::<ast::AttrArgList>(attr.syntax())
                        .and_then(|l| ast::child::<ast::AttrArg>(l.syntax()))
                        .and_then(|a| ast::child::<ast::SemVer>(a.syntax()))
                    {
                        version = parse_semver_text(&sv.syntax().text().to_string());
                    }
                }
                Some("deterministic") => is_deterministic = true,
                _ => {}
            }
        }
    }

    let mut env = LayoutEnv::default();
    let mut layouts = IndexMap::new();
    let mut soa_strata = IndexMap::new();
    let mut non_pod_wrapper_items: HashSet<String> = HashSet::new();
    // Maps `(ComponentShortName, FieldName)` -> `"Comp::stratum"` (or `"Comp"` for non-SoA).
    let mut field_to_stratum: HashMap<String, String> = HashMap::new();

    // Pass 1: Collect enums first so struct/component fields can reference enum types.
    for item in sf.items() {
        if let ast::Item::Enum(en) = item {
            let def = collect_enum(file, src, &module_path, &en, &mut diags);
            let short = en
                .name()
                .map_or_else(|| "Enum".to_owned(), |t| t.text().to_owned());
            env.enums.insert(short, def);
        }
    }

    // Pass 2: Collect structs, components (including `@soa`), resources, events, streams, relations,
    // timelines, tasks, fsms, spatial indices.
    for item in sf.items() {
        match item {
            ast::Item::Struct(st) => {
                resolve_struct_item(
                    file,
                    src,
                    &module_path,
                    &st,
                    &mut env,
                    &mut layouts,
                    &mut non_pod_wrapper_items,
                    &mut diags,
                );
            }
            ast::Item::Component(comp) => {
                resolve_component_item(
                    file,
                    src,
                    &module_path,
                    &comp,
                    &mut env,
                    &mut layouts,
                    &mut soa_strata,
                    &mut field_to_stratum,
                    &non_pod_wrapper_items,
                    &mut diags,
                );
            }
            ast::Item::Resource(res) => {
                resolve_resource_item(
                    file,
                    src,
                    &module_path,
                    &res,
                    &mut env,
                    &mut layouts,
                    &mut non_pod_wrapper_items,
                    &mut diags,
                );
            }
            ast::Item::Event(ev) => {
                let short = ast::first_ident(ev.syntax())
                    .map_or_else(|| "Event".to_owned(), |t| t.text().to_owned());
                resolve_simple_fields_item(
                    file,
                    src,
                    &module_path,
                    &short,
                    SchemaItemKind::Event,
                    ev.syntax(),
                    &mut env,
                    &mut layouts,
                    &non_pod_wrapper_items,
                    &mut diags,
                );
            }
            ast::Item::Stream(st) => {
                let short = ast::first_ident(st.syntax())
                    .map_or_else(|| "Stream".to_owned(), |t| t.text().to_owned());
                resolve_simple_fields_item(
                    file,
                    src,
                    &module_path,
                    &short,
                    SchemaItemKind::Stream,
                    st.syntax(),
                    &mut env,
                    &mut layouts,
                    &non_pod_wrapper_items,
                    &mut diags,
                );
            }
            ast::Item::Relation(rel) => {
                let short = ast::first_ident(rel.syntax())
                    .map_or_else(|| "Relation".to_owned(), |t| t.text().to_owned());
                let fields: Vec<_> = ast::children::<ast::FieldDecl>(rel.syntax()).collect();
                if !fields.is_empty() {
                    resolve_simple_fields_item(
                        file,
                        src,
                        &module_path,
                        &short,
                        SchemaItemKind::Relation,
                        rel.syntax(),
                        &mut env,
                        &mut layouts,
                        &non_pod_wrapper_items,
                        &mut diags,
                    );
                }
            }
            ast::Item::Timeline(tl) => {
                let short = ast::first_ident(tl.syntax())
                    .map_or_else(|| "Timeline".to_owned(), |t| t.text().to_owned());
                let attr_names: Vec<String> = ast::attrs(tl.syntax())
                    .iter()
                    .filter_map(ast::attr_name)
                    .collect();
                let (_, _, is_summary) =
                    flags_from_attr_names(attr_names.iter().map(|s| s.as_str()));
                if is_summary {
                    diags.push(Diagnostic::error(
                        codes::E0110_SPARSE_SUMMARY_TICK,
                        Span::from_range(file, src, tl.syntax().text_range()),
                        format!("timeline `{short}` uses sparse storage and cannot combine with `@summary_tick`"),
                        None,
                    ));
                }
                let canonical = format!("{module_path}::{short}");
                if let Ok(solved) = solve_timeline_layout(&canonical, &env) {
                    env.resolved.insert(
                        short,
                        (
                            solved.size,
                            solved.align,
                            solved.is_abi_pod,
                            bamabi_sys::BamFieldKind::NESTED.0,
                            canonical.clone(),
                        ),
                    );
                    layouts.insert(canonical, solved);
                }
            }
            ast::Item::Task(task) => {
                let short = ast::first_ident(task.syntax())
                    .map_or_else(|| "Task".to_owned(), |t| t.text().to_owned());
                let attr_names: Vec<String> = ast::attrs(task.syntax())
                    .iter()
                    .filter_map(ast::attr_name)
                    .collect();
                let (_, is_sparse, is_summary) =
                    flags_from_attr_names(attr_names.iter().map(|s| s.as_str()));
                if is_sparse && is_summary {
                    diags.push(Diagnostic::error(
                        codes::E0110_SPARSE_SUMMARY_TICK,
                        Span::from_range(file, src, task.syntax().text_range()),
                        format!("task `{short}` cannot combine `@sparse` and `@summary_tick`"),
                        None,
                    ));
                }
                let live_vars = collect_task_live_vars(file, src, task.syntax(), &mut diags);
                let canonical = format!("{module_path}::{short}");
                if let Ok(solved) = solve_task_state_layout(&canonical, &live_vars, is_sparse, &env)
                {
                    layouts.insert(canonical, solved);
                }
            }
            ast::Item::Fsm(fsm) => {
                let short = ast::first_ident(fsm.syntax())
                    .map_or_else(|| "Fsm".to_owned(), |t| t.text().to_owned());
                let canonical = format!("{module_path}::{short}");
                let fields = vec![
                    ("__state".to_owned(), Ty::U16),
                    ("__flags".to_owned(), Ty::U16),
                ];
                if let Ok(solved) = solve_pod_layout(
                    &canonical,
                    SchemaItemKind::FsmState,
                    &fields,
                    0,
                    Vec::new(),
                    &env,
                ) {
                    layouts.insert(canonical, solved);
                }
            }
            ast::Item::SpatialGrid(sg) => {
                let short = ast::first_ident(sg.syntax())
                    .map_or_else(|| "Grid".to_owned(), |t| t.text().to_owned());
                let canonical = format!("{module_path}::{short}");
                let fields = vec![
                    ("capacity".to_owned(), Ty::U32),
                    ("cell_count".to_owned(), Ty::U32),
                    ("count".to_owned(), Ty::U32),
                    ("cell_size".to_owned(), Ty::F32),
                ];
                if let Ok(solved) = solve_pod_layout(
                    &canonical,
                    SchemaItemKind::SpatialGrid,
                    &fields,
                    0,
                    Vec::new(),
                    &env,
                ) {
                    layouts.insert(canonical, solved);
                }
            }
            ast::Item::SpatialHistory(sh) => {
                let short = ast::first_ident(sh.syntax())
                    .map_or_else(|| "History".to_owned(), |t| t.text().to_owned());
                let canonical = format!("{module_path}::{short}");
                let fields = vec![
                    ("frames".to_owned(), Ty::U32),
                    ("capacity".to_owned(), Ty::U32),
                    ("head_tick".to_owned(), Ty::U32),
                    ("cell_size".to_owned(), Ty::F32),
                ];
                if let Ok(solved) = solve_pod_layout(
                    &canonical,
                    SchemaItemKind::SpatialHistory,
                    &fields,
                    0,
                    Vec::new(),
                    &env,
                ) {
                    layouts.insert(canonical, solved);
                }
            }
            _ => {}
        }
    }

    SolvedModuleLayouts {
        module_path,
        version,
        is_deterministic,
        layouts,
        soa_strata,
        enums: env.enums,
        field_to_stratum,
        diagnostics: diags,
    }
}

pub(super) fn parse_semver_text(s: &str) -> Option<SemVerInfo> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some(SemVerInfo {
        major,
        minor,
        patch,
    })
}

pub(super) fn collect_enum(
    file: &str,
    src: &str,
    module_path: &str,
    en: &EnumDecl,
    diags: &mut Vec<Diagnostic>,
) -> EnumDef {
    let short = en
        .name()
        .map_or_else(|| "Enum".to_owned(), |t| t.text().to_owned());
    let mut explicit_repr: Option<(usize, String, TextRange)> = None;
    for attr in ast::attrs(en.syntax()) {
        if ast::attr_name(&attr).as_deref() == Some("repr")
            && let Some(arg) = attr.args().into_iter().next()
        {
            let txt = arg.syntax().text().to_string();
            let trimmed = txt.trim().to_owned();
            let bytes = match trimmed.as_str() {
                "u8" => Some(1),
                "u16" => Some(2),
                "u32" | "i32" => Some(4),
                _ => None,
            };
            if let Some(b) = bytes {
                explicit_repr = Some((b, trimmed, attr.syntax().text_range()));
            } else {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, attr.syntax().text_range()),
                    format!(
                        "unsupported `@repr({trimmed})` on enum `{short}`; expected `u8`, `u16`, `u32`, or `i32`"
                    ),
                    None,
                ));
            }
        }
    }

    let mut next_disc = 0i128;
    let mut variants = Vec::new();
    for v in en.variants() {
        let v_name = ast::first_ident(v.syntax())
            .map_or_else(|| "Variant".to_owned(), |t| t.text().to_owned());
        let mut seen_eq = false;
        let mut has_minus = false;
        for el in v.syntax().descendants_with_tokens() {
            if let Some(tok) = el.into_token() {
                match tok.kind() {
                    SyntaxKind::Eq => seen_eq = true,
                    SyntaxKind::Minus if seen_eq => has_minus = !has_minus,
                    SyntaxKind::IntLit if seen_eq => {
                        if let Some(parsed) = parse_int_lit_i128(tok.text()) {
                            next_disc = if has_minus {
                                parsed.wrapping_neg()
                            } else {
                                parsed
                            };
                        } else {
                            diags.push(Diagnostic::error(
                                codes::E0103_INVALID_ABI_POD_FIELD,
                                Span::from_range(file, src, tok.text_range()),
                                format!(
                                    "enum `{short}` variant `{v_name}` discriminant `{}` overflows 128-bit integer range",
                                    tok.text()
                                ),
                                None,
                            ));
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
        variants.push((v_name, next_disc));
        next_disc = next_disc.saturating_add(1);
    }

    let min_disc = variants.iter().map(|(_, d)| *d).min().unwrap_or(0);
    let max_disc = variants.iter().map(|(_, d)| *d).max().unwrap_or(0);
    let needed_bytes = if variants.is_empty() || (min_disc >= 0 && max_disc <= 255) {
        1
    } else if min_disc >= 0 && max_disc <= 65_535 {
        2
    } else {
        4
    };
    let has_neg = !variants.is_empty() && min_disc < 0;
    let (repr_bytes, is_signed) = if let Some((exp_bytes, exp_name, exp_range)) = explicit_repr {
        if exp_bytes < needed_bytes {
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, exp_range),
                format!(
                    "enum `{short}` has discriminant(s) outside `@repr({exp_name})` range (requires at least {needed_bytes} bytes)"
                ),
                None,
            ));
        } else if exp_name.starts_with('u') && has_neg {
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, exp_range),
                format!(
                    "enum `{short}` has negative discriminant(s) outside `@repr({exp_name})` range"
                ),
                None,
            ));
        } else if exp_name == "i32"
            && !variants.is_empty()
            && (min_disc < i128::from(i32::MIN) || max_disc > i128::from(i32::MAX))
        {
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, exp_range),
                format!(
                    "enum `{short}` has discriminant(s) outside `@repr(i32)` range ({}..={})",
                    i32::MIN,
                    i32::MAX
                ),
                None,
            ));
        } else if exp_name == "u32" && !variants.is_empty() && max_disc > i128::from(u32::MAX) {
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, exp_range),
                format!(
                    "enum `{short}` has discriminant(s) outside `@repr(u32)` range (0..={})",
                    u32::MAX
                ),
                None,
            ));
        }
        (exp_bytes.max(needed_bytes), exp_name == "i32" || has_neg)
    } else {
        if !variants.is_empty() {
            if has_neg && (min_disc < i128::from(i32::MIN) || max_disc > i128::from(i32::MAX)) {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, en.syntax().text_range()),
                    format!(
                        "enum `{short}` has signed discriminant(s) outside `i32` range ({}..={})",
                        i32::MIN,
                        i32::MAX
                    ),
                    None,
                ));
            } else if !has_neg && max_disc > i128::from(u32::MAX) {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, en.syntax().text_range()),
                    format!(
                        "enum `{short}` has discriminant(s) outside `u32` range (0..={})",
                        u32::MAX
                    ),
                    None,
                ));
            }
        }
        (needed_bytes, has_neg)
    };
    let variants_i64 = variants
        .into_iter()
        .map(|(n, d)| (n, i64::try_from(d).unwrap_or(0)))
        .collect();
    EnumDef {
        canonical_name: format!("{module_path}::{short}"),
        variants: variants_i64,
        repr_bytes,
        is_signed,
    }
}

fn find_banned_wire(ty: &Ty) -> Option<&str> {
    match ty {
        Ty::BannedWire(name) => Some(name.as_str()),
        Ty::Array { elem, .. }
        | Ty::SmallVec { elem, .. }
        | Ty::Option(elem)
        | Ty::Borrow { inner: elem, .. } => find_banned_wire(elem),
        Ty::Result { ok, err } => find_banned_wire(ok).or_else(|| find_banned_wire(err)),
        Ty::Tuple(items) => items.iter().find_map(find_banned_wire),
        _ => None,
    }
}

fn ty_uses_non_pod_wrapper(ty: &Ty, non_pod_wrapper_items: &HashSet<String>) -> bool {
    match ty {
        Ty::Option(_) | Ty::Result { .. } | Ty::Borrow { .. } => true,
        Ty::Named(n) => non_pod_wrapper_items.contains(n),
        Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => {
            ty_uses_non_pod_wrapper(elem, non_pod_wrapper_items)
        }
        Ty::Tuple(items) => items
            .iter()
            .any(|t| ty_uses_non_pod_wrapper(t, non_pod_wrapper_items)),
        _ => false,
    }
}

pub(super) fn check_and_collect_fields(
    file: &str,
    src: &str,
    owner_name: &str,
    field_nodes: &[ast::FieldDecl],
    diags: &mut Vec<Diagnostic>,
) -> Vec<(String, Ty)> {
    let mut out = Vec::new();
    for f in field_nodes {
        let fname = f
            .name()
            .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
        let ty = f.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
        if let Some(banned) = find_banned_wire(&ty) {
            let replacement = match banned {
                "String" | "str" => "InlineStr<32>",
                "Vec" => "SmallVec<T, 4>",
                "usize" | "u128" => "u64",
                "isize" | "i128" => "i64",
                _ => "u32",
            };
            let fixit = if matches!(ty, Ty::BannedWire(_)) {
                f.type_node().map(|tn| FixIt {
                    replace_byte_start: u32::from(tn.text_range().start()),
                    replace_byte_end: u32::from(tn.text_range().end()),
                    replacement: replacement.to_owned(),
                })
            } else {
                None
            };
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, f.syntax().text_range()),
                format!(
                    "field `{owner_name}.{fname}` uses banned non-ABI type `{banned}`; use `{replacement}`"
                ),
                fixit,
            ));
        } else if let Ty::InlineStr(cap) = ty
            && cap % 4 != 0
        {
            diags.push(Diagnostic::error(
                codes::E0104_PADDING_HAZARD,
                Span::from_range(file, src, f.syntax().text_range()),
                format!(
                    "`{owner_name}.{fname}: InlineStr<{cap}>` capacity must be a multiple of 4 to avoid C99 tail padding"
                ),
                None,
            ));
        }
        // Check unit consistency on default expression if present.
        if let Some(dim) = ty.unit_dim() {
            check_field_default_unit(file, src, f.syntax(), dim, diags);
        }
        out.push((fname, ty));
    }
    out
}

pub(super) fn check_field_default_unit(
    file: &str,
    src: &str,
    field_node: &SyntaxNode,
    expected: UnitDim,
    diags: &mut Vec<Diagnostic>,
) {
    let mut saw_eq = false;
    for el in field_node.descendants_with_tokens() {
        if let NodeOrToken::Token(tok) = el {
            if tok.kind() == SyntaxKind::Eq {
                saw_eq = true;
            } else if saw_eq
                && tok.kind() == SyntaxKind::UnitLit
                && let Some(Ty::UnitScalar { dim, .. }) = Ty::unit_from_literal(tok.text())
                && dim != expected
            {
                diags.push(Diagnostic::error(
                    codes::E0102_UNIT_MISMATCH,
                    Span::from_range(file, src, tok.text_range()),
                    format!("unit mismatch in field initializer `{}`", tok.text()),
                    None,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_struct_item(
    file: &str,
    src: &str,
    module_path: &str,
    st: &StructDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    non_pod_wrapper_items: &mut HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let short = st
        .name()
        .map_or_else(|| "Struct".to_owned(), |t| t.text().to_owned());
    let diags_before = diags.len();
    let fields = check_and_collect_fields(file, src, &short, &st.fields(), diags);
    let canonical = format!("{module_path}::{short}");
    match solve_pod_layout(
        &canonical,
        SchemaItemKind::Struct,
        &fields,
        0,
        Vec::new(),
        env,
    ) {
        Ok(solved) => {
            env.resolved.insert(
                short,
                (
                    solved.size,
                    solved.align,
                    solved.is_abi_pod,
                    bamabi_sys::BamFieldKind::NESTED.0,
                    canonical.clone(),
                ),
            );
            layouts.insert(canonical, solved);
        }
        Err(err) => {
            if fields
                .iter()
                .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
            {
                non_pod_wrapper_items.insert(short);
            } else if diags.len() == diags_before {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, st.syntax().text_range()),
                    format!("struct `{short}` does not have a valid AbiPod layout: {err}"),
                    None,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_resource_item(
    file: &str,
    src: &str,
    module_path: &str,
    res: &ResourceDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    non_pod_wrapper_items: &mut HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let short = res
        .name()
        .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
    let diags_before = diags.len();
    let fields = check_and_collect_fields(file, src, &short, &res.fields(), diags);
    let canonical = format!("{module_path}::{short}");
    match solve_pod_layout(
        &canonical,
        SchemaItemKind::Resource,
        &fields,
        0,
        Vec::new(),
        env,
    ) {
        Ok(solved) => {
            env.resolved.insert(
                short,
                (
                    solved.size,
                    solved.align,
                    solved.is_abi_pod,
                    bamabi_sys::BamFieldKind::NESTED.0,
                    canonical.clone(),
                ),
            );
            layouts.insert(canonical, solved);
        }
        Err(err) => {
            if fields
                .iter()
                .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
            {
                non_pod_wrapper_items.insert(short);
            } else if diags.len() == diags_before {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, res.syntax().text_range()),
                    format!("resource `{short}` does not have a valid AbiPod layout: {err}"),
                    None,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_simple_fields_item(
    file: &str,
    src: &str,
    module_path: &str,
    short: &str,
    kind: SchemaItemKind,
    node: &SyntaxNode,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    non_pod_wrapper_items: &HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let diags_before = diags.len();
    let field_nodes: Vec<_> = ast::children::<ast::FieldDecl>(node).collect();
    let fields = check_and_collect_fields(file, src, short, &field_nodes, diags);
    let canonical = format!("{module_path}::{short}");
    match solve_pod_layout(&canonical, kind, &fields, 0, Vec::new(), env) {
        Ok(solved) => {
            env.resolved.insert(
                short.to_owned(),
                (
                    solved.size,
                    solved.align,
                    solved.is_abi_pod,
                    bamabi_sys::BamFieldKind::NESTED.0,
                    canonical.clone(),
                ),
            );
            layouts.insert(canonical, solved);
        }
        Err(err) => {
            if !fields
                .iter()
                .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
                && diags.len() == diags_before
            {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    Span::from_range(file, src, node.text_range()),
                    format!("item `{short}` does not have a valid AbiPod layout: {err}"),
                    None,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_component_item(
    file: &str,
    src: &str,
    module_path: &str,
    comp: &ComponentDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    soa_strata: &mut IndexMap<String, Vec<String>>,
    field_to_stratum: &mut HashMap<String, String>,
    non_pod_wrapper_items: &HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let short = comp
        .name()
        .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
    let attr_names: Vec<String> = comp
        .attributes()
        .iter()
        .filter_map(ast::attr_name)
        .collect();
    let (flags, is_sparse, is_summary) =
        flags_from_attr_names(attr_names.iter().map(|s| s.as_str()));
    let has_no_pad = attr_names.iter().any(|a| a == "no_pad");
    let is_soa = attr_names.iter().any(|a| a == "soa");

    if is_sparse && is_summary {
        diags.push(Diagnostic::error(
            codes::E0110_SPARSE_SUMMARY_TICK,
            Span::from_range(file, src, comp.syntax().text_range()),
            format!("component `{short}` cannot combine `@sparse` and `@summary_tick`"),
            None,
        ));
    }

    let reqs: Vec<String> = comp
        .require_clause()
        .map(|rc| {
            ast::children::<ast::RequireItem>(rc.syntax())
                .filter_map(|ri| ast::child::<ast::Path>(ri.syntax()).map(|p| ast::path_text(&p)))
                .collect()
        })
        .unwrap_or_default();

    let strata = comp.strata();
    if is_soa || !strata.is_empty() {
        let mut stratum_names = Vec::new();
        let hot_canon = format!("{module_path}::{short}");
        for st in &strata {
            let sname = st.stratum_name();
            let diags_before = diags.len();
            let raw_fields = check_and_collect_fields(
                file,
                src,
                &format!("{short}::{sname}"),
                &st.fields(),
                diags,
            );
            for (fn_name, _) in &raw_fields {
                field_to_stratum.insert(format!("{short}.{fn_name}"), format!("{short}::{sname}"));
            }
            if st.is_hot() {
                match solve_pod_layout(
                    &hot_canon,
                    SchemaItemKind::SoaHot,
                    &raw_fields,
                    flags,
                    reqs.clone(),
                    env,
                ) {
                    Ok(solved) => {
                        if has_no_pad && solved.explicit_pad_bytes > 0 {
                            diags.push(Diagnostic::error(
                                codes::E0104_PADDING_HAZARD,
                                Span::from_range(file, src, st.syntax().text_range()),
                                format!(
                                    "`{short}::hot` requires {} explicit padding bytes",
                                    solved.explicit_pad_bytes
                                ),
                                None,
                            ));
                        }
                        layouts.insert(format!("{hot_canon}::hot"), solved.clone());
                        layouts.insert(hot_canon.clone(), solved);
                        stratum_names.push(format!("{short}::hot"));
                    }
                    Err(err) => {
                        if !raw_fields
                            .iter()
                            .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
                            && diags.len() == diags_before
                        {
                            diags.push(Diagnostic::error(
                                codes::E0103_INVALID_ABI_POD_FIELD,
                                Span::from_range(file, src, st.syntax().text_range()),
                                format!(
                                    "component stratum `{short}::{sname}` does not have a valid AbiPod layout: {err}"
                                ),
                                None,
                            ));
                        }
                    }
                }
            } else {
                let cold_short = format!("{short}__{sname}");
                let cold_canon = format!("{module_path}::{cold_short}");
                let mut cold_reqs = vec![hot_canon.clone()];
                cold_reqs.extend(reqs.iter().cloned());
                match solve_pod_layout(
                    &cold_canon,
                    SchemaItemKind::SoaCold,
                    &raw_fields,
                    0,
                    cold_reqs,
                    env,
                ) {
                    Ok(solved) => {
                        layouts.insert(format!("{hot_canon}::{sname}"), solved.clone());
                        layouts.insert(cold_canon, solved);
                        stratum_names.push(format!("{short}::{sname}"));
                    }
                    Err(err) => {
                        if !raw_fields
                            .iter()
                            .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
                            && diags.len() == diags_before
                        {
                            diags.push(Diagnostic::error(
                                codes::E0103_INVALID_ABI_POD_FIELD,
                                Span::from_range(file, src, st.syntax().text_range()),
                                format!(
                                    "component stratum `{short}::{sname}` does not have a valid AbiPod layout: {err}"
                                ),
                                None,
                            ));
                        }
                    }
                }
            }
        }
        soa_strata.insert(short.clone(), stratum_names);
    } else {
        let diags_before = diags.len();
        let raw_fields = check_and_collect_fields(file, src, &short, &comp.fields(), diags);
        for (fn_name, _) in &raw_fields {
            field_to_stratum.insert(format!("{short}.{fn_name}"), short.clone());
        }
        let canonical = format!("{module_path}::{short}");
        match solve_pod_layout(
            &canonical,
            SchemaItemKind::Component,
            &raw_fields,
            flags,
            reqs,
            env,
        ) {
            Ok(solved) => {
                if has_no_pad && solved.explicit_pad_bytes > 0 {
                    diags.push(Diagnostic::error(
                        codes::E0104_PADDING_HAZARD,
                        Span::from_range(file, src, comp.syntax().text_range()),
                        format!(
                            "component `{short}` has {} padding bytes under `@no_pad`",
                            solved.explicit_pad_bytes
                        ),
                        None,
                    ));
                }
                if solved.size > 64 {
                    diags.push(Diagnostic::warning(
                        codes::W0404_LARGE_AOS_COMPONENT_SPLIT_SOA,
                        Span::from_range(file, src, comp.syntax().text_range()),
                        format!(
                            "component `{short}` is {} bytes (> 64 B cache line); consider `@soa` hot/cold splitting",
                            solved.size
                        ),
                        None,
                    ));
                }
                env.resolved.insert(
                    short,
                    (
                        solved.size,
                        solved.align,
                        solved.is_abi_pod,
                        bamabi_sys::BamFieldKind::NESTED.0,
                        canonical.clone(),
                    ),
                );
                layouts.insert(canonical, solved);
            }
            Err(err) => {
                if !raw_fields
                    .iter()
                    .any(|(_, ty)| ty_uses_non_pod_wrapper(ty, non_pod_wrapper_items))
                    && diags.len() == diags_before
                {
                    diags.push(Diagnostic::error(
                        codes::E0103_INVALID_ABI_POD_FIELD,
                        Span::from_range(file, src, comp.syntax().text_range()),
                        format!("component `{short}` does not have a valid AbiPod layout: {err}"),
                        None,
                    ));
                }
            }
        }
    }
}

pub(super) fn collect_task_live_vars(
    file: &str,
    src: &str,
    task_node: &SyntaxNode,
    diags: &mut Vec<Diagnostic>,
) -> Vec<(String, Ty)> {
    let mut vars = Vec::new();
    // Params
    if let Some(pl) = ast::child::<ast::ParamList>(task_node) {
        for p in ast::children::<ast::Param>(pl.syntax()) {
            let pname = ast::first_ident(p.syntax())
                .map_or_else(|| "param".to_owned(), |t| t.text().to_owned());
            let ty = p
                .syntax()
                .children()
                .find(|c| {
                    matches!(
                        c.kind(),
                        SyntaxKind::TypeRef | SyntaxKind::ArrayType | SyntaxKind::RefType
                    )
                })
                .map_or(Ty::Unknown, |n| parse_type_node(&n));
            if let Ty::BannedWire(ref b) = ty {
                diags.push(Diagnostic::error(
                    codes::E0302_NON_POD_ACROSS_WAIT,
                    Span::from_range(file, src, p.syntax().text_range()),
                    format!("task parameter `{pname}: {b}` cannot live across suspension points; must satisfy AbiPod"),
                    None,
                ));
            } else if ty != Ty::Unknown {
                vars.push((pname, ty));
            }
        }
    }
    // Check `let` statements inside task body for banned non-AbiPod locals.
    if let Some(body) = ast::child::<ast::Block>(task_node) {
        let has_suspension = body.syntax().descendants().any(|n| {
            matches!(
                n.kind(),
                SyntaxKind::WaitStmt
                    | SyntaxKind::WaitUntilStmt
                    | SyntaxKind::YieldTickStmt
                    | SyntaxKind::RaceStmt
            )
        });
        for ls in body
            .syntax()
            .descendants()
            .filter(|n| matches!(n.kind(), SyntaxKind::LetStmt | SyntaxKind::UniformLetStmt))
        {
            if let Some(tn) = ls.children().find(|c| {
                matches!(
                    c.kind(),
                    SyntaxKind::TypeRef | SyntaxKind::ArrayType | SyntaxKind::RefType
                )
            }) {
                let ty = parse_type_node(&tn);
                let vname = ls
                    .children()
                    .find(|c| c.kind() == SyntaxKind::Pattern)
                    .map_or_else(
                        || "var".to_owned(),
                        |p| p.text().to_string().trim().to_owned(),
                    );
                if has_suspension && let Ty::BannedWire(ref b) = ty {
                    diags.push(Diagnostic::error(
                        codes::E0302_NON_POD_ACROSS_WAIT,
                        Span::from_range(file, src, ls.text_range()),
                        format!("task local `{vname}: {b}` live across `wait` must satisfy AbiPod"),
                        None,
                    ));
                } else if ty != Ty::Unknown {
                    vars.push((vname, ty));
                }
            }
        }
    }
    vars
}

pub(super) fn eval_const_f64(expr: &HirExpr) -> Option<f64> {
    let val = match expr {
        HirExpr::IntLit { value, .. } => *value as f64,
        HirExpr::FloatLit { value, .. } => *value,
        HirExpr::Unary {
            op: HirUnOp::Neg,
            expr,
            ..
        } => -eval_const_f64(expr)?,
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_const_f64(lhs)?;
            let r = eval_const_f64(rhs)?;
            match op {
                HirBinOp::Add => l + r,
                HirBinOp::Sub => l - r,
                HirBinOp::Mul => l * r,
                HirBinOp::Div if r != 0.0 => l / r,
                _ => return None,
            }
        }
        _ => return None,
    };
    val.is_finite().then_some(val)
}

pub(super) fn extract_field_defaults_list(
    fields: &[ast::FieldDecl],
    lower_env: &LowerEnv<'_>,
) -> IndexMap<String, HirExpr> {
    let mut map = IndexMap::new();
    let mut scope = ScopeStack::new();
    for fd in fields {
        let Some(fname) = fd.name().map(|t| t.text().to_owned()) else {
            continue;
        };
        let mut saw_eq = false;
        for el in fd.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::Eq => {
                    saw_eq = true;
                }
                NodeOrToken::Node(n) if saw_eq && is_expr_node(n.kind()) => {
                    map.insert(fname, lower_expr(&n, lower_env, &mut scope, &[]));
                    break;
                }
                _ => {}
            }
        }
    }
    map
}

pub(super) fn collect_field_defaults(
    sf: &SourceFile,
    module_path: &str,
    _layouts: &IndexMap<String, SolvedLayout>,
    lower_env: &LowerEnv<'_>,
) -> IndexMap<String, IndexMap<String, HirExpr>> {
    let mut out: IndexMap<String, IndexMap<String, HirExpr>> = IndexMap::new();
    for item in sf.items() {
        match item {
            ast::Item::Struct(st) => {
                let short = st
                    .name()
                    .map_or_else(|| "Struct".to_owned(), |t| t.text().to_owned());
                let defaults = extract_field_defaults_list(&st.fields(), lower_env);
                if !defaults.is_empty() {
                    out.insert(format!("{module_path}::{short}"), defaults);
                }
            }
            ast::Item::Component(comp) => {
                let short = comp
                    .name()
                    .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
                let strata = comp.strata();
                if strata.is_empty() {
                    let defaults = extract_field_defaults_list(&comp.fields(), lower_env);
                    if !defaults.is_empty() {
                        out.insert(format!("{module_path}::{short}"), defaults);
                    }
                } else {
                    for st in &strata {
                        let defaults = extract_field_defaults_list(&st.fields(), lower_env);
                        if defaults.is_empty() {
                            continue;
                        }
                        let sname = st.stratum_name();
                        if st.is_hot() {
                            out.insert(format!("{module_path}::{short}"), defaults.clone());
                            out.insert(format!("{module_path}::{short}::hot"), defaults);
                        } else {
                            out.insert(
                                format!("{module_path}::{short}__{sname}"),
                                defaults.clone(),
                            );
                            out.insert(format!("{module_path}::{short}::{sname}"), defaults);
                        }
                    }
                }
            }
            ast::Item::Resource(r) => {
                let short = r
                    .name()
                    .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
                let defaults = extract_field_defaults_list(&r.fields(), lower_env);
                if !defaults.is_empty() {
                    out.insert(format!("{module_path}::{short}"), defaults);
                }
            }
            ast::Item::Event(e) => {
                let short = ast::first_ident(e.syntax())
                    .map_or_else(|| "Event".to_owned(), |t| t.text().to_owned());
                let fields: Vec<_> = ast::children::<ast::FieldDecl>(e.syntax()).collect();
                let defaults = extract_field_defaults_list(&fields, lower_env);
                if !defaults.is_empty() {
                    out.insert(format!("{module_path}::{short}"), defaults);
                }
            }
            ast::Item::Stream(s) => {
                let short = ast::first_ident(s.syntax())
                    .map_or_else(|| "Stream".to_owned(), |t| t.text().to_owned());
                let fields: Vec<_> = ast::children::<ast::FieldDecl>(s.syntax()).collect();
                let defaults = extract_field_defaults_list(&fields, lower_env);
                if !defaults.is_empty() {
                    out.insert(format!("{module_path}::{short}"), defaults);
                }
            }
            ast::Item::Relation(rel) => {
                let short = ast::first_ident(rel.syntax())
                    .map_or_else(|| "Relation".to_owned(), |t| t.text().to_owned());
                let fields: Vec<_> = ast::children::<ast::FieldDecl>(rel.syntax()).collect();
                let defaults = extract_field_defaults_list(&fields, lower_env);
                if !defaults.is_empty() {
                    out.insert(format!("{module_path}::{short}"), defaults);
                }
            }
            _ => {}
        }
    }
    out
}

/// Collects user-declared type names (`struct`, `component`, `resource`, `enum`, `object`)
/// so builtin type aliases (`Quat`, `Rgba8`) do not shadow explicit user declarations.
pub(super) fn parse_int_lit_i128(s: &str) -> Option<i128> {
    const INT_SUFFIXES: &[&str] = &["_u16", "_u32", "_u64", "_i16", "_i32", "_i64", "_u8", "_i8"];
    let mut stem = s.trim();
    for suf in INT_SUFFIXES {
        if let Some(rest) = stem.strip_suffix(suf) {
            stem = rest;
            break;
        }
    }
    let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = cleaned
        .strip_prefix("0b")
        .or_else(|| cleaned.strip_prefix("0B"))
    {
        i128::from_str_radix(bin, 2).ok()
    } else if let Some(oct) = cleaned
        .strip_prefix("0o")
        .or_else(|| cleaned.strip_prefix("0O"))
    {
        i128::from_str_radix(oct, 8).ok()
    } else {
        cleaned.parse::<i128>().ok()
    }
}

pub(super) fn parse_int_lit_i64(s: &str) -> Option<i64> {
    parse_int_lit_i128(s).and_then(|v| i64::try_from(v).ok())
}

pub(super) fn collect_user_type_names(sf: &SourceFile) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in sf.items() {
        match item {
            ast::Item::Struct(s) => {
                if let Some(n) = s.name() {
                    names.insert(n.text().to_owned());
                }
            }
            ast::Item::Component(c) => {
                if let Some(n) = c.name() {
                    names.insert(n.text().to_owned());
                }
            }
            ast::Item::Resource(r) => {
                if let Some(n) = r.name() {
                    names.insert(n.text().to_owned());
                }
            }
            ast::Item::Enum(e) => {
                if let Some(n) = e.name() {
                    names.insert(n.text().to_owned());
                }
            }
            ast::Item::Object(o) => {
                if let Some(n) = ast::first_ident(o.syntax()) {
                    names.insert(n.text().to_owned());
                }
            }
            _ => {}
        }
    }
    names
}

/// Collects resolved field types `(field_name, Ty)` for every `component` (including `@soa`
/// strata), `struct`, and `resource` declaration regardless of ABI-POD eligibility (eliminating
/// Class A `Ty::Unknown` blind spots on non-POD structs and resources).
pub(super) fn collect_all_item_fields(
    sf: &SourceFile,
    module_path: &str,
    user_types: &HashSet<String>,
) -> IndexMap<String, Vec<(String, Ty)>> {
    let parse_fields = |decls: &[ast::FieldDecl]| -> Vec<(String, Ty)> {
        decls
            .iter()
            .map(|fd| {
                let fname = fd
                    .name()
                    .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
                let fty = fd.type_node().map_or(Ty::Unknown, |n| {
                    parse_type_node_with_user_types(&n, user_types)
                });
                (fname, fty)
            })
            .collect()
    };

    let mut out = IndexMap::new();
    for item in sf.items() {
        match item {
            ast::Item::Struct(st) => {
                let short = st
                    .name()
                    .map_or_else(|| "Struct".to_owned(), |t| t.text().to_owned());
                let canon = format!("{module_path}::{short}");
                out.insert(canon, parse_fields(&st.fields()));
            }
            ast::Item::Resource(res) => {
                let short = res
                    .name()
                    .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
                let canon = format!("{module_path}::{short}");
                out.insert(canon, parse_fields(&res.fields()));
            }
            ast::Item::Component(comp) => {
                let short = comp
                    .name()
                    .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
                let strata = comp.strata();
                if strata.is_empty() {
                    let canon = format!("{module_path}::{short}");
                    out.insert(canon, parse_fields(&comp.fields()));
                } else {
                    let mut all_fields = Vec::new();
                    for st in &strata {
                        let sf_list = parse_fields(&st.fields());
                        let sname = st.stratum_name();
                        if !st.is_hot() {
                            out.insert(format!("{module_path}::{short}__{sname}"), sf_list.clone());
                        }
                        all_fields.extend(sf_list);
                    }
                    out.insert(format!("{module_path}::{short}"), all_fields);
                }
            }
            _ => {}
        }
    }
    out
}
