//! Declaration lowering and validation for constants, tables, curves, systems, functions, and tests.

use crate::access::{
    FilteredAccessSet, QueryAccessDesc, QueryTerm, TermAccessMode, validate_system_accesses,
};
use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    HirAssignOp, HirCallable, HirConst, HirCurve, HirExpr, HirFn, HirForIter, HirFsm, HirLValue,
    HirMigration, HirNetSimTest, HirObject, HirParam, HirParamKind, HirPattern, HirRelation,
    HirRpc, HirSchedule, HirScheduleGroup, HirSimTest, HirSpatialIndex, HirStmt, HirTable, HirTask,
    HirTimeline, HirUnOp,
};
use crate::hir_lower::{
    LowerEnv, ScopeBinding, ScopeStack, is_expr_node, is_type_node, lower_block,
    lower_block_as_stmts, lower_comp_init_list, lower_expr, lower_field_init_list,
    lower_fsm_details, lower_param_list, lower_proj_term, lower_stmt_node, lower_sys_param_list,
};
use crate::layout::{EnumDef, LayoutEnv, SchemaItemKind, SolvedLayout, solve_pod_layout};
use crate::types::{QueryRowTerm, Ty, UnitDim, parse_type_node, parse_type_node_with_user_types};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{self, AstNode};
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode};

/// Extracts only schema/declaration headers (stripping `sys`/`obs`/`fn`/`sim_test`/`net_sim_test`
/// bodies) so Salsa early-cutoff avoids re-running layout resolution on body-only edits.
use super::attrs::*;
use super::effects::*;
use super::schema::*;

pub(super) fn analyze_const(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> Option<HirConst> {
    let name = ast::first_ident(node)?.text().to_owned();
    let ty = node
        .children()
        .find(|c| matches!(c.kind(), SyntaxKind::TypeRef | SyntaxKind::ArrayType))
        .map_or(Ty::Unknown, |n| parse_type_node(&n));
    let full = node.text().to_string();
    let value_expr = full
        .split_once('=')
        .map(|(_, rhs)| rhs.trim().trim_end_matches(';').trim().to_owned())
        .unwrap_or_default();

    let mut scope = ScopeStack::new();
    let mut saw_eq = false;
    let mut expr = None;
    for el in node.children_with_tokens() {
        match el {
            NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::Eq => saw_eq = true,
            NodeOrToken::Node(n) if saw_eq && is_expr_node(n.kind()) => {
                expr = Some(lower_expr(&n, lower_env, &mut scope, &[]));
                break;
            }
            _ => {}
        }
    }

    if let Some(expected_dim) = ty.unit_dim() {
        for tok in node
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .filter(|t| t.kind() == SyntaxKind::UnitLit)
        {
            if let Some(Ty::UnitScalar { dim, .. }) = Ty::unit_from_literal(tok.text())
                && dim != expected_dim
            {
                diags.push(Diagnostic::error(
                    codes::E0102_UNIT_MISMATCH,
                    Span::from_range(file, src, tok.text_range()),
                    format!(
                        "unit mismatch on const `{name}` initializer `{}`",
                        tok.text()
                    ),
                    None,
                ));
            }
        }
    }
    Some(HirConst {
        name,
        ty,
        value_expr,
        expr,
    })
}

pub(super) fn analyze_table(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    enums: &IndexMap<String, EnumDef>,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirTable {
    let name = ast::first_ident(node).map_or_else(|| "Table".to_owned(), |t| t.text().to_owned());
    let key_enum = ast::child::<ast::Path>(node)
        .map(|p| ast::path_text(&p))
        .unwrap_or_default();
    let fields = ast::children::<ast::FieldDecl>(node)
        .map(|f| {
            let fn_name = f
                .name()
                .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
            let fty = f.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
            (fn_name, fty)
        })
        .collect();

    let mut rows = Vec::new();
    let mut typed_rows = Vec::new();
    let mut seen = HashSet::new();
    let mut scope = ScopeStack::new();
    for row in ast::children::<ast::TableRow>(node) {
        let rname =
            ast::first_ident(row.syntax()).map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
        seen.insert(rname.clone());
        let fil = ast::child::<ast::FieldInitList>(row.syntax());
        let fields_src = fil
            .as_ref()
            .map(|l| l.syntax().text().to_string())
            .unwrap_or_default();
        let typed_fields = fil
            .as_ref()
            .map(|l| lower_field_init_list(l.syntax(), lower_env, &mut scope, &[]))
            .unwrap_or_default();
        rows.push((rname.clone(), fields_src));
        typed_rows.push((rname, typed_fields));
    }

    if let Some(en) = enums.get(&key_enum) {
        let missing: Vec<_> = en
            .variants
            .iter()
            .filter(|(v, _)| !seen.contains(v))
            .map(|(v, _)| v.as_str())
            .collect();
        if !missing.is_empty() {
            diags.push(Diagnostic::error(
                codes::E0106_TABLE_NOT_EXHAUSTIVE,
                Span::from_range(file, src, node.text_range()),
                format!(
                    "table `{name}` is missing rows for enum `{key_enum}` variants: {}",
                    missing.join(", ")
                ),
                None,
            ));
        }
    }

    HirTable {
        name,
        key_enum,
        fields,
        rows,
        typed_rows,
    }
}

pub(super) fn analyze_curve(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirCurve {
    let name = ast::first_ident(node).map_or_else(|| "Curve".to_owned(), |t| t.text().to_owned());
    let types: Vec<_> = node
        .children()
        .filter(|c| matches!(c.kind(), SyntaxKind::TypeRef))
        .map(|n| parse_type_node(&n))
        .collect();
    let input_ty = types.first().cloned().unwrap_or(Ty::F32);
    let output_ty = types.get(1).cloned().unwrap_or(Ty::F32);

    let mut points = Vec::new();
    let mut prev_x: Option<f64> = None;
    let mut scope = ScopeStack::new();
    for pt in ast::children::<ast::CurvePoint>(node) {
        let coords: Vec<SyntaxNode> = pt
            .syntax()
            .children()
            .filter(|c| is_expr_node(c.kind()))
            .collect();
        if coords.len() >= 2 {
            let hx = lower_expr(&coords[0], lower_env, &mut scope, &[]);
            let hy = lower_expr(&coords[1], lower_env, &mut scope, &[]);
            let x = eval_const_f64(&hx).unwrap_or(0.0);
            let y = eval_const_f64(&hy).unwrap_or(0.0);
            if let Some(px) = prev_x
                && x <= px
            {
                diags.push(Diagnostic::error(
                    codes::E0107_CURVE_NON_MONOTONIC,
                    Span::from_range(file, src, pt.syntax().text_range()),
                    format!(
                        "curve `{name}` x-coordinate {x} is not strictly greater than previous {px}"
                    ),
                    None,
                ));
            }
            prev_x = Some(x);
            points.push((x, y));
        }
    }

    HirCurve {
        name,
        input_ty,
        output_ty,
        points,
    }
}

pub(super) fn parse_numeric_prefix(s: &str) -> Option<f64> {
    let trimmed = s.trim();
    if trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || trimmed.starts_with("0b")
        || trimmed.starts_with("0B")
        || trimmed.starts_with("0o")
        || trimmed.starts_with("0O")
    {
        return parse_int_lit_i64(trimmed).map(|v| v as f64);
    }
    if let Some((stem, _, _, _)) = Ty::split_unit_literal(trimmed) {
        let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
        return cleaned.parse::<f64>().ok();
    }
    const NUM_SUFFIXES: &[&str] = &[
        "_u16", "_u32", "_u64", "_i16", "_i32", "_i64", "_f32", "_f64", "_u8", "_i8",
    ];
    let mut stem = trimmed;
    for suf in NUM_SUFFIXES {
        if let Some(rest) = trimmed.strip_suffix(suf) {
            stem = rest;
            break;
        }
    }
    let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
    cleaned.parse::<f64>().ok()
}

pub(super) fn analyze_relation(
    module_path: &str,
    node: &SyntaxNode,
    layouts: &IndexMap<String, SolvedLayout>,
) -> HirRelation {
    let name =
        ast::first_ident(node).map_or_else(|| "Relation".to_owned(), |t| t.text().to_owned());
    let canonical_name = format!("{module_path}::{name}");
    let flags = ast::child::<ast::RelFlags>(node)
        .map(|rf| {
            rf.syntax()
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .filter(|t| t.kind() == SyntaxKind::Ident)
                .map(|t| t.text().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let payload_layout = layouts.get(&canonical_name).cloned();
    HirRelation {
        canonical_name,
        name,
        flags,
        payload_layout,
    }
}

fn eval_spatial_f64(node: &SyntaxNode) -> Option<f64> {
    match node.kind() {
        SyntaxKind::ParenExpr => node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .and_then(|c| eval_spatial_f64(&c)),
        SyntaxKind::LiteralExpr => {
            for el in node.children_with_tokens() {
                if let Some(tok) = el.into_token() {
                    match tok.kind() {
                        SyntaxKind::UnitLit => {
                            if let Some((stem, _, _, scale)) = Ty::split_unit_literal(tok.text()) {
                                let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
                                if let Ok(v) = cleaned.parse::<f64>() {
                                    let res = v * scale;
                                    return res.is_finite().then_some(res);
                                }
                            }
                            if let Some(v) = parse_numeric_prefix(tok.text()) {
                                return v.is_finite().then_some(v);
                            }
                        }
                        SyntaxKind::FloatLit => {
                            if let Some(v) = parse_numeric_prefix(tok.text()) {
                                return v.is_finite().then_some(v);
                            }
                        }
                        SyntaxKind::IntLit => {
                            let v = parse_int_lit_i64(tok.text())? as f64;
                            return v.is_finite().then_some(v);
                        }
                        _ => {}
                    }
                }
            }
            None
        }
        SyntaxKind::PrefixExpr => {
            let inner = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .and_then(|c| eval_spatial_f64(&c))?;
            let is_neg = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Minus)
            });
            let is_plus = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Plus)
            });
            if is_neg {
                Some(-inner)
            } else if is_plus {
                Some(inner)
            } else {
                None
            }
        }
        SyntaxKind::BinaryExpr => {
            let exprs: Vec<_> = node.children().filter(|c| is_expr_node(c.kind())).collect();
            if exprs.len() < 2 {
                return None;
            }
            let l = eval_spatial_f64(&exprs[0])?;
            let r = eval_spatial_f64(&exprs[1])?;
            let op = node.children_with_tokens().find_map(|el| {
                let tok = el.into_token()?;
                match tok.kind() {
                    SyntaxKind::Plus | SyntaxKind::Minus | SyntaxKind::Star | SyntaxKind::Slash => {
                        Some(tok.kind())
                    }
                    _ => None,
                }
            })?;
            let v = match op {
                SyntaxKind::Plus => l + r,
                SyntaxKind::Minus => l - r,
                SyntaxKind::Star => l * r,
                SyntaxKind::Slash if r != 0.0 => l / r,
                _ => return None,
            };
            v.is_finite().then_some(v)
        }
        _ => None,
    }
}

fn eval_spatial_vec_endpoint(node: &SyntaxNode, by_field_path: &str) -> Option<([f32; 2], bool)> {
    if node.kind() == SyntaxKind::ParenExpr {
        return node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .and_then(|c| eval_spatial_vec_endpoint(&c, by_field_path));
    }
    if node.kind() == SyntaxKind::PostfixCallExpr {
        let callee = node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .map(|c| c.text().to_string().trim().to_owned())
            .unwrap_or_default();
        let arg_list = ast::child::<ast::ArgList>(node)?;
        let args: Vec<SyntaxNode> = arg_list
            .syntax()
            .children()
            .filter(|c| is_expr_node(c.kind()))
            .collect();
        let coords: Vec<f32> = args
            .iter()
            .filter_map(|a| eval_spatial_f64(a).map(|v| v as f32))
            .collect();
        if (callee == "vec2" || callee.ends_with("::vec2")) && coords.len() >= 2 {
            return Some(([coords[0], coords[1]], true));
        }
        if (callee == "vec3" || callee.ends_with("::vec3")) && coords.len() >= 3 {
            let pair = if by_field_path.ends_with(".xz") {
                [coords[0], coords[2]]
            } else {
                [coords[0], coords[1]]
            };
            return Some((pair, false));
        }
    }
    None
}

fn resolve_spatial_const_u32(spatial_node: &SyntaxNode, name: &str) -> Option<u32> {
    let parent = spatial_node.parent()?;
    let sf = ast::SourceFile::cast(parent)?;
    for item in sf.items() {
        if let ast::Item::Const(c) = item
            && ast::first_ident(c.syntax()).is_some_and(|t| t.text() == name)
        {
            let mut saw_eq = false;
            for el in c.syntax().children_with_tokens() {
                match el {
                    NodeOrToken::Token(t) if t.kind() == SyntaxKind::Eq => saw_eq = true,
                    NodeOrToken::Node(n) if saw_eq && is_expr_node(n.kind()) => {
                        return eval_cst_const_i64(&n).and_then(|v| u32::try_from(v).ok());
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

pub(super) fn analyze_spatial(
    module_path: &str,
    node: &SyntaxNode,
    is_history: bool,
    layouts: &IndexMap<String, SolvedLayout>,
) -> HirSpatialIndex {
    let name = ast::first_ident(node).map_or_else(|| "Grid".to_owned(), |t| t.text().to_owned());
    let canonical = format!("{module_path}::{name}");
    let paths: Vec<String> = ast::children::<ast::Path>(node)
        .map(|p| ast::path_text(&p))
        .collect();
    let over_component = paths.first().cloned().unwrap_or_default();
    let by_field_path = paths.get(1).cloned().unwrap_or_default();

    let mut frames = 1u32;
    let mut cell_size = 4.0_f32;
    let mut bounds_min = [-128.0_f32, -128.0_f32];
    let mut bounds_max = [128.0_f32, 128.0_f32];
    let mut capacity = 512_u32;
    let mut bounds_is_vec2 = false;

    if let Some(fil) = ast::child::<ast::FieldInitList>(node) {
        for fi in ast::children::<ast::FieldInit>(fil.syntax()) {
            let Some(fname) = ast::first_ident(fi.syntax()) else {
                continue;
            };
            let val_expr = fi.syntax().children().find(|c| is_expr_node(c.kind()));
            match fname.text() {
                "frames" => {
                    if let Some(val) = fi
                        .syntax()
                        .descendants_with_tokens()
                        .filter_map(|e| e.into_token())
                        .find(|t| t.kind() == SyntaxKind::IntLit)
                    {
                        frames = parse_int_lit_i64(val.text())
                            .and_then(|v| u32::try_from(v).ok())
                            .unwrap_or(1)
                            .max(1);
                    }
                }
                "cell_size" | "cell" => {
                    if let Some(ref expr) = val_expr
                        && let Some(cs) = eval_spatial_f64(expr)
                        && cs > 0.0
                    {
                        cell_size = cs as f32;
                    }
                }
                "capacity" => {
                    if let Some(ref expr) = val_expr {
                        if let Some(v) = eval_cst_const_i64(expr)
                            .and_then(|v| u32::try_from(v).ok())
                            .filter(|&v| v > 0)
                        {
                            capacity = v;
                        } else if expr.kind() == SyntaxKind::PathExpr {
                            let cname = expr.text().to_string().trim().to_owned();
                            if let Some(v) =
                                resolve_spatial_const_u32(node, &cname).filter(|&v| v > 0)
                            {
                                capacity = v;
                            }
                        }
                    }
                }
                "bounds" => {
                    if let Some(ref expr) = val_expr
                        && expr.kind() == SyntaxKind::BinaryExpr
                        && expr.children_with_tokens().any(|el| {
                            el.into_token().is_some_and(|t| {
                                matches!(t.kind(), SyntaxKind::DotDot | SyntaxKind::DotDotEq)
                            })
                        })
                    {
                        let endpoints: Vec<SyntaxNode> =
                            expr.children().filter(|c| is_expr_node(c.kind())).collect();
                        if endpoints.len() >= 2
                            && let (Some((bmin, v2_a)), Some((bmax, v2_b))) = (
                                eval_spatial_vec_endpoint(&endpoints[0], &by_field_path),
                                eval_spatial_vec_endpoint(&endpoints[1], &by_field_path),
                            )
                        {
                            bounds_min = bmin;
                            bounds_max = bmax;
                            bounds_is_vec2 = v2_a && v2_b;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let inv_cs = if cell_size > 0.0 {
        1.0 / cell_size
    } else {
        0.25
    };
    let cols = (((bounds_max[0] - bounds_min[0]).abs() * inv_cs).ceil() as u32).clamp(1, 256);
    let rows = (((bounds_max[1] - bounds_min[1]).abs() * inv_cs).ceil() as u32).clamp(1, 256);
    let plane_axes =
        if (bounds_is_vec2 && by_field_path.ends_with(".xyz")) || by_field_path.ends_with(".xz") {
            [0, 2]
        } else {
            [0, 1]
        };

    let cached_components = ast::child::<ast::ProjTermList>(node)
        .map(|ptl| {
            ast::children::<ast::ProjTerm>(ptl.syntax())
                .filter_map(|pt| {
                    pt.syntax()
                        .descendants()
                        .find(|n| n.kind() == SyntaxKind::TypeRef)
                        .map(|tr| tr.text().to_string().trim().to_owned())
                })
                .collect()
        })
        .unwrap_or_default();

    let resource_layout = layouts
        .get(&canonical)
        .cloned()
        .unwrap_or_else(|| SolvedLayout {
            canonical_name: canonical,
            item_kind: if is_history {
                SchemaItemKind::SpatialHistory
            } else {
                SchemaItemKind::SpatialGrid
            },
            fields: Vec::new(),
            size: 16,
            align: 4,
            is_abi_pod: true,
            component_flags: 0,
            uuid_bytes: [0; 16],
            uuid_hex: String::new(),
            schema_fingerprint: 0,
            required_components: Vec::new(),
            explicit_pad_bytes: 0,
        });

    HirSpatialIndex {
        name,
        is_history,
        frames,
        over_component,
        by_field_path,
        cached_components,
        resource_layout,
        cell_size,
        bounds_min,
        bounds_max,
        capacity,
        cols,
        rows,
        plane_axes,
    }
}

pub(super) fn analyze_timeline(
    file: &str,
    src: &str,
    module_path: &str,
    node: &SyntaxNode,
    layouts: &IndexMap<String, SolvedLayout>,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirTimeline {
    let name =
        ast::first_ident(node).map_or_else(|| "Timeline".to_owned(), |t| t.text().to_owned());
    let canonical_name = format!("{module_path}::{name}");
    let mut rate_hz = 60u32;
    let mut duration_frames = 60u32;

    for attr in ast::attrs(node) {
        let aname = ast::attr_name(&attr);
        let num = attr
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .find(|t| matches!(t.kind(), SyntaxKind::IntLit | SyntaxKind::UnitLit))
            .and_then(|t| parse_numeric_prefix(t.text()))
            .map(|v| v as u32);
        match (aname.as_deref(), num) {
            (Some("rate"), Some(n)) => rate_hz = n,
            (Some("duration"), Some(n)) => duration_frames = n,
            _ => {}
        }
    }

    let mut windows = Vec::new();
    for (idx, w) in ast::children::<ast::TimelineWindow>(node).enumerate() {
        let wname =
            ast::first_ident(w.syntax()).map_or_else(|| format!("w{idx}"), |t| t.text().to_owned());
        let nums: Vec<u32> = w
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .filter(|t| matches!(t.kind(), SyntaxKind::IntLit | SyntaxKind::UnitLit))
            .filter_map(|t| parse_numeric_prefix(t.text()).map(|v| v as u32))
            .collect();
        let start = nums.first().copied().unwrap_or(0);
        let end = nums.get(1).copied().unwrap_or(0);
        if start >= end || end > duration_frames {
            diags.push(Diagnostic::error(
                codes::E0108_TIMELINE_INVALID_WINDOW,
                Span::from_range(file, src, w.syntax().text_range()),
                format!(
                    "timeline `{name}` window `{wname}` ({start}..{end}) invalid for @duration({duration_frames}_f)"
                ),
                None,
            ));
        }
        windows.push((wname, start, end, idx as u8));
    }

    let mut triggers = Vec::new();
    let mut typed_triggers = Vec::new();
    let mut scope = ScopeStack::new();
    for at in ast::children::<ast::TimelineAt>(node) {
        let frame = at
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .find(|t| matches!(t.kind(), SyntaxKind::IntLit | SyntaxKind::UnitLit))
            .and_then(|t| parse_numeric_prefix(t.text()))
            .unwrap_or(0.0) as u32;
        triggers.push((frame, at.syntax().text().to_string()));

        let mut stmts = Vec::new();
        let mut after_arrow = false;
        for el in at.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::FatArrow => {
                    after_arrow = true;
                }
                NodeOrToken::Node(n) if after_arrow => {
                    if n.kind() == SyntaxKind::Block {
                        stmts.extend(lower_block_as_stmts(&n, lower_env, &mut scope, &[], false));
                    } else if is_expr_node(n.kind()) {
                        stmts.push(HirStmt::Expr(lower_expr(&n, lower_env, &mut scope, &[])));
                    } else {
                        lower_stmt_node(&n, lower_env, &mut scope, &[], &mut stmts);
                    }
                }
                _ => {}
            }
        }
        validate_no_query_handle_reassign(
            file,
            src,
            &name,
            Span::from_range(file, src, at.syntax().text_range()),
            &stmts,
            None,
            &[],
            diags,
        );
        typed_triggers.push((frame, stmts));
    }

    let cursor_layout = layouts
        .get(&canonical_name)
        .cloned()
        .expect("timeline layout always synthesized");

    HirTimeline {
        canonical_name,
        name,
        rate_hz,
        duration_frames,
        windows,
        triggers,
        typed_triggers,
        cursor_layout,
    }
}

pub(super) fn analyze_task(
    file: &str,
    src: &str,
    module_path: &str,
    node: &SyntaxNode,
    layouts: &IndexMap<String, SolvedLayout>,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirTask {
    let name = ast::first_ident(node).map_or_else(|| "Task".to_owned(), |t| t.text().to_owned());
    let canonical = format!("{module_path}::{name}");
    let is_sparse = ast::attrs(node)
        .iter()
        .filter_map(ast::attr_name)
        .any(|a| a == "sparse");

    let mut access = FilteredAccessSet {
        system_name: name.clone(),
        ..Default::default()
    };

    let mut scope = ScopeStack::new();
    let typed_params = lower_param_list(node, lower_env, &mut scope);
    let params: Vec<(String, Ty)> = typed_params
        .iter()
        .map(|p| (p.name.clone(), p.ty.clone()))
        .collect();

    // `on (...)` terms become the task's primary entity query.
    let mut on_terms = Vec::new();
    let mut typed_on_terms = Vec::new();
    if let Some(ptl) = ast::child::<ast::ProjTermList>(node) {
        let mut q = QueryAccessDesc {
            is_task_on_header: true,
            byte_start: u32::from(ptl.syntax().text_range().start()),
            byte_end: u32::from(ptl.syntax().text_range().end()),
            ..Default::default()
        };
        for pt in ast::children::<ast::ProjTerm>(ptl.syntax()) {
            on_terms.push(pt.syntax().text().to_string().trim().to_owned());
            if let Some(ht) = lower_proj_term(pt.syntax(), lower_env) {
                scope.insert(
                    ht.alias.clone(),
                    ScopeBinding::QueryRow {
                        terms: vec![ht.clone()],
                        extra_tys: Vec::new(),
                    },
                );
                q.terms.push(QueryTerm {
                    storage_key: ht.storage_key.clone(),
                    field_name: ht.field_name.clone(),
                    mode: ht.mode,
                    byte_start: u32::from(pt.syntax().text_range().start()),
                    byte_end: u32::from(pt.syntax().text_range().end()),
                });
                typed_on_terms.push(ht);
            }
        }
        q.terms.push(QueryTerm {
            storage_key: name.clone(),
            field_name: None,
            mode: TermAccessMode::Write,
            byte_start: q.byte_start,
            byte_end: q.byte_end,
        });
        access.queries.push(q);
    }

    let mut using_params = Vec::new();
    if let Some(spl) = ast::child::<ast::SysParamList>(node) {
        for sp in ast::children::<ast::SysParam>(spl.syntax()) {
            using_params.push(sp.syntax().text().to_string().trim().to_owned());
            record_sys_param(sp.syntax(), &mut access);
        }
    }
    let typed_using_params = lower_sys_param_list(node, lower_env, &mut scope);

    let (body_source, body) = ast::child::<ast::Block>(node)
        .map(|b| {
            collect_body_queries(b.syntax(), lower_env, &mut access);
            let stmts =
                lower_block_as_stmts(b.syntax(), lower_env, &mut scope, &access.queries, false);
            (b.syntax().text().to_string(), stmts)
        })
        .unwrap_or_default();

    diags.extend(validate_system_accesses(
        file,
        src,
        &access,
        (
            u32::from(node.text_range().start()),
            u32::from(node.text_range().end()),
        ),
    ));

    let state_layout = layouts
        .get(&canonical)
        .cloned()
        .expect("task layout synthesized");
    let live_across_wait = collect_task_live_vars(file, src, node, &mut Vec::new());

    let task = HirTask {
        name,
        is_sparse,
        params,
        typed_params,
        on_terms,
        typed_on_terms,
        using_params,
        typed_using_params,
        live_across_wait,
        state_layout,
        access,
        body_source,
        body,
    };
    let mut initial_handles: Vec<(String, HandleValue)> = task
        .typed_on_terms
        .iter()
        .map(|ht| {
            let is_opt = matches!(
                ht.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            );
            let hv = if ht.field_name.is_some() && !is_opt {
                HandleValue::ProjectedTerm
            } else if is_opt {
                HandleValue::Optional(Box::new(HandleValue::Comp))
            } else {
                HandleValue::Comp
            };
            (ht.alias.clone(), hv)
        })
        .collect();
    for p in &task.typed_params {
        if let Some(hv) = handle_value_from_param(p) {
            initial_handles.push((p.name.clone(), hv));
        }
    }
    validate_no_query_handle_reassign(
        file,
        src,
        &task.name,
        Span::from_range(file, src, node.text_range()),
        &task.body,
        None,
        &initial_handles,
        diags,
    );
    task
}

pub(super) fn analyze_fsm(
    file: &str,
    src: &str,
    module_path: &str,
    node: &SyntaxNode,
    layouts: &IndexMap<String, SolvedLayout>,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirFsm {
    let name = ast::first_ident(node).map_or_else(|| "Fsm".to_owned(), |t| t.text().to_owned());
    let canonical = format!("{module_path}::{name}");
    let is_persist = ast::attrs(node)
        .iter()
        .filter_map(ast::attr_name)
        .any(|a| a == "persist");

    let mut access = FilteredAccessSet {
        system_name: name.clone(),
        ..Default::default()
    };
    if let Some(spl) = ast::child::<ast::SysParamList>(node) {
        for sp in ast::children::<ast::SysParam>(spl.syntax()) {
            record_sys_param(sp.syntax(), &mut access);
        }
    }
    let mut scope = ScopeStack::new();
    let params = lower_sys_param_list(node, lower_env, &mut scope);

    // Extract `initial <State>;`
    let tokens: Vec<_> = node
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .filter(|t| !t.kind().is_trivia())
        .collect();
    let initial_state = tokens
        .windows(2)
        .find(|w| w[0].kind() == SyntaxKind::KwInitial)
        .map_or_else(String::new, |w| w[1].text().to_owned());

    let mut states = Vec::new();
    let mut transitions = Vec::new();
    for st in ast::children::<ast::StateDecl>(node) {
        let sname = ast::first_ident(st.syntax())
            .map_or_else(|| "State".to_owned(), |t| t.text().to_owned());
        states.push(sname.clone());
        for blk in ast::children::<ast::Block>(st.syntax()) {
            collect_body_queries(blk.syntax(), lower_env, &mut access);
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
                        .and_then(|t| {
                            parse_int_lit_i64(t.text()).and_then(|v| i32::try_from(v).ok())
                        })
                })
                .unwrap_or(0);
            transitions.push((sname.clone(), target, tr.syntax().text().to_string(), prio));
        }
    }

    let (typed_transitions, state_hooks) = lower_fsm_details(node, lower_env, &mut scope);

    let state_set: HashSet<&str> = states.iter().map(|s| s.as_str()).collect();
    if !initial_state.is_empty() && !state_set.contains(initial_state.as_str()) {
        diags.push(Diagnostic::error(
            codes::E0109_FSM_INVALID_TARGET,
            Span::from_range(file, src, node.text_range()),
            format!("fsm `{name}` initial state `{initial_state}` is not declared"),
            None,
        ));
    }
    for (from_s, to_s, _, _) in &transitions {
        if !state_set.contains(to_s.as_str()) {
            diags.push(Diagnostic::error(
                codes::E0109_FSM_INVALID_TARGET,
                Span::from_range(file, src, node.text_range()),
                format!(
                    "fsm `{name}` transition `{from_s} -> {to_s}` targets undeclared state `{to_s}`"
                ),
                None,
            ));
        }
    }

    let state_layout = layouts
        .get(&canonical)
        .cloned()
        .expect("fsm layout synthesized");

    let fsm_span = Span::from_range(file, src, node.text_range());
    for tr in &typed_transitions {
        validate_no_query_handle_reassign(
            file,
            src,
            &name,
            fsm_span.clone(),
            &[],
            Some(&tr.guard),
            &[],
            diags,
        );
    }
    for st in &state_hooks {
        for hook in [&st.on_enter, &st.on_tick, &st.on_exit] {
            validate_no_query_handle_reassign(
                file,
                src,
                &name,
                fsm_span.clone(),
                hook,
                None,
                &[],
                diags,
            );
        }
    }

    HirFsm {
        name,
        is_persist,
        initial_state,
        states,
        transitions,
        params,
        typed_transitions,
        state_hooks,
        state_layout,
        access,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn analyze_callable(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    is_observer: bool,
    lower_env: &LowerEnv<'_>,
    layouts: &IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) -> HirCallable {
    let name =
        ast::first_ident(node).map_or_else(|| "callable".to_owned(), |t| t.text().to_owned());

    let mut par_chunk = None;
    let mut par_read_only = false;
    for attr in ast::attrs(node) {
        if ast::attr_name(&attr).as_deref() == Some("par") {
            let txt = attr.syntax().text().to_string();
            if txt.contains("read_only") {
                par_read_only = true;
            }
            if let Some(num_tok) = attr
                .syntax()
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::IntLit)
            {
                par_chunk = parse_int_lit_i64(num_tok.text()).and_then(|v| u32::try_from(v).ok());
            }
            if par_chunk.is_none() {
                par_chunk = Some(512);
            }
        }
    }

    let mut access = FilteredAccessSet {
        system_name: name.clone(),
        is_par: par_chunk.is_some(),
        is_read_only_par: par_read_only,
        ..Default::default()
    };

    let mut scope = ScopeStack::new();
    let params = lower_sys_param_list(node, lower_env, &mut scope);

    let mut trigger_event = None;
    let mut trigger_target_comp = None;
    if let Some(spl) = ast::child::<ast::SysParamList>(node) {
        for (idx, sp) in ast::children::<ast::SysParam>(spl.syntax()).enumerate() {
            if is_observer && idx == 0 {
                if let Some(p) = params.get(idx)
                    && p.kind == HirParamKind::Trigger
                {
                    if let Ty::Named(ref ev) = p.ty {
                        trigger_event = Some(ev.clone());
                    }
                    trigger_target_comp = p.trigger_target.clone();
                }
                if trigger_event.is_none() {
                    trigger_event = sp
                        .syntax()
                        .descendants()
                        .find(|n| n.kind() == SyntaxKind::GenericArgs)
                        .map(|g| g.text().to_string());
                }
            } else {
                record_sys_param(sp.syntax(), &mut access);
            }
        }
    }

    let declared_effects =
        ast::child::<ast::EffectsClause>(node).map(|ec| parse_effects(ec.syntax()));

    let body_node = ast::child::<ast::Block>(node);
    let (body_source, body) = if let Some(ref b) = body_node {
        collect_body_queries(b.syntax(), lower_env, &mut access);
        check_body_lints(file, src, &name, b.syntax(), diags);
        if let Some(ref eff) = declared_effects {
            verify_effects(file, src, &name, eff, &access, b.syntax(), layouts, diags);
        }
        let stmts = lower_block_as_stmts(b.syntax(), lower_env, &mut scope, &access.queries, false);
        (b.syntax().text().to_string(), stmts)
    } else {
        (String::new(), Vec::new())
    };

    let byte_range = (
        u32::from(node.text_range().start()),
        u32::from(node.text_range().end()),
    );
    diags.extend(validate_system_accesses(file, src, &access, byte_range));

    let (authority, is_predicted) = extract_item_authority(node);
    let node_group = extract_valid_node_group(node);
    let net_rpc = extract_net_rpc_attr(node);

    let callable = HirCallable {
        name,
        is_observer,
        trigger_event,
        trigger_target_comp,
        par_chunk,
        par_read_only,
        declared_effects,
        access,
        params,
        body,
        body_source,
        byte_range,
        authority,
        is_predicted,
        node_group,
        net_rpc,
    };
    let initial_handles: Vec<(String, HandleValue)> = callable
        .params
        .iter()
        .filter_map(|p| handle_value_from_param(p).map(|hv| (p.name.clone(), hv)))
        .collect();
    validate_no_query_handle_reassign(
        file,
        src,
        &callable.name,
        Span::from_bytes(file, src, callable.byte_range.0, callable.byte_range.1),
        &callable.body,
        None,
        &initial_handles,
        diags,
    );
    callable
}

pub(super) fn analyze_fn(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirFn {
    let name = ast::first_ident(node).map_or_else(|| "fn".to_owned(), |t| t.text().to_owned());
    let generic_params = node
        .children()
        .find(|c| c.kind() == SyntaxKind::GenericParams)
        .map(|gp| {
            gp.children_with_tokens()
                .filter_map(|e| e.into_token())
                .filter(|t| t.kind() == SyntaxKind::Ident)
                .map(|t| t.text().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut scope = ScopeStack::new();
    let params = lower_param_list(node, lower_env, &mut scope);
    let ret_ty = node
        .children()
        .find(|c| is_type_node(c.kind()))
        .map_or(Ty::Unit, |t| {
            parse_type_node_with_user_types(&t, lower_env.user_types)
        });
    let (body, tail) = ast::child::<ast::Block>(node)
        .map(|b| lower_block(b.syntax(), lower_env, &mut scope, &[]))
        .unwrap_or_default();
    let is_node_pure = has_attr_name(node, "node_pure");
    let node_group = extract_valid_node_group(node);

    let hf = HirFn {
        name,
        generic_params,
        params,
        ret_ty,
        body,
        tail,
        byte_range: (
            u32::from(node.text_range().start()),
            u32::from(node.text_range().end()),
        ),
        is_node_pure,
        node_group,
    };
    if !hf.is_node_pure {
        validate_helper_fn_no_queries(file, src, &hf, diags);
    }
    let initial_handles: Vec<(String, HandleValue)> = hf
        .params
        .iter()
        .filter_map(|p| handle_value_from_param(p).map(|hv| (p.name.clone(), hv)))
        .collect();
    validate_no_query_handle_reassign(
        file,
        src,
        &hf.name,
        Span::from_bytes(file, src, hf.byte_range.0, hf.byte_range.1),
        &hf.body,
        hf.tail.as_ref(),
        &initial_handles,
        diags,
    );
    hf
}

fn is_compile_time_const_expr(
    expr: &HirExpr,
    lower_env: &LowerEnv<'_>,
    consts: &[HirConst],
    visiting: &mut HashSet<String>,
) -> bool {
    match expr {
        HirExpr::BoolLit(_)
        | HirExpr::IntLit { .. }
        | HirExpr::FloatLit { .. }
        | HirExpr::StringLit(_)
        | HirExpr::CharLit(_) => true,
        HirExpr::Unary { expr, .. } | HirExpr::Cast { expr, .. } => {
            is_compile_time_const_expr(expr, lower_env, consts, visiting)
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            is_compile_time_const_expr(lhs, lower_env, consts, visiting)
                && is_compile_time_const_expr(rhs, lower_env, consts, visiting)
        }
        HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => elems
            .iter()
            .all(|e| is_compile_time_const_expr(e, lower_env, consts, visiting)),
        HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => fields
            .iter()
            .all(|(_, v)| is_compile_time_const_expr(v, lower_env, consts, visiting)),
        HirExpr::BundleLit { components } => components.iter().all(|ci| {
            ci.fields
                .iter()
                .all(|(_, v)| is_compile_time_const_expr(v, lower_env, consts, visiting))
        }),
        HirExpr::Path { name, .. } => {
            let seg = name.rsplit("::").next().unwrap_or(name.as_str());
            if let Some(hc) = consts
                .iter()
                .find(|c| c.name == *name || c.name.rsplit("::").next() == Some(seg))
            {
                if !visiting.insert(hc.name.clone()) {
                    return false;
                }
                let ok = hc
                    .expr
                    .as_ref()
                    .is_some_and(|e| is_compile_time_const_expr(e, lower_env, consts, visiting));
                visiting.remove(&hc.name);
                return ok;
            }
            if let Some((en, vn)) = name.rsplit_once("::") {
                let en_short = en.rsplit("::").next().unwrap_or(en);
                if let Some(ed) = lower_env
                    .enums
                    .get(en)
                    .or_else(|| lower_env.enums.get(en_short))
                    && ed.variants.iter().any(|(v, _)| v == vn)
                {
                    return true;
                }
            }
            matches!(
                name.as_str(),
                "vec2::ZERO"
                    | "vec2::ONE"
                    | "vec2::X"
                    | "vec2::Y"
                    | "ivec2::ZERO"
                    | "ivec2::ONE"
                    | "ivec2::X"
                    | "ivec2::Y"
                    | "uvec2::ZERO"
                    | "uvec2::ONE"
                    | "uvec2::X"
                    | "uvec2::Y"
                    | "vec3::ZERO"
                    | "vec3::ONE"
                    | "vec3::X"
                    | "vec3::Y"
                    | "vec3::UP"
                    | "vec3::Z"
                    | "ivec3::ZERO"
                    | "ivec3::ONE"
                    | "ivec3::X"
                    | "ivec3::Y"
                    | "ivec3::Z"
                    | "vec4::ZERO"
                    | "vec4::ONE"
                    | "vec4::X"
                    | "vec4::Y"
                    | "vec4::Z"
                    | "vec4::W"
            )
        }
        HirExpr::Call(call) => {
            let callee = call
                .callee
                .rsplit("::")
                .next()
                .unwrap_or(call.callee.as_str());
            call.receiver.is_none()
                && matches!(
                    callee,
                    "vec2"
                        | "Vec2"
                        | "vec3"
                        | "Vec3"
                        | "vec3a"
                        | "Vec3a"
                        | "vec4"
                        | "Vec4"
                        | "ivec2"
                        | "IVec2"
                        | "ivec3"
                        | "IVec3"
                        | "uvec2"
                        | "UVec2"
                        | "quat"
                        | "Quat"
                        | "rgba"
                        | "Rgba"
                        | "bits"
                        | "meters"
                        | "sec"
                        | "ms"
                        | "rad"
                        | "deg"
                        | "mps"
                        | "mps2"
                        | "hz"
                        | "frames"
                )
                && call
                    .args
                    .iter()
                    .all(|a| is_compile_time_const_expr(a, lower_env, consts, visiting))
        }
        _ => false,
    }
}

pub(super) fn validate_const_inits(
    file: &str,
    src: &str,
    consts: &[HirConst],
    const_ranges: &[strata_syntax::TextRange],
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) {
    for (hc, range) in consts.iter().zip(const_ranges.iter().copied()) {
        let ok = hc.expr.as_ref().is_some_and(|e| {
            let mut visiting = HashSet::new();
            visiting.insert(hc.name.clone());
            is_compile_time_const_expr(e, lower_env, consts, &mut visiting)
        });
        if !ok {
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, range),
                format!(
                    "const `{}` initializer must be a compile-time constant expression",
                    hc.name
                ),
                None,
            ));
        }
    }
}

pub(super) fn validate_object_const_inits(
    file: &str,
    src: &str,
    obj_range: strata_syntax::TextRange,
    ho: &HirObject,
    lower_env: &LowerEnv<'_>,
    consts: &[HirConst],
    diags: &mut Vec<Diagnostic>,
) {
    let span = Span::from_range(file, src, obj_range);
    for ci in &ho.inits {
        for (fname, fexpr) in &ci.fields {
            if !is_compile_time_const_expr(fexpr, lower_env, consts, &mut HashSet::new()) {
                diags.push(Diagnostic::error(
                    codes::E0103_INVALID_ABI_POD_FIELD,
                    span.clone(),
                    format!(
                        "object `{}` component `{}` field `{fname}` initializer must be a compile-time constant expression",
                        ho.name, ci.component
                    ),
                    None,
                ));
            }
        }
    }
}

pub(super) fn analyze_object(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirObject {
    let name = ast::first_ident(node).map_or_else(|| "Object".to_owned(), |t| t.text().to_owned());
    let is_persist = ast::attrs(node)
        .iter()
        .filter_map(ast::attr_name)
        .any(|a| a == "persist");
    let mut scope = ScopeStack::new();
    let inits = ast::child::<ast::CompInitList>(node)
        .map(|cil| lower_comp_init_list(cil.syntax(), lower_env, &mut scope, &[]))
        .unwrap_or_default();
    let components = inits.iter().map(|c| c.component.clone()).collect();
    HirObject {
        name,
        is_persist,
        components,
        inits,
    }
}

pub(super) fn analyze_migrate(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirMigration {
    let paths: Vec<String> = ast::children::<ast::Path>(node)
        .map(|p| ast::path_text(&p))
        .collect();
    let component = paths.first().cloned().unwrap_or_default();
    let semvers: Vec<String> = ast::children::<ast::SemVer>(node)
        .map(|s| s.syntax().text().to_string())
        .collect();
    let from_ver = semvers.first().cloned().unwrap_or_default();
    let to_ver = semvers.get(1).cloned().unwrap_or_default();

    let mut saw_lparen = false;
    let mut param_name = "old".to_owned();
    for tok in node
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .filter(|t| !t.kind().is_trivia())
    {
        if tok.kind() == SyntaxKind::LParen {
            saw_lparen = true;
        } else if saw_lparen && tok.kind() == SyntaxKind::Colon {
            break;
        } else if saw_lparen {
            param_name = tok.text().to_owned();
            break;
        }
    }

    let parsed_from = node
        .children()
        .find(|c| is_type_node(c.kind()))
        .map_or(Ty::Unknown, |n| {
            parse_type_node_with_user_types(&n, lower_env.user_types)
        });
    let from_type = match parsed_from {
        Ty::Borrow { inner, .. } => *inner,
        other => other,
    };
    let to_type = paths
        .get(1)
        .cloned()
        .map(Ty::Named)
        .unwrap_or_else(|| Ty::Named(component.clone()));

    let mut scope = ScopeStack::new();
    scope.insert(param_name.clone(), ScopeBinding::Var(from_type.clone()));

    let block = ast::child::<ast::Block>(node);
    let body_source = block
        .as_ref()
        .map(|b| b.syntax().text().to_string())
        .unwrap_or_default();
    let (body, tail) = block
        .as_ref()
        .map(|b| lower_block(b.syntax(), lower_env, &mut scope, &[]))
        .unwrap_or_default();

    HirMigration {
        component,
        from_ver,
        to_ver,
        param_name,
        from_type,
        to_type,
        body,
        tail,
        body_source,
    }
}

pub(super) fn analyze_schedule(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirSchedule {
    let label = ast::child::<ast::Path>(node)
        .map(|p| ast::path_text(&p))
        .unwrap_or_else(|| "Update".to_owned());
    let run_if_mod = ast::children::<ast::ScheduleMod>(node).find(|m| {
        m.syntax()
            .children_with_tokens()
            .filter_map(|e| e.into_token())
            .any(|t| t.kind() == SyntaxKind::KwRunIf)
    });
    let run_if = run_if_mod.as_ref().map(|m| m.syntax().text().to_string());
    let mut scope = ScopeStack::new();
    let run_if_expr = run_if_mod.and_then(|m| {
        m.syntax()
            .children()
            .find(|c| is_expr_node(c.kind()))
            .map(|e| lower_expr(&e, lower_env, &mut scope, &[]))
    });
    let nodes = ast::children::<ast::ScheduleNode>(node)
        .map(|sn| parse_schedule_group(sn.syntax()))
        .collect();
    HirSchedule {
        label,
        run_if,
        run_if_expr,
        nodes,
    }
}

pub(super) fn parse_schedule_group(node: &SyntaxNode) -> HirScheduleGroup {
    let kind = node
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .find_map(|t| match t.kind() {
            SyntaxKind::KwSeq => Some("seq".to_owned()),
            SyntaxKind::KwSeqWeak => Some("seq_weak".to_owned()),
            SyntaxKind::KwPar => Some("par".to_owned()),
            SyntaxKind::KwSet => Some("set".to_owned()),
            _ => None,
        })
        .unwrap_or_else(|| "leaf".to_owned());

    let name = if kind == "leaf" {
        ast::child::<ast::Path>(node)
            .map(|p| ast::path_text(&p))
            .unwrap_or_default()
    } else {
        ast::first_ident(node).map_or_else(String::new, |t| t.text().to_owned())
    };
    let children = ast::children::<ast::ScheduleNode>(node)
        .map(|c| parse_schedule_group(c.syntax()))
        .collect();
    HirScheduleGroup {
        kind,
        name,
        children,
    }
}

pub(super) fn analyze_sim_test(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirSimTest {
    let name = node
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::StringLit)
        .map_or_else(
            || "sim_test".to_owned(),
            |t| t.text().trim_matches('"').to_owned(),
        );
    let block = ast::child::<ast::Block>(node);
    let body_source = block
        .as_ref()
        .map(|b| b.syntax().text().to_string())
        .unwrap_or_default();
    let mut scope = ScopeStack::new();
    let body = block
        .as_ref()
        .map(|b| lower_block_as_stmts(b.syntax(), lower_env, &mut scope, &[], false))
        .unwrap_or_default();
    validate_no_query_handle_reassign(
        file,
        src,
        &name,
        Span::from_range(file, src, node.text_range()),
        &body,
        None,
        &[],
        diags,
    );
    HirSimTest {
        name,
        body,
        body_source,
    }
}

pub(super) fn analyze_rpc(module_path: &str, rpc: &ast::RpcDecl, env: &mut LayoutEnv) -> HirRpc {
    let name = rpc
        .name()
        .map_or_else(|| "Rpc".to_owned(), |t| t.text().to_owned());
    let canonical_name = format!("{module_path}::{name}");
    let is_marker = rpc.is_marker();
    let (authority, _) = extract_item_authority(rpc.syntax());
    let node_group = extract_valid_node_group(rpc.syntax());
    let net_rpc = extract_net_rpc_attr(rpc.syntax()).unwrap_or_default();

    let mut fields = Vec::new();
    let mut quantized_fields = Vec::new();
    for fd in rpc.fields() {
        let fname = fd
            .name()
            .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
        let fty = fd.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
        for attr in fd.attributes() {
            if ast::attr_name(&attr).as_deref() == Some("quantize")
                && let Some(spec) = parse_quantize_attr("", "", &name, &fname, &attr, None)
            {
                quantized_fields.push(spec);
            }
        }
        fields.push((fname, fty));
    }

    let payload_layout = solve_pod_layout(
        &canonical_name,
        SchemaItemKind::Struct,
        &fields,
        0,
        Vec::new(),
        env,
    )
    .unwrap_or_else(|_| SolvedLayout {
        canonical_name: canonical_name.clone(),
        item_kind: SchemaItemKind::Struct,
        fields: Vec::new(),
        size: 0,
        align: 1,
        is_abi_pod: true,
        component_flags: 0,
        uuid_bytes: [0; 16],
        uuid_hex: String::new(),
        schema_fingerprint: 0,
        required_components: Vec::new(),
        explicit_pad_bytes: 0,
    });

    env.resolved.insert(
        name.clone(),
        (
            payload_layout.size,
            payload_layout.align,
            payload_layout.is_abi_pod,
            bamabi_sys::BamFieldKind::NESTED.0,
            canonical_name.clone(),
        ),
    );

    let rpc_id = bamabi_sys::fnv1a_64_str(&canonical_name);

    HirRpc {
        canonical_name,
        name,
        direction: net_rpc.direction,
        reliability: net_rpc.reliability,
        channel: net_rpc.channel,
        authority,
        node_group,
        is_marker,
        fields,
        quantized_fields,
        payload_layout,
        rpc_id,
    }
}

pub(super) fn eval_time_ms(expr: &HirExpr) -> Result<f64, String> {
    match expr {
        HirExpr::FloatLit {
            value,
            ty: Ty::UnitScalar { dim, .. },
        } => {
            if *dim == UnitDim::SEC {
                Ok(*value * 1000.0)
            } else {
                Err("expected a time unit (e.g. `50ms` or `0.1s`)".to_owned())
            }
        }
        HirExpr::IntLit { value, .. } => Ok(*value as f64),
        HirExpr::FloatLit { value, .. } => Ok(*value),
        HirExpr::Unary {
            op: HirUnOp::Neg,
            expr,
            ..
        } => eval_time_ms(expr).map(|v| -v),
        _ => eval_const_f64(expr).ok_or_else(|| "expected a numeric or time literal".to_owned()),
    }
}

pub(super) fn analyze_net_sim_test(
    file: &str,
    src: &str,
    nst: &ast::NetSimTestDecl,
    lower_env: &LowerEnv<'_>,
    diags: &mut Vec<Diagnostic>,
) -> HirNetSimTest {
    let name = nst.name().unwrap_or_else(|| "net_sim_test".to_owned());
    let mut latency_ms = 0.0_f64;
    let mut jitter_ms = 0.0_f64;
    let mut loss = 0.0_f64;
    let mut seed = 1_u64;
    let mut clients = 1_u32;
    let mut seen_clients_param = false;
    let mut seen_keys = HashSet::new();
    let mut params = Vec::new();
    let mut param_scope = ScopeStack::new();

    for param in nst.params() {
        let key = param
            .name()
            .map(|t| t.text().to_owned())
            .unwrap_or_default();
        let pspan = Span::from_range(file, src, param.syntax().text_range());
        if !seen_keys.insert(key.clone()) {
            diags.push(Diagnostic::error(
                codes::E0505_INVALID_NET_SIM_PARAM,
                pspan.clone(),
                format!("duplicate parameter `{key}` in net_sim_test `{name}`"),
                None,
            ));
        }
        let val_expr = param.value_expr().map_or(
            HirExpr::Tuple {
                elems: Vec::new(),
                ty: Ty::Unit,
            },
            |e| lower_expr(&e, lower_env, &mut param_scope, &[]),
        );

        match key.as_str() {
            "latency" | "jitter" => match eval_time_ms(&val_expr) {
                Ok(ms) if ms.is_finite() && ms >= 0.0 => {
                    if key == "latency" {
                        latency_ms = ms;
                    } else {
                        jitter_ms = ms;
                    }
                }
                Ok(ms) => {
                    diags.push(Diagnostic::error(
                        codes::E0505_INVALID_NET_SIM_PARAM,
                        pspan,
                        format!("net_sim_test `{name}` `{key}` ({ms}) cannot be negative"),
                        None,
                    ));
                }
                Err(msg) => {
                    diags.push(Diagnostic::error(
                        codes::E0505_INVALID_NET_SIM_PARAM,
                        pspan,
                        format!("net_sim_test `{name}` `{key}` invalid: {msg}"),
                        None,
                    ));
                }
            },
            "loss" => {
                if matches!(val_expr.ty(), Ty::UnitScalar { .. }) {
                    diags.push(Diagnostic::error(
                        codes::E0505_INVALID_NET_SIM_PARAM,
                        pspan,
                        format!("net_sim_test `{name}` `loss` must be a dimensionless ratio in range 0.0..=1.0"),
                        None,
                    ));
                } else if let Some(v) = eval_const_f64(&val_expr) {
                    if v.is_finite() && (0.0..=1.0).contains(&v) {
                        loss = v;
                    } else {
                        diags.push(Diagnostic::error(
                            codes::E0505_INVALID_NET_SIM_PARAM,
                            pspan,
                            format!(
                                "net_sim_test `{name}` `loss` ({v}) must be in range 0.0..=1.0"
                            ),
                            None,
                        ));
                    }
                } else {
                    diags.push(Diagnostic::error(
                        codes::E0505_INVALID_NET_SIM_PARAM,
                        pspan,
                        format!("net_sim_test `{name}` `loss` must be a float in range 0.0..=1.0"),
                        None,
                    ));
                }
            }
            "seed" => {
                let parsed = param.value_expr().and_then(|e| eval_cst_const_i64(&e));
                match parsed {
                    Some(v) if v >= 0 => seed = v as u64,
                    _ => {
                        diags.push(Diagnostic::error(
                            codes::E0505_INVALID_NET_SIM_PARAM,
                            pspan,
                            format!("net_sim_test `{name}` `seed` must be a non-negative integer"),
                            None,
                        ));
                    }
                }
            }
            "clients" => {
                seen_clients_param = true;
                let parsed = param.value_expr().and_then(|e| eval_cst_const_i64(&e));
                match parsed {
                    Some(v) if v >= 1 && v <= u32::MAX as i64 => clients = v as u32,
                    _ => {
                        diags.push(Diagnostic::error(
                            codes::E0505_INVALID_NET_SIM_PARAM,
                            pspan,
                            format!("net_sim_test `{name}` `clients` must be an integer >= 1"),
                            None,
                        ));
                    }
                }
            }
            other => {
                diags.push(Diagnostic::error(
                    codes::E0505_INVALID_NET_SIM_PARAM,
                    pspan,
                    format!("unknown parameter `{other}` in net_sim_test `{name}`"),
                    None,
                ));
            }
        }
        params.push((key, val_expr));
    }

    let block = nst.body();
    let body_source = block
        .as_ref()
        .map(|b| b.syntax().text().to_string())
        .unwrap_or_default();
    let mut scope = ScopeStack::new();
    let body = block
        .as_ref()
        .map(|b| lower_block_as_stmts(b.syntax(), lower_env, &mut scope, &[], false))
        .unwrap_or_default();

    if !seen_clients_param {
        for stmt in &body {
            if let HirStmt::Expr(HirExpr::Call(c)) = stmt
                && c.receiver.is_none()
                && c.callee == "clients"
                && let Some(HirExpr::IntLit { value, .. }) = c.args.first()
                && *value >= 1
                && *value <= u32::MAX as i64
            {
                clients = *value as u32;
                break;
            }
        }
    }

    validate_no_query_handle_reassign(
        file,
        src,
        &name,
        Span::from_range(file, src, nst.syntax().text_range()),
        &body,
        None,
        &[],
        diags,
    );

    HirNetSimTest {
        name,
        latency_ms,
        jitter_ms,
        loss,
        seed,
        clients,
        node_group: None,
        params,
        body,
        body_source,
    }
}

pub(super) fn validate_node_pure_fn(
    file: &str,
    src: &str,
    fn_node: &SyntaxNode,
    hf: &HirFn,
    all_user_fns: &HashSet<String>,
    pure_fns: &HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let fn_span = Span::from_bytes(file, src, hf.byte_range.0, hf.byte_range.1);

    // Check parameter list for forbidden ECS resource / mutable / stream / trigger parameters.
    for p in &hf.params {
        match p.kind {
            HirParamKind::ResRead | HirParamKind::ResWrite => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    Span::from_range(file, src, fn_node.text_range()),
                    format!(
                        "@node_pure function `{}` cannot access ECS resource parameter `{}`",
                        hf.name, p.name
                    ),
                    None,
                ));
            }
            HirParamKind::StreamIn | HirParamKind::Trigger | HirParamKind::RefMut => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    Span::from_range(file, src, fn_node.text_range()),
                    format!(
                        "@node_pure function `{}` cannot take ECS/mutable parameter `{}`",
                        hf.name, p.name
                    ),
                    None,
                ));
            }
            HirParamKind::Value | HirParamKind::Ref => {}
        }
    }

    fn check_lvalue_pure(
        lv: &HirLValue,
        fn_name: &str,
        span: &Span,
        all_user_fns: &HashSet<String>,
        pure_fns: &HashSet<String>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match lv {
            HirLValue::ResourceAccess {
                resource,
                client_id,
                ..
            } => {
                if let Some(cid) = client_id {
                    check_expr_pure(cid, fn_name, span, all_user_fns, pure_fns, diags);
                }
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!(
                        "@node_pure function `{fn_name}` cannot access ECS resource `{resource}`"
                    ),
                    None,
                ));
            }
            HirLValue::Field { base, .. } => {
                check_lvalue_pure(base, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirLValue::Index { base, index, .. } => {
                check_lvalue_pure(base, fn_name, span, all_user_fns, pure_fns, diags);
                check_expr_pure(index, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirLValue::Local { .. } => {}
            HirLValue::Expr(e) => check_expr_pure(e, fn_name, span, all_user_fns, pure_fns, diags),
        }
    }

    fn check_expr_pure(
        expr: &HirExpr,
        fn_name: &str,
        span: &Span,
        all_user_fns: &HashSet<String>,
        pure_fns: &HashSet<String>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match expr {
            HirExpr::Query(_) => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!(
                        "@node_pure function `{fn_name}` cannot perform ECS `query` side effect"
                    ),
                    None,
                ));
            }
            HirExpr::Spawn(_) => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `spawn` side effect"),
                    None,
                ));
            }
            HirExpr::DespawnAll { .. } => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!(
                        "@node_pure function `{fn_name}` cannot perform `despawn_all` side effect"
                    ),
                    None,
                ));
            }
            HirExpr::Insert { .. } => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `insert` side effect"),
                    None,
                ));
            }
            HirExpr::Remove { .. } => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `remove` side effect"),
                    None,
                ));
            }
            HirExpr::Unary {
                op, expr: inner, ..
            } => {
                if *op == HirUnOp::RefMut {
                    diags.push(Diagnostic::error(
                        codes::E0601_NODE_PURE_VIOLATION,
                        span.clone(),
                        format!(
                            "@node_pure function `{fn_name}` cannot take `&mut` mutable borrow"
                        ),
                        None,
                    ));
                }
                check_expr_pure(inner, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirExpr::Binary { lhs, rhs, .. } => {
                check_expr_pure(lhs, fn_name, span, all_user_fns, pure_fns, diags);
                check_expr_pure(rhs, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirExpr::Cast { expr: inner, .. } | HirExpr::Field { base: inner, .. } => {
                check_expr_pure(inner, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirExpr::Index { base, index, .. } => {
                check_expr_pure(base, fn_name, span, all_user_fns, pure_fns, diags);
                check_expr_pure(index, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirExpr::Call(call) => {
                if let Some(ref r) = call.receiver {
                    check_expr_pure(r, fn_name, span, all_user_fns, pure_fns, diags);
                }
                for a in &call.args {
                    check_expr_pure(a, fn_name, span, all_user_fns, pure_fns, diags);
                }
                if call.receiver.is_none() {
                    const IMPURE_BUILTINS: &[&str] = &[
                        "query",
                        "query_one",
                        "query_many",
                        "emit",
                        "trigger",
                        "despawn",
                        "insert",
                        "remove",
                        "spawn",
                        "spawn_batch",
                        "despawn_all",
                        "insert_relation",
                        "remove_relation",
                        "res",
                        "res_mut",
                        "send_rpc",
                        "step_fixed",
                        "server_res",
                        "client_res",
                        "server_query",
                        "client_query",
                        "server_spawn",
                        "client_spawn",
                    ];
                    if IMPURE_BUILTINS.contains(&call.callee.as_str()) {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            span.clone(),
                            format!(
                                "@node_pure function `{fn_name}` cannot call ECS/side-effect builtin `{}`",
                                call.callee
                            ),
                            None,
                        ));
                    } else if all_user_fns.contains(&call.callee)
                        && !pure_fns.contains(&call.callee)
                    {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            span.clone(),
                            format!(
                                "@node_pure function `{fn_name}` cannot call non-@node_pure function `{}`",
                                call.callee
                            ),
                            None,
                        ));
                    }
                } else if matches!(call.callee.as_str(), "query_disc" | "query_segment_at") {
                    diags.push(Diagnostic::error(
                        codes::E0601_NODE_PURE_VIOLATION,
                        span.clone(),
                        format!(
                            "@node_pure function `{fn_name}` cannot call spatial ECS query `{}`",
                            call.callee
                        ),
                        None,
                    ));
                }
            }
            HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
                for (_, v) in fields {
                    check_expr_pure(v, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    for (_, v) in &ci.fields {
                        check_expr_pure(v, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                }
            }
            HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
                for e in elems {
                    check_expr_pure(e, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                for s in stmts {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
                if let Some(t) = tail {
                    check_expr_pure(t, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::If {
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ..
            } => {
                check_expr_pure(cond, fn_name, span, all_user_fns, pure_fns, diags);
                for s in then_stmts {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
                if let Some(t) = then_tail {
                    check_expr_pure(t, fn_name, span, all_user_fns, pure_fns, diags);
                }
                for s in else_stmts {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
                if let Some(t) = else_tail {
                    check_expr_pure(t, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::Match(m) => {
                check_expr_pure(&m.scrutinee, fn_name, span, all_user_fns, pure_fns, diags);
                for arm in &m.arms {
                    if let Some(ref g) = arm.guard {
                        check_expr_pure(g, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                    check_expr_pure(&arm.body, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::For(f) => {
                match &f.iter {
                    HirForIter::Query(_) => {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            span.clone(),
                            format!("@node_pure function `{fn_name}` cannot iterate ECS `query`"),
                            None,
                        ));
                    }
                    HirForIter::SpatialDisc { center, radius, .. } => {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            span.clone(),
                            format!("@node_pure function `{fn_name}` cannot perform spatial ECS query `query_disc`"),
                            None,
                        ));
                        check_expr_pure(center, fn_name, span, all_user_fns, pure_fns, diags);
                        check_expr_pure(radius, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                    HirForIter::SpatialSegmentAt { tick, p0, p1, .. } => {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            span.clone(),
                            format!("@node_pure function `{fn_name}` cannot perform spatial ECS query `query_segment_at`"),
                            None,
                        ));
                        check_expr_pure(tick, fn_name, span, all_user_fns, pure_fns, diags);
                        check_expr_pure(p0, fn_name, span, all_user_fns, pure_fns, diags);
                        check_expr_pure(p1, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                    HirForIter::Range { start, end, .. } => {
                        check_expr_pure(start, fn_name, span, all_user_fns, pure_fns, diags);
                        check_expr_pure(end, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                    HirForIter::Expr(e) => {
                        check_expr_pure(e, fn_name, span, all_user_fns, pure_fns, diags);
                    }
                }
                for s in &f.body {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
                for r in &f.reduce {
                    check_expr_pure(&r.identity, fn_name, span, all_user_fns, pure_fns, diags);
                    check_expr_pure(&r.value, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirExpr::IntLit { .. }
            | HirExpr::FloatLit { .. }
            | HirExpr::BoolLit(_)
            | HirExpr::StringLit(_)
            | HirExpr::CharLit(_)
            | HirExpr::Path { .. } => {}
        }
    }

    fn check_stmt_pure(
        stmt: &HirStmt,
        fn_name: &str,
        span: &Span,
        all_user_fns: &HashSet<String>,
        pure_fns: &HashSet<String>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match stmt {
            HirStmt::Let {
                value, else_block, ..
            } => {
                check_expr_pure(value, fn_name, span, all_user_fns, pure_fns, diags);
                for s in else_block {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirStmt::Assign { target, value, .. } => {
                check_lvalue_pure(target, fn_name, span, all_user_fns, pure_fns, diags);
                check_expr_pure(value, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirStmt::Expr(e) => {
                check_expr_pure(e, fn_name, span, all_user_fns, pure_fns, diags);
            }
            HirStmt::Return(opt) | HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    check_expr_pure(e, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirStmt::Continue => {}
            HirStmt::While { cond, body } => {
                check_expr_pure(cond, fn_name, span, all_user_fns, pure_fns, diags);
                for s in body {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirStmt::Loop { body } => {
                for s in body {
                    check_stmt_pure(s, fn_name, span, all_user_fns, pure_fns, diags);
                }
            }
            HirStmt::Emit(_) => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `emit` side effect"),
                    None,
                ));
            }
            HirStmt::Trigger { .. } => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `trigger` side effect"),
                    None,
                ));
            }
            HirStmt::Despawn(_) => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform `despawn` side effect"),
                    None,
                ));
            }
            HirStmt::InsertRelation { .. } | HirStmt::RemoveRelation { .. } => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot mutate ECS relations"),
                    None,
                ));
            }
            HirStmt::Atomic(_)
            | HirStmt::AbortIf { .. }
            | HirStmt::Wait(_)
            | HirStmt::WaitUntil(_)
            | HirStmt::YieldTick
            | HirStmt::Race { .. }
            | HirStmt::RequireTrue(_) => {
                diags.push(Diagnostic::error(
                    codes::E0601_NODE_PURE_VIOLATION,
                    span.clone(),
                    format!("@node_pure function `{fn_name}` cannot perform coroutine/transactional side effect"),
                    None,
                ));
            }
        }
    }

    for p in &hf.params {
        if let Some(ref def_expr) = p.default {
            check_expr_pure(def_expr, &hf.name, &fn_span, all_user_fns, pure_fns, diags);
        }
    }
    for stmt in &hf.body {
        check_stmt_pure(stmt, &hf.name, &fn_span, all_user_fns, pure_fns, diags);
    }
    if let Some(ref tail) = hf.tail {
        check_expr_pure(tail, &hf.name, &fn_span, all_user_fns, pure_fns, diags);
    }
}

#[derive(Clone, PartialEq, Eq)]
enum HandleValue {
    Row(HashMap<String, bool>),
    Comp,
    ProjectedTerm,
    Optional(Box<HandleValue>),
    Tuple(Vec<Option<HandleValue>>),
    Array(Box<HandleValue>),
    Struct(HashMap<String, HandleValue>),
}

fn comp_terms_from_ty_terms(terms: &[QueryRowTerm]) -> HashMap<String, bool> {
    let mut map = HashMap::new();
    for term in terms {
        if term.field_name.is_none() && term.storage_key != "Entity" {
            let is_opt = matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            );
            map.insert(term.alias.clone(), is_opt);
        }
    }
    map
}

fn handle_value_from_ty(ty: &Ty) -> Option<HandleValue> {
    match ty {
        Ty::Borrow { inner, .. } => match inner.as_ref() {
            Ty::QueryRow(terms) => Some(HandleValue::Row(comp_terms_from_ty_terms(terms))),
            Ty::Named(_)
            | Ty::Ref(_)
            | Ty::Tuple(_)
            | Ty::Array { .. }
            | Ty::Option(_)
            | Ty::Record(_) => Some(HandleValue::Comp),
            _ => Some(HandleValue::ProjectedTerm),
        },
        Ty::QueryRow(terms) => Some(HandleValue::Row(comp_terms_from_ty_terms(terms))),
        Ty::Option(inner) => {
            handle_value_from_ty(inner).map(|hv| HandleValue::Optional(Box::new(hv)))
        }
        Ty::Tuple(elems) => {
            let vals: Vec<Option<HandleValue>> = elems.iter().map(handle_value_from_ty).collect();
            vals.iter()
                .any(Option::is_some)
                .then_some(HandleValue::Tuple(vals))
        }
        Ty::Array { elem, .. } => {
            handle_value_from_ty(elem).map(|hv| HandleValue::Array(Box::new(hv)))
        }
        _ => None,
    }
}

fn handle_value_from_param(p: &HirParam) -> Option<HandleValue> {
    match p.kind {
        HirParamKind::ResRead
        | HirParamKind::ResWrite
        | HirParamKind::Trigger
        | HirParamKind::StreamIn => None,
        HirParamKind::Ref | HirParamKind::RefMut => match &p.ty {
            Ty::QueryRow(terms) => Some(HandleValue::Row(comp_terms_from_ty_terms(terms))),
            Ty::Named(_)
            | Ty::Ref(_)
            | Ty::Tuple(_)
            | Ty::Array { .. }
            | Ty::Option(_)
            | Ty::Record(_) => Some(HandleValue::Comp),
            _ => Some(HandleValue::ProjectedTerm),
        },
        HirParamKind::Value => handle_value_from_ty(&p.ty),
    }
}

fn validate_helper_fn_no_queries(file: &str, src: &str, hf: &HirFn, diags: &mut Vec<Diagnostic>) {
    let fn_span = Span::from_bytes(file, src, hf.byte_range.0, hf.byte_range.1);

    fn check_lvalue(lv: &HirLValue, fn_name: &str, span: &Span, diags: &mut Vec<Diagnostic>) {
        match lv {
            HirLValue::Field { base, .. } => check_lvalue(base, fn_name, span, diags),
            HirLValue::Index { base, index, .. } => {
                check_lvalue(base, fn_name, span, diags);
                check_expr(index, fn_name, span, diags);
            }
            HirLValue::ResourceAccess { client_id, .. } => {
                if let Some(cid) = client_id {
                    check_expr(cid, fn_name, span, diags);
                }
            }
            HirLValue::Expr(e) => check_expr(e, fn_name, span, diags),
            HirLValue::Local { .. } => {}
        }
    }

    fn check_expr(expr: &HirExpr, fn_name: &str, span: &Span, diags: &mut Vec<Diagnostic>) {
        match expr {
            HirExpr::Query(hq) => {
                let what = if hq.is_point_lookup {
                    "query_one"
                } else {
                    "query"
                };
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    span.clone(),
                    format!(
                        "helper function `{fn_name}` cannot execute ECS `{what}` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context"
                    ),
                    None,
                ));
                if let Some(ref pred) = hq.where_pred {
                    check_expr(pred, fn_name, span, diags);
                }
                if let Some(ref tgt) = hq.on_target {
                    check_expr(tgt, fn_name, span, diags);
                }
            }
            HirExpr::Unary { expr: inner, .. }
            | HirExpr::Cast { expr: inner, .. }
            | HirExpr::Field { base: inner, .. }
            | HirExpr::Remove { entity: inner, .. } => {
                check_expr(inner, fn_name, span, diags);
            }
            HirExpr::Binary { lhs, rhs, .. }
            | HirExpr::Index {
                base: lhs,
                index: rhs,
                ..
            }
            | HirExpr::Insert {
                entity: lhs,
                value: rhs,
                ..
            } => {
                check_expr(lhs, fn_name, span, diags);
                check_expr(rhs, fn_name, span, diags);
            }
            HirExpr::Call(call) => {
                if let Some(ref r) = call.receiver {
                    check_expr(r, fn_name, span, diags);
                }
                for a in &call.args {
                    check_expr(a, fn_name, span, diags);
                }
                if call.receiver.is_none()
                    && matches!(
                        call.callee.as_str(),
                        "query" | "query_one" | "query_many" | "server_query" | "client_query"
                    )
                {
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        span.clone(),
                        format!(
                            "helper function `{fn_name}` cannot execute ECS `{}` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context",
                            call.callee
                        ),
                        None,
                    ));
                } else if matches!(call.callee.as_str(), "query_disc" | "query_segment_at") {
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        span.clone(),
                        format!(
                            "helper function `{fn_name}` cannot execute spatial ECS `{}` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context",
                            call.callee
                        ),
                        None,
                    ));
                }
            }
            HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
                for (_, v) in fields {
                    check_expr(v, fn_name, span, diags);
                }
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    for (_, v) in &ci.fields {
                        check_expr(v, fn_name, span, diags);
                    }
                }
            }
            HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
                for e in elems {
                    check_expr(e, fn_name, span, diags);
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                for s in stmts {
                    check_stmt(s, fn_name, span, diags);
                }
                if let Some(t) = tail {
                    check_expr(t, fn_name, span, diags);
                }
            }
            HirExpr::If {
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ..
            } => {
                check_expr(cond, fn_name, span, diags);
                for s in then_stmts {
                    check_stmt(s, fn_name, span, diags);
                }
                if let Some(t) = then_tail {
                    check_expr(t, fn_name, span, diags);
                }
                for s in else_stmts {
                    check_stmt(s, fn_name, span, diags);
                }
                if let Some(t) = else_tail {
                    check_expr(t, fn_name, span, diags);
                }
            }
            HirExpr::Match(m) => {
                check_expr(&m.scrutinee, fn_name, span, diags);
                for arm in &m.arms {
                    if let Some(ref g) = arm.guard {
                        check_expr(g, fn_name, span, diags);
                    }
                    check_expr(&arm.body, fn_name, span, diags);
                }
            }
            HirExpr::For(f) => {
                match &f.iter {
                    HirForIter::Query(hq) => {
                        let what = if hq.is_point_lookup {
                            "query_one"
                        } else {
                            "query"
                        };
                        diags.push(Diagnostic::error(
                            codes::E0204_EFFECTS_MISMATCH,
                            span.clone(),
                            format!(
                                "helper function `{fn_name}` cannot iterate ECS `{what}` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context"
                            ),
                            None,
                        ));
                        if let Some(ref pred) = hq.where_pred {
                            check_expr(pred, fn_name, span, diags);
                        }
                        if let Some(ref tgt) = hq.on_target {
                            check_expr(tgt, fn_name, span, diags);
                        }
                    }
                    HirForIter::SpatialDisc { center, radius, .. } => {
                        diags.push(Diagnostic::error(
                            codes::E0204_EFFECTS_MISMATCH,
                            span.clone(),
                            format!(
                                "helper function `{fn_name}` cannot iterate spatial ECS `query_disc` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context"
                            ),
                            None,
                        ));
                        check_expr(center, fn_name, span, diags);
                        check_expr(radius, fn_name, span, diags);
                    }
                    HirForIter::SpatialSegmentAt { tick, p0, p1, .. } => {
                        diags.push(Diagnostic::error(
                            codes::E0204_EFFECTS_MISMATCH,
                            span.clone(),
                            format!(
                                "helper function `{fn_name}` cannot iterate spatial ECS `query_segment_at` outside a `sys`, `obs`, `task`, `fsm`, or `sim_test` context"
                            ),
                            None,
                        ));
                        check_expr(tick, fn_name, span, diags);
                        check_expr(p0, fn_name, span, diags);
                        check_expr(p1, fn_name, span, diags);
                    }
                    HirForIter::Range { start, end, .. } => {
                        check_expr(start, fn_name, span, diags);
                        check_expr(end, fn_name, span, diags);
                    }
                    HirForIter::Expr(e) => check_expr(e, fn_name, span, diags),
                }
                for s in &f.body {
                    check_stmt(s, fn_name, span, diags);
                }
                for r in &f.reduce {
                    check_expr(&r.identity, fn_name, span, diags);
                    check_expr(&r.value, fn_name, span, diags);
                }
            }
            HirExpr::Spawn(sp) => {
                if let Some(ref cnt) = sp.count {
                    check_expr(cnt, fn_name, span, diags);
                }
                for s in &sp.preamble {
                    check_stmt(s, fn_name, span, diags);
                }
                for ci in &sp.components {
                    for (_, v) in &ci.fields {
                        check_expr(v, fn_name, span, diags);
                    }
                }
            }
            HirExpr::IntLit { .. }
            | HirExpr::FloatLit { .. }
            | HirExpr::BoolLit(_)
            | HirExpr::StringLit(_)
            | HirExpr::CharLit(_)
            | HirExpr::Path { .. }
            | HirExpr::DespawnAll { .. } => {}
        }
    }

    fn check_stmt(stmt: &HirStmt, fn_name: &str, span: &Span, diags: &mut Vec<Diagnostic>) {
        match stmt {
            HirStmt::Let {
                value, else_block, ..
            } => {
                check_expr(value, fn_name, span, diags);
                for s in else_block {
                    check_stmt(s, fn_name, span, diags);
                }
            }
            HirStmt::Assign { target, value, .. } => {
                check_lvalue(target, fn_name, span, diags);
                check_expr(value, fn_name, span, diags);
            }
            HirStmt::Expr(e)
            | HirStmt::Wait(e)
            | HirStmt::WaitUntil(e)
            | HirStmt::RequireTrue(e)
            | HirStmt::Emit(e)
            | HirStmt::Despawn(e) => {
                check_expr(e, fn_name, span, diags);
            }
            HirStmt::Return(opt) | HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    check_expr(e, fn_name, span, diags);
                }
            }
            HirStmt::Continue | HirStmt::YieldTick => {}
            HirStmt::While { cond, body }
            | HirStmt::AbortIf {
                cond,
                cleanup: body,
            } => {
                check_expr(cond, fn_name, span, diags);
                for s in body {
                    check_stmt(s, fn_name, span, diags);
                }
            }
            HirStmt::Loop { body } => {
                for s in body {
                    check_stmt(s, fn_name, span, diags);
                }
            }
            HirStmt::Atomic(at) => {
                for s in &at.body {
                    check_stmt(s, fn_name, span, diags);
                }
                for s in &at.on_rollback {
                    check_stmt(s, fn_name, span, diags);
                }
            }
            HirStmt::Race { branches } => {
                for br in branches {
                    for s in br {
                        check_stmt(s, fn_name, span, diags);
                    }
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    check_expr(t, fn_name, span, diags);
                }
                check_expr(event, fn_name, span, diags);
            }
            HirStmt::InsertRelation {
                entity,
                target,
                payload,
                ..
            } => {
                check_expr(entity, fn_name, span, diags);
                check_expr(target, fn_name, span, diags);
                if let Some(p) = payload {
                    check_expr(p, fn_name, span, diags);
                }
            }
            HirStmt::RemoveRelation { entity, target, .. } => {
                check_expr(entity, fn_name, span, diags);
                check_expr(target, fn_name, span, diags);
            }
        }
    }

    for p in &hf.params {
        if let Some(ref def_expr) = p.default {
            check_expr(def_expr, &hf.name, &fn_span, diags);
        }
    }
    for stmt in &hf.body {
        check_stmt(stmt, &hf.name, &fn_span, diags);
    }
    if let Some(ref tail) = hf.tail {
        check_expr(tail, &hf.name, &fn_span, diags);
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_no_query_handle_reassign(
    _file: &str,
    _src: &str,
    item_name: &str,
    span: Span,
    stmts: &[HirStmt],
    tail: Option<&HirExpr>,
    initial_handles: &[(String, HandleValue)],
    diags: &mut Vec<Diagnostic>,
) {
    type HandleScope = HashMap<String, Option<HandleValue>>;

    fn comp_terms_for_query(hq: &crate::hir::HirQuery) -> HashMap<String, bool> {
        let mut map = HashMap::new();
        for term in &hq.terms {
            if term.field_name.is_none() && term.storage_key != "Entity" {
                let is_opt = matches!(
                    term.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                );
                map.insert(term.alias.clone(), is_opt);
            }
        }
        map
    }

    fn lookup_handle<'a>(scopes: &'a [HandleScope], name: &str) -> Option<&'a HandleValue> {
        for s in scopes.iter().rev() {
            if let Some(entry) = s.get(name) {
                return entry.as_ref();
            }
        }
        None
    }

    fn is_opt_borrow_ty(ty: &Ty) -> bool {
        matches!(
            ty,
            Ty::Option(inner)
                if matches!(
                    inner.as_ref(),
                    Ty::Borrow { .. } | Ty::QueryRow(_) | Ty::Ref(_)
                )
        )
    }

    fn unwrap_optional_handle(hv: &HandleValue) -> Option<HandleValue> {
        match hv {
            HandleValue::Optional(inner) => Some((**inner).clone()),
            HandleValue::Row(m) => Some(HandleValue::Row(m.clone())),
            HandleValue::Comp => Some(HandleValue::Comp),
            _ => None,
        }
    }

    fn wrap_optional_handle(hv: HandleValue) -> Option<HandleValue> {
        match hv {
            HandleValue::Optional(_) => Some(hv),
            other if contains_handle(&other) => Some(HandleValue::Optional(Box::new(other))),
            _ => None,
        }
    }

    fn merge_handle_values(a: Option<HandleValue>, b: Option<HandleValue>) -> Option<HandleValue> {
        match (a, b) {
            (Some(HandleValue::Row(mut m1)), Some(HandleValue::Row(m2))) => {
                for (k, v) in m2 {
                    m1.entry(k).and_modify(|e| *e |= v).or_insert(v);
                }
                Some(HandleValue::Row(m1))
            }
            (Some(HandleValue::Optional(a1)), Some(HandleValue::Optional(b1))) => {
                merge_handle_values(Some(*a1), Some(*b1))
                    .map(|inner| HandleValue::Optional(Box::new(inner)))
            }
            (Some(HandleValue::Array(a1)), Some(HandleValue::Array(b1))) => {
                merge_handle_values(Some(*a1), Some(*b1))
                    .map(|inner| HandleValue::Array(Box::new(inner)))
            }
            (Some(HandleValue::Struct(mut s1)), Some(HandleValue::Struct(s2))) => {
                for (k, v2) in s2 {
                    let merged = merge_handle_values(s1.remove(&k), Some(v2));
                    if let Some(m) = merged {
                        s1.insert(k, m);
                    }
                }
                Some(HandleValue::Struct(s1))
            }
            (Some(HandleValue::Tuple(v1)), Some(HandleValue::Tuple(v2))) => {
                let len = v1.len().max(v2.len());
                let mut out = Vec::with_capacity(len);
                for i in 0..len {
                    let e1 = v1.get(i).cloned().flatten();
                    let e2 = v2.get(i).cloned().flatten();
                    out.push(merge_handle_values(e1, e2));
                }
                Some(HandleValue::Tuple(out))
            }
            (Some(x), None) | (None, Some(x)) | (Some(x), Some(_)) => Some(x),
            (None, None) => None,
        }
    }

    fn contains_handle(hv: &HandleValue) -> bool {
        match hv {
            HandleValue::Row(_) | HandleValue::Comp | HandleValue::ProjectedTerm => true,
            HandleValue::Optional(inner) | HandleValue::Array(inner) => contains_handle(inner),
            HandleValue::Tuple(elems) => elems
                .iter()
                .any(|e| e.as_ref().is_some_and(contains_handle)),
            HandleValue::Struct(fields) => fields.values().any(contains_handle),
        }
    }

    fn contains_borrow_handle(hv: &HandleValue) -> bool {
        match hv {
            HandleValue::Row(_) | HandleValue::Comp => true,
            HandleValue::ProjectedTerm => false,
            HandleValue::Optional(inner) | HandleValue::Array(inner) => {
                contains_borrow_handle(inner)
            }
            HandleValue::Tuple(elems) => elems
                .iter()
                .any(|e| e.as_ref().is_some_and(contains_borrow_handle)),
            HandleValue::Struct(fields) => fields.values().any(contains_borrow_handle),
        }
    }

    fn simulate_stmt_handles(stmt: &HirStmt, scopes: &mut [HandleScope]) {
        if let HirStmt::Let { pattern, value, .. } = stmt {
            let hv = expr_handle_value(value, scopes);
            bind_handle_pattern(pattern, hv, scopes);
        }
    }

    fn expr_handle_value(expr: &HirExpr, scopes: &[HandleScope]) -> Option<HandleValue> {
        match expr {
            HirExpr::Query(hq) => {
                if hq.is_count {
                    None
                } else if hq.is_point_lookup && !hq.is_unwrap {
                    Some(HandleValue::Optional(Box::new(HandleValue::Row(
                        comp_terms_for_query(hq),
                    ))))
                } else if hq.terms.len() == 1
                    && hq.terms[0].field_name.is_some()
                    && !matches!(
                        hq.terms[0].mode,
                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                    )
                {
                    Some(HandleValue::ProjectedTerm)
                } else {
                    Some(HandleValue::Row(comp_terms_for_query(hq)))
                }
            }
            HirExpr::Path { name, .. } => lookup_handle(scopes, name).cloned(),
            HirExpr::Field { base, field, .. } => match expr_handle_value(base, scopes)? {
                HandleValue::Row(comp_terms) => {
                    if let Some(&is_opt) = comp_terms.get(field) {
                        Some(if is_opt || is_opt_borrow_ty(&expr.ty()) {
                            HandleValue::Optional(Box::new(HandleValue::Comp))
                        } else {
                            HandleValue::Comp
                        })
                    } else {
                        None
                    }
                }
                HandleValue::Tuple(elems) => {
                    let idx = field.parse::<usize>().ok()?;
                    elems.get(idx).cloned().flatten()
                }
                HandleValue::Struct(fields) => fields.get(field).cloned(),
                _ => None,
            },
            HirExpr::Index { base, .. } => match expr_handle_value(base, scopes)? {
                HandleValue::Array(inner) => Some(*inner),
                _ => None,
            },
            HirExpr::ArrayLit { elems, .. } => {
                let mut acc: Option<HandleValue> = None;
                for e in elems {
                    let ehv = expr_handle_value(e, scopes);
                    acc = merge_handle_values(acc, ehv);
                }
                acc.filter(contains_handle)
                    .map(|inner| HandleValue::Array(Box::new(inner)))
            }
            HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
                let mut map = HashMap::new();
                for (k, v) in fields {
                    if let Some(hv) = expr_handle_value(v, scopes)
                        && contains_handle(&hv)
                    {
                        map.insert(k.clone(), hv);
                    }
                }
                (!map.is_empty()).then_some(HandleValue::Struct(map))
            }
            HirExpr::Call(call)
                if matches!(
                    call.callee.as_str(),
                    "unwrap"
                        | "expect"
                        | "unwrap_or"
                        | "unwrap_or_else"
                        | "or"
                        | "or_else"
                        | "and"
                        | "and_then"
                        | "as_ref"
                        | "as_mut"
                        | "take"
                        | "filter"
                        | "Option::unwrap"
                        | "Option::expect"
                        | "Option::unwrap_or"
                        | "Option::unwrap_or_else"
                        | "Option::or"
                        | "Option::or_else"
                        | "Option::and"
                        | "Option::and_then"
                        | "Option::as_ref"
                        | "Option::as_mut"
                        | "Option::take"
                        | "Option::filter"
                ) =>
            {
                let recv = call.receiver.as_deref().or_else(|| call.args.first())?;
                let fb_idx = usize::from(call.receiver.is_none());
                match call.callee.as_str() {
                    "unwrap" | "expect" | "Option::unwrap" | "Option::expect" => {
                        expr_handle_value(recv, scopes).and_then(|hv| unwrap_optional_handle(&hv))
                    }
                    "unwrap_or"
                    | "unwrap_or_else"
                    | "Option::unwrap_or"
                    | "Option::unwrap_or_else" => {
                        let recv_hv = expr_handle_value(recv, scopes)
                            .and_then(|hv| unwrap_optional_handle(&hv));
                        let fb_hv = call
                            .args
                            .get(fb_idx)
                            .and_then(|a| expr_handle_value(a, scopes));
                        merge_handle_values(recv_hv, fb_hv)
                    }
                    "or" | "or_else" | "Option::or" | "Option::or_else" => {
                        let recv_hv = expr_handle_value(recv, scopes);
                        let fb_hv = call
                            .args
                            .get(fb_idx)
                            .and_then(|a| expr_handle_value(a, scopes));
                        merge_handle_values(recv_hv, fb_hv)
                    }
                    "and" | "and_then" | "Option::and" | "Option::and_then" => call
                        .args
                        .get(fb_idx)
                        .and_then(|a| expr_handle_value(a, scopes)),
                    "as_ref" | "as_mut" | "take" | "filter" | "Option::as_ref"
                    | "Option::as_mut" | "Option::take" | "Option::filter" => {
                        expr_handle_value(recv, scopes)
                    }
                    _ => None,
                }
            }
            HirExpr::Call(call)
                if call.receiver.is_none()
                    && matches!(call.callee.as_str(), "Some" | "Option::Some")
                    && call.args.len() == 1 =>
            {
                expr_handle_value(&call.args[0], scopes).and_then(wrap_optional_handle)
            }
            HirExpr::Tuple { elems, .. } => {
                let vals: Vec<Option<HandleValue>> =
                    elems.iter().map(|e| expr_handle_value(e, scopes)).collect();
                vals.iter()
                    .any(|v| v.as_ref().is_some_and(contains_handle))
                    .then_some(HandleValue::Tuple(vals))
            }
            HirExpr::Block { stmts, tail, .. } => {
                let t = tail.as_deref()?;
                let mut inner = scopes.to_vec();
                inner.push(HashMap::new());
                for s in stmts {
                    simulate_stmt_handles(s, &mut inner);
                }
                expr_handle_value(t, &inner)
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
                let then_hv = then_tail.as_deref().and_then(|t| {
                    let mut then_scopes = scopes.to_vec();
                    then_scopes.push(HashMap::new());
                    if let Some(pat) = let_pat {
                        let unwrapped = expr_handle_value(cond, scopes)
                            .and_then(|hv| unwrap_optional_handle(&hv));
                        bind_handle_pattern(pat, unwrapped, &mut then_scopes);
                    }
                    for s in then_stmts {
                        simulate_stmt_handles(s, &mut then_scopes);
                    }
                    expr_handle_value(t, &then_scopes)
                });
                let else_hv = else_tail.as_deref().and_then(|t| {
                    let mut else_scopes = scopes.to_vec();
                    else_scopes.push(HashMap::new());
                    for s in else_stmts {
                        simulate_stmt_handles(s, &mut else_scopes);
                    }
                    expr_handle_value(t, &else_scopes)
                });
                merge_handle_values(then_hv, else_hv)
            }
            HirExpr::Match(m) => {
                let scrut_hv = expr_handle_value(&m.scrutinee, scopes);
                let mut acc: Option<HandleValue> = None;
                for arm in &m.arms {
                    let mut arm_scopes = scopes.to_vec();
                    arm_scopes.push(HashMap::new());
                    bind_match_arm_pattern(&arm.pattern, scrut_hv.as_ref(), &mut arm_scopes);
                    let arm_hv = expr_handle_value(&arm.body, &arm_scopes);
                    acc = merge_handle_values(acc, arm_hv);
                }
                acc
            }
            _ => None,
        }
    }

    fn base_handle_value(lv: &HirLValue, scopes: &[HandleScope]) -> Option<HandleValue> {
        match lv {
            HirLValue::Local { name, .. } => lookup_handle(scopes, name).cloned(),
            HirLValue::Field { base, field, .. } => match base_handle_value(base, scopes)? {
                HandleValue::Row(comp_terms) => {
                    if let Some(&is_opt) = comp_terms.get(field) {
                        Some(if is_opt {
                            HandleValue::Optional(Box::new(HandleValue::Comp))
                        } else {
                            HandleValue::Comp
                        })
                    } else {
                        None
                    }
                }
                HandleValue::Tuple(elems) => {
                    let idx = field.parse::<usize>().ok()?;
                    elems.get(idx).cloned().flatten()
                }
                HandleValue::Struct(fields) => fields.get(field).cloned(),
                _ => None,
            },
            HirLValue::Index { base, .. } => match base_handle_value(base, scopes)? {
                HandleValue::Array(inner) => Some(*inner),
                _ => None,
            },
            HirLValue::Expr(e) => expr_handle_value(e, scopes),
            HirLValue::ResourceAccess { .. } => None,
        }
    }

    fn bind_match_arm_pattern(
        pat: &HirPattern,
        scrut_hv: Option<&HandleValue>,
        scopes: &mut [HandleScope],
    ) {
        match pat {
            HirPattern::TupleStruct { path, fields }
                if (path == "Some" || path.ends_with("::Some")) && !fields.is_empty() =>
            {
                let unwrapped = scrut_hv.and_then(unwrap_optional_handle);
                bind_handle_pattern(&fields[0], unwrapped, scopes);
                for extra in &fields[1..] {
                    bind_handle_pattern(extra, None, scopes);
                }
            }
            _ => bind_handle_pattern(pat, scrut_hv.cloned(), scopes),
        }
    }

    fn bind_handle_pattern(pat: &HirPattern, hv: Option<HandleValue>, scopes: &mut [HandleScope]) {
        match pat {
            HirPattern::Binding { name, .. } if name != "None" && name != "_" => {
                if let Some(top) = scopes.last_mut() {
                    top.insert(name.clone(), hv.filter(contains_handle));
                }
            }
            HirPattern::Tuple(elems) => {
                if let Some(HandleValue::Tuple(vals)) = hv {
                    for (idx, p) in elems.iter().enumerate() {
                        let v = vals.get(idx).cloned().flatten();
                        bind_handle_pattern(p, v, scopes);
                    }
                } else {
                    for p in elems {
                        bind_handle_pattern(p, None, scopes);
                    }
                }
            }
            HirPattern::TupleStruct { path, fields }
                if (path == "Some" || path.ends_with("::Some")) && !fields.is_empty() =>
            {
                let unwrapped = hv.as_ref().and_then(unwrap_optional_handle);
                bind_handle_pattern(&fields[0], unwrapped, scopes);
                for extra in &fields[1..] {
                    bind_handle_pattern(extra, None, scopes);
                }
            }
            HirPattern::TupleStruct { fields, .. } => {
                for f in fields {
                    bind_handle_pattern(f, None, scopes);
                }
            }
            _ => {}
        }
    }

    fn walk_lvalue(
        lv: &HirLValue,
        item_name: &str,
        span: &Span,
        scopes: &mut Vec<HandleScope>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match lv {
            HirLValue::Field { base, .. } => walk_lvalue(base, item_name, span, scopes, diags),
            HirLValue::Index { base, index, .. } => {
                walk_lvalue(base, item_name, span, scopes, diags);
                walk_expr(index, item_name, span, scopes, diags);
            }
            HirLValue::ResourceAccess { client_id, .. } => {
                if let Some(cid) = client_id {
                    walk_expr(cid, item_name, span, scopes, diags);
                }
            }
            HirLValue::Expr(e) => walk_expr(e, item_name, span, scopes, diags),
            HirLValue::Local { .. } => {}
        }
    }

    fn walk_expr(
        expr: &HirExpr,
        item_name: &str,
        span: &Span,
        scopes: &mut Vec<HandleScope>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match expr {
            HirExpr::Query(hq) => {
                if let Some(ref pred) = hq.where_pred {
                    walk_expr(pred, item_name, span, scopes, diags);
                }
                if let Some(ref tgt) = hq.on_target {
                    walk_expr(tgt, item_name, span, scopes, diags);
                }
            }
            HirExpr::Unary { expr: inner, .. }
            | HirExpr::Cast { expr: inner, .. }
            | HirExpr::Field { base: inner, .. }
            | HirExpr::Remove { entity: inner, .. } => {
                walk_expr(inner, item_name, span, scopes, diags);
            }
            HirExpr::Binary { lhs, rhs, .. }
            | HirExpr::Index {
                base: lhs,
                index: rhs,
                ..
            }
            | HirExpr::Insert {
                entity: lhs,
                value: rhs,
                ..
            } => {
                walk_expr(lhs, item_name, span, scopes, diags);
                walk_expr(rhs, item_name, span, scopes, diags);
            }
            HirExpr::Call(call) => {
                if let Some(ref r) = call.receiver {
                    walk_expr(r, item_name, span, scopes, diags);
                }
                for a in &call.args {
                    walk_expr(a, item_name, span, scopes, diags);
                }
                if matches!(
                    call.callee.as_str(),
                    "unwrap_or"
                        | "unwrap_or_else"
                        | "or"
                        | "or_else"
                        | "Option::unwrap_or"
                        | "Option::unwrap_or_else"
                        | "Option::or"
                        | "Option::or_else"
                ) {
                    let recv = call.receiver.as_deref().or_else(|| call.args.first());
                    let fb_idx = usize::from(call.receiver.is_none());
                    let fb = call.args.get(fb_idx);
                    let recv_has_handle = recv
                        .and_then(|r| expr_handle_value(r, scopes))
                        .is_some_and(|hv| contains_borrow_handle(&hv));
                    let fb_has_handle = fb
                        .and_then(|a| expr_handle_value(a, scopes))
                        .is_some_and(|hv| contains_borrow_handle(&hv));
                    if recv_has_handle || fb_has_handle {
                        diags.push(Diagnostic::error(
                            codes::E0201_ALIASING_CONFLICT,
                            span.clone(),
                            format!(
                                "cannot merge or select borrowed query handles via `{}` in `{item_name}`",
                                call.callee
                            ),
                            None,
                        ));
                    }
                }
            }
            HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
                for (_, v) in fields {
                    walk_expr(v, item_name, span, scopes, diags);
                }
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    for (_, v) in &ci.fields {
                        walk_expr(v, item_name, span, scopes, diags);
                    }
                }
            }
            HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
                for e in elems {
                    walk_expr(e, item_name, span, scopes, diags);
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                scopes.push(HashMap::new());
                for s in stmts {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                if let Some(t) = tail {
                    walk_expr(t, item_name, span, scopes, diags);
                }
                scopes.pop();
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
                walk_expr(cond, item_name, span, scopes, diags);
                let opt_unwrapped =
                    expr_handle_value(cond, scopes).and_then(|hv| unwrap_optional_handle(&hv));
                scopes.push(HashMap::new());
                if let Some(pat) = let_pat {
                    bind_handle_pattern(pat, opt_unwrapped, scopes);
                }
                for s in then_stmts {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                let then_has_handle = then_tail.as_deref().is_some_and(|t| {
                    walk_expr(t, item_name, span, scopes, diags);
                    expr_handle_value(t, scopes).is_some_and(|hv| contains_borrow_handle(&hv))
                });
                scopes.pop();

                scopes.push(HashMap::new());
                for s in else_stmts {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                let else_has_handle = else_tail.as_deref().is_some_and(|t| {
                    walk_expr(t, item_name, span, scopes, diags);
                    expr_handle_value(t, scopes).is_some_and(|hv| contains_borrow_handle(&hv))
                });
                scopes.pop();

                if then_has_handle || else_has_handle {
                    diags.push(Diagnostic::error(
                        codes::E0201_ALIASING_CONFLICT,
                        span.clone(),
                        format!(
                            "cannot return or merge borrowed query handles from conditional `if` expression in `{item_name}`"
                        ),
                        None,
                    ));
                }
            }
            HirExpr::Match(m) => {
                walk_expr(&m.scrutinee, item_name, span, scopes, diags);
                let scrut_hv = expr_handle_value(&m.scrutinee, scopes);
                let mut any_arm_handle = false;
                for arm in &m.arms {
                    scopes.push(HashMap::new());
                    bind_match_arm_pattern(&arm.pattern, scrut_hv.as_ref(), scopes);
                    if let Some(ref g) = arm.guard {
                        walk_expr(g, item_name, span, scopes, diags);
                    }
                    walk_expr(&arm.body, item_name, span, scopes, diags);
                    if expr_handle_value(&arm.body, scopes)
                        .is_some_and(|hv| contains_borrow_handle(&hv))
                    {
                        any_arm_handle = true;
                    }
                    scopes.pop();
                }
                if any_arm_handle {
                    diags.push(Diagnostic::error(
                        codes::E0201_ALIASING_CONFLICT,
                        span.clone(),
                        format!(
                            "cannot return or merge borrowed query handles from `match` expression in `{item_name}`"
                        ),
                        None,
                    ));
                }
            }
            HirExpr::For(f) => {
                scopes.push(HashMap::new());
                match &f.iter {
                    HirForIter::Query(hq) => {
                        let is_proj = hq.terms.len() == 1
                            && hq.terms[0].field_name.is_some()
                            && !matches!(
                                hq.terms[0].mode,
                                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                            );
                        let row_hv = if let HirPattern::Binding { name, .. } = &f.binding
                            && is_proj
                            && hq.terms[0].alias == *name
                        {
                            HandleValue::ProjectedTerm
                        } else {
                            HandleValue::Row(comp_terms_for_query(hq))
                        };
                        bind_handle_pattern(&f.binding, Some(row_hv), scopes);
                        for term in &hq.terms {
                            let is_opt = matches!(
                                term.mode,
                                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                            );
                            let hv = if term.field_name.is_some() && !is_opt {
                                HandleValue::ProjectedTerm
                            } else if is_opt {
                                HandleValue::Optional(Box::new(HandleValue::Comp))
                            } else {
                                HandleValue::Comp
                            };
                            if let Some(top) = scopes.last_mut() {
                                top.entry(term.alias.clone()).or_insert(Some(hv));
                            }
                        }
                        if let Some(ref pred) = hq.where_pred {
                            walk_expr(pred, item_name, span, scopes, diags);
                        }
                        if let Some(ref tgt) = hq.on_target {
                            walk_expr(tgt, item_name, span, scopes, diags);
                        }
                    }
                    HirForIter::SpatialDisc { center, radius, .. } => {
                        walk_expr(center, item_name, span, scopes, diags);
                        walk_expr(radius, item_name, span, scopes, diags);
                        bind_handle_pattern(&f.binding, None, scopes);
                    }
                    HirForIter::SpatialSegmentAt { tick, p0, p1, .. } => {
                        walk_expr(tick, item_name, span, scopes, diags);
                        walk_expr(p0, item_name, span, scopes, diags);
                        walk_expr(p1, item_name, span, scopes, diags);
                        bind_handle_pattern(&f.binding, None, scopes);
                    }
                    HirForIter::Range { start, end, .. } => {
                        walk_expr(start, item_name, span, scopes, diags);
                        walk_expr(end, item_name, span, scopes, diags);
                        bind_handle_pattern(&f.binding, None, scopes);
                    }
                    HirForIter::Expr(e) => {
                        walk_expr(e, item_name, span, scopes, diags);
                        let elem_hv = expr_handle_value(e, scopes).and_then(|hv| match hv {
                            HandleValue::Array(inner) => Some(*inner),
                            _ => None,
                        });
                        bind_handle_pattern(&f.binding, elem_hv, scopes);
                    }
                }
                for s in &f.body {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                for r in &f.reduce {
                    walk_expr(&r.identity, item_name, span, scopes, diags);
                    walk_expr(&r.value, item_name, span, scopes, diags);
                }
                scopes.pop();
            }
            HirExpr::Spawn(sp) => {
                if let Some(ref cnt) = sp.count {
                    walk_expr(cnt, item_name, span, scopes, diags);
                }
                scopes.push(HashMap::new());
                for s in &sp.preamble {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
                for ci in &sp.components {
                    for (_, v) in &ci.fields {
                        walk_expr(v, item_name, span, scopes, diags);
                    }
                }
            }
            HirExpr::IntLit { .. }
            | HirExpr::FloatLit { .. }
            | HirExpr::BoolLit(_)
            | HirExpr::StringLit(_)
            | HirExpr::CharLit(_)
            | HirExpr::Path { .. }
            | HirExpr::DespawnAll { .. } => {}
        }
    }

    fn walk_stmt(
        stmt: &HirStmt,
        item_name: &str,
        span: &Span,
        scopes: &mut Vec<HandleScope>,
        diags: &mut Vec<Diagnostic>,
    ) {
        match stmt {
            HirStmt::Let {
                pattern,
                value,
                else_block,
                ..
            } => {
                walk_expr(value, item_name, span, scopes, diags);
                scopes.push(HashMap::new());
                for s in else_block {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
                let hv = expr_handle_value(value, scopes);
                bind_handle_pattern(pattern, hv, scopes);
            }
            HirStmt::Assign { target, op, value } => {
                walk_lvalue(target, item_name, span, scopes, diags);
                walk_expr(value, item_name, span, scopes, diags);
                match target {
                    HirLValue::Local { name, .. } => {
                        if let Some(hv) = lookup_handle(scopes, name) {
                            let is_disallowed = match hv {
                                HandleValue::ProjectedTerm => {
                                    *op == HirAssignOp::Set
                                        && expr_handle_value(value, scopes).is_some()
                                }
                                _ => contains_handle(hv),
                            };
                            if is_disallowed {
                                diags.push(Diagnostic::error(
                                    codes::E0201_ALIASING_CONFLICT,
                                    span.clone(),
                                    format!(
                                        "borrowed query handle `{name}` in `{item_name}` cannot be reassigned; mutate its fields or bind a fresh `let` alias instead"
                                    ),
                                    None,
                                ));
                            }
                        }
                    }
                    HirLValue::Index { base, .. } => {
                        if let Some(HandleValue::Array(inner)) = base_handle_value(base, scopes) {
                            let is_disallowed = match inner.as_ref() {
                                HandleValue::ProjectedTerm => {
                                    *op == HirAssignOp::Set
                                        && expr_handle_value(value, scopes).is_some()
                                }
                                _ => contains_handle(&inner),
                            };
                            if is_disallowed {
                                diags.push(Diagnostic::error(
                                    codes::E0201_ALIASING_CONFLICT,
                                    span.clone(),
                                    format!(
                                        "borrowed query handle element in `{item_name}` cannot be reassigned; mutate its fields or bind a fresh `let` alias instead"
                                    ),
                                    None,
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            HirStmt::Expr(e)
            | HirStmt::Wait(e)
            | HirStmt::WaitUntil(e)
            | HirStmt::RequireTrue(e)
            | HirStmt::Emit(e)
            | HirStmt::Despawn(e) => {
                walk_expr(e, item_name, span, scopes, diags);
            }
            HirStmt::Return(opt) | HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    walk_expr(e, item_name, span, scopes, diags);
                }
            }
            HirStmt::Continue | HirStmt::YieldTick => {}
            HirStmt::While { cond, body }
            | HirStmt::AbortIf {
                cond,
                cleanup: body,
            } => {
                walk_expr(cond, item_name, span, scopes, diags);
                scopes.push(HashMap::new());
                for s in body {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
            }
            HirStmt::Loop { body } => {
                scopes.push(HashMap::new());
                for s in body {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
            }
            HirStmt::Atomic(at) => {
                scopes.push(HashMap::new());
                for s in &at.body {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
                scopes.push(HashMap::new());
                for s in &at.on_rollback {
                    walk_stmt(s, item_name, span, scopes, diags);
                }
                scopes.pop();
            }
            HirStmt::Race { branches } => {
                for br in branches {
                    scopes.push(HashMap::new());
                    for s in br {
                        walk_stmt(s, item_name, span, scopes, diags);
                    }
                    scopes.pop();
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    walk_expr(t, item_name, span, scopes, diags);
                }
                walk_expr(event, item_name, span, scopes, diags);
            }
            HirStmt::InsertRelation {
                entity,
                target,
                payload,
                ..
            } => {
                walk_expr(entity, item_name, span, scopes, diags);
                walk_expr(target, item_name, span, scopes, diags);
                if let Some(p) = payload {
                    walk_expr(p, item_name, span, scopes, diags);
                }
            }
            HirStmt::RemoveRelation { entity, target, .. } => {
                walk_expr(entity, item_name, span, scopes, diags);
                walk_expr(target, item_name, span, scopes, diags);
            }
        }
    }

    let mut scopes: Vec<HandleScope> = vec![HashMap::new()];
    for (k, hv) in initial_handles {
        scopes[0].insert(k.clone(), Some(hv.clone()));
    }
    for s in stmts {
        walk_stmt(s, item_name, &span, &mut scopes, diags);
    }
    if let Some(t) = tail {
        walk_expr(t, item_name, &span, &mut scopes, diags);
    }
}
