//! Attribute validation, net/quantize/authority parsing, and RPC metadata extraction.

use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    AuthorityKind, HirNetConfig, HirNetRpcMeta, HirQuantizeSpec, NetComponentMeta, NetDirection,
    NetReliability,
};
use crate::hir_lower::is_expr_node;
use crate::types::{Ty, UnitDim, parse_type_node};
use indexmap::IndexMap;
use strata_syntax::ast::{self, AstNode, ComponentDecl, SourceFile};
use strata_syntax::{SyntaxKind, SyntaxNode};

/// Extracts only schema/declaration headers (stripping `sys`/`obs`/`fn`/`sim_test`/`net_sim_test`
/// bodies) so Salsa early-cutoff avoids re-running layout resolution on body-only edits.
use super::schema::*;

pub(super) fn has_attr_name(node: &SyntaxNode, name: &str) -> bool {
    ast::attrs(node)
        .iter()
        .any(|a| ast::attr_name(a).as_deref() == Some(name))
}

pub(super) fn extract_valid_node_group(node: &SyntaxNode) -> Option<String> {
    let attr = ast::attrs(node)
        .into_iter()
        .find(|a| ast::attr_name(a).as_deref() == Some("node_group"))?;
    let s = attr.first_string_arg()?;
    let trimmed = s.trim();
    (!trimmed.is_empty()).then_some(s)
}

pub(super) fn record_item_node_group(
    module_path: &str,
    item: &ast::Item,
    node_groups: &mut IndexMap<String, String>,
) {
    let valid_target = matches!(
        item,
        ast::Item::Component(_)
            | ast::Item::Fn(_)
            | ast::Item::Timeline(_)
            | ast::Item::Fsm(_)
            | ast::Item::Task(_)
            | ast::Item::Table(_)
            | ast::Item::Curve(_)
            | ast::Item::Schedule(_)
            | ast::Item::Sys(_)
            | ast::Item::Rpc(_)
    );
    if !valid_target {
        return;
    }
    if let Some(group) = extract_valid_node_group(item.syntax()) {
        let name = item_short_name(item);
        node_groups.insert(format!("{module_path}::{name}"), group);
    }
}

pub(super) fn item_kind_name(item: &ast::Item) -> &'static str {
    match item {
        ast::Item::Module(_) => "module",
        ast::Item::Import(_) => "import",
        ast::Item::Const(_) => "const",
        ast::Item::Enum(_) => "enum",
        ast::Item::Struct(_) => "struct",
        ast::Item::Tag(_) => "tag",
        ast::Item::Component(_) => "component",
        ast::Item::Resource(_) => "resource",
        ast::Item::Event(_) => "event",
        ast::Item::Stream(_) => "stream",
        ast::Item::Relation(_) => "relation",
        ast::Item::SpatialGrid(_) => "spatial_grid",
        ast::Item::SpatialHistory(_) => "spatial_history",
        ast::Item::HashIndex(_) => "hash_index",
        ast::Item::Aspect(_) => "aspect",
        ast::Item::Prefab(_) => "prefab",
        ast::Item::Zone(_) => "zone",
        ast::Item::Table(_) => "table",
        ast::Item::Curve(_) => "curve",
        ast::Item::Timeline(_) => "timeline",
        ast::Item::Task(_) => "task",
        ast::Item::Fsm(_) => "fsm",
        ast::Item::Sys(_) => "sys",
        ast::Item::Obs(_) => "obs",
        ast::Item::Fn(_) => "fn",
        ast::Item::Migrate(_) => "migrate",
        ast::Item::Schedule(_) => "schedule",
        ast::Item::Object(_) => "object",
        ast::Item::SimTest(_) => "sim_test",
        ast::Item::NetSimTest(_) => "net_sim_test",
        ast::Item::Rpc(_) => "rpc",
        ast::Item::AssertLayout(_) => "assert_layout",
        ast::Item::AssertPar(_) => "assert_par",
    }
}

pub(super) fn item_short_name(item: &ast::Item) -> String {
    match item {
        ast::Item::Schedule(sc) => ast::child::<ast::Path>(sc.syntax())
            .map(|p| ast::path_text(&p))
            .unwrap_or_else(|| "Update".to_owned()),
        ast::Item::NetSimTest(nst) => nst.name().unwrap_or_else(|| "net_sim_test".to_owned()),
        _ => ast::first_ident(item.syntax())
            .map_or_else(|| item_kind_name(item).to_owned(), |t| t.text().to_owned()),
    }
}

pub(super) fn eval_cst_const_f64(node: &SyntaxNode) -> Option<f64> {
    match node.kind() {
        SyntaxKind::ParenExpr => node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .and_then(|c| eval_cst_const_f64(&c)),
        SyntaxKind::LiteralExpr => {
            for el in node.children_with_tokens() {
                if let Some(tok) = el.into_token() {
                    match tok.kind() {
                        SyntaxKind::FloatLit => {
                            let s = tok
                                .text()
                                .strip_suffix("_f64")
                                .or_else(|| tok.text().strip_suffix("_f32"))
                                .unwrap_or(tok.text());
                            let cleaned: String = s.chars().filter(|&c| c != '_').collect();
                            let v = cleaned.parse::<f64>().ok()?;
                            return v.is_finite().then_some(v);
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
                .and_then(|c| eval_cst_const_f64(&c))?;
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
            let l = eval_cst_const_f64(&exprs[0])?;
            let r = eval_cst_const_f64(&exprs[1])?;
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

pub(super) fn eval_cst_const_i64(node: &SyntaxNode) -> Option<i64> {
    match node.kind() {
        SyntaxKind::ParenExpr => node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .and_then(|c| eval_cst_const_i64(&c)),
        SyntaxKind::LiteralExpr => node
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .find(|t| t.kind() == SyntaxKind::IntLit)
            .and_then(|t| parse_int_lit_i64(t.text())),
        SyntaxKind::PrefixExpr => {
            let inner = node
                .children()
                .find(|c| is_expr_node(c.kind()))
                .and_then(|c| eval_cst_const_i64(&c))?;
            let is_neg = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Minus)
            });
            let is_plus = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Plus)
            });
            if is_neg {
                inner.checked_neg()
            } else if is_plus {
                Some(inner)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn is_quantizable_ty(ty: &Ty) -> bool {
    matches!(
        ty,
        Ty::U8
            | Ty::U16
            | Ty::U32
            | Ty::U64
            | Ty::I8
            | Ty::I16
            | Ty::I32
            | Ty::I64
            | Ty::F32
            | Ty::F64
            | Ty::Fix32
            | Ty::Fix64
            | Ty::UnitScalar { .. }
            | Ty::Vec2
            | Ty::Vec3
            | Ty::Vec3a
            | Ty::Vec4
            | Ty::IVec2
            | Ty::IVec3
            | Ty::UVec2
            | Ty::Quat
    )
}

pub(super) fn validate_all_attributes(
    file: &str,
    src: &str,
    sf: &SourceFile,
    diags: &mut Vec<Diagnostic>,
) {
    for item in sf.items() {
        let kind_name = item_kind_name(&item);
        let item_name = item_short_name(&item);
        let mut seen_node_group = false;
        let mut seen_net = false;
        let mut seen_net_rpc = false;
        let mut seen_authority = false;
        let mut seen_predicted = false;
        let mut seen_quantize = false;
        let mut authority_server_span: Option<strata_syntax::TextRange> = None;
        let mut predicted_span: Option<strata_syntax::TextRange> = None;

        for attr in ast::attrs(item.syntax()) {
            let Some(aname) = ast::attr_name(&attr) else {
                continue;
            };
            let attr_span = Span::from_range(file, src, attr.syntax().text_range());
            match aname.as_str() {
                "node_pure" => {
                    if !matches!(item, ast::Item::Fn(_)) {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            attr_span,
                            format!(
                                "@node_pure is only valid on `fn` declarations, not `{kind_name}`"
                            ),
                            None,
                        ));
                    } else if attr.arg_list().is_some() {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            attr_span,
                            "@node_pure does not accept arguments",
                            None,
                        ));
                    }
                }
                "node_group" => {
                    let valid_target = matches!(
                        item,
                        ast::Item::Component(_)
                            | ast::Item::Fn(_)
                            | ast::Item::Timeline(_)
                            | ast::Item::Fsm(_)
                            | ast::Item::Task(_)
                            | ast::Item::Table(_)
                            | ast::Item::Curve(_)
                            | ast::Item::Schedule(_)
                            | ast::Item::Sys(_)
                            | ast::Item::Rpc(_)
                    );
                    if !valid_target {
                        diags.push(Diagnostic::error(
                            codes::E0602_INVALID_NODE_GROUP,
                            attr_span,
                            format!("@node_group is not valid on `{kind_name}`"),
                            None,
                        ));
                    } else if seen_node_group {
                        diags.push(Diagnostic::error(
                            codes::E0602_INVALID_NODE_GROUP,
                            attr_span,
                            format!("duplicate @node_group attribute on `{item_name}`"),
                            None,
                        ));
                    } else {
                        seen_node_group = true;
                        validate_node_group_attr(file, src, &attr, diags);
                    }
                }
                "net" => {
                    if !matches!(item, ast::Item::Component(_) | ast::Item::Resource(_)) {
                        diags.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            attr_span,
                            format!(
                                "@net is only valid on `component` or `resource`, not `{kind_name}`"
                            ),
                            None,
                        ));
                    } else if seen_net {
                        diags.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            attr_span,
                            format!("duplicate @net attribute on `{item_name}`"),
                            None,
                        ));
                    } else {
                        seen_net = true;
                        let _ = parse_net_attr(file, src, &item_name, &attr, Some(diags));
                    }
                }
                "net_rpc" => {
                    if !matches!(item, ast::Item::Rpc(_) | ast::Item::Sys(_)) {
                        diags.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            attr_span,
                            format!("@net_rpc is only valid on `rpc` or `sys`, not `{kind_name}`"),
                            None,
                        ));
                    } else if seen_net_rpc {
                        diags.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            attr_span,
                            format!("duplicate @net_rpc attribute on `{item_name}`"),
                            None,
                        ));
                    } else {
                        seen_net_rpc = true;
                        let _ = parse_net_rpc_attr(file, src, &item_name, &attr, Some(diags));
                    }
                }
                "authority" => {
                    if !matches!(
                        item,
                        ast::Item::Component(_)
                            | ast::Item::Resource(_)
                            | ast::Item::Sys(_)
                            | ast::Item::Rpc(_)
                    ) {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!(
                                "@authority is only valid on `component`, `resource`, `sys`, or `rpc`, not `{kind_name}`"
                            ),
                            None,
                        ));
                    } else if seen_authority {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!("duplicate @authority attribute on `{item_name}`"),
                            None,
                        ));
                    } else {
                        seen_authority = true;
                        if let Some(auth) =
                            parse_authority_attr(file, src, &item_name, &attr, Some(diags))
                            && auth == AuthorityKind::Server
                        {
                            authority_server_span = Some(attr.syntax().text_range());
                        }
                    }
                }
                "predicted" => {
                    if !matches!(item, ast::Item::Component(_) | ast::Item::Sys(_)) {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!(
                                "@predicted is only valid on `component` or `sys`, not `{kind_name}`"
                            ),
                            None,
                        ));
                    } else if seen_predicted {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!("duplicate @predicted attribute on `{item_name}`"),
                            None,
                        ));
                    } else if attr.arg_list().is_some() {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!("@predicted on `{item_name}` does not accept arguments"),
                            None,
                        ));
                    } else {
                        seen_predicted = true;
                        predicted_span = Some(attr.syntax().text_range());
                    }
                }
                "quantize" => {
                    if let ast::Item::Component(ref comp) = item {
                        if seen_quantize {
                            diags.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                attr_span,
                                format!("duplicate @quantize attribute on `{item_name}`"),
                                None,
                            ));
                        } else {
                            seen_quantize = true;
                            let _ =
                                parse_quantize_attr(file, src, &item_name, "*", &attr, Some(diags));
                            let mut fields: Vec<ast::FieldDecl> = comp.fields();
                            for st in comp.strata() {
                                fields.extend(st.fields());
                            }
                            if fields.is_empty() {
                                diags.push(Diagnostic::error(
                                    codes::E0503_INVALID_QUANTIZE,
                                    attr_span,
                                    format!("@quantize on `{item_name}` requires at least one numeric or vector field"),
                                    None,
                                ));
                            } else {
                                for fd in fields {
                                    let fname = fd
                                        .name()
                                        .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
                                    let fty =
                                        fd.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
                                    if !is_quantizable_ty(&fty) {
                                        diags.push(Diagnostic::error(
                                            codes::E0503_INVALID_QUANTIZE,
                                            Span::from_range(file, src, fd.syntax().text_range()),
                                            format!(
                                                "@quantize on `{item_name}.{fname}` requires a numeric or vector field type, found `{}`",
                                                fty.canonical_tag()
                                            ),
                                            None,
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        diags.push(Diagnostic::error(
                            codes::E0503_INVALID_QUANTIZE,
                            attr_span,
                            format!(
                                "@quantize is only valid on component/struct/resource/rpc fields or components, not `{kind_name}`"
                            ),
                            None,
                        ));
                    }
                }
                _ => {}
            }
        }

        if let (Some(_), Some(pred_range)) = (authority_server_span, predicted_span) {
            diags.push(Diagnostic::error(
                codes::E0504_INVALID_AUTHORITY,
                Span::from_range(file, src, pred_range),
                format!("`{item_name}` cannot combine `@predicted` with `@authority(server)`"),
                None,
            ));
        }

        // Check nested FieldDecls inside the item.
        for fd in ast_field_scan::children_descendants_fields(item.syntax()) {
            let allow_quantize_parent = fd.syntax().parent().is_some_and(|p| {
                matches!(
                    p.kind(),
                    SyntaxKind::ComponentDecl
                        | SyntaxKind::StratumBlock
                        | SyntaxKind::RpcDecl
                        | SyntaxKind::StructDecl
                        | SyntaxKind::ResourceDecl
                )
            });
            let fname = fd
                .name()
                .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
            let fty = fd.type_node().map_or(Ty::Unknown, |n| parse_type_node(&n));
            let target_label = format!("{item_name}.{fname}");
            let mut seen_field_quantize = false;
            for attr in fd.attributes() {
                let Some(aname) = ast::attr_name(&attr) else {
                    continue;
                };
                let attr_span = Span::from_range(file, src, attr.syntax().text_range());
                match aname.as_str() {
                    "quantize" => {
                        if !allow_quantize_parent {
                            diags.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                attr_span,
                                format!("@quantize is not valid on field `{target_label}`"),
                                None,
                            ));
                        } else if seen_field_quantize {
                            diags.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                attr_span,
                                format!("duplicate @quantize attribute on `{target_label}`"),
                                None,
                            ));
                        } else {
                            seen_field_quantize = true;
                            let _ = parse_quantize_attr(
                                file,
                                src,
                                &target_label,
                                &fname,
                                &attr,
                                Some(diags),
                            );
                            if !is_quantizable_ty(&fty) {
                                diags.push(Diagnostic::error(
                                    codes::E0503_INVALID_QUANTIZE,
                                    Span::from_range(file, src, fd.syntax().text_range()),
                                    format!(
                                        "@quantize on `{target_label}` requires a numeric or vector field type, found `{}`",
                                        fty.canonical_tag()
                                    ),
                                    None,
                                ));
                            }
                        }
                    }
                    "node_pure" => {
                        diags.push(Diagnostic::error(
                            codes::E0601_NODE_PURE_VIOLATION,
                            attr_span,
                            "@node_pure is only valid on `fn` declarations, not `field`",
                            None,
                        ));
                    }
                    "node_group" => {
                        diags.push(Diagnostic::error(
                            codes::E0602_INVALID_NODE_GROUP,
                            attr_span,
                            "@node_group is not valid on `field`",
                            None,
                        ));
                    }
                    "net" | "net_rpc" => {
                        diags.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            attr_span,
                            format!("@{aname} is not valid on `field`"),
                            None,
                        ));
                    }
                    "authority" | "predicted" => {
                        diags.push(Diagnostic::error(
                            codes::E0504_INVALID_AUTHORITY,
                            attr_span,
                            format!("@{aname} is not valid on `field`"),
                            None,
                        ));
                    }
                    _ => {}
                }
            }
        }

        // Check nested blocks/statements (StratumBlock, StateDecl, TransitionDecl, SpawnExpr, InsertExpr)
        // for misplaced Phase 3 attributes.
        for desc in item.syntax().descendants() {
            if !matches!(
                desc.kind(),
                SyntaxKind::StratumBlock
                    | SyntaxKind::StateDecl
                    | SyntaxKind::TransitionDecl
                    | SyntaxKind::SpawnExpr
                    | SyntaxKind::InsertExpr
            ) {
                continue;
            }
            for attr in ast::attrs(&desc) {
                let Some(aname) = ast::attr_name(&attr) else {
                    continue;
                };
                let attr_span = Span::from_range(file, src, attr.syntax().text_range());
                match aname.as_str() {
                    "node_pure" => diags.push(Diagnostic::error(
                        codes::E0601_NODE_PURE_VIOLATION,
                        attr_span,
                        "@node_pure is only valid on `fn` declarations",
                        None,
                    )),
                    "node_group" => diags.push(Diagnostic::error(
                        codes::E0602_INVALID_NODE_GROUP,
                        attr_span,
                        "@node_group is not valid here",
                        None,
                    )),
                    "net" | "net_rpc" => diags.push(Diagnostic::error(
                        codes::E0502_INVALID_NET_ATTR,
                        attr_span,
                        format!("@{aname} is not valid here"),
                        None,
                    )),
                    "quantize" => diags.push(Diagnostic::error(
                        codes::E0503_INVALID_QUANTIZE,
                        attr_span,
                        "@quantize is not valid here",
                        None,
                    )),
                    "authority" | "predicted" => diags.push(Diagnostic::error(
                        codes::E0504_INVALID_AUTHORITY,
                        attr_span,
                        format!("@{aname} is not valid here"),
                        None,
                    )),
                    _ => {}
                }
            }
        }
    }
}

mod ast_field_scan {
    use strata_syntax::SyntaxNode;
    use strata_syntax::ast::{self, AstNode};

    pub(super) fn children_descendants_fields(node: &SyntaxNode) -> Vec<ast::FieldDecl> {
        node.descendants()
            .filter_map(ast::FieldDecl::cast)
            .collect()
    }
}

pub(super) fn validate_node_group_attr(
    file: &str,
    src: &str,
    attr: &ast::Attribute,
    diags: &mut Vec<Diagnostic>,
) {
    let attr_span = Span::from_range(file, src, attr.syntax().text_range());
    let Some(arg_list) = attr.arg_list() else {
        diags.push(Diagnostic::error(
            codes::E0602_INVALID_NODE_GROUP,
            attr_span,
            "@node_group requires a single non-empty string literal group name",
            None,
        ));
        return;
    };
    let args = arg_list.args();
    if args.len() != 1 {
        diags.push(Diagnostic::error(
            codes::E0602_INVALID_NODE_GROUP,
            attr_span,
            "@node_group requires a single non-empty string literal group name",
            None,
        ));
        return;
    }
    let arg = &args[0];
    if let Some(key) = arg.key()
        && key.text() != "name"
    {
        diags.push(Diagnostic::error(
            codes::E0602_INVALID_NODE_GROUP,
            Span::from_range(file, src, arg.syntax().text_range()),
            format!(
                "unknown @node_group argument `{}`; expected group string",
                key.text()
            ),
            None,
        ));
        return;
    }
    let is_str_lit = arg.value_expr().is_some_and(|e| {
        e.kind() == SyntaxKind::LiteralExpr
            && e.children_with_tokens()
                .filter_map(|el| el.into_token())
                .any(|tok| tok.kind() == SyntaxKind::StringLit)
    });
    if !is_str_lit {
        diags.push(Diagnostic::error(
            codes::E0602_INVALID_NODE_GROUP,
            Span::from_range(file, src, arg.syntax().text_range()),
            "@node_group group argument must be a string literal",
            None,
        ));
        return;
    }
    if let Some(val) = attr.first_string_arg()
        && val.trim().is_empty()
    {
        diags.push(Diagnostic::error(
            codes::E0602_INVALID_NODE_GROUP,
            Span::from_range(file, src, arg.syntax().text_range()),
            "@node_group group name cannot be empty",
            None,
        ));
    }
}

pub(super) enum RateUnitEval {
    Hz(f64),
    WrongUnit(String),
    NotUnitExpr,
}

pub(super) fn eval_cst_hz_expr(node: &SyntaxNode) -> RateUnitEval {
    match node.kind() {
        SyntaxKind::ParenExpr => node
            .children()
            .find(|c| is_expr_node(c.kind()))
            .map_or(RateUnitEval::NotUnitExpr, |c| eval_cst_hz_expr(&c)),
        SyntaxKind::LiteralExpr => {
            if let Some(tok) = node
                .children_with_tokens()
                .filter_map(|el| el.into_token())
                .find(|t| t.kind() == SyntaxKind::UnitLit)
                && let Some((stem, _, dim, _)) = Ty::split_unit_literal(tok.text())
            {
                if dim == UnitDim::HZ {
                    let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
                    if let Ok(v) = cleaned.parse::<f64>()
                        && v.is_finite()
                    {
                        return RateUnitEval::Hz(v);
                    }
                } else {
                    return RateUnitEval::WrongUnit(tok.text().to_owned());
                }
            }
            RateUnitEval::NotUnitExpr
        }
        SyntaxKind::PrefixExpr => {
            let Some(inner) = node.children().find(|c| is_expr_node(c.kind())) else {
                return RateUnitEval::NotUnitExpr;
            };
            let is_neg = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Minus)
            });
            let is_plus = node.children_with_tokens().any(|el| {
                el.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::Plus)
            });
            if !is_neg && !is_plus {
                return RateUnitEval::NotUnitExpr;
            }
            match eval_cst_hz_expr(&inner) {
                RateUnitEval::Hz(v) => RateUnitEval::Hz(if is_neg { -v } else { v }),
                other => other,
            }
        }
        _ => RateUnitEval::NotUnitExpr,
    }
}

pub(super) fn parse_net_attr(
    file: &str,
    src: &str,
    owner: &str,
    attr: &ast::Attribute,
    mut diags: Option<&mut Vec<Diagnostic>>,
) -> Option<HirNetConfig> {
    let attr_span = Span::from_range(file, src, attr.syntax().text_range());
    let Some(arg_list) = attr.arg_list() else {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0502_INVALID_NET_ATTR,
                attr_span,
                format!(
                    "@net on `{owner}` requires arguments (e.g. `@net(reliable, rate = 20Hz)`)"
                ),
                None,
            ));
        }
        return None;
    };
    let args = arg_list.args();
    if args.is_empty() {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0502_INVALID_NET_ATTR,
                attr_span,
                format!("@net on `{owner}` cannot be empty"),
                None,
            ));
        }
        return None;
    }

    let mut reliability: Option<NetReliability> = None;
    let mut rate_hz: Option<f64> = None;
    let mut interval_ticks: Option<u32> = None;
    let mut channel: u8 = 0;
    let mut seen_channel = false;

    for arg in &args {
        let arg_span = Span::from_range(file, src, arg.syntax().text_range());
        if let Some(key) = arg.key() {
            let k = key.text();
            match k {
                "reliability" => {
                    let v = arg.value_text();
                    let parsed = match v.as_str() {
                        "reliable" => Some(NetReliability::Reliable),
                        "unreliable" => Some(NetReliability::Unreliable),
                        _ => None,
                    };
                    match parsed {
                        Some(r) => {
                            if reliability.is_some() {
                                if let Some(d) = diags.as_deref_mut() {
                                    d.push(Diagnostic::error(
                                        codes::E0502_INVALID_NET_ATTR,
                                        arg_span,
                                        format!("duplicate reliability specification in @net on `{owner}`"),
                                        None,
                                    ));
                                }
                            } else {
                                reliability = Some(r);
                            }
                        }
                        None => {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("invalid @net reliability `{v}` on `{owner}`; expected `reliable` or `unreliable`"),
                                    None,
                                ));
                            }
                        }
                    }
                }
                "rate" => {
                    if rate_hz.is_some() {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("duplicate `rate` argument in @net on `{owner}`"),
                                None,
                            ));
                        }
                        continue;
                    }
                    let mut parsed_hz = None;
                    if let Some(ve) = arg.value_expr() {
                        match eval_cst_hz_expr(&ve) {
                            RateUnitEval::Hz(v) => parsed_hz = Some(v),
                            RateUnitEval::WrongUnit(txt) => {
                                if let Some(d) = diags.as_deref_mut() {
                                    d.push(Diagnostic::error(
                                        codes::E0502_INVALID_NET_ATTR,
                                        arg_span.clone(),
                                        format!("@net `rate` on `{owner}` requires Hz unit (e.g. `20Hz`), found `{txt}`"),
                                        None,
                                    ));
                                }
                                continue;
                            }
                            RateUnitEval::NotUnitExpr => {
                                parsed_hz = eval_cst_const_f64(&ve);
                            }
                        }
                    }
                    match parsed_hz {
                        Some(hz) if hz.is_finite() && hz > 0.0 => rate_hz = Some(hz),
                        _ => {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("@net `rate` on `{owner}` must be a positive frequency (e.g. `20Hz`)"),
                                    None,
                                ));
                            }
                        }
                    }
                }
                "interval" => {
                    if interval_ticks.is_some() {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("duplicate `interval` argument in @net on `{owner}`"),
                                None,
                            ));
                        }
                        continue;
                    }
                    let parsed = arg.value_expr().and_then(|e| eval_cst_const_i64(&e));
                    match parsed {
                        Some(iv) if iv >= 1 && iv <= u32::MAX as i64 => {
                            interval_ticks = Some(iv as u32);
                        }
                        _ => {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("@net `interval` on `{owner}` must be an integer >= 1"),
                                    None,
                                ));
                            }
                        }
                    }
                }
                "channel" => {
                    if seen_channel {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("duplicate `channel` argument in @net on `{owner}`"),
                                None,
                            ));
                        }
                        continue;
                    }
                    seen_channel = true;
                    let parsed = arg.value_expr().and_then(|e| eval_cst_const_i64(&e));
                    match parsed {
                        Some(ch) if (0..=255).contains(&ch) => channel = ch as u8,
                        _ => {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("@net `channel` on `{owner}` must be in 0..=255"),
                                    None,
                                ));
                            }
                        }
                    }
                }
                _ => {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            arg_span,
                            format!("unknown @net argument `{k}` on `{owner}`"),
                            None,
                        ));
                    }
                }
            }
        } else {
            let v = arg.value_text();
            match v.as_str() {
                "reliable" => {
                    if reliability.is_some() {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("conflicting/duplicate reliability in @net on `{owner}`"),
                                None,
                            ));
                        }
                    } else {
                        reliability = Some(NetReliability::Reliable);
                    }
                }
                "unreliable" => {
                    if reliability.is_some() {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("conflicting/duplicate reliability in @net on `{owner}`"),
                                None,
                            ));
                        }
                    } else {
                        reliability = Some(NetReliability::Unreliable);
                    }
                }
                _ => {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            arg_span,
                            format!("unexpected positional @net argument `{v}` on `{owner}`"),
                            None,
                        ));
                    }
                }
            }
        }
    }

    if rate_hz.is_some()
        && interval_ticks.is_some()
        && let Some(d) = diags
    {
        d.push(Diagnostic::error(
            codes::E0502_INVALID_NET_ATTR,
            attr_span,
            format!("@net on `{owner}` cannot specify both `rate` and `interval`"),
            None,
        ));
    }

    Some(HirNetConfig {
        reliability: reliability.unwrap_or(NetReliability::Reliable),
        rate_hz,
        interval_ticks,
        channel,
    })
}

pub(super) fn parse_quantize_attr(
    file: &str,
    src: &str,
    target_label: &str,
    field_name: &str,
    attr: &ast::Attribute,
    mut diags: Option<&mut Vec<Diagnostic>>,
) -> Option<HirQuantizeSpec> {
    let attr_span = Span::from_range(file, src, attr.syntax().text_range());
    let Some(arg_list) = attr.arg_list() else {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0503_INVALID_QUANTIZE,
                attr_span,
                format!(
                    "@quantize on `{target_label}` requires `min`, `max`, and `bits` arguments"
                ),
                None,
            ));
        }
        return None;
    };

    let mut min_val: Option<f64> = None;
    let mut max_val: Option<f64> = None;
    let mut bits_val: Option<u8> = None;
    let mut step_val: Option<f64> = None;
    let mut seen_min = false;
    let mut seen_max = false;
    let mut seen_bits = false;
    let mut seen_step = false;

    for arg in arg_list.args() {
        let arg_span = Span::from_range(file, src, arg.syntax().text_range());
        let Some(key) = arg.key() else {
            if let Some(d) = diags.as_deref_mut() {
                d.push(Diagnostic::error(
                    codes::E0503_INVALID_QUANTIZE,
                    arg_span,
                    format!("@quantize on `{target_label}` requires keyed arguments (`min = ...`, `max = ...`, `bits = ...`)"),
                    None,
                ));
            }
            continue;
        };
        match key.text() {
            "min" => {
                if seen_min {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0503_INVALID_QUANTIZE,
                            arg_span,
                            format!("duplicate `min` argument in @quantize on `{target_label}`"),
                            None,
                        ));
                    }
                    continue;
                }
                seen_min = true;
                match arg.value_expr().and_then(|e| eval_cst_const_f64(&e)) {
                    Some(v) => min_val = Some(v),
                    None => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                arg_span,
                                format!(
                                    "@quantize `min` on `{target_label}` must be a finite number"
                                ),
                                None,
                            ));
                        }
                    }
                }
            }
            "max" => {
                if seen_max {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0503_INVALID_QUANTIZE,
                            arg_span,
                            format!("duplicate `max` argument in @quantize on `{target_label}`"),
                            None,
                        ));
                    }
                    continue;
                }
                seen_max = true;
                match arg.value_expr().and_then(|e| eval_cst_const_f64(&e)) {
                    Some(v) => max_val = Some(v),
                    None => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                arg_span,
                                format!(
                                    "@quantize `max` on `{target_label}` must be a finite number"
                                ),
                                None,
                            ));
                        }
                    }
                }
            }
            "bits" => {
                if seen_bits {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0503_INVALID_QUANTIZE,
                            arg_span,
                            format!("duplicate `bits` argument in @quantize on `{target_label}`"),
                            None,
                        ));
                    }
                    continue;
                }
                seen_bits = true;
                match arg.value_expr().and_then(|e| eval_cst_const_i64(&e)) {
                    Some(b) if (1..=32).contains(&b) => bits_val = Some(b as u8),
                    Some(b) => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                arg_span,
                                format!("@quantize `bits` on `{target_label}` must be in 1..=32, found {b}"),
                                None,
                            ));
                        }
                    }
                    None => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                arg_span,
                                format!("@quantize `bits` on `{target_label}` must be an integer in 1..=32"),
                                None,
                            ));
                        }
                    }
                }
            }
            "step" => {
                if seen_step {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0503_INVALID_QUANTIZE,
                            arg_span,
                            format!("duplicate `step` argument in @quantize on `{target_label}`"),
                            None,
                        ));
                    }
                    continue;
                }
                seen_step = true;
                match arg.value_expr().and_then(|e| eval_cst_const_f64(&e)) {
                    Some(s) if s.is_finite() && s > 0.0 => step_val = Some(s),
                    _ => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0503_INVALID_QUANTIZE,
                                arg_span,
                                format!("@quantize `step` on `{target_label}` must be a finite number > 0.0"),
                                None,
                            ));
                        }
                    }
                }
            }
            other => {
                if let Some(d) = diags.as_deref_mut() {
                    d.push(Diagnostic::error(
                        codes::E0503_INVALID_QUANTIZE,
                        arg_span,
                        format!("unknown @quantize argument `{other}` on `{target_label}`"),
                        None,
                    ));
                }
            }
        }
    }

    if (min_val.is_none() || max_val.is_none() || bits_val.is_none())
        && let Some(d) = diags.as_deref_mut()
    {
        d.push(Diagnostic::error(
            codes::E0503_INVALID_QUANTIZE,
            attr_span.clone(),
            format!("@quantize on `{target_label}` requires `min`, `max`, and `bits`"),
            None,
        ));
    }

    if let (Some(min), Some(max)) = (min_val, max_val)
        && min >= max
    {
        if let Some(d) = diags {
            d.push(Diagnostic::error(
                codes::E0503_INVALID_QUANTIZE,
                attr_span,
                format!(
                    "@quantize range invalid on `{target_label}`: `min` ({min}) must be less than `max` ({max})"
                ),
                None,
            ));
        }
        return None;
    }

    Some(HirQuantizeSpec {
        field_name: field_name.to_owned(),
        min: min_val?,
        max: max_val?,
        bits: bits_val?,
        step: step_val,
    })
}

pub(super) fn parse_net_rpc_attr(
    file: &str,
    src: &str,
    owner: &str,
    attr: &ast::Attribute,
    mut diags: Option<&mut Vec<Diagnostic>>,
) -> Option<HirNetRpcMeta> {
    let attr_span = Span::from_range(file, src, attr.syntax().text_range());
    let Some(arg_list) = attr.arg_list() else {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0502_INVALID_NET_ATTR,
                attr_span,
                format!("@net_rpc on `{owner}` requires `direction = client_to_server | server_to_client | bidirectional`"),
                None,
            ));
        }
        return None;
    };

    let mut direction: Option<NetDirection> = None;
    let mut reliability: Option<NetReliability> = None;
    let mut channel: u8 = 0;
    let mut seen_channel = false;

    for arg in arg_list.args() {
        let arg_span = Span::from_range(file, src, arg.syntax().text_range());
        let key_str = arg.key().map(|k| k.text().to_owned());
        let val = arg.value_text();
        match key_str.as_deref() {
            Some("direction") => {
                let parsed = match val.as_str() {
                    "client_to_server" => Some(NetDirection::ClientToServer),
                    "server_to_client" => Some(NetDirection::ServerToClient),
                    "bidirectional" => Some(NetDirection::Bidirectional),
                    _ => None,
                };
                match parsed {
                    Some(dir) => {
                        if direction.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("duplicate `direction` in @net_rpc on `{owner}`"),
                                    None,
                                ));
                            }
                        } else {
                            direction = Some(dir);
                        }
                    }
                    None => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("invalid @net_rpc direction `{val}` on `{owner}`; expected `client_to_server`, `server_to_client`, or `bidirectional`"),
                                None,
                            ));
                        }
                    }
                }
            }
            Some("reliability") => {
                let parsed = match val.as_str() {
                    "reliable" => Some(NetReliability::Reliable),
                    "unreliable" => Some(NetReliability::Unreliable),
                    _ => None,
                };
                match parsed {
                    Some(rel) => {
                        if reliability.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!("duplicate `reliability` in @net_rpc on `{owner}`"),
                                    None,
                                ));
                            }
                        } else {
                            reliability = Some(rel);
                        }
                    }
                    None => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("invalid @net_rpc reliability `{val}` on `{owner}`; expected `reliable` or `unreliable`"),
                                None,
                            ));
                        }
                    }
                }
            }
            Some("channel") => {
                if seen_channel {
                    if let Some(d) = diags.as_deref_mut() {
                        d.push(Diagnostic::error(
                            codes::E0502_INVALID_NET_ATTR,
                            arg_span,
                            format!("duplicate `channel` in @net_rpc on `{owner}`"),
                            None,
                        ));
                    }
                    continue;
                }
                seen_channel = true;
                match arg.value_expr().and_then(|e| eval_cst_const_i64(&e)) {
                    Some(ch) if (0..=255).contains(&ch) => channel = ch as u8,
                    _ => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("@net_rpc `channel` on `{owner}` must be in 0..=255"),
                                None,
                            ));
                        }
                    }
                }
            }
            Some(other) => {
                if let Some(d) = diags.as_deref_mut() {
                    d.push(Diagnostic::error(
                        codes::E0502_INVALID_NET_ATTR,
                        arg_span,
                        format!("unknown @net_rpc argument `{other}` on `{owner}`"),
                        None,
                    ));
                }
            }
            None => {
                match val.as_str() {
                    "client_to_server" => {
                        if direction.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!(
                                        "conflicting/duplicate `direction` in @net_rpc on `{owner}`"
                                    ),
                                    None,
                                ));
                            }
                        } else {
                            direction = Some(NetDirection::ClientToServer);
                        }
                    }
                    "server_to_client" => {
                        if direction.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!(
                                        "conflicting/duplicate `direction` in @net_rpc on `{owner}`"
                                    ),
                                    None,
                                ));
                            }
                        } else {
                            direction = Some(NetDirection::ServerToClient);
                        }
                    }
                    "bidirectional" => {
                        if direction.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                    codes::E0502_INVALID_NET_ATTR,
                                    arg_span,
                                    format!(
                                        "conflicting/duplicate `direction` in @net_rpc on `{owner}`"
                                    ),
                                    None,
                                ));
                            }
                        } else {
                            direction = Some(NetDirection::Bidirectional);
                        }
                    }
                    "reliable" => {
                        if reliability.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("conflicting/duplicate `reliability` in @net_rpc on `{owner}`"),
                                None,
                            ));
                            }
                        } else {
                            reliability = Some(NetReliability::Reliable);
                        }
                    }
                    "unreliable" => {
                        if reliability.is_some() {
                            if let Some(d) = diags.as_deref_mut() {
                                d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("conflicting/duplicate `reliability` in @net_rpc on `{owner}`"),
                                None,
                            ));
                            }
                        } else {
                            reliability = Some(NetReliability::Unreliable);
                        }
                    }
                    other => {
                        if let Some(d) = diags.as_deref_mut() {
                            d.push(Diagnostic::error(
                                codes::E0502_INVALID_NET_ATTR,
                                arg_span,
                                format!("unexpected @net_rpc argument `{other}` on `{owner}`"),
                                None,
                            ));
                        }
                    }
                }
            }
        }
    }

    if direction.is_none() {
        if let Some(d) = diags {
            d.push(Diagnostic::error(
                codes::E0502_INVALID_NET_ATTR,
                attr_span,
                format!("@net_rpc on `{owner}` requires `direction` (`client_to_server`, `server_to_client`, or `bidirectional`)"),
                None,
            ));
        }
        return None;
    }

    Some(HirNetRpcMeta {
        direction: direction.unwrap_or(NetDirection::ClientToServer),
        reliability: reliability.unwrap_or(NetReliability::Reliable),
        channel,
    })
}

pub(super) fn parse_authority_attr(
    file: &str,
    src: &str,
    owner: &str,
    attr: &ast::Attribute,
    mut diags: Option<&mut Vec<Diagnostic>>,
) -> Option<AuthorityKind> {
    let attr_span = Span::from_range(file, src, attr.syntax().text_range());
    let Some(arg_list) = attr.arg_list() else {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0504_INVALID_AUTHORITY,
                attr_span,
                format!("@authority on `{owner}` requires one argument: `server`, `client`, `predicted`, or `shared`"),
                None,
            ));
        }
        return None;
    };
    let args = arg_list.args();
    if args.len() != 1 || args[0].key().is_some() {
        if let Some(d) = diags.as_deref_mut() {
            d.push(Diagnostic::error(
                codes::E0504_INVALID_AUTHORITY,
                attr_span,
                format!("@authority on `{owner}` expects a single positional argument (`server`, `client`, `predicted`, or `shared`)"),
                None,
            ));
        }
        return None;
    }
    let val = args[0].value_text();
    match val.as_str() {
        "server" => Some(AuthorityKind::Server),
        "client" => Some(AuthorityKind::Client),
        "predicted" => Some(AuthorityKind::Predicted),
        "shared" => Some(AuthorityKind::Shared),
        other => {
            if let Some(d) = diags {
                d.push(Diagnostic::error(
                    codes::E0504_INVALID_AUTHORITY,
                    Span::from_range(file, src, args[0].syntax().text_range()),
                    format!(
                        "@authority on `{owner}` has invalid authority `{other}`; expected `server`, `client`, `predicted`, or `shared`"
                    ),
                    None,
                ));
            }
            None
        }
    }
}

pub(super) fn extract_item_authority(node: &SyntaxNode) -> (AuthorityKind, bool) {
    let mut auth = AuthorityKind::Unspecified;
    let mut is_predicted = false;
    for attr in ast::attrs(node) {
        match ast::attr_name(&attr).as_deref() {
            Some("authority") => {
                if let Some(parsed) = parse_authority_attr("", "", "", &attr, None) {
                    auth = parsed;
                    if parsed == AuthorityKind::Predicted {
                        is_predicted = true;
                    }
                }
            }
            Some("predicted") => {
                is_predicted = true;
                if auth == AuthorityKind::Unspecified {
                    auth = AuthorityKind::Predicted;
                }
            }
            _ => {}
        }
    }
    (auth, is_predicted)
}

pub(super) fn extract_net_rpc_attr(node: &SyntaxNode) -> Option<HirNetRpcMeta> {
    ast::attrs(node)
        .into_iter()
        .find(|a| ast::attr_name(a).as_deref() == Some("net_rpc"))
        .and_then(|a| parse_net_rpc_attr("", "", "", &a, None))
}

pub(super) fn register_component_authority(
    module_path: &str,
    short: &str,
    comp: &ComponentDecl,
    auth: AuthorityKind,
    authorities: &mut IndexMap<String, AuthorityKind>,
) {
    authorities.insert(short.to_owned(), auth);
    authorities.insert(format!("{module_path}::{short}"), auth);
    for st in comp.strata() {
        let sname = st.stratum_name();
        authorities.insert(format!("{short}::{sname}"), auth);
        authorities.insert(format!("{module_path}::{short}::{sname}"), auth);
        if !st.is_hot() {
            authorities.insert(format!("{short}__{sname}"), auth);
            authorities.insert(format!("{module_path}::{short}__{sname}"), auth);
        }
    }
}

pub(super) fn collect_net_component_meta(
    module_path: &str,
    short: &str,
    node: &SyntaxNode,
    is_resource: bool,
    authority: AuthorityKind,
    is_predicted: bool,
) -> Option<NetComponentMeta> {
    let net_config = ast::attrs(node)
        .into_iter()
        .find(|a| ast::attr_name(a).as_deref() == Some("net"))
        .and_then(|a| parse_net_attr("", "", short, &a, None));
    let is_replicated = net_config.is_some();

    let mut quantized_fields = Vec::new();
    for attr in ast::attrs(node) {
        if ast::attr_name(&attr).as_deref() == Some("quantize")
            && let Some(spec) = parse_quantize_attr("", "", short, "*", &attr, None)
        {
            quantized_fields.push(spec);
        }
    }
    for fd in ast_field_scan::children_descendants_fields(node) {
        let fname = fd
            .name()
            .map_or_else(|| "_".to_owned(), |t| t.text().to_owned());
        for attr in fd.attributes() {
            if ast::attr_name(&attr).as_deref() == Some("quantize")
                && let Some(spec) = parse_quantize_attr("", "", short, &fname, &attr, None)
            {
                quantized_fields.push(spec);
            }
        }
    }

    if !is_replicated
        && quantized_fields.is_empty()
        && authority == AuthorityKind::Unspecified
        && !is_predicted
    {
        return None;
    }

    Some(NetComponentMeta {
        canonical_name: format!("{module_path}::{short}"),
        short_name: short.to_owned(),
        is_resource,
        is_replicated,
        net_config,
        authority,
        is_predicted,
        quantized_fields,
    })
}
