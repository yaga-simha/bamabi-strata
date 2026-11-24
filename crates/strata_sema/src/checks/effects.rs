//! System effects tracking, query collection, body lints, and static assertions.

use crate::access::{FilteredAccessSet, QueryAccessDesc, QueryTerm, system_conflicts};
use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::EffectsSpec;
use crate::hir_lower::{LowerEnv, classify_param_type, is_type_node, lower_proj_term};
use crate::layout::SolvedLayout;
use crate::types::Ty;
use indexmap::IndexMap;
use std::collections::HashSet;
use strata_syntax::ast::{self, AstNode};
use strata_syntax::{SyntaxKind, SyntaxNode};

pub(super) fn record_sys_param(param: &SyntaxNode, access: &mut FilteredAccessSet) {
    let Some(type_node) = param.children().find(|c| is_type_node(c.kind())) else {
        return;
    };
    let (kind, ty, _) = classify_param_type(&type_node);
    let target = match ty {
        Ty::Named(n) => n,
        _ => type_node
            .descendants()
            .find(|n| n.kind() == SyntaxKind::Path)
            .and_then(ast::Path::cast)
            .map(|p| ast::path_text(&p))
            .unwrap_or_else(|| type_node.text().to_string().trim().to_owned()),
    };
    match kind {
        crate::hir::HirParamKind::StreamIn => {
            access.stream_reads.insert(target);
        }
        crate::hir::HirParamKind::ResWrite => {
            access.res_writes.insert(target);
        }
        crate::hir::HirParamKind::ResRead => {
            access.res_reads.insert(target);
        }
        _ => {
            // Check direct Mut token fallback
            if type_node.kind() == SyntaxKind::RefType
                && type_node.children_with_tokens().any(|e| {
                    e.into_token()
                        .is_some_and(|t| t.kind() == SyntaxKind::KwMut)
                })
            {
                access.res_writes.insert(target);
            } else {
                access.res_reads.insert(target);
            }
        }
    }
}

pub(super) fn parse_effects(node: &SyntaxNode) -> EffectsSpec {
    let mut spec = EffectsSpec::default();
    for entry in ast::children::<ast::EffectEntry>(node) {
        let kind =
            ast::first_ident(entry.syntax()).map_or_else(String::new, |t| t.text().to_owned());
        let paths: Vec<String> = ast::children::<ast::Path>(entry.syntax())
            .map(|p| ast::path_text(&p))
            .collect();
        match kind.as_str() {
            "reads" => spec.reads.extend(paths),
            "writes" => spec.writes.extend(paths),
            "spawns" => spec.spawns.extend(paths),
            "despawns" => spec.despawns.extend(paths),
            "triggers" => spec.triggers.extend(paths),
            "emits" => spec.emits.extend(paths),
            _ => {}
        }
    }
    spec
}

pub(super) fn verify_effects(
    file: &str,
    src: &str,
    sys_name: &str,
    eff: &EffectsSpec,
    access: &FilteredAccessSet,
    body: &SyntaxNode,
    layouts: &IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let base_of = |key: &str| key.split("::").next().unwrap_or(key).to_owned();
    let allowed_writes: HashSet<String> = eff.writes.iter().cloned().collect();
    let allowed_reads: HashSet<String> =
        eff.reads.iter().chain(eff.writes.iter()).cloned().collect();

    for q in &access.queries {
        for term in &q.terms {
            let base = base_of(&term.storage_key);
            if term.mode.is_mutable() && !allowed_writes.contains(&base) {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_bytes(file, src, term.byte_start, term.byte_end),
                    format!(
                        "system `{sys_name}` mutates `{base}` which is missing from `effects(writes: [...])`"
                    ),
                    None,
                ));
            } else if term.mode.accesses_component_data() && !allowed_reads.contains(&base) {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_bytes(file, src, term.byte_start, term.byte_end),
                    format!(
                        "system `{sys_name}` reads `{base}` which is missing from `effects(reads: [...])`"
                    ),
                    None,
                ));
            }
        }
    }

    // Collect spawned components covered by `effects(spawns: [...])` including transitive `@require`s.
    let mut covered_spawns: HashSet<String> = eff.spawns.iter().cloned().collect();
    for sp in &eff.spawns {
        for (canon, layout) in layouts {
            if canon.ends_with(&format!("::{sp}")) || canon == sp {
                for req in &layout.required_components {
                    covered_spawns.insert(req.rsplit("::").next().unwrap_or(req).to_owned());
                }
            }
        }
    }

    for sp_node in body
        .descendants()
        .filter(|n| matches!(n.kind(), SyntaxKind::SpawnExpr | SyntaxKind::SpawnBatchExpr))
    {
        for ci in sp_node
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::CompInit)
        {
            if let Some(p) = ast::child::<ast::Path>(&ci) {
                let comp = ast::path_text(&p);
                if !covered_spawns.contains(&comp) {
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        Span::from_range(file, src, ci.text_range()),
                        format!(
                            "system `{sys_name}` spawns `{comp}` not covered by `effects(spawns: [...])`"
                        ),
                        None,
                    ));
                }
            }
        }
    }

    let allowed_despawns: HashSet<String> = eff.despawns.iter().cloned().collect();
    let allowed_triggers: HashSet<String> = eff.triggers.iter().cloned().collect();
    let allowed_emits: HashSet<String> = eff.emits.iter().cloned().collect();

    for dnode in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::DespawnAllExpr)
    {
        let filters: Vec<String> = dnode
            .children()
            .find(|c| c.kind() == SyntaxKind::GenericArgs)
            .map(|ga| {
                ga.children()
                    .filter(|c| c.kind() == SyntaxKind::TypeRef)
                    .map(|tr| tr.text().to_string().trim().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        if filters.is_empty() {
            if allowed_despawns.is_empty() {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_range(file, src, dnode.text_range()),
                    format!(
                        "system `{sys_name}` invokes `despawn_all` which is missing from `effects(despawns: [...])`"
                    ),
                    None,
                ));
            }
        } else {
            for f in filters {
                let comp = f
                    .strip_prefix("With<")
                    .or_else(|| f.strip_prefix("Without<"))
                    .or_else(|| f.strip_prefix("Changed<"))
                    .and_then(|s| s.strip_suffix('>'))
                    .map_or(f.as_str(), str::trim);
                if !allowed_despawns.contains(comp)
                    && !allowed_despawns.contains("Entity")
                    && !allowed_despawns.contains("*")
                {
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        Span::from_range(file, src, dnode.text_range()),
                        format!(
                            "system `{sys_name}` despawns `{comp}` not covered by `effects(despawns: [...])`"
                        ),
                        None,
                    ));
                }
            }
        }
    }

    for node in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::PostfixCallExpr)
    {
        let has_dot = node
            .children_with_tokens()
            .filter_map(|e| e.into_token())
            .any(|t| t.kind() == SyntaxKind::Dot);
        if has_dot {
            continue;
        }
        let Some(first_child) = node.first_child() else {
            continue;
        };
        if first_child.kind() != SyntaxKind::PathExpr {
            continue;
        }
        let callee = first_child.text().to_string().trim().to_owned();
        match callee.as_str() {
            "despawn" => {
                if allowed_despawns.is_empty() {
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        Span::from_range(file, src, node.text_range()),
                        format!(
                            "system `{sys_name}` calls `despawn` which is missing from `effects(despawns: [...])`"
                        ),
                        None,
                    ));
                }
            }
            "trigger" => {
                let ev_name = ast::child::<ast::ArgList>(&node).and_then(|al| {
                    let pos_args: Vec<_> = al
                        .syntax()
                        .children()
                        .filter(|c| {
                            !(c.kind() == SyntaxKind::FieldInit
                                && ast::first_ident(c).is_some_and(|t| t.text() == "propagate"))
                        })
                        .collect();
                    let ev_arg = if pos_args.len() >= 2 {
                        pos_args.get(1)
                    } else {
                        pos_args.first()
                    };
                    ev_arg
                        .and_then(|arg| {
                            if arg.kind() == SyntaxKind::StructLitExpr {
                                Some(arg.clone())
                            } else {
                                arg.descendants()
                                    .find(|d| d.kind() == SyntaxKind::StructLitExpr)
                            }
                        })
                        .and_then(|sl| sl.children().find(|c| c.kind() == SyntaxKind::PathExpr))
                        .map(|pe| pe.text().to_string().trim().to_owned())
                });
                let ok = match ev_name.as_deref() {
                    Some(ev) => allowed_triggers.contains(ev) || allowed_triggers.contains("*"),
                    None => !allowed_triggers.is_empty(),
                };
                if !ok {
                    let what = ev_name.as_deref().unwrap_or("event");
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        Span::from_range(file, src, node.text_range()),
                        format!(
                            "system `{sys_name}` triggers `{what}` not covered by `effects(triggers: [...])`"
                        ),
                        None,
                    ));
                }
            }
            "emit" => {
                let ev_name = ast::child::<ast::ArgList>(&node)
                    .and_then(|al| {
                        al.syntax()
                            .descendants()
                            .find(|d| d.kind() == SyntaxKind::StructLitExpr)
                    })
                    .and_then(|sl| sl.children().find(|c| c.kind() == SyntaxKind::PathExpr))
                    .map(|pe| pe.text().to_string().trim().to_owned());
                let ok = match ev_name.as_deref() {
                    Some(ev) => allowed_emits.contains(ev) || allowed_emits.contains("*"),
                    None => !allowed_emits.is_empty(),
                };
                if !ok {
                    let what = ev_name.as_deref().unwrap_or("event");
                    diags.push(Diagnostic::error(
                        codes::E0204_EFFECTS_MISMATCH,
                        Span::from_range(file, src, node.text_range()),
                        format!(
                            "system `{sys_name}` emits `{what}` not covered by `effects(emits: [...])`"
                        ),
                        None,
                    ));
                }
            }
            _ => {}
        }
    }
}

pub(super) fn collect_body_queries(
    body: &SyntaxNode,
    lower_env: &LowerEnv<'_>,
    access: &mut FilteredAccessSet,
) {
    // Find every PostfixCallExpr whose callee is `query` or `query_one`, plus chained `.with`/`.without`.
    for node in body.descendants() {
        if node.kind() != SyntaxKind::PostfixCallExpr {
            continue;
        }
        let Some(first_child) = node.first_child() else {
            continue;
        };
        if first_child.kind() == SyntaxKind::PathExpr {
            let callee = first_child.text().to_string().trim().to_owned();
            if callee == "emit"
                && let Some(arg_list) = ast::child::<ast::ArgList>(&node)
                && let Some(sl) = arg_list
                    .syntax()
                    .descendants()
                    .find(|n| n.kind() == SyntaxKind::StructLitExpr)
                && let Some(pe) = sl.children().find(|c| c.kind() == SyntaxKind::PathExpr)
            {
                access
                    .stream_writes
                    .insert(pe.text().to_string().trim().to_owned());
            }
            if matches!(callee.as_str(), "query" | "query_one") {
                let mut q = QueryAccessDesc {
                    is_point_lookup: callee == "query_one",
                    byte_start: u32::from(node.text_range().start()),
                    byte_end: u32::from(node.text_range().end()),
                    ..Default::default()
                };
                if let Some(ptl) = node
                    .descendants()
                    .find(|n| n.kind() == SyntaxKind::ProjTermList)
                {
                    for pt in ast::children::<ast::ProjTerm>(&ptl) {
                        if let Some(qt) = parse_proj_term(pt.syntax(), lower_env) {
                            q.terms.push(qt);
                        }
                    }
                }
                // Walk outer PostfixCallExpr chain checking direct `.method<T>()` tokens.
                let mut cur = node.parent();
                while let Some(p) = cur {
                    if p.kind() == SyntaxKind::PostfixCallExpr {
                        let method_name = p
                            .children_with_tokens()
                            .filter_map(|e| e.into_token())
                            .skip_while(|t| t.kind() != SyntaxKind::Dot)
                            .skip(1)
                            .find(|t| !t.kind().is_trivia())
                            .filter(|t| t.kind() == SyntaxKind::Ident)
                            .map(|t| t.text().to_owned());
                        if let Some(args) =
                            p.children().find(|c| c.kind() == SyntaxKind::GenericArgs)
                        {
                            let types: Vec<String> = args
                                .children()
                                .filter(|c| is_type_node(c.kind()))
                                .map(|t| t.text().to_string().trim().to_owned())
                                .collect();
                            let filters = if types.is_empty() {
                                vec![
                                    args.text()
                                        .to_string()
                                        .trim_matches(&['<', '>'][..])
                                        .trim()
                                        .to_owned(),
                                ]
                            } else {
                                types
                            };
                            match method_name.as_deref() {
                                Some("with") => q.with_filters.extend(filters),
                                Some("without") => q.without_filters.extend(filters),
                                Some("changed") => q.changed_filters.extend(filters),
                                _ => {}
                            }
                        } else if method_name.as_deref() == Some("changed") {
                            for t in &q.terms {
                                q.changed_filters.insert(t.storage_key.clone());
                            }
                        }
                        cur = p.parent();
                    } else {
                        break;
                    }
                }
                access.queries.push(q);
            }
        }
    }
}

pub(super) fn parse_proj_term(pt: &SyntaxNode, lower_env: &LowerEnv<'_>) -> Option<QueryTerm> {
    let ht = lower_proj_term(pt, lower_env)?;
    Some(QueryTerm {
        storage_key: ht.storage_key,
        field_name: ht.field_name,
        mode: ht.mode,
        byte_start: u32::from(pt.text_range().start()),
        byte_end: u32::from(pt.text_range().end()),
    })
}

pub(super) fn check_body_lints(
    file: &str,
    src: &str,
    sys_name: &str,
    body: &SyntaxNode,
    diags: &mut Vec<Diagnostic>,
) {
    // W0401: Nested `for ... in query(...)` inside another `for ... in query(...)` without spatial/.on
    for outer in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::ForExpr)
    {
        let outer_has_query = outer_for_uses_unindexed_query(&outer);
        if !outer_has_query {
            continue;
        }
        for inner in outer
            .descendants()
            .filter(|n| n != &outer && n.kind() == SyntaxKind::ForExpr)
        {
            if outer_for_uses_unindexed_query(&inner) {
                diags.push(Diagnostic::warning(
                    codes::W0401_QUADRATIC_NESTED_QUERY,
                    Span::from_range(file, src, inner.text_range()),
                    format!(
                        "nested `for ... in query(...)` in `{sys_name}` is O(N*M); use `spatial_grid`, `spatial_history`, or `hash_index`"
                    ),
                    None,
                ));
            }
        }
    }

    // W0403: `spawn { ... }` inside an integer range `for i in a..b` loop
    for loop_node in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::ForExpr)
    {
        let header = loop_node
            .children()
            .take_while(|c| c.kind() != SyntaxKind::Block)
            .map(|c| c.text().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        if header.contains("..")
            && loop_node
                .descendants()
                .any(|d| d.kind() == SyntaxKind::SpawnExpr)
        {
            diags.push(Diagnostic::warning(
                codes::W0403_USE_SPAWN_BATCH,
                Span::from_range(file, src, loop_node.text_range()),
                format!("`spawn` inside range loop in `{sys_name}`; prefer `spawn_batch(N)` (Slot 39, 2.66x faster)"),
                None,
            ));
        }
    }

    // W0402: `&mut` binding mutated strictly inside a single-branch `if` without `else`
    for for_node in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::ForExpr)
    {
        let Some(blk) = ast::child::<ast::Block>(&for_node) else {
            continue;
        };
        let header_txt: String = for_node
            .children()
            .take_while(|c| c.kind() != SyntaxKind::Block)
            .map(|c| c.text().to_string())
            .collect();
        if !header_txt.contains("&mut ") {
            continue;
        }
        let stmts: Vec<_> = blk.syntax().children().collect();
        if stmts.len() == 1
            && let Some(if_node) = stmts
                .first()
                .and_then(|s| s.descendants().find(|n| n.kind() == SyntaxKind::IfExpr))
            && !if_node.children_with_tokens().any(|t| {
                t.into_token()
                    .is_some_and(|tok| tok.kind() == SyntaxKind::KwElse)
            })
        {
            diags.push(Diagnostic::warning(
                codes::W0402_USE_SELECTIVE_MUT_TICK,
                Span::from_range(file, src, for_node.text_range()),
                format!(
                    "`{sys_name}` conditionally mutates `&mut` only inside `if`; prefer `&mut?` selective tick coalescing (Slots 14–15)"
                ),
                None,
            ));
        }
    }
}

pub(super) fn outer_for_uses_unindexed_query(for_node: &SyntaxNode) -> bool {
    let mut header = String::new();
    for ch in for_node.children() {
        if ch.kind() == SyntaxKind::Block || ch.kind() == SyntaxKind::ReduceClause {
            break;
        }
        header.push_str(&ch.text().to_string());
    }
    header.contains("query(")
        && !header.contains(".on(")
        && !header.contains("query_disc")
        && !header.contains("query_segment")
}

pub(super) fn evaluate_assert_layout(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    module_path: &str,
    layouts: &IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let Some(path) = ast::child::<ast::Path>(node) else {
        return;
    };
    let target = ast::path_text(&path);
    let canon_target = format!("{module_path}::{target}");
    let layout = layouts
        .get(&canon_target)
        .or_else(|| layouts.get(&target))
        .or_else(|| {
            layouts
                .iter()
                .find(|(k, _)| k.ends_with(&format!("::{target}")))
                .map(|(_, v)| v)
        });
    let Some(layout) = layout else {
        diags.push(Diagnostic::error(
            codes::E0105_ASSERT_LAYOUT_FAILED,
            Span::from_range(file, src, node.text_range()),
            format!("assert_layout target `{target}` not found"),
            None,
        ));
        return;
    };

    for expr in node
        .children()
        .filter(|c| c.kind() == SyntaxKind::BinaryExpr)
    {
        let txt = expr.text().to_string();
        let parts: Vec<_> = txt.split_whitespace().collect();
        if parts.len() == 3 {
            let lhs = match parts[0] {
                "size" => layout.size,
                "align" => layout.align,
                "padding" => layout.explicit_pad_bytes,
                _ => continue,
            };
            let Ok(rhs) = parts[2].parse::<usize>() else {
                continue;
            };
            let ok = match parts[1] {
                "==" => lhs == rhs,
                "<=" => lhs <= rhs,
                ">=" => lhs >= rhs,
                "<" => lhs < rhs,
                ">" => lhs > rhs,
                "!=" => lhs != rhs,
                _ => true,
            };
            if !ok {
                diags.push(Diagnostic::error(
                    codes::E0105_ASSERT_LAYOUT_FAILED,
                    Span::from_range(file, src, expr.text_range()),
                    format!("assert_layout({target}, {txt}) failed: actual {lhs}"),
                    None,
                ));
            }
        }
    }
}

pub(super) fn evaluate_assert_par(
    file: &str,
    src: &str,
    node: &SyntaxNode,
    systems: &[FilteredAccessSet],
    diags: &mut Vec<Diagnostic>,
) {
    let names: Vec<String> = ast::children::<ast::Path>(node)
        .map(|p| ast::path_text(&p))
        .collect();
    let mut resolved = Vec::new();
    for name in &names {
        if let Some(sys) = systems.iter().find(|s| &s.system_name == name) {
            resolved.push(sys);
        } else {
            diags.push(Diagnostic::error(
                codes::E0301_UNRESOLVED_SYMBOL,
                Span::from_range(file, src, node.text_range()),
                format!("assert_par references unknown system `{name}`"),
                None,
            ));
        }
    }
    for i in 0..resolved.len() {
        for j in (i + 1)..resolved.len() {
            let conflicts = system_conflicts(resolved[i], resolved[j]);
            if !conflicts.is_empty() {
                diags.push(Diagnostic::error(
                    codes::E0202_ASSERT_PAR_FAILED,
                    Span::from_range(file, src, node.text_range()),
                    format!(
                        "assert_par({}, {}) failed due to conflicting access on: {}",
                        resolved[i].system_name,
                        resolved[j].system_name,
                        conflicts.join(", ")
                    ),
                    None,
                ));
            }
        }
    }
}
