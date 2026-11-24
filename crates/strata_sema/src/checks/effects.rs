//! System effects tracking, query collection, body lints, and static assertions.

use crate::access::{
    FilteredAccessSet, QueryAccessDesc, QueryTerm, check_res_param_body_aliasing,
    same_resource_name, system_conflicts,
};
use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    EffectsSpec, HirCallable, HirExpr, HirFn, HirForIter, HirFsm, HirLValue, HirParamKind, HirStmt,
    HirTask, HirTimeline,
};
use crate::hir_lower::{LowerEnv, classify_param_type, is_type_node, lower_proj_term};
use crate::layout::SolvedLayout;
use crate::types::Ty;
use indexmap::IndexMap;
use std::collections::{BTreeSet, HashMap, HashSet};
use strata_syntax::TextRange;
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
    let start = u32::from(param.text_range().start());
    let end = u32::from(param.text_range().end());
    match kind {
        HirParamKind::StreamIn => {
            access.stream_reads.insert(target);
        }
        HirParamKind::ResWrite => {
            access.res_writes.insert(target.clone());
            access.res_param_borrows.push((target, true, start, end));
        }
        HirParamKind::ResRead => {
            access.res_reads.insert(target.clone());
            access.res_param_borrows.push((target, false, start, end));
        }
        HirParamKind::Trigger | HirParamKind::Ref | HirParamKind::RefMut | HirParamKind::Value => {
            let has_res = type_node.children_with_tokens().any(|e| {
                e.into_token()
                    .is_some_and(|t| t.kind() == SyntaxKind::KwRes)
            });
            if has_res {
                let is_mut = type_node.children_with_tokens().any(|e| {
                    e.into_token()
                        .is_some_and(|t| t.kind() == SyntaxKind::KwMut)
                });
                if is_mut {
                    access.res_writes.insert(target.clone());
                } else {
                    access.res_reads.insert(target.clone());
                }
                access.res_param_borrows.push((target, is_mut, start, end));
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

    // Parameter `&mut res R` borrows must be declared in `effects(writes: [...])`.
    for (rname, is_mut, sb, eb) in &access.res_param_borrows {
        if *is_mut {
            let rbase = rname.rsplit("::").next().unwrap_or(rname);
            if !allowed_writes.contains(rbase)
                && !allowed_writes.contains(rname.as_str())
                && !allowed_writes.contains("*")
            {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_bytes(file, src, *sb, *eb),
                    format!(
                        "system `{sys_name}` mutates resource `{rbase}` via `&mut res` parameter missing from `effects(writes: [...])`"
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
            "res_mut" | "server_res" | "client_res" => {
                if let Some(rname) = extract_first_generic_type_name(&node) {
                    let rbase = rname.rsplit("::").next().unwrap_or(&rname);
                    if !allowed_writes.contains(rbase)
                        && !allowed_writes.contains(&rname)
                        && !allowed_writes.contains("*")
                    {
                        diags.push(Diagnostic::error(
                            codes::E0204_EFFECTS_MISMATCH,
                            Span::from_range(file, src, node.text_range()),
                            format!(
                                "system `{sys_name}` calls `{callee}<{rbase}>()` which mutates resource `{rbase}` missing from `effects(writes: [...])`"
                            ),
                            None,
                        ));
                    }
                }
            }
            "insert_relation" | "remove_relation" => {
                if let Some(rel) = extract_first_generic_type_name(&node) {
                    let rbase = rel.rsplit("::").next().unwrap_or(&rel);
                    if !allowed_writes.contains(rbase)
                        && !allowed_writes.contains(&rel)
                        && !allowed_writes.contains("*")
                    {
                        diags.push(Diagnostic::error(
                            codes::E0204_EFFECTS_MISMATCH,
                            Span::from_range(file, src, node.text_range()),
                            format!(
                                "system `{sys_name}` calls `{callee}<{rbase}>` not covered by `effects(writes: [...])`"
                            ),
                            None,
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    // Check `insert(...)` / `insert @if_new(...)` against `effects(writes/spawns: [...])`.
    for inode in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::InsertExpr)
    {
        let comp = ast::child::<ast::ArgList>(&inode).and_then(|al| {
            let pos_args: Vec<_> = al
                .syntax()
                .children()
                .filter(|c| {
                    matches!(
                        c.kind(),
                        SyntaxKind::StructLitExpr
                            | SyntaxKind::PathExpr
                            | SyntaxKind::BundleLitExpr
                    )
                })
                .collect();
            let val_arg = pos_args.get(1).or_else(|| pos_args.first())?;
            if val_arg.kind() == SyntaxKind::StructLitExpr {
                val_arg
                    .children()
                    .find(|c| c.kind() == SyntaxKind::PathExpr)
                    .map(|pe| pe.text().to_string().trim().to_owned())
            } else {
                val_arg
                    .descendants()
                    .find(|d| d.kind() == SyntaxKind::StructLitExpr)
                    .and_then(|sl| sl.children().find(|c| c.kind() == SyntaxKind::PathExpr))
                    .map(|pe| pe.text().to_string().trim().to_owned())
            }
        });
        if let Some(comp) = comp {
            let cbase = comp.rsplit("::").next().unwrap_or(&comp);
            if !allowed_writes.contains(cbase)
                && !covered_spawns.contains(cbase)
                && !allowed_writes.contains("*")
            {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_range(file, src, inode.text_range()),
                    format!(
                        "system `{sys_name}` inserts `{cbase}` not covered by `effects(writes: [...])` or `effects(spawns: [...])`"
                    ),
                    None,
                ));
            }
        } else if allowed_writes.is_empty() && covered_spawns.is_empty() {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                Span::from_range(file, src, inode.text_range()),
                format!("system `{sys_name}` uses `insert(...)` without declaring `effects(writes: [...])`"),
                None,
            ));
        }
    }

    // Check `remove<Comp>(...)` against `effects(writes/despawns: [...])`.
    for rnode in body
        .descendants()
        .filter(|n| n.kind() == SyntaxKind::RemoveExpr)
    {
        if let Some(comp) = extract_first_generic_type_name(&rnode) {
            let cbase = comp.rsplit("::").next().unwrap_or(&comp);
            if !allowed_writes.contains(cbase)
                && !allowed_despawns.contains(cbase)
                && !allowed_writes.contains("*")
                && !allowed_despawns.contains("*")
            {
                diags.push(Diagnostic::error(
                    codes::E0204_EFFECTS_MISMATCH,
                    Span::from_range(file, src, rnode.text_range()),
                    format!(
                        "system `{sys_name}` removes `{cbase}` not covered by `effects(writes: [...])` or `effects(despawns: [...])`"
                    ),
                    None,
                ));
            }
        }
    }
}

fn extract_first_generic_type_name(node: &SyntaxNode) -> Option<String> {
    let ga = node
        .children()
        .find(|c| c.kind() == SyntaxKind::GenericArgs)
        .or_else(|| {
            node.first_child()
                .and_then(|fc| fc.children().find(|c| c.kind() == SyntaxKind::GenericArgs))
        })?;
    ga.children()
        .find(|c| is_type_node(c.kind()))
        .map(|tr| tr.text().to_string().trim().to_owned())
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
            if matches!(
                callee.as_str(),
                "res" | "res_mut" | "server_res" | "client_res"
            ) && let Some(rname) = extract_first_generic_type_name(&node)
            {
                let is_mut = matches!(callee.as_str(), "res_mut" | "server_res" | "client_res");
                let short = rname.rsplit("::").next().unwrap_or(&rname).to_owned();
                if is_mut {
                    access.res_writes.insert(short.clone());
                } else {
                    access.res_reads.insert(short.clone());
                }
                access.res_body_accesses.push((
                    short,
                    is_mut,
                    u32::from(node.text_range().start()),
                    u32::from(node.text_range().end()),
                ));
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

#[derive(Default, Clone)]
struct BodyEffectsSummary {
    res_reads: BTreeSet<String>,
    res_writes: BTreeSet<String>,
    comp_writes: BTreeSet<String>,
    spawns: BTreeSet<String>,
    despawns_any: bool,
    despawn_all_filters: BTreeSet<String>,
    triggers: BTreeSet<String>,
    emits: BTreeSet<String>,
    plays: BTreeSet<String>,
    callees: BTreeSet<String>,
}

impl BodyEffectsSummary {
    fn merge_effects_from(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for r in &other.res_reads {
            changed |= self.res_reads.insert(r.clone());
        }
        for r in &other.res_writes {
            changed |= self.res_writes.insert(r.clone());
        }
        for c in &other.comp_writes {
            changed |= self.comp_writes.insert(c.clone());
        }
        for s in &other.spawns {
            changed |= self.spawns.insert(s.clone());
        }
        if other.despawns_any && !self.despawns_any {
            self.despawns_any = true;
            changed = true;
        }
        for f in &other.despawn_all_filters {
            changed |= self.despawn_all_filters.insert(f.clone());
        }
        for t in &other.triggers {
            changed |= self.triggers.insert(t.clone());
        }
        for e in &other.emits {
            changed |= self.emits.insert(e.clone());
        }
        for p in &other.plays {
            changed |= self.plays.insert(p.clone());
        }
        changed
    }

    fn has_any_side_effect(&self) -> bool {
        !self.res_writes.is_empty()
            || !self.comp_writes.is_empty()
            || !self.spawns.is_empty()
            || self.despawns_any
            || !self.despawn_all_filters.is_empty()
            || !self.triggers.is_empty()
            || !self.emits.is_empty()
    }
}

fn short_name(s: &str) -> &str {
    s.rsplit("::").next().unwrap_or(s)
}

fn collect_effects_in_stmts(stmts: &[HirStmt], out: &mut BodyEffectsSummary) {
    for stmt in stmts {
        collect_effects_in_stmt(stmt, out);
    }
}

fn collect_effects_in_stmt(stmt: &HirStmt, out: &mut BodyEffectsSummary) {
    match stmt {
        HirStmt::Let {
            value, else_block, ..
        } => {
            collect_effects_in_expr(value, out);
            collect_effects_in_stmts(else_block, out);
        }
        HirStmt::Assign { target, value, .. } => {
            collect_effects_in_lvalue(target, out);
            collect_effects_in_expr(value, out);
        }
        HirStmt::Expr(e) | HirStmt::Wait(e) | HirStmt::WaitUntil(e) | HirStmt::RequireTrue(e) => {
            collect_effects_in_expr(e, out)
        }
        HirStmt::Return(Some(e)) | HirStmt::Break(Some(e)) => collect_effects_in_expr(e, out),
        HirStmt::Return(None) | HirStmt::Break(None) | HirStmt::Continue | HirStmt::YieldTick => {}
        HirStmt::While { cond, body } => {
            collect_effects_in_expr(cond, out);
            collect_effects_in_stmts(body, out);
        }
        HirStmt::Loop { body } => collect_effects_in_stmts(body, out),
        HirStmt::Atomic(at) => {
            collect_effects_in_stmts(&at.body, out);
            collect_effects_in_stmts(&at.on_rollback, out);
        }
        HirStmt::AbortIf { cond, cleanup } => {
            collect_effects_in_expr(cond, out);
            collect_effects_in_stmts(cleanup, out);
        }
        HirStmt::Race { branches } => {
            for br in branches {
                collect_effects_in_stmts(br, out);
            }
        }
        HirStmt::Trigger { target, event, .. } => {
            if let Some(t) = target {
                collect_effects_in_expr(t, out);
            }
            collect_effects_in_expr(event, out);
            if let Some(ev_name) = extract_struct_or_ty_name(event) {
                out.triggers.insert(ev_name);
            }
        }
        HirStmt::Emit(e) => {
            collect_effects_in_expr(e, out);
            if let Some(st_name) = extract_struct_or_ty_name(e) {
                out.emits.insert(st_name);
            }
        }
        HirStmt::Despawn(e) => {
            collect_effects_in_expr(e, out);
            out.despawns_any = true;
        }
        HirStmt::InsertRelation {
            relation,
            entity,
            target,
            payload,
        } => {
            out.comp_writes.insert(short_name(relation).to_owned());
            collect_effects_in_expr(entity, out);
            collect_effects_in_expr(target, out);
            if let Some(p) = payload {
                collect_effects_in_expr(p, out);
            }
        }
        HirStmt::RemoveRelation {
            relation,
            entity,
            target,
        } => {
            out.comp_writes.insert(short_name(relation).to_owned());
            collect_effects_in_expr(entity, out);
            collect_effects_in_expr(target, out);
        }
    }
}

fn collect_effects_in_lvalue(lv: &HirLValue, out: &mut BodyEffectsSummary) {
    match lv {
        HirLValue::Local { .. } => {}
        HirLValue::Field { base, .. } => collect_effects_in_lvalue(base, out),
        HirLValue::Index { base, index, .. } => {
            collect_effects_in_lvalue(base, out);
            collect_effects_in_expr(index, out);
        }
        HirLValue::ResourceAccess {
            resource,
            is_mut,
            client_id,
            ..
        } => {
            let short = short_name(resource).to_owned();
            if *is_mut {
                out.res_writes.insert(short);
            } else {
                out.res_reads.insert(short);
            }
            if let Some(cid) = client_id {
                collect_effects_in_expr(cid, out);
            }
        }
        HirLValue::Expr(e) => collect_effects_in_expr(e, out),
    }
}

fn extract_struct_or_ty_name(expr: &HirExpr) -> Option<String> {
    match expr {
        HirExpr::StructLit { name, .. } => Some(short_name(name).to_owned()),
        _ => match expr.ty() {
            Ty::Named(n) => Some(short_name(&n).to_owned()),
            _ => None,
        },
    }
}

fn collect_effects_in_expr(expr: &HirExpr, out: &mut BodyEffectsSummary) {
    match expr {
        HirExpr::Unary { expr: inner, .. } | HirExpr::Cast { expr: inner, .. } => {
            collect_effects_in_expr(inner, out);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            collect_effects_in_expr(lhs, out);
            collect_effects_in_expr(rhs, out);
        }
        HirExpr::Field { base, .. } => collect_effects_in_expr(base, out),
        HirExpr::Index { base, index, .. } => {
            collect_effects_in_expr(base, out);
            collect_effects_in_expr(index, out);
        }
        HirExpr::Call(c) => {
            if let Some(ref recv) = c.receiver {
                collect_effects_in_expr(recv, out);
            }
            for a in &c.args {
                collect_effects_in_expr(a, out);
            }
            if c.receiver.is_none() {
                match c.callee.as_str() {
                    "res" => {
                        if let Some(r) = c.generic_args.first() {
                            out.res_reads.insert(short_name(r).to_owned());
                        }
                    }
                    "res_mut" | "server_res" | "client_res" => {
                        if let Some(r) = c.generic_args.first() {
                            out.res_writes.insert(short_name(r).to_owned());
                        }
                    }
                    "play" => {
                        for a in &c.args {
                            if let Some(name) = match a {
                                HirExpr::Path { name, .. } | HirExpr::StructLit { name, .. } => {
                                    Some(short_name(name).to_owned())
                                }
                                _ => match a.ty() {
                                    Ty::Named(n) => Some(short_name(&n).to_owned()),
                                    _ => None,
                                },
                            } {
                                out.plays.insert(name);
                            }
                        }
                    }
                    "despawn" => out.despawns_any = true,
                    other => {
                        if let Some(prefix) = other.strip_suffix("::start") {
                            out.plays.insert(short_name(prefix).to_owned());
                        } else {
                            out.callees.insert(short_name(other).to_owned());
                        }
                    }
                }
            }
        }
        HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
            for (_, v) in fields {
                collect_effects_in_expr(v, out);
            }
        }
        HirExpr::BundleLit { components } => {
            for ci in components {
                out.spawns.insert(short_name(&ci.component).to_owned());
                for (_, v) in &ci.fields {
                    collect_effects_in_expr(v, out);
                }
            }
        }
        HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
            for e in elems {
                collect_effects_in_expr(e, out);
            }
        }
        HirExpr::Block { stmts, tail, .. } => {
            collect_effects_in_stmts(stmts, out);
            if let Some(t) = tail {
                collect_effects_in_expr(t, out);
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
            collect_effects_in_expr(cond, out);
            collect_effects_in_stmts(then_stmts, out);
            if let Some(t) = then_tail {
                collect_effects_in_expr(t, out);
            }
            collect_effects_in_stmts(else_stmts, out);
            if let Some(t) = else_tail {
                collect_effects_in_expr(t, out);
            }
        }
        HirExpr::Match(m) => {
            collect_effects_in_expr(&m.scrutinee, out);
            for arm in &m.arms {
                if let Some(ref g) = arm.guard {
                    collect_effects_in_expr(g, out);
                }
                collect_effects_in_expr(&arm.body, out);
            }
        }
        HirExpr::For(f) => {
            match &f.iter {
                HirForIter::Query(q) => {
                    if let Some(ref wp) = q.where_pred {
                        collect_effects_in_expr(wp, out);
                    }
                    if let Some(ref ot) = q.on_target {
                        collect_effects_in_expr(ot, out);
                    }
                }
                HirForIter::Range { start, end, .. } => {
                    collect_effects_in_expr(start, out);
                    collect_effects_in_expr(end, out);
                }
                HirForIter::SpatialDisc { center, radius, .. } => {
                    collect_effects_in_expr(center, out);
                    collect_effects_in_expr(radius, out);
                }
                HirForIter::SpatialSegmentAt {
                    tick,
                    p0,
                    p1,
                    radius,
                    ..
                } => {
                    collect_effects_in_expr(tick, out);
                    collect_effects_in_expr(p0, out);
                    collect_effects_in_expr(p1, out);
                    if let Some(r) = radius {
                        collect_effects_in_expr(r, out);
                    }
                }
                HirForIter::Expr(e) => collect_effects_in_expr(e, out),
            }
            collect_effects_in_stmts(&f.body, out);
            for r in &f.reduce {
                collect_effects_in_expr(&r.identity, out);
                collect_effects_in_expr(&r.value, out);
            }
        }
        HirExpr::Spawn(sp) => {
            if let Some(ref cnt) = sp.count {
                collect_effects_in_expr(cnt, out);
            }
            collect_effects_in_stmts(&sp.preamble, out);
            for ci in &sp.components {
                out.spawns.insert(short_name(&ci.component).to_owned());
                for (_, v) in &ci.fields {
                    collect_effects_in_expr(v, out);
                }
            }
        }
        HirExpr::DespawnAll { filters } => {
            for f in filters {
                let comp = f
                    .strip_prefix("With<")
                    .or_else(|| f.strip_prefix("Without<"))
                    .or_else(|| f.strip_prefix("Changed<"))
                    .and_then(|s| s.strip_suffix('>'))
                    .map_or(f.as_str(), str::trim);
                out.despawn_all_filters.insert(short_name(comp).to_owned());
            }
        }
        HirExpr::Insert { entity, value, .. } => {
            collect_effects_in_expr(entity, out);
            collect_effects_in_expr(value, out);
            if let Some(comp) = extract_struct_or_ty_name(value) {
                out.comp_writes.insert(comp);
            }
        }
        HirExpr::Remove { component, entity } => {
            out.comp_writes.insert(short_name(component).to_owned());
            collect_effects_in_expr(entity, out);
        }
        HirExpr::Query(q) => {
            if let Some(ref wp) = q.where_pred {
                collect_effects_in_expr(wp, out);
            }
            if let Some(ref ot) = q.on_target {
                collect_effects_in_expr(ot, out);
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

fn check_par_read_only_stmts(
    stmts: &[HirStmt],
    sys_name: &str,
    span: &Span,
    total_queries: &mut usize,
    ro_queries: &mut usize,
    diags: &mut Vec<Diagnostic>,
) {
    for stmt in stmts {
        match stmt {
            HirStmt::Let {
                value, else_block, ..
            } => {
                check_par_read_only_expr(value, sys_name, span, total_queries, ro_queries, diags);
                check_par_read_only_stmts(
                    else_block,
                    sys_name,
                    span,
                    total_queries,
                    ro_queries,
                    diags,
                );
            }
            HirStmt::Assign { value, .. }
            | HirStmt::Expr(value)
            | HirStmt::Wait(value)
            | HirStmt::WaitUntil(value)
            | HirStmt::RequireTrue(value)
            | HirStmt::Emit(value)
            | HirStmt::Despawn(value)
            | HirStmt::Return(Some(value))
            | HirStmt::Break(Some(value)) => {
                check_par_read_only_expr(value, sys_name, span, total_queries, ro_queries, diags);
            }
            HirStmt::Return(None)
            | HirStmt::Break(None)
            | HirStmt::Continue
            | HirStmt::YieldTick => {}
            HirStmt::While { cond, body }
            | HirStmt::AbortIf {
                cond,
                cleanup: body,
            } => {
                check_par_read_only_expr(cond, sys_name, span, total_queries, ro_queries, diags);
                check_par_read_only_stmts(body, sys_name, span, total_queries, ro_queries, diags);
            }
            HirStmt::Loop { body } => {
                check_par_read_only_stmts(body, sys_name, span, total_queries, ro_queries, diags);
            }
            HirStmt::Atomic(at) => {
                check_par_read_only_stmts(
                    &at.body,
                    sys_name,
                    span,
                    total_queries,
                    ro_queries,
                    diags,
                );
                check_par_read_only_stmts(
                    &at.on_rollback,
                    sys_name,
                    span,
                    total_queries,
                    ro_queries,
                    diags,
                );
            }
            HirStmt::Race { branches } => {
                for br in branches {
                    check_par_read_only_stmts(br, sys_name, span, total_queries, ro_queries, diags);
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    check_par_read_only_expr(t, sys_name, span, total_queries, ro_queries, diags);
                }
                check_par_read_only_expr(event, sys_name, span, total_queries, ro_queries, diags);
            }
            HirStmt::InsertRelation {
                entity,
                target,
                payload,
                ..
            } => {
                check_par_read_only_expr(entity, sys_name, span, total_queries, ro_queries, diags);
                check_par_read_only_expr(target, sys_name, span, total_queries, ro_queries, diags);
                if let Some(p) = payload {
                    check_par_read_only_expr(p, sys_name, span, total_queries, ro_queries, diags);
                }
            }
            HirStmt::RemoveRelation { entity, target, .. } => {
                check_par_read_only_expr(entity, sys_name, span, total_queries, ro_queries, diags);
                check_par_read_only_expr(target, sys_name, span, total_queries, ro_queries, diags);
            }
        }
    }
}

fn check_par_read_only_expr(
    expr: &HirExpr,
    sys_name: &str,
    span: &Span,
    total_queries: &mut usize,
    ro_queries: &mut usize,
    diags: &mut Vec<Diagnostic>,
) {
    match expr {
        HirExpr::Unary { expr: inner, .. } | HirExpr::Cast { expr: inner, .. } => {
            check_par_read_only_expr(inner, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            check_par_read_only_expr(lhs, sys_name, span, total_queries, ro_queries, diags);
            check_par_read_only_expr(rhs, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Field { base, .. } => {
            check_par_read_only_expr(base, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Index { base, index, .. } => {
            check_par_read_only_expr(base, sys_name, span, total_queries, ro_queries, diags);
            check_par_read_only_expr(index, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Call(c) => {
            if let Some(ref recv) = c.receiver {
                check_par_read_only_expr(recv, sys_name, span, total_queries, ro_queries, diags);
            }
            for a in &c.args {
                check_par_read_only_expr(a, sys_name, span, total_queries, ro_queries, diags);
            }
        }
        HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
            for (_, v) in fields {
                check_par_read_only_expr(v, sys_name, span, total_queries, ro_queries, diags);
            }
        }
        HirExpr::BundleLit { components } => {
            for ci in components {
                for (_, v) in &ci.fields {
                    check_par_read_only_expr(v, sys_name, span, total_queries, ro_queries, diags);
                }
            }
        }
        HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
            for e in elems {
                check_par_read_only_expr(e, sys_name, span, total_queries, ro_queries, diags);
            }
        }
        HirExpr::Block { stmts, tail, .. } => {
            check_par_read_only_stmts(stmts, sys_name, span, total_queries, ro_queries, diags);
            if let Some(t) = tail {
                check_par_read_only_expr(t, sys_name, span, total_queries, ro_queries, diags);
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
            check_par_read_only_expr(cond, sys_name, span, total_queries, ro_queries, diags);
            check_par_read_only_stmts(then_stmts, sys_name, span, total_queries, ro_queries, diags);
            if let Some(t) = then_tail {
                check_par_read_only_expr(t, sys_name, span, total_queries, ro_queries, diags);
            }
            check_par_read_only_stmts(else_stmts, sys_name, span, total_queries, ro_queries, diags);
            if let Some(t) = else_tail {
                check_par_read_only_expr(t, sys_name, span, total_queries, ro_queries, diags);
            }
        }
        HirExpr::Match(m) => {
            check_par_read_only_expr(
                &m.scrutinee,
                sys_name,
                span,
                total_queries,
                ro_queries,
                diags,
            );
            for arm in &m.arms {
                if let Some(ref g) = arm.guard {
                    check_par_read_only_expr(g, sys_name, span, total_queries, ro_queries, diags);
                }
                check_par_read_only_expr(
                    &arm.body,
                    sys_name,
                    span,
                    total_queries,
                    ro_queries,
                    diags,
                );
            }
        }
        HirExpr::For(f) => {
            if let HirForIter::Query(q) = &f.iter {
                *total_queries += 1;
                let has_mut = q.terms.iter().any(|t| t.mode.is_mutable());
                if !has_mut {
                    *ro_queries += 1;
                }
                if !f.reduce.is_empty() && has_mut {
                    diags.push(Diagnostic::error(
                        codes::E0202_ASSERT_PAR_FAILED,
                        span.clone(),
                        format!(
                            "`@par(read_only)` reduce query in `{sys_name}` cannot borrow `&mut` / `&mut?` component terms"
                        ),
                        None,
                    ));
                }
            }
            check_par_read_only_stmts(&f.body, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Spawn(sp) => {
            check_par_read_only_stmts(
                &sp.preamble,
                sys_name,
                span,
                total_queries,
                ro_queries,
                diags,
            );
        }
        HirExpr::Insert { entity, value, .. } => {
            check_par_read_only_expr(entity, sys_name, span, total_queries, ro_queries, diags);
            check_par_read_only_expr(value, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::Remove { entity, .. } => {
            check_par_read_only_expr(entity, sys_name, span, total_queries, ro_queries, diags);
        }
        HirExpr::IntLit { .. }
        | HirExpr::FloatLit { .. }
        | HirExpr::BoolLit(_)
        | HirExpr::StringLit(_)
        | HirExpr::CharLit(_)
        | HirExpr::Path { .. }
        | HirExpr::Query(_)
        | HirExpr::DespawnAll { .. } => {}
    }
}

fn check_call_arg_res_aliasing_stmts(
    stmts: &[HirStmt],
    item_name: &str,
    param_res: &HashMap<String, (String, bool)>,
    span: &Span,
    diags: &mut Vec<Diagnostic>,
) {
    for stmt in stmts {
        match stmt {
            HirStmt::Let {
                value, else_block, ..
            } => {
                check_call_arg_res_aliasing_expr(value, item_name, param_res, span, diags);
                check_call_arg_res_aliasing_stmts(else_block, item_name, param_res, span, diags);
            }
            HirStmt::Assign { value, .. }
            | HirStmt::Expr(value)
            | HirStmt::Wait(value)
            | HirStmt::WaitUntil(value)
            | HirStmt::RequireTrue(value)
            | HirStmt::Emit(value)
            | HirStmt::Despawn(value)
            | HirStmt::Return(Some(value))
            | HirStmt::Break(Some(value)) => {
                check_call_arg_res_aliasing_expr(value, item_name, param_res, span, diags);
            }
            HirStmt::Return(None)
            | HirStmt::Break(None)
            | HirStmt::Continue
            | HirStmt::YieldTick => {}
            HirStmt::While { cond, body }
            | HirStmt::AbortIf {
                cond,
                cleanup: body,
            } => {
                check_call_arg_res_aliasing_expr(cond, item_name, param_res, span, diags);
                check_call_arg_res_aliasing_stmts(body, item_name, param_res, span, diags);
            }
            HirStmt::Loop { body } => {
                check_call_arg_res_aliasing_stmts(body, item_name, param_res, span, diags);
            }
            HirStmt::Atomic(at) => {
                check_call_arg_res_aliasing_stmts(&at.body, item_name, param_res, span, diags);
                check_call_arg_res_aliasing_stmts(
                    &at.on_rollback,
                    item_name,
                    param_res,
                    span,
                    diags,
                );
            }
            HirStmt::Race { branches } => {
                for br in branches {
                    check_call_arg_res_aliasing_stmts(br, item_name, param_res, span, diags);
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    check_call_arg_res_aliasing_expr(t, item_name, param_res, span, diags);
                }
                check_call_arg_res_aliasing_expr(event, item_name, param_res, span, diags);
            }
            HirStmt::InsertRelation {
                entity,
                target,
                payload,
                ..
            } => {
                check_call_arg_res_aliasing_expr(entity, item_name, param_res, span, diags);
                check_call_arg_res_aliasing_expr(target, item_name, param_res, span, diags);
                if let Some(p) = payload {
                    check_call_arg_res_aliasing_expr(p, item_name, param_res, span, diags);
                }
            }
            HirStmt::RemoveRelation { entity, target, .. } => {
                check_call_arg_res_aliasing_expr(entity, item_name, param_res, span, diags);
                check_call_arg_res_aliasing_expr(target, item_name, param_res, span, diags);
            }
        }
    }
}

fn direct_arg_res_borrow(
    expr: &HirExpr,
    param_res: &HashMap<String, (String, bool)>,
) -> Option<(String, bool)> {
    match expr {
        HirExpr::Call(c)
            if c.receiver.is_none()
                && matches!(
                    c.callee.as_str(),
                    "res" | "res_mut" | "server_res" | "client_res"
                ) =>
        {
            let r = c.generic_args.first()?;
            Some((
                short_name(r).to_owned(),
                matches!(c.callee.as_str(), "res_mut" | "server_res" | "client_res"),
            ))
        }
        HirExpr::Path { name, .. } => param_res.get(name).cloned(),
        HirExpr::Unary { expr: inner, .. } => direct_arg_res_borrow(inner, param_res),
        _ => None,
    }
}

fn check_call_arg_res_aliasing_expr(
    expr: &HirExpr,
    item_name: &str,
    param_res: &HashMap<String, (String, bool)>,
    span: &Span,
    diags: &mut Vec<Diagnostic>,
) {
    match expr {
        HirExpr::Call(c) => {
            if let Some(ref recv) = c.receiver {
                check_call_arg_res_aliasing_expr(recv, item_name, param_res, span, diags);
            }
            let borrows: Vec<(String, bool)> = c
                .args
                .iter()
                .filter_map(|a| direct_arg_res_borrow(a, param_res))
                .collect();
            for i in 0..borrows.len() {
                for j in (i + 1)..borrows.len() {
                    if same_resource_name(&borrows[i].0, &borrows[j].0)
                        && (borrows[i].1 || borrows[j].1)
                    {
                        diags.push(Diagnostic::error(
                            codes::E0201_ALIASING_CONFLICT,
                            span.clone(),
                            format!(
                                "singleton resource aliasing conflict in `{item_name}`: call to `{}` aliases `{}` mutably across arguments",
                                c.callee, borrows[j].0
                            ),
                            None,
                        ));
                    }
                }
            }
            for a in &c.args {
                check_call_arg_res_aliasing_expr(a, item_name, param_res, span, diags);
            }
        }
        HirExpr::Unary { expr: inner, .. } | HirExpr::Cast { expr: inner, .. } => {
            check_call_arg_res_aliasing_expr(inner, item_name, param_res, span, diags);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            check_call_arg_res_aliasing_expr(lhs, item_name, param_res, span, diags);
            check_call_arg_res_aliasing_expr(rhs, item_name, param_res, span, diags);
        }
        HirExpr::Field { base, .. } => {
            check_call_arg_res_aliasing_expr(base, item_name, param_res, span, diags);
        }
        HirExpr::Index { base, index, .. } => {
            check_call_arg_res_aliasing_expr(base, item_name, param_res, span, diags);
            check_call_arg_res_aliasing_expr(index, item_name, param_res, span, diags);
        }
        HirExpr::StructLit { fields, .. } | HirExpr::RecordLit { fields, .. } => {
            for (_, v) in fields {
                check_call_arg_res_aliasing_expr(v, item_name, param_res, span, diags);
            }
        }
        HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
            for e in elems {
                check_call_arg_res_aliasing_expr(e, item_name, param_res, span, diags);
            }
        }
        HirExpr::Block { stmts, tail, .. } => {
            check_call_arg_res_aliasing_stmts(stmts, item_name, param_res, span, diags);
            if let Some(t) = tail {
                check_call_arg_res_aliasing_expr(t, item_name, param_res, span, diags);
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
            check_call_arg_res_aliasing_expr(cond, item_name, param_res, span, diags);
            check_call_arg_res_aliasing_stmts(then_stmts, item_name, param_res, span, diags);
            if let Some(t) = then_tail {
                check_call_arg_res_aliasing_expr(t, item_name, param_res, span, diags);
            }
            check_call_arg_res_aliasing_stmts(else_stmts, item_name, param_res, span, diags);
            if let Some(t) = else_tail {
                check_call_arg_res_aliasing_expr(t, item_name, param_res, span, diags);
            }
        }
        HirExpr::Match(m) => {
            check_call_arg_res_aliasing_expr(&m.scrutinee, item_name, param_res, span, diags);
            for arm in &m.arms {
                check_call_arg_res_aliasing_expr(&arm.body, item_name, param_res, span, diags);
            }
        }
        HirExpr::For(f) => {
            check_call_arg_res_aliasing_stmts(&f.body, item_name, param_res, span, diags);
        }
        _ => {}
    }
}

fn check_summary_against_effects(
    sys_name: &str,
    span: &Span,
    summary: &BodyEffectsSummary,
    eff: &EffectsSpec,
    layouts: &IndexMap<String, SolvedLayout>,
    target_summaries: &HashMap<String, BodyEffectsSummary>,
    diags: &mut Vec<Diagnostic>,
) {
    let allowed_writes: HashSet<&str> = eff.writes.iter().map(String::as_str).collect();
    let allowed_despawns: HashSet<&str> = eff.despawns.iter().map(String::as_str).collect();
    let allowed_triggers: HashSet<&str> = eff.triggers.iter().map(String::as_str).collect();
    let allowed_emits: HashSet<&str> = eff.emits.iter().map(String::as_str).collect();
    let mut covered_spawns: HashSet<String> = eff.spawns.iter().cloned().collect();
    for sp in &eff.spawns {
        for (canon, layout) in layouts {
            if canon.ends_with(&format!("::{sp}")) || canon == sp {
                for req in &layout.required_components {
                    covered_spawns.insert(short_name(req).to_owned());
                }
            }
        }
    }

    for r in &summary.res_writes {
        if !allowed_writes.contains(r.as_str()) && !allowed_writes.contains("*") {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively mutates resource `{r}` missing from `effects(writes: [...])`"
                ),
                None,
            ));
        }
    }
    for c in &summary.comp_writes {
        if !allowed_writes.contains(c.as_str()) && !allowed_writes.contains("*") {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively writes `{c}` missing from `effects(writes: [...])`"
                ),
                None,
            ));
        }
    }
    for s in &summary.spawns {
        if !covered_spawns.contains(s.as_str()) {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively spawns `{s}` missing from `effects(spawns: [...])`"
                ),
                None,
            ));
        }
    }
    if summary.despawns_any && allowed_despawns.is_empty() {
        diags.push(Diagnostic::error(
            codes::E0204_EFFECTS_MISMATCH,
            span.clone(),
            format!(
                "system `{sys_name}` transitively despawns entities missing from `effects(despawns: [...])`"
            ),
            None,
        ));
    }
    for f in &summary.despawn_all_filters {
        if !allowed_despawns.contains(f.as_str())
            && !allowed_despawns.contains("Entity")
            && !allowed_despawns.contains("*")
        {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively despawns `{f}` missing from `effects(despawns: [...])`"
                ),
                None,
            ));
        }
    }
    for ev in &summary.triggers {
        if !allowed_triggers.contains(ev.as_str()) && !allowed_triggers.contains("*") {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively triggers `{ev}` missing from `effects(triggers: [...])`"
                ),
                None,
            ));
        }
    }
    for st in &summary.emits {
        if !allowed_emits.contains(st.as_str()) && !allowed_emits.contains("*") {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` transitively emits `{st}` missing from `effects(emits: [...])`"
                ),
                None,
            ));
        }
    }
    for pl in &summary.plays {
        let target_listed = allowed_writes.contains(pl.as_str())
            || covered_spawns.contains(pl.as_str())
            || allowed_writes.contains("*");
        if target_listed {
            continue;
        }
        if let Some(ts) = target_summaries.get(pl)
            && ts.has_any_side_effect()
        {
            check_summary_against_effects(
                sys_name,
                span,
                ts,
                eff,
                layouts,
                target_summaries,
                diags,
            );
        } else {
            diags.push(Diagnostic::error(
                codes::E0204_EFFECTS_MISMATCH,
                span.clone(),
                format!(
                    "system `{sys_name}` plays/starts `{pl}` not covered by `effects(writes: [...])` or `effects(spawns: [...])`"
                ),
                None,
            ));
        }
    }
}

/// Propagates transitive helper `fn` resource reads/writes into [`FilteredAccessSet`] (`PM-06`),
/// enforces `@par(read_only)` (`PM-15`), validates `fn`/call-argument resource aliasing, and
/// checks transitive helper/`play` effects against declared `effects(...)` clauses (`NT-10c`).
#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_effects_par_and_aliasing(
    file: &str,
    src: &str,
    fns: &[HirFn],
    callables: &mut [HirCallable],
    tasks: &mut [HirTask],
    fsms: &mut [HirFsm],
    timelines: &[HirTimeline],
    layouts: &IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let mut fn_summaries: HashMap<String, BodyEffectsSummary> = HashMap::new();
    for hf in fns {
        let mut s = BodyEffectsSummary::default();
        collect_effects_in_stmts(&hf.body, &mut s);
        if let Some(ref t) = hf.tail {
            collect_effects_in_expr(t, &mut s);
        }
        let short = short_name(&hf.name).to_owned();
        fn_summaries.insert(short, s);
    }

    loop {
        let mut changed = false;
        let snapshot = fn_summaries.clone();
        for s in fn_summaries.values_mut() {
            let callees: Vec<String> = s.callees.iter().cloned().collect();
            for cname in callees {
                if let Some(other) = snapshot.get(&cname) {
                    changed |= s.merge_effects_from(other);
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut target_summaries: HashMap<String, BodyEffectsSummary> = HashMap::new();
    for t in tasks.iter() {
        let mut s = BodyEffectsSummary::default();
        for term in &t.typed_on_terms {
            if term.mode.is_mutable() {
                s.comp_writes
                    .insert(short_name(&term.storage_key).to_owned());
            }
        }
        for p in &t.typed_using_params {
            if p.kind == HirParamKind::ResWrite
                && let Ty::Named(ref r) = p.ty
            {
                s.res_writes.insert(short_name(r).to_owned());
            }
        }
        collect_effects_in_stmts(&t.body, &mut s);
        let direct_callees: Vec<String> = s.callees.iter().cloned().collect();
        for c in direct_callees {
            if let Some(fs) = fn_summaries.get(&c) {
                s.merge_effects_from(fs);
            }
        }
        target_summaries.insert(short_name(&t.name).to_owned(), s);
    }
    for f in fsms.iter() {
        let mut s = BodyEffectsSummary::default();
        for p in &f.params {
            if p.kind == HirParamKind::ResWrite
                && let Ty::Named(ref r) = p.ty
            {
                s.res_writes.insert(short_name(r).to_owned());
            }
        }
        for st in &f.state_hooks {
            collect_effects_in_stmts(&st.on_enter, &mut s);
            collect_effects_in_stmts(&st.on_tick, &mut s);
            collect_effects_in_stmts(&st.on_exit, &mut s);
        }
        for tr in &f.typed_transitions {
            collect_effects_in_expr(&tr.guard, &mut s);
            for (_, v) in &tr.target_args {
                collect_effects_in_expr(v, &mut s);
            }
        }
        let direct_callees: Vec<String> = s.callees.iter().cloned().collect();
        for c in direct_callees {
            if let Some(fs) = fn_summaries.get(&c) {
                s.merge_effects_from(fs);
            }
        }
        target_summaries.insert(short_name(&f.name).to_owned(), s);
    }
    for tl in timelines {
        let mut s = BodyEffectsSummary::default();
        for (_, stmts) in &tl.typed_triggers {
            collect_effects_in_stmts(stmts, &mut s);
        }
        let direct_callees: Vec<String> = s.callees.iter().cloned().collect();
        for c in direct_callees {
            if let Some(fs) = fn_summaries.get(&c) {
                s.merge_effects_from(fs);
            }
        }
        target_summaries.insert(short_name(&tl.name).to_owned(), s);
    }

    let fallback_span = Span::from_range(file, src, TextRange::empty(0.into()));

    // Check helper `fn` parameter resource aliasing and call-argument aliasing.
    for hf in fns {
        let span = Span::from_bytes(file, src, hf.byte_range.0, hf.byte_range.1);
        let res_params: Vec<(String, bool)> = hf
            .params
            .iter()
            .filter_map(|p| match (p.kind, &p.ty) {
                (HirParamKind::ResWrite, Ty::Named(r)) => Some((short_name(r).to_owned(), true)),
                (HirParamKind::ResRead, Ty::Named(r)) => Some((short_name(r).to_owned(), false)),
                _ => None,
            })
            .collect();
        for i in 0..res_params.len() {
            for j in (i + 1)..res_params.len() {
                if same_resource_name(&res_params[i].0, &res_params[j].0)
                    && (res_params[i].1 || res_params[j].1)
                {
                    diags.push(Diagnostic::error(
                        codes::E0201_ALIASING_CONFLICT,
                        span.clone(),
                        format!(
                            "singleton resource aliasing conflict in `fn {}`: `{}` cannot have overlapping mutable and shared/mutable parameter borrows",
                            hf.name, res_params[j].0
                        ),
                        None,
                    ));
                }
            }
        }
        let param_res_map: HashMap<String, (String, bool)> = hf
            .params
            .iter()
            .filter_map(|p| match (p.kind, &p.ty) {
                (HirParamKind::ResWrite, Ty::Named(r)) => {
                    Some((p.name.clone(), (short_name(r).to_owned(), true)))
                }
                (HirParamKind::ResRead, Ty::Named(r)) => {
                    Some((p.name.clone(), (short_name(r).to_owned(), false)))
                }
                _ => None,
            })
            .collect();
        check_call_arg_res_aliasing_stmts(&hf.body, &hf.name, &param_res_map, &span, diags);
        if let Some(ref tail) = hf.tail {
            check_call_arg_res_aliasing_expr(tail, &hf.name, &param_res_map, &span, diags);
        }
    }

    // Propagate helper resource reads/writes into tasks and fsms.
    for t in tasks.iter_mut() {
        if let Some(s) = target_summaries.get(short_name(&t.name)) {
            for r in &s.res_reads {
                t.access.res_reads.insert(r.clone());
            }
            for r in &s.res_writes {
                t.access.res_writes.insert(r.clone());
            }
        }
    }
    for f in fsms.iter_mut() {
        if let Some(s) = target_summaries.get(short_name(&f.name)) {
            for r in &s.res_reads {
                f.access.res_reads.insert(r.clone());
            }
            for r in &s.res_writes {
                f.access.res_writes.insert(r.clone());
            }
        }
    }

    // Callable validation: PM-06 propagation, transitive aliasing, PM-15 @par(read_only),
    // same-call resource aliasing, and NT-10c transitive effects / `play`.
    for c in callables.iter_mut() {
        let span = Span::from_bytes(file, src, c.byte_range.0, c.byte_range.1);
        let mut direct_summary = BodyEffectsSummary::default();
        collect_effects_in_stmts(&c.body, &mut direct_summary);

        let mut helper_summary = BodyEffectsSummary::default();
        for cname in &direct_summary.callees {
            if let Some(fs) = fn_summaries.get(cname) {
                helper_summary.merge_effects_from(fs);
            }
        }

        // Propagate transitive helper `res<R>()` / `res_mut<R>()` into `c.access` (PM-06).
        let mut added_res_accesses = Vec::new();
        for r in &helper_summary.res_reads {
            if !c.access.res_reads.iter().any(|x| same_resource_name(x, r)) {
                c.access.res_reads.insert(r.clone());
            }
            added_res_accesses.push((r.clone(), false, c.byte_range.0, c.byte_range.1));
        }
        for r in &helper_summary.res_writes {
            if !c.access.res_writes.iter().any(|x| same_resource_name(x, r)) {
                c.access.res_writes.insert(r.clone());
            }
            added_res_accesses.push((r.clone(), true, c.byte_range.0, c.byte_range.1));
        }
        if !added_res_accesses.is_empty() {
            check_res_param_body_aliasing(file, src, &c.access, &added_res_accesses, diags);
            c.access.res_body_accesses.extend(added_res_accesses);
        }

        // Same-call resource argument aliasing.
        let param_res_map: HashMap<String, (String, bool)> = c
            .params
            .iter()
            .filter_map(|p| match (p.kind, &p.ty) {
                (HirParamKind::ResWrite, Ty::Named(r)) => {
                    Some((p.name.clone(), (short_name(r).to_owned(), true)))
                }
                (HirParamKind::ResRead, Ty::Named(r)) => {
                    Some((p.name.clone(), (short_name(r).to_owned(), false)))
                }
                _ => None,
            })
            .collect();
        check_call_arg_res_aliasing_stmts(&c.body, &c.name, &param_res_map, &span, diags);

        // PM-15: enforce `@par(read_only)` contract.
        if c.par_read_only {
            let mut total_queries = 0usize;
            let mut ro_queries = 0usize;
            check_par_read_only_stmts(
                &c.body,
                &c.name,
                &span,
                &mut total_queries,
                &mut ro_queries,
                diags,
            );
            if total_queries > 0 && ro_queries == 0 {
                diags.push(Diagnostic::error(
                    codes::E0202_ASSERT_PAR_FAILED,
                    span.clone(),
                    format!(
                        "`@par(read_only)` system `{}` has no read-only `query(...)` loop (all queries borrow `&mut` / `&mut?`)",
                        c.name
                    ),
                    None,
                ));
            }
        }

        // NT-10c: verify transitive helper `fn` effects and direct/transitive `play(...)`.
        if let Some(ref eff) = c.declared_effects {
            let mut transitive = helper_summary;
            transitive.plays.extend(direct_summary.plays);
            check_summary_against_effects(
                &c.name,
                &span,
                &transitive,
                eff,
                layouts,
                &target_summaries,
                diags,
            );
        }
    }
    let _ = fallback_span;
}
