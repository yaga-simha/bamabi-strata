//! Full semantic pass implementing layout resolution, wire UUID/FNV-1a parity, Theorem 0.1
//! `FilteredAccessSet` proofs, `effects`/`assert_layout`/`assert_par` verification, and AI-native
//! anti-pattern lints (`W0401..W0404`).

use crate::access::{
    FilteredAccessSet, QueryAccessDesc, QueryTerm, TermAccessMode, build_concurrency_graph,
    system_conflicts, validate_system_accesses,
};
use crate::diagnostics::{Diagnostic, FixIt, Span, codes};
use crate::hir::{
    AnalyzedModule, EffectsSpec, HirBinOp, HirCallable, HirConst, HirCurve, HirExpr, HirFn, HirFsm,
    HirMigration, HirObject, HirParamKind, HirRelation, HirSchedule, HirScheduleGroup, HirSimTest,
    HirSpatialIndex, HirStmt, HirTable, HirTask, HirTimeline, HirUnOp, SemVerInfo,
};
use crate::hir_lower::{
    LowerEnv, ScopeBinding, ScopeStack, classify_param_type, is_expr_node, is_type_node,
    lower_block, lower_block_as_stmts, lower_comp_init_list, lower_expr, lower_field_init_list,
    lower_fsm_details, lower_param_list, lower_proj_term, lower_stmt_node, lower_sys_param_list,
};
use crate::layout::{
    EnumDef, LayoutEnv, SchemaItemKind, SolvedLayout, flags_from_attr_names, solve_pod_layout,
    solve_task_state_layout, solve_timeline_layout,
};
use crate::types::{Ty, UnitDim, parse_type_node};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{
    self, AstNode, ComponentDecl, EnumDecl, ResourceDecl, SourceFile, StructDecl,
};
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode, parse};

/// Extracts only schema/declaration headers (stripping `sys`/`obs`/`fn`/`sim_test` bodies) so
/// Salsa early-cutoff avoids re-running layout resolution on body-only edits.
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
            ast::Item::SimTest(_) => {}
            _ => {
                out.push_str(&node.text().to_string());
                out.push('\n');
            }
        }
    }
    out
}

fn push_node_prefix(node: &SyntaxNode, body_start: Option<u32>, out: &mut String) {
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
    // Maps `(ComponentShortName, FieldName)` -> `"Comp::stratum"` (or `"Comp"` for non-SoA).
    let mut field_to_stratum: HashMap<String, String> = HashMap::new();

    // Pass 1: Collect enums first so struct/component fields can reference enum types.
    for item in sf.items() {
        if let ast::Item::Enum(en) = item {
            let def = collect_enum(&module_path, &en);
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

/// Runs the complete semantic analysis pipeline on `src` and returns [`AnalyzedModule`].
pub fn analyze_module_full(file: &str, src: &str) -> AnalyzedModule {
    let SolvedModuleLayouts {
        module_path,
        version,
        is_deterministic,
        layouts,
        soa_strata,
        enums,
        field_to_stratum,
        diagnostics: mut diags,
    } = solve_module_layouts(file, src);

    let parsed = parse(src);
    let root = parsed.syntax();
    let Some(sf) = SourceFile::cast(root) else {
        return AnalyzedModule {
            module_path,
            version,
            is_deterministic,
            layouts,
            soa_strata,
            enums,
            tags: Vec::new(),
            consts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: Vec::new(),
            fsms: Vec::new(),
            callables: Vec::new(),
            fns: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
            concurrency_graph: build_concurrency_graph(&[]),
            diagnostics: diags,
        };
    };

    let mut env = LayoutEnv {
        resolved: IndexMap::new(),
        enums: enums.clone(),
    };
    for (canon, layout) in &layouts {
        let short = canon.rsplit("::").next().unwrap_or(canon).to_owned();
        env.resolved.insert(
            short,
            (
                layout.size,
                layout.align,
                layout.is_abi_pod,
                bamabi_sys::BamFieldKind::NESTED.0,
                canon.clone(),
            ),
        );
    }

    let mut lower_env = LowerEnv {
        module_path: &module_path,
        layouts: &layouts,
        field_to_stratum: &field_to_stratum,
        enums: &enums,
        const_tys: HashMap::new(),
        table_fields: HashMap::new(),
        curve_ret_tys: HashMap::new(),
        fn_ret_tys: HashMap::new(),
        objects: HashSet::new(),
        sparse_components: HashSet::new(),
    };
    for (canon, layout) in &layouts {
        if (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0 {
            let short = canon.rsplit("::").next().unwrap_or(canon).to_owned();
            lower_env.sparse_components.insert(short);
            lower_env.sparse_components.insert(canon.clone());
        }
    }

    let mut tags = Vec::new();
    let mut consts = Vec::new();
    let mut tables = Vec::new();
    let mut curves = Vec::new();
    let mut relations = Vec::new();
    let mut spatial_indices = Vec::new();
    let mut objects = Vec::new();

    // Pass A: collect constants, tables, curves, tags, relations, spatial indices, objects, fn sigs.
    for item in sf.items() {
        match item {
            ast::Item::Tag(tg) => {
                for tok in tg
                    .syntax()
                    .children_with_tokens()
                    .filter_map(|e| e.into_token())
                    .filter(|t| t.kind() == SyntaxKind::Ident)
                {
                    tags.push(tok.text().to_owned());
                }
            }
            ast::Item::Const(c) => {
                if let Some(hc) = analyze_const(file, src, c.syntax(), &lower_env, &mut diags) {
                    lower_env.const_tys.insert(hc.name.clone(), hc.ty.clone());
                    consts.push(hc);
                }
            }
            ast::Item::Table(tb) => {
                let ht = analyze_table(file, src, tb.syntax(), &enums, &lower_env, &mut diags);
                lower_env
                    .table_fields
                    .insert(ht.name.clone(), ht.fields.clone());
                tables.push(ht);
            }
            ast::Item::Curve(cv) => {
                let hc = analyze_curve(file, src, cv.syntax(), &lower_env, &mut diags);
                lower_env
                    .curve_ret_tys
                    .insert(hc.name.clone(), hc.output_ty.clone());
                curves.push(hc);
            }
            ast::Item::Relation(rel) => {
                relations.push(analyze_relation(&module_path, rel.syntax(), &layouts));
            }
            ast::Item::SpatialGrid(sg) => {
                spatial_indices.push(analyze_spatial(&module_path, sg.syntax(), false, &layouts));
            }
            ast::Item::SpatialHistory(sh) => {
                spatial_indices.push(analyze_spatial(&module_path, sh.syntax(), true, &layouts));
            }
            ast::Item::Object(obj) => {
                let ho = analyze_object(obj.syntax(), &lower_env);
                lower_env.objects.insert(ho.name.clone());
                objects.push(ho);
            }
            ast::Item::Fn(f) => {
                if let Some(fname) = ast::first_ident(f.syntax()) {
                    let ret_ty = f
                        .syntax()
                        .children()
                        .find(|c| is_type_node(c.kind()))
                        .map_or(Ty::Unit, |t| parse_type_node(&t));
                    lower_env.fn_ret_tys.insert(fname.text().to_owned(), ret_ty);
                }
            }
            _ => {}
        }
    }

    // Collect FieldDecl default expressions for every layout (including `@soa` strata).
    let field_defaults = collect_field_defaults(&sf, &module_path, &layouts, &lower_env);

    // Pass B: lower executable items with full module symbol table in `lower_env`.
    let mut timelines = Vec::new();
    let mut tasks = Vec::new();
    let mut fsms = Vec::new();
    let mut callables = Vec::new();
    let mut fns = Vec::new();
    let mut migrations = Vec::new();
    let mut schedules = Vec::new();
    let mut sim_tests = Vec::new();

    for item in sf.items() {
        match item {
            ast::Item::Timeline(tl) => {
                timelines.push(analyze_timeline(
                    file,
                    src,
                    &module_path,
                    tl.syntax(),
                    &layouts,
                    &lower_env,
                    &mut diags,
                ));
            }
            ast::Item::Task(tk) => {
                tasks.push(analyze_task(
                    file,
                    src,
                    &module_path,
                    tk.syntax(),
                    &layouts,
                    &lower_env,
                    &mut diags,
                ));
            }
            ast::Item::Fsm(fm) => {
                fsms.push(analyze_fsm(
                    file,
                    src,
                    &module_path,
                    fm.syntax(),
                    &layouts,
                    &lower_env,
                    &mut diags,
                ));
            }
            ast::Item::Sys(sy) => {
                callables.push(analyze_callable(
                    file,
                    src,
                    sy.syntax(),
                    false,
                    &lower_env,
                    &layouts,
                    &mut diags,
                ));
            }
            ast::Item::Obs(ob) => {
                callables.push(analyze_callable(
                    file,
                    src,
                    ob.syntax(),
                    true,
                    &lower_env,
                    &layouts,
                    &mut diags,
                ));
            }
            ast::Item::Fn(f) => {
                fns.push(analyze_fn(f.syntax(), &lower_env));
            }
            ast::Item::Migrate(mg) => {
                migrations.push(analyze_migrate(mg.syntax(), &lower_env));
            }
            ast::Item::Schedule(sc) => {
                schedules.push(analyze_schedule(sc.syntax(), &lower_env));
            }
            ast::Item::SimTest(st) => {
                sim_tests.push(analyze_sim_test(st.syntax(), &lower_env));
            }
            ast::Item::AssertLayout(al) => {
                evaluate_assert_layout(file, src, al.syntax(), &module_path, &layouts, &mut diags);
            }
            _ => {}
        }
    }

    // Build access map across callables, tasks, and FSMs for `ConcurrencyGraph` and `assert_par`.
    let mut all_access: Vec<FilteredAccessSet> =
        callables.iter().map(|c| c.access.clone()).collect();
    all_access.extend(tasks.iter().map(|t| t.access.clone()));
    all_access.extend(fsms.iter().map(|f| f.access.clone()));
    let concurrency_graph = build_concurrency_graph(&all_access);

    // Evaluate `assert_par(a, b, ...)`.
    for item in sf.items() {
        if let ast::Item::AssertPar(ap) = item {
            evaluate_assert_par(file, src, ap.syntax(), &all_access, &mut diags);
        }
    }

    AnalyzedModule {
        module_path,
        version,
        is_deterministic,
        layouts,
        soa_strata,
        enums,
        tags,
        consts,
        tables,
        curves,
        relations,
        spatial_indices,
        timelines,
        tasks,
        fsms,
        callables,
        fns,
        objects,
        migrations,
        schedules,
        sim_tests,
        field_defaults,
        concurrency_graph,
        diagnostics: diags,
    }
}

fn parse_semver_text(s: &str) -> Option<SemVerInfo> {
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

fn collect_enum(module_path: &str, en: &EnumDecl) -> EnumDef {
    let short = en
        .name()
        .map_or_else(|| "Enum".to_owned(), |t| t.text().to_owned());
    let mut next_disc = 0i64;
    let mut variants = Vec::new();
    for v in en.variants() {
        let v_name = ast::first_ident(v.syntax())
            .map_or_else(|| "Variant".to_owned(), |t| t.text().to_owned());
        if let Some(int_tok) = v
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .find(|t| t.kind() == SyntaxKind::IntLit)
            && let Ok(parsed) = int_tok
                .text()
                .split('_')
                .next()
                .unwrap_or("")
                .parse::<i64>()
        {
            next_disc = parsed;
        }
        variants.push((v_name, next_disc));
        next_disc += 1;
    }
    let repr_bytes = if variants.len() <= 255 { 1 } else { 4 };
    EnumDef {
        canonical_name: format!("{module_path}::{short}"),
        variants,
        repr_bytes,
    }
}

fn check_and_collect_fields(
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
        if let Ty::BannedWire(ref banned) = ty {
            let replacement = match banned.as_str() {
                "String" => "InlineStr<32>",
                "Vec" => "SmallVec<T, 4>",
                "usize" | "u128" => "u64",
                "isize" | "i128" => "i64",
                _ => "u32",
            };
            diags.push(Diagnostic::error(
                codes::E0103_INVALID_ABI_POD_FIELD,
                Span::from_range(file, src, f.syntax().text_range()),
                format!(
                    "field `{owner_name}.{fname}` uses banned non-ABI type `{banned}`; use `{replacement}`"
                ),
                f.type_node().map(|tn| FixIt {
                    replace_byte_start: u32::from(tn.text_range().start()),
                    replace_byte_end: u32::from(tn.text_range().end()),
                    replacement: replacement.to_owned(),
                }),
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

fn check_field_default_unit(
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

fn resolve_struct_item(
    file: &str,
    src: &str,
    module_path: &str,
    st: &StructDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let short = st
        .name()
        .map_or_else(|| "Struct".to_owned(), |t| t.text().to_owned());
    let fields = check_and_collect_fields(file, src, &short, &st.fields(), diags);
    let canonical = format!("{module_path}::{short}");
    if let Ok(solved) = solve_pod_layout(
        &canonical,
        SchemaItemKind::Struct,
        &fields,
        0,
        Vec::new(),
        env,
    ) {
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

fn resolve_resource_item(
    file: &str,
    src: &str,
    module_path: &str,
    res: &ResourceDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let short = res
        .name()
        .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
    let fields = check_and_collect_fields(file, src, &short, &res.fields(), diags);
    let canonical = format!("{module_path}::{short}");
    if let Ok(solved) = solve_pod_layout(
        &canonical,
        SchemaItemKind::Resource,
        &fields,
        0,
        Vec::new(),
        env,
    ) {
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

#[allow(clippy::too_many_arguments)]
fn resolve_simple_fields_item(
    file: &str,
    src: &str,
    module_path: &str,
    short: &str,
    kind: SchemaItemKind,
    node: &SyntaxNode,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    diags: &mut Vec<Diagnostic>,
) {
    let field_nodes: Vec<_> = ast::children::<ast::FieldDecl>(node).collect();
    let fields = check_and_collect_fields(file, src, short, &field_nodes, diags);
    let canonical = format!("{module_path}::{short}");
    if let Ok(solved) = solve_pod_layout(&canonical, kind, &fields, 0, Vec::new(), env) {
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
}

#[allow(clippy::too_many_arguments)]
fn resolve_component_item(
    file: &str,
    src: &str,
    module_path: &str,
    comp: &ComponentDecl,
    env: &mut LayoutEnv,
    layouts: &mut IndexMap<String, SolvedLayout>,
    soa_strata: &mut IndexMap<String, Vec<String>>,
    field_to_stratum: &mut HashMap<String, String>,
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
                if let Ok(solved) = solve_pod_layout(
                    &hot_canon,
                    SchemaItemKind::SoaHot,
                    &raw_fields,
                    flags,
                    reqs.clone(),
                    env,
                ) {
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
            } else {
                let cold_short = format!("{short}__{sname}");
                let cold_canon = format!("{module_path}::{cold_short}");
                let mut cold_reqs = vec![hot_canon.clone()];
                cold_reqs.extend(reqs.iter().cloned());
                if let Ok(solved) = solve_pod_layout(
                    &cold_canon,
                    SchemaItemKind::SoaCold,
                    &raw_fields,
                    0,
                    cold_reqs,
                    env,
                ) {
                    layouts.insert(format!("{hot_canon}::{sname}"), solved.clone());
                    layouts.insert(cold_canon, solved);
                    stratum_names.push(format!("{short}::{sname}"));
                }
            }
        }
        soa_strata.insert(short.clone(), stratum_names);
    } else {
        let raw_fields = check_and_collect_fields(file, src, &short, &comp.fields(), diags);
        for (fn_name, _) in &raw_fields {
            field_to_stratum.insert(format!("{short}.{fn_name}"), short.clone());
        }
        let canonical = format!("{module_path}::{short}");
        if let Ok(solved) = solve_pod_layout(
            &canonical,
            SchemaItemKind::Component,
            &raw_fields,
            flags,
            reqs,
            env,
        ) {
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
    }
}

fn collect_task_live_vars(
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

fn eval_const_f64(expr: &HirExpr) -> Option<f64> {
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

fn extract_field_defaults_list(
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
                    map.insert(fname.clone(), lower_expr(&n, lower_env, &mut scope, &[]));
                    break;
                }
                _ => {}
            }
        }
    }
    map
}

fn collect_field_defaults(
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

fn analyze_const(
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

fn analyze_table(
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

fn analyze_curve(
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

fn parse_numeric_prefix(s: &str) -> Option<f64> {
    let clean = s.split('_').next().unwrap_or(s).trim();
    clean.parse::<f64>().ok()
}

fn analyze_relation(
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

fn analyze_spatial(
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
    if let Some(fil) = ast::child::<ast::FieldInitList>(node) {
        for fi in ast::children::<ast::FieldInit>(fil.syntax()) {
            if ast::first_ident(fi.syntax()).is_some_and(|t| t.text() == "frames")
                && let Some(val) = fi
                    .syntax()
                    .descendants_with_tokens()
                    .filter_map(|e| e.into_token())
                    .find(|t| t.kind() == SyntaxKind::IntLit)
            {
                frames = val
                    .text()
                    .split('_')
                    .next()
                    .unwrap_or("1")
                    .parse()
                    .unwrap_or(1);
            }
        }
    }

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
    }
}

fn analyze_timeline(
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

fn analyze_task(
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

    HirTask {
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
    }
}

fn analyze_fsm(
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
                        .and_then(|t| t.text().parse::<i32>().ok())
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
fn analyze_callable(
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
                par_chunk = num_tok.text().parse::<u32>().ok();
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

    HirCallable {
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
    }
}

fn analyze_fn(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirFn {
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
        .map_or(Ty::Unit, |t| parse_type_node(&t));
    let (body, tail) = ast::child::<ast::Block>(node)
        .map(|b| lower_block(b.syntax(), lower_env, &mut scope, &[]))
        .unwrap_or_default();

    HirFn {
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
    }
}

fn record_sys_param(param: &SyntaxNode, access: &mut FilteredAccessSet) {
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

fn parse_effects(node: &SyntaxNode) -> EffectsSpec {
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

fn verify_effects(
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
}

fn collect_body_queries(
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
                                _ => {}
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

fn parse_proj_term(pt: &SyntaxNode, lower_env: &LowerEnv<'_>) -> Option<QueryTerm> {
    let ht = lower_proj_term(pt, lower_env)?;
    Some(QueryTerm {
        storage_key: ht.storage_key,
        field_name: ht.field_name,
        mode: ht.mode,
        byte_start: u32::from(pt.text_range().start()),
        byte_end: u32::from(pt.text_range().end()),
    })
}

fn check_body_lints(
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

fn outer_for_uses_unindexed_query(for_node: &SyntaxNode) -> bool {
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

fn evaluate_assert_layout(
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

fn evaluate_assert_par(
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

fn analyze_object(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirObject {
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

fn analyze_migrate(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirMigration {
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

    let from_type = node
        .children()
        .find(|c| is_type_node(c.kind()))
        .map_or(Ty::Unknown, |n| parse_type_node(&n));
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

fn analyze_schedule(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirSchedule {
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

fn parse_schedule_group(node: &SyntaxNode) -> HirScheduleGroup {
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

fn analyze_sim_test(node: &SyntaxNode, lower_env: &LowerEnv<'_>) -> HirSimTest {
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
    HirSimTest {
        name,
        body,
        body_source,
    }
}
