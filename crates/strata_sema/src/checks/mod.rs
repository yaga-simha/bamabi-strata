//! Semantic validation, layout resolution, effects/node verification, and HIR construction.

mod attrs;
mod effects;
mod items;
mod schema;
mod type_check;

pub use schema::{SolvedModuleLayouts, extract_schema_signature_text, solve_module_layouts};

use crate::access::{FilteredAccessSet, build_concurrency_graph};
use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    AnalyzedModule, AuthorityKind, HirCallable, HirFn, HirFsm, HirMigration, HirNetSimTest,
    HirSchedule, HirSimTest, HirTask, HirTimeline, NetComponentMeta,
};
use crate::hir_lower::{LowerEnv, is_type_node};
use crate::layout::{LayoutEnv, compute_net_schema_fingerprint};
use crate::types::{Ty, parse_type_node_with_user_types};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::ast::{self, AstNode, SourceFile};
use strata_syntax::{SyntaxKind, SyntaxNode, parse};

/// Extracts only schema/declaration headers (stripping `sys`/`obs`/`fn`/`sim_test`/`net_sim_test`
/// bodies) so Salsa early-cutoff avoids re-running layout resolution on body-only edits.
use attrs::*;
use effects::*;
use items::*;
use schema::*;

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
            rpcs: Vec::new(),
            net_sim_tests: Vec::new(),
            net_components: Vec::new(),
            net_schema_fingerprint: 0,
            node_groups: IndexMap::new(),
            pure_fns: Vec::new(),
            authorities: IndexMap::new(),
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

    let user_types = collect_user_type_names(&sf);
    let item_fields = collect_all_item_fields(&sf, &module_path, &user_types);

    let mut lower_env = LowerEnv {
        module_path: &module_path,
        layouts: &layouts,
        item_fields: &item_fields,
        user_types: &user_types,
        field_to_stratum: &field_to_stratum,
        enums: &enums,
        const_tys: HashMap::new(),
        table_fields: HashMap::new(),
        curve_ret_tys: HashMap::new(),
        fn_ret_tys: HashMap::new(),
        objects: HashSet::new(),
        sparse_components: HashSet::new(),
        authorities: IndexMap::new(),
    };
    for (canon, layout) in &layouts {
        if (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0 {
            let short = canon.rsplit("::").next().unwrap_or(canon).to_owned();
            lower_env.sparse_components.insert(short);
            lower_env.sparse_components.insert(canon.clone());
        }
    }

    // Validate Phase 3 attributes across all items, fields, and nested declarations.
    validate_all_attributes(file, src, &sf, &mut diags);

    let mut tags = Vec::new();
    let mut consts = Vec::new();
    let mut const_ranges = Vec::new();
    let mut tables = Vec::new();
    let mut curves = Vec::new();
    let mut relations = Vec::new();
    let mut spatial_indices = Vec::new();
    let mut objects = Vec::new();
    let mut obj_ranges = Vec::new();
    let mut rpcs = Vec::new();
    let mut seen_rpcs = HashSet::new();
    let mut all_user_fns = HashSet::new();
    let mut pure_fns_set = HashSet::new();
    let mut pure_fns = Vec::new();
    let mut node_groups: IndexMap<String, String> = IndexMap::new();
    let mut authorities: IndexMap<String, AuthorityKind> = IndexMap::new();
    let mut net_components: Vec<NetComponentMeta> = Vec::new();
    let struct_quantizes = collect_struct_quantize_map(&sf);

    // Pass A: collect constants, tables, curves, tags, relations, spatial indices, objects,
    // fn sigs, RPCs, node groups, authorities, and net component metadata.
    for item in sf.items() {
        record_item_node_group(&module_path, &item, &mut node_groups);
        match &item {
            ast::Item::Component(comp) => {
                let short = comp
                    .name()
                    .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
                let (auth, is_pred) = extract_item_authority(comp.syntax());
                if auth != AuthorityKind::Unspecified {
                    register_component_authority(
                        &module_path,
                        &short,
                        comp,
                        auth,
                        &mut authorities,
                    );
                }
                if let Some(meta) = collect_net_component_meta(
                    &module_path,
                    &short,
                    comp.syntax(),
                    false,
                    auth,
                    is_pred,
                    &struct_quantizes,
                ) {
                    net_components.push(meta);
                }
            }
            ast::Item::Resource(res) => {
                let short = res
                    .name()
                    .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
                let (auth, is_pred) = extract_item_authority(res.syntax());
                if auth != AuthorityKind::Unspecified {
                    authorities.insert(short.clone(), auth);
                    authorities.insert(format!("{module_path}::{short}"), auth);
                }
                if let Some(meta) = collect_net_component_meta(
                    &module_path,
                    &short,
                    res.syntax(),
                    true,
                    auth,
                    is_pred,
                    &struct_quantizes,
                ) {
                    net_components.push(meta);
                }
            }
            ast::Item::Rpc(rpc) => {
                let short = rpc
                    .name()
                    .map_or_else(|| "Rpc".to_owned(), |t| t.text().to_owned());
                if !seen_rpcs.insert(short.clone()) {
                    diags.push(Diagnostic::error(
                        codes::E0303_DUPLICATE_SYMBOL,
                        Span::from_range(file, src, rpc.syntax().text_range()),
                        format!("duplicate rpc declaration `{short}`"),
                        None,
                    ));
                } else {
                    let hir_rpc = analyze_rpc(&module_path, rpc, &mut env, &struct_quantizes);
                    rpcs.push(hir_rpc);
                }
            }
            _ => {}
        }
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
                    const_ranges.push(c.syntax().text_range());
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
                obj_ranges.push(obj.syntax().text_range());
                objects.push(ho);
            }
            ast::Item::Fn(f) => {
                if let Some(fname) = ast::first_ident(f.syntax()) {
                    let fn_name = fname.text().to_owned();
                    let canonical_fn = format!("{module_path}::{fn_name}");
                    let ret_ty = f
                        .syntax()
                        .children()
                        .find(|c| is_type_node(c.kind()))
                        .map_or(Ty::Unit, |t| {
                            parse_type_node_with_user_types(&t, &user_types)
                        });
                    lower_env.fn_ret_tys.insert(fn_name.clone(), ret_ty.clone());
                    lower_env.fn_ret_tys.insert(canonical_fn.clone(), ret_ty);
                    all_user_fns.insert(fn_name.clone());
                    all_user_fns.insert(canonical_fn.clone());
                    if has_attr_name(f.syntax(), "node_pure") {
                        pure_fns_set.insert(fn_name.clone());
                        pure_fns_set.insert(canonical_fn);
                        pure_fns.push(fn_name);
                    }
                }
            }
            _ => {}
        }
    }

    // Collect FieldDecl default expressions for every layout (including `@soa` strata).
    lower_env.authorities = authorities.clone();
    validate_const_inits(file, src, &consts, &const_ranges, &lower_env, &mut diags);
    for (ho, range) in objects.iter().zip(obj_ranges.iter().copied()) {
        validate_object_const_inits(file, src, range, ho, &lower_env, &consts, &mut diags);
    }
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
    let mut net_sim_tests = Vec::new();

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
                fns.push(analyze_fn(file, src, f.syntax(), &lower_env, &mut diags));
            }
            ast::Item::Migrate(mg) => {
                migrations.push(analyze_migrate(mg.syntax(), &lower_env));
            }
            ast::Item::Schedule(sc) => {
                schedules.push(analyze_schedule(sc.syntax(), &lower_env));
            }
            ast::Item::SimTest(st) => {
                sim_tests.push(analyze_sim_test(
                    file,
                    src,
                    st.syntax(),
                    &lower_env,
                    &mut diags,
                ));
            }
            ast::Item::NetSimTest(nst) => {
                net_sim_tests.push(analyze_net_sim_test(
                    file, src, &nst, &lower_env, &mut diags,
                ));
            }
            ast::Item::AssertLayout(al) => {
                evaluate_assert_layout(file, src, al.syntax(), &module_path, &layouts, &mut diags);
            }
            _ => {}
        }
    }

    // Validate `@node_pure` functions against CST + HIR bodies and transitive helper calls.
    for (item, hf) in sf
        .items()
        .filter_map(|it| match it {
            ast::Item::Fn(f) => Some(f),
            _ => None,
        })
        .zip(fns.iter())
    {
        if hf.is_node_pure {
            validate_node_pure_fn(
                file,
                src,
                item.syntax(),
                hf,
                &all_user_fns,
                &pure_fns_set,
                &mut diags,
            );
        }
    }

    // Enforce `E0111` array/SmallVec literal mismatches and `E0301` query/field resolution.
    type_check::validate_module_types(
        file,
        src,
        &sf,
        &lower_env,
        &consts,
        &objects,
        &field_defaults,
        &fns,
        &callables,
        &tasks,
        &fsms,
        &timelines,
        &sim_tests,
        &net_sim_tests,
        &mut diags,
    );

    // Enforce `E0501` authority isolation via the unified provenance abstract interpreter.
    let server_res_items = collect_server_res_usages(&sf, &module_path);
    crate::authority::validate_module_authority(
        file,
        src,
        &module_path,
        &authorities,
        &layouts,
        &enums,
        &item_fields,
        &fns,
        &callables,
        &tasks,
        &fsms,
        &timelines,
        &objects,
        &server_res_items,
        &mut diags,
    );

    // Enforce `PM-06` helper resource propagation, `PM-15` `@par(read_only)`, resource
    // aliasing, and `NT-10c` transitive `effects(...)` before `ConcurrencyGraph` / `assert_par`.
    finalize_effects_par_and_aliasing(
        file,
        src,
        &fns,
        &mut callables,
        &mut tasks,
        &mut fsms,
        &timelines,
        &layouts,
        &mut diags,
    );

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

    let net_schema_fingerprint =
        compute_net_schema_fingerprint(&module_path, &layouts, &net_components, &rpcs);

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
        rpcs,
        net_sim_tests,
        net_components,
        net_schema_fingerprint,
        node_groups,
        pure_fns,
        authorities,
    }
}

/// Module-level environment summary computed strictly from `schema_signature` (invariants
/// under `sys`/`obs`/`fn`/`sim_test`/`net_sim_test` body edits) for per-item Salsa caching.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ModuleEnvSummary {
    pub(crate) module_path: String,
    pub(crate) layouts: IndexMap<String, crate::layout::SolvedLayout>,
    pub(crate) enums: IndexMap<String, crate::layout::EnumDef>,
    pub(crate) field_to_stratum: HashMap<String, String>,
    pub(crate) user_types: HashSet<String>,
    pub(crate) item_fields: IndexMap<String, Vec<(String, Ty)>>,
    pub(crate) const_tys: HashMap<String, Ty>,
    pub(crate) table_fields: HashMap<String, Vec<(String, Ty)>>,
    pub(crate) curve_ret_tys: HashMap<String, Ty>,
    pub(crate) fn_ret_tys: HashMap<String, Ty>,
    pub(crate) objects: HashSet<String>,
    pub(crate) sparse_components: HashSet<String>,
    pub(crate) authorities: IndexMap<String, AuthorityKind>,
}

/// Per-item semantic lowering output keyed off a detached [`rowan::GreenNode`] and
/// [`ModuleEnvSummary`] (relative offsets `0..item_len`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SingleItemAnalysis {
    Timeline {
        item: HirTimeline,
        diags: Vec<Diagnostic>,
    },
    Task {
        item: HirTask,
        diags: Vec<Diagnostic>,
    },
    Fsm {
        item: HirFsm,
        diags: Vec<Diagnostic>,
    },
    Callable {
        item: HirCallable,
        diags: Vec<Diagnostic>,
    },
    Fn {
        item: HirFn,
        diags: Vec<Diagnostic>,
    },
    Migrate {
        item: HirMigration,
        diags: Vec<Diagnostic>,
    },
    Schedule {
        item: HirSchedule,
        diags: Vec<Diagnostic>,
    },
    SimTest {
        item: HirSimTest,
        diags: Vec<Diagnostic>,
    },
    NetSimTest {
        item: HirNetSimTest,
        diags: Vec<Diagnostic>,
    },
    AssertLayout {
        diags: Vec<Diagnostic>,
    },
    Other,
}

/// Computes [`ModuleEnvSummary`] strictly from `sig` (the output of `schema_signature`),
/// preserving Salsa early-cutoff across body-only edits.
pub(crate) fn compute_module_env_summary(file: &str, sig: &str) -> ModuleEnvSummary {
    let SolvedModuleLayouts {
        module_path,
        layouts,
        enums,
        field_to_stratum,
        ..
    } = solve_module_layouts(file, sig);

    let parsed = parse(sig);
    let Some(sf) = SourceFile::cast(parsed.syntax()) else {
        return ModuleEnvSummary {
            module_path,
            layouts,
            enums,
            field_to_stratum,
            user_types: HashSet::new(),
            item_fields: IndexMap::new(),
            const_tys: HashMap::new(),
            table_fields: HashMap::new(),
            curve_ret_tys: HashMap::new(),
            fn_ret_tys: HashMap::new(),
            objects: HashSet::new(),
            sparse_components: HashSet::new(),
            authorities: IndexMap::new(),
        };
    };

    let user_types = collect_user_type_names(&sf);
    let item_fields = collect_all_item_fields(&sf, &module_path, &user_types);

    let mut lower_env = LowerEnv {
        module_path: &module_path,
        layouts: &layouts,
        item_fields: &item_fields,
        user_types: &user_types,
        field_to_stratum: &field_to_stratum,
        enums: &enums,
        const_tys: HashMap::new(),
        table_fields: HashMap::new(),
        curve_ret_tys: HashMap::new(),
        fn_ret_tys: HashMap::new(),
        objects: HashSet::new(),
        sparse_components: HashSet::new(),
        authorities: IndexMap::new(),
    };
    for (canon, layout) in &layouts {
        if (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0 {
            let short = canon.rsplit("::").next().unwrap_or(canon).to_owned();
            lower_env.sparse_components.insert(short);
            lower_env.sparse_components.insert(canon.clone());
        }
    }

    let mut authorities: IndexMap<String, AuthorityKind> = IndexMap::new();
    let mut discard_diags = Vec::new();
    for item in sf.items() {
        match &item {
            ast::Item::Component(comp) => {
                let short = comp
                    .name()
                    .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
                let (auth, _) = extract_item_authority(comp.syntax());
                if auth != AuthorityKind::Unspecified {
                    register_component_authority(
                        &module_path,
                        &short,
                        comp,
                        auth,
                        &mut authorities,
                    );
                }
            }
            ast::Item::Resource(res) => {
                let short = res
                    .name()
                    .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
                let (auth, _) = extract_item_authority(res.syntax());
                if auth != AuthorityKind::Unspecified {
                    authorities.insert(short.clone(), auth);
                    authorities.insert(format!("{module_path}::{short}"), auth);
                }
            }
            _ => {}
        }
        match item {
            ast::Item::Const(c) => {
                if let Some(hc) =
                    analyze_const(file, sig, c.syntax(), &lower_env, &mut discard_diags)
                {
                    lower_env.const_tys.insert(hc.name, hc.ty);
                }
            }
            ast::Item::Table(tb) => {
                let ht = analyze_table(
                    file,
                    sig,
                    tb.syntax(),
                    &enums,
                    &lower_env,
                    &mut discard_diags,
                );
                lower_env.table_fields.insert(ht.name.clone(), ht.fields);
            }
            ast::Item::Curve(cv) => {
                let hc = analyze_curve(file, sig, cv.syntax(), &lower_env, &mut discard_diags);
                lower_env
                    .curve_ret_tys
                    .insert(hc.name.clone(), hc.output_ty);
            }
            ast::Item::Object(obj) => {
                let ho = analyze_object(obj.syntax(), &lower_env);
                lower_env.objects.insert(ho.name);
            }
            ast::Item::Fn(f) => {
                if let Some(fname) = ast::first_ident(f.syntax()) {
                    let fn_name = fname.text().to_owned();
                    let canonical_fn = format!("{module_path}::{fn_name}");
                    let ret_ty = f
                        .syntax()
                        .children()
                        .find(|c| is_type_node(c.kind()))
                        .map_or(Ty::Unit, |t| {
                            parse_type_node_with_user_types(&t, &user_types)
                        });
                    lower_env.fn_ret_tys.insert(fn_name, ret_ty.clone());
                    lower_env.fn_ret_tys.insert(canonical_fn, ret_ty);
                }
            }
            _ => {}
        }
    }

    ModuleEnvSummary {
        module_path: module_path.clone(),
        const_tys: lower_env.const_tys,
        table_fields: lower_env.table_fields,
        curve_ret_tys: lower_env.curve_ret_tys,
        fn_ret_tys: lower_env.fn_ret_tys,
        objects: lower_env.objects,
        sparse_components: lower_env.sparse_components,
        authorities,
        layouts,
        enums,
        field_to_stratum,
        user_types,
        item_fields,
    }
}

/// Lowers and lints a single detached top-level item [`rowan::GreenNode`] against `env`.
pub(crate) fn analyze_item_from_green(
    file: &str,
    green: &rowan::GreenNode,
    env: &ModuleEnvSummary,
) -> SingleItemAnalysis {
    let root = SyntaxNode::new_root(green.clone());
    let Some(item) = ast::Item::cast(root) else {
        return SingleItemAnalysis::Other;
    };
    let item_src = item.syntax().text().to_string();
    let lower_env = LowerEnv {
        module_path: &env.module_path,
        layouts: &env.layouts,
        item_fields: &env.item_fields,
        user_types: &env.user_types,
        field_to_stratum: &env.field_to_stratum,
        enums: &env.enums,
        const_tys: env.const_tys.clone(),
        table_fields: env.table_fields.clone(),
        curve_ret_tys: env.curve_ret_tys.clone(),
        fn_ret_tys: env.fn_ret_tys.clone(),
        objects: env.objects.clone(),
        sparse_components: env.sparse_components.clone(),
        authorities: env.authorities.clone(),
    };
    let mut diags = Vec::new();
    match item {
        ast::Item::Timeline(tl) => SingleItemAnalysis::Timeline {
            item: analyze_timeline(
                file,
                &item_src,
                &env.module_path,
                tl.syntax(),
                &env.layouts,
                &lower_env,
                &mut diags,
            ),
            diags,
        },
        ast::Item::Task(tk) => SingleItemAnalysis::Task {
            item: analyze_task(
                file,
                &item_src,
                &env.module_path,
                tk.syntax(),
                &env.layouts,
                &lower_env,
                &mut diags,
            ),
            diags,
        },
        ast::Item::Fsm(fm) => SingleItemAnalysis::Fsm {
            item: analyze_fsm(
                file,
                &item_src,
                &env.module_path,
                fm.syntax(),
                &env.layouts,
                &lower_env,
                &mut diags,
            ),
            diags,
        },
        ast::Item::Sys(sy) => SingleItemAnalysis::Callable {
            item: analyze_callable(
                file,
                &item_src,
                sy.syntax(),
                false,
                &lower_env,
                &env.layouts,
                &mut diags,
            ),
            diags,
        },
        ast::Item::Obs(ob) => SingleItemAnalysis::Callable {
            item: analyze_callable(
                file,
                &item_src,
                ob.syntax(),
                true,
                &lower_env,
                &env.layouts,
                &mut diags,
            ),
            diags,
        },
        ast::Item::Fn(f) => SingleItemAnalysis::Fn {
            item: analyze_fn(file, &item_src, f.syntax(), &lower_env, &mut diags),
            diags,
        },
        ast::Item::Migrate(mg) => SingleItemAnalysis::Migrate {
            item: analyze_migrate(mg.syntax(), &lower_env),
            diags,
        },
        ast::Item::Schedule(sc) => SingleItemAnalysis::Schedule {
            item: analyze_schedule(sc.syntax(), &lower_env),
            diags,
        },
        ast::Item::SimTest(st) => SingleItemAnalysis::SimTest {
            item: analyze_sim_test(file, &item_src, st.syntax(), &lower_env, &mut diags),
            diags,
        },
        ast::Item::NetSimTest(nst) => SingleItemAnalysis::NetSimTest {
            item: analyze_net_sim_test(file, &item_src, &nst, &lower_env, &mut diags),
            diags,
        },
        ast::Item::AssertLayout(al) => {
            evaluate_assert_layout(
                file,
                &item_src,
                al.syntax(),
                &env.module_path,
                &env.layouts,
                &mut diags,
            );
            SingleItemAnalysis::AssertLayout { diags }
        }
        _ => SingleItemAnalysis::Other,
    }
}

/// Assembles a complete [`AnalyzedModule`] from the cached [`strata_syntax::Parse`],
/// [`ModuleEnvSummary`], and per-item [`SingleItemAnalysis`] results.
pub(crate) fn assemble_analyzed_module(
    file: &str,
    src: &str,
    parsed: &strata_syntax::Parse,
    env_summary: &ModuleEnvSummary,
    per_item: &[(u32, &SingleItemAnalysis)],
) -> AnalyzedModule {
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

    let Some(sf) = SourceFile::cast(parsed.syntax()) else {
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
            rpcs: Vec::new(),
            net_sim_tests: Vec::new(),
            net_components: Vec::new(),
            net_schema_fingerprint: 0,
            node_groups: IndexMap::new(),
            pure_fns: Vec::new(),
            authorities: IndexMap::new(),
        };
    };

    let mut layout_env = LayoutEnv {
        resolved: IndexMap::new(),
        enums: enums.clone(),
    };
    for (canon, layout) in &layouts {
        let short = canon.rsplit("::").next().unwrap_or(canon).to_owned();
        layout_env.resolved.insert(
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

    let lower_env = LowerEnv {
        module_path: &module_path,
        layouts: &layouts,
        item_fields: &env_summary.item_fields,
        user_types: &env_summary.user_types,
        field_to_stratum: &field_to_stratum,
        enums: &enums,
        const_tys: env_summary.const_tys.clone(),
        table_fields: env_summary.table_fields.clone(),
        curve_ret_tys: env_summary.curve_ret_tys.clone(),
        fn_ret_tys: env_summary.fn_ret_tys.clone(),
        objects: env_summary.objects.clone(),
        sparse_components: env_summary.sparse_components.clone(),
        authorities: env_summary.authorities.clone(),
    };

    let mut tags = Vec::new();
    let mut consts = Vec::new();
    let mut const_ranges = Vec::new();
    let mut tables = Vec::new();
    let mut curves = Vec::new();
    let mut relations = Vec::new();
    let mut spatial_indices = Vec::new();
    let mut objects = Vec::new();
    let mut obj_ranges = Vec::new();
    let mut rpcs = Vec::new();
    let mut seen_rpcs = HashSet::new();
    let mut all_user_fns = HashSet::new();
    let mut pure_fns_set = HashSet::new();
    let mut pure_fns = Vec::new();
    let mut node_groups: IndexMap<String, String> = IndexMap::new();
    let mut net_components: Vec<NetComponentMeta> = Vec::new();
    let struct_quantizes = collect_struct_quantize_map(&sf);

    validate_all_attributes(file, src, &sf, &mut diags);

    for item in sf.items() {
        record_item_node_group(&module_path, &item, &mut node_groups);
        match &item {
            ast::Item::Component(comp) => {
                let short = comp
                    .name()
                    .map_or_else(|| "Component".to_owned(), |t| t.text().to_owned());
                let (auth, is_pred) = extract_item_authority(comp.syntax());
                if let Some(meta) = collect_net_component_meta(
                    &module_path,
                    &short,
                    comp.syntax(),
                    false,
                    auth,
                    is_pred,
                    &struct_quantizes,
                ) {
                    net_components.push(meta);
                }
            }
            ast::Item::Resource(res) => {
                let short = res
                    .name()
                    .map_or_else(|| "Resource".to_owned(), |t| t.text().to_owned());
                let (auth, is_pred) = extract_item_authority(res.syntax());
                if let Some(meta) = collect_net_component_meta(
                    &module_path,
                    &short,
                    res.syntax(),
                    true,
                    auth,
                    is_pred,
                    &struct_quantizes,
                ) {
                    net_components.push(meta);
                }
            }
            ast::Item::Rpc(rpc) => {
                let short = rpc
                    .name()
                    .map_or_else(|| "Rpc".to_owned(), |t| t.text().to_owned());
                if !seen_rpcs.insert(short.clone()) {
                    diags.push(Diagnostic::error(
                        codes::E0303_DUPLICATE_SYMBOL,
                        Span::from_range(file, src, rpc.syntax().text_range()),
                        format!("duplicate rpc declaration `{short}`"),
                        None,
                    ));
                } else {
                    rpcs.push(analyze_rpc(
                        &module_path,
                        rpc,
                        &mut layout_env,
                        &struct_quantizes,
                    ));
                }
            }
            _ => {}
        }
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
                    const_ranges.push(c.syntax().text_range());
                    consts.push(hc);
                }
            }
            ast::Item::Table(tb) => {
                tables.push(analyze_table(
                    file,
                    src,
                    tb.syntax(),
                    &enums,
                    &lower_env,
                    &mut diags,
                ));
            }
            ast::Item::Curve(cv) => {
                curves.push(analyze_curve(
                    file,
                    src,
                    cv.syntax(),
                    &lower_env,
                    &mut diags,
                ));
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
                obj_ranges.push(obj.syntax().text_range());
                objects.push(analyze_object(obj.syntax(), &lower_env));
            }
            ast::Item::Fn(f) => {
                if let Some(fname) = ast::first_ident(f.syntax()) {
                    let fn_name = fname.text().to_owned();
                    let canonical_fn = format!("{module_path}::{fn_name}");
                    all_user_fns.insert(fn_name.clone());
                    all_user_fns.insert(canonical_fn.clone());
                    if has_attr_name(f.syntax(), "node_pure") {
                        pure_fns_set.insert(fn_name.clone());
                        pure_fns_set.insert(canonical_fn);
                        pure_fns.push(fn_name);
                    }
                }
            }
            _ => {}
        }
    }

    validate_const_inits(file, src, &consts, &const_ranges, &lower_env, &mut diags);
    for (ho, range) in objects.iter().zip(obj_ranges.iter().copied()) {
        validate_object_const_inits(file, src, range, ho, &lower_env, &consts, &mut diags);
    }
    let field_defaults = collect_field_defaults(&sf, &module_path, &layouts, &lower_env);

    let shift_diag = |offset: u32, d: &Diagnostic| -> Diagnostic {
        let mut out = d.clone();
        let abs_s = d.span.byte_start.saturating_add(offset);
        let abs_e = d.span.byte_end.saturating_add(offset);
        out.span = Span::from_bytes(file, src, abs_s, abs_e);
        if let Some(ref mut fx) = out.fixit {
            fx.replace_byte_start = fx.replace_byte_start.saturating_add(offset);
            fx.replace_byte_end = fx.replace_byte_end.saturating_add(offset);
        }
        out
    };

    let mut timelines = Vec::new();
    let mut tasks = Vec::new();
    let mut fsms = Vec::new();
    let mut callables = Vec::new();
    let mut fns = Vec::new();
    let mut migrations = Vec::new();
    let mut schedules = Vec::new();
    let mut sim_tests = Vec::new();
    let mut net_sim_tests = Vec::new();

    for &(offset, item_res) in per_item {
        match item_res {
            SingleItemAnalysis::Timeline { item, diags: ds } => {
                timelines.push(item.clone());
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Task { item, diags: ds } => {
                let mut t = item.clone();
                for q in &mut t.access.queries {
                    q.byte_start = q.byte_start.saturating_add(offset);
                    q.byte_end = q.byte_end.saturating_add(offset);
                    for tm in &mut q.terms {
                        tm.byte_start = tm.byte_start.saturating_add(offset);
                        tm.byte_end = tm.byte_end.saturating_add(offset);
                    }
                }
                tasks.push(t);
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Fsm { item, diags: ds } => {
                let mut f = item.clone();
                for q in &mut f.access.queries {
                    q.byte_start = q.byte_start.saturating_add(offset);
                    q.byte_end = q.byte_end.saturating_add(offset);
                    for tm in &mut q.terms {
                        tm.byte_start = tm.byte_start.saturating_add(offset);
                        tm.byte_end = tm.byte_end.saturating_add(offset);
                    }
                }
                fsms.push(f);
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Callable { item, diags: ds } => {
                let mut c = item.clone();
                c.byte_range = (
                    c.byte_range.0.saturating_add(offset),
                    c.byte_range.1.saturating_add(offset),
                );
                for q in &mut c.access.queries {
                    q.byte_start = q.byte_start.saturating_add(offset);
                    q.byte_end = q.byte_end.saturating_add(offset);
                    for tm in &mut q.terms {
                        tm.byte_start = tm.byte_start.saturating_add(offset);
                        tm.byte_end = tm.byte_end.saturating_add(offset);
                    }
                }
                callables.push(c);
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Fn { item, diags: ds } => {
                let mut f = item.clone();
                f.byte_range = (
                    f.byte_range.0.saturating_add(offset),
                    f.byte_range.1.saturating_add(offset),
                );
                fns.push(f);
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Migrate { item, diags: ds } => {
                migrations.push(item.clone());
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Schedule { item, diags: ds } => {
                schedules.push(item.clone());
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::SimTest { item, diags: ds } => {
                sim_tests.push(item.clone());
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::NetSimTest { item, diags: ds } => {
                net_sim_tests.push(item.clone());
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::AssertLayout { diags: ds } => {
                diags.extend(ds.iter().map(|d| shift_diag(offset, d)));
            }
            SingleItemAnalysis::Other => {}
        }
    }

    for (item, hf) in sf
        .items()
        .filter_map(|it| match it {
            ast::Item::Fn(f) => Some(f),
            _ => None,
        })
        .zip(fns.iter())
    {
        if hf.is_node_pure {
            validate_node_pure_fn(
                file,
                src,
                item.syntax(),
                hf,
                &all_user_fns,
                &pure_fns_set,
                &mut diags,
            );
        }
    }

    type_check::validate_module_types(
        file,
        src,
        &sf,
        &lower_env,
        &consts,
        &objects,
        &field_defaults,
        &fns,
        &callables,
        &tasks,
        &fsms,
        &timelines,
        &sim_tests,
        &net_sim_tests,
        &mut diags,
    );

    let server_res_items = collect_server_res_usages(&sf, &module_path);
    crate::authority::validate_module_authority(
        file,
        src,
        &module_path,
        &env_summary.authorities,
        &layouts,
        &enums,
        &env_summary.item_fields,
        &fns,
        &callables,
        &tasks,
        &fsms,
        &timelines,
        &objects,
        &server_res_items,
        &mut diags,
    );

    finalize_effects_par_and_aliasing(
        file,
        src,
        &fns,
        &mut callables,
        &mut tasks,
        &mut fsms,
        &timelines,
        &layouts,
        &mut diags,
    );

    let mut all_access: Vec<FilteredAccessSet> =
        callables.iter().map(|c| c.access.clone()).collect();
    all_access.extend(tasks.iter().map(|t| t.access.clone()));
    all_access.extend(fsms.iter().map(|f| f.access.clone()));
    let concurrency_graph = build_concurrency_graph(&all_access);

    for item in sf.items() {
        if let ast::Item::AssertPar(ap) = item {
            evaluate_assert_par(file, src, ap.syntax(), &all_access, &mut diags);
        }
    }

    let net_schema_fingerprint =
        compute_net_schema_fingerprint(&module_path, &layouts, &net_components, &rpcs);

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
        rpcs,
        net_sim_tests,
        net_components,
        net_schema_fingerprint,
        node_groups,
        pure_fns,
        authorities: env_summary.authorities.clone(),
    }
}

fn collect_server_res_usages(sf: &ast::SourceFile, module_path: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for item in sf.items() {
        let node = match item {
            ast::Item::Fn(n) => n.syntax().clone(),
            ast::Item::Sys(n) => n.syntax().clone(),
            ast::Item::Obs(n) => n.syntax().clone(),
            ast::Item::Task(n) => n.syntax().clone(),
            ast::Item::Fsm(n) => n.syntax().clone(),
            ast::Item::Timeline(n) => n.syntax().clone(),
            _ => continue,
        };
        let has_server_res = node.descendants().any(|d| {
            d.kind() == strata_syntax::SyntaxKind::PostfixCallExpr
                && d.first_child().is_some_and(|fc| {
                    fc.kind() == strata_syntax::SyntaxKind::PathExpr
                        && fc.text().to_string().trim() == "server_res"
                })
        });
        if has_server_res && let Some(ident) = ast::first_ident(&node) {
            let short = ident.text().to_owned();
            out.insert(format!("{module_path}::{short}"));
            out.insert(short);
        }
    }
    out
}
