//! Strict ISO C99 backend (`bamabi` ABI `0.3.0`, C99 `-std=c99 -Wall -Wextra -Wpedantic -Werror`).
//!
//! Consumes [`MirModule`] and [`MirFunction`] SSA CFGs directly (`blocks`, `locals`,
//! `query_bindings`, `resources`, `layouts`, `tables`, `curves`, `relations`,
//! `spatial_indices`, `objects`, `schedules`, `fns`) with zero `expr.rs` usage.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use bamabi_sys::{ComponentUuid, MAX_QUERIES_PER_SYSTEM, MAX_TERMS_PER_QUERY, fnv1a_64_str};
use strata_mir::ir::{
    BasicBlock, BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirStmt,
    MirType, Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{HirCompInit, HirExpr, HirObject, HirScheduleGroup, HirUnOp};
use strata_sema::layout::{SchemaItemKind, SolvedField, SolvedLayout};
use strata_sema::types::Ty;

use crate::{
    CodegenError, GeneratedArtifact, GeneratedFile, TargetKind, find_layout, is_ecs_component_kind,
    module_stem, sanitize_ident, system_schedule_label,
};

/// Emit a strict ISO C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) source file
/// and companion `bamabi.h` header from a verified [`MirModule`].
pub fn emit(mir: &MirModule) -> Result<GeneratedArtifact, CodegenError> {
    let mut ctx = EmitCtx::new(mir)?;
    ctx.emit_all()?;
    let stem = module_stem(&mir.module_path);
    Ok(GeneratedArtifact {
        target: TargetKind::C99,
        module_name: mir.module_path.clone(),
        files: vec![
            GeneratedFile {
                path: "bamabi.h".to_string(),
                content: crate::emit_bamabi_header(),
            },
            GeneratedFile {
                path: format!("{stem}.c"),
                content: ctx.out,
            },
        ],
    })
}

#[derive(Clone, Debug)]
struct RegComponent {
    idx: usize,
    canonical: String,
    short: String,
    layout_idx: Option<usize>,
    item_kind: Option<SchemaItemKind>,
    has_mod_res: bool,
    size: usize,
    align: usize,
    uuid: ComponentUuid,
    fingerprint: u64,
    flags: u32,
    migration_fn: Option<String>,
    required_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct RegRelation {
    idx: usize,
    canonical: String,
    flags_expr: String,
    uuid: ComponentUuid,
    data_size: usize,
    data_align: usize,
    max_degree: u32,
}

#[derive(Clone, Debug)]
struct RegObject {
    primary_comp_idx: Option<usize>,
}

#[derive(Clone, Debug)]
struct RegScheduleSet {
    idx: usize,
    name: String,
    schedule: &'static str,
    flags_expr: &'static str,
    after_sets: Vec<String>,
}

#[derive(Clone, Debug)]
struct RegSystem {
    idx: usize,
    mir_fn_idx: Option<usize>,
    c_fn_name: String,
    reg_name: String,
    schedule: &'static str,
    flags_expr: String,
    after_names: Vec<String>,
    in_sets: Vec<String>,
    run_if_fn: Option<String>,
    run_if_resources: Vec<usize>,
    is_startup_objects: bool,
}

#[derive(Clone, Debug)]
struct RegObserver {
    c_fn_name: String,
    reg_name: String,
    event_comp_idx: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PtrKind {
    LayoutPtr { layout_idx: usize, is_mut: bool },
    EntitySlice,
    SparseRows { is_mut: bool },
    ScalarPtr { c_pointee: String, is_mut: bool },
}

impl PtrKind {
    fn c_type(&self, layout_c_names: &[String]) -> String {
        match self {
            Self::LayoutPtr { layout_idx, is_mut } => {
                if *is_mut {
                    format!("{}*", layout_c_names[*layout_idx])
                } else {
                    format!("const {}*", layout_c_names[*layout_idx])
                }
            }
            Self::EntitySlice => "const BamEntity*".to_string(),
            Self::SparseRows { is_mut } => {
                if *is_mut {
                    "void*".to_string()
                } else {
                    "const void*".to_string()
                }
            }
            Self::ScalarPtr { c_pointee, is_mut } => {
                if *is_mut {
                    format!("{c_pointee}*")
                } else {
                    format!("const {c_pointee}*")
                }
            }
        }
    }

    fn is_mut(&self) -> bool {
        match self {
            Self::LayoutPtr { is_mut, .. }
            | Self::SparseRows { is_mut }
            | Self::ScalarPtr { is_mut, .. } => *is_mut,
            Self::EntitySlice => false,
        }
    }
}

struct EmitCtx<'a> {
    mir: &'a MirModule,
    out: String,
    layouts: &'a [SolvedLayout],
    layout_by_key: HashMap<String, usize>,
    layout_c_names: Vec<String>,
    components: Vec<RegComponent>,
    comp_by_key: HashMap<String, usize>,
    relations: Vec<RegRelation>,
    rel_by_key: HashMap<String, usize>,
    objects: Vec<RegObject>,
    obj_by_name: HashMap<String, usize>,
    sets: Vec<RegScheduleSet>,
    systems: Vec<RegSystem>,
    observers: Vec<RegObserver>,
    helper_by_name: HashMap<String, usize>,
    tuple_types: Vec<(Vec<MirType>, String)>,
    array_types: Vec<(MirType, usize, String)>,
    run_if_wrappers: Vec<String>,
}

impl<'a> EmitCtx<'a> {
    fn new(mir: &'a MirModule) -> Result<Self, CodegenError> {
        let layouts = &mir.layouts;
        let mut layout_by_key = HashMap::new();
        let mut layout_c_names = Vec::with_capacity(layouts.len());

        for (idx, l) in layouts.iter().enumerate() {
            let short = short_name(&l.canonical_name);
            let ident = sanitize_ident(short);
            let cname = format!("StrataType_{idx}_{ident}");
            layout_c_names.push(cname);
            layout_by_key.insert(l.canonical_name.clone(), idx);
            layout_by_key.insert(short.to_string(), idx);
        }

        let mut ctx = Self {
            mir,
            out: String::with_capacity(32 * 1024),
            layouts,
            layout_by_key,
            layout_c_names,
            components: Vec::new(),
            comp_by_key: HashMap::new(),
            relations: Vec::new(),
            rel_by_key: HashMap::new(),
            objects: Vec::new(),
            obj_by_name: HashMap::new(),
            sets: Vec::new(),
            systems: Vec::new(),
            observers: Vec::new(),
            helper_by_name: HashMap::new(),
            tuple_types: Vec::new(),
            array_types: Vec::new(),
            run_if_wrappers: Vec::new(),
        };
        ctx.collect_registries()?;
        Ok(ctx)
    }

    fn mir_functions(&self) -> &[MirFunction] {
        if !self.mir.fns.is_empty() {
            &self.mir.fns
        } else {
            &self.mir.functions
        }
    }

    fn collect_registries(&mut self) -> Result<(), CodegenError> {
        // 1. Collect migrations and helper functions.
        let mut mig_map: HashMap<String, String> = HashMap::new();
        let fns_ref = if !self.mir.fns.is_empty() {
            &self.mir.fns
        } else {
            &self.mir.functions
        };
        for (fn_idx, f) in fns_ref.iter().enumerate() {
            match &f.kind {
                MirFnKind::Migration { component, .. } => {
                    let c_fn = format!("strata_mig_{}", sanitize_ident(&f.name));
                    mig_map.insert(component.clone(), c_fn.clone());
                    mig_map.insert(short_name(component).to_string(), c_fn);
                }
                MirFnKind::HelperFn => {
                    self.helper_by_name.insert(f.name.clone(), fn_idx);
                }
                _ => {}
            }
        }

        // 2. Register ECS layouts.
        for (l_idx, layout) in self.layouts.iter().enumerate() {
            if is_ecs_component_kind(layout.item_kind)
                || matches!(
                    layout.item_kind,
                    SchemaItemKind::Resource
                        | SchemaItemKind::Event
                        | SchemaItemKind::Stream
                        | SchemaItemKind::SpatialGrid
                        | SchemaItemKind::SpatialHistory
                )
            {
                let short = short_name(&layout.canonical_name).to_string();
                let mig_fn = mig_map
                    .get(&layout.canonical_name)
                    .or_else(|| mig_map.get(&short))
                    .cloned();
                let uuid = ComponentUuid::from_bytes(layout.uuid_bytes);
                let has_mod_res = matches!(
                    layout.item_kind,
                    SchemaItemKind::Resource
                        | SchemaItemKind::SpatialGrid
                        | SchemaItemKind::SpatialHistory
                ) && layout.size > 0;
                self.insert_component(RegComponent {
                    idx: self.components.len(),
                    canonical: layout.canonical_name.clone(),
                    short,
                    layout_idx: Some(l_idx),
                    item_kind: Some(layout.item_kind),
                    has_mod_res,
                    size: layout.size,
                    align: layout.align.max(1),
                    uuid,
                    fingerprint: layout.schema_fingerprint,
                    flags: layout.component_flags,
                    migration_fn: mig_fn,
                    required_indices: Vec::new(),
                });
            }
        }

        // 3. Collect ZST tags and any referenced unregistered components/resources/events/streams.
        let mut extra_tags: BTreeSet<String> = BTreeSet::new();
        for layout in self.layouts {
            for req in &layout.required_components {
                extra_tags.insert(req.clone());
            }
        }
        for obj in &self.mir.objects {
            for c in &obj.components {
                extra_tags.insert(c.clone());
            }
            for ci in &obj.inits {
                extra_tags.insert(
                    ci.canonical_component
                        .clone()
                        .unwrap_or_else(|| ci.component.clone()),
                );
            }
        }
        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        for f in &fns_snapshot {
            for qb in &f.query_bindings {
                for t in &qb.terms {
                    extra_tags.insert(t.canonical_component.clone());
                }
                for w in &qb.with_filters {
                    extra_tags.insert(w.clone());
                }
                for wo in &qb.without_filters {
                    extra_tags.insert(wo.clone());
                }
            }
            for r in &f.resources {
                extra_tags.insert(r.canonical_name.clone());
            }
            if let MirFnKind::Observer { event, target_comp } = &f.kind {
                extra_tags.insert(event.clone());
                if let Some(tc) = target_comp {
                    extra_tags.insert(tc.clone());
                }
            }
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    collect_inst_components(&stmt.inst, &mut extra_tags);
                }
            }
        }
        for tag in extra_tags {
            if self.find_comp_idx(&tag).is_none() {
                if let Some((prefix, _)) = tag.rsplit_once("::")
                    && self.find_comp_idx(prefix).is_some()
                {
                    continue;
                }
                let canon = canonicalize(&self.mir.module_path, &tag);
                let short = short_name(&canon).to_string();
                let uuid = ComponentUuid::from_parts(&canon, 0, 1, 0);
                let fp = fnv1a_64_str(&canon);
                let mig_fn = mig_map.get(&canon).or_else(|| mig_map.get(&short)).cloned();
                self.insert_component(RegComponent {
                    idx: self.components.len(),
                    canonical: canon,
                    short,
                    layout_idx: None,
                    item_kind: None,
                    has_mod_res: false,
                    size: 0,
                    align: 1,
                    uuid,
                    fingerprint: fp,
                    flags: 0,
                    migration_fn: mig_fn,
                    required_indices: Vec::new(),
                });
            }
        }

        // Resolve @require indices.
        let mut req_pairs: Vec<(usize, Vec<usize>)> = Vec::new();
        for c in &self.components {
            if let Some(l_idx) = c.layout_idx {
                let mut reqs = Vec::new();
                for req_name in &self.layouts[l_idx].required_components {
                    if let Some(r_idx) = self.find_comp_idx(req_name) {
                        reqs.push(r_idx);
                    }
                }
                req_pairs.push((c.idx, reqs));
            }
        }
        for (c_idx, reqs) in req_pairs {
            self.components[c_idx].required_indices = reqs;
        }

        // 4. Relations.
        for rel in &self.mir.relations {
            let layout_opt = rel
                .payload_layout
                .as_ref()
                .or_else(|| find_layout(self.mir, &rel.canonical_name))
                .or_else(|| find_layout(self.mir, &rel.name));
            let (data_size, data_align) =
                layout_opt.map_or((0usize, 1usize), |l| (l.size, l.align.max(1)));
            let mut flags = Vec::new();
            let mut max_degree = 0u32;
            for fl in &rel.flags {
                let low = fl.to_ascii_lowercase();
                if low.contains("exclusive") {
                    flags.push("BAM_RELATION_FLAG_EXCLUSIVE");
                } else if low.contains("cascade") {
                    flags.push("BAM_RELATION_FLAG_CASCADE_DESPAWN");
                } else if low.contains("symmetric") {
                    flags.push("BAM_RELATION_FLAG_SYMMETRIC");
                } else if low.contains("acyclic") {
                    flags.push("BAM_RELATION_FLAG_ACYCLIC");
                } else if low.contains("cleanup") {
                    flags.push("BAM_RELATION_FLAG_CLEANUP_REMOVE");
                } else if let Some(rest) = low.strip_prefix("max_degree") {
                    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = digits.parse::<u32>() {
                        max_degree = n;
                    }
                }
            }
            let flags_expr = if flags.is_empty() {
                "0u".to_string()
            } else {
                flags.join(" | ")
            };
            let uuid = ComponentUuid::from_parts(&rel.canonical_name, data_size, data_align, 0);
            let idx = self.relations.len();
            self.rel_by_key.insert(rel.canonical_name.clone(), idx);
            self.rel_by_key.insert(rel.name.clone(), idx);
            self.relations.push(RegRelation {
                idx,
                canonical: rel.canonical_name.clone(),
                flags_expr,
                uuid,
                data_size,
                data_align,
                max_degree,
            });
        }

        // 5. Named objects.
        for obj in &self.mir.objects {
            let idx = self.objects.len();
            let primary_comp_idx = obj
                .components
                .first()
                .and_then(|c| self.find_comp_idx(c))
                .or_else(|| {
                    obj.inits.first().and_then(|i| {
                        i.canonical_component
                            .as_deref()
                            .and_then(|cc| self.find_comp_idx(cc))
                            .or_else(|| self.find_comp_idx(&i.component))
                    })
                });
            self.obj_by_name.insert(obj.name.clone(), idx);
            self.objects.push(RegObject { primary_comp_idx });
        }

        // 6. Schedules, schedule sets, systems, observers.
        self.collect_schedules_and_systems()?;

        // 7. Collect synthetic Tuple / Array C types.
        self.collect_composite_types();
        Ok(())
    }

    fn insert_component(&mut self, comp: RegComponent) {
        let idx = comp.idx;
        self.comp_by_key.insert(comp.canonical.clone(), idx);
        self.comp_by_key.insert(comp.short.clone(), idx);
        self.components.push(comp);
    }

    fn find_comp_idx(&self, key: &str) -> Option<usize> {
        self.comp_by_key
            .get(key)
            .copied()
            .or_else(|| self.comp_by_key.get(short_name(key)).copied())
    }

    fn find_rel_idx(&self, key: &str) -> Option<usize> {
        self.rel_by_key
            .get(key)
            .copied()
            .or_else(|| self.rel_by_key.get(short_name(key)).copied())
    }

    fn find_layout_idx(&self, key: &str) -> Option<usize> {
        self.layout_by_key
            .get(key)
            .copied()
            .or_else(|| self.layout_by_key.get(short_name(key)).copied())
    }

    fn collect_schedules_and_systems(&mut self) -> Result<(), CodegenError> {
        let mut sys_sets: HashMap<String, Vec<String>> = HashMap::new();
        let mut sys_after: HashMap<String, Vec<String>> = HashMap::new();

        for sched in &self.mir.schedules {
            let sched_c = c_schedule_const(&sched.label);
            let mut prev_set_name: Option<String> = None;
            for node in &sched.nodes {
                self.walk_schedule_node(
                    node,
                    sched_c,
                    &mut prev_set_name,
                    None,
                    &mut sys_sets,
                    &mut sys_after,
                );
            }
        }

        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        let mut timer_tick_reg_name: Option<String> = None;
        for f in &fns_snapshot {
            if matches!(f.kind, MirFnKind::SynthesizedTimerTick) {
                timer_tick_reg_name = Some(format!("{}::{}", self.mir.module_path, f.name));
                break;
            }
        }

        if !self.mir.objects.is_empty() {
            let idx = self.systems.len();
            self.systems.push(RegSystem {
                idx,
                mir_fn_idx: None,
                c_fn_name: "strata_sys_startup_objects".to_string(),
                reg_name: format!("{}::__strata_startup_objects", self.mir.module_path),
                schedule: "BAM_SCHEDULE_STARTUP",
                flags_expr: "BAM_SYSTEM_FLAG_MAIN_THREAD".to_string(),
                after_names: Vec::new(),
                in_sets: Vec::new(),
                run_if_fn: None,
                run_if_resources: Vec::new(),
                is_startup_objects: true,
            });
        }

        for (fn_idx, f) in fns_snapshot.iter().enumerate() {
            match &f.kind {
                MirFnKind::System
                | MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick => {
                    let is_timer_tick = matches!(f.kind, MirFnKind::SynthesizedTimerTick);
                    let sched_label = if is_timer_tick {
                        "FixedUpdate"
                    } else {
                        system_schedule_label(self.mir, &f.name)
                    };
                    let sched_c = c_schedule_const(sched_label);
                    let reg_name = format!("{}::{}", self.mir.module_path, f.name);
                    let c_fn_name = format!("strata_sys_{}", sanitize_ident(&f.name));
                    let mut after_names = sys_after.remove(&f.name).unwrap_or_default();
                    if !is_timer_tick
                        && sched_c == "BAM_SCHEDULE_FIXED_UPDATE"
                        && let Some(ref tt_name) = timer_tick_reg_name
                        && !after_names.contains(tt_name)
                    {
                        after_names.push(tt_name.clone());
                    }
                    let in_sets = sys_sets.remove(&f.name).unwrap_or_default();
                    let run_if_fn = self.schedule_run_if_for(sched_label, fn_idx);
                    let run_if_resources = run_if_fn
                        .as_ref()
                        .map(|(_, r)| r.clone())
                        .unwrap_or_default();
                    let run_if_name = run_if_fn.map(|(n, _)| n);
                    let idx = self.systems.len();
                    self.systems.push(RegSystem {
                        idx,
                        mir_fn_idx: Some(fn_idx),
                        c_fn_name,
                        reg_name,
                        schedule: sched_c,
                        flags_expr: "0u".to_string(),
                        after_names,
                        in_sets,
                        run_if_fn: run_if_name,
                        run_if_resources,
                        is_startup_objects: false,
                    });
                }
                MirFnKind::Observer { event, .. } => {
                    let event_comp_idx =
                        self.find_comp_idx(event)
                            .ok_or_else(|| CodegenError::Unsupported {
                                context: format!("c99::observer({})", f.name),
                                detail: format!("unregistered trigger event `{event}`"),
                            })?;
                    self.observers.push(RegObserver {
                        c_fn_name: format!("strata_obs_{}", sanitize_ident(&f.name)),
                        reg_name: format!("{}::{}", self.mir.module_path, f.name),
                        event_comp_idx,
                    });
                }
                MirFnKind::HelperFn | MirFnKind::Migration { .. } => {}
            }
        }
        Ok(())
    }

    fn schedule_run_if_for(
        &mut self,
        sched_label: &str,
        sys_idx: usize,
    ) -> Option<(String, Vec<usize>)> {
        let sched = self
            .mir
            .schedules
            .iter()
            .find(|s| s.label.eq_ignore_ascii_case(sched_label))?;
        let cond_expr = sched.run_if.as_deref()?;
        let mut res_indices = Vec::new();
        for c in &self.components {
            if c.layout_idx
                .is_some_and(|li| matches!(self.layouts[li].item_kind, SchemaItemKind::Resource))
                && (cond_expr.contains(&c.short) || cond_expr.contains(&c.canonical))
            {
                res_indices.push(c.idx);
            }
        }
        if res_indices.is_empty() {
            return None;
        }
        let fn_name = format!("strata_run_if_{}_{}", sanitize_ident(sched_label), sys_idx);
        let cond_c = self.translate_run_if_expr(cond_expr, &res_indices);
        let mut body = String::new();
        let _ = writeln!(
            body,
            "static BAM_UNUSED BamResult {fn_name}(BamSystemCtx* sys_ctx, void* user_data) {{"
        );
        let _ = writeln!(
            body,
            "    const StrataModState* state = (const StrataModState*)user_data;"
        );
        let _ = writeln!(body, "    if (state == NULL || state->api == NULL) {{");
        let _ = writeln!(body, "        return BAM_RESULT_OK;");
        let _ = writeln!(body, "    }}");
        for &r_idx in &res_indices {
            if let Some(l_idx) = self.components[r_idx].layout_idx {
                let cty = &self.layout_c_names[l_idx];
                let short = sanitize_ident(&self.components[r_idx].short);
                let _ = writeln!(
                    body,
                    "    const {cty}* res_{short} = (state->res_flags[{r_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? (const {cty}*)state->api->sys_res_ptr(sys_ctx, state->components[{r_idx}], NULL) : NULL;"
                );
                if self.components[r_idx].has_mod_res {
                    let _ = writeln!(
                        body,
                        "    if (res_{short} == NULL) {{ res_{short} = &state->mod_res_{r_idx}; }}"
                    );
                } else {
                    let _ = writeln!(
                        body,
                        "    if (res_{short} == NULL) {{ return BAM_RESULT_INVALID_STATE; }}"
                    );
                }
            }
        }
        let _ = writeln!(
            body,
            "    return ({cond_c}) ? BAM_RESULT_OK : BAM_RESULT_INVALID_STATE;"
        );
        let _ = writeln!(body, "}}");
        self.run_if_wrappers.push(body);
        Some((fn_name, res_indices))
    }

    fn translate_run_if_expr(&self, expr: &str, res_indices: &[usize]) -> String {
        let mut s = expr.trim();
        if let Some(inner) = s.strip_prefix("run_if(").and_then(|r| r.strip_suffix(')')) {
            s = inner.trim();
        }
        let mut s = s.to_string();
        for &r_idx in res_indices {
            let short = &self.components[r_idx].short;
            let ident = sanitize_ident(short);
            s = s.replace(&format!("res<{short}>()."), &format!("res_{ident}->"));
            s = s.replace(&format!("res::<{short}>()."), &format!("res_{ident}->"));
        }
        for unit in ["_ms", "_sec", "_s", "_px", "_m"] {
            s = s.replace(unit, "f");
        }
        if s.is_empty() || (s.contains('<') && !s.contains("<=") && !s.contains("->")) {
            if let Some(&first) = res_indices.first() {
                let short = sanitize_ident(&self.components[first].short);
                return format!("(res_{short} != NULL)");
            }
            return "1".to_string();
        }
        s
    }

    fn walk_schedule_node(
        &mut self,
        node: &HirScheduleGroup,
        sched_c: &'static str,
        prev_sibling: &mut Option<String>,
        parent_set: Option<&str>,
        sys_sets: &mut HashMap<String, Vec<String>>,
        sys_after: &mut HashMap<String, Vec<String>>,
    ) {
        match node.kind.as_str() {
            "leaf" => {
                if let Some(pset) = parent_set {
                    sys_sets
                        .entry(node.name.clone())
                        .or_default()
                        .push(pset.to_string());
                }
                if let Some(prev) = prev_sibling {
                    sys_after
                        .entry(node.name.clone())
                        .or_default()
                        .push(format!("{}::{}", self.mir.module_path, prev));
                }
            }
            kind @ ("seq" | "seq_weak" | "par" | "set") => {
                let set_name = if node.name.is_empty() {
                    format!("{}::set_{}", self.mir.module_path, self.sets.len())
                } else {
                    format!("{}::{}", self.mir.module_path, node.name)
                };
                let flags_expr = match kind {
                    "seq" => "BAM_SCHEDULE_SET_FLAG_SEQUENCE",
                    "seq_weak" => "BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK",
                    _ => "BAM_SCHEDULE_SET_FLAG_PARALLEL",
                };
                let mut after_sets = Vec::new();
                if let Some(prev) = prev_sibling.as_ref() {
                    after_sets.push(prev.clone());
                }
                let idx = self.sets.len();
                self.sets.push(RegScheduleSet {
                    idx,
                    name: set_name.clone(),
                    schedule: sched_c,
                    flags_expr,
                    after_sets,
                });
                let mut child_prev: Option<String> = None;
                for child in &node.children {
                    if kind == "seq" || kind == "seq_weak" {
                        self.walk_schedule_node(
                            child,
                            sched_c,
                            &mut child_prev,
                            Some(&set_name),
                            sys_sets,
                            sys_after,
                        );
                        if child.kind == "leaf" {
                            child_prev = Some(child.name.clone());
                        }
                    } else {
                        let mut no_prev = None;
                        self.walk_schedule_node(
                            child,
                            sched_c,
                            &mut no_prev,
                            Some(&set_name),
                            sys_sets,
                            sys_after,
                        );
                    }
                }
                *prev_sibling = Some(set_name);
            }
            _ => {
                for child in &node.children {
                    self.walk_schedule_node(
                        child,
                        sched_c,
                        prev_sibling,
                        parent_set,
                        sys_sets,
                        sys_after,
                    );
                }
            }
        }
    }

    fn collect_composite_types(&mut self) {
        let mut queue: Vec<MirType> = Vec::new();
        for f in self.mir_functions() {
            for l in &f.locals {
                queue.push(l.ty.clone());
            }
            for p in &f.params {
                queue.push(p.ty.clone());
            }
            queue.push(f.ret_ty.clone());
            for bb in &f.blocks {
                for st in &bb.stmts {
                    if let Inst::SlotAlloc { ty } = &st.inst {
                        queue.push(ty.clone());
                    }
                }
            }
        }
        while let Some(ty) = queue.pop() {
            match ty {
                MirType::Tuple(ref elems) => {
                    if !self.tuple_types.iter().any(|(e, _)| e == elems) {
                        let id = self.tuple_types.len();
                        self.tuple_types
                            .push((elems.clone(), format!("StrataTuple_{id}")));
                        for e in elems {
                            queue.push(e.clone());
                        }
                    }
                }
                MirType::Array { ref elem, len } => {
                    let elem_ty = (**elem).clone();
                    if !self
                        .array_types
                        .iter()
                        .any(|(e, l, _)| *e == elem_ty && *l == len)
                    {
                        let id = self.array_types.len();
                        self.array_types
                            .push((elem_ty.clone(), len, format!("StrataArray_{id}")));
                        queue.push(elem_ty);
                    }
                }
                _ => {}
            }
        }
    }

    fn tuple_name(&self, elems: &[MirType]) -> Option<&str> {
        self.tuple_types
            .iter()
            .find(|(e, _)| e.as_slice() == elems)
            .map(|(_, n)| n.as_str())
    }

    fn array_name(&self, elem: &MirType, len: usize) -> Option<&str> {
        self.array_types
            .iter()
            .find(|(e, l, _)| e == elem && *l == len)
            .map(|(_, _, n)| n.as_str())
    }

    fn emit_all(&mut self) -> Result<(), CodegenError> {
        self.emit_preamble();
        self.emit_value_and_math_helpers();
        self.emit_enums();
        self.emit_layouts()?;
        self.emit_composite_typedefs();
        self.emit_defaults()?;
        self.emit_rodata_tables_and_curves()?;
        self.emit_state_struct_and_forward_decls();
        for w in &self.run_if_wrappers.clone() {
            self.out.push_str(w);
            self.out.push('\n');
        }
        self.emit_functions()?;
        self.emit_startup_objects_fn()?;
        self.emit_manifest_init_shutdown()?;
        Ok(())
    }

    fn emit_preamble(&mut self) {
        self.out.push_str(
            "/* Generated by strata_codegen (Strict ISO C99 backend, bamabi ABI 0.3.0). */\n",
        );
        self.out
            .push_str("#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L\n");
        self.out
            .push_str("#error \"Strict ISO C99 (-std=c99) required.\"\n");
        self.out.push_str("#endif\n");
        if self.mir.is_deterministic || self.mir_functions().iter().any(|f| f.is_deterministic) {
            self.out.push_str("#if defined(__clang__)\n");
            self.out.push_str("#pragma STDC FP_CONTRACT OFF\n");
            self.out.push_str("#endif\n");
        }
        self.out.push_str("#include \"bamabi.h\"\n");
        self.out.push_str("#include <float.h>\n");
        self.out.push_str("#include <math.h>\n");
        self.out.push_str("#include <stdbool.h>\n");
        self.out.push_str("#include <stddef.h>\n");
        self.out.push_str("#include <stdint.h>\n");
        self.out.push_str("#include <stdlib.h>\n");
        self.out.push_str("#include <string.h>\n\n");
        self.out
            .push_str("#define STRATA_PI_F 3.14159265358979323846f\n\n");
    }

    fn emit_value_and_math_helpers(&mut self) {
        self.out.push_str(
            "\
typedef struct StrataVec2 { float x; float y; } StrataVec2;
typedef struct StrataVec3 { float x; float y; float z; } StrataVec3;
typedef struct StrataVec4 { float x; float y; float z; float w; } StrataVec4;
typedef struct StrataIVec2 { int32_t x; int32_t y; } StrataIVec2;
typedef struct StrataIVec3 { int32_t x; int32_t y; int32_t z; } StrataIVec3;
typedef struct StrataUVec2 { uint32_t x; uint32_t y; } StrataUVec2;
typedef struct StrataMat3 { float m[9]; } StrataMat3;
typedef struct StrataMat4 { float m[16]; } StrataMat4;

BAM_STATIC_ASSERT(sizeof(StrataVec2) == 8u, strata_vec2_size);
BAM_STATIC_ASSERT(sizeof(StrataVec3) == 12u, strata_vec3_size);
BAM_STATIC_ASSERT(sizeof(StrataVec4) == 16u, strata_vec4_size);
BAM_STATIC_ASSERT(sizeof(StrataIVec2) == 8u, strata_ivec2_size);
BAM_STATIC_ASSERT(sizeof(StrataIVec3) == 12u, strata_ivec3_size);
BAM_STATIC_ASSERT(sizeof(StrataUVec2) == 8u, strata_uvec2_size);
BAM_STATIC_ASSERT(sizeof(StrataMat3) == 36u, strata_mat3_size);
BAM_STATIC_ASSERT(sizeof(StrataMat4) == 64u, strata_mat4_size);

static BAM_UNUSED inline StrataVec2 strata_vec2(float x, float y) {
    StrataVec2 v; v.x = x; v.y = y; return v;
}
static BAM_UNUSED inline StrataVec3 strata_vec3(float x, float y, float z) {
    StrataVec3 v; v.x = x; v.y = y; v.z = z; return v;
}
static BAM_UNUSED inline StrataVec4 strata_vec4(float x, float y, float z, float w) {
    StrataVec4 v; v.x = x; v.y = y; v.z = z; v.w = w; return v;
}
static BAM_UNUSED inline StrataIVec2 strata_ivec2(int32_t x, int32_t y) {
    StrataIVec2 v; v.x = x; v.y = y; return v;
}
static BAM_UNUSED inline StrataIVec3 strata_ivec3(int32_t x, int32_t y, int32_t z) {
    StrataIVec3 v; v.x = x; v.y = y; v.z = z; return v;
}
static BAM_UNUSED inline StrataUVec2 strata_uvec2(uint32_t x, uint32_t y) {
    StrataUVec2 v; v.x = x; v.y = y; return v;
}

static BAM_UNUSED inline StrataVec2 strata_vec2_add(StrataVec2 a, StrataVec2 b) {
    return strata_vec2(a.x + b.x, a.y + b.y);
}
static BAM_UNUSED inline StrataVec2 strata_vec2_sub(StrataVec2 a, StrataVec2 b) {
    return strata_vec2(a.x - b.x, a.y - b.y);
}
static BAM_UNUSED inline StrataVec2 strata_vec2_mul(StrataVec2 a, StrataVec2 b) {
    return strata_vec2(a.x * b.x, a.y * b.y);
}
static BAM_UNUSED inline StrataVec2 strata_vec2_scale(StrataVec2 a, float s) {
    return strata_vec2(a.x * s, a.y * s);
}
static BAM_UNUSED inline float strata_vec2_dot(StrataVec2 a, StrataVec2 b) {
    return a.x * b.x + a.y * b.y;
}
static BAM_UNUSED inline float strata_vec2_len_sq(StrataVec2 a) {
    return a.x * a.x + a.y * a.y;
}
static BAM_UNUSED inline float strata_vec2_len(StrataVec2 a) {
    return sqrtf(strata_vec2_len_sq(a));
}
static BAM_UNUSED inline float strata_vec2_dist(StrataVec2 a, StrataVec2 b) {
    return strata_vec2_len(strata_vec2_sub(a, b));
}
static BAM_UNUSED inline float strata_vec2_dist_sq(StrataVec2 a, StrataVec2 b) {
    return strata_vec2_len_sq(strata_vec2_sub(a, b));
}
static BAM_UNUSED inline StrataVec2 strata_vec2_norm(StrataVec2 a) {
    float l = strata_vec2_len(a);
    return (l > 1e-6f) ? strata_vec2_scale(a, 1.0f / l) : strata_vec2(0.0f, 0.0f);
}
static BAM_UNUSED inline StrataVec2 strata_vec2_lerp(StrataVec2 a, StrataVec2 b, float t) {
    return strata_vec2(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t);
}

static BAM_UNUSED inline StrataVec3 strata_vec3_add(StrataVec3 a, StrataVec3 b) {
    return strata_vec3(a.x + b.x, a.y + b.y, a.z + b.z);
}
static BAM_UNUSED inline StrataVec3 strata_vec3_sub(StrataVec3 a, StrataVec3 b) {
    return strata_vec3(a.x - b.x, a.y - b.y, a.z - b.z);
}
static BAM_UNUSED inline StrataVec3 strata_vec3_mul(StrataVec3 a, StrataVec3 b) {
    return strata_vec3(a.x * b.x, a.y * b.y, a.z * b.z);
}
static BAM_UNUSED inline StrataVec3 strata_vec3_scale(StrataVec3 a, float s) {
    return strata_vec3(a.x * s, a.y * s, a.z * s);
}
static BAM_UNUSED inline float strata_vec3_dot(StrataVec3 a, StrataVec3 b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}
static BAM_UNUSED inline float strata_vec3_len_sq(StrataVec3 a) {
    return a.x * a.x + a.y * a.y + a.z * a.z;
}
static BAM_UNUSED inline float strata_vec3_len(StrataVec3 a) {
    return sqrtf(strata_vec3_len_sq(a));
}
static BAM_UNUSED inline float strata_vec3_dist(StrataVec3 a, StrataVec3 b) {
    return strata_vec3_len(strata_vec3_sub(a, b));
}
static BAM_UNUSED inline float strata_vec3_dist_sq(StrataVec3 a, StrataVec3 b) {
    return strata_vec3_len_sq(strata_vec3_sub(a, b));
}
static BAM_UNUSED inline StrataVec3 strata_vec3_norm(StrataVec3 a) {
    float l = strata_vec3_len(a);
    return (l > 1e-6f) ? strata_vec3_scale(a, 1.0f / l) : strata_vec3(0.0f, 0.0f, 0.0f);
}
static BAM_UNUSED inline StrataVec3 strata_vec3_cross(StrataVec3 a, StrataVec3 b) {
    return strata_vec3(a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x);
}
static BAM_UNUSED inline StrataVec3 strata_vec3_lerp(StrataVec3 a, StrataVec3 b, float t) {
    return strata_vec3(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t);
}

static BAM_UNUSED inline StrataVec4 strata_vec4_add(StrataVec4 a, StrataVec4 b) {
    return strata_vec4(a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w);
}
static BAM_UNUSED inline StrataVec4 strata_vec4_sub(StrataVec4 a, StrataVec4 b) {
    return strata_vec4(a.x - b.x, a.y - b.y, a.z - b.z, a.w - b.w);
}
static BAM_UNUSED inline StrataVec4 strata_vec4_mul(StrataVec4 a, StrataVec4 b) {
    return strata_vec4(a.x * b.x, a.y * b.y, a.z * b.z, a.w * b.w);
}
static BAM_UNUSED inline StrataVec4 strata_vec4_scale(StrataVec4 a, float s) {
    return strata_vec4(a.x * s, a.y * s, a.z * s, a.w * s);
}
static BAM_UNUSED inline float strata_vec4_dot(StrataVec4 a, StrataVec4 b) {
    return a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
}
static BAM_UNUSED inline float strata_vec4_len(StrataVec4 a) {
    return sqrtf(strata_vec4_dot(a, a));
}
static BAM_UNUSED inline StrataVec4 strata_vec4_norm(StrataVec4 a) {
    float l = strata_vec4_len(a);
    return (l > 1e-6f) ? strata_vec4_scale(a, 1.0f / l) : strata_vec4(0.0f, 0.0f, 0.0f, 1.0f);
}
static BAM_UNUSED inline StrataVec4 strata_quat_from_rotation_y(float angle_rad) {
    float half = 0.5f * angle_rad;
    return strata_vec4(0.0f, sinf(half), 0.0f, cosf(half));
}

static BAM_UNUSED inline float strata_sqr_f32(float x) { return x * x; }
static BAM_UNUSED inline double strata_sqr_f64(double x) { return x * x; }
static BAM_UNUSED inline float strata_clamp_f32(float v, float lo, float hi) {
    return (v < lo) ? lo : ((v > hi) ? hi : v);
}
static BAM_UNUSED inline int32_t strata_clamp_i32(int32_t v, int32_t lo, int32_t hi) {
    return (v < lo) ? lo : ((v > hi) ? hi : v);
}
static BAM_UNUSED inline float strata_lerp_f32(float a, float b, float t) {
    return a + (b - a) * t;
}
static BAM_UNUSED inline float strata_signum_f32(float v) {
    return (v > 0.0f) ? 1.0f : ((v < 0.0f) ? -1.0f : 0.0f);
}

/* Primitive runtime helpers matching bamabi_native_rt::primitives ABI layouts. */
static BAM_UNUSED inline void strata_grace_arm(void* ptr, float duration_sec) {
    if (ptr != NULL) {
        float val = (duration_sec > 0.0f) ? duration_sec : 0.0f;
        memcpy(ptr, &val, sizeof(float));
    }
}
static BAM_UNUSED inline void strata_grace_clear(void* ptr) {
    if (ptr != NULL) {
        float zero = 0.0f;
        memcpy(ptr, &zero, sizeof(float));
    }
}
static BAM_UNUSED inline void strata_grace_tick(void* ptr, float dt) {
    if (ptr != NULL) {
        float rem = 0.0f;
        memcpy(&rem, ptr, sizeof(float));
        rem -= dt;
        if (rem < 0.0f) { rem = 0.0f; }
        memcpy(ptr, &rem, sizeof(float));
    }
}
static BAM_UNUSED inline BamBool strata_grace_is_active(const void* ptr) {
    float rem = 0.0f;
    if (ptr == NULL) { return BAM_FALSE; }
    memcpy(&rem, ptr, sizeof(float));
    return (rem > 0.0f) ? BAM_TRUE : BAM_FALSE;
}

typedef struct StrataInputEntry {
    uint16_t action_id;
    uint16_t pad;
    float remaining_sec;
} StrataInputEntry;
BAM_STATIC_ASSERT(sizeof(StrataInputEntry) == 8u, strata_input_entry_size);

static BAM_UNUSED inline void strata_input_init(void* ptr, uint32_t cap) {
    if (ptr == NULL) { return; }
    uint8_t* bytes = (uint8_t*)ptr;
    for (uint32_t i = 0u; i < cap; ++i) {
        StrataInputEntry e;
        e.action_id = 0xFFFFu;
        e.pad = 0u;
        e.remaining_sec = 0.0f;
        memcpy(bytes + (size_t)i * sizeof(StrataInputEntry), &e, sizeof(e));
    }
}
static BAM_UNUSED inline void strata_input_push(void* ptr, uint32_t cap, uint16_t action_id, float window_sec) {
    if (ptr == NULL || cap == 0u) { return; }
    uint8_t* bytes = (uint8_t*)ptr;
    uint32_t replace_idx = 0u;
    float min_rem = FLT_MAX;
    for (uint32_t i = 0u; i < cap; ++i) {
        StrataInputEntry e;
        memcpy(&e, bytes + (size_t)i * sizeof(StrataInputEntry), sizeof(e));
        if (e.action_id == action_id || e.action_id == 0xFFFFu || e.remaining_sec <= 0.0f) {
            replace_idx = i;
            break;
        }
        if (e.remaining_sec < min_rem) {
            min_rem = e.remaining_sec;
            replace_idx = i;
        }
    }
    StrataInputEntry ne;
    ne.action_id = action_id;
    ne.pad = 0u;
    ne.remaining_sec = window_sec;
    memcpy(bytes + (size_t)replace_idx * sizeof(StrataInputEntry), &ne, sizeof(ne));
}
static BAM_UNUSED inline BamBool strata_input_peek(const void* ptr, uint32_t cap, uint16_t action_id) {
    if (ptr == NULL) { return BAM_FALSE; }
    const uint8_t* bytes = (const uint8_t*)ptr;
    for (uint32_t i = 0u; i < cap; ++i) {
        StrataInputEntry e;
        memcpy(&e, bytes + (size_t)i * sizeof(StrataInputEntry), sizeof(e));
        if (e.action_id == action_id && e.remaining_sec > 0.0f) {
            return BAM_TRUE;
        }
    }
    return BAM_FALSE;
}
static BAM_UNUSED inline BamBool strata_input_consume(void* ptr, uint32_t cap, uint16_t action_id) {
    if (ptr == NULL) { return BAM_FALSE; }
    uint8_t* bytes = (uint8_t*)ptr;
    for (uint32_t i = 0u; i < cap; ++i) {
        StrataInputEntry e;
        memcpy(&e, bytes + (size_t)i * sizeof(StrataInputEntry), sizeof(e));
        if (e.action_id == action_id && e.remaining_sec > 0.0f) {
            e.action_id = 0xFFFFu;
            e.remaining_sec = 0.0f;
            memcpy(bytes + (size_t)i * sizeof(StrataInputEntry), &e, sizeof(e));
            return BAM_TRUE;
        }
    }
    return BAM_FALSE;
}
static BAM_UNUSED inline void strata_input_tick(void* ptr, uint32_t cap, float dt) {
    if (ptr == NULL) { return; }
    uint8_t* bytes = (uint8_t*)ptr;
    for (uint32_t i = 0u; i < cap; ++i) {
        StrataInputEntry e;
        memcpy(&e, bytes + (size_t)i * sizeof(StrataInputEntry), sizeof(e));
        if (e.action_id != 0xFFFFu) {
            e.remaining_sec -= dt;
            if (e.remaining_sec <= 0.0f) {
                e.action_id = 0xFFFFu;
                e.remaining_sec = 0.0f;
            }
            memcpy(bytes + (size_t)i * sizeof(StrataInputEntry), &e, sizeof(e));
        }
    }
}

static BAM_UNUSED inline BamBool strata_bitset_get(const void* ptr, uint32_t words, uint32_t bit) {
    uint32_t w = bit >> 6u;
    uint32_t b = bit & 63u;
    if (ptr == NULL || w >= words) { return BAM_FALSE; }
    uint64_t val = 0ull;
    memcpy(&val, (const uint8_t*)ptr + (size_t)w * sizeof(uint64_t), sizeof(uint64_t));
    return ((val & (1ull << b)) != 0ull) ? BAM_TRUE : BAM_FALSE;
}
static BAM_UNUSED inline void strata_bitset_set(void* ptr, uint32_t words, uint32_t bit) {
    uint32_t w = bit >> 6u;
    uint32_t b = bit & 63u;
    if (ptr == NULL || w >= words) { return; }
    uint64_t val = 0ull;
    memcpy(&val, (const uint8_t*)ptr + (size_t)w * sizeof(uint64_t), sizeof(uint64_t));
    val |= (1ull << b);
    memcpy((uint8_t*)ptr + (size_t)w * sizeof(uint64_t), &val, sizeof(uint64_t));
}
static BAM_UNUSED inline void strata_bitset_clear(void* ptr, uint32_t words, uint32_t bit) {
    uint32_t w = bit >> 6u;
    uint32_t b = bit & 63u;
    if (ptr == NULL || w >= words) { return; }
    uint64_t val = 0ull;
    memcpy(&val, (const uint8_t*)ptr + (size_t)w * sizeof(uint64_t), sizeof(uint64_t));
    val &= ~(1ull << b);
    memcpy((uint8_t*)ptr + (size_t)w * sizeof(uint64_t), &val, sizeof(uint64_t));
}

typedef struct StrataSpatialHits {
    BamEntity entities[64];
    uint32_t count;
} StrataSpatialHits;

static BAM_UNUSED inline StrataSpatialHits strata_spatial_query_disc(
    const void* grid_ptr,
    StrataVec2 center,
    float radius)
{
    StrataSpatialHits hits;
    memset(&hits, 0, sizeof(hits));
    (void)grid_ptr;
    (void)center;
    (void)radius;
    return hits;
}
static BAM_UNUSED inline StrataSpatialHits strata_spatial_query_segment_at(
    const void* hist_ptr,
    StrataVec3 p0,
    StrataVec3 p1,
    float radius,
    float tick_offset)
{
    StrataSpatialHits hits;
    memset(&hits, 0, sizeof(hits));
    (void)hist_ptr;
    (void)p0;
    (void)p1;
    (void)radius;
    (void)tick_offset;
    return hits;
}

",
        );
    }

    fn emit_enums(&mut self) {
        for e in &self.mir.enums {
            let short = short_name(&e.canonical_name);
            let enum_ident = sanitize_ident(short);
            let _ = writeln!(self.out, "/* Enum {} */", e.canonical_name);
            for (v_name, disc) in &e.variants {
                let v_ident = sanitize_ident(v_name);
                let _ = writeln!(
                    self.out,
                    "#define STRATA_ENUM_{enum_ident}_{v_ident} ((int32_t){disc})"
                );
            }
            self.out.push('\n');
        }
    }

    fn emit_layouts(&mut self) -> Result<(), CodegenError> {
        for (idx, layout) in self.layouts.iter().enumerate() {
            let cname = &self.layout_c_names[idx];
            if layout.size == 0 {
                let _ = writeln!(
                    self.out,
                    "typedef struct {cname} {{\n    uint8_t _zst_pad;\n}} {cname};"
                );
                let _ = writeln!(
                    self.out,
                    "BAM_STATIC_ASSERT(sizeof({cname}) == 1u, {cname}_zst_size);\n"
                );
                continue;
            }
            let _ = writeln!(self.out, "typedef struct {cname} {{");
            let mut cursor: usize = 0;
            let mut pad_idx: usize = 0;
            for f in &layout.fields {
                if f.offset > cursor {
                    let gap = f.offset - cursor;
                    let _ = writeln!(self.out, "    uint8_t _pad_{pad_idx}[{gap}];");
                    pad_idx += 1;
                }
                let f_c = sanitize_c_field(&f.name);
                let f_decl = self.c_field_decl(&f.ty, f.size, &f_c);
                let _ = writeln!(self.out, "    {f_decl};");
                cursor = f.offset.saturating_add(f.size);
            }
            if layout.size > cursor {
                let tail = layout.size - cursor;
                let _ = writeln!(self.out, "    uint8_t _pad_tail[{tail}];");
            }
            let _ = writeln!(self.out, "}} {cname};");
            let _ = writeln!(
                self.out,
                "BAM_STATIC_ASSERT(sizeof({cname}) == {}u, {cname}_size);",
                layout.size
            );
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let f_c = sanitize_c_field(&f.name);
                let _ = writeln!(
                    self.out,
                    "BAM_STATIC_ASSERT(offsetof({cname}, {f_c}) == {}u, {cname}_off_{f_c});",
                    f.offset
                );
            }
            self.out.push('\n');
        }
        Ok(())
    }

    fn c_field_decl(&self, ty: &Ty, byte_size: usize, field_name: &str) -> String {
        match ty {
            Ty::Bool | Ty::U8 => format!("uint8_t {field_name}"),
            Ty::I8 => format!("int8_t {field_name}"),
            Ty::I16 => format!("int16_t {field_name}"),
            Ty::I32 | Ty::Fix32 => format!("int32_t {field_name}"),
            Ty::I64 | Ty::Fix64 => format!("int64_t {field_name}"),
            Ty::U16 => format!("uint16_t {field_name}"),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("uint32_t {field_name}"),
            Ty::U64 => format!("uint64_t {field_name}"),
            Ty::F32 | Ty::UnitScalar { .. } => {
                if byte_size == 8 {
                    format!("double {field_name}")
                } else {
                    format!("float {field_name}")
                }
            }
            Ty::F64 => format!("double {field_name}"),
            Ty::Ref(_) => {
                if byte_size == 8 {
                    format!("BamEntity {field_name}")
                } else {
                    format!("uint8_t {field_name}[{}]", byte_size.max(1))
                }
            }
            Ty::Vec2 => format!("StrataVec2 {field_name}"),
            Ty::Vec3 => format!("StrataVec3 {field_name}"),
            Ty::Vec3a => {
                if byte_size == 12 {
                    format!("StrataVec3 {field_name}")
                } else {
                    format!("StrataVec4 {field_name}")
                }
            }
            Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVec4 {field_name}"),
            Ty::IVec2 => format!("StrataIVec2 {field_name}"),
            Ty::IVec3 => format!("StrataIVec3 {field_name}"),
            Ty::UVec2 => format!("StrataUVec2 {field_name}"),
            Ty::Mat3 => format!("StrataMat3 {field_name}"),
            Ty::Mat4 => format!("StrataMat4 {field_name}"),
            Ty::Named(key) => {
                if let Some(l_idx) = self.find_layout_idx(key)
                    && self.layouts[l_idx].size == byte_size
                {
                    format!("{} {field_name}", self.layout_c_names[l_idx])
                } else if byte_size == 4 {
                    format!("int32_t {field_name}")
                } else if byte_size == 1 {
                    format!("uint8_t {field_name}")
                } else if byte_size == 2 {
                    format!("uint16_t {field_name}")
                } else if byte_size == 8 {
                    format!("int64_t {field_name}")
                } else {
                    format!("uint8_t {field_name}[{}]", byte_size.max(1))
                }
            }
            _ => format!("uint8_t {field_name}[{}]", byte_size.max(1)),
        }
    }

    fn emit_composite_typedefs(&mut self) {
        let tuples = self.tuple_types.clone();
        for (elems, name) in &tuples {
            let _ = writeln!(self.out, "typedef struct {name} {{");
            if elems.is_empty() {
                let _ = writeln!(self.out, "    uint8_t _empty;");
            } else {
                for (i, e) in elems.iter().enumerate() {
                    let cty = self.c_ty(e);
                    let _ = writeln!(self.out, "    {cty} f{i};");
                }
            }
            let _ = writeln!(self.out, "}} {name};\n");
        }
        let arrays = self.array_types.clone();
        for (elem, len, name) in &arrays {
            let cty = self.c_ty(elem);
            let _ = writeln!(
                self.out,
                "typedef struct {name} {{ {cty} data[{}]; }} {name};\n",
                (*len).max(1)
            );
        }
    }

    fn emit_defaults(&mut self) -> Result<(), CodegenError> {
        for idx in 0..self.layouts.len() {
            let layout = &self.layouts[idx];
            if layout.size == 0 {
                continue;
            }
            let short = short_name(&layout.canonical_name);
            let cname = &self.layout_c_names[idx];
            let def_fn = format!("strata_default_{idx}_{}", sanitize_ident(short));
            let defs_opt = self
                .mir
                .field_defaults
                .get(&layout.canonical_name)
                .or_else(|| self.mir.field_defaults.get(short));

            let _ = writeln!(
                self.out,
                "static BAM_UNUSED inline {cname} {def_fn}(void) {{"
            );
            let _ = writeln!(self.out, "    {cname} out;");
            let _ = writeln!(self.out, "    memset(&out, 0, sizeof(out));");
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let fc = sanitize_c_field(&f.name);
                if let Ty::InputBuffer { cap, .. } = &f.ty {
                    let _ = writeln!(self.out, "    strata_input_init(&out.{fc}, {cap}u);");
                }
                if let Some(defs) = defs_opt
                    && let Some(val) = defs.get(&f.name)
                {
                    let init_expr = self.c_const_val(val);
                    let _ = writeln!(self.out, "    out.{fc} = {init_expr};");
                }
            }
            let _ = writeln!(self.out, "    return out;");
            let _ = writeln!(self.out, "}}\n");
        }
        Ok(())
    }

    fn emit_rodata_tables_and_curves(&mut self) -> Result<(), CodegenError> {
        // 1. `.rodata` tables keyed by enum discriminant.
        for t in &self.mir.tables {
            let t_ident = sanitize_ident(&t.name);
            let _ = writeln!(self.out, "/* .rodata Table {} */", t.name);
            let _ = writeln!(self.out, "typedef struct StrataTable_{t_ident} {{");
            if t.fields.is_empty() {
                let _ = writeln!(self.out, "    uint8_t _empty;");
            } else {
                for (fname, fty) in &t.fields {
                    let c_ty = self.c_ty_from_sema(fty);
                    let c_col = sanitize_c_field(fname);
                    let _ = writeln!(self.out, "    {c_ty} {c_col};");
                }
            }
            let _ = writeln!(self.out, "}} StrataTable_{t_ident};");

            let key_enum = self.mir.enums.iter().find(|e| {
                e.canonical_name == t.key_enum
                    || short_name(&e.canonical_name) == short_name(&t.key_enum)
            });
            let mut max_disc: usize = 0;
            let mut row_by_disc: BTreeMap<usize, Vec<String>> = BTreeMap::new();
            for (row_key, col_exprs) in &t.typed_rows {
                let disc = key_enum
                    .and_then(|e| {
                        e.variants
                            .iter()
                            .find(|(vn, _)| vn == row_key)
                            .map(|(_, d)| (*d).max(0) as usize)
                    })
                    .unwrap_or(row_by_disc.len());
                max_disc = max_disc.max(disc);
                let mut vals = Vec::with_capacity(t.fields.len());
                for (fname, fty) in &t.fields {
                    let v = col_exprs
                        .iter()
                        .find(|(k, _)| k == fname)
                        .map(|(_, expr)| self.c_hir_expr(expr, fty))
                        .unwrap_or_else(|| self.c_zero_for_sema(fty));
                    vals.push(v);
                }
                row_by_disc.insert(disc, vals);
            }
            let len = (max_disc + 1).max(1);
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const StrataTable_{t_ident} STRATA_TABLE_{t_ident}[{len}] = {{"
            );
            for d in 0..len {
                let comma = if d + 1 < len { "," } else { "" };
                if let Some(vals) = row_by_disc.get(&d) {
                    if vals.is_empty() {
                        let _ = writeln!(self.out, "    {{ 0u }}{comma}");
                    } else {
                        let _ = writeln!(self.out, "    {{ {} }}{comma}", vals.join(", "));
                    }
                } else if t.fields.is_empty() {
                    let _ = writeln!(self.out, "    {{ 0u }}{comma}");
                } else {
                    let zeros: Vec<String> = t
                        .fields
                        .iter()
                        .map(|(_, ty)| self.c_zero_for_sema(ty))
                        .collect();
                    let _ = writeln!(self.out, "    {{ {} }}{comma}", zeros.join(", "));
                }
            }
            let _ = writeln!(self.out, "}};");
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED inline StrataTable_{t_ident} strata_table_load_{t_ident}(int32_t key) {{"
            );
            let _ = writeln!(
                self.out,
                "    size_t idx = (key >= 0 && (size_t)key < {len}u) ? (size_t)key : 0u;"
            );
            let _ = writeln!(self.out, "    return STRATA_TABLE_{t_ident}[idx];");
            let _ = writeln!(self.out, "}}\n");
        }

        // 2. `.rodata` piecewise-linear curves.
        for c in &self.mir.curves {
            let c_ident = sanitize_ident(&c.name);
            let n = c.points.len().max(1);
            let xs: Vec<String> = if c.points.is_empty() {
                vec!["0.0f".to_string()]
            } else {
                c.points.iter().map(|(x, _)| c_f32(*x as f32)).collect()
            };
            let ys: Vec<String> = if c.points.is_empty() {
                vec!["0.0f".to_string()]
            } else {
                c.points.iter().map(|(_, y)| c_f32(*y as f32)).collect()
            };
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const float STRATA_CURVE_X_{c_ident}[{n}] = {{ {} }};",
                xs.join(", ")
            );
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const float STRATA_CURVE_Y_{c_ident}[{n}] = {{ {} }};",
                ys.join(", ")
            );
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED inline float strata_curve_sample_{c_ident}(float x) {{"
            );
            let _ = writeln!(
                self.out,
                "    if (x <= STRATA_CURVE_X_{c_ident}[0]) {{ return STRATA_CURVE_Y_{c_ident}[0]; }}"
            );
            let _ = writeln!(
                self.out,
                "    if (x >= STRATA_CURVE_X_{c_ident}[{}]) {{ return STRATA_CURVE_Y_{c_ident}[{}]; }}",
                n - 1,
                n - 1
            );
            if n > 1 {
                let _ = writeln!(self.out, "    for (size_t i = 0u; i + 1u < {n}u; ++i) {{");
                let _ = writeln!(self.out, "        float x0 = STRATA_CURVE_X_{c_ident}[i];");
                let _ = writeln!(
                    self.out,
                    "        float x1 = STRATA_CURVE_X_{c_ident}[i + 1u];"
                );
                let _ = writeln!(self.out, "        if (x >= x0 && x <= x1) {{");
                let _ = writeln!(self.out, "            float span = x1 - x0;");
                let _ = writeln!(
                    self.out,
                    "            float t = (span > 1e-6f) ? ((x - x0) / span) : 0.0f;"
                );
                let _ = writeln!(
                    self.out,
                    "            return STRATA_CURVE_Y_{c_ident}[i] + (STRATA_CURVE_Y_{c_ident}[i + 1u] - STRATA_CURVE_Y_{c_ident}[i]) * t;"
                );
                let _ = writeln!(self.out, "        }}");
                let _ = writeln!(self.out, "    }}");
            }
            let _ = writeln!(self.out, "    return STRATA_CURVE_Y_{c_ident}[{}];", n - 1);
            let _ = writeln!(self.out, "}}\n");
        }
        Ok(())
    }

    fn emit_state_struct_and_forward_decls(&mut self) {
        let comp_n = self.components.len().max(1);
        let rel_n = self.relations.len().max(1);
        let obj_n = self.objects.len().max(1);
        let sys_n = self.systems.len().max(1);
        let set_n = self.sets.len().max(1);

        let mut mod_res_fields = String::new();
        for c in &self.components {
            if c.has_mod_res
                && let Some(l_idx) = c.layout_idx
            {
                let cty = &self.layout_c_names[l_idx];
                let _ = writeln!(mod_res_fields, "    {cty} mod_res_{};", c.idx);
            }
        }

        let _ = writeln!(
            self.out,
            "\
typedef struct StrataModState {{
    const BamHostApi* api;
    const BamHostCtx* host_ctx;
    BamComponent components[{comp_n}u];
    uint8_t res_flags[{comp_n}u];
    BamComponent relations[{rel_n}u];
    BamEntity named_objects[{obj_n}u];
    BamSystem systems[{sys_n}u];
    BamSystemSet sets[{set_n}u];
    BamBool objects_initialized;
{mod_res_fields}}} StrataModState;\n"
        );

        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        for f in &fns_snapshot {
            match &f.kind {
                MirFnKind::HelperFn => {
                    let sig = self.helper_sig(f);
                    let _ = writeln!(self.out, "{sig};");
                }
                MirFnKind::System
                | MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_sys_{name}(BamSystemCtx* sys_ctx, void* user_data);"
                    );
                }
                MirFnKind::Observer { .. } => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_obs_{name}(BamEntity entity, const void* event_data, BamCommands* commands, void* user_data);"
                    );
                }
                MirFnKind::Migration { .. } => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_mig_{name}(const void* src_row, void* dst_row, void* user_data);"
                    );
                }
            }
        }
        if !self.mir.objects.is_empty() {
            let _ = writeln!(
                self.out,
                "static BamResult strata_sys_startup_objects(BamSystemCtx* sys_ctx, void* user_data);"
            );
        }
        self.out.push('\n');
    }

    fn helper_sig(&self, f: &MirFunction) -> String {
        let ret = if matches!(f.ret_ty, MirType::Unit) {
            "void".to_string()
        } else {
            self.c_ty(&f.ret_ty)
        };
        let fn_name = format!("strata_fn_{}", sanitize_ident(&f.name));
        let mut params = vec!["StrataModState* state".to_string()];
        for (i, p) in f.params.iter().enumerate() {
            let p_ty = self.c_ty(&p.ty);
            params.push(format!("{p_ty} p_{i}"));
        }
        format!("static BAM_UNUSED {ret} {fn_name}({})", params.join(", "))
    }

    fn emit_functions(&mut self) -> Result<(), CodegenError> {
        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        for f in &fns_snapshot {
            let body = self.emit_mir_function(f)?;
            self.out.push_str(&body);
            self.out.push('\n');
        }
        Ok(())
    }

    fn emit_mir_function(&self, f: &MirFunction) -> Result<String, CodegenError> {
        let mut s = String::new();
        let is_helper = matches!(f.kind, MirFnKind::HelperFn);
        let is_void_helper = is_helper && matches!(f.ret_ty, MirType::Unit);
        let is_observer = matches!(f.kind, MirFnKind::Observer { .. });
        let is_migration = matches!(f.kind, MirFnKind::Migration { .. });

        match &f.kind {
            MirFnKind::HelperFn => {
                let _ = writeln!(s, "{} {{", self.helper_sig(f));
                let _ = writeln!(s, "    (void)state;");
                let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(s, "    (void)sys_ctx; (void)cmds_cache;");
                for i in 0..f.params.len() {
                    let _ = writeln!(s, "    (void)p_{i};");
                }
            }
            MirFnKind::Observer { .. } => {
                let name = sanitize_ident(&f.name);
                let _ = writeln!(
                    s,
                    "static BamResult strata_obs_{name}(BamEntity entity, const void* event_data, BamCommands* commands, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = commands;");
                let _ = writeln!(
                    s,
                    "    if (state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                let _ = writeln!(
                    s,
                    "    (void)entity; (void)event_data; (void)sys_ctx; (void)cmds_cache;"
                );
            }
            MirFnKind::Migration { .. } => {
                let name = sanitize_ident(&f.name);
                let _ = writeln!(
                    s,
                    "static BamResult strata_mig_{name}(const void* src_row, void* dst_row, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(
                    s,
                    "    if (src_row == NULL || dst_row == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                let _ = writeln!(s, "    (void)state; (void)sys_ctx; (void)cmds_cache;");
            }
            _ => {
                let name = sanitize_ident(&f.name);
                let c_fn = format!("strata_sys_{name}");
                let _ = writeln!(
                    s,
                    "static BamResult {c_fn}(BamSystemCtx* sys_ctx, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(
                    s,
                    "    if (sys_ctx == NULL || state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                if let Some(rs) = self.systems.iter().find(|rs| rs.c_fn_name == c_fn)
                    && let Some(ref rif) = rs.run_if_fn
                {
                    let _ = writeln!(
                        s,
                        "    if ({rif}(sys_ctx, user_data) != BAM_RESULT_OK) {{ return BAM_RESULT_OK; }}"
                    );
                }
                let _ = writeln!(s, "    (void)cmds_cache;");
            }
        }

        // Pre-scan statements to infer refined pointer provenance, `BAM_RESTRICT` column locals,
        // `SlotAlloc` stack allocations, dirty-run owners, spatial buffers, and coerced local types.
        let mut ptr_meta: HashMap<LocalId, PtrKind> = HashMap::new();
        let mut restrict_cols: HashMap<LocalId, PtrKind> = HashMap::new();
        let mut projected_fields: HashMap<LocalId, String> = HashMap::new();
        let mut slot_allocs: Vec<(LocalId, MirType)> = Vec::new();
        let mut spatial_hits_locals: Vec<LocalId> = Vec::new();
        let mut dirty_owners: HashMap<(u32, u32), Vec<(u32, u32)>> = HashMap::new();
        let mut checkpoint_locals: Vec<LocalId> = Vec::new();
        let mut local_types: HashMap<LocalId, MirType> = HashMap::new();
        for l in &f.locals {
            local_types.insert(l.id, l.ty.clone());
        }

        for bb in &f.blocks {
            for stmt in &bb.stmts {
                let dst = stmt.dst;
                match &stmt.inst {
                    Inst::InternSymbol { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Sym);
                        }
                    }
                    Inst::IterNextChunk { .. }
                    | Inst::OptionalChunkIsPresent { .. }
                    | Inst::GraceIsActive { .. }
                    | Inst::InputBufConsume { .. }
                    | Inst::InputBufPeek { .. }
                    | Inst::BitSetGet { .. }
                    | Inst::TimelineInWindow { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Bool);
                        }
                    }
                    Inst::IterChunkLen { .. } | Inst::IterCount { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::U32);
                        }
                    }
                    Inst::CmdSpawn { .. } | Inst::TriggerTarget | Inst::EntityAtRow { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Entity);
                        }
                    }
                    Inst::SpatialQueryDisc { .. } | Inst::SpatialQuerySegmentAt { .. } => {
                        if let Some(d) = dst {
                            spatial_hits_locals.push(d);
                            ptr_meta.insert(d, PtrKind::EntitySlice);
                        }
                    }
                    Inst::VecSwizzle { lanes, .. } => {
                        if let Some(d) = dst {
                            let vty = match lanes.len() {
                                2 => MirType::Vec2,
                                3 => MirType::Vec3,
                                _ => MirType::Vec4,
                            };
                            local_types.insert(d, vty);
                        }
                    }
                    Inst::SlotAlloc { ty } => {
                        if let Some(d) = dst {
                            slot_allocs.push((d, ty.clone()));
                            let pk = match ty {
                                MirType::Named(key) => {
                                    if let Some(l_idx) = self.find_layout_idx(key) {
                                        PtrKind::LayoutPtr {
                                            layout_idx: l_idx,
                                            is_mut: true,
                                        }
                                    } else {
                                        PtrKind::ScalarPtr {
                                            c_pointee: self.c_ty(ty),
                                            is_mut: true,
                                        }
                                    }
                                }
                                _ => PtrKind::ScalarPtr {
                                    c_pointee: self.c_ty(ty),
                                    is_mut: true,
                                },
                            };
                            ptr_meta.insert(d, pk);
                        }
                    }
                    Inst::IterEntities { .. } => {
                        if let Some(d) = dst {
                            ptr_meta.insert(d, PtrKind::EntitySlice);
                        }
                    }
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            let term_opt = f
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx));
                            let layout_opt = self
                                .find_layout_idx(storage_key)
                                .or_else(|| {
                                    storage_key
                                        .rsplit_once("::")
                                        .and_then(|(c, _)| self.find_layout_idx(c))
                                })
                                .or_else(|| {
                                    term_opt
                                        .and_then(|t| self.find_layout_idx(&t.canonical_component))
                                });
                            if let Some(l_idx) = layout_opt {
                                let pk = PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: false,
                                };
                                restrict_cols.insert(d, pk.clone());
                                ptr_meta.insert(d, pk);
                            }
                            if let Some(fnm) = term_opt.and_then(|t| t.field_name.clone()) {
                                projected_fields.insert(d, fnm);
                            } else if let Some((_, fld)) = storage_key.rsplit_once("::")
                                && self.find_layout_idx(storage_key).is_none()
                            {
                                projected_fields.insert(d, fld.to_string());
                            }
                        }
                    }
                    Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            let term_opt = f
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx));
                            let layout_opt = self
                                .find_layout_idx(storage_key)
                                .or_else(|| {
                                    storage_key
                                        .rsplit_once("::")
                                        .and_then(|(c, _)| self.find_layout_idx(c))
                                })
                                .or_else(|| {
                                    term_opt
                                        .and_then(|t| self.find_layout_idx(&t.canonical_component))
                                });
                            if let Some(l_idx) = layout_opt {
                                let pk = PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: true,
                                };
                                restrict_cols.insert(d, pk.clone());
                                ptr_meta.insert(d, pk);
                            }
                            if let Some(fnm) = term_opt.and_then(|t| t.field_name.clone()) {
                                projected_fields.insert(d, fnm);
                            } else if let Some((_, fld)) = storage_key.rsplit_once("::")
                                && self.find_layout_idx(storage_key).is_none()
                            {
                                projected_fields.insert(d, fld.to_string());
                            }
                        }
                    }
                    Inst::IterColRowsRead { .. } => {
                        if let Some(d) = dst {
                            ptr_meta.insert(d, PtrKind::SparseRows { is_mut: false });
                        }
                    }
                    Inst::IterColRowsWrite { .. } => {
                        if let Some(d) = dst {
                            ptr_meta.insert(d, PtrKind::SparseRows { is_mut: true });
                        }
                    }
                    Inst::EntityGet { storage_key, .. }
                    | Inst::ResRead {
                        resource: storage_key,
                    }
                    | Inst::TriggerPayload { event: storage_key }
                    | Inst::MigrateSrcPtr {
                        layout_key: storage_key,
                    } => {
                        if let Some(d) = dst
                            && let Some(l_idx) = self.find_layout_idx(storage_key)
                        {
                            ptr_meta.insert(
                                d,
                                PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: false,
                                },
                            );
                        }
                    }
                    Inst::EntityGetMut { storage_key, .. }
                    | Inst::ResWrite {
                        resource: storage_key,
                    }
                    | Inst::MigrateDstPtr {
                        layout_key: storage_key,
                    } => {
                        if let Some(d) = dst
                            && let Some(l_idx) = self.find_layout_idx(storage_key)
                        {
                            ptr_meta.insert(
                                d,
                                PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: true,
                                },
                            );
                        }
                    }
                    Inst::IterMarkChangedRange {
                        query_idx,
                        term_idx,
                        run_start,
                        run_len,
                    } => {
                        dirty_owners
                            .entry((run_start.0, run_len.0))
                            .or_default()
                            .push((*query_idx, *term_idx));
                    }
                    Inst::CmdCheckpoint => {
                        if let Some(d) = dst {
                            checkpoint_locals.push(d);
                        }
                    }
                    _ => {}
                }
            }
        }
        // Propagate TableLoad struct types into SlotAlloc / SlotStore / SlotLoad,
        // RowPtr pointee layout, and VecInsert / Copy vector dimensions.
        let mut slot_ty_overrides: HashMap<LocalId, MirType> = HashMap::new();
        for _ in 0..3 {
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    if let Some(d) = stmt.dst {
                        match &stmt.inst {
                            Inst::TableLoad {
                                table_name, field, ..
                            } if field.is_empty() => {
                                local_types.insert(
                                    d,
                                    MirType::Named(format!("__strata_table_{table_name}")),
                                );
                            }
                            Inst::SlotLoad { slot } => {
                                if let Some(ov) = slot_ty_overrides.get(slot) {
                                    local_types.insert(d, ov.clone());
                                }
                            }
                            Inst::FieldLoad {
                                layout_key,
                                field,
                                offset_bytes,
                                ..
                            } => {
                                if let Some(l_idx) = self.find_layout_idx(layout_key) {
                                    let f_opt = self.layouts[l_idx].fields.iter().find(|sf| {
                                        !sf.is_padding
                                            && ((!field.is_empty() && sf.name == *field)
                                                || sf.offset == *offset_bytes as usize)
                                    });
                                    if let Some(sf) = f_opt
                                        && matches!(sf.ty, Ty::BitSet(w) if w <= 64)
                                    {
                                        local_types.insert(d, MirType::U64);
                                    }
                                }
                            }
                            Inst::RowPtr { col_ptr, .. } => {
                                if let Some(PtrKind::LayoutPtr { layout_idx, is_mut }) =
                                    ptr_meta.get(col_ptr)
                                {
                                    ptr_meta.insert(
                                        d,
                                        PtrKind::LayoutPtr {
                                            layout_idx: *layout_idx,
                                            is_mut: *is_mut,
                                        },
                                    );
                                }
                                if let Some(pf) = projected_fields.get(col_ptr).cloned() {
                                    projected_fields.insert(d, pf);
                                }
                            }
                            Inst::VecInsert { vec, .. } => {
                                if let Some(vty) = local_types.get(vec).cloned() {
                                    local_types.insert(d, vty);
                                }
                            }
                            Inst::Copy { val } => {
                                if matches!(
                                    local_types.get(&d),
                                    Some(MirType::Vec2 | MirType::Vec3 | MirType::Vec4)
                                ) && let Some(vty) = local_types.get(val).cloned()
                                    && matches!(vty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4)
                                {
                                    local_types.insert(d, vty);
                                }
                            }
                            _ => {}
                        }
                    } else if let Inst::SlotStore { slot, val } = &stmt.inst
                        && let Some(vty) = local_types.get(val)
                        && matches!(vty, MirType::Named(k) if k.starts_with("__strata_table_"))
                    {
                        slot_ty_overrides.insert(*slot, vty.clone());
                    }
                }
            }
        }
        for (slot_id, st_ty) in &mut slot_allocs {
            if let Some(ov) = slot_ty_overrides.get(slot_id) {
                *st_ty = ov.clone();
                ptr_meta.insert(
                    *slot_id,
                    PtrKind::ScalarPtr {
                        c_pointee: self.c_ty(ov),
                        is_mut: true,
                    },
                );
            }
        }

        // Emit function-top C99 declarations (`BamIter*`, `SlotAlloc` buffers, spatial hit buffers, SSA locals).
        for sh_id in &spatial_hits_locals {
            let sid = sh_id.0;
            let _ = writeln!(s, "    StrataSpatialHits spatial_buf_{sid};");
            let _ = writeln!(
                s,
                "    memset(&spatial_buf_{sid}, 0, sizeof(spatial_buf_{sid}));"
            );
            let _ = writeln!(s, "    (void)spatial_buf_{sid};");
        }
        for qb in &f.query_bindings {
            let qi = qb.query_idx;
            let _ = writeln!(s, "    BamIter* iter_{qi} = NULL;");
            let _ = writeln!(s, "    size_t iter_{qi}_len = 0u;");
            let _ = writeln!(s, "    const BamEntity* iter_{qi}_ents = NULL;");
            let _ = writeln!(s, "    BamEntity iter_{qi}_cur_ent = BAM_ENTITY_NULL;");
            let _ = writeln!(
                s,
                "    (void)iter_{qi}; (void)iter_{qi}_len; (void)iter_{qi}_ents; (void)iter_{qi}_cur_ent;"
            );
        }
        for (slot_id, ty) in &slot_allocs {
            let slot_cty = self.c_ty(ty);
            let sid = slot_id.0;
            let _ = writeln!(s, "    {slot_cty} slot_buf_{sid};");
            let _ = writeln!(s, "    memset(&slot_buf_{sid}, 0, sizeof(slot_buf_{sid}));");
            if let MirType::Named(key) = ty
                && let Some(l_idx) = self.find_layout_idx(key)
                && self.layouts[l_idx].size > 0
            {
                let def_fn = format!(
                    "strata_default_{l_idx}_{}",
                    sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                );
                let _ = writeln!(s, "    slot_buf_{sid} = {def_fn}();");
            }
            let _ = writeln!(s, "    (void)slot_buf_{sid};");
        }

        for local in &f.locals {
            let lid = local.id.0;
            if let Some(pk) = restrict_cols.get(&local.id) {
                let cty = pk.c_type(&self.layout_c_names);
                let _ = writeln!(s, "    {cty} BAM_RESTRICT col_{lid} = NULL;");
                let _ = writeln!(s, "    (void)col_{lid};");
            } else if let Some(pk) = ptr_meta.get(&local.id) {
                let cty = pk.c_type(&self.layout_c_names);
                let _ = writeln!(s, "    {cty} v_{lid} = NULL;");
                let _ = writeln!(s, "    (void)v_{lid};");
            } else {
                let eff_ty = local_types.get(&local.id).unwrap_or(&local.ty);
                let cty = self.c_ty(eff_ty);
                if self.is_aggregate_mir_ty(eff_ty) {
                    let _ = writeln!(s, "    {cty} v_{lid};");
                    let _ = writeln!(s, "    memset(&v_{lid}, 0, sizeof(v_{lid}));");
                } else {
                    let init = self.c_zero_for_mir(eff_ty);
                    let _ = writeln!(s, "    {cty} v_{lid} = {init};");
                }
                let _ = writeln!(s, "    (void)v_{lid};");
            }
        }

        if is_helper {
            for (i, p) in f.params.iter().enumerate() {
                if let Some(ploc) = p.local {
                    let lhs = if restrict_cols.contains_key(&ploc) {
                        format!("col_{}", ploc.0)
                    } else {
                        format!("v_{}", ploc.0)
                    };
                    let _ = writeln!(s, "    {lhs} = p_{i};");
                }
            }
        }

        let (reachable, label_targets) = analyze_cfg(&f.blocks);
        if f.blocks.is_empty() {
            if is_void_helper {
                let _ = writeln!(s, "    return;");
            } else if is_helper {
                let z = self.c_zero_for_mir(&f.ret_ty);
                let _ = writeln!(s, "    return {z};");
            } else {
                let _ = writeln!(s, "    return BAM_RESULT_OK;");
            }
            let _ = writeln!(s, "}}");
            return Ok(s);
        }

        if label_targets.contains(&0) {
            let _ = writeln!(s, "    goto bb_0;");
        }

        let fc = FnEmitCtx {
            parent: self,
            func: f,
            is_observer,
            is_migration,
            is_void_helper,
            is_helper,
            ptr_meta,
            restrict_cols,
            projected_fields,
            dirty_owners,
            local_types,
            last_checkpoint: checkpoint_locals.first().copied(),
        };

        for bb in &f.blocks {
            if !reachable.contains(&bb.id.0) {
                continue;
            }
            if label_targets.contains(&bb.id.0) {
                let _ = writeln!(s, "bb_{}:;", bb.id.0);
            }
            for stmt in &bb.stmts {
                fc.emit_stmt(stmt, &mut s)?;
            }
            fc.emit_terminator(&bb.terminator, &mut s)?;
        }

        let _ = writeln!(s, "}}");
        Ok(s)
    }

    fn emit_startup_objects_fn(&mut self) -> Result<(), CodegenError> {
        if self.mir.objects.is_empty() {
            return Ok(());
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "static BamResult strata_sys_startup_objects(BamSystemCtx* sys_ctx, void* user_data) {{"
        );
        let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
        let _ = writeln!(
            s,
            "    if (sys_ctx == NULL || state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
        );
        let _ = writeln!(
            s,
            "    if (state->objects_initialized) {{ return BAM_RESULT_OK; }}"
        );
        let _ = writeln!(s, "    state->objects_initialized = BAM_TRUE;");
        let _ = writeln!(s, "    BamCommands* cmds = NULL;");
        let _ = writeln!(
            s,
            "    if (state->api->sys_commands != NULL) {{ (void)state->api->sys_commands(sys_ctx, &cmds); }}"
        );

        let objs = self.mir.objects.clone();
        let mut probe_q_idx = 0usize;
        for (o_idx, obj) in objs.iter().enumerate() {
            let reg_obj = &self.objects[o_idx];
            let _ = writeln!(s, "    /* Named Object: {} */", obj.name);
            let _ = writeln!(
                s,
                "    if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL) {{"
            );
            if reg_obj.primary_comp_idx.is_some() {
                let qi = probe_q_idx;
                probe_q_idx += 1;
                let _ = writeln!(s, "        BamIter* it = NULL;");
                let _ = writeln!(
                    s,
                    "        if (state->api->sys_query != NULL && state->api->sys_query(sys_ctx, {qi}u, &it) == BAM_RESULT_OK && it != NULL) {{"
                );
                let _ = writeln!(s, "            size_t len = 0u;");
                let _ = writeln!(
                    s,
                    "            if (state->api->iter_next_chunk != NULL && state->api->iter_next_chunk(it, &len) != BAM_FALSE && len > 0u && state->api->iter_entities != NULL) {{"
                );
                let _ = writeln!(
                    s,
                    "                const BamEntity* ents = state->api->iter_entities(it);"
                );
                let _ = writeln!(
                    s,
                    "                if (ents != NULL && ents[0] != BAM_ENTITY_NULL) {{ state->named_objects[{o_idx}] = ents[0]; }}"
                );
                let _ = writeln!(s, "            }}");
                let _ = writeln!(s, "        }}");
            }
            let _ = writeln!(
                s,
                "        if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL && cmds != NULL) {{"
            );
            let bundle = self.build_object_component_bundle(obj);
            let n_comps = bundle.len().max(1);
            let _ = writeln!(s, "            BamComponent comps[{n_comps}u];");
            let _ = writeln!(s, "            const uint8_t* datas[{n_comps}u];");
            for (bi, (c_idx, init_opt)) in bundle.iter().enumerate() {
                let comp = &self.components[*c_idx];
                let _ = writeln!(s, "            comps[{bi}u] = state->components[{c_idx}u];");
                if let Some(l_idx) = comp.layout_idx
                    && self.layouts[l_idx].size > 0
                {
                    let cty = &self.layout_c_names[l_idx];
                    let def_fn = format!(
                        "strata_default_{l_idx}_{}",
                        sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                    );
                    let _ = writeln!(s, "            {cty} val_{bi} = {def_fn}();");
                    if let Some(ci) = init_opt {
                        for (fname, fexpr) in &ci.fields {
                            let fc = sanitize_c_field(fname);
                            let field_ty = self.layouts[l_idx]
                                .fields
                                .iter()
                                .find(|f| f.name == *fname)
                                .map(|f| f.ty.clone())
                                .unwrap_or(Ty::Unknown);
                            let expr = self.c_hir_expr(fexpr, &field_ty);
                            let _ = writeln!(s, "            val_{bi}.{fc} = {expr};");
                        }
                    }
                    let _ = writeln!(s, "            datas[{bi}u] = (const uint8_t*)&val_{bi};");
                } else {
                    let _ = writeln!(s, "            datas[{bi}u] = NULL;");
                }
            }
            if bundle.is_empty() {
                let _ = writeln!(s, "            comps[0u] = BAM_COMPONENT_INVALID;");
                let _ = writeln!(s, "            datas[0u] = NULL;");
            }
            let spawn_fn = if obj.is_persist {
                "cmd_spawn_persistent"
            } else {
                "cmd_spawn"
            };
            let real_count = bundle.len();
            let _ = writeln!(
                s,
                "            BamEntity spawned = BAM_ENTITY_NULL;\n            if (state->api->{spawn_fn} != NULL) {{\n                (void)state->api->{spawn_fn}(cmds, comps, datas, {real_count}u, &spawned);\n            }}\n            state->named_objects[{o_idx}] = spawned;"
            );
            let _ = writeln!(s, "        }}");
            let escaped = c_escape(&obj.name);
            let _ = writeln!(
                s,
                "        if (state->named_objects[{o_idx}] != BAM_ENTITY_NULL && state->host_ctx != NULL && state->api->bind_named_object != NULL) {{"
            );
            let _ = writeln!(
                s,
                "            (void)state->api->bind_named_object(state->host_ctx, bam_str_view(\"{escaped}\"), state->named_objects[{o_idx}]);"
            );
            let _ = writeln!(s, "        }}");
            let _ = writeln!(s, "    }}");
        }
        let _ = writeln!(s, "    return BAM_RESULT_OK;");
        let _ = writeln!(s, "}}\n");
        self.out.push_str(&s);
        Ok(())
    }

    fn build_object_component_bundle<'b>(
        &self,
        obj: &'b HirObject,
    ) -> Vec<(usize, Option<&'b HirCompInit>)> {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut out: Vec<(usize, Option<&'b HirCompInit>)> = Vec::new();
        let mut queue: VecDeque<usize> = VecDeque::new();

        for ci in &obj.inits {
            let idx_opt = ci
                .canonical_component
                .as_deref()
                .and_then(|cc| self.find_comp_idx(cc))
                .or_else(|| self.find_comp_idx(&ci.component));
            if let Some(idx) = idx_opt
                && seen.insert(idx)
            {
                out.push((idx, Some(ci)));
                queue.push_back(idx);
            }
        }
        for cname in &obj.components {
            if let Some(idx) = self.find_comp_idx(cname)
                && seen.insert(idx)
            {
                out.push((idx, None));
                queue.push_back(idx);
            }
        }
        while let Some(c_idx) = queue.pop_front() {
            for &req in &self.components[c_idx].required_indices {
                if seen.insert(req) {
                    out.push((req, None));
                    queue.push_back(req);
                }
            }
        }
        out
    }

    fn emit_manifest_init_shutdown(&mut self) -> Result<(), CodegenError> {
        let mod_name = c_escape(&self.mir.module_path);

        let _ = writeln!(
            self.out,
            "\
static const BamManifest STRATA_MANIFEST = {{
    (uint32_t)sizeof(BamManifest),
    BAM_ABI_VERSION,
    \"{mod_name}\",
    \"0.3.0\",
    0u,
    0u,
    NULL,
    NULL
}};

BAM_EXPORT const BamManifest* bamabi_manifest(void) {{
    return &STRATA_MANIFEST;
}}
"
        );

        let _ = writeln!(
            self.out,
            "\
BAM_EXPORT BamResult bamabi_init(const BamHostApi* api, BamLoadCtx* load_ctx, BamInstance** instance_out) {{
    if (api == NULL || load_ctx == NULL || instance_out == NULL) {{
        return BAM_RESULT_NULL_POINTER;
    }}
    if (api->struct_size < BAM_HOST_API_MIN_V0_2_SIZE) {{
        return BAM_RESULT_INVALID_VERSION;
    }}
    if (api->register_component == NULL) {{
        return BAM_RESULT_UNSUPPORTED;
    }}
    StrataModState* state = (StrataModState*)calloc(1u, sizeof(StrataModState));
    if (state == NULL) {{
        return BAM_RESULT_INTERNAL_ERROR;
    }}
    state->api = api;
    state->host_ctx = (api->load_host_ctx != NULL) ? api->load_host_ctx(load_ctx) : NULL;
    *instance_out = (BamInstance*)state;
"
        );

        let comps = self.components.clone();
        for comp in &comps {
            if comp.has_mod_res
                && let Some(l_idx) = comp.layout_idx
            {
                let short = short_name(&self.layouts[l_idx].canonical_name);
                let def_fn = format!("strata_default_{l_idx}_{}", sanitize_ident(short));
                let _ = writeln!(self.out, "    state->mod_res_{} = {def_fn}();", comp.idx);
            }
        }
        for comp in &comps {
            let idx = comp.idx;
            let canon_esc = c_escape(&comp.canonical);
            let fp = comp.fingerprint;
            let uuid_bytes: Vec<String> = comp
                .uuid
                .bytes
                .iter()
                .map(|b| format!("0x{b:02X}u"))
                .collect();
            let _ = writeln!(self.out, "    /* Component [{idx}]: {} */", comp.canonical);
            let _ = writeln!(self.out, "    {{");
            let mut field_count = 0usize;
            if let Some(l_idx) = comp.layout_idx {
                let all_fields = &self.layouts[l_idx].fields;
                if !all_fields.is_empty() {
                    field_count = all_fields.len();
                    let _ = writeln!(
                        self.out,
                        "        static const BamFieldDesc fields_{idx}[{field_count}] = {{"
                    );
                    for (fi, fld) in all_fields.iter().enumerate() {
                        let comma = if fi + 1 < all_fields.len() { "," } else { "" };
                        let f_esc = c_escape(&fld.name);
                        let t_esc = c_escape(&fld.type_tag);
                        let _ = writeln!(
                            self.out,
                            "            {{ (uint32_t)sizeof(BamFieldDesc), (BamFieldKind){}, {{ (const uint8_t*)\"{f_esc}\", sizeof(\"{f_esc}\") - 1u }}, {{ (const uint8_t*)\"{t_esc}\", sizeof(\"{t_esc}\") - 1u }}, {}u, {}u, {}u }}{comma}",
                            fld.bam_field_kind, fld.offset, fld.size, fld.align
                        );
                    }
                    let _ = writeln!(self.out, "        }};");
                }
            }
            let _ = writeln!(
                self.out,
                "        BamComponentUuid comp_uuid_{idx} = {{ {{ {} }} }};",
                uuid_bytes.join(", ")
            );
            let _ = writeln!(
                self.out,
                "        BamComponentDesc cdesc = bam_desc_component_with_layout(\"{canon_esc}\", {}u, {}u, NULL);",
                comp.size, comp.align
            );
            let _ = writeln!(self.out, "        cdesc.uuid = comp_uuid_{idx};");
            let _ = writeln!(self.out, "        cdesc.flags = {}u;", comp.flags);
            let _ = writeln!(
                self.out,
                "        cdesc.schema_fingerprint = 0x{fp:016X}ull;"
            );
            if field_count > 0 {
                let _ = writeln!(self.out, "        cdesc.fields = fields_{idx};");
                let _ = writeln!(self.out, "        cdesc.field_count = {field_count}u;");
            }
            let size = comp.size;
            let align = comp.align;
            if let Some(ref mig_fn) = comp.migration_fn {
                let _ = writeln!(
                    self.out,
                    "\
        BamResult reg_rc = BAM_RESULT_NOT_FOUND;
        if (state->host_ctx != NULL && api->resolve_component != NULL) {{
            reg_rc = api->resolve_component(state->host_ctx, cdesc.name, NULL, &state->components[{idx}]);
            if (reg_rc == BAM_RESULT_OK && api->component_layout_info != NULL) {{
                BamLayoutInfo linfo;
                memset(&linfo, 0, sizeof(linfo));
                linfo.struct_size = (uint32_t)sizeof(BamLayoutInfo);
                if (api->component_layout_info(state->host_ctx, state->components[{idx}], &linfo) == BAM_RESULT_OK) {{
                    if (linfo.schema_fingerprint != 0x{fp:016X}ull || linfo.size != {size}u || linfo.align != {align}u) {{
                        if (api->migrate_component_column == NULL) {{
                            free(state);
                            *instance_out = NULL;
                            return BAM_RESULT_TYPE_MISMATCH;
                        }}
                        reg_rc = api->migrate_component_column(load_ctx, state->components[{idx}], 0ull, &cdesc, {mig_fn}, state);
                    }}
                }}
            }}
        }}
        if (reg_rc == BAM_RESULT_NOT_FOUND) {{
            reg_rc = api->register_component(load_ctx, &cdesc, &state->components[{idx}]);
            if (reg_rc == BAM_RESULT_TYPE_MISMATCH) {{
                if (state->host_ctx == NULL || api->resolve_component == NULL || api->migrate_component_column == NULL) {{
                    free(state);
                    *instance_out = NULL;
                    return BAM_RESULT_TYPE_MISMATCH;
                }}
                reg_rc = api->resolve_component(state->host_ctx, cdesc.name, NULL, &state->components[{idx}]);
                if (reg_rc == BAM_RESULT_OK) {{
                    reg_rc = api->migrate_component_column(load_ctx, state->components[{idx}], 0ull, &cdesc, {mig_fn}, state);
                }}
            }}
        }}"
                );
            } else {
                let resolve_by_name_only = comp.layout_idx.is_none()
                    || matches!(
                        comp.item_kind,
                        Some(
                            SchemaItemKind::Resource
                                | SchemaItemKind::Event
                                | SchemaItemKind::Stream
                                | SchemaItemKind::SpatialGrid
                                | SchemaItemKind::SpatialHistory
                        )
                    );
                let uuid_arg = if resolve_by_name_only {
                    "NULL".to_string()
                } else {
                    format!("&comp_uuid_{idx}")
                };
                let _ = writeln!(
                    self.out,
                    "\
        BamResult reg_rc = BAM_RESULT_NOT_FOUND;
        if (state->host_ctx != NULL && api->resolve_component != NULL) {{
            reg_rc = api->resolve_component(state->host_ctx, cdesc.name, {uuid_arg}, &state->components[{idx}]);
        }}
        if (reg_rc == BAM_RESULT_NOT_FOUND) {{
            reg_rc = api->register_component(load_ctx, &cdesc, &state->components[{idx}]);
        }}"
                );
            }
            let _ = writeln!(
                self.out,
                "\
        if (reg_rc == BAM_RESULT_OK && state->host_ctx != NULL && api->component_layout_info != NULL) {{
            BamLayoutInfo linfo;
            memset(&linfo, 0, sizeof(linfo));
            linfo.struct_size = (uint32_t)sizeof(BamLayoutInfo);
            if (api->component_layout_info(state->host_ctx, state->components[{idx}], &linfo) == BAM_RESULT_OK) {{
                if ((linfo.flags & BAM_STORAGE_FLAG_RESOURCE) != 0u) {{
                    state->res_flags[{idx}] = 1u;
                }} else if ((linfo.flags & BAM_STORAGE_FLAG_MESSAGE) != 0u) {{
                    state->res_flags[{idx}] = 2u;
                }}
            }}
        }}
        if (reg_rc != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return reg_rc; }}"
            );
            let _ = writeln!(self.out, "    }}");
        }

        if !self.relations.is_empty() {
            let rels = self.relations.clone();
            let _ = writeln!(
                self.out,
                "    if (api->register_relation == NULL) {{ free(state); *instance_out = NULL; return BAM_RESULT_UNSUPPORTED; }}"
            );
            for r in &rels {
                let idx = r.idx;
                let esc = c_escape(&r.canonical);
                let uuid_bytes: Vec<String> =
                    r.uuid.bytes.iter().map(|b| format!("0x{b:02X}u")).collect();
                let _ = writeln!(self.out, "    {{");
                let _ = writeln!(
                    self.out,
                    "        BamComponentUuid rel_uuid_{idx} = {{ {{ {} }} }};",
                    uuid_bytes.join(", ")
                );
                let _ = writeln!(self.out, "        BamRelationDesc rdesc;");
                let _ = writeln!(self.out, "        memset(&rdesc, 0, sizeof(rdesc));");
                let _ = writeln!(
                    self.out,
                    "        rdesc.struct_size = (uint32_t)sizeof(BamRelationDesc);"
                );
                let _ = writeln!(self.out, "        rdesc.flags = {};", r.flags_expr);
                let _ = writeln!(self.out, "        rdesc.name = \"{esc}\";");
                let _ = writeln!(self.out, "        rdesc.uuid = rel_uuid_{idx};");
                let _ = writeln!(self.out, "        rdesc.data_size = {}u;", r.data_size);
                let _ = writeln!(self.out, "        rdesc.data_align = {}u;", r.data_align);
                let _ = writeln!(self.out, "        rdesc.max_degree = {}u;", r.max_degree);
                let _ = writeln!(
                    self.out,
                    "        BamResult rrc = api->register_relation(load_ctx, &rdesc, &state->relations[{idx}]);"
                );
                let _ = writeln!(
                    self.out,
                    "        if (rrc != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return rrc; }}"
                );
                let _ = writeln!(self.out, "    }}");
            }
        }

        if !self.sets.is_empty() {
            let sets = self.sets.clone();
            let set_idx_by_name: HashMap<String, usize> =
                sets.iter().map(|st| (st.name.clone(), st.idx)).collect();
            let _ = writeln!(self.out, "    if (api->configure_schedule_set != NULL) {{");
            for s in &sets {
                let idx = s.idx;
                let esc = c_escape(&s.name);
                let after_handles: Vec<String> = s
                    .after_sets
                    .iter()
                    .filter_map(|n| set_idx_by_name.get(n))
                    .map(|p_idx| format!("state->sets[{p_idx}]"))
                    .collect();
                let _ = writeln!(self.out, "        {{");
                if !after_handles.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "            BamSystemSet after_sets_{idx}[{}] = {{ {} }};",
                        after_handles.len(),
                        after_handles.join(", ")
                    );
                }
                let _ = writeln!(self.out, "            BamScheduleSetDesc set_desc;");
                let _ = writeln!(
                    self.out,
                    "            memset(&set_desc, 0, sizeof(set_desc));"
                );
                let _ = writeln!(
                    self.out,
                    "            set_desc.struct_size = (uint32_t)sizeof(BamScheduleSetDesc);"
                );
                let _ = writeln!(self.out, "            set_desc.flags = {};", s.flags_expr);
                let _ = writeln!(self.out, "            set_desc.schedule = {};", s.schedule);
                let _ = writeln!(self.out, "            set_desc.name = \"{esc}\";");
                if !after_handles.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "            set_desc.after_sets = after_sets_{idx};"
                    );
                    let _ = writeln!(
                        self.out,
                        "            set_desc.after_count = {}u;",
                        after_handles.len()
                    );
                }
                let _ = writeln!(
                    self.out,
                    "            BamResult src = api->configure_schedule_set(load_ctx, &set_desc, &state->sets[{idx}]);"
                );
                let _ = writeln!(
                    self.out,
                    "            if (src != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return src; }}"
                );
                let _ = writeln!(self.out, "        }}");
            }
            let _ = writeln!(self.out, "    }}");
        }

        let systems = self.systems.clone();
        for sys in &systems {
            self.emit_register_single_system(sys)?;
        }

        let observers = self.observers.clone();
        if !observers.is_empty() {
            let _ = writeln!(
                self.out,
                "    if (api->register_observer == NULL) {{ free(state); *instance_out = NULL; return BAM_RESULT_UNSUPPORTED; }}"
            );
            for obs in &observers {
                let esc = c_escape(&obs.reg_name);
                let _ = writeln!(self.out, "    {{");
                let _ = writeln!(
                    self.out,
                    "        BamObserverDesc odesc = bam_observer_desc(state->components[{}], BAM_ENTITY_NULL, {}, state);",
                    obs.event_comp_idx, obs.c_fn_name
                );
                let _ = writeln!(self.out, "        odesc.name = \"{esc}\";");
                let _ = writeln!(
                    self.out,
                    "        BamResult orc = api->register_observer(load_ctx, &odesc);"
                );
                let _ = writeln!(
                    self.out,
                    "        if (orc != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return orc; }}"
                );
                let _ = writeln!(self.out, "    }}");
            }
        }

        let _ = writeln!(self.out, "    return BAM_RESULT_OK;");
        let _ = writeln!(
            self.out,
            "}}\n\nBAM_EXPORT void bamabi_shutdown(BamInstance* instance) {{\n    if (instance != NULL) {{\n        free(instance);\n    }}\n}}"
        );
        Ok(())
    }

    fn emit_register_single_system(&mut self, sys: &RegSystem) -> Result<(), CodegenError> {
        let s_idx = sys.idx;
        let _ = writeln!(self.out, "    /* System [{s_idx}]: {} */", sys.reg_name);
        let _ = writeln!(self.out, "    {{");

        let mut query_terms_c: Vec<Vec<String>> = Vec::new();
        let mut res_modes: BTreeMap<usize, bool> = BTreeMap::new();
        if sys.is_startup_objects {
            for obj in &self.objects {
                if let Some(p_idx) = obj.primary_comp_idx {
                    query_terms_c.push(vec![format!(
                        "bam_term_desc(state->components[{p_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                    )]);
                }
            }
        } else if let Some(fn_idx) = sys.mir_fn_idx {
            let f = &self.mir_functions()[fn_idx];

            for qb in &f.query_bindings {
                let mut t_strs = Vec::new();
                for term in &qb.terms {
                    let c_idx = self
                        .find_comp_idx(&term.canonical_component)
                        .ok_or_else(|| CodegenError::Unsupported {
                            context: format!("c99::system({})", f.name),
                            detail: format!(
                                "missing component `{}` in query {}",
                                term.canonical_component, qb.query_idx
                            ),
                        })?;
                    let mode_c = c_access_mode(term.mode);
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], {mode_c}, 0u)"
                    ));
                }
                for w in &qb.with_filters {
                    if let Some(c_idx) = self.find_comp_idx(w) {
                        t_strs.push(format!(
                            "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                        ));
                    }
                }
                for wo in &qb.without_filters {
                    if let Some(c_idx) = self.find_comp_idx(wo) {
                        t_strs.push(format!(
                            "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_WITHOUT, 0u)"
                        ));
                    }
                }
                if t_strs.len() > MAX_TERMS_PER_QUERY {
                    return Err(CodegenError::Unsupported {
                        context: format!("c99::system({})", f.name),
                        detail: format!(
                            "query {} exceeds MAX_TERMS_PER_QUERY ({})",
                            qb.query_idx, MAX_TERMS_PER_QUERY
                        ),
                    });
                }
                query_terms_c.push(t_strs);
            }

            for r in &f.resources {
                if let Some(c_idx) = self.find_comp_idx(&r.canonical_name) {
                    res_modes
                        .entry(c_idx)
                        .and_modify(|m| *m |= r.mutable)
                        .or_insert(r.mutable);
                }
            }
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    match &stmt.inst {
                        Inst::ResRead { resource }
                        | Inst::SpatialQueryDisc {
                            grid_name: resource,
                            ..
                        }
                        | Inst::SpatialQuerySegmentAt {
                            history_name: resource,
                            ..
                        } => {
                            if let Some(c_idx) = self.find_comp_idx(resource) {
                                res_modes.entry(c_idx).or_insert(false);
                            }
                        }
                        Inst::ResWrite { resource } => {
                            if let Some(c_idx) = self.find_comp_idx(resource) {
                                res_modes.insert(c_idx, true);
                            }
                        }
                        _ => {}
                    }
                }
            }
            for &r_idx in &sys.run_if_resources {
                res_modes.entry(r_idx).or_insert(false);
            }
        }

        let ecs_q_count = query_terms_c.len();
        let max_res_queries = res_modes.len().div_ceil(MAX_TERMS_PER_QUERY);
        let max_total_queries = ecs_q_count + max_res_queries;
        if max_total_queries > MAX_QUERIES_PER_SYSTEM {
            return Err(CodegenError::Unsupported {
                context: format!("c99::system({})", sys.reg_name),
                detail: format!(
                    "exceeds MAX_QUERIES_PER_SYSTEM ({})",
                    MAX_QUERIES_PER_SYSTEM
                ),
            });
        }

        for (qi, terms) in query_terms_c.iter().enumerate() {
            if !terms.is_empty() {
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc terms_{s_idx}_{qi}[{}];",
                    terms.len()
                );
                for (ti, t_expr) in terms.iter().enumerate() {
                    let _ = writeln!(self.out, "        terms_{s_idx}_{qi}[{ti}] = {t_expr};");
                }
            }
        }

        let has_any_queries = max_total_queries > 0;
        if has_any_queries {
            let _ = writeln!(
                self.out,
                "        BamQueryDesc qdescs_{s_idx}[{max_total_queries}u];"
            );
            let _ = writeln!(
                self.out,
                "        uint32_t q_count_{s_idx} = {ecs_q_count}u;"
            );
            for (qi, terms) in query_terms_c.iter().enumerate() {
                let _ = writeln!(
                    self.out,
                    "        memset(&qdescs_{s_idx}[{qi}], 0, sizeof(BamQueryDesc));"
                );
                let _ = writeln!(
                    self.out,
                    "        qdescs_{s_idx}[{qi}].struct_size = (uint32_t)sizeof(BamQueryDesc);"
                );
                if !terms.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].terms = terms_{s_idx}_{qi};"
                    );
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].term_count = {}u;",
                        terms.len()
                    );
                }
            }
            if !res_modes.is_empty() {
                let res_cap = res_modes.len();
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc res_terms_{s_idx}[{res_cap}u];"
                );
                let _ = writeln!(self.out, "        uint32_t res_n_{s_idx} = 0u;");
                for (&c_idx, &is_mut) in &res_modes {
                    let access = if is_mut {
                        "BAM_ACCESS_RESOURCE_WRITE"
                    } else {
                        "BAM_ACCESS_RESOURCE_READ"
                    };
                    let _ = writeln!(
                        self.out,
                        "        if (state->res_flags[{c_idx}] == 1u) {{ res_terms_{s_idx}[res_n_{s_idx}++] = bam_term_desc(state->components[{c_idx}], {access}, 0u); }}"
                    );
                }
                let _ = writeln!(
                    self.out,
                    "\
        uint32_t res_off_{s_idx} = 0u;
        while (res_off_{s_idx} < res_n_{s_idx} && q_count_{s_idx} < {max_total_queries}u) {{
            uint32_t chunk_n = res_n_{s_idx} - res_off_{s_idx};
            if (chunk_n > {MAX_TERMS_PER_QUERY}u) {{ chunk_n = {MAX_TERMS_PER_QUERY}u; }}
            memset(&qdescs_{s_idx}[q_count_{s_idx}], 0, sizeof(BamQueryDesc));
            qdescs_{s_idx}[q_count_{s_idx}].struct_size = (uint32_t)sizeof(BamQueryDesc);
            qdescs_{s_idx}[q_count_{s_idx}].terms = &res_terms_{s_idx}[res_off_{s_idx}];
            qdescs_{s_idx}[q_count_{s_idx}].term_count = chunk_n;
            q_count_{s_idx}++;
            res_off_{s_idx} += chunk_n;
        }}"
                );
            }
        }

        let reg_esc = c_escape(&sys.reg_name);
        let q_ptr = if has_any_queries {
            format!("(q_count_{s_idx} > 0u) ? qdescs_{s_idx} : NULL")
        } else {
            "NULL".to_string()
        };
        let q_cnt = if has_any_queries {
            format!("q_count_{s_idx}")
        } else {
            "0u".to_string()
        };
        let _ = writeln!(self.out, "        BamSystemDesc sdesc;");
        let _ = writeln!(
            self.out,
            "        memset(&sdesc, 0, sizeof(BamSystemDesc));"
        );
        let _ = writeln!(
            self.out,
            "        sdesc.struct_size = (uint32_t)sizeof(BamSystemDesc);"
        );
        let _ = writeln!(self.out, "        sdesc.flags = {};", sys.flags_expr);
        let _ = writeln!(self.out, "        sdesc.name = \"{reg_esc}\";");
        let _ = writeln!(self.out, "        sdesc.queries = {q_ptr};");
        let _ = writeln!(self.out, "        sdesc.query_count = {q_cnt};");
        let _ = writeln!(self.out, "        sdesc.callback = {};", sys.c_fn_name);
        let _ = writeln!(self.out, "        sdesc.user_data = state;");
        let _ = writeln!(self.out, "        sdesc.schedule = {};", sys.schedule);

        if !sys.after_names.is_empty() {
            let after_lits: Vec<String> = sys
                .after_names
                .iter()
                .map(|a| format!("\"{}\"", c_escape(a)))
                .collect();
            let _ = writeln!(
                self.out,
                "        static const char* const sys_after_{s_idx}[{}] = {{ {} }};",
                after_lits.len(),
                after_lits.join(", ")
            );
            let _ = writeln!(self.out, "        sdesc.after = sys_after_{s_idx};");
            let _ = writeln!(
                self.out,
                "        sdesc.after_count = {}u;",
                after_lits.len()
            );
        }
        if !sys.in_sets.is_empty() {
            let set_lits: Vec<String> = sys
                .in_sets
                .iter()
                .map(|n| format!("\"{}\"", c_escape(n)))
                .collect();
            let _ = writeln!(
                self.out,
                "        static const char* const sys_sets_{s_idx}[{}] = {{ {} }};",
                set_lits.len(),
                set_lits.join(", ")
            );
            let _ = writeln!(self.out, "        sdesc.in_sets = sys_sets_{s_idx};");
            let _ = writeln!(
                self.out,
                "        sdesc.in_set_count = {}u;",
                set_lits.len()
            );
        }
        if let Some(ref rif) = sys.run_if_fn {
            let _ = writeln!(
                self.out,
                "        /* Schedule condition `{rif}` enforced at entry of `{}`. */",
                sys.c_fn_name
            );
        }

        let _ = writeln!(
            self.out,
            "\
        BamResult syarc = BAM_RESULT_UNSUPPORTED;
        if (api->register_system_handle != NULL && api->mount_system_in_schedule != NULL) {{
            syarc = api->register_system_handle(load_ctx, &sdesc, &state->systems[{s_idx}]);
            if (syarc == BAM_RESULT_OK) {{
                syarc = api->mount_system_in_schedule(load_ctx, state->systems[{s_idx}], {}, BAM_SYSTEM_SET_INVALID);
            }}
        }} else if (api->register_system != NULL) {{
            syarc = api->register_system(load_ctx, &sdesc);
        }}
        if (syarc != BAM_RESULT_OK) {{
            free(state);
            *instance_out = NULL;
            return syarc;
        }}",
            sys.schedule
        );
        let _ = writeln!(self.out, "    }}");
        Ok(())
    }

    fn is_aggregate_mir_ty(&self, ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::Vec2
                | MirType::Vec3
                | MirType::Vec4
                | MirType::Array { .. }
                | MirType::Tuple(_)
        ) || matches!(
            ty,
            MirType::Named(k) if k.starts_with("__strata_table_")
                || self.find_layout_idx(k).is_some()
                || k.contains("SpatialHits")
                || k.contains("Vec2")
                || k.contains("Vec3")
                || k.contains("Vec4")
                || k.contains("Quat")
                || k.contains("Rgba")
                || k.contains("IVec")
                || k.contains("UVec")
        )
    }

    fn c_ty(&self, ty: &MirType) -> String {
        match ty {
            MirType::Bool => "BamBool".to_string(),
            MirType::I8 => "int8_t".to_string(),
            MirType::I16 => "int16_t".to_string(),
            MirType::I32 | MirType::Fix32 => "int32_t".to_string(),
            MirType::I64 | MirType::Fix64 => "int64_t".to_string(),
            MirType::Unit | MirType::U8 => "uint8_t".to_string(),
            MirType::U16 => "uint16_t".to_string(),
            MirType::U32 | MirType::Sym => "uint32_t".to_string(),
            MirType::U64 => "uint64_t".to_string(),
            MirType::F32 => "float".to_string(),
            MirType::F64 => "double".to_string(),
            MirType::Entity => "BamEntity".to_string(),
            MirType::Vec2 => "StrataVec2".to_string(),
            MirType::Vec3 => "StrataVec3".to_string(),
            MirType::Vec4 => "StrataVec4".to_string(),
            MirType::Ptr => "const void*".to_string(),
            MirType::MutPtr => "void*".to_string(),
            MirType::QueryIter => "BamIter*".to_string(),
            MirType::Checkpoint => "size_t".to_string(),
            MirType::Tuple(elems) => self
                .tuple_name(elems)
                .map(str::to_string)
                .unwrap_or_else(|| "uint8_t".to_string()),
            MirType::Array { elem, len } => self
                .array_name(elem, *len)
                .map(str::to_string)
                .unwrap_or_else(|| "uint8_t".to_string()),
            MirType::Named(key) => {
                if let Some(tname) = key.strip_prefix("__strata_table_") {
                    format!("StrataTable_{}", sanitize_ident(tname))
                } else if let Some(l_idx) = self.find_layout_idx(key) {
                    self.layout_c_names[l_idx].clone()
                } else if key.contains("SpatialHits") {
                    "StrataSpatialHits".to_string()
                } else if key.contains("Vec2") || key == "vec2" {
                    "StrataVec2".to_string()
                } else if key.contains("Vec3") || key == "vec3" {
                    "StrataVec3".to_string()
                } else if key.contains("Vec4") || key.contains("Quat") || key.contains("Rgba") {
                    "StrataVec4".to_string()
                } else if key.contains("IVec2") {
                    "StrataIVec2".to_string()
                } else if key.contains("IVec3") {
                    "StrataIVec3".to_string()
                } else if key.contains("UVec2") {
                    "StrataUVec2".to_string()
                } else if self.mir.enums.iter().any(|e| {
                    e.canonical_name == *key || short_name(&e.canonical_name) == short_name(key)
                }) {
                    "int32_t".to_string()
                } else if let Some(t) = self.mir.tables.iter().find(|tb| tb.name == *key) {
                    format!("StrataTable_{}", sanitize_ident(&t.name))
                } else {
                    "int32_t".to_string()
                }
            }
        }
    }

    fn c_ty_from_sema(&self, ty: &Ty) -> String {
        match ty {
            Ty::Unit | Ty::U8 | Ty::Bool => "uint8_t".to_string(),
            Ty::I8 => "int8_t".to_string(),
            Ty::I16 => "int16_t".to_string(),
            Ty::I64 | Ty::Fix64 => "int64_t".to_string(),
            Ty::U16 => "uint16_t".to_string(),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => "uint32_t".to_string(),
            Ty::U64 | Ty::BitSet(_) => "uint64_t".to_string(),
            Ty::F32 | Ty::UnitScalar { .. } => "float".to_string(),
            Ty::F64 => "double".to_string(),
            Ty::Ref(_) => "BamEntity".to_string(),
            Ty::Vec2 => "StrataVec2".to_string(),
            Ty::Vec3 => "StrataVec3".to_string(),
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "StrataVec4".to_string(),
            Ty::IVec2 => "StrataIVec2".to_string(),
            Ty::IVec3 => "StrataIVec3".to_string(),
            Ty::UVec2 => "StrataUVec2".to_string(),
            Ty::Mat3 => "StrataMat3".to_string(),
            Ty::Mat4 => "StrataMat4".to_string(),
            Ty::Named(key) => {
                if let Some(l_idx) = self.find_layout_idx(key) {
                    self.layout_c_names[l_idx].clone()
                } else {
                    "int32_t".to_string()
                }
            }
            _ => "int32_t".to_string(),
        }
    }

    fn c_zero_for_mir(&self, ty: &MirType) -> String {
        match ty {
            MirType::Unit
            | MirType::Bool
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::Sym => "0u".to_string(),
            MirType::U64 => "0ull".to_string(),
            MirType::I8 | MirType::I16 | MirType::I32 | MirType::Fix32 => "0".to_string(),
            MirType::I64 | MirType::Fix64 => "0ll".to_string(),
            MirType::F32 => "0.0f".to_string(),
            MirType::F64 => "0.0".to_string(),
            MirType::Entity => "BAM_ENTITY_NULL".to_string(),
            MirType::Ptr | MirType::MutPtr | MirType::QueryIter => "NULL".to_string(),
            MirType::Vec2 => "strata_vec2(0.0f, 0.0f)".to_string(),
            MirType::Vec3 => "strata_vec3(0.0f, 0.0f, 0.0f)".to_string(),
            MirType::Vec4 => "strata_vec4(0.0f, 0.0f, 0.0f, 0.0f)".to_string(),
            MirType::Named(k) if self.find_layout_idx(k).is_none() => "0".to_string(),
            _ => "{ 0 }".to_string(),
        }
    }

    fn c_zero_for_sema(&self, ty: &Ty) -> String {
        match ty {
            Ty::Bool | Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => "0u".to_string(),
            Ty::U64 | Ty::BitSet(_) => "0ull".to_string(),
            Ty::I64 | Ty::Fix64 => "0ll".to_string(),
            Ty::F32 | Ty::UnitScalar { .. } => "0.0f".to_string(),
            Ty::F64 => "0.0".to_string(),
            Ty::Ref(_) => "BAM_ENTITY_NULL".to_string(),
            Ty::Vec2 => "strata_vec2(0.0f, 0.0f)".to_string(),
            Ty::Vec3 => "strata_vec3(0.0f, 0.0f, 0.0f)".to_string(),
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => {
                "strata_vec4(0.0f, 0.0f, 0.0f, 0.0f)".to_string()
            }
            Ty::IVec2 => "strata_ivec2(0, 0)".to_string(),
            Ty::IVec3 => "strata_ivec3(0, 0, 0)".to_string(),
            Ty::UVec2 => "strata_uvec2(0u, 0u)".to_string(),
            _ => "0".to_string(),
        }
    }

    fn c_const_val(&self, val: &MirConstVal) -> String {
        match val {
            MirConstVal::Unit => "0u".to_string(),
            MirConstVal::Bool(b) => {
                if *b {
                    "BAM_TRUE".to_string()
                } else {
                    "BAM_FALSE".to_string()
                }
            }
            MirConstVal::Int(v) => {
                if *v == i64::MIN {
                    "(-9223372036854775807ll - 1ll)".to_string()
                } else {
                    format!("{v}")
                }
            }
            MirConstVal::Float(v) => c_f32(*v as f32),
            MirConstVal::Vec2(v) => format!(
                "strata_vec2({}, {})",
                c_f32(v[0] as f32),
                c_f32(v[1] as f32)
            ),
            MirConstVal::Vec3(v) => format!(
                "strata_vec3({}, {}, {})",
                c_f32(v[0] as f32),
                c_f32(v[1] as f32),
                c_f32(v[2] as f32)
            ),
            MirConstVal::Vec4(v) => format!(
                "strata_vec4({}, {}, {}, {})",
                c_f32(v[0] as f32),
                c_f32(v[1] as f32),
                c_f32(v[2] as f32),
                c_f32(v[3] as f32)
            ),
            MirConstVal::String(s) => format!("\"{}\"", c_escape(s)),
            MirConstVal::Array(elems) => {
                let items: Vec<String> = elems.iter().map(|e| self.c_const_val(e)).collect();
                if items.is_empty() {
                    "{ 0 }".to_string()
                } else {
                    format!("{{ {{ {} }} }}", items.join(", "))
                }
            }
            MirConstVal::Struct { fields, .. } => {
                if fields.is_empty() {
                    "{ 0 }".to_string()
                } else {
                    let items: Vec<String> =
                        fields.iter().map(|(_, fv)| self.c_const_val(fv)).collect();
                    format!("{{ {} }}", items.join(", "))
                }
            }
        }
    }

    fn c_hir_expr(&self, expr: &HirExpr, hint_ty: &Ty) -> String {
        match expr {
            HirExpr::IntLit { value, .. } => format!("{value}"),
            HirExpr::FloatLit { value, ty } => {
                if matches!(ty, Ty::F64) || matches!(hint_ty, Ty::F64) {
                    c_f64(*value)
                } else {
                    c_f32(*value as f32)
                }
            }
            HirExpr::BoolLit(b) => {
                if *b {
                    "BAM_TRUE".to_string()
                } else {
                    "BAM_FALSE".to_string()
                }
            }
            HirExpr::StringLit(st) => format!("\"{}\"", c_escape(st)),
            HirExpr::Unary { op, expr, .. } => {
                let inner = self.c_hir_expr(expr, hint_ty);
                match op {
                    HirUnOp::Neg => format!("-({inner})"),
                    HirUnOp::Not => format!("(!({inner}))"),
                    _ => inner,
                }
            }
            HirExpr::Path { name, .. } => {
                let seg = short_name(name);
                for e in &self.mir.enums {
                    if let Some((_, disc)) = e.variants.iter().find(|(vn, _)| vn == seg) {
                        return format!("((int32_t){disc})");
                    }
                }
                self.c_zero_for_sema(hint_ty)
            }
            HirExpr::Call(call) => {
                let a = |i: usize| {
                    call.args
                        .get(i)
                        .map(|arg| self.c_hir_expr(arg, &Ty::F32))
                        .unwrap_or_else(|| "0.0f".to_string())
                };
                match short_name(&call.callee) {
                    "vec2" | "Vec2" => format!("strata_vec2({}, {})", a(0), a(1)),
                    "vec3" | "Vec3" => format!("strata_vec3({}, {}, {})", a(0), a(1), a(2)),
                    "vec4" | "Vec4" => {
                        format!("strata_vec4({}, {}, {}, {})", a(0), a(1), a(2), a(3))
                    }
                    "ivec2" | "IVec2" => format!("strata_ivec2({}, {})", a(0), a(1)),
                    "ivec3" | "IVec3" => format!("strata_ivec3({}, {}, {})", a(0), a(1), a(2)),
                    "uvec2" | "UVec2" => format!("strata_uvec2({}, {})", a(0), a(1)),
                    "bits" => {
                        let mut mask = 0u64;
                        for arg in &call.args {
                            if let HirExpr::IntLit { value, .. } = arg
                                && *value >= 0
                                && (*value as u32) < 64
                            {
                                mask |= 1u64 << (*value as u32);
                            }
                        }
                        format!("0x{mask:016X}ull")
                    }
                    _ => self.c_zero_for_sema(hint_ty),
                }
            }
            _ => self.c_zero_for_sema(hint_ty),
        }
    }
}

struct FnEmitCtx<'a, 'b> {
    parent: &'a EmitCtx<'b>,
    func: &'a MirFunction,
    is_observer: bool,
    is_migration: bool,
    is_void_helper: bool,
    is_helper: bool,
    ptr_meta: HashMap<LocalId, PtrKind>,
    restrict_cols: HashMap<LocalId, PtrKind>,
    projected_fields: HashMap<LocalId, String>,
    dirty_owners: HashMap<(u32, u32), Vec<(u32, u32)>>,
    local_types: HashMap<LocalId, MirType>,
    last_checkpoint: Option<LocalId>,
}

impl<'a, 'b> FnEmitCtx<'a, 'b> {
    fn local_expr(&self, id: LocalId) -> String {
        if self.restrict_cols.contains_key(&id) {
            format!("col_{}", id.0)
        } else {
            format!("v_{}", id.0)
        }
    }

    fn local_ty(&self, id: LocalId) -> Option<&MirType> {
        self.local_types.get(&id)
    }

    fn unwrap_operand_expr(&self, id: LocalId, expected_vec: Option<&MirType>) -> String {
        let p = self.local_expr(id);
        if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) {
            let layout = &self.parent.layouts[*layout_idx];
            if let Some(pf) = self.projected_fields.get(&id)
                && let Some(sf) = layout
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && f.name == *pf)
            {
                let fc = sanitize_c_field(&sf.name);
                let z = self.parent.c_zero_for_sema(&sf.ty);
                return format!("({p} != NULL ? {p}->{fc} : {z})");
            }
            if let Some(exp) = expected_vec
                && let Some(sf) = layout
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && ty_matches_sema(&f.ty, exp))
            {
                let fc = sanitize_c_field(&sf.name);
                let z = self.parent.c_zero_for_sema(&sf.ty);
                return format!("({p} != NULL ? {p}->{fc} : {z})");
            }
        }
        p
    }

    fn effective_vec_ty(&self, id: LocalId) -> Option<MirType> {
        if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) {
            for f in &self.parent.layouts[*layout_idx].fields {
                if !f.is_padding {
                    match f.ty {
                        Ty::Vec2 => return Some(MirType::Vec2),
                        Ty::Vec3 => return Some(MirType::Vec3),
                        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => return Some(MirType::Vec4),
                        _ => {}
                    }
                }
            }
        }
        self.local_ty(id).cloned()
    }

    fn ptr_c_ty(&self, id: LocalId) -> Option<String> {
        self.ptr_meta
            .get(&id)
            .map(|pk| pk.c_type(&self.parent.layout_c_names))
    }

    fn projected_sema_ty(&self, id: LocalId) -> Option<&Ty> {
        let pf = self.projected_fields.get(&id)?;
        let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) else {
            return None;
        };
        let layout = &self.parent.layouts[*layout_idx];
        layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == *pf)
            .map(|f| &f.ty)
    }

    fn operand_c_ty(&self, id: LocalId) -> String {
        if let Some(sty) = self.projected_sema_ty(id) {
            return self.parent.c_ty_from_sema(sty);
        }
        if let Some(pt) = self.ptr_c_ty(id) {
            return pt;
        }
        self.parent.c_ty(self.local_ty(id).unwrap_or(&MirType::I32))
    }

    fn is_projected_aggregate(&self, id: LocalId) -> bool {
        let Some(sty) = self.projected_sema_ty(id) else {
            return false;
        };
        Self::is_sema_aggregate(self.parent, sty)
    }

    fn is_sema_aggregate(parent: &EmitCtx<'_>, sty: &Ty) -> bool {
        matches!(
            sty,
            Ty::Vec2
                | Ty::Vec3
                | Ty::Vec3a
                | Ty::Vec4
                | Ty::Quat
                | Ty::Rgba
                | Ty::IVec2
                | Ty::IVec3
                | Ty::UVec2
                | Ty::Mat3
                | Ty::Mat4
        ) || matches!(sty, Ty::Named(key) if parent.find_layout_idx(key).is_some())
    }

    fn emit_stmt(&self, stmt: &MirStmt, s: &mut String) -> Result<(), CodegenError> {
        let dst = stmt.dst;
        match &stmt.inst {
            Inst::ConstInt { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if *value == i64::MIN {
                        let _ = writeln!(s, "    {de} = (-9223372036854775807ll - 1ll);");
                    } else {
                        let _ = writeln!(s, "    {de} = {value};");
                    }
                }
            }
            Inst::ConstFloat { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if matches!(self.local_ty(d), Some(MirType::F64)) {
                        let _ = writeln!(s, "    {de} = {};", c_f64(*value));
                    } else {
                        let _ = writeln!(s, "    {de} = {};", c_f32(*value as f32));
                    }
                }
            }
            Inst::ConstBool { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let lit = if *value { "BAM_TRUE" } else { "BAM_FALSE" };
                    let _ = writeln!(s, "    {de} = {lit};");
                }
            }
            Inst::ConstVec { dims, values } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let eff_dims = match self.local_ty(d) {
                        Some(MirType::Vec2) => 2u8,
                        Some(MirType::Vec3) => 3u8,
                        Some(MirType::Vec4) => 4u8,
                        _ => *dims,
                    };
                    match eff_dims {
                        2 => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec2({}, {});",
                                c_f32(values[0] as f32),
                                c_f32(values[1] as f32)
                            );
                        }
                        3 => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec3({}, {}, {});",
                                c_f32(values[0] as f32),
                                c_f32(values[1] as f32),
                                c_f32(values[2] as f32)
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec4({}, {}, {}, {});",
                                c_f32(values[0] as f32),
                                c_f32(values[1] as f32),
                                c_f32(values[2] as f32),
                                c_f32(values[3] as f32)
                            );
                        }
                    }
                }
            }
            Inst::ConstString { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let esc = c_escape(value);
                    let _ = writeln!(s, "    {de} = (const void*)\"{esc}\";");
                }
            }
            Inst::Copy { val } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*val);
                    if let Some(dst_ptr_cty) = self.ptr_c_ty(d) {
                        let _ = writeln!(s, "    {de} = ({dst_ptr_cty}){ve};");
                    } else {
                        let _ = writeln!(s, "    {de} = {ve};");
                    }
                }
            }
            Inst::SlotAlloc { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    if let Some(dst_ptr_cty) = self.ptr_c_ty(d) {
                        let _ = writeln!(s, "    {de} = ({dst_ptr_cty})&slot_buf_{sid};");
                    } else {
                        let _ = writeln!(s, "    {de} = &slot_buf_{sid};");
                    }
                }
            }
            Inst::SlotLoad { slot } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let se = self.local_expr(*slot);
                    let _ = writeln!(
                        s,
                        "    if ({se} != NULL) {{ memcpy(&{de}, {se}, sizeof({de})); }}"
                    );
                }
            }
            Inst::SlotStore { slot, val } => {
                let se = self.local_expr(*slot);
                let ve = self.local_expr(*val);
                let _ = writeln!(
                    s,
                    "    if ({se} != NULL) {{ memcpy({se}, &{ve}, sizeof({ve})); }}"
                );
            }
            Inst::BinOp { op, lhs, rhs, .. } => {
                if let Some(d) = dst {
                    self.emit_binop(d, op, *lhs, *rhs, s)?;
                }
            }
            Inst::UnOp { op, val } => {
                if let Some(d) = dst {
                    self.emit_unop(d, op, *val, s);
                }
            }
            Inst::Cast { val, target_ty } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*val);
                    let cty = self.parent.c_ty(target_ty);
                    if matches!(target_ty, MirType::Bool) {
                        let _ = writeln!(s, "    {de} = ({ve}) ? BAM_TRUE : BAM_FALSE;");
                    } else {
                        let _ = writeln!(s, "    {de} = ({cty})({ve});");
                    }
                }
            }
            Inst::VecExtract { vec, lane } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    let field = lane_name(*lane);
                    let _ = writeln!(s, "    {de} = {ve}.{field};");
                }
            }
            Inst::VecInsert { vec, lane, val } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    let vle = self.local_expr(*val);
                    let field = lane_name(*lane);
                    let _ = writeln!(s, "    {de} = {ve};\n    {de}.{field} = {vle};");
                }
            }
            Inst::VecSwizzle { vec, lanes } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    match lanes.len() {
                        2 => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec2({ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1])
                            );
                        }
                        3 => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec3({ve}.{}, {ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1]),
                                lane_name(lanes[2])
                            );
                        }
                        _ => {
                            let l0 = lane_name(*lanes.first().unwrap_or(&0));
                            let l1 = lane_name(*lanes.get(1).unwrap_or(&0));
                            let l2 = lane_name(*lanes.get(2).unwrap_or(&0));
                            let l3 = lane_name(*lanes.get(3).unwrap_or(&0));
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec4({ve}.{l0}, {ve}.{l1}, {ve}.{l2}, {ve}.{l3});"
                            );
                        }
                    }
                }
            }
            Inst::IntrinsicMath { name, args, .. } => {
                if let Some(d) = dst {
                    self.emit_intrinsic_math(d, name, args, s);
                }
            }
            Inst::Call { callee, args } => {
                self.emit_call(dst, callee, args, s)?;
            }
            Inst::StructInit { type_name, fields } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                    if let Some(l_idx) = self.parent.find_layout_idx(type_name) {
                        if self.parent.layouts[l_idx].size > 0 {
                            let def_fn = format!(
                                "strata_default_{l_idx}_{}",
                                sanitize_ident(short_name(
                                    &self.parent.layouts[l_idx].canonical_name
                                ))
                            );
                            let _ = writeln!(s, "    {de} = {def_fn}();");
                        }
                        for (fname, fval) in fields {
                            let fc = sanitize_c_field(fname);
                            let vr = self.local_expr(*fval);
                            let needs_memcpy = self.parent.layouts[l_idx]
                                .fields
                                .iter()
                                .find(|sf| sf.name == *fname)
                                .is_some_and(|sf| {
                                    matches!(
                                        sf.ty,
                                        Ty::IVec2
                                            | Ty::IVec3
                                            | Ty::UVec2
                                            | Ty::BitSet(_)
                                            | Ty::SmallVec { .. }
                                            | Ty::InlineStr(_)
                                            | Ty::GraceWindow
                                            | Ty::InputBuffer { .. }
                                            | Ty::Array { .. }
                                    )
                                });
                            if needs_memcpy {
                                let _ = writeln!(
                                    s,
                                    "    memcpy(&{de}.{fc}, &{vr}, sizeof({de}.{fc}));"
                                );
                            } else {
                                let _ = writeln!(s, "    {de}.{fc} = {vr};");
                            }
                        }
                    }
                }
            }
            Inst::ArrayInit { elems } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                    for (i, el) in elems.iter().enumerate() {
                        let ev = self.local_expr(*el);
                        let _ = writeln!(s, "    {de}.data[{i}] = {ev};");
                    }
                }
            }
            Inst::ArrayIndex { base, index } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let be = self.local_expr(*base);
                    let ie = self.local_expr(*index);
                    let bty = self.local_ty(*base);
                    if matches!(bty, Some(MirType::Array { .. })) {
                        let _ = writeln!(s, "    {de} = {be}.data[{ie}];");
                    } else {
                        let _ = writeln!(
                            s,
                            "    if ({be} != NULL) {{ memcpy(&{de}, ((const uint8_t*){be}) + ((size_t)({ie}) * sizeof({de})), sizeof({de})); }}"
                        );
                    }
                }
            }
            Inst::FieldPtr {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
            } => {
                if let Some(d) = dst {
                    self.emit_field_ptr(d, *base_ptr, layout_key, field, *offset_bytes, s);
                }
            }
            Inst::FieldLoad {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                field_ty,
            } => {
                if let Some(d) = dst {
                    self.emit_field_load(
                        d,
                        *base_ptr,
                        layout_key,
                        field,
                        *offset_bytes,
                        field_ty,
                        s,
                    );
                }
            }
            Inst::FieldStore {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                val,
            } => {
                self.emit_field_store(*base_ptr, layout_key, field, *offset_bytes, *val, s);
            }
            Inst::RowPtr {
                col_ptr,
                row_idx,
                stride_bytes,
                is_sparse,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ce = self.local_expr(*col_ptr);
                    let re = self.local_expr(*row_idx);
                    let dst_cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    if *is_sparse {
                        let _ = writeln!(
                            s,
                            "    {de} = ({ce} != NULL) ? ({dst_cty})(((const uint8_t* const*){ce})[{re}]) : NULL;"
                        );
                    } else if self.restrict_cols.contains_key(col_ptr) {
                        let _ = writeln!(
                            s,
                            "    {de} = ({ce} != NULL) ? ({dst_cty})(&{ce}[{re}]) : NULL;"
                        );
                    } else {
                        let _ = writeln!(
                            s,
                            "    {de} = ({ce} != NULL) ? ({dst_cty})(((const uint8_t*){ce}) + ((size_t){re} * {stride_bytes}u)) : NULL;"
                        );
                    }
                }
            }
            Inst::IterNextChunk { query_idx } => {
                let qi = *query_idx;
                let dh = dst
                    .map(|d| self.local_expr(d))
                    .unwrap_or_else(|| "_unused_has_chunk".to_string());
                if dst.is_none() {
                    let _ = writeln!(s, "    {{ BamBool _unused_has_chunk = BAM_FALSE;");
                }
                let _ = writeln!(
                    s,
                    "    iter_{qi}_len = 0u;\n    {dh} = BAM_FALSE;\n    if (sys_ctx != NULL && state->api->iter_next_chunk != NULL) {{\n        if (iter_{qi} == NULL && state->api->sys_query != NULL) {{\n            (void)state->api->sys_query(sys_ctx, {qi}u, &iter_{qi});\n        }}\n        if (iter_{qi} != NULL) {{\n            while (state->api->iter_next_chunk(iter_{qi}, &iter_{qi}_len) != BAM_FALSE) {{\n                if (iter_{qi}_len > 0u) {{\n                    {dh} = BAM_TRUE;\n                    break;\n                }}\n            }}\n        }}\n    }}"
                );
                if dst.is_none() {
                    let _ = writeln!(s, "    (void)_unused_has_chunk; }}");
                }
            }
            Inst::IterChunkLen { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    {de} = (uint32_t)iter_{query_idx}_len;");
                }
            }
            Inst::IterEntities { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    iter_{query_idx}_ents = (iter_{query_idx} != NULL && state->api->iter_entities != NULL) ? state->api->iter_entities(iter_{query_idx}) : NULL;\n    {de} = iter_{query_idx}_ents;"
                    );
                }
            }
            Inst::EntityAtRow {
                entities_ptr,
                row_idx,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ep = self.local_expr(*entities_ptr);
                    let re = self.local_expr(*row_idx);
                    let _ = writeln!(
                        s,
                        "    {de} = ({ep} != NULL) ? ((const BamEntity*){ep})[{re}] : BAM_ENTITY_NULL;"
                    );
                    for qb in &self.func.query_bindings {
                        let _ = writeln!(s, "    iter_{}_cur_ent = {de};", qb.query_idx);
                    }
                }
            }
            Inst::IterColRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_readonly != NULL) ? ({cty})state->api->iter_column_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::IterColWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_mutable != NULL) ? ({cty})state->api->iter_column_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::IterColWriteUntracked {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_mutable_untracked != NULL) ? ({cty})state->api->iter_column_mutable_untracked(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::IterMarkChangedRange {
                query_idx,
                term_idx,
                run_start,
                run_len,
            } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let _ = writeln!(
                    s,
                    "    if ({rl} > 0u && iter_{query_idx} != NULL && state->api->iter_mark_changed_range != NULL) {{\n        (void)state->api->iter_mark_changed_range(iter_{query_idx}, {term_idx}u, (size_t){rs}, (size_t){rl});\n    }}"
                );
            }
            Inst::IterColRowsRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_readonly != NULL) ? (const void*)state->api->iter_column_rows_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::IterColRowsWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_mutable != NULL) ? (void*)state->api->iter_column_rows_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::IterCount { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    {de} = 0u;\n    if (sys_ctx != NULL && state->api->sys_query != NULL && state->api->iter_count != NULL) {{\n        BamIter* cnt_it = NULL;\n        if (state->api->sys_query(sys_ctx, {query_idx}u, &cnt_it) == BAM_RESULT_OK && cnt_it != NULL) {{\n            size_t raw_cnt = 0u;\n            (void)state->api->iter_count(cnt_it, &raw_cnt);\n            {de} = (uint32_t)raw_cnt;\n        }}\n    }}"
                    );
                }
            }
            Inst::IterUpCascade {
                query_idx,
                relation,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let r_idx = self.parent.find_rel_idx(relation).unwrap_or(0);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* raw_up = NULL;\n        BamEntity up_owner = BAM_ENTITY_NULL;\n        if (iter_{query_idx} != NULL && state->api->iter_up_cascade != NULL) {{\n            (void)state->api->iter_up_cascade(iter_{query_idx}, state->relations[{r_idx}], iter_{query_idx}_cur_ent, 0u, &raw_up, &up_owner);\n        }}\n        (void)up_owner;\n        {de} = ({cty})raw_up;\n    }}"
                    );
                }
            }
            Inst::ParForEachChunk {
                query_idx,
                chunk_size,
            } => {
                let _ = writeln!(
                    s,
                    "    /* @par chunk_size={chunk_size} */\n    (void)(state->api->par_for_each_chunk != NULL && iter_{query_idx} != NULL);"
                );
            }
            Inst::ParForEachChunkReadonly {
                query_idx,
                chunk_size,
                deterministic_order,
            } => {
                let _ = writeln!(
                    s,
                    "    /* @par readonly chunk_size={chunk_size} deterministic={deterministic_order} */\n    (void)(state->api->par_for_each_chunk_readonly != NULL && iter_{query_idx} != NULL);"
                );
            }
            Inst::ReduceInit { identity, .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ie = self.local_expr(*identity);
                    let _ = writeln!(s, "    {de} = {ie};");
                }
            }
            Inst::ReduceAccum { acc, op, val } => {
                let ae = self.local_expr(*acc);
                let ve = self.local_expr(*val);
                let aty = self.local_ty(*acc).cloned().unwrap_or(MirType::F32);
                match op.as_str() {
                    "min" | "Min" => {
                        if matches!(aty, MirType::F32) {
                            let _ = writeln!(s, "    {ae} = fminf({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae} < {ve}) ? {ae} : {ve};");
                        }
                    }
                    "max" | "Max" => {
                        if matches!(aty, MirType::F32) {
                            let _ = writeln!(s, "    {ae} = fmaxf({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae} > {ve}) ? {ae} : {ve};");
                        }
                    }
                    "prod" | "*" | "Mul" => {
                        let _ = writeln!(s, "    {ae} = ({ae}) * ({ve});");
                    }
                    _ => {
                        if matches!(aty, MirType::Vec2) {
                            let _ = writeln!(s, "    {ae} = strata_vec2_add({ae}, {ve});");
                        } else if matches!(aty, MirType::Vec3) {
                            let _ = writeln!(s, "    {ae} = strata_vec3_add({ae}, {ve});");
                        } else if matches!(aty, MirType::Vec4) {
                            let _ = writeln!(s, "    {ae} = strata_vec4_add({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae}) + ({ve});");
                        }
                    }
                }
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    {de} = {ae};");
                }
            }
            Inst::ResRead { resource } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let c_idx = self.parent.find_comp_idx(resource).unwrap_or(0);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? ({cty})state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL;"
                    );
                    if self
                        .parent
                        .components
                        .get(c_idx)
                        .is_some_and(|c| c.has_mod_res)
                    {
                        let _ = writeln!(
                            s,
                            "    if ({de} == NULL) {{ {de} = ({cty})&state->mod_res_{c_idx}; }}"
                        );
                    }
                }
            }
            Inst::ResWrite { resource } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let c_idx = self.parent.find_comp_idx(resource).unwrap_or(0);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_mut_ptr != NULL) ? ({cty})state->api->sys_res_mut_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL;"
                    );
                    if self
                        .parent
                        .components
                        .get(c_idx)
                        .is_some_and(|c| c.has_mod_res)
                    {
                        let _ = writeln!(
                            s,
                            "    if ({de} == NULL) {{ {de} = ({cty})&state->mod_res_{c_idx}; }}"
                        );
                    }
                }
            }
            Inst::EntityGet {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ee = self.local_expr(*entity);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (sys_ctx != NULL && state->api->sys_entity_get != NULL && {ee} != BAM_ENTITY_NULL) ? ({cty})state->api->sys_entity_get(sys_ctx, {query_idx}u, {ee}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::EntityGetMut {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ee = self.local_expr(*entity);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (sys_ctx != NULL && state->api->sys_entity_get_mut != NULL && {ee} != BAM_ENTITY_NULL) ? ({cty})state->api->sys_entity_get_mut(sys_ctx, {query_idx}u, {ee}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::BindNamedObject { name } => {
                if let Some(&o_idx) = self.parent.obj_by_name.get(name) {
                    let esc = c_escape(name);
                    let _ = writeln!(
                        s,
                        "    if (state->named_objects[{o_idx}] != BAM_ENTITY_NULL && state->host_ctx != NULL && state->api->bind_named_object != NULL) {{\n        (void)state->api->bind_named_object(state->host_ctx, bam_str_view(\"{esc}\"), state->named_objects[{o_idx}]);\n    }}"
                    );
                }
            }
            Inst::ResolveNamedObject { name } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if let Some(&o_idx) = self.parent.obj_by_name.get(name) {
                        let obj = &self.parent.objects[o_idx];
                        let match_q = obj.primary_comp_idx.and_then(|p_idx| {
                            let p_comp = &self.parent.components[p_idx];
                            self.func.query_bindings.iter().find(|qb| {
                                qb.terms.iter().any(|t| {
                                    t.canonical_component == p_comp.canonical
                                        || short_name(&t.canonical_component) == p_comp.short
                                }) || qb.with_filters.iter().any(|w| {
                                    *w == p_comp.canonical || short_name(w) == p_comp.short
                                })
                            })
                        });
                        let _ = writeln!(
                            s,
                            "    if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL && sys_ctx != NULL && state->api->sys_query != NULL && state->api->iter_next_chunk != NULL && state->api->iter_entities != NULL) {{"
                        );
                        if let Some(qb) = match_q {
                            let qi = qb.query_idx;
                            let _ = writeln!(
                                s,
                                "\
        BamIter* probe_it = NULL;
        if (state->api->sys_query(sys_ctx, {qi}u, &probe_it) == BAM_RESULT_OK && probe_it != NULL) {{
            if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(probe_it); }}
            size_t plen = 0u;
            if (state->api->iter_next_chunk(probe_it, &plen) != BAM_FALSE && plen > 0u) {{
                const BamEntity* pents = state->api->iter_entities(probe_it);
                if (pents != NULL && pents[0] != BAM_ENTITY_NULL) {{
                    state->named_objects[{o_idx}] = pents[0];
                }}
            }}
            if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(probe_it); }}
        }}"
                            );
                        }
                        let _ = writeln!(s, "    }}");
                        let _ = writeln!(s, "    {de} = state->named_objects[{o_idx}];");
                    } else {
                        let _ = writeln!(s, "    {de} = BAM_ENTITY_NULL;");
                    }
                }
            }
            Inst::InternSymbol { symbol } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let esc = c_escape(symbol);
                    let _ = writeln!(
                        s,
                        "    {de} = BAM_SYMBOL_INVALID;\n    if (state->host_ctx != NULL && state->api->intern_symbol != NULL) {{\n        (void)state->api->intern_symbol(state->host_ctx, bam_str_view(\"{esc}\"), &{de});\n    }}"
                    );
                }
            }
            Inst::TriggerPayload { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    if self.is_observer {
                        let _ = writeln!(s, "    {de} = ({cty})event_data;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
            Inst::TriggerTarget => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if self.is_observer {
                        let _ = writeln!(s, "    {de} = entity;");
                    } else {
                        let _ = writeln!(s, "    {de} = BAM_ENTITY_NULL;");
                    }
                }
            }
            Inst::GraceArm { ptr, duration_sec } => {
                let p = self.local_expr(*ptr);
                let dur = self.local_expr(*duration_sec);
                let _ = writeln!(s, "    strata_grace_arm({p}, {dur});");
            }
            Inst::GraceTick { ptr, dt_sec } => {
                let p = self.local_expr(*ptr);
                let dtv = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    strata_grace_tick({p}, {dtv});");
            }
            Inst::GraceIsActive { ptr } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let _ = writeln!(s, "    {de} = strata_grace_is_active({p});");
                }
            }
            Inst::GraceClear { ptr } => {
                let p = self.local_expr(*ptr);
                let _ = writeln!(s, "    strata_grace_clear({p});");
            }
            Inst::InputBufPush {
                ptr,
                capacity,
                action_id,
                window_sec,
            } => {
                let p = self.local_expr(*ptr);
                let a = self.local_expr(*action_id);
                let w = self.local_expr(*window_sec);
                let _ = writeln!(
                    s,
                    "    strata_input_push({p}, {capacity}u, (uint16_t){a}, {w});"
                );
            }
            Inst::InputBufConsume {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let a = self.local_expr(*action_id);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_input_consume({p}, {capacity}u, (uint16_t){a});"
                    );
                }
            }
            Inst::InputBufPeek {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let a = self.local_expr(*action_id);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_input_peek({p}, {capacity}u, (uint16_t){a});"
                    );
                }
            }
            Inst::InputBufTick {
                ptr,
                capacity,
                dt_sec,
            } => {
                let p = self.local_expr(*ptr);
                let dtv = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    strata_input_tick({p}, {capacity}u, {dtv});");
            }
            Inst::BitSetSet { ptr, words, bit } => {
                let p = self.local_expr(*ptr);
                let ptr_arg = if self.is_ptr_local(*ptr) {
                    p
                } else {
                    format!("&({p})")
                };
                let b = self.local_expr(*bit);
                let _ = writeln!(
                    s,
                    "    strata_bitset_set({ptr_arg}, {words}u, (uint32_t){b});"
                );
            }
            Inst::BitSetGet { ptr, words, bit } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let ptr_arg = if self.is_ptr_local(*ptr) {
                        p
                    } else {
                        format!("&({p})")
                    };
                    let b = self.local_expr(*bit);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_bitset_get({ptr_arg}, {words}u, (uint32_t){b});"
                    );
                }
            }
            Inst::BitSetClear { ptr, words, bit } => {
                let p = self.local_expr(*ptr);
                let ptr_arg = if self.is_ptr_local(*ptr) {
                    p
                } else {
                    format!("&({p})")
                };
                let b = self.local_expr(*bit);
                let _ = writeln!(
                    s,
                    "    strata_bitset_clear({ptr_arg}, {words}u, (uint32_t){b});"
                );
            }
            Inst::TimelineInWindow { ptr, window_bit } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let _ = writeln!(
                        s,
                        "    {de} = BAM_FALSE;\n    if ({p} != NULL) {{\n        uint32_t mask = 0u;\n        memcpy(&mask, ((const uint8_t*){p}) + sizeof(float) + sizeof(uint32_t), sizeof(uint32_t));\n        {de} = ((mask & (1u << {window_bit}u)) != 0u) ? BAM_TRUE : BAM_FALSE;\n    }}"
                    );
                }
            }
            Inst::TimelineAdvance {
                cursor_ptr,
                dt_sec,
                rate_hz,
                duration_frames,
                window_masks,
                ..
            } => {
                let p = self.local_expr(*cursor_ptr);
                let dt = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    if ({p} != NULL) {{");
                let _ = writeln!(s, "        float elapsed = 0.0f;");
                let _ = writeln!(s, "        memcpy(&elapsed, {p}, sizeof(float));");
                let _ = writeln!(s, "        elapsed += {dt};");
                let _ = writeln!(
                    s,
                    "        uint32_t frame = (uint32_t)(elapsed * (float){rate_hz}u);"
                );
                let _ = writeln!(
                    s,
                    "        if (frame > {duration_frames}u) {{ frame = {duration_frames}u; }}"
                );
                let _ = writeln!(s, "        uint32_t mask = 0u;");
                for (_, start_f, end_f, bit) in window_masks {
                    let _ = writeln!(
                        s,
                        "        if (frame >= {start_f}u && frame <= {end_f}u) {{ mask |= (1u << {bit}u); }}"
                    );
                }
                let _ = writeln!(s, "        memcpy({p}, &elapsed, sizeof(float));");
                let _ = writeln!(
                    s,
                    "        memcpy(((uint8_t*){p}) + sizeof(float), &frame, sizeof(uint32_t));"
                );
                let _ = writeln!(
                    s,
                    "        memcpy(((uint8_t*){p}) + sizeof(float) + sizeof(uint32_t), &mask, sizeof(uint32_t));"
                );
                let _ = writeln!(s, "    }}");
            }
            Inst::CmdSpawn {
                persistent,
                components,
            } => {
                self.emit_cmd_spawn(dst, components, *persistent, s);
            }
            Inst::CmdSpawnBatch { count, components } => {
                self.emit_cmd_spawn_batch(*count, components, s);
            }
            Inst::CmdDespawn { entity } => {
                let e = self.local_expr(*entity);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_despawn != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->cmd_despawn(cmds_cache, {e});\n    }}"
                );
            }
            Inst::CmdDespawnAll { filter } => {
                self.emit_cmd_despawn_all(filter, s);
            }
            Inst::CmdInsert {
                entity,
                component,
                data,
                if_new,
            } => {
                let e = self.local_expr(*entity);
                let p = data
                    .map(|id| {
                        let is_ptr = self.ptr_meta.contains_key(&id)
                            || matches!(self.local_ty(id), Some(MirType::Ptr | MirType::MutPtr));
                        let pe = self.local_expr(id);
                        if is_ptr {
                            format!("(const uint8_t*){pe}")
                        } else {
                            format!("(const uint8_t*)&{pe}")
                        }
                    })
                    .unwrap_or_else(|| "NULL".to_string());
                let c_idx = self.parent.find_comp_idx(component).unwrap_or(0);
                let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                let slot = if *if_new {
                    "cmd_insert_if_new"
                } else {
                    "cmd_insert"
                };
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->{slot} != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->{slot}(cmds_cache, {e}, state->components[{c_idx}], {p}, {sz}u);\n    }}"
                );
            }
            Inst::CmdRemove { entity, component } => {
                let e = self.local_expr(*entity);
                let c_idx = self.parent.find_comp_idx(component).unwrap_or(0);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_remove != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->cmd_remove(cmds_cache, {e}, state->components[{c_idx}]);\n    }}"
                );
            }
            Inst::CmdTrigger {
                event,
                target,
                payload,
                propagate,
            } => {
                let c_idx = self.parent.find_comp_idx(event).unwrap_or(0);
                let trg = target
                    .map(|id| self.local_expr(id))
                    .unwrap_or_else(|| "BAM_ENTITY_NULL".to_string());
                let (pp, psz) = if let Some(pid) = payload {
                    let is_ptr =
                        matches!(self.local_ty(*pid), Some(MirType::Ptr | MirType::MutPtr));
                    let pe = self.local_expr(*pid);
                    let comp_sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                    if is_ptr {
                        (format!("(const uint8_t*){pe}"), comp_sz)
                    } else {
                        (format!("(const uint8_t*)&{pe}"), comp_sz)
                    }
                } else {
                    ("NULL".to_string(), 0usize)
                };
                self.ensure_cmds_snippet(s);
                if *propagate {
                    let buf_n = psz.max(1);
                    let _ = writeln!(
                        s,
                        "    if (cmds_cache != NULL && state->api->cmd_trigger_ex != NULL) {{\n        uint8_t trg_buf[{buf_n}u];\n        memset(trg_buf, 0, sizeof(trg_buf));\n        if ({pp} != NULL && {psz}u > 0u) {{ memcpy(trg_buf, {pp}, {psz}u); }}\n        BamTriggerDesc tdesc = bam_trigger_desc(state->components[{c_idx}], {trg}, ({psz}u > 0u) ? trg_buf : NULL, {psz}u);\n        tdesc.flags = BAM_OBSERVER_FLAG_PROPAGATE;\n        (void)state->api->cmd_trigger_ex(cmds_cache, &tdesc);\n    }}"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    if (cmds_cache != NULL && state->api->cmd_trigger != NULL) {{\n        (void)state->api->cmd_trigger(cmds_cache, state->components[{c_idx}], {trg}, {pp}, {psz}u);\n    }}"
                    );
                }
            }
            Inst::StreamEmit { stream, payload } => {
                let c_idx = self.parent.find_comp_idx(stream).unwrap_or(0);
                let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                let is_ptr = self.ptr_meta.contains_key(payload)
                    || matches!(
                        self.local_ty(*payload),
                        Some(MirType::Ptr | MirType::MutPtr)
                    );
                let pe = self.local_expr(*payload);
                let ptr_expr = if is_ptr {
                    format!("(const uint8_t*){pe}")
                } else {
                    format!("(const uint8_t*)&{pe}")
                };
                let stream_short = short_name(stream);
                let match_term = self.func.query_bindings.iter().find_map(|qb| {
                    qb.terms
                        .iter()
                        .find(|t| {
                            t.mode == TermAccessMode::StreamWrite
                                && (t.canonical_component == *stream
                                    || short_name(&t.canonical_component) == stream_short)
                        })
                        .map(|t| (qb.query_idx, t.term_idx))
                });
                if let Some((qi, ti)) = match_term {
                    let _ = writeln!(
                        s,
                        "    if (sys_ctx != NULL && state->api->msg_send != NULL) {{\n        if (iter_{qi} == NULL && state->api->sys_query != NULL) {{ (void)state->api->sys_query(sys_ctx, {qi}u, &iter_{qi}); }}\n        if (iter_{qi} != NULL) {{ (void)state->api->msg_send(iter_{qi}, {ti}u, {ptr_expr}, {sz}u); }}\n    }}"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    if (state->api->msg_send != NULL) {{\n        (void)state->api->msg_send(NULL, 0u, {ptr_expr}, {sz}u);\n    }}"
                    );
                }
            }
            Inst::CmdCheckpoint => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    self.ensure_cmds_snippet(s);
                    let _ = writeln!(
                        s,
                        "    if (cmds_cache != NULL && state->api->cmd_checkpoint != NULL) {{\n        (void)state->api->cmd_checkpoint(cmds_cache, &{de});\n    }}"
                    );
                }
            }
            Inst::CmdRollback { checkpoint } => {
                let cp = self.local_expr(*checkpoint);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_rollback != NULL) {{\n        (void)state->api->cmd_rollback(cmds_cache, {cp});\n    }}"
                );
            }
            Inst::CmdInsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                let r_idx = self.parent.find_rel_idx(relation).unwrap_or(0);
                let ch = self.local_expr(*entity);
                let pa = self.local_expr(*target);
                let sz = self.parent.relations.get(r_idx).map_or(0, |r| r.data_size);
                let pp = if let Some(pid) = payload {
                    let is_ptr =
                        matches!(self.local_ty(*pid), Some(MirType::Ptr | MirType::MutPtr));
                    let pe = self.local_expr(*pid);
                    if is_ptr { pe } else { format!("&{pe}") }
                } else {
                    "NULL".to_string()
                };
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_insert_relation != NULL) {{\n        (void)state->api->cmd_insert_relation(cmds_cache, state->relations[{r_idx}], {ch}, {pa}, {pp}, {sz}u);\n    }}"
                );
            }
            Inst::CmdRemoveRelation {
                relation,
                entity,
                target,
            } => {
                let r_idx = self.parent.find_rel_idx(relation).unwrap_or(0);
                let ch = self.local_expr(*entity);
                let pa = self.local_expr(*target);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_remove_relation != NULL) {{\n        (void)state->api->cmd_remove_relation(cmds_cache, state->relations[{r_idx}], {ch}, {pa});\n    }}"
                );
            }
            Inst::SpatialRebuildCsr { index_name, .. } => {
                let _ = writeln!(s, "    /* Spatial CSR rebuilt for `{index_name}` */");
            }
            Inst::SpatialQueryDisc {
                grid_name,
                center,
                radius,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    let ce = self.local_expr(*center);
                    let re = self.local_expr(*radius);
                    let grid_ptr_expr = if let Some(c_idx) = self.parent.find_comp_idx(grid_name) {
                        if self.parent.components[c_idx].has_mod_res {
                            format!(
                                "(state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? (const void*)state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : (const void*)&state->mod_res_{c_idx}"
                            )
                        } else {
                            format!(
                                "(state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? (const void*)state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL"
                            )
                        }
                    } else {
                        "NULL".to_string()
                    };
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* g_ptr = {grid_ptr_expr};\n        spatial_buf_{sid} = strata_spatial_query_disc(g_ptr, {ce}, (float){re});\n        {de} = (const BamEntity*)spatial_buf_{sid}.entities;\n    }}"
                    );
                }
            }
            Inst::SpatialQuerySegmentAt {
                history_name,
                start,
                end,
                radius,
                tick_offset,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    let a = self.local_expr(*start);
                    let b = self.local_expr(*end);
                    let r = self.local_expr(*radius);
                    let toff = self.local_expr(*tick_offset);
                    let hist_ptr_expr = if let Some(c_idx) = self.parent.find_comp_idx(history_name)
                    {
                        if self.parent.components[c_idx].has_mod_res {
                            format!(
                                "(state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? (const void*)state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : (const void*)&state->mod_res_{c_idx}"
                            )
                        } else {
                            format!(
                                "(state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? (const void*)state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL"
                            )
                        }
                    } else {
                        "NULL".to_string()
                    };
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* h_ptr = {hist_ptr_expr};\n        spatial_buf_{sid} = strata_spatial_query_segment_at(h_ptr, {a}, {b}, (float){r}, (float){toff});\n        {de} = (const BamEntity*)spatial_buf_{sid}.entities;\n    }}"
                    );
                }
            }
            Inst::TableLoad {
                table_name,
                key,
                field,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ke = self.local_expr(*key);
                    let t_ident = sanitize_ident(table_name);
                    if field.is_empty() {
                        let _ =
                            writeln!(s, "    {de} = strata_table_load_{t_ident}((int32_t){ke});");
                    } else {
                        let fc = sanitize_c_field(field);
                        let _ = writeln!(
                            s,
                            "    {de} = strata_table_load_{t_ident}((int32_t){ke}).{fc};"
                        );
                    }
                }
            }
            Inst::CurveSample { curve_name, x } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let xe = self.local_expr(*x);
                    let c_ident = sanitize_ident(curve_name);
                    let _ = writeln!(s, "    {de} = strata_curve_sample_{c_ident}({xe});");
                }
            }
            Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let pe = self.local_expr(*slice_ptr);
                    let _ = writeln!(s, "    {de} = ({pe} != NULL) ? BAM_TRUE : BAM_FALSE;");
                }
            }
            Inst::DirtyRunInit { run_start, run_len } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let _ = writeln!(s, "    {rs} = 0u;\n    {rl} = 0u;");
            }
            Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx,
            } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let r = self.local_expr(*row_idx);
                let _ = writeln!(s, "    if ({rl} == 0u) {{");
                let _ = writeln!(s, "        {rs} = {r};\n        {rl} = 1u;");
                let _ = writeln!(s, "    }} else if ({rs} + {rl} == {r}) {{");
                let _ = writeln!(s, "        {rl} += 1u;");
                let _ = writeln!(s, "    }} else {{");
                if let Some(owners) = self.dirty_owners.get(&(run_start.0, run_len.0)) {
                    for &(qi, ti) in owners {
                        let _ = writeln!(
                            s,
                            "        if (iter_{qi} != NULL && state->api->iter_mark_changed_range != NULL) {{\n            (void)state->api->iter_mark_changed_range(iter_{qi}, {ti}u, (size_t){rs}, (size_t){rl});\n        }}"
                        );
                    }
                }
                let _ = writeln!(s, "        {rs} = {r};\n        {rl} = 1u;");
                let _ = writeln!(s, "    }}");
            }
            Inst::ShadowWrite {
                shadow_slot, val, ..
            } => {
                let se = self.local_expr(*shadow_slot);
                let ve = self.local_expr(*val);
                let is_ptr = self.ptr_meta.contains_key(shadow_slot)
                    || matches!(
                        self.local_ty(*shadow_slot),
                        Some(MirType::Ptr | MirType::MutPtr)
                    );
                if is_ptr {
                    let _ = writeln!(
                        s,
                        "    if ({se} != NULL) {{ memcpy({se}, &{ve}, sizeof({ve})); }}"
                    );
                } else {
                    let _ = writeln!(s, "    {se} = {ve};");
                }
            }
            Inst::ShadowCommit {
                target_name,
                shadow_slot,
            } => {
                let se = self.local_expr(*shadow_slot);
                let _ = writeln!(
                    s,
                    "    /* Shadow commit `{target_name}` */\n    (void){se};"
                );
            }
            Inst::RequireTrue { cond } => {
                let ce = self.local_expr(*cond);
                if let Some(cp) = self.last_checkpoint {
                    let cpe = self.local_expr(cp);
                    let _ = writeln!(
                        s,
                        "    if (!({ce}) && cmds_cache != NULL && state->api->cmd_rollback != NULL) {{\n        (void)state->api->cmd_rollback(cmds_cache, {cpe});\n    }}"
                    );
                } else {
                    let _ = writeln!(s, "    (void)({ce});");
                }
            }
            Inst::FsmDispatch { fsm, .. } => {
                let _ = writeln!(s, "    /* FSM dispatch hook `{fsm}` */");
            }
            Inst::TaskStep {
                task,
                pc_local,
                timer_local,
                ..
            } => {
                let pe = self.local_expr(*pc_local);
                let te = self.local_expr(*timer_local);
                let _ = writeln!(
                    s,
                    "    /* Task step `{task}` */\n    (void){pe}; (void){te};"
                );
            }
            Inst::MigrateSrcPtr { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    if self.is_migration {
                        let _ = writeln!(s, "    {de} = ({cty})src_row;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
            Inst::MigrateDstPtr { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    if self.is_migration {
                        let _ = writeln!(s, "    {de} = ({cty})dst_row;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
        }
        Ok(())
    }

    fn ensure_cmds_snippet(&self, s: &mut String) {
        if !self.is_observer {
            let _ = writeln!(
                s,
                "    if (cmds_cache == NULL && sys_ctx != NULL && state->api->sys_commands != NULL) {{\n        (void)state->api->sys_commands(sys_ctx, &cmds_cache);\n    }}"
            );
        }
    }

    fn emit_binop(
        &self,
        dst: LocalId,
        op: &str,
        lhs: LocalId,
        rhs: LocalId,
        s: &mut String,
    ) -> Result<(), CodegenError> {
        let d = self.local_expr(dst);
        let lty = self.local_ty(lhs).cloned().unwrap_or(MirType::I32);
        let rty = self.local_ty(rhs).cloned().unwrap_or(MirType::I32);
        let is_eq_ne = matches!(op, "==" | "Eq" | "!=" | "Ne");
        let l = if is_eq_ne && !self.projected_fields.contains_key(&lhs) {
            self.local_expr(lhs)
        } else {
            self.unwrap_operand_expr(lhs, None)
        };
        let r = if is_eq_ne && !self.projected_fields.contains_key(&rhs) {
            self.local_expr(rhs)
        } else {
            self.unwrap_operand_expr(rhs, None)
        };

        match (&lty, &rty, op) {
            (MirType::Vec2, MirType::Vec2, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec2_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::Vec2, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec2_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::Vec2, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({l}, (float){r});");
                return Ok(());
            }
            (MirType::F32 | MirType::F64, MirType::Vec2, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({r}, (float){l});");
                return Ok(());
            }
            (MirType::Vec2, MirType::F32 | MirType::F64, "/" | "Div") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({l}, 1.0f / (float)({r}));");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec3_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec3_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({l}, (float){r});");
                return Ok(());
            }
            (MirType::F32 | MirType::F64, MirType::Vec3, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({r}, (float){l});");
                return Ok(());
            }
            (MirType::Vec3, MirType::F32 | MirType::F64, "/" | "Div") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({l}, 1.0f / (float)({r}));");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec4_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec4_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec4_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec4_scale({l}, (float){r});");
                return Ok(());
            }
            _ => {}
        }

        let (c_op, is_cmp) = match op {
            "+" | "Add" => ("+", false),
            "-" | "Sub" => ("-", false),
            "*" | "Mul" => ("*", false),
            "/" | "Div" => ("/", false),
            "%" | "Rem" => {
                if matches!(lty, MirType::F32) {
                    let _ = writeln!(s, "    {d} = fmodf({l}, {r});");
                    return Ok(());
                } else if matches!(lty, MirType::F64) {
                    let _ = writeln!(s, "    {d} = fmod({l}, {r});");
                    return Ok(());
                }
                ("%", false)
            }
            "==" | "Eq" => ("==", true),
            "!=" | "Ne" => ("!=", true),
            "<" | "Lt" => ("<", true),
            "<=" | "Le" => ("<=", true),
            ">" | "Gt" => (">", true),
            ">=" | "Ge" => (">=", true),
            "&&" | "And" => ("&&", true),
            "||" | "Or" => ("||", true),
            "&" | "BitAnd" => ("&", false),
            "|" | "BitOr" => ("|", false),
            "^" | "BitXor" => ("^", false),
            "<<" | "Shl" => ("<<", false),
            ">>" | "Shr" => (">>", false),
            other => {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::binop({})", self.func.name),
                    detail: format!("unsupported binary operator `{other}`"),
                });
            }
        };
        if is_cmp {
            let l_is_ptr = self.is_ptr_local(lhs) && !self.projected_fields.contains_key(&lhs);
            let r_is_ptr = self.is_ptr_local(rhs) && !self.projected_fields.contains_key(&rhs);
            let l_is_agg = (!l_is_ptr && self.parent.is_aggregate_mir_ty(&lty))
                || self.is_projected_aggregate(lhs);
            let r_is_agg = (!r_is_ptr && self.parent.is_aggregate_mir_ty(&rty))
                || self.is_projected_aggregate(rhs);
            let is_float = |id: LocalId, ty: &MirType| {
                matches!(ty, MirType::F32 | MirType::F64)
                    || matches!(
                        self.projected_sema_ty(id),
                        Some(Ty::F32 | Ty::F64 | Ty::UnitScalar { .. })
                    )
            };
            let is_u64 = |id: LocalId, ty: &MirType| {
                matches!(ty, MirType::U64 | MirType::Entity)
                    || matches!(
                        self.projected_sema_ty(id),
                        Some(Ty::U64 | Ty::BitSet(_) | Ty::Ref(_))
                    )
            };
            let is_scalar = |id: LocalId, ty: &MirType| {
                if is_float(id, ty) {
                    return false;
                }
                if let Some(sty) = self.projected_sema_ty(id) {
                    return !Self::is_sema_aggregate(self.parent, sty);
                }
                matches!(
                    ty,
                    MirType::Unit
                        | MirType::Bool
                        | MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Fix32
                        | MirType::Fix64
                        | MirType::Sym
                        | MirType::Entity
                )
            };
            if matches!(c_op, "==" | "!=") && (l_is_ptr || r_is_ptr) {
                let cmp = if c_op == "==" { "== 0" } else { "!= 0" };
                if l_is_ptr && !r_is_ptr && !is_scalar(rhs, &rty) {
                    let r_cty = self.operand_c_ty(rhs);
                    let _ = writeln!(s, "    {{");
                    let _ = writeln!(s, "        {r_cty} _cr = {r};");
                    let _ = writeln!(
                        s,
                        "        {d} = ({l} != NULL && memcmp({l}, &_cr, sizeof(_cr)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                    );
                    let _ = writeln!(s, "    }}");
                } else if r_is_ptr && !l_is_ptr && !is_scalar(lhs, &lty) {
                    let l_cty = self.operand_c_ty(lhs);
                    let _ = writeln!(s, "    {{");
                    let _ = writeln!(s, "        {l_cty} _cl = {l};");
                    let _ = writeln!(
                        s,
                        "        {d} = ({r} != NULL && memcmp({r}, &_cl, sizeof(_cl)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                    );
                    let _ = writeln!(s, "    }}");
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = (((uintptr_t)({l})) {c_op} ((uintptr_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
            } else if matches!(c_op, "==" | "!=") && (l_is_agg || r_is_agg) {
                let l_cty = self.operand_c_ty(lhs);
                let r_cty = self.operand_c_ty(rhs);
                let cmp = if c_op == "==" { "== 0" } else { "!= 0" };
                let _ = writeln!(s, "    {{");
                let _ = writeln!(s, "        {l_cty} _cl = {l};");
                let _ = writeln!(s, "        {r_cty} _cr = {r};");
                let _ = writeln!(
                    s,
                    "        {d} = (memcmp(&_cl, &_cr, sizeof(_cl) <= sizeof(_cr) ? sizeof(_cl) : sizeof(_cr)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                );
                let _ = writeln!(s, "    }}");
            } else if is_scalar(lhs, &lty) && is_scalar(rhs, &rty) && !matches!(c_op, "&&" | "||") {
                if is_u64(lhs, &lty) || is_u64(rhs, &rty) {
                    let _ = writeln!(
                        s,
                        "    {d} = (((uint64_t)({l})) {c_op} ((uint64_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = (((int64_t)({l})) {c_op} ((int64_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
            } else {
                let _ = writeln!(s, "    {d} = (({l}) {c_op} ({r})) ? BAM_TRUE : BAM_FALSE;");
            }
        } else {
            let _ = writeln!(s, "    {d} = ({l}) {c_op} ({r});");
        }
        Ok(())
    }

    fn emit_unop(&self, dst: LocalId, op: &str, val: LocalId, s: &mut String) {
        let d = self.local_expr(dst);
        let r = self.local_expr(val);
        let src_ty = self.local_ty(val).cloned().unwrap_or(MirType::I32);
        match op {
            "-" | "Neg" => match src_ty {
                MirType::Vec2 => {
                    let _ = writeln!(s, "    {d} = strata_vec2(-{r}.x, -{r}.y);");
                }
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3(-{r}.x, -{r}.y, -{r}.z);");
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4(-{r}.x, -{r}.y, -{r}.z, -{r}.w);");
                }
                _ => {
                    let _ = writeln!(s, "    {d} = -({r});");
                }
            },
            "!" | "Not" => {
                let _ = writeln!(s, "    {d} = (!({r})) ? BAM_TRUE : BAM_FALSE;");
            }
            _ => {
                let _ = writeln!(s, "    {d} = ~({r});");
            }
        }
    }

    fn emit_intrinsic_math(&self, dst: LocalId, name: &str, args: &[LocalId], s: &mut String) {
        let d = self.local_expr(dst);
        let a = |i: usize| {
            args.get(i)
                .map(|id| self.local_expr(*id))
                .unwrap_or_else(|| "0.0f".to_string())
        };
        let vec_kind = args
            .iter()
            .find_map(|id| match self.effective_vec_ty(*id) {
                Some(MirType::Vec3) => Some(MirType::Vec3),
                Some(MirType::Vec4) => Some(MirType::Vec4),
                _ => None,
            })
            .or_else(|| args.first().and_then(|id| self.effective_vec_ty(*id)))
            .unwrap_or(MirType::Vec2);
        let av = |i: usize| {
            args.get(i)
                .map(|id| self.unwrap_operand_expr(*id, Some(&vec_kind)))
                .unwrap_or_else(|| "strata_vec2(0.0f, 0.0f)".to_string())
        };
        let d_ty = self.local_ty(dst).cloned().unwrap_or(MirType::F32);
        let t0 = vec_kind.clone();
        match short_name(name) {
            "sin" => {
                let _ = writeln!(s, "    {d} = sinf((float){});", a(0));
            }
            "cos" => {
                let _ = writeln!(s, "    {d} = cosf((float){});", a(0));
            }
            "tan" => {
                let _ = writeln!(s, "    {d} = tanf((float){});", a(0));
            }
            "atan2" => {
                let _ = writeln!(s, "    {d} = atan2f((float){}, (float){});", a(0), a(1));
            }
            "sqrt" => {
                let _ = writeln!(s, "    {d} = sqrtf((float){});", a(0));
            }
            "abs" => {
                if matches!(
                    d_ty,
                    MirType::I32 | MirType::I64 | MirType::I16 | MirType::I8
                ) {
                    let x = a(0);
                    let _ = writeln!(s, "    {d} = ({x} < 0) ? -{x} : {x};");
                } else {
                    let _ = writeln!(s, "    {d} = fabsf((float){});", a(0));
                }
            }
            "min" => {
                let x = a(0);
                let y = a(1);
                if matches!(d_ty, MirType::F32) {
                    let _ = writeln!(s, "    {d} = fminf({x}, {y});");
                } else if matches!(d_ty, MirType::F64) {
                    let _ = writeln!(s, "    {d} = fmin({x}, {y});");
                } else {
                    let _ = writeln!(s, "    {d} = ({x} < {y}) ? {x} : {y};");
                }
            }
            "max" => {
                let x = a(0);
                let y = a(1);
                if matches!(d_ty, MirType::F32) {
                    let _ = writeln!(s, "    {d} = fmaxf({x}, {y});");
                } else if matches!(d_ty, MirType::F64) {
                    let _ = writeln!(s, "    {d} = fmax({x}, {y});");
                } else {
                    let _ = writeln!(s, "    {d} = ({x} > {y}) ? {x} : {y};");
                }
            }
            "floor" => {
                let _ = writeln!(s, "    {d} = floorf((float){});", a(0));
            }
            "ceil" => {
                let _ = writeln!(s, "    {d} = ceilf((float){});", a(0));
            }
            "round" => {
                let _ = writeln!(s, "    {d} = roundf((float){});", a(0));
            }
            "pow" | "powf" => {
                let _ = writeln!(s, "    {d} = powf((float){}, (float){});", a(0), a(1));
            }
            "exp" => {
                let _ = writeln!(s, "    {d} = expf((float){});", a(0));
            }
            "log" | "ln" => {
                let _ = writeln!(s, "    {d} = logf((float){});", a(0));
            }
            "clamp" => {
                let x = a(0);
                let lo = a(1);
                let hi = a(2);
                let _ = writeln!(
                    s,
                    "    {d} = ({x} < {lo}) ? {lo} : (({x} > {hi}) ? {hi} : {x});"
                );
            }
            "lerp" => match d_ty {
                MirType::Vec2 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_vec2_lerp({}, {}, {});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
                MirType::Vec3 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_vec3_lerp({}, {}, {});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
                _ => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_lerp_f32((float){}, (float){}, (float){});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
            },
            "dot" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dot({}, {});", av(0), av(1));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_dot({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dot({}, {});", av(0), av(1));
                }
            },
            "length" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_len({});", av(0));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_len({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_len({});", av(0));
                }
            },
            "length_sq" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_len_sq({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_len_sq({});", av(0));
                }
            },
            "distance" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dist({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dist({}, {});", av(0), av(1));
                }
            },
            "distance_sq" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dist_sq({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dist_sq({}, {});", av(0), av(1));
                }
            },
            "normalize" | "normalize_or_zero" => match d_ty {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_norm({});", av(0));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_norm({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_norm({});", av(0));
                }
            },
            "cross" => {
                let _ = writeln!(s, "    {d} = strata_vec3_cross({}, {});", av(0), av(1));
            }
            "vec2" | "Vec2" => {
                let _ = writeln!(s, "    {d} = strata_vec2({}, {});", a(0), a(1));
            }
            "vec3" | "Vec3" => {
                let _ = writeln!(s, "    {d} = strata_vec3({}, {}, {});", a(0), a(1), a(2));
            }
            "vec4" | "Vec4" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_vec4({}, {}, {}, {});",
                    a(0),
                    a(1),
                    a(2),
                    a(3)
                );
            }
            "from_rotation_y" | "quat_from_rotation_y" => {
                let _ = writeln!(s, "    {d} = strata_quat_from_rotation_y({});", a(0));
            }
            "sqr" => {
                let _ = writeln!(s, "    {d} = strata_sqr_f32((float){});", a(0));
            }
            "signum" => {
                let _ = writeln!(s, "    {d} = strata_signum_f32((float){});", a(0));
            }
            _ => {
                let _ = writeln!(
                    s,
                    "    /* intrinsic `{name}` */ memset(&{d}, 0, sizeof({d}));"
                );
            }
        }
    }

    fn resolve_member_in_layout(
        &self,
        layout_key: &str,
        field_name: &str,
        offset_bytes: u32,
        target_ty: Option<&MirType>,
    ) -> Option<(usize, String, String)> {
        let l_idx = self.parent.find_layout_idx(layout_key)?;
        let layout = &self.parent.layouts[l_idx];
        let path = self.resolve_path_in_fields(
            &layout.fields,
            field_name,
            offset_bytes as usize,
            target_ty,
        )?;
        let ptr_cast = format!("const {}", self.parent.layout_c_names[l_idx]);
        Some((l_idx, ptr_cast, path))
    }

    fn resolve_path_in_fields(
        &self,
        fields: &[SolvedField],
        field_name: &str,
        rel_offset: usize,
        target_ty: Option<&MirType>,
    ) -> Option<String> {
        // Prefer exact offset match when type also aligns in C99 representation.
        for f in fields {
            if f.is_padding {
                continue;
            }
            if f.offset == rel_offset
                && (field_name.is_empty() || f.name == field_name)
                && target_ty.is_none_or(|tt| ty_matches_sema(&f.ty, tt))
            {
                return Some(sanitize_c_field(&f.name));
            }
        }
        // Try nested subfield traversal.
        for f in fields {
            if f.is_padding {
                continue;
            }
            if rel_offset >= f.offset && rel_offset < f.offset + f.size {
                let sub_off = rel_offset - f.offset;
                let sub_field = field_name
                    .strip_prefix(&format!("{}.", f.name))
                    .unwrap_or(field_name);
                if let Some(sub_path) =
                    self.resolve_path_in_sema_ty(&f.ty, sub_field, sub_off, target_ty)
                {
                    return Some(format!("{}.{sub_path}", sanitize_c_field(&f.name)));
                }
            }
        }
        None
    }

    fn resolve_path_in_sema_ty(
        &self,
        ty: &Ty,
        field_name: &str,
        rel_offset: usize,
        target_ty: Option<&MirType>,
    ) -> Option<String> {
        match ty {
            Ty::Vec2 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some("x".to_string()),
                (4, None | Some(MirType::F32)) => Some("y".to_string()),
                _ => None,
            },
            Ty::Vec3 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some("x".to_string()),
                (4, None | Some(MirType::F32)) => Some("y".to_string()),
                (8, None | Some(MirType::F32)) => Some("z".to_string()),
                _ => None,
            },
            Ty::Vec4 | Ty::Quat | Ty::Rgba | Ty::Vec3a => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some("x".to_string()),
                (4, None | Some(MirType::F32)) => Some("y".to_string()),
                (8, None | Some(MirType::F32)) => Some("z".to_string()),
                (12, None | Some(MirType::F32)) => Some("w".to_string()),
                _ => None,
            },
            Ty::IVec2 | Ty::UVec2 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::I32 | MirType::U32)) => Some("x".to_string()),
                (4, None | Some(MirType::I32 | MirType::U32)) => Some("y".to_string()),
                _ => None,
            },
            Ty::IVec3 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::I32)) => Some("x".to_string()),
                (4, None | Some(MirType::I32)) => Some("y".to_string()),
                (8, None | Some(MirType::I32)) => Some("z".to_string()),
                _ => None,
            },
            Ty::Named(key) => {
                let l_idx = self.parent.find_layout_idx(key)?;
                self.resolve_path_in_fields(
                    &self.parent.layouts[l_idx].fields,
                    field_name,
                    rel_offset,
                    target_ty,
                )
            }
            _ => None,
        }
    }

    fn is_ptr_local(&self, id: LocalId) -> bool {
        self.ptr_meta.contains_key(&id)
            || matches!(self.local_ty(id), Some(MirType::Ptr | MirType::MutPtr))
    }

    fn resolve_tuple_or_vec_member(
        &self,
        ty: &MirType,
        field: &str,
        offset_bytes: u32,
    ) -> Option<String> {
        match ty {
            MirType::Tuple(elems) => {
                if let Ok(idx) = field.trim_start_matches('f').parse::<usize>()
                    && idx < elems.len()
                {
                    return Some(format!("f{idx}"));
                }
                let mut off = 0u32;
                for (i, et) in elems.iter().enumerate() {
                    let (sz, al) = approx_mir_size_align(et);
                    let rem = off % al;
                    if rem != 0 {
                        off += al - rem;
                    }
                    if off == offset_bytes {
                        return Some(format!("f{i}"));
                    }
                    off += sz;
                }
                None
            }
            MirType::Vec2 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                _ => None,
            },
            MirType::Vec3 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                ("z", _) | (_, 8) => Some("z".to_string()),
                _ => None,
            },
            MirType::Vec4 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                ("z", _) | (_, 8) => Some("z".to_string()),
                ("w", _) | (_, 12) => Some("w".to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_field_load(
        &self,
        dst: LocalId,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        field_ty: &MirType,
        s: &mut String,
    ) {
        let d = self.local_expr(dst);
        let p = self.local_expr(base_ptr);

        if !self.is_ptr_local(base_ptr) {
            if let Some(MirType::Named(k)) = self.local_ty(base_ptr)
                && let Some(tname) = k.strip_prefix("__strata_table_")
                && let Some(tbl) = self.parent.mir.tables.iter().find(|tb| tb.name == tname)
                && !field.is_empty()
                && tbl.fields.iter().any(|(fnm, _)| fnm == field)
            {
                let fc = sanitize_c_field(field);
                if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(s, "    {d} = ({p}.{fc}) ? BAM_TRUE : BAM_FALSE;");
                } else {
                    let _ = writeln!(s, "    {d} = {p}.{fc};");
                }
                return;
            }
            if let Some(bty) = self.local_ty(base_ptr)
                && let Some(mem) = self.resolve_tuple_or_vec_member(bty, field, offset_bytes)
            {
                if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(s, "    {d} = ({p}.{mem}) ? BAM_TRUE : BAM_FALSE;");
                } else {
                    let _ = writeln!(s, "    {d} = {p}.{mem};");
                }
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key
                && let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, Some(field_ty))
            {
                if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(s, "    {d} = ({p}.{path}) ? BAM_TRUE : BAM_FALSE;");
                } else {
                    let _ = writeln!(s, "    {d} = {p}.{path};");
                }
                return;
            }
            let _ = writeln!(
                s,
                "    memcpy(&{d}, ((const uint8_t*)&{p}) + {offset_bytes}u, sizeof({d}));"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key
            && let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, Some(field_ty))
        {
            let same_ptr = matches!(
                self.ptr_meta.get(&base_ptr),
                Some(PtrKind::LayoutPtr { layout_idx, .. }) if *layout_idx == l_idx
            );
            let access = if same_ptr {
                format!("{p}->{path}")
            } else {
                let cty = &self.parent.layout_c_names[l_idx];
                format!("((const {cty}* BAM_RESTRICT){p})->{path}")
            };
            if matches!(field_ty, MirType::Bool) {
                let _ = writeln!(
                    s,
                    "    if ({p} != NULL) {{ {d} = ({access}) ? BAM_TRUE : BAM_FALSE; }}"
                );
            } else {
                let _ = writeln!(s, "    if ({p} != NULL) {{ {d} = {access}; }}");
            }
            return;
        }
        let _ = writeln!(
            s,
            "    if ({p} != NULL) {{ memcpy(&{d}, ((const uint8_t*){p}) + {offset_bytes}u, sizeof({d})); }}"
        );
    }

    fn emit_field_store(
        &self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        val: LocalId,
        s: &mut String,
    ) {
        let p = self.local_expr(base_ptr);
        let v = self.local_expr(val);
        let vty = self.local_ty(val).cloned().unwrap_or(MirType::U32);

        if !self.is_ptr_local(base_ptr) {
            if let Some(bty) = self.local_ty(base_ptr)
                && let Some(mem) = self.resolve_tuple_or_vec_member(bty, field, offset_bytes)
            {
                let _ = writeln!(s, "    {p}.{mem} = {v};");
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key
                && let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, Some(&vty))
            {
                let _ = writeln!(s, "    {p}.{path} = {v};");
                return;
            }
            let _ = writeln!(
                s,
                "    memcpy(((uint8_t*)&{p}) + {offset_bytes}u, &{v}, sizeof({v}));"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key
            && let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, Some(&vty))
        {
            let same_ptr = matches!(
                self.ptr_meta.get(&base_ptr),
                Some(PtrKind::LayoutPtr { layout_idx, is_mut: true }) if *layout_idx == l_idx
            );
            let access = if same_ptr {
                format!("{p}->{path}")
            } else {
                let cty = &self.parent.layout_c_names[l_idx];
                format!("(({cty}* BAM_RESTRICT){p})->{path}")
            };
            let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = {v}; }}");
            return;
        }
        let _ = writeln!(
            s,
            "    if ({p} != NULL) {{ memcpy(((uint8_t*){p}) + {offset_bytes}u, &{v}, sizeof({v})); }}"
        );
    }

    fn emit_field_ptr(
        &self,
        dst: LocalId,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        s: &mut String,
    ) {
        let d = self.local_expr(dst);
        let p = self.local_expr(base_ptr);
        let dst_cty = self.ptr_c_ty(dst).unwrap_or_else(|| "void*".to_string());

        if !self.is_ptr_local(base_ptr) {
            if let Some(MirType::Named(k)) = self.local_ty(base_ptr)
                && let Some(tname) = k.strip_prefix("__strata_table_")
                && let Some(tbl) = self.parent.mir.tables.iter().find(|tb| tb.name == tname)
                && !field.is_empty()
                && tbl.fields.iter().any(|(fnm, _)| fnm == field)
            {
                let fc = sanitize_c_field(field);
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{fc});");
                return;
            }
            if let Some(bty) = self.local_ty(base_ptr)
                && let Some(mem) = self.resolve_tuple_or_vec_member(bty, field, offset_bytes)
            {
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{mem});");
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key
                && let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, None)
            {
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{path});");
                return;
            }
            let _ = writeln!(
                s,
                "    {d} = ({dst_cty})(((uint8_t*)&{p}) + {offset_bytes}u);"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key
            && let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, None)
        {
            let is_mut = self.ptr_meta.get(&base_ptr).is_none_or(PtrKind::is_mut);
            let cty = &self.parent.layout_c_names[l_idx];
            let access = if is_mut {
                format!("(({cty}*){p})->{path}")
            } else {
                format!("((const {cty}*){p})->{path}")
            };
            let _ = writeln!(
                s,
                "    {d} = ({p} != NULL) ? ({dst_cty})&({access}) : NULL;"
            );
            return;
        }
        let _ = writeln!(
            s,
            "    {d} = ({p} != NULL) ? ({dst_cty})(((uint8_t*){p}) + {offset_bytes}u) : NULL;"
        );
    }

    fn emit_cmd_spawn(
        &self,
        dst_entity: Option<LocalId>,
        components: &[(String, LocalId)],
        is_persistent: bool,
        s: &mut String,
    ) {
        self.ensure_cmds_snippet(s);
        let n = components.len().max(1);
        let slot = if is_persistent {
            "cmd_spawn_persistent"
        } else {
            "cmd_spawn"
        };
        let _ = writeln!(s, "    {{");
        let _ = writeln!(s, "        BamComponent sp_comps[{n}u];");
        let _ = writeln!(s, "        const uint8_t* sp_datas[{n}u];");
        for (i, (cname, lid)) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            let _ = writeln!(s, "        sp_comps[{i}u] = state->components[{c_idx}];");
            if sz == 0 {
                let _ = writeln!(s, "        sp_datas[{i}u] = NULL;");
            } else {
                let is_ptr = self.ptr_meta.contains_key(lid)
                    || matches!(self.local_ty(*lid), Some(MirType::Ptr | MirType::MutPtr));
                let le = self.local_expr(*lid);
                if is_ptr {
                    let _ = writeln!(s, "        sp_datas[{i}u] = (const uint8_t*){le};");
                } else {
                    let _ = writeln!(s, "        sp_datas[{i}u] = (const uint8_t*)&{le};");
                }
            }
        }
        if components.is_empty() {
            let _ = writeln!(s, "        sp_comps[0u] = BAM_COMPONENT_INVALID;");
            let _ = writeln!(s, "        sp_datas[0u] = NULL;");
        }
        let _ = writeln!(s, "        BamEntity out_ent = BAM_ENTITY_NULL;");
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->{slot} != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->{slot}(cmds_cache, sp_comps, sp_datas, {}u, &out_ent);",
            components.len()
        );
        let _ = writeln!(s, "        }}");
        if let Some(d) = dst_entity {
            let de = self.local_expr(d);
            let _ = writeln!(s, "        {de} = out_ent;");
        }
        let _ = writeln!(s, "    }}");
    }

    fn emit_cmd_spawn_batch(
        &self,
        count: LocalId,
        components: &[(String, LocalId)],
        s: &mut String,
    ) {
        self.ensure_cmds_snippet(s);
        let cnt = self.local_expr(count);
        let n = components.len().max(1);
        let _ = writeln!(s, "    if ((int64_t)({cnt}) > 0) {{");
        let _ = writeln!(s, "        size_t batch_n = (size_t)({cnt});");
        let _ = writeln!(s, "        BamComponent sp_comps[{n}u];");
        let _ = writeln!(s, "        const uint8_t* sp_cols[{n}u];");
        let _ = writeln!(s, "        uint8_t* sp_allocs[{n}u];");
        for (i, (cname, lid)) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            let _ = writeln!(s, "        sp_comps[{i}u] = state->components[{c_idx}];");
            let _ = writeln!(s, "        sp_cols[{i}u] = NULL;");
            let _ = writeln!(s, "        sp_allocs[{i}u] = NULL;");
            if sz > 0 {
                let is_ptr = self.ptr_meta.contains_key(lid)
                    || matches!(self.local_ty(*lid), Some(MirType::Ptr | MirType::MutPtr));
                let le = self.local_expr(*lid);
                let src_p = if is_ptr {
                    format!("(const uint8_t*){le}")
                } else {
                    format!("(const uint8_t*)&{le}")
                };
                let _ = writeln!(
                    s,
                    "        sp_allocs[{i}u] = (uint8_t*)calloc(batch_n, {sz}u);\n        if (sp_allocs[{i}u] != NULL) {{\n            const uint8_t* tmpl_{i} = {src_p};\n            if (tmpl_{i} != NULL) {{\n                for (size_t r = 0u; r < batch_n; ++r) {{\n                    memcpy(sp_allocs[{i}u] + r * {sz}u, tmpl_{i}, {sz}u);\n                }}\n            }}\n            sp_cols[{i}u] = sp_allocs[{i}u];\n        }}"
                );
            }
        }
        if components.is_empty() {
            let _ = writeln!(s, "        sp_comps[0u] = BAM_COMPONENT_INVALID;");
            let _ = writeln!(s, "        sp_cols[0u] = NULL;");
            let _ = writeln!(s, "        sp_allocs[0u] = NULL;");
        }
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->cmd_spawn_batch != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->cmd_spawn_batch(cmds_cache, sp_comps, sp_cols, {}u, batch_n, NULL);",
            components.len()
        );
        let _ = writeln!(s, "        }}");
        for i in 0..n {
            let _ = writeln!(s, "        free(sp_allocs[{i}u]);");
        }
        let _ = writeln!(s, "    }}");
    }

    fn emit_cmd_despawn_all(&self, filter: &str, s: &mut String) {
        self.ensure_cmds_snippet(s);
        let mut t_strs = Vec::new();
        for tok in filter.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if let Some(inner) = tok
                .strip_prefix("Without<")
                .and_then(|r| r.strip_suffix('>'))
            {
                if let Some(c_idx) = self.parent.find_comp_idx(inner.trim()) {
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_WITHOUT, 0u)"
                    ));
                }
            } else if let Some(inner) = tok.strip_prefix("With<").and_then(|r| r.strip_suffix('>'))
            {
                if let Some(c_idx) = self.parent.find_comp_idx(inner.trim()) {
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                    ));
                }
            } else if let Some(c_idx) = self.parent.find_comp_idx(tok) {
                t_strs.push(format!(
                    "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                ));
            }
        }
        let n = t_strs.len().max(1);
        let _ = writeln!(s, "    {{");
        let _ = writeln!(s, "        BamTermDesc flt_terms[{n}u];");
        for (i, ts) in t_strs.iter().enumerate() {
            let _ = writeln!(s, "        flt_terms[{i}u] = {ts};");
        }
        if t_strs.is_empty() {
            let _ = writeln!(s, "        memset(&flt_terms[0u], 0, sizeof(BamTermDesc));");
        }
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->cmd_despawn_all != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->cmd_despawn_all(cmds_cache, flt_terms, {}u);",
            t_strs.len()
        );
        let _ = writeln!(s, "        }}");
        let _ = writeln!(s, "    }}");
    }

    fn emit_call(
        &self,
        dst: Option<LocalId>,
        callee: &str,
        args: &[LocalId],
        s: &mut String,
    ) -> Result<(), CodegenError> {
        let a = |i: usize| {
            args.get(i)
                .map(|id| self.local_expr(*id))
                .unwrap_or_else(|| "0".to_string())
        };
        if let Some(d) = dst {
            let de = self.local_expr(d);
            let dty = self.local_ty(d).cloned().unwrap_or(MirType::F32);
            if let Some(&h_idx) = self.parent.helper_by_name.get(callee) {
                let h_name = format!(
                    "strata_fn_{}",
                    sanitize_ident(&self.parent.mir_functions()[h_idx].name)
                );
                let mut call_args = vec!["state".to_string()];
                for id in args {
                    call_args.push(self.local_expr(*id));
                }
                let _ = writeln!(s, "    {de} = {h_name}({});", call_args.join(", "));
                return Ok(());
            }
            match short_name(callee) {
                "sqr" => {
                    if matches!(dty, MirType::F64) {
                        let _ = writeln!(s, "    {de} = strata_sqr_f64((double){});", a(0));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_sqr_f32((float){});", a(0));
                    }
                }
                "signum" => {
                    let _ = writeln!(s, "    {de} = strata_signum_f32((float){});", a(0));
                }
                "length_sq" => {
                    let t0 = args
                        .first()
                        .and_then(|id| self.local_ty(*id))
                        .cloned()
                        .unwrap_or(MirType::Vec2);
                    if matches!(t0, MirType::Vec3) {
                        let _ = writeln!(s, "    {de} = strata_vec3_len_sq({});", a(0));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_vec2_len_sq({});", a(0));
                    }
                }
                "distance_sq" => {
                    let t0 = args
                        .first()
                        .and_then(|id| self.local_ty(*id))
                        .cloned()
                        .unwrap_or(MirType::Vec2);
                    if matches!(t0, MirType::Vec3) {
                        let _ = writeln!(s, "    {de} = strata_vec3_dist_sq({}, {});", a(0), a(1));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_vec2_dist_sq({}, {});", a(0), a(1));
                    }
                }
                "remap" => {
                    let v = a(0);
                    let i0 = a(1);
                    let i1 = a(2);
                    let o0 = a(3);
                    let o1 = a(4);
                    let _ = writeln!(
                        s,
                        "    {{\n        float span = (float)({i1}) - (float)({i0});\n        float t = (fabsf(span) > 1e-6f) ? (((float)({v}) - (float)({i0})) / span) : 0.0f;\n        {de} = (float)({o0}) + ((float)({o1}) - (float)({o0})) * t;\n    }}"
                    );
                }
                _ => {
                    let _ = writeln!(
                        s,
                        "    /* call `{callee}` */ memset(&{de}, 0, sizeof({de}));"
                    );
                }
            }
        } else if let Some(&h_idx) = self.parent.helper_by_name.get(callee) {
            let h_name = format!(
                "strata_fn_{}",
                sanitize_ident(&self.parent.mir_functions()[h_idx].name)
            );
            let mut call_args = vec!["state".to_string()];
            for id in args {
                call_args.push(self.local_expr(*id));
            }
            let _ = writeln!(s, "    {h_name}({});", call_args.join(", "));
        }
        Ok(())
    }

    fn emit_terminator(&self, term: &Terminator, s: &mut String) -> Result<(), CodegenError> {
        match term {
            Terminator::Goto(target) => {
                let _ = writeln!(s, "    goto bb_{};", target.0);
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let c = self.local_expr(*cond);
                let _ = writeln!(
                    s,
                    "    if ({c}) {{ goto bb_{}; }} else {{ goto bb_{}; }}",
                    then_bb.0, else_bb.0
                );
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                let sc = self.local_expr(*scrutinee);
                let _ = writeln!(s, "    switch ((uint32_t){sc}) {{");
                let mut seen_vals: HashSet<u32> = HashSet::new();
                for (val, target) in cases {
                    if seen_vals.insert(*val) {
                        let _ = writeln!(s, "        case {val}u: goto bb_{};", target.0);
                    }
                }
                let _ = writeln!(s, "        default: goto bb_{};", default_bb.0);
                let _ = writeln!(s, "    }}");
            }
            Terminator::Return(val_opt) => {
                if self.is_void_helper {
                    let _ = writeln!(s, "    return;");
                } else if self.is_helper {
                    if let Some(val) = val_opt {
                        let v = self.local_expr(*val);
                        let _ = writeln!(s, "    return {v};");
                    } else {
                        let rcty = self.parent.c_ty(&self.func.ret_ty);
                        let _ = writeln!(
                            s,
                            "    {{ {rcty} _ret_zero; memset(&_ret_zero, 0, sizeof(_ret_zero)); return _ret_zero; }}"
                        );
                    }
                } else {
                    let _ = writeln!(s, "    return BAM_RESULT_OK;");
                }
            }
        }
        Ok(())
    }
}

fn analyze_cfg(blocks: &[BasicBlock]) -> (HashSet<u32>, HashSet<u32>) {
    let mut reachable: HashSet<u32> = HashSet::new();
    let mut label_targets: HashSet<u32> = HashSet::new();
    let by_id: HashMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.0, i))
        .collect();
    if let Some(&entry_idx) = by_id.get(&0) {
        let mut q = VecDeque::new();
        reachable.insert(0);
        q.push_back(entry_idx);
        while let Some(bi) = q.pop_front() {
            let bb = &blocks[bi];
            let mut push_t = |tid: BlockId| {
                label_targets.insert(tid.0);
                if reachable.insert(tid.0)
                    && let Some(&next_idx) = by_id.get(&tid.0)
                {
                    q.push_back(next_idx);
                }
            };
            match &bb.terminator {
                Terminator::Goto(t) => push_t(*t),
                Terminator::Branch {
                    then_bb, else_bb, ..
                } => {
                    push_t(*then_bb);
                    push_t(*else_bb);
                }
                Terminator::Switch {
                    cases, default_bb, ..
                } => {
                    for (_, t) in cases {
                        push_t(*t);
                    }
                    push_t(*default_bb);
                }
                Terminator::Return(_) => {}
            }
        }
    }
    (reachable, label_targets)
}

fn collect_inst_components(inst: &Inst, out: &mut BTreeSet<String>) {
    match inst {
        Inst::IterColRead { storage_key, .. }
        | Inst::IterColWrite { storage_key, .. }
        | Inst::IterColWriteUntracked { storage_key, .. }
        | Inst::IterColRowsRead { storage_key, .. }
        | Inst::IterColRowsWrite { storage_key, .. }
        | Inst::EntityGet { storage_key, .. }
        | Inst::EntityGetMut { storage_key, .. } => {
            out.insert(storage_key.clone());
        }
        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
            out.insert(resource.clone());
        }
        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
            out.insert(component.clone());
        }
        Inst::CmdSpawn { components, .. } | Inst::CmdSpawnBatch { components, .. } => {
            for (c, _) in components {
                out.insert(c.clone());
            }
        }
        Inst::CmdDespawnAll { filter } => {
            for tok in filter.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let inner = tok
                    .strip_prefix("Without<")
                    .or_else(|| tok.strip_prefix("With<"))
                    .and_then(|r| r.strip_suffix('>'))
                    .unwrap_or(tok)
                    .trim();
                if !inner.is_empty() {
                    out.insert(inner.to_string());
                }
            }
        }
        Inst::CmdTrigger { event, .. } => {
            out.insert(event.clone());
        }
        Inst::StreamEmit { stream, .. } => {
            out.insert(stream.clone());
        }
        _ => {}
    }
}

fn canonicalize(module_path: &str, name: &str) -> String {
    if name.contains("::") {
        name.to_string()
    } else {
        format!("{module_path}::{name}")
    }
}

fn short_name(canon: &str) -> &str {
    canon.rsplit("::").next().unwrap_or(canon)
}

fn lane_name(lane: u8) -> &'static str {
    match lane {
        0 => "x",
        1 => "y",
        2 => "z",
        _ => "w",
    }
}

fn approx_mir_size_align(ty: &MirType) -> (u32, u32) {
    match ty {
        MirType::Unit | MirType::Bool | MirType::U8 | MirType::I8 => (1, 1),
        MirType::U16 | MirType::I16 => (2, 2),
        MirType::U32 | MirType::I32 | MirType::F32 | MirType::Fix32 | MirType::Sym => (4, 4),
        MirType::U64
        | MirType::I64
        | MirType::F64
        | MirType::Fix64
        | MirType::Entity
        | MirType::Ptr
        | MirType::MutPtr
        | MirType::QueryIter
        | MirType::Checkpoint
        | MirType::Tuple(_)
        | MirType::Named(_) => (8, 8),
        MirType::Vec2 => (8, 4),
        MirType::Vec3 => (12, 4),
        MirType::Vec4 => (16, 4),
        MirType::Array { elem, len } => {
            let (sz, al) = approx_mir_size_align(elem);
            (sz.saturating_mul(*len as u32), al)
        }
    }
}

fn c_schedule_const(label: &str) -> &'static str {
    if label.eq_ignore_ascii_case("Startup") {
        "BAM_SCHEDULE_STARTUP"
    } else if label.eq_ignore_ascii_case("PreUpdate") {
        "BAM_SCHEDULE_PRE_UPDATE"
    } else if label.eq_ignore_ascii_case("PostUpdate") {
        "BAM_SCHEDULE_POST_UPDATE"
    } else if label.eq_ignore_ascii_case("FixedUpdate") {
        "BAM_SCHEDULE_FIXED_UPDATE"
    } else if label.eq_ignore_ascii_case("Last") {
        "BAM_SCHEDULE_LAST"
    } else {
        "BAM_SCHEDULE_UPDATE"
    }
}

fn c_access_mode(mode: TermAccessMode) -> &'static str {
    match mode {
        TermAccessMode::Read => "BAM_ACCESS_READ",
        TermAccessMode::Write | TermAccessMode::SelectiveWrite => "BAM_ACCESS_WRITE",
        TermAccessMode::OptionalRead => "BAM_ACCESS_OPTIONAL_READ",
        TermAccessMode::OptionalWrite => "BAM_ACCESS_OPTIONAL_WRITE",
        TermAccessMode::With => "BAM_ACCESS_FILTER_ONLY",
        TermAccessMode::Without => "BAM_ACCESS_WITHOUT",
        TermAccessMode::Allow => "BAM_ACCESS_ALLOW",
        TermAccessMode::Has => "BAM_ACCESS_HAS",
        TermAccessMode::RemovedRead => "BAM_ACCESS_REMOVED_READ",
        TermAccessMode::ResRead => "BAM_ACCESS_RESOURCE_READ",
        TermAccessMode::ResWrite => "BAM_ACCESS_RESOURCE_WRITE",
        TermAccessMode::StreamRead => "BAM_ACCESS_MESSAGE_READ",
        TermAccessMode::StreamWrite => "BAM_ACCESS_MESSAGE_WRITE",
    }
}

fn sanitize_c_field(name: &str) -> String {
    let s = sanitize_ident(name);
    match s.as_str() {
        "auto" | "break" | "case" | "char" | "const" | "continue" | "default" | "do" | "double"
        | "else" | "enum" | "extern" | "float" | "for" | "goto" | "if" | "inline" | "int"
        | "long" | "register" | "restrict" | "return" | "short" | "signed" | "sizeof"
        | "static" | "struct" | "switch" | "typedef" | "union" | "unsigned" | "void"
        | "volatile" | "while" | "state" | "type" | "class" => format!("f_{s}"),
        _ => s,
    }
}

fn c_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn c_f32(v: f32) -> String {
    if !v.is_finite() {
        return "0.0f".to_string();
    }
    let s = format!("{v}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        format!("{s}f")
    } else {
        format!("{s}.0f")
    }
}

fn c_f64(v: f64) -> String {
    if !v.is_finite() {
        return "0.0".to_string();
    }
    let s = format!("{v}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

fn ty_matches_sema(sema: &Ty, mir: &MirType) -> bool {
    matches!(
        (sema, mir),
        (Ty::Unit, MirType::Unit)
            | (Ty::Bool, MirType::Bool)
            | (Ty::I8, MirType::I8)
            | (Ty::I16, MirType::I16)
            | (Ty::I32, MirType::I32)
            | (Ty::I64, MirType::I64)
            | (Ty::U8, MirType::U8)
            | (Ty::U16, MirType::U16)
            | (Ty::U32, MirType::U32)
            | (Ty::U64, MirType::U64)
            | (Ty::F32 | Ty::UnitScalar { .. }, MirType::F32)
            | (Ty::F64, MirType::F64)
            | (Ty::Fix32, MirType::Fix32)
            | (Ty::Fix64, MirType::Fix64)
            | (Ty::Sym, MirType::Sym)
            | (Ty::Ref(_), MirType::Entity)
            | (Ty::Vec2, MirType::Vec2)
            | (Ty::Vec3, MirType::Vec3)
            | (Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba, MirType::Vec4)
    ) || matches!(
        (sema, mir),
        (Ty::Named(a), MirType::Named(b)) if a == b || short_name(a) == short_name(b)
    ) || matches!((sema, mir), (Ty::Named(_), MirType::I32))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    fn compile_strata_to_mir(label: &str, src: &str) -> MirModule {
        let parsed = strata_syntax::parse(src);
        assert!(
            parsed.errors().is_empty(),
            "syntax errors in {label}: {:?}",
            parsed.errors()
        );
        let sema = strata_sema::analyze_source(label, src);
        let fatal: Vec<_> = sema
            .diagnostics
            .iter()
            .filter(|d| matches!(d.severity, strata_sema::diagnostics::Severity::Error))
            .collect();
        assert!(fatal.is_empty(), "sema errors in {label}: {fatal:?}");
        strata_mir::lower_to_mir(&sema)
    }

    fn verify_strict_c99_syntax(artifact: &GeneratedArtifact, label: &str) {
        let tmp = tempfile::tempdir().expect("tempdir");
        for f in &artifact.files {
            let p = tmp.path().join(&f.path);
            std::fs::write(&p, &f.content).expect("write generated artifact");
        }
        let c_file = artifact
            .files
            .iter()
            .find(|f| f.path.ends_with(".c"))
            .expect("C source artifact");
        let primary = tmp.path().join(&c_file.path);
        let compiler = if Command::new("cc").arg("--version").output().is_ok() {
            "cc"
        } else {
            "clang"
        };
        let output = Command::new(compiler)
            .arg("-std=c99")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Wpedantic")
            .arg("-Werror")
            .arg("-fsyntax-only")
            .arg("-I")
            .arg(tmp.path())
            .arg(&primary)
            .output()
            .expect("invoke C99 compiler");
        assert!(
            output.status.success(),
            "Strict ISO C99 compilation failed for `{label}`:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn host_api_slot_constants_aligned_with_bamabi_sys() {
        assert_eq!(bamabi_sys::BAM_HOST_API_SLOT_COUNT, 68);
        const {
            assert!(MAX_TERMS_PER_QUERY >= 16);
            assert!(MAX_QUERIES_PER_SYSTEM >= 8);
        }
    }

    #[test]
    fn all_six_cookbooks_compile_under_strict_c99() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("cookbooks");
        let names = [
            "01_rain_swarm.strata",
            "02_soa_and_ticks.strata",
            "03_metroidvania_core.strata",
            "04_cozy_valley.strata",
            "05_soulslike_combat.strata",
            "06_battle_royale_server.strata",
        ];
        for name in names {
            let path = root.join(name);
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
            let mir = compile_strata_to_mir(name, &src);
            let artifact = emit(&mir).unwrap_or_else(|e| panic!("c99 emit failed for {name}: {e}"));
            let primary_c = &artifact
                .files
                .iter()
                .find(|f| f.path.ends_with(".c"))
                .expect("primary C file")
                .content;
            assert!(
                !primary_c.contains("g_strata_state"),
                "{name}: must not use global state `g_strata_state`"
            );
            assert!(
                primary_c.contains("calloc(1u, sizeof(StrataModState))"),
                "{name}: must heap-allocate StrataModState"
            );
            assert!(
                primary_c.contains("free(instance)"),
                "{name}: must free StrataModState in bamabi_shutdown"
            );
            verify_strict_c99_syntax(&artifact, name);
        }
    }

    #[test]
    fn migration_fixture_wires_migrate_component_column_and_compiles_c99() {
        let src = r#"
module demo::mig @version(2.0.0);

component HealthV1 {
    hp: f32,
}

component Health {
    hp: f32,
    max_hp: f32 = 100.0,
}

migrate Health from 1.0.0 to 2.0.0(old: &HealthV1) -> Health {
    Health { hp: old.hp, max_hp: old.hp }
}

sys heal() {
    for row in query(h: &mut Health) {
        row.h.hp = row.h.max_hp;
    }
}

schedule Update { heal }
"#;
        let mir = compile_strata_to_mir("migration_fixture.strata", src);
        let artifact = emit(&mir).expect("c99 emit for migration fixture");
        let primary_c = &artifact
            .files
            .iter()
            .find(|f| f.path.ends_with(".c"))
            .expect("primary C file")
            .content;
        assert!(
            primary_c.contains("migrate_component_column"),
            "migration fixture must emit migrate_component_column wiring"
        );
        verify_strict_c99_syntax(&artifact, "migration_fixture");
    }
}
