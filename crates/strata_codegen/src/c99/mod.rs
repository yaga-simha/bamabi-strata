//! Strict ISO C99 backend (`bamabi` ABI `0.3.0`, C99 `-std=c99 -Wall -Wextra -Wpedantic -Werror`).
//!
//! Consumes [`MirModule`] and [`MirFunction`] SSA CFGs directly (`blocks`, `locals`,
//! `query_bindings`, `resources`, `layouts`, `tables`, `curves`, `relations`,
//! `spatial_indices`, `objects`, `schedules`, `fns`) with zero `expr.rs` usage.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use bamabi_sys::{ComponentUuid, MAX_QUERIES_PER_SYSTEM, MAX_TERMS_PER_QUERY, fnv1a_64_str};
use strata_mir::ir::{
    BasicBlock, BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule,
    MirNetComponent, MirNetFieldSpec, MirQueryBinding, MirRpc, MirStmt, MirStreamOpKind, MirType,
    Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{
    HirBinOp, HirCompInit, HirExpr, HirObject, HirParamKind, HirScheduleGroup, HirUnOp,
};
use strata_sema::layout::{SchemaItemKind, SolvedField, SolvedLayout, compute_wire_identity};
use strata_sema::types::Ty;

use crate::net::{
    FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, FLAG_IS_RPC,
    PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_RESOURCE_DELTA, PACKET_KIND_RPC,
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_ALIGN, STRATA_NET_PACKET_CANONICAL_NAME,
    STRATA_NET_PACKET_MAGIC, STRATA_NET_PACKET_SCHEMA_FINGERPRINT, STRATA_NET_PACKET_SIZE,
    STRATA_NET_RX_BATCH_CAP, STRATA_NET_WIRE_VERSION, has_net_protocol,
    validate_net_packet_capacity,
};
use crate::{
    CodegenError, GeneratedArtifact, GeneratedFile, TargetKind, find_layout, is_ecs_component_kind,
    module_stem, sanitize_ident, system_schedule_label,
};

mod decls;
mod fn_emit;
mod inst_emit;
mod net_emit;
mod prelude;
#[cfg(test)]
mod tests;

use fn_emit::{collect_inst_components, mir_const_is_all_zero, mir_const_vals_match};
use inst_emit::FnEmitCtx;

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
    after_sets: Vec<usize>,
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
    after_weak_names: Vec<String>,
    before_names: Vec<String>,
    in_sets: Vec<String>,
    mount_set_indices: Vec<usize>,
    sched_order: usize,
    run_if_fn: Option<String>,
    run_if_resources: Vec<usize>,
    startup_obj_range: Option<(usize, usize)>,
}

#[derive(Clone, Debug)]
pub(super) struct DedupQueryTerms {
    pub(super) terms: Vec<(usize, &'static str, &'static str)>,
    pub(super) extra_changed: Vec<usize>,
    pub(super) extra_added: Vec<usize>,
    pub(super) remap: HashMap<u32, u32>,
    pub(super) aliased_dedup_indices: HashSet<u32>,
    pub(super) stream_comps: HashSet<usize>,
}

#[derive(Clone, Debug)]
struct RegObserver {
    obs_idx: usize,
    mir_fn_idx: usize,
    c_fn_name: String,
    reg_name: String,
    event_comp_idx: usize,
    target_comp_idx: Option<usize>,
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

#[derive(Clone, Copy)]
enum CompositeDecl {
    Tuple(usize),
    Array(usize),
}

struct EmitCtx<'a> {
    mir: &'a MirModule,
    all_fns: Vec<MirFunction>,
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
    raw_pod_sizes: BTreeSet<usize>,
    composite_order: Vec<CompositeDecl>,
    run_if_wrappers: Vec<String>,
}

impl<'a> EmitCtx<'a> {
    fn new(mir: &'a MirModule) -> Result<Self, CodegenError> {
        if has_net_protocol(mir) {
            validate_net_packet_capacity(mir)?;
        }
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

        let all_fns: Vec<MirFunction> = mir
            .fns
            .iter()
            .chain(mir.functions.iter())
            .cloned()
            .collect();
        let mut ctx = Self {
            mir,
            all_fns,
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
            raw_pod_sizes: BTreeSet::new(),
            composite_order: Vec::new(),
            run_if_wrappers: Vec::new(),
        };
        ctx.collect_registries()?;
        Ok(ctx)
    }

    fn mir_functions(&self) -> &[MirFunction] {
        &self.all_fns
    }

    fn collect_registries(&mut self) -> Result<(), CodegenError> {
        // 1. Collect migrations and helper functions.
        let mut mig_map: HashMap<String, String> = HashMap::new();
        for (fn_idx, f) in self.all_fns.iter().enumerate() {
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
            for op in &f.stream_ops {
                extra_tags.insert(op.canonical_stream.clone());
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
        let mut uses_child_of = false;
        for f in &fns_snapshot {
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    if let Inst::CmdInsertRelation { relation, .. }
                    | Inst::CmdRemoveRelation { relation, .. } = &stmt.inst
                        && is_child_of_rel(relation)
                    {
                        uses_child_of = true;
                    }
                }
            }
        }
        if uses_child_of && self.find_comp_idx(bamabi_sys::BAM_CHILD_OF_NAME).is_none() {
            let uuid = ComponentUuid::from_parts(bamabi_sys::BAM_CHILD_OF_NAME, 8, 8, 0);
            let (_, fp) = compute_wire_identity(bamabi_sys::BAM_CHILD_OF_NAME, 8, 8, 0, true, &[]);
            let idx = self.components.len();
            self.comp_by_key
                .insert(bamabi_sys::BAM_CHILD_OF_NAME.to_string(), idx);
            self.comp_by_key.insert("ChildOf".to_string(), idx);
            self.components.push(RegComponent {
                idx,
                canonical: bamabi_sys::BAM_CHILD_OF_NAME.to_string(),
                short: "ChildOf".to_string(),
                layout_idx: None,
                item_kind: None,
                has_mod_res: false,
                size: 8,
                align: 8,
                uuid,
                fingerprint: fp,
                flags: 0,
                migration_fn: None,
                required_indices: Vec::new(),
            });
        }
        for tag in extra_tags {
            if self.find_comp_idx(&tag).is_none() {
                if let Some((prefix, _)) = tag.rsplit_once("::")
                    && self.find_comp_idx(prefix).is_some()
                {
                    continue;
                }
                if let Some((prefix, _)) = tag.split_once('.')
                    && self.find_comp_idx(prefix).is_some()
                {
                    continue;
                }
                let canon = canonicalize(&self.mir.module_path, &tag);
                let short = short_name(&canon).to_string();
                let (uuid, fp) = compute_wire_identity(&canon, 0, 1, 0, true, &[]);
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
                    if let Some(r_idx) = self.find_comp_idx(req_name)
                        && r_idx != c.idx
                        && !reqs.contains(&r_idx)
                    {
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

    fn is_query_term_sparse(
        &self,
        f: &MirFunction,
        query_idx: u32,
        term_idx: u32,
        storage_key: &str,
    ) -> bool {
        let term_opt = f
            .query_bindings
            .iter()
            .find(|qb| qb.query_idx == query_idx)
            .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == term_idx));
        if let Some(c_idx) = term_opt
            .and_then(|t| self.find_comp_idx(&t.canonical_component))
            .or_else(|| self.find_comp_idx(storage_key))
        {
            return (self.components[c_idx].flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0;
        }
        term_opt.is_some_and(|t| t.is_sparse)
    }

    fn compute_query_param_set_groups(&self, f: &MirFunction) -> Vec<u32> {
        #[derive(Default)]
        struct QueryAccessSummary {
            with_set: HashSet<usize>,
            without_set: HashSet<usize>,
            reads: HashSet<usize>,
            writes: HashSet<usize>,
        }

        let n = f.query_bindings.len();
        if n <= 1 {
            return vec![0; n];
        }

        let mut summaries: Vec<QueryAccessSummary> = Vec::with_capacity(n);
        for qb in &f.query_bindings {
            let mut sum = QueryAccessSummary::default();
            for term in &qb.terms {
                let Some(c_idx) = self.find_comp_idx(&term.canonical_component) else {
                    continue;
                };
                let is_changed = f.changed_terms.iter().any(|ct| {
                    ct.query_idx == qb.query_idx
                        && (ct.term_idx == term.term_idx
                            || ct.canonical_component == term.canonical_component)
                });
                match term.mode {
                    TermAccessMode::With => {
                        sum.with_set.insert(c_idx);
                    }
                    TermAccessMode::Without => {
                        sum.without_set.insert(c_idx);
                    }
                    TermAccessMode::Read => {
                        sum.with_set.insert(c_idx);
                        sum.reads.insert(c_idx);
                    }
                    TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                        sum.with_set.insert(c_idx);
                        sum.writes.insert(c_idx);
                    }
                    TermAccessMode::OptionalRead => {
                        sum.reads.insert(c_idx);
                        if is_changed {
                            sum.with_set.insert(c_idx);
                        }
                    }
                    TermAccessMode::OptionalWrite => {
                        sum.writes.insert(c_idx);
                        if is_changed {
                            sum.with_set.insert(c_idx);
                        }
                    }
                    TermAccessMode::StreamRead | TermAccessMode::ResRead => {
                        sum.reads.insert(c_idx);
                    }
                    TermAccessMode::StreamWrite | TermAccessMode::ResWrite => {
                        sum.writes.insert(c_idx);
                    }
                    TermAccessMode::Allow | TermAccessMode::Has | TermAccessMode::RemovedRead => {}
                }
            }
            for w in &qb.with_filters {
                if let Some(c_idx) = self.find_comp_idx(w) {
                    sum.with_set.insert(c_idx);
                }
            }
            for wo in &qb.without_filters {
                if let Some(c_idx) = self.find_comp_idx(wo) {
                    sum.without_set.insert(c_idx);
                }
            }
            if let Some(qdesc) = f.queries.get(qb.query_idx as usize) {
                for cf in &qdesc.changed_filters {
                    if let Some(c_idx) = self.find_comp_idx(cf) {
                        sum.with_set.insert(c_idx);
                        if !sum.writes.contains(&c_idx) {
                            sum.reads.insert(c_idx);
                        }
                    }
                }
            }
            summaries.push(sum);
        }

        let mut adj = vec![Vec::new(); n];
        for i in 0..n {
            for j in (i + 1)..n {
                let a = &summaries[i];
                let b = &summaries[j];
                if !a.with_set.is_disjoint(&b.without_set)
                    || !b.with_set.is_disjoint(&a.without_set)
                {
                    continue;
                }
                if !a.writes.is_disjoint(&b.reads)
                    || !a.writes.is_disjoint(&b.writes)
                    || !b.writes.is_disjoint(&a.reads)
                {
                    adj[i].push(j);
                    adj[j].push(i);
                }
            }
        }

        let mut groups = vec![0u32; n];
        let mut visited = vec![false; n];
        let mut next_group = 1u32;
        for start in 0..n {
            if visited[start] || adj[start].is_empty() {
                visited[start] = true;
                continue;
            }
            let mut comp = Vec::new();
            let mut queue = VecDeque::new();
            visited[start] = true;
            queue.push_back(start);
            while let Some(u) = queue.pop_front() {
                comp.push(u);
                for &v in &adj[u] {
                    if !visited[v] {
                        visited[v] = true;
                        queue.push_back(v);
                    }
                }
            }
            if comp.len() >= 2 {
                for u in comp {
                    groups[u] = next_group;
                }
                next_group += 1;
            }
        }
        groups
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

    fn find_spatial_name(&self, func: &MirFunction, key: &str) -> Option<String> {
        let short = short_name(key);
        if let Some(sp) = self
            .mir
            .spatial_indices
            .iter()
            .find(|sp| sp.name == key || sp.name == short)
        {
            return Some(sp.name.clone());
        }
        for rb in &func.resources {
            if (rb.param_name == key || rb.resource_name == key || rb.canonical_name == key)
                && let Some(sp) = self
                    .mir
                    .spatial_indices
                    .iter()
                    .find(|sp| sp.name == rb.resource_name)
            {
                return Some(sp.name.clone());
            }
        }
        self.mir
            .spatial_indices
            .iter()
            .find(|sp| {
                sp.resource_layout.canonical_name == key
                    || short_name(&sp.resource_layout.canonical_name) == short
            })
            .map(|sp| sp.name.clone())
    }

    pub(super) fn compute_dedup_query_terms(
        &self,
        f: &MirFunction,
        qb: &MirQueryBinding,
        err_ctx: &str,
    ) -> Result<DedupQueryTerms, CodegenError> {
        #[derive(Clone, Copy)]
        struct AccEntry {
            c_idx: usize,
            mode: TermAccessMode,
            is_changed: bool,
            is_added: bool,
            seen_count: usize,
        }

        let mut entries: Vec<AccEntry> = Vec::new();
        let mut comp_to_pos: HashMap<usize, usize> = HashMap::new();
        let mut remap: HashMap<u32, u32> = HashMap::new();
        let mut stream_comps: HashSet<usize> = HashSet::new();

        for term in &qb.terms {
            let c_idx = self
                .find_comp_idx(&term.canonical_component)
                .ok_or_else(|| CodegenError::Unsupported {
                    context: err_ctx.to_owned(),
                    detail: format!(
                        "missing component `{}` in query {}",
                        term.canonical_component, qb.query_idx
                    ),
                })?;
            if matches!(
                term.mode,
                TermAccessMode::StreamRead | TermAccessMode::StreamWrite
            ) {
                stream_comps.insert(c_idx);
            }
            let is_changed = f.changed_terms.iter().any(|ct| {
                ct.query_idx == qb.query_idx
                    && (ct.term_idx == term.term_idx
                        || ct.canonical_component == term.canonical_component)
            });
            let is_added = f.added_terms.iter().any(|at| {
                at.query_idx == qb.query_idx
                    && (at.term_idx == term.term_idx
                        || at.canonical_component == term.canonical_component)
            });
            if let Some(&pos) = comp_to_pos.get(&c_idx) {
                let entry = &mut entries[pos];
                entry.mode = merge_term_access_mode(entry.mode, term.mode);
                entry.is_changed |= is_changed;
                entry.is_added |= is_added;
                entry.seen_count += 1;
                remap.insert(term.term_idx, pos as u32);
            } else {
                let pos = entries.len();
                comp_to_pos.insert(c_idx, pos);
                entries.push(AccEntry {
                    c_idx,
                    mode: term.mode,
                    is_changed,
                    is_added,
                    seen_count: 1,
                });
                remap.insert(term.term_idx, pos as u32);
            }
        }

        let mut terms = Vec::with_capacity(entries.len());
        let mut aliased_dedup_indices = HashSet::new();
        let mut extra_changed = Vec::new();
        let mut extra_added = Vec::new();

        for (pos, e) in entries.iter().enumerate() {
            if e.seen_count > 1 {
                aliased_dedup_indices.insert(pos as u32);
            }
            let (mode_c, flags_c) = if e.is_added {
                if e.is_changed {
                    (
                        c_access_mode(e.mode),
                        "BAM_TERM_FLAG_CHANGED | BAM_TERM_FLAG_ADDED",
                    )
                } else {
                    (c_access_mode(e.mode), "BAM_TERM_FLAG_ADDED")
                }
            } else if e.is_changed && e.mode == TermAccessMode::Read {
                ("BAM_ACCESS_CHANGED", "0u")
            } else {
                if e.is_changed && !extra_changed.contains(&e.c_idx) {
                    extra_changed.push(e.c_idx);
                }
                (c_access_mode(e.mode), "0u")
            };
            terms.push((e.c_idx, mode_c, flags_c));
        }

        if let Some(qdesc) = f.queries.get(qb.query_idx as usize) {
            for cf in &qdesc.changed_filters {
                if let Some(c_idx) = self.find_comp_idx(cf)
                    && !comp_to_pos.contains_key(&c_idx)
                    && !extra_changed.contains(&c_idx)
                {
                    extra_changed.push(c_idx);
                }
            }
        }
        for (qi, af) in &f.added_filters {
            if *qi == qb.query_idx
                && let Some(c_idx) = self.find_comp_idx(af)
                && !comp_to_pos.contains_key(&c_idx)
                && !extra_added.contains(&c_idx)
            {
                extra_added.push(c_idx);
            }
        }

        Ok(DedupQueryTerms {
            terms,
            extra_changed,
            extra_added,
            remap,
            aliased_dedup_indices,
            stream_comps,
        })
    }

    pub(super) fn resolve_helper_param_tys(&self, f: &MirFunction) -> Vec<MirType> {
        let mut out: Vec<MirType> = f.params.iter().map(|p| p.ty.clone()).collect();
        if !matches!(f.kind, MirFnKind::HelperFn) {
            return out;
        }
        let all_fns = self.mir_functions();
        for (pi, p) in f.params.iter().enumerate() {
            if !matches!(p.ty, MirType::Ptr | MirType::MutPtr) {
                continue;
            }
            if p.layout_key
                .as_deref()
                .and_then(|k| self.find_layout_idx(k))
                .is_some()
            {
                continue;
            }
            let Some(ploc) = p.local else {
                continue;
            };
            let used_as_ptr = f.blocks.iter().any(|bb| {
                bb.stmts.iter().any(|st| match &st.inst {
                    Inst::FieldPtr { base_ptr, .. }
                    | Inst::FieldLoad { base_ptr, .. }
                    | Inst::FieldStore { base_ptr, .. }
                    | Inst::ArrayStore { base_ptr, .. } => *base_ptr == ploc,
                    Inst::ArrayIndex { base, .. } => *base == ploc,
                    Inst::BitSetGet { ptr, .. }
                    | Inst::BitSetSet { ptr, .. }
                    | Inst::BitSetClear { ptr, .. }
                    | Inst::GraceArm { ptr, .. }
                    | Inst::GraceClear { ptr, .. }
                    | Inst::GraceIsActive { ptr, .. }
                    | Inst::GraceTick { ptr, .. }
                    | Inst::InputBufPush { ptr, .. }
                    | Inst::InputBufConsume { ptr, .. }
                    | Inst::InputBufPeek { ptr, .. }
                    | Inst::InputBufTick { ptr, .. }
                    | Inst::TimelineInWindow { ptr, .. } => *ptr == ploc,
                    Inst::TimelineAdvance { cursor_ptr, .. } => *cursor_ptr == ploc,
                    _ => false,
                })
            });
            if used_as_ptr {
                continue;
            }
            let mut inferred: Option<MirType> = None;
            for caller in all_fns {
                for bb in &caller.blocks {
                    for st in &bb.stmts {
                        if let Inst::Call { callee, args } = &st.inst
                            && (callee == &f.name || short_name(callee) == short_name(&f.name))
                            && let Some(&arg_id) = args.get(pi)
                            && let Some(arg_loc) = caller.locals.iter().find(|l| l.id == arg_id)
                            && !matches!(arg_loc.ty, MirType::Ptr | MirType::MutPtr | MirType::Unit)
                        {
                            inferred = Some(arg_loc.ty.clone());
                            break;
                        }
                    }
                    if inferred.is_some() {
                        break;
                    }
                }
                if inferred.is_some() {
                    break;
                }
            }
            if inferred.is_none() {
                for bb in &f.blocks {
                    for st in &bb.stmts {
                        if let Inst::BinOp { lhs, rhs, .. } = &st.inst {
                            let peer = if *lhs == ploc {
                                Some(*rhs)
                            } else if *rhs == ploc {
                                Some(*lhs)
                            } else {
                                None
                            };
                            if let Some(pid) = peer
                                && let Some(pl) = f.locals.iter().find(|l| l.id == pid)
                                && !matches!(pl.ty, MirType::Ptr | MirType::MutPtr | MirType::Unit)
                            {
                                inferred = Some(pl.ty.clone());
                                break;
                            }
                        }
                    }
                    if inferred.is_some() {
                        break;
                    }
                }
            }
            if inferred.is_none() {
                for bb in &f.blocks {
                    if let Terminator::Return(Some(rid)) = &bb.terminator
                        && *rid == ploc
                        && !matches!(f.ret_ty, MirType::Ptr | MirType::MutPtr | MirType::Unit)
                    {
                        inferred = Some(f.ret_ty.clone());
                        break;
                    }
                }
            }
            if let Some(ty) = inferred {
                out[pi] = ty;
            }
        }
        out
    }

    fn collect_schedules_and_systems(&mut self) -> Result<(), CodegenError> {
        let mut sys_in_sets: HashMap<String, Vec<String>> = HashMap::new();
        let mut sys_mount_sets: HashMap<String, Vec<usize>> = HashMap::new();
        let mut sys_after: HashMap<String, Vec<String>> = HashMap::new();
        let mut sys_after_weak: HashMap<String, Vec<String>> = HashMap::new();
        let mut sys_before: HashMap<String, Vec<String>> = HashMap::new();
        let mut sys_sched_order: HashMap<String, usize> = HashMap::new();
        let mut set_index_map: HashMap<(&'static str, String), usize> = HashMap::new();
        let mut set_seq_counter = 0usize;
        let mut leaf_order = 0usize;

        for sched in &self.mir.schedules {
            let sched_c = c_schedule_const(&sched.label);
            let mut parent_sets: Vec<(usize, String)> = Vec::new();
            for node in &sched.nodes {
                let (_leaves, _cur_set_idx) = self.walk_schedule_node(
                    node,
                    sched_c,
                    &mut parent_sets,
                    &mut set_index_map,
                    &mut set_seq_counter,
                    &mut leaf_order,
                    &mut sys_in_sets,
                    &mut sys_mount_sets,
                    &mut sys_after,
                    &mut sys_after_weak,
                    &mut sys_before,
                    &mut sys_sched_order,
                );
            }
        }

        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        let mut timer_tick_reg_name: Option<String> = None;
        for f in &fns_snapshot {
            if matches!(f.kind, MirFnKind::SynthesizedTimerTick) {
                timer_tick_reg_name = Some(short_name(&f.name).to_string());
                break;
            }
        }

        let rep_count = self
            .mir
            .net_components
            .iter()
            .filter(|nc| nc.is_replicated)
            .count();
        let net_chunk_count = if has_net_protocol(self.mir) && rep_count > 0 {
            let max_per_sys = MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
            rep_count.div_ceil(max_per_sys)
        } else {
            0
        };

        let mut startup_obj_names: Vec<String> = Vec::new();
        if !self.mir.objects.is_empty() {
            let obj_total = self.mir.objects.len();
            let obj_chunk_sz = MAX_QUERIES_PER_SYSTEM.max(1);
            let obj_chunks = obj_total.div_ceil(obj_chunk_sz);
            for chunk_idx in 0..obj_chunks {
                let start = chunk_idx * obj_chunk_sz;
                let end = (start + obj_chunk_sz).min(obj_total);
                let (c_fn_name, reg_name) = if obj_chunks == 1 {
                    (
                        "strata_sys_startup_objects".to_string(),
                        "__strata_startup_objects".to_string(),
                    )
                } else {
                    (
                        format!("strata_sys_startup_objects_{chunk_idx}"),
                        format!("__strata_startup_objects_{chunk_idx}"),
                    )
                };
                let mut after_names = Vec::new();
                if let Some(prev_name) = startup_obj_names.last() {
                    after_names.push(prev_name.clone());
                }
                startup_obj_names.push(reg_name.clone());
                let idx = self.systems.len();
                self.systems.push(RegSystem {
                    idx,
                    mir_fn_idx: None,
                    c_fn_name,
                    reg_name,
                    schedule: "BAM_SCHEDULE_STARTUP",
                    flags_expr: "BAM_SYSTEM_FLAG_MAIN_THREAD".to_string(),
                    after_names,
                    after_weak_names: Vec::new(),
                    before_names: Vec::new(),
                    in_sets: Vec::new(),
                    mount_set_indices: Vec::new(),
                    sched_order: chunk_idx,
                    run_if_fn: None,
                    run_if_resources: Vec::new(),
                    startup_obj_range: Some((start, end)),
                });
            }
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
                    let reg_name = short_name(&f.name).to_string();
                    let c_fn_name = format!("strata_sys_{}", sanitize_ident(&f.name));
                    let mut after_names = sys_after
                        .remove(&reg_name)
                        .or_else(|| sys_after.remove(&f.name))
                        .unwrap_or_default();
                    let after_weak_list = sys_after_weak
                        .remove(&reg_name)
                        .or_else(|| sys_after_weak.remove(&f.name))
                        .unwrap_or_default();
                    let before_names = sys_before
                        .remove(&reg_name)
                        .or_else(|| sys_before.remove(&f.name))
                        .unwrap_or_default();
                    if !is_timer_tick
                        && sched_c == "BAM_SCHEDULE_FIXED_UPDATE"
                        && let Some(ref tt_name) = timer_tick_reg_name
                        && !after_names.contains(tt_name)
                    {
                        after_names.push(tt_name.clone());
                    }
                    if sched_c == "BAM_SCHEDULE_STARTUP" {
                        for st_name in &startup_obj_names {
                            if !after_names.contains(st_name) {
                                after_names.push(st_name.clone());
                            }
                        }
                    }
                    let mut after_weak_names = after_weak_list;
                    if sched_c == "BAM_SCHEDULE_FIXED_UPDATE" && net_chunk_count > 0 {
                        for chunk_idx in 0..net_chunk_count {
                            let rx_name = format!("__strata_net_rx_{chunk_idx}");
                            if !after_weak_names.contains(&rx_name) {
                                after_weak_names.push(rx_name);
                            }
                        }
                    }
                    let in_sets = sys_in_sets
                        .remove(&reg_name)
                        .or_else(|| sys_in_sets.remove(&f.name))
                        .unwrap_or_default();
                    let mount_set_indices = sys_mount_sets
                        .remove(&reg_name)
                        .or_else(|| sys_mount_sets.remove(&f.name))
                        .unwrap_or_default();
                    let sched_order = sys_sched_order
                        .get(&reg_name)
                        .or_else(|| sys_sched_order.get(&f.name))
                        .copied()
                        .unwrap_or(usize::MAX);
                    let run_if_fn = self.schedule_run_if_for(sched_label, &f.name, &f.kind, fn_idx);
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
                        after_weak_names,
                        before_names,
                        in_sets,
                        mount_set_indices,
                        sched_order,
                        run_if_fn: run_if_name,
                        run_if_resources,
                        startup_obj_range: None,
                    });
                }
                MirFnKind::Observer { event, target_comp } => {
                    let event_comp_idx =
                        self.find_comp_idx(event)
                            .ok_or_else(|| CodegenError::Unsupported {
                                context: format!("c99::observer({})", f.name),
                                detail: format!("unregistered trigger event `{event}`"),
                            })?;
                    let target_comp_idx =
                        target_comp.as_deref().and_then(|tc| self.find_comp_idx(tc));
                    let obs_idx = self.observers.len();
                    self.observers.push(RegObserver {
                        obs_idx,
                        mir_fn_idx: fn_idx,
                        c_fn_name: format!("strata_obs_{}", sanitize_ident(&f.name)),
                        reg_name: short_name(&f.name).to_string(),
                        event_comp_idx,
                        target_comp_idx,
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
        fn_name: &str,
        fn_kind: &MirFnKind,
        sys_idx: usize,
    ) -> Option<(String, Vec<usize>)> {
        let is_synth = matches!(
            fn_kind,
            MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick
        );
        let sched = self
            .mir
            .schedules
            .iter()
            .find(|s| {
                s.label.eq_ignore_ascii_case(sched_label)
                    && c99_schedule_nodes_contain(&s.nodes, fn_name)
            })
            .or_else(|| {
                is_synth.then(|| {
                    self.mir
                        .schedules
                        .iter()
                        .find(|s| s.label.eq_ignore_ascii_case(sched_label))
                })?
            })?;
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
        if res_indices.is_empty() {
            let _ = writeln!(body, "    (void)sys_ctx; (void)state;");
        } else {
            let _ = writeln!(body, "    if (state == NULL || state->api == NULL) {{");
            let _ = writeln!(body, "        return BAM_RESULT_OK;");
            let _ = writeln!(body, "    }}");
        }
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
        if s == "false" {
            return "BAM_FALSE".to_string();
        }
        if s == "true" {
            return "BAM_TRUE".to_string();
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

    #[allow(clippy::too_many_arguments)]
    fn walk_schedule_node(
        &mut self,
        node: &HirScheduleGroup,
        sched_c: &'static str,
        parent_sets: &mut Vec<(usize, String)>,
        set_index_map: &mut HashMap<(&'static str, String), usize>,
        set_seq_counter: &mut usize,
        leaf_order: &mut usize,
        sys_in_sets: &mut HashMap<String, Vec<String>>,
        sys_mount_sets: &mut HashMap<String, Vec<usize>>,
        sys_after: &mut HashMap<String, Vec<String>>,
        sys_after_weak: &mut HashMap<String, Vec<String>>,
        sys_before: &mut HashMap<String, Vec<String>>,
        sys_sched_order: &mut HashMap<String, usize>,
    ) -> (Vec<String>, Option<usize>) {
        let push_uniq_s = |map: &mut HashMap<String, Vec<String>>, key: &str, val: String| {
            let list = map.entry(key.to_string()).or_default();
            if !list.contains(&val) {
                list.push(val);
            }
        };
        match node.kind.as_str() {
            "leaf" if !node.name.is_empty() => {
                let leaf_name = short_name(&node.name).to_string();
                sys_sched_order.entry(leaf_name.clone()).or_insert_with(|| {
                    let o = *leaf_order;
                    *leaf_order += 1;
                    o
                });
                for (_, ps_name) in parent_sets.iter() {
                    push_uniq_s(sys_in_sets, &leaf_name, ps_name.clone());
                }
                if let Some(&(set_idx, _)) = parent_sets.last() {
                    let mlist = sys_mount_sets.entry(leaf_name.clone()).or_default();
                    if !mlist.contains(&set_idx) {
                        mlist.push(set_idx);
                    }
                }
                for a in &node.after {
                    push_uniq_s(sys_after, &leaf_name, short_name(a).to_string());
                }
                for b in &node.before {
                    push_uniq_s(sys_before, &leaf_name, short_name(b).to_string());
                }
                (vec![leaf_name], None)
            }
            kind @ ("seq" | "seq_weak" | "par" | "set") => {
                let set_name = if node.name.is_empty() {
                    *set_seq_counter += 1;
                    format!("__group_{set_seq_counter}")
                } else {
                    short_name(&node.name).to_string()
                };
                let key = (sched_c, set_name.clone());
                let own_set_idx = if let Some(&existing) = set_index_map.get(&key) {
                    existing
                } else {
                    let flags_expr = match kind {
                        "seq" => "BAM_SCHEDULE_SET_FLAG_SEQUENCE",
                        "seq_weak" => "BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK",
                        _ => "BAM_SCHEDULE_SET_FLAG_PARALLEL",
                    };
                    let idx = self.sets.len();
                    self.sets.push(RegScheduleSet {
                        idx,
                        name: set_name.clone(),
                        schedule: sched_c,
                        flags_expr,
                        after_sets: Vec::new(),
                    });
                    set_index_map.insert(key, idx);
                    idx
                };
                parent_sets.push((own_set_idx, set_name));
                let is_seq = kind == "seq";
                let is_seq_weak = kind == "seq_weak";
                let mut prev_leaves: Vec<String> = Vec::new();
                let mut prev_set_idx: Option<usize> = None;
                let mut all_leaves: Vec<String> = Vec::new();
                for child in &node.children {
                    let (leaves, cur_set_idx) = self.walk_schedule_node(
                        child,
                        sched_c,
                        parent_sets,
                        set_index_map,
                        set_seq_counter,
                        leaf_order,
                        sys_in_sets,
                        sys_mount_sets,
                        sys_after,
                        sys_after_weak,
                        sys_before,
                        sys_sched_order,
                    );
                    if is_seq || is_seq_weak {
                        if let (Some(p_s), Some(c_s)) = (prev_set_idx, cur_set_idx)
                            && p_s != c_s
                            && !self.sets[c_s].after_sets.contains(&p_s)
                        {
                            self.sets[c_s].after_sets.push(p_s);
                        }
                        for l in &leaves {
                            for pl in &prev_leaves {
                                if pl != l {
                                    if is_seq {
                                        push_uniq_s(sys_after, l, pl.clone());
                                    } else {
                                        push_uniq_s(sys_after_weak, l, pl.clone());
                                    }
                                }
                            }
                        }
                    }
                    if !leaves.is_empty() {
                        prev_leaves = leaves.clone();
                    }
                    if cur_set_idx.is_some() {
                        prev_set_idx = cur_set_idx;
                    } else if !leaves.is_empty() {
                        prev_set_idx = None;
                    }
                    all_leaves.extend(leaves);
                }
                parent_sets.pop();
                for a in &node.after {
                    let a_short = short_name(a).to_string();
                    if let Some(&a_idx) = set_index_map.get(&(sched_c, a_short.clone()))
                        && a_idx != own_set_idx
                        && !self.sets[own_set_idx].after_sets.contains(&a_idx)
                    {
                        self.sets[own_set_idx].after_sets.push(a_idx);
                    }
                    for l in &all_leaves {
                        push_uniq_s(sys_after, l, a_short.clone());
                    }
                }
                for b in &node.before {
                    let b_short = short_name(b).to_string();
                    for l in &all_leaves {
                        push_uniq_s(sys_before, l, b_short.clone());
                    }
                }
                (all_leaves, Some(own_set_idx))
            }
            _ => {
                let mut all_leaves = Vec::new();
                for child in &node.children {
                    let (leaves, _) = self.walk_schedule_node(
                        child,
                        sched_c,
                        parent_sets,
                        set_index_map,
                        set_seq_counter,
                        leaf_order,
                        sys_in_sets,
                        sys_mount_sets,
                        sys_after,
                        sys_after_weak,
                        sys_before,
                        sys_sched_order,
                    );
                    all_leaves.extend(leaves);
                }
                (all_leaves, None)
            }
        }
    }

    fn collect_composite_types(&mut self) {
        let mut roots: Vec<MirType> = Vec::new();
        for f in self.mir_functions() {
            for l in &f.locals {
                roots.push(l.ty.clone());
            }
            for p in &f.params {
                roots.push(p.ty.clone());
            }
            roots.push(f.ret_ty.clone());
            for bb in &f.blocks {
                for st in &bb.stmts {
                    match &st.inst {
                        Inst::SlotAlloc { ty } => roots.push(ty.clone()),
                        Inst::FieldLoad { field_ty, .. } => roots.push(field_ty.clone()),
                        Inst::ArrayStore { elem_ty, .. } => roots.push(elem_ty.clone()),
                        _ => {}
                    }
                }
            }
        }
        let sema_roots: Vec<Ty> = self
            .mir
            .tables
            .iter()
            .flat_map(|t| t.fields.iter().map(|(_, ty)| ty.clone()))
            .chain(self.layouts.iter().flat_map(|l| {
                l.fields
                    .iter()
                    .filter(|f| !f.is_padding)
                    .map(|f| f.ty.clone())
            }))
            .chain(self.mir.consts.iter().map(|c| c.ty.clone()))
            .collect();
        for ty in &sema_roots {
            self.register_sema_composite_type(ty);
        }
        for ty in &roots {
            self.register_composite_type(ty);
        }
    }

    fn sema_to_mir_storage_ty(ty: &Ty) -> MirType {
        match ty {
            Ty::Bool => MirType::Bool,
            Ty::I8 => MirType::I8,
            Ty::I16 => MirType::I16,
            Ty::I32 => MirType::I32,
            Ty::I64 => MirType::I64,
            Ty::U8 => MirType::U8,
            Ty::U16 => MirType::U16,
            Ty::U32 | Ty::Sym | Ty::Rgba8 => MirType::U32,
            Ty::U64 => MirType::U64,
            Ty::Fix32 => MirType::Fix32,
            Ty::Fix64 => MirType::Fix64,
            Ty::F32 | Ty::UnitScalar { .. } => MirType::F32,
            Ty::F64 => MirType::F64,
            Ty::GraceWindow => MirType::Named("GraceWindow".to_owned()),
            Ty::Vec2 => MirType::Vec2,
            Ty::Vec3 => MirType::Vec3,
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => MirType::Vec4,
            Ty::IVec2 => MirType::IVec2,
            Ty::IVec3 => MirType::IVec3,
            Ty::UVec2 => MirType::UVec2,
            Ty::Mat3 => MirType::Named("mat3".to_owned()),
            Ty::Mat4 => MirType::Named("mat4".to_owned()),
            Ty::Ref(_) => MirType::Entity,
            Ty::BitSet(bits) => MirType::Named(format!("BitSet<{bits}>")),
            Ty::InlineStr(cap) => MirType::Named(format!("InlineStr<{cap}>")),
            Ty::InputBuffer { action, cap } => {
                MirType::Named(format!("InputBuffer<{action},{cap}>"))
            }
            Ty::SmallVec { elem, cap } => MirType::Named(format!("SmallVec<{elem:?},{cap}>")),
            Ty::Array { elem, len } => MirType::Array {
                elem: Box::new(Self::sema_to_mir_storage_ty(elem)),
                len: *len,
            },
            Ty::Tuple(items) => {
                MirType::Tuple(items.iter().map(Self::sema_to_mir_storage_ty).collect())
            }
            Ty::Named(n) => MirType::Named(n.clone()),
            _ => MirType::Unit,
        }
    }

    fn register_sema_composite_type(&mut self, ty: &Ty) {
        if let Some((sz, _)) = self.sema_ty_size_align(ty)
            && matches!(
                ty,
                Ty::BitSet(_) | Ty::InlineStr(_) | Ty::InputBuffer { .. } | Ty::SmallVec { .. }
            )
        {
            self.raw_pod_sizes.insert(sz.max(1));
        }
        match ty {
            Ty::Array { elem, .. } => {
                self.register_sema_composite_type(elem);
                let mty = Self::sema_to_mir_storage_ty(ty);
                self.register_composite_type(&mty);
            }
            Ty::SmallVec { elem, .. } => {
                self.register_sema_composite_type(elem);
            }
            Ty::Tuple(items) => {
                for it in items {
                    self.register_sema_composite_type(it);
                }
                let mty = Self::sema_to_mir_storage_ty(ty);
                self.register_composite_type(&mty);
            }
            _ => {}
        }
    }

    fn register_composite_type(&mut self, ty: &MirType) {
        match ty {
            MirType::Named(key) => {
                if let Some(sz) = self.named_mir_pod_bytes(key) {
                    self.raw_pod_sizes.insert(sz.max(1));
                }
            }
            MirType::Tuple(elems) => {
                if self.tuple_types.iter().any(|(e, _)| e == elems) {
                    return;
                }
                for e in elems {
                    self.register_composite_type(e);
                }
                let id = self.tuple_types.len();
                self.tuple_types
                    .push((elems.clone(), format!("StrataTuple_{id}")));
                self.composite_order.push(CompositeDecl::Tuple(id));
            }
            MirType::Array { elem, len } => {
                let elem_ty = (**elem).clone();
                self.register_composite_type(&elem_ty);
                if self
                    .array_types
                    .iter()
                    .any(|(e, l, _)| *e == elem_ty && *l == *len)
                {
                    return;
                }
                let id = self.array_types.len();
                self.array_types
                    .push((elem_ty, *len, format!("StrataArray_{id}")));
                self.composite_order.push(CompositeDecl::Array(id));
            }
            _ => {}
        }
    }

    fn parse_smallvec_mir_key(&self, key: &str) -> Option<(Ty, usize)> {
        let inner = key.strip_prefix("SmallVec<")?.strip_suffix('>')?;
        let (elem_dbg, cap_s) = inner.rsplit_once(',')?;
        let cap = cap_s.trim().parse::<usize>().ok()?;
        let elem = parse_mir_debug_ty(elem_dbg.trim())?;
        Some((elem, cap))
    }

    fn named_mir_pod_bytes(&self, key: &str) -> Option<usize> {
        if let Some(rest) = key
            .strip_prefix("BitSet<")
            .and_then(|s| s.strip_suffix('>'))
        {
            let bits = rest.trim().parse::<usize>().ok()?;
            return Some(bits.div_ceil(32).max(1) * 4);
        }
        if let Some(rest) = key
            .strip_prefix("InlineStr<")
            .and_then(|s| s.strip_suffix('>'))
        {
            let cap = rest.trim().parse::<usize>().ok()?;
            return Some(4 + cap.div_ceil(4) * 4);
        }
        if let Some(rest) = key
            .strip_prefix("InputBuffer<")
            .and_then(|s| s.strip_suffix('>'))
            && let Some((_, cap_s)) = rest.rsplit_once(',')
        {
            let cap = cap_s.trim().parse::<usize>().ok()?;
            return Some(cap.max(1) * 8);
        }
        if let Some((elem, cap)) = self.parse_smallvec_mir_key(key) {
            return self
                .sema_ty_size_align(&Ty::SmallVec {
                    elem: Box::new(elem),
                    cap,
                })
                .map(|(s, _)| s.max(1));
        }
        None
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
        if has_net_protocol(self.mir) {
            self.emit_net_protocol_and_codecs()?;
        }
        self.emit_defaults()?;
        self.emit_rodata_tables_and_curves()?;
        self.emit_state_struct_and_forward_decls();
        for w in &self.run_if_wrappers.clone() {
            self.out.push_str(w);
            self.out.push('\n');
        }
        self.emit_functions()?;
        if has_net_protocol(self.mir) {
            self.emit_net_synthesized_systems();
        }
        self.emit_startup_objects_fn()?;
        self.emit_manifest_init_shutdown()?;
        Ok(())
    }

    fn is_aggregate_mir_ty(&self, ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::Vec2
                | MirType::Vec3
                | MirType::Vec4
                | MirType::IVec2
                | MirType::IVec3
                | MirType::UVec2
                | MirType::Array { .. }
                | MirType::Tuple(_)
        ) || matches!(
            ty,
            MirType::Named(k) if k.starts_with("__strata_table_")
                || self.find_layout_idx(k).is_some()
                || self.named_mir_pod_bytes(k).is_some()
                || matches!(k.as_str(), "mat3" | "Mat3" | "mat4" | "Mat4")
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
            MirType::IVec2 => "StrataIVec2".to_string(),
            MirType::IVec3 => "StrataIVec3".to_string(),
            MirType::UVec2 => "StrataUVec2".to_string(),
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
                } else if let Some(et) = self.c_enum_ty(key) {
                    et.to_string()
                } else if let Some(l_idx) = self.find_layout_idx(key) {
                    self.layout_c_names[l_idx].clone()
                } else if key == "InlineStr" {
                    "const char*".to_string()
                } else if key == "GraceWindow" {
                    "float".to_string()
                } else if matches!(key.as_str(), "mat3" | "Mat3") {
                    "StrataMat3".to_string()
                } else if matches!(key.as_str(), "mat4" | "Mat4") {
                    "StrataMat4".to_string()
                } else if let Some(sz) = self.named_mir_pod_bytes(key) {
                    format!("StrataBytes_{sz}")
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
                } else if let Some(t) = self.mir.tables.iter().find(|tb| tb.name == *key) {
                    format!("StrataTable_{}", sanitize_ident(&t.name))
                } else {
                    "int32_t".to_string()
                }
            }
        }
    }

    fn c_enum_ty(&self, key: &str) -> Option<&'static str> {
        let seg = short_name(key);
        self.mir
            .enums
            .iter()
            .find(|e| e.canonical_name == key || short_name(&e.canonical_name) == seg)
            .map(|e| match (e.repr_bytes, e.is_signed) {
                (1, _) => "uint8_t",
                (2, _) => "uint16_t",
                (_, true) => "int32_t",
                _ => "uint32_t",
            })
    }

    fn c_ty_from_sema(&self, ty: &Ty) -> String {
        match ty {
            Ty::Unit | Ty::U8 | Ty::Bool => "uint8_t".to_string(),
            Ty::I8 => "int8_t".to_string(),
            Ty::I16 => "int16_t".to_string(),
            Ty::I64 | Ty::Fix64 => "int64_t".to_string(),
            Ty::U16 => "uint16_t".to_string(),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => "uint32_t".to_string(),
            Ty::U64 => "uint64_t".to_string(),
            Ty::BitSet(bits) => {
                let sz = (*bits).div_ceil(32).max(1) * 4;
                format!("StrataBytes_{sz}")
            }
            Ty::InlineStr(cap) => {
                let sz = 4 + cap.div_ceil(4) * 4;
                format!("StrataBytes_{sz}")
            }
            Ty::InputBuffer { .. } | Ty::SmallVec { .. } => self
                .sema_ty_size_align(ty)
                .map(|(s, _)| format!("StrataBytes_{}", s.max(1)))
                .unwrap_or_else(|| "int32_t".to_string()),
            Ty::Array { elem, len } => {
                let m = Self::sema_to_mir_storage_ty(elem);
                if let Some(n) = self.array_name(&m, *len) {
                    n.to_string()
                } else {
                    self.sema_ty_size_align(ty)
                        .map(|(s, _)| format!("StrataBytes_{}", s.max(1)))
                        .unwrap_or_else(|| "int32_t".to_string())
                }
            }
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "float".to_string(),
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
                if let Some(et) = self.c_enum_ty(key) {
                    et.to_string()
                } else if let Some(l_idx) = self.find_layout_idx(key) {
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
            MirType::IVec2 => "strata_ivec2(0, 0)".to_string(),
            MirType::IVec3 => "strata_ivec3(0, 0, 0)".to_string(),
            MirType::UVec2 => "strata_uvec2(0u, 0u)".to_string(),
            MirType::Named(k) if k == "InlineStr" => "\"\"".to_string(),
            MirType::Named(k) if k == "GraceWindow" => "0.0f".to_string(),
            MirType::Named(k) if matches!(k.as_str(), "mat3" | "Mat3") => {
                "((StrataMat3){ { 0.0f } })".to_string()
            }
            MirType::Named(k) if matches!(k.as_str(), "mat4" | "Mat4") => {
                "((StrataMat4){ { 0.0f } })".to_string()
            }
            MirType::Named(k) if self.named_mir_pod_bytes(k).is_some() => {
                let sz = self.named_mir_pod_bytes(k).unwrap_or(4);
                format!("((StrataBytes_{sz}){{ {{ 0 }} }})")
            }
            MirType::Named(k) if self.find_layout_idx(k).is_none() => "0".to_string(),
            _ => "{ 0 }".to_string(),
        }
    }

    fn c_zero_for_sema(&self, ty: &Ty) -> String {
        match ty {
            Ty::Bool | Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => "0u".to_string(),
            Ty::U64 => "0ull".to_string(),
            Ty::BitSet(_)
            | Ty::InlineStr(_)
            | Ty::InputBuffer { .. }
            | Ty::SmallVec { .. }
            | Ty::Array { .. } => {
                let cty = self.c_ty_from_sema(ty);
                format!("(({cty}){{ {{ 0 }} }})")
            }
            Ty::I64 | Ty::Fix64 => "0ll".to_string(),
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "0.0f".to_string(),
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
            Ty::Mat3 => "((StrataMat3){ { 0.0f } })".to_string(),
            Ty::Mat4 => "((StrataMat4){ { 0.0f } })".to_string(),
            Ty::Named(key) if self.find_layout_idx(key).is_some() => {
                let cty = self.c_ty_from_sema(ty);
                format!("(({cty}){{ 0 }})")
            }
            _ => "0".to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_c_field_default_init(
        &self,
        buf: &mut String,
        indent: &str,
        target: &str,
        ty: &Ty,
        f_size: usize,
        val_opt: Option<&MirConstVal>,
        zero_missing_array_elems: bool,
    ) {
        match ty {
            Ty::BitSet(bits) => {
                let byte_len = f_size.max((*bits).div_ceil(32).max(1) * 4);
                if let Some(val) = val_opt {
                    let packed = pack_bitset_bytes(val, byte_len);
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                    if packed.iter().any(|&b| b != 0) {
                        let bytes_c: Vec<String> =
                            packed.iter().map(|b| format!("0x{b:02X}u")).collect();
                        let _ = writeln!(
                            buf,
                            "{indent}{{ uint8_t _bs[{byte_len}] = {{ {} }}; size_t _n = sizeof({target}) < sizeof(_bs) ? sizeof({target}) : sizeof(_bs); memcpy({target}, _bs, _n); }}",
                            bytes_c.join(", ")
                        );
                    }
                } else if zero_missing_array_elems {
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                }
            }
            Ty::Array { .. } => {
                let elems_opt = val_opt.and_then(|v| {
                    if let MirConstVal::Array(es) = v {
                        Some(es.as_slice())
                    } else {
                        None
                    }
                });
                if zero_missing_array_elems {
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                }
                self.emit_c_array_field_init_to(buf, indent, target, ty, elems_opt, 0);
            }
            Ty::Named(key) => {
                let l_idx_opt = self.find_layout_idx(key).or_else(|| {
                    if let Some(MirConstVal::Struct { name, .. }) = val_opt {
                        self.find_layout_idx(name)
                    } else {
                        None
                    }
                });
                if let Some(l_idx) = l_idx_opt
                    && self.layouts[l_idx].item_kind != SchemaItemKind::Enum
                    && self.layouts[l_idx].size == f_size
                    && self.layouts[l_idx].size > 0
                {
                    let s_short = short_name(&self.layouts[l_idx].canonical_name);
                    let s_def_fn = format!("strata_default_{l_idx}_{}", sanitize_ident(s_short));
                    let _ = writeln!(buf, "{indent}{target} = {s_def_fn}();");
                    if let Some(MirConstVal::Struct { fields, .. }) = val_opt {
                        for (sf_name, sf_val) in fields {
                            if let Some(sf) = self.layouts[l_idx]
                                .fields
                                .iter()
                                .find(|sf| !sf.is_padding && sf.name == *sf_name)
                            {
                                let sfc = sanitize_c_field(sf_name);
                                self.emit_c_field_default_init(
                                    buf,
                                    indent,
                                    &format!("{target}.{sfc}"),
                                    &sf.ty,
                                    sf.size,
                                    Some(sf_val),
                                    false,
                                );
                            }
                        }
                    }
                } else if let Some(val) = val_opt {
                    let init_expr = self.c_const_val_for_ty(ty, val);
                    let _ = writeln!(buf, "{indent}{target} = {init_expr};");
                }
            }
            Ty::InlineStr(cap) => {
                if let Some(MirConstVal::String(s)) = val_opt {
                    let mut end = s.len().min(*cap);
                    while end > 0 && !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    let len_le = (end as u32).to_le_bytes();
                    let mut bytes_strs: Vec<String> =
                        len_le.iter().map(|b| format!("{b}u")).collect();
                    for &b in &s.as_bytes()[..end] {
                        bytes_strs.push(format!("0x{b:02x}u"));
                    }
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                    let _ = writeln!(
                        buf,
                        "{indent}{{ static const uint8_t _istr[] = {{ {} }}; size_t _n = sizeof(_istr) < sizeof({target}) ? sizeof(_istr) : sizeof({target}); memcpy({target}, _istr, _n); }}",
                        bytes_strs.join(", ")
                    );
                }
            }
            Ty::InputBuffer { .. } => {
                if zero_missing_array_elems || val_opt.is_some() {
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                }
            }
            Ty::SmallVec { elem, cap } => {
                if zero_missing_array_elems || val_opt.is_some() {
                    let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
                }
                if let Some(MirConstVal::Array(elems)) = val_opt {
                    let (es, ea) = self.sema_ty_size_align(elem).unwrap_or((4, 4));
                    let stride = es.div_ceil(ea) * ea;
                    let count = elems.len().min(*cap);
                    if count > 0 {
                        let _ = writeln!(
                            buf,
                            "{indent}{{ uint32_t _sv_len = {count}u; memcpy({target}, &_sv_len, sizeof(uint32_t)); }}"
                        );
                        for (ei, ev) in elems.iter().take(count).enumerate() {
                            let byte_off = 8 + ei * stride;
                            if let Some(bytes) = self.pack_const_bytes_for_ty(elem, ev)
                                && !bytes.is_empty()
                            {
                                let bytes_c: Vec<String> =
                                    bytes.iter().map(|b| format!("0x{b:02X}u")).collect();
                                let n = bytes.len();
                                let _ = writeln!(
                                    buf,
                                    "{indent}{{ static const uint8_t _sve[{n}] = {{ {} }}; if (({byte_off}u + {n}u) <= sizeof({target})) {{ memcpy(((uint8_t*)({target})) + {byte_off}u, _sve, {n}u); }} }}",
                                    bytes_c.join(", ")
                                );
                            } else {
                                let elem_cty = self.c_ty_from_sema(elem);
                                let ev_s = self.c_const_val_for_ty(elem, ev);
                                let _ = writeln!(
                                    buf,
                                    "{indent}{{ {elem_cty} _sve = {ev_s}; if (({byte_off}u + sizeof(_sve)) <= sizeof({target})) {{ memcpy(((uint8_t*)({target})) + {byte_off}u, &_sve, sizeof(_sve)); }} }}"
                                );
                            }
                        }
                    }
                }
            }
            _ => {
                if let Some(val) = val_opt {
                    let init_expr = self.c_const_val_for_ty(ty, val);
                    let _ = writeln!(buf, "{indent}{target} = {init_expr};");
                }
            }
        }
    }

    fn emit_c_array_field_init_to(
        &self,
        buf: &mut String,
        indent: &str,
        target: &str,
        ty: &Ty,
        elems_opt: Option<&[MirConstVal]>,
        flat_idx_base: usize,
    ) {
        if let Ty::Array { elem, len } = ty {
            if matches!(**elem, Ty::Array { .. }) {
                let mut stride = 1usize;
                let mut cur = &**elem;
                while let Ty::Array { elem: e, len: l } = cur {
                    stride *= *l;
                    cur = e;
                }
                for i in 0..*len {
                    let inner_elems = elems_opt.and_then(|es| es.get(i)).and_then(|ev| {
                        if let MirConstVal::Array(inner) = ev {
                            Some(inner.as_slice())
                        } else {
                            None
                        }
                    });
                    self.emit_c_array_field_init_to(
                        buf,
                        indent,
                        target,
                        elem,
                        inner_elems,
                        flat_idx_base + i * stride,
                    );
                }
            } else if let Ty::BitSet(bits) = &**elem {
                let bs_bytes = (*bits).div_ceil(32).max(1) * 4;
                for ei in 0..*len {
                    let flat_ei = flat_idx_base + ei;
                    if let Some(ev) = elems_opt.and_then(|es| es.get(ei)) {
                        let packed = pack_bitset_bytes(ev, bs_bytes);
                        if packed.iter().any(|&b| b != 0) {
                            let bytes_c: Vec<String> =
                                packed.iter().map(|b| format!("0x{b:02X}u")).collect();
                            let _ = writeln!(
                                buf,
                                "{indent}{{ uint8_t _bs_el[{bs_bytes}] = {{ {} }}; if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * {bs_bytes}u], _bs_el, {bs_bytes}u); }} }}",
                                bytes_c.join(", ")
                            );
                        } else {
                            let _ = writeln!(
                                buf,
                                "{indent}if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ memset(&({target})[{flat_ei}u * {bs_bytes}u], 0, {bs_bytes}u); }}"
                            );
                        }
                    }
                }
            } else {
                let elem_cty = self.c_ty_from_sema(elem);
                let named_non_zst = if let Ty::Named(key) = &**elem {
                    self.find_layout_idx(key)
                        .filter(|&li| self.layouts[li].size > 0)
                } else {
                    None
                };
                for ei in 0..*len {
                    let flat_ei = flat_idx_base + ei;
                    let ev_opt = elems_opt.and_then(|es| es.get(ei));
                    if let Some(l_idx) = named_non_zst {
                        let s_short = short_name(&self.layouts[l_idx].canonical_name);
                        let s_def_fn =
                            format!("strata_default_{l_idx}_{}", sanitize_ident(s_short));
                        let ae_var = format!("_ae_{}", indent.len());
                        let _ = writeln!(buf, "{indent}{{");
                        let _ = writeln!(buf, "{indent}    {elem_cty} {ae_var} = {s_def_fn}();");
                        if let Some(MirConstVal::Struct { fields, .. }) = ev_opt {
                            let sub_indent = format!("{indent}    ");
                            for (sf_name, sf_val) in fields {
                                if let Some(sf) = self.layouts[l_idx]
                                    .fields
                                    .iter()
                                    .find(|sf| !sf.is_padding && sf.name == *sf_name)
                                {
                                    let sfc = sanitize_c_field(sf_name);
                                    self.emit_c_field_default_init(
                                        buf,
                                        &sub_indent,
                                        &format!("{ae_var}.{sfc}"),
                                        &sf.ty,
                                        sf.size,
                                        Some(sf_val),
                                        false,
                                    );
                                }
                            }
                        }
                        let _ = writeln!(
                            buf,
                            "{indent}    if (({flat_ei}u + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }}"
                        );
                        let _ = writeln!(buf, "{indent}}}");
                    } else if let Some(ev) = ev_opt {
                        let ev_s = self.c_const_val_for_ty(elem, ev);
                        let ae_var = format!("_ae_{}", indent.len());
                        let _ = writeln!(
                            buf,
                            "{indent}{{ {elem_cty} {ae_var} = {ev_s}; if (({flat_ei}u + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }} }}"
                        );
                    }
                }
            }
        }
    }

    pub(super) fn emit_c_object_field_override(
        &self,
        buf: &mut String,
        indent: &str,
        target: &str,
        ty: &Ty,
        f_size: usize,
        expr: &HirExpr,
        zero_array: bool,
        depth: usize,
    ) {
        if depth < 64
            && let HirExpr::Path { name, .. } = expr
            && let Some(c) = self.mir.consts.iter().find(|c| {
                let seg = short_name(name);
                c.name == *name || short_name(&c.name) == seg
            })
            && let Some(ref inner) = c.expr
        {
            self.emit_c_object_field_override(
                buf,
                indent,
                target,
                ty,
                f_size,
                inner,
                zero_array,
                depth + 1,
            );
            return;
        }
        if let Some(mc) = self.hir_expr_to_mir_const_for_ty(expr, Some(ty)) {
            self.emit_c_field_default_init(buf, indent, target, ty, f_size, Some(&mc), zero_array);
            return;
        }
        if let HirExpr::StructLit {
            name: sname,
            fields: sfields,
            ..
        } = expr
            && let Some(sl_idx) = self.find_layout_idx(sname).or_else(|| match ty {
                Ty::Named(k) => self.find_layout_idx(k),
                _ => None,
            })
            && self.layouts[sl_idx].item_kind != SchemaItemKind::Enum
            && self.layouts[sl_idx].size > 0
        {
            let s_short = short_name(&self.layouts[sl_idx].canonical_name);
            let s_def = format!("strata_default_{sl_idx}_{}", sanitize_ident(s_short));
            let _ = writeln!(buf, "{indent}{target} = {s_def}();");
            for (sfn, sfexpr) in sfields {
                let sfc = sanitize_c_field(sfn);
                if let Some((sty, ssz)) = self.layouts[sl_idx]
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && f.name == *sfn)
                    .map(|f| (f.ty.clone(), f.size))
                {
                    self.emit_c_object_field_override(
                        buf,
                        indent,
                        &format!("{target}.{sfc}"),
                        &sty,
                        ssz,
                        sfexpr,
                        false,
                        depth + 1,
                    );
                }
            }
            return;
        }
        if let HirExpr::ArrayLit { elems, .. } = expr
            && matches!(ty, Ty::Array { .. })
        {
            if zero_array {
                let _ = writeln!(buf, "{indent}memset({target}, 0, sizeof({target}));");
            }
            self.emit_c_array_expr_init_to(buf, indent, target, ty, elems, 0, depth);
            return;
        }
        let is_enum = matches!(ty, Ty::Named(k) if self.c_enum_ty(k).is_some());
        if !matches!(
            ty,
            Ty::Array { .. } | Ty::BitSet(_) | Ty::Named(_) | Ty::InlineStr(_)
        ) || is_enum
        {
            let expr_s = self.c_hir_expr(expr, ty);
            let _ = writeln!(buf, "{indent}{target} = {expr_s};");
        } else {
            self.emit_c_field_default_init(buf, indent, target, ty, f_size, None, zero_array);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_c_array_expr_init_to(
        &self,
        buf: &mut String,
        indent: &str,
        target: &str,
        ty: &Ty,
        elems: &[HirExpr],
        flat_idx_base: usize,
        depth: usize,
    ) {
        if let Ty::Array { elem, len } = ty {
            if matches!(**elem, Ty::Array { .. }) {
                let mut stride = 1usize;
                let mut cur = &**elem;
                while let Ty::Array { elem: e, len: l } = cur {
                    stride *= *l;
                    cur = e;
                }
                for (i, el_expr) in elems.iter().take(*len).enumerate() {
                    let resolved = self.resolve_const_hir_expr(el_expr, depth);
                    if let HirExpr::ArrayLit {
                        elems: inner_elems, ..
                    } = resolved
                    {
                        self.emit_c_array_expr_init_to(
                            buf,
                            indent,
                            target,
                            elem,
                            inner_elems,
                            flat_idx_base + i * stride,
                            depth + 1,
                        );
                    } else if let Some(MirConstVal::Array(mc_elems)) =
                        self.hir_expr_to_mir_const_for_ty(resolved, Some(elem))
                    {
                        self.emit_c_array_field_init_to(
                            buf,
                            indent,
                            target,
                            elem,
                            Some(&mc_elems),
                            flat_idx_base + i * stride,
                        );
                    }
                }
            } else if let Ty::BitSet(bits) = &**elem {
                let bs_bytes = (*bits).div_ceil(32).max(1) * 4;
                for (ei, el_expr) in elems.iter().take(*len).enumerate() {
                    let flat_ei = flat_idx_base + ei;
                    let resolved = self.resolve_const_hir_expr(el_expr, depth);
                    if let Some(mc) = self.hir_expr_to_mir_const_for_ty(resolved, Some(elem)) {
                        let packed = pack_bitset_bytes(&mc, bs_bytes);
                        if packed.iter().any(|&b| b != 0) {
                            let bytes_c: Vec<String> =
                                packed.iter().map(|b| format!("0x{b:02X}u")).collect();
                            let _ = writeln!(
                                buf,
                                "{indent}{{ uint8_t _bs_el[{bs_bytes}] = {{ {} }}; if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * {bs_bytes}u], _bs_el, {bs_bytes}u); }} }}",
                                bytes_c.join(", ")
                            );
                        } else {
                            let _ = writeln!(
                                buf,
                                "{indent}if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ memset(&({target})[{flat_ei}u * {bs_bytes}u], 0, {bs_bytes}u); }}"
                            );
                        }
                    } else {
                        let ev_s = self.c_hir_expr(el_expr, elem);
                        let _ = writeln!(
                            buf,
                            "{indent}if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ uint64_t _bs64 = (uint64_t)({ev_s}); size_t _cn = {bs_bytes}u < sizeof(_bs64) ? {bs_bytes}u : sizeof(_bs64); memset(&({target})[{flat_ei}u * {bs_bytes}u], 0, {bs_bytes}u); memcpy(&({target})[{flat_ei}u * {bs_bytes}u], &_bs64, _cn); }}"
                        );
                    }
                }
            } else {
                let elem_cty = self.c_ty_from_sema(elem);
                let named_non_zst = if let Ty::Named(key) = &**elem {
                    self.find_layout_idx(key).filter(|&li| {
                        self.layouts[li].item_kind != SchemaItemKind::Enum
                            && self.layouts[li].size > 0
                    })
                } else {
                    None
                };
                for (ei, el_expr) in elems.iter().take(*len).enumerate() {
                    let flat_ei = flat_idx_base + ei;
                    let ae_var = format!("_ae_{depth}_{flat_ei}");
                    if let Some(l_idx) = named_non_zst {
                        let s_short = short_name(&self.layouts[l_idx].canonical_name);
                        let s_def_fn =
                            format!("strata_default_{l_idx}_{}", sanitize_ident(s_short));
                        let sub_indent = format!("{indent}    ");
                        let _ = writeln!(buf, "{indent}{{");
                        let _ = writeln!(buf, "{sub_indent}{elem_cty} {ae_var} = {s_def_fn}();");
                        self.emit_c_object_field_override(
                            buf,
                            &sub_indent,
                            &ae_var,
                            elem,
                            self.layouts[l_idx].size,
                            el_expr,
                            false,
                            depth + 1,
                        );
                        let _ = writeln!(
                            buf,
                            "{sub_indent}if (({flat_ei}u + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }}"
                        );
                        let _ = writeln!(buf, "{indent}}}");
                    } else {
                        let ev_s = self.c_hir_expr(el_expr, elem);
                        let _ = writeln!(
                            buf,
                            "{indent}{{ {elem_cty} {ae_var} = {ev_s}; if (({flat_ei}u + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }} }}"
                        );
                    }
                }
            }
        }
    }

    fn resolve_const_hir_expr<'b>(
        &'b self,
        mut expr: &'b HirExpr,
        mut depth: usize,
    ) -> &'b HirExpr {
        while depth < 64 {
            if let HirExpr::Path { name, .. } = expr
                && let Some(c) = self.mir.consts.iter().find(|c| {
                    let seg = short_name(name);
                    c.name == *name || short_name(&c.name) == seg
                })
                && let Some(ref inner) = c.expr
            {
                expr = inner;
                depth += 1;
                continue;
            }
            break;
        }
        expr
    }

    fn c_const_val_for_ty(&self, ty: &Ty, val: &MirConstVal) -> String {
        match (ty, val) {
            (Ty::Fix32, MirConstVal::Int(v)) => {
                let q = (*v).saturating_mul(65_536) as i32;
                c_i32_lit(q)
            }
            (Ty::Fix32, MirConstVal::Float(v)) => {
                let q = if v.is_finite() {
                    (*v * 65_536.0).round() as i32
                } else {
                    0
                };
                c_i32_lit(q)
            }
            (Ty::Fix32, MirConstVal::Bool(b)) => c_i32_lit(if *b { 65_536 } else { 0 }),
            (Ty::Fix64, MirConstVal::Int(v)) => {
                let q = v.wrapping_shl(32);
                c_i64_lit(q)
            }
            (Ty::Fix64, MirConstVal::Float(v)) => {
                let q = if v.is_finite() {
                    (*v * 4_294_967_296.0).round() as i64
                } else {
                    0
                };
                c_i64_lit(q)
            }
            (Ty::Fix64, MirConstVal::Bool(b)) => c_i64_lit(if *b { 1i64 << 32 } else { 0 }),
            (Ty::F64, MirConstVal::Float(v)) => c_f64(*v),
            (Ty::F64, MirConstVal::Int(v)) => c_f64(*v as f64),
            (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Float(v)) => {
                c_f32(*v as f32)
            }
            (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Int(v)) => {
                c_f32(*v as f32)
            }
            (Ty::I8 | Ty::I16 | Ty::I32, MirConstVal::Int(v)) => c_i32_lit(*v as i32),
            (Ty::I64, MirConstVal::Int(v)) => c_i64_lit(*v),
            (Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8, MirConstVal::Int(v)) => {
                format!("{}u", *v as u32)
            }
            (Ty::U64, MirConstVal::Int(v)) => format!("((uint64_t){}ull)", *v as u64),
            (Ty::Bool, MirConstVal::Int(v)) => {
                if *v != 0 {
                    "BAM_TRUE".to_string()
                } else {
                    "BAM_FALSE".to_string()
                }
            }
            (Ty::IVec2, MirConstVal::Vec2(v)) => format!(
                "strata_ivec2({}, {})",
                c_i32_lit(v[0] as i32),
                c_i32_lit(v[1] as i32)
            ),
            (Ty::IVec3, MirConstVal::Vec3(v)) => format!(
                "strata_ivec3({}, {}, {})",
                c_i32_lit(v[0] as i32),
                c_i32_lit(v[1] as i32),
                c_i32_lit(v[2] as i32)
            ),
            (Ty::UVec2, MirConstVal::Vec2(v)) => {
                format!("strata_uvec2({}u, {}u)", v[0] as u32, v[1] as u32)
            }
            (Ty::Named(key), MirConstVal::Struct { name, fields }) => {
                if let Some(l_idx) = self
                    .find_layout_idx(key)
                    .or_else(|| self.find_layout_idx(name))
                {
                    if self.layouts[l_idx].size == 0 || fields.is_empty() {
                        format!("(({}){{ 0 }})", self.layout_c_names[l_idx])
                    } else {
                        let mut inits = Vec::new();
                        for (sf_name, sf_val) in fields {
                            if let Some(sf) = self.layouts[l_idx]
                                .fields
                                .iter()
                                .find(|sf| sf.name == *sf_name)
                            {
                                let sfc = sanitize_c_field(sf_name);
                                let sv = self.c_const_val_for_ty(&sf.ty, sf_val);
                                inits.push(format!(".{sfc} = {sv}"));
                            }
                        }
                        if inits.is_empty() {
                            format!("(({}){{ 0 }})", self.layout_c_names[l_idx])
                        } else {
                            format!(
                                "(({}){{ {} }})",
                                self.layout_c_names[l_idx],
                                inits.join(", ")
                            )
                        }
                    }
                } else {
                    self.c_const_val(val)
                }
            }
            (Ty::Named(key), MirConstVal::Int(v)) if self.c_enum_ty(key).is_some() => {
                let et = self.c_enum_ty(key).unwrap_or("int32_t");
                if et == "int32_t" {
                    c_i32_lit(*v as i32)
                } else {
                    format!("(({et}){}u)", *v as u32)
                }
            }
            (Ty::Vec3a, MirConstVal::Vec3(v)) => format!(
                "strata_vec4({}, {}, {}, 0.0f)",
                c_f32(v[0] as f32),
                c_f32(v[1] as f32),
                c_f32(v[2] as f32)
            ),
            (Ty::Vec3, MirConstVal::Vec4(v)) => format!(
                "strata_vec3({}, {}, {})",
                c_f32(v[0] as f32),
                c_f32(v[1] as f32),
                c_f32(v[2] as f32)
            ),
            (Ty::Mat3, MirConstVal::Array(elems)) => {
                let floats = flatten_mat_floats(elems, 9);
                let items: Vec<String> = floats.iter().map(|&f| c_f32(f)).collect();
                format!("((StrataMat3){{ {{ {} }} }})", items.join(", "))
            }
            (Ty::Mat4, MirConstVal::Array(elems)) => {
                let floats = flatten_mat_floats(elems, 16);
                let items: Vec<String> = floats.iter().map(|&f| c_f32(f)).collect();
                format!("((StrataMat4){{ {{ {} }} }})", items.join(", "))
            }
            (Ty::InlineStr(cap), MirConstVal::String(s)) => {
                let total = 4 + cap.div_ceil(4) * 4;
                let mut end = s.len().min(*cap);
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                let mut raw = vec![0u8; total];
                raw[..4].copy_from_slice(&(end as u32).to_le_bytes());
                raw[4..4 + end].copy_from_slice(&s.as_bytes()[..end]);
                let bytes_c: Vec<String> = raw.iter().map(|b| format!("0x{b:02X}u")).collect();
                format!("((StrataBytes_{total}){{ {{ {} }} }})", bytes_c.join(", "))
            }
            (Ty::BitSet(bits), val) => {
                let byte_len = (*bits).div_ceil(32).max(1) * 4;
                let packed = pack_bitset_bytes(val, byte_len);
                let bytes_c: Vec<String> = packed.iter().map(|b| format!("0x{b:02X}u")).collect();
                format!("{{ {} }}", bytes_c.join(", "))
            }
            (Ty::Array { .. }, MirConstVal::Array(_)) => {
                if let Some(packed) = self.pack_const_bytes_for_ty(ty, val) {
                    if packed.is_empty() {
                        "{ 0 }".to_string()
                    } else {
                        let bytes_c: Vec<String> =
                            packed.iter().map(|b| format!("0x{b:02X}u")).collect();
                        format!("{{ {} }}", bytes_c.join(", "))
                    }
                } else {
                    self.c_const_val(val)
                }
            }
            _ => self.c_const_val(val),
        }
    }

    fn sema_ty_size_align(&self, ty: &Ty) -> Option<(usize, usize)> {
        match ty {
            Ty::Bool | Ty::U8 | Ty::I8 => Some((1, 1)),
            Ty::U16 | Ty::I16 => Some((2, 2)),
            Ty::U32
            | Ty::I32
            | Ty::Fix32
            | Ty::Sym
            | Ty::Rgba8
            | Ty::F32
            | Ty::UnitScalar { .. }
            | Ty::GraceWindow => Some((4, 4)),
            Ty::U64 | Ty::I64 | Ty::Fix64 | Ty::F64 | Ty::Ref(_) => Some((8, 8)),
            Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => Some((8, 4)),
            Ty::Vec3 | Ty::IVec3 => Some((12, 4)),
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Some((16, 4)),
            Ty::Mat3 => Some((36, 4)),
            Ty::Mat4 => Some((64, 4)),
            Ty::BitSet(bits) => Some(((*bits).div_ceil(32).max(1) * 4, 4)),
            Ty::InlineStr(cap) => Some((4 + cap.div_ceil(4) * 4, 4)),
            Ty::InputBuffer { cap, .. } => Some(((*cap).max(1) * 8, 4)),
            Ty::SmallVec { elem, cap } => {
                let (es, ea) = self.sema_ty_size_align(elem)?;
                let align = ea.max(4);
                let stride = es.div_ceil(ea) * ea;
                Some((8 + stride * *cap, align))
            }
            Ty::Array { elem, len } => {
                let (es, ea) = self.sema_ty_size_align(elem)?;
                let stride = es.div_ceil(ea) * ea;
                Some((stride * *len, ea))
            }
            Ty::Named(key) => {
                if let Some(l_idx) = self.find_layout_idx(key) {
                    Some((self.layouts[l_idx].size, self.layouts[l_idx].align.max(1)))
                } else if let Some(et) = self.c_enum_ty(key) {
                    match et {
                        "uint8_t" => Some((1, 1)),
                        "uint16_t" => Some((2, 2)),
                        _ => Some((4, 4)),
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn pack_const_bytes_for_ty(&self, ty: &Ty, val: &MirConstVal) -> Option<Vec<u8>> {
        match (ty, val) {
            (Ty::Bool, MirConstVal::Bool(b)) => Some(vec![u8::from(*b)]),
            (Ty::Bool, MirConstVal::Int(v)) => Some(vec![u8::from(*v != 0)]),
            (Ty::U8, MirConstVal::Int(v)) => Some(vec![*v as u8]),
            (Ty::I8, MirConstVal::Int(v)) => Some(vec![(*v as i8) as u8]),
            (Ty::U16, MirConstVal::Int(v)) => Some((*v as u16).to_le_bytes().to_vec()),
            (Ty::I16, MirConstVal::Int(v)) => Some((*v as i16).to_le_bytes().to_vec()),
            (Ty::U32 | Ty::Sym | Ty::Rgba8, MirConstVal::Int(v)) => {
                Some((*v as u32).to_le_bytes().to_vec())
            }
            (Ty::I32, MirConstVal::Int(v)) => Some((*v as i32).to_le_bytes().to_vec()),
            (Ty::U64, MirConstVal::Int(v)) => Some((*v as u64).to_le_bytes().to_vec()),
            (Ty::I64, MirConstVal::Int(v)) => Some(v.to_le_bytes().to_vec()),
            (Ty::Fix32, MirConstVal::Int(v)) => {
                Some(((*v).saturating_mul(65_536) as i32).to_le_bytes().to_vec())
            }
            (Ty::Fix32, MirConstVal::Float(v)) => {
                let q = if v.is_finite() {
                    (*v * 65_536.0).round() as i32
                } else {
                    0
                };
                Some(q.to_le_bytes().to_vec())
            }
            (Ty::Fix32, MirConstVal::Bool(b)) => {
                Some((if *b { 65_536i32 } else { 0 }).to_le_bytes().to_vec())
            }
            (Ty::Fix64, MirConstVal::Int(v)) => Some(v.wrapping_shl(32).to_le_bytes().to_vec()),
            (Ty::Fix64, MirConstVal::Float(v)) => {
                let q = if v.is_finite() {
                    (*v * 4_294_967_296.0).round() as i64
                } else {
                    0
                };
                Some(q.to_le_bytes().to_vec())
            }
            (Ty::Fix64, MirConstVal::Bool(b)) => {
                Some((if *b { 1i64 << 32 } else { 0 }).to_le_bytes().to_vec())
            }
            (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Float(v)) => {
                Some((*v as f32).to_le_bytes().to_vec())
            }
            (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Int(v)) => {
                Some((*v as f32).to_le_bytes().to_vec())
            }
            (Ty::F64, MirConstVal::Float(v)) => Some(v.to_le_bytes().to_vec()),
            (Ty::F64, MirConstVal::Int(v)) => Some((*v as f64).to_le_bytes().to_vec()),
            (Ty::Vec2, MirConstVal::Vec2(v)) => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&(v[0] as f32).to_le_bytes());
                out.extend_from_slice(&(v[1] as f32).to_le_bytes());
                Some(out)
            }
            (Ty::Vec3, MirConstVal::Vec3(v)) => {
                let mut out = Vec::with_capacity(12);
                for x in v {
                    out.extend_from_slice(&(*x as f32).to_le_bytes());
                }
                Some(out)
            }
            (Ty::Vec3, MirConstVal::Vec4(v)) => {
                let mut out = Vec::with_capacity(12);
                for x in &v[..3] {
                    out.extend_from_slice(&(*x as f32).to_le_bytes());
                }
                Some(out)
            }
            (Ty::Vec3a, MirConstVal::Vec3(v)) => {
                let mut out = Vec::with_capacity(16);
                for x in v {
                    out.extend_from_slice(&(*x as f32).to_le_bytes());
                }
                out.extend_from_slice(&0.0f32.to_le_bytes());
                Some(out)
            }
            (Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba, MirConstVal::Vec4(v)) => {
                let mut out = Vec::with_capacity(16);
                for x in v {
                    out.extend_from_slice(&(*x as f32).to_le_bytes());
                }
                Some(out)
            }
            (Ty::IVec2, MirConstVal::Vec2(v)) => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&(v[0] as i32).to_le_bytes());
                out.extend_from_slice(&(v[1] as i32).to_le_bytes());
                Some(out)
            }
            (Ty::IVec3, MirConstVal::Vec3(v)) => {
                let mut out = Vec::with_capacity(12);
                for x in v {
                    out.extend_from_slice(&(*x as i32).to_le_bytes());
                }
                Some(out)
            }
            (Ty::UVec2, MirConstVal::Vec2(v)) => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&(v[0] as u32).to_le_bytes());
                out.extend_from_slice(&(v[1] as u32).to_le_bytes());
                Some(out)
            }
            (Ty::Mat3, MirConstVal::Array(elems)) => {
                let floats = flatten_mat_floats(elems, 9);
                let mut out = Vec::with_capacity(36);
                for f in floats {
                    out.extend_from_slice(&f.to_le_bytes());
                }
                Some(out)
            }
            (Ty::Mat4, MirConstVal::Array(elems)) => {
                let floats = flatten_mat_floats(elems, 16);
                let mut out = Vec::with_capacity(64);
                for f in floats {
                    out.extend_from_slice(&f.to_le_bytes());
                }
                Some(out)
            }
            (Ty::BitSet(bits), _) => {
                let byte_len = (*bits).div_ceil(32).max(1) * 4;
                Some(pack_bitset_bytes(val, byte_len))
            }
            (Ty::InlineStr(cap), MirConstVal::String(s)) => {
                let total = 4 + cap.div_ceil(4) * 4;
                let mut end = s.len().min(*cap);
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                let mut out = vec![0u8; total];
                out[..4].copy_from_slice(&(end as u32).to_le_bytes());
                out[4..4 + end].copy_from_slice(&s.as_bytes()[..end]);
                Some(out)
            }
            (Ty::Array { elem, len }, MirConstVal::Array(elems)) => {
                let (es, ea) = self.sema_ty_size_align(elem)?;
                let stride = es.div_ceil(ea) * ea;
                let mut out = vec![0u8; stride * *len];
                for (i, ev) in elems.iter().take(*len).enumerate() {
                    let eb = self.pack_const_bytes_for_ty(elem, ev)?;
                    let copy_n = eb.len().min(es);
                    out[i * stride..i * stride + copy_n].copy_from_slice(&eb[..copy_n]);
                }
                Some(out)
            }
            (Ty::Named(key), MirConstVal::Struct { name, fields }) => {
                let l_idx = self
                    .find_layout_idx(key)
                    .or_else(|| self.find_layout_idx(name))?;
                let mut out = vec![0u8; self.layouts[l_idx].size];
                for (sf_name, sf_val) in fields {
                    if let Some(sf) = self.layouts[l_idx]
                        .fields
                        .iter()
                        .find(|sf| !sf.is_padding && sf.name == *sf_name)
                    {
                        let sb = self.pack_const_bytes_for_ty(&sf.ty, sf_val)?;
                        let copy_n = sb.len().min(sf.size);
                        if sf.offset + copy_n <= out.len() {
                            out[sf.offset..sf.offset + copy_n].copy_from_slice(&sb[..copy_n]);
                        }
                    }
                }
                Some(out)
            }
            (Ty::Named(key), MirConstVal::Int(v)) => match self.c_enum_ty(key)? {
                "uint8_t" => Some(vec![*v as u8]),
                "uint16_t" => Some((*v as u16).to_le_bytes().to_vec()),
                "int32_t" => Some((*v as i32).to_le_bytes().to_vec()),
                _ => Some((*v as u32).to_le_bytes().to_vec()),
            },
            _ => None,
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

    fn hir_expr_is_float(&self, expr: &HirExpr, ty: &Ty) -> bool {
        if matches!(
            ty,
            Ty::F32 | Ty::F64 | Ty::UnitScalar { .. } | Ty::GraceWindow
        ) {
            return true;
        }
        if !matches!(ty, Ty::Unknown) {
            return false;
        }
        match expr {
            HirExpr::FloatLit { .. } => true,
            HirExpr::Unary { expr: inner, .. } => self.hir_expr_is_float(inner, &inner.ty()),
            HirExpr::Binary { lhs, rhs, .. } => {
                self.hir_expr_is_float(lhs, &lhs.ty()) || self.hir_expr_is_float(rhs, &rhs.ty())
            }
            HirExpr::Path { name, .. } => {
                let seg = short_name(name);
                self.mir
                    .consts
                    .iter()
                    .find(|c| c.name == *name || short_name(&c.name) == seg)
                    .is_some_and(|c| {
                        matches!(
                            c.ty,
                            Ty::F32 | Ty::F64 | Ty::UnitScalar { .. } | Ty::GraceWindow
                        )
                    })
            }
            _ => false,
        }
    }

    fn c_hir_expr(&self, expr: &HirExpr, hint_ty: &Ty) -> String {
        match expr {
            HirExpr::IntLit { value, .. } => match hint_ty {
                Ty::Fix32 => c_i32_lit((*value).saturating_mul(65_536) as i32),
                Ty::Fix64 => c_i64_lit(value.wrapping_shl(32)),
                Ty::I64 => c_i64_lit(*value),
                Ty::U64 => format!("((uint64_t){}ull)", *value as u64),
                _ => format!("{value}"),
            },
            HirExpr::FloatLit { value, ty } => match (ty, hint_ty) {
                (Ty::Fix32, _) | (_, Ty::Fix32) => {
                    let q = if value.is_finite() {
                        (*value * 65_536.0).round() as i32
                    } else {
                        0
                    };
                    c_i32_lit(q)
                }
                (Ty::Fix64, _) | (_, Ty::Fix64) => {
                    let q = if value.is_finite() {
                        (*value * 4_294_967_296.0).round() as i64
                    } else {
                        0
                    };
                    c_i64_lit(q)
                }
                (Ty::F64, _) | (_, Ty::F64) => c_f64(*value),
                _ => c_f32(*value as f32),
            },
            HirExpr::BoolLit(b) => {
                if *b {
                    "BAM_TRUE".to_string()
                } else {
                    "BAM_FALSE".to_string()
                }
            }
            HirExpr::StringLit(st) => {
                if matches!(hint_ty, Ty::InlineStr(_)) {
                    self.c_const_val_for_ty(hint_ty, &MirConstVal::String(st.clone()))
                } else {
                    format!("\"{}\"", c_escape(st))
                }
            }
            HirExpr::Unary { op, expr, .. } => {
                if matches!(op, HirUnOp::Neg) && matches!(hint_ty, Ty::Fix32 | Ty::Fix64) {
                    match &**expr {
                        HirExpr::IntLit { value, .. } => {
                            let neg = value.wrapping_neg();
                            return match hint_ty {
                                Ty::Fix32 => c_i32_lit(neg.saturating_mul(65_536) as i32),
                                Ty::Fix64 => c_i64_lit(neg.wrapping_shl(32)),
                                _ => format!("{neg}"),
                            };
                        }
                        HirExpr::FloatLit { value, .. } => {
                            let neg = -*value;
                            return match hint_ty {
                                Ty::Fix32 => {
                                    let q = if neg.is_finite() {
                                        (neg * 65_536.0).round() as i32
                                    } else {
                                        0
                                    };
                                    c_i32_lit(q)
                                }
                                Ty::Fix64 => {
                                    let q = if neg.is_finite() {
                                        (neg * 4_294_967_296.0).round() as i64
                                    } else {
                                        0
                                    };
                                    c_i64_lit(q)
                                }
                                _ => c_f32(neg as f32),
                            };
                        }
                        _ => {}
                    }
                }
                let inner = self.c_hir_expr(expr, hint_ty);
                match op {
                    HirUnOp::Neg => format!("-({inner})"),
                    HirUnOp::Not => format!("(!({inner}))"),
                    _ => inner,
                }
            }
            HirExpr::Path { name, .. } => {
                let seg = short_name(name);
                if let Some((en, var)) = name.split_once("::")
                    && let Some(e) = self
                        .mir
                        .enums
                        .iter()
                        .find(|e| e.canonical_name == en || short_name(&e.canonical_name) == en)
                    && let Some((_, disc)) = e.variants.iter().find(|(vn, _)| vn == var)
                {
                    return self.c_const_val_for_ty(hint_ty, &MirConstVal::Int(*disc));
                }
                for e in &self.mir.enums {
                    if let Some((_, disc)) = e.variants.iter().find(|(vn, _)| vn == seg) {
                        return self.c_const_val_for_ty(hint_ty, &MirConstVal::Int(*disc));
                    }
                }
                if let Some(c) = self
                    .mir
                    .consts
                    .iter()
                    .find(|c| c.name == *name || short_name(&c.name) == seg)
                    && let Some(ref inner) = c.expr
                {
                    let eff_hint = if matches!(hint_ty, Ty::Unknown) {
                        &c.ty
                    } else {
                        hint_ty
                    };
                    return self.c_hir_expr(inner, eff_hint);
                }
                if let Some(mc) = self.hir_expr_to_mir_const(expr) {
                    let eff_ty = if name.starts_with("ivec2::") {
                        &Ty::IVec2
                    } else if name.starts_with("uvec2::") {
                        &Ty::UVec2
                    } else if name.starts_with("ivec3::") {
                        &Ty::IVec3
                    } else if name.starts_with("vec2::") {
                        &Ty::Vec2
                    } else if name.starts_with("vec3::") {
                        &Ty::Vec3
                    } else if name.starts_with("vec4::") {
                        &Ty::Vec4
                    } else {
                        hint_ty
                    };
                    return self.c_const_val_for_ty(eff_ty, &mc);
                }
                self.c_zero_for_sema(hint_ty)
            }
            HirExpr::Cast { expr, target_ty } => {
                if let Some(mc) = self.hir_expr_to_mir_const(&HirExpr::Cast {
                    expr: expr.clone(),
                    target_ty: target_ty.clone(),
                }) {
                    return self.c_const_val_for_ty(hint_ty, &mc);
                }
                let src_ty = expr.ty();
                let src_hint = if matches!(src_ty, Ty::Unknown) {
                    target_ty
                } else {
                    &src_ty
                };
                let inner = self.c_hir_expr(expr, src_hint);
                let mid_cty = self.c_ty_from_sema(target_ty);
                let is_src_float = self.hir_expr_is_float(expr, &src_ty);
                let mid = if is_src_float
                    && matches!(
                        target_ty,
                        Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::Sym | Ty::Rgba8
                    ) {
                    let helper = match target_ty {
                        Ty::U8 => "strata_f64_to_u8",
                        Ty::U16 => "strata_f64_to_u16",
                        Ty::U64 => "strata_f64_to_u64",
                        _ => "strata_f64_to_u32",
                    };
                    let raw = format!("{helper}((double)({inner}))");
                    if matches!(target_ty, Ty::Sym | Ty::Rgba8) {
                        format!("(({mid_cty}){raw})")
                    } else {
                        raw
                    }
                } else if is_src_float && matches!(target_ty, Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64)
                {
                    let helper = match target_ty {
                        Ty::I8 => "strata_f64_to_i8",
                        Ty::I16 => "strata_f64_to_i16",
                        Ty::I32 => "strata_f64_to_i32",
                        _ => "strata_f64_to_i64",
                    };
                    format!("{helper}((double)({inner}))")
                } else if matches!(target_ty, Ty::Fix32) {
                    if matches!(src_ty, Ty::Fix32) {
                        inner
                    } else if matches!(src_ty, Ty::Fix64) {
                        format!("strata_fix64_to_fix32({inner})")
                    } else if is_src_float {
                        format!("strata_f64_to_fix32((double)({inner}))")
                    } else {
                        format!("((int32_t)((int64_t)({inner}) * 65536ll))")
                    }
                } else if matches!(target_ty, Ty::Fix64) {
                    if matches!(src_ty, Ty::Fix64) {
                        inner
                    } else if matches!(src_ty, Ty::Fix32) {
                        format!("strata_fix32_to_fix64({inner})")
                    } else if is_src_float {
                        format!("strata_f64_to_fix64((double)({inner}))")
                    } else {
                        format!("((int64_t)({inner}) * 4294967296ll)")
                    }
                } else if matches!(src_ty, Ty::Fix32)
                    && matches!(
                        target_ty,
                        Ty::I8
                            | Ty::I16
                            | Ty::I32
                            | Ty::I64
                            | Ty::U8
                            | Ty::U16
                            | Ty::U32
                            | Ty::U64
                            | Ty::Sym
                            | Ty::Rgba8
                    )
                {
                    format!("(({mid_cty})((int32_t)({inner}) / 65536))")
                } else if matches!(src_ty, Ty::Fix64)
                    && matches!(
                        target_ty,
                        Ty::I8
                            | Ty::I16
                            | Ty::I32
                            | Ty::I64
                            | Ty::U8
                            | Ty::U16
                            | Ty::U32
                            | Ty::U64
                            | Ty::Sym
                            | Ty::Rgba8
                    )
                {
                    format!("(({mid_cty})((int64_t)({inner}) / 4294967296ll))")
                } else if matches!(src_ty, Ty::Fix32)
                    && matches!(target_ty, Ty::F32 | Ty::UnitScalar { .. })
                {
                    format!("((float)((double)({inner}) / 65536.0))")
                } else if matches!(src_ty, Ty::Fix32) && matches!(target_ty, Ty::F64) {
                    format!("((double)({inner}) / 65536.0)")
                } else if matches!(src_ty, Ty::Fix64)
                    && matches!(target_ty, Ty::F32 | Ty::UnitScalar { .. })
                {
                    format!("((float)((double)({inner}) / 4294967296.0))")
                } else if matches!(src_ty, Ty::Fix64) && matches!(target_ty, Ty::F64) {
                    format!("((double)({inner}) / 4294967296.0)")
                } else {
                    format!("(({mid_cty})({inner}))")
                };
                match (target_ty, hint_ty) {
                    (Ty::Fix32, Ty::Fix32)
                    | (Ty::Fix64, Ty::Fix64)
                    | (Ty::Fix32, Ty::Unknown)
                    | (Ty::Fix64, Ty::Unknown) => mid,
                    (Ty::Fix32, Ty::Fix64) => format!("strata_fix32_to_fix64({mid})"),
                    (Ty::Fix64, Ty::Fix32) => format!("strata_fix64_to_fix32({mid})"),
                    (Ty::Fix32, Ty::F32 | Ty::UnitScalar { .. }) => {
                        format!("((float)((double)({mid}) / 65536.0))")
                    }
                    (Ty::Fix32, Ty::F64) => format!("((double)({mid}) / 65536.0)"),
                    (Ty::Fix64, Ty::F32 | Ty::UnitScalar { .. }) => {
                        format!("((float)((double)({mid}) / 4294967296.0))")
                    }
                    (Ty::Fix64, Ty::F64) => format!("((double)({mid}) / 4294967296.0)"),
                    (
                        Ty::Fix32,
                        Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8,
                    ) => {
                        let dst_cty = self.c_ty_from_sema(hint_ty);
                        format!("(({dst_cty})((int32_t)({mid}) / 65536))")
                    }
                    (
                        Ty::Fix64,
                        Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8,
                    ) => {
                        let dst_cty = self.c_ty_from_sema(hint_ty);
                        format!("(({dst_cty})((int64_t)({mid}) / 4294967296ll))")
                    }
                    (_, Ty::Fix32) => {
                        if matches!(target_ty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) {
                            format!("strata_f64_to_fix32((double)({mid}))")
                        } else {
                            format!("((int32_t)((int64_t)({mid}) * 65536ll))")
                        }
                    }
                    (_, Ty::Fix64) => {
                        if matches!(target_ty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) {
                            format!("strata_f64_to_fix64((double)({mid}))")
                        } else {
                            format!("((int64_t)({mid}) * 4294967296ll)")
                        }
                    }
                    _ => {
                        let dst_cty = self.c_ty_from_sema(hint_ty);
                        if dst_cty == mid_cty {
                            mid
                        } else {
                            format!("(({dst_cty}){mid})")
                        }
                    }
                }
            }
            HirExpr::Binary { op, lhs, rhs, ty } => {
                if let Some(mc) = self.hir_expr_to_mir_const(&HirExpr::Binary {
                    op: *op,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    ty: ty.clone(),
                }) {
                    return self.c_const_val_for_ty(hint_ty, &mc);
                }
                let child_ty = if matches!(ty, Ty::Unknown) {
                    hint_ty
                } else {
                    ty
                };
                let l = self.c_hir_expr(lhs, child_ty);
                let r = self.c_hir_expr(rhs, child_ty);
                let cop = match op {
                    HirBinOp::Add => "+",
                    HirBinOp::Sub => "-",
                    HirBinOp::Mul => "*",
                    HirBinOp::Div => "/",
                    HirBinOp::Rem => "%",
                    HirBinOp::BitAnd => "&",
                    HirBinOp::BitOr => "|",
                    HirBinOp::BitXor => "^",
                    HirBinOp::Shl => "<<",
                    HirBinOp::Shr => ">>",
                    HirBinOp::Eq => "==",
                    HirBinOp::Ne => "!=",
                    HirBinOp::Lt => "<",
                    HirBinOp::Le => "<=",
                    HirBinOp::Gt => ">",
                    HirBinOp::Ge => ">=",
                    HirBinOp::And => "&&",
                    HirBinOp::Or => "||",
                    HirBinOp::Range | HirBinOp::RangeInclusive => {
                        return self.c_zero_for_sema(hint_ty);
                    }
                };
                format!("(({l}) {cop} ({r}))")
            }
            HirExpr::Call(call) => {
                let a = |i: usize, ty_hint: &Ty, fallback: &str| {
                    call.args
                        .get(i)
                        .map(|arg| self.c_hir_expr(arg, ty_hint))
                        .unwrap_or_else(|| fallback.to_string())
                };
                match short_name(&call.callee) {
                    "vec2" | "Vec2" => format!(
                        "strata_vec2({}, {})",
                        a(0, &Ty::F32, "0.0f"),
                        a(1, &Ty::F32, "0.0f")
                    ),
                    "vec3" | "Vec3" => format!(
                        "strata_vec3({}, {}, {})",
                        a(0, &Ty::F32, "0.0f"),
                        a(1, &Ty::F32, "0.0f"),
                        a(2, &Ty::F32, "0.0f")
                    ),
                    "vec3a" | "Vec3a" => {
                        if matches!(hint_ty, Ty::Vec3a) {
                            format!(
                                "strata_vec4({}, {}, {}, 0.0f)",
                                a(0, &Ty::F32, "0.0f"),
                                a(1, &Ty::F32, "0.0f"),
                                a(2, &Ty::F32, "0.0f")
                            )
                        } else {
                            format!(
                                "strata_vec3({}, {}, {})",
                                a(0, &Ty::F32, "0.0f"),
                                a(1, &Ty::F32, "0.0f"),
                                a(2, &Ty::F32, "0.0f")
                            )
                        }
                    }
                    "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => format!(
                        "strata_vec4({}, {}, {}, {})",
                        a(0, &Ty::F32, "0.0f"),
                        a(1, &Ty::F32, "0.0f"),
                        a(2, &Ty::F32, "0.0f"),
                        a(3, &Ty::F32, "0.0f")
                    ),
                    "ivec2" | "IVec2" => format!(
                        "strata_ivec2((int32_t)({}), (int32_t)({}))",
                        a(0, &Ty::I32, "0"),
                        a(1, &Ty::I32, "0")
                    ),
                    "ivec3" | "IVec3" => format!(
                        "strata_ivec3((int32_t)({}), (int32_t)({}), (int32_t)({}))",
                        a(0, &Ty::I32, "0"),
                        a(1, &Ty::I32, "0"),
                        a(2, &Ty::I32, "0")
                    ),
                    "uvec2" | "UVec2" => format!(
                        "strata_uvec2((uint32_t)({}), (uint32_t)({}))",
                        a(0, &Ty::U32, "0u"),
                        a(1, &Ty::U32, "0u")
                    ),
                    "mat3" | "Mat3" => {
                        if call.args.len() == 3 {
                            let c0 = call
                                .args
                                .first()
                                .and_then(|e| self.hir_expr_to_mir_const(e))
                                .unwrap_or(MirConstVal::Vec3([0.0; 3]));
                            let c1 = call
                                .args
                                .get(1)
                                .and_then(|e| self.hir_expr_to_mir_const(e))
                                .unwrap_or(MirConstVal::Vec3([0.0; 3]));
                            let c2 = call
                                .args
                                .get(2)
                                .and_then(|e| self.hir_expr_to_mir_const(e))
                                .unwrap_or(MirConstVal::Vec3([0.0; 3]));
                            let fl = flatten_mat_floats(&[c0, c1, c2], 9);
                            let items: Vec<String> = fl.iter().map(|&f| c_f32(f)).collect();
                            format!("((StrataMat3){{ {{ {} }} }})", items.join(", "))
                        } else {
                            let mut items = Vec::with_capacity(9);
                            for i in 0..9 {
                                items.push(a(i, &Ty::F32, "0.0f"));
                            }
                            format!("((StrataMat3){{ {{ {} }} }})", items.join(", "))
                        }
                    }
                    "mat4" | "Mat4" => {
                        let mut items = Vec::with_capacity(16);
                        for i in 0..16 {
                            items.push(a(i, &Ty::F32, "0.0f"));
                        }
                        format!("((StrataMat4){{ {{ {} }} }})", items.join(", "))
                    }
                    "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => {
                        let inner_ty = if matches!(hint_ty, Ty::Unknown | Ty::Fix32 | Ty::Fix64) {
                            &Ty::F32
                        } else {
                            hint_ty
                        };
                        let v = a(0, inner_ty, "0.0f");
                        match hint_ty {
                            Ty::Fix32 => format!("strata_f64_to_fix32((double)({v}))"),
                            Ty::Fix64 => format!("strata_f64_to_fix64((double)({v}))"),
                            _ => v,
                        }
                    }
                    "bits" => {
                        let mut mask = 0u64;
                        for arg in &call.args {
                            if let Some(MirConstVal::Int(b)) = self.hir_expr_to_mir_const(arg)
                                && b >= 0
                                && (b as u32) < 64
                            {
                                mask |= 1u64 << (b as u32);
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

    pub(super) fn hir_expr_to_mir_const(&self, expr: &HirExpr) -> Option<MirConstVal> {
        self.hir_expr_to_mir_const_for_ty(expr, None)
    }

    pub(super) fn hir_expr_to_mir_const_for_ty(
        &self,
        expr: &HirExpr,
        hint_ty: Option<&Ty>,
    ) -> Option<MirConstVal> {
        let as_f64 = |mc: &MirConstVal| -> Option<f64> {
            match mc {
                MirConstVal::Int(i) => Some(*i as f64),
                MirConstVal::Float(f) => Some(*f),
                _ => None,
            }
        };
        match expr {
            HirExpr::IntLit { value, .. } => Some(MirConstVal::Int(*value)),
            HirExpr::FloatLit { value, .. } => Some(MirConstVal::Float(*value)),
            HirExpr::BoolLit(b) => Some(MirConstVal::Bool(*b)),
            HirExpr::StringLit(st) => Some(MirConstVal::String(st.clone())),
            HirExpr::Cast { expr, target_ty } => {
                let v = self.hir_expr_to_mir_const(expr)?;
                let src_fix = match expr.ty() {
                    Ty::Fix32 => Some(false),
                    Ty::Fix64 => Some(true),
                    _ => match expr.as_ref() {
                        HirExpr::Cast {
                            target_ty: Ty::Fix32,
                            ..
                        } => Some(false),
                        HirExpr::Cast {
                            target_ty: Ty::Fix64,
                            ..
                        } => Some(true),
                        _ => None,
                    },
                };
                if let Some(is_fix64) = src_fix
                    && matches!(
                        target_ty,
                        Ty::I8
                            | Ty::I16
                            | Ty::I32
                            | Ty::I64
                            | Ty::U8
                            | Ty::U16
                            | Ty::U32
                            | Ty::U64
                            | Ty::Sym
                            | Ty::Rgba8
                    )
                {
                    let trunc: i64 = if is_fix64 {
                        let q = match v {
                            MirConstVal::Int(i) => i.wrapping_shl(32),
                            MirConstVal::Float(f) if f.is_finite() => {
                                (f * 4_294_967_296.0).round() as i64
                            }
                            MirConstVal::Float(_) => 0,
                            MirConstVal::Bool(b) => {
                                if b {
                                    1i64 << 32
                                } else {
                                    0
                                }
                            }
                            _ => return None,
                        };
                        q / 4_294_967_296
                    } else {
                        let q = match v {
                            MirConstVal::Int(i) => i.saturating_mul(65_536) as i32,
                            MirConstVal::Float(f) if f.is_finite() => (f * 65_536.0).round() as i32,
                            MirConstVal::Float(_) => 0,
                            MirConstVal::Bool(b) => {
                                if b {
                                    65_536
                                } else {
                                    0
                                }
                            }
                            _ => return None,
                        };
                        i64::from(q / 65_536)
                    };
                    return match target_ty {
                        Ty::I8 => Some(MirConstVal::Int(i64::from(trunc as i8))),
                        Ty::I16 => Some(MirConstVal::Int(i64::from(trunc as i16))),
                        Ty::I32 => Some(MirConstVal::Int(i64::from(trunc as i32))),
                        Ty::I64 | Ty::U64 => Some(MirConstVal::Int(trunc)),
                        Ty::U8 => Some(MirConstVal::Int(i64::from(trunc as u8))),
                        Ty::U16 => Some(MirConstVal::Int(i64::from(trunc as u16))),
                        Ty::U32 | Ty::Sym | Ty::Rgba8 => {
                            Some(MirConstVal::Int(i64::from(trunc as u32)))
                        }
                        _ => None,
                    };
                }
                match target_ty {
                    Ty::F32 => as_f64(&v).map(|f| MirConstVal::Float((f as f32) as f64)),
                    Ty::F64 => as_f64(&v).map(MirConstVal::Float),
                    Ty::Fix32 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                        MirConstVal::Float(f) if f.is_finite() => {
                            let q = (f * 65_536.0).round() as i32;
                            Some(MirConstVal::Float(f64::from(q) / 65_536.0))
                        }
                        MirConstVal::Float(_) => Some(MirConstVal::Int(0)),
                        MirConstVal::Bool(b) => Some(MirConstVal::Int(i64::from(b))),
                        _ => None,
                    },
                    Ty::Fix64 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                        MirConstVal::Float(f) if f.is_finite() => {
                            let q = (f * 4_294_967_296.0).round() as i64;
                            Some(MirConstVal::Float((q as f64) / 4_294_967_296.0))
                        }
                        MirConstVal::Float(_) => Some(MirConstVal::Int(0)),
                        MirConstVal::Bool(b) => Some(MirConstVal::Int(i64::from(b))),
                        _ => None,
                    },
                    Ty::U8 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u8))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u8))),
                        _ => None,
                    },
                    Ty::U16 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u16))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u16))),
                        _ => None,
                    },
                    Ty::U32 | Ty::Sym | Ty::Rgba8 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u32))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u32))),
                        _ => None,
                    },
                    Ty::U64 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                        MirConstVal::Float(f) => Some(MirConstVal::Int((f as u64) as i64)),
                        _ => None,
                    },
                    Ty::I8 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i8))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i8))),
                        _ => None,
                    },
                    Ty::I16 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i16))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i16))),
                        _ => None,
                    },
                    Ty::I32 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i32))),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i32))),
                        _ => None,
                    },
                    Ty::I64 => match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                        MirConstVal::Float(f) => Some(MirConstVal::Int(f as i64)),
                        _ => None,
                    },
                    Ty::Bool => match v {
                        MirConstVal::Bool(b) => Some(MirConstVal::Bool(b)),
                        MirConstVal::Int(i) => Some(MirConstVal::Bool(i != 0)),
                        _ => None,
                    },
                    _ => Some(v),
                }
            }
            HirExpr::Path { name, .. } => {
                let seg = short_name(name);
                if let Some((en, var)) = name.split_once("::")
                    && let Some(e) = self
                        .mir
                        .enums
                        .iter()
                        .find(|e| e.canonical_name == en || short_name(&e.canonical_name) == en)
                    && let Some((_, disc)) = e.variants.iter().find(|(vn, _)| vn == var)
                {
                    return Some(MirConstVal::Int(*disc));
                }
                for e in &self.mir.enums {
                    if let Some((_, disc)) = e.variants.iter().find(|(vn, _)| vn == seg) {
                        return Some(MirConstVal::Int(*disc));
                    }
                }
                if let Some(c) = self
                    .mir
                    .consts
                    .iter()
                    .find(|c| c.name == *name || short_name(&c.name) == seg)
                    && let Some(ref inner) = c.expr
                {
                    return self.hir_expr_to_mir_const_for_ty(inner, hint_ty.or(Some(&c.ty)));
                }
                match name.as_str() {
                    "vec2::ZERO" | "ivec2::ZERO" | "uvec2::ZERO" => {
                        Some(MirConstVal::Vec2([0.0, 0.0]))
                    }
                    "vec2::ONE" | "ivec2::ONE" | "uvec2::ONE" => {
                        Some(MirConstVal::Vec2([1.0, 1.0]))
                    }
                    "vec2::X" | "ivec2::X" | "uvec2::X" => Some(MirConstVal::Vec2([1.0, 0.0])),
                    "vec2::Y" | "ivec2::Y" | "uvec2::Y" => Some(MirConstVal::Vec2([0.0, 1.0])),
                    "vec3::ZERO" | "ivec3::ZERO" => Some(MirConstVal::Vec3([0.0, 0.0, 0.0])),
                    "vec3::ONE" | "ivec3::ONE" => Some(MirConstVal::Vec3([1.0, 1.0, 1.0])),
                    "vec3::X" | "ivec3::X" => Some(MirConstVal::Vec3([1.0, 0.0, 0.0])),
                    "vec3::Y" | "vec3::UP" | "ivec3::Y" => Some(MirConstVal::Vec3([0.0, 1.0, 0.0])),
                    "vec3::Z" | "ivec3::Z" => Some(MirConstVal::Vec3([0.0, 0.0, 1.0])),
                    "vec4::ZERO" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 0.0])),
                    "vec4::ONE" => Some(MirConstVal::Vec4([1.0, 1.0, 1.0, 1.0])),
                    "vec4::X" => Some(MirConstVal::Vec4([1.0, 0.0, 0.0, 0.0])),
                    "vec4::Y" => Some(MirConstVal::Vec4([0.0, 1.0, 0.0, 0.0])),
                    "vec4::Z" => Some(MirConstVal::Vec4([0.0, 0.0, 1.0, 0.0])),
                    "vec4::W" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 1.0])),
                    "mat3::ZERO" => Some(MirConstVal::Array(vec![MirConstVal::Float(0.0); 9])),
                    "mat3::IDENTITY" => Some(MirConstVal::Array(vec![
                        MirConstVal::Float(1.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(1.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(1.0),
                    ])),
                    "mat4::ZERO" => Some(MirConstVal::Array(vec![MirConstVal::Float(0.0); 16])),
                    "mat4::IDENTITY" => Some(MirConstVal::Array(vec![
                        MirConstVal::Float(1.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(1.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(1.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(0.0),
                        MirConstVal::Float(1.0),
                    ])),
                    _ => None,
                }
            }
            HirExpr::Unary { op, expr, .. } => match (op, self.hir_expr_to_mir_const(expr)?) {
                (HirUnOp::Neg, MirConstVal::Int(i)) => Some(MirConstVal::Int(i.wrapping_neg())),
                (HirUnOp::Neg, MirConstVal::Float(f)) => Some(MirConstVal::Float(-f)),
                (HirUnOp::Not, MirConstVal::Bool(b)) => Some(MirConstVal::Bool(!b)),
                (HirUnOp::BitNot, MirConstVal::Int(i)) => Some(MirConstVal::Int(!i)),
                _ => None,
            },
            HirExpr::Binary { op, lhs, rhs, .. } => {
                let l = self.hir_expr_to_mir_const(lhs)?;
                let r = self.hir_expr_to_mir_const(rhs)?;
                match (l, r) {
                    (MirConstVal::Int(a), MirConstVal::Int(b)) => match op {
                        HirBinOp::Add => Some(MirConstVal::Int(a.wrapping_add(b))),
                        HirBinOp::Sub => Some(MirConstVal::Int(a.wrapping_sub(b))),
                        HirBinOp::Mul => Some(MirConstVal::Int(a.wrapping_mul(b))),
                        HirBinOp::Div if b != 0 => Some(MirConstVal::Int(a.wrapping_div(b))),
                        HirBinOp::Rem if b != 0 => Some(MirConstVal::Int(a.wrapping_rem(b))),
                        HirBinOp::BitAnd => Some(MirConstVal::Int(a & b)),
                        HirBinOp::BitOr => Some(MirConstVal::Int(a | b)),
                        HirBinOp::BitXor => Some(MirConstVal::Int(a ^ b)),
                        HirBinOp::Shl => Some(MirConstVal::Int(a.wrapping_shl(b as u32))),
                        HirBinOp::Shr => Some(MirConstVal::Int(a.wrapping_shr(b as u32))),
                        HirBinOp::Eq => Some(MirConstVal::Bool(a == b)),
                        HirBinOp::Ne => Some(MirConstVal::Bool(a != b)),
                        HirBinOp::Lt => Some(MirConstVal::Bool(a < b)),
                        HirBinOp::Le => Some(MirConstVal::Bool(a <= b)),
                        HirBinOp::Gt => Some(MirConstVal::Bool(a > b)),
                        HirBinOp::Ge => Some(MirConstVal::Bool(a >= b)),
                        _ => None,
                    },
                    (MirConstVal::Bool(a), MirConstVal::Bool(b)) => match op {
                        HirBinOp::And => Some(MirConstVal::Bool(a && b)),
                        HirBinOp::Or => Some(MirConstVal::Bool(a || b)),
                        HirBinOp::Eq => Some(MirConstVal::Bool(a == b)),
                        HirBinOp::Ne => Some(MirConstVal::Bool(a != b)),
                        _ => None,
                    },
                    (a, b) => {
                        let fa = as_f64(&a)?;
                        let fb = as_f64(&b)?;
                        match op {
                            HirBinOp::Eq => Some(MirConstVal::Bool(fa == fb)),
                            HirBinOp::Ne => Some(MirConstVal::Bool(fa != fb)),
                            HirBinOp::Lt => Some(MirConstVal::Bool(fa < fb)),
                            HirBinOp::Le => Some(MirConstVal::Bool(fa <= fb)),
                            HirBinOp::Gt => Some(MirConstVal::Bool(fa > fb)),
                            HirBinOp::Ge => Some(MirConstVal::Bool(fa >= fb)),
                            _ => {
                                let res = match op {
                                    HirBinOp::Add => fa + fb,
                                    HirBinOp::Sub => fa - fb,
                                    HirBinOp::Mul => fa * fb,
                                    HirBinOp::Div => fa / fb,
                                    HirBinOp::Rem => fa % fb,
                                    _ => return None,
                                };
                                Some(MirConstVal::Float(res))
                            }
                        }
                    }
                }
            }
            HirExpr::ArrayLit { elems, ty } => {
                let elem_hint = match hint_ty.unwrap_or(ty) {
                    Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }
                        if !matches!(**elem, Ty::Unknown) =>
                    {
                        Some(elem.as_ref())
                    }
                    _ => None,
                };
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(self.hir_expr_to_mir_const_for_ty(e, elem_hint)?);
                }
                Some(MirConstVal::Array(out))
            }
            HirExpr::StructLit { name, fields, .. } => {
                let layout_idx = self.find_layout_idx(name).or_else(|| match hint_ty {
                    Some(Ty::Named(k)) => self.find_layout_idx(k),
                    _ => None,
                });
                let mut out_fields = Vec::with_capacity(fields.len());
                for (k, v) in fields {
                    let f_hint = layout_idx.and_then(|li| {
                        self.layouts[li]
                            .fields
                            .iter()
                            .find(|sf| !sf.is_padding && sf.name == *k)
                            .map(|sf| &sf.ty)
                    });
                    out_fields.push((k.clone(), self.hir_expr_to_mir_const_for_ty(v, f_hint)?));
                }
                Some(MirConstVal::Struct {
                    name: name.clone(),
                    fields: out_fields,
                })
            }
            HirExpr::Call(call) => match short_name(&call.callee) {
                "bits" => {
                    if matches!(hint_ty, Some(Ty::BitSet(_))) {
                        let mut bit_indices = Vec::new();
                        for arg in &call.args {
                            if let Some(MirConstVal::Int(b)) = self.hir_expr_to_mir_const(arg)
                                && b >= 0
                            {
                                bit_indices.push(MirConstVal::Int(b));
                            }
                        }
                        return Some(MirConstVal::Array(bit_indices));
                    }
                    let mut mask = 0u64;
                    for arg in &call.args {
                        if let Some(MirConstVal::Int(b)) = self.hir_expr_to_mir_const(arg)
                            && b >= 0
                            && (b as u32) < 64
                        {
                            mask |= 1u64 << (b as u32);
                        }
                    }
                    Some(MirConstVal::Int(mask as i64))
                }
                "vec2" | "Vec2" => {
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec2([a0, a1]))
                }
                "ivec2" | "IVec2" => {
                    let to_i32_f64 = |mc: &MirConstVal| -> Option<f64> {
                        match mc {
                            MirConstVal::Int(i) => Some(f64::from(*i as i32)),
                            MirConstVal::Float(f) => Some(f64::from(*f as i32)),
                            _ => None,
                        }
                    };
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_i32_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_i32_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec2([a0, a1]))
                }
                "uvec2" | "UVec2" => {
                    let to_u32_f64 = |mc: &MirConstVal| -> Option<f64> {
                        match mc {
                            MirConstVal::Int(i) => Some(f64::from(*i as u32)),
                            MirConstVal::Float(f) => Some(f64::from(*f as u32)),
                            _ => None,
                        }
                    };
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_u32_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_u32_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec2([a0, a1]))
                }
                "vec3" | "Vec3" => {
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a2 = call
                        .args
                        .get(2)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec3([a0, a1, a2]))
                }
                "ivec3" | "IVec3" => {
                    let to_i32_f64 = |mc: &MirConstVal| -> Option<f64> {
                        match mc {
                            MirConstVal::Int(i) => Some(f64::from(*i as i32)),
                            MirConstVal::Float(f) => Some(f64::from(*f as i32)),
                            _ => None,
                        }
                    };
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_i32_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_i32_f64(&m))
                        .unwrap_or(0.0);
                    let a2 = call
                        .args
                        .get(2)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| to_i32_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec3([a0, a1, a2]))
                }
                "vec3a" | "Vec3a" => {
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a2 = call
                        .args
                        .get(2)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec4([a0, a1, a2, 0.0]))
                }
                "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => {
                    let a0 = call
                        .args
                        .first()
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a1 = call
                        .args
                        .get(1)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a2 = call
                        .args
                        .get(2)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    let a3 = call
                        .args
                        .get(3)
                        .and_then(|e| self.hir_expr_to_mir_const(e))
                        .and_then(|m| as_f64(&m))
                        .unwrap_or(0.0);
                    Some(MirConstVal::Vec4([a0, a1, a2, a3]))
                }
                "mat3" | "Mat3" => {
                    let mut cols = Vec::with_capacity(call.args.len());
                    for a in &call.args {
                        cols.push(self.hir_expr_to_mir_const(a)?);
                    }
                    let floats = flatten_mat_floats(&cols, 9);
                    Some(MirConstVal::Array(
                        floats
                            .into_iter()
                            .map(|f| MirConstVal::Float(f64::from(f)))
                            .collect(),
                    ))
                }
                "mat4" | "Mat4" => {
                    let mut cols = Vec::with_capacity(call.args.len());
                    for a in &call.args {
                        cols.push(self.hir_expr_to_mir_const(a)?);
                    }
                    let floats = flatten_mat_floats(&cols, 16);
                    Some(MirConstVal::Array(
                        floats
                            .into_iter()
                            .map(|f| MirConstVal::Float(f64::from(f)))
                            .collect(),
                    ))
                }
                "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => call
                    .args
                    .first()
                    .and_then(|e| self.hir_expr_to_mir_const(e)),
                _ => None,
            },
            _ => None,
        }
    }

    pub(super) fn resolve_sema_field_ty(
        &self,
        l_idx: usize,
        field: &str,
        offset_bytes: usize,
    ) -> Option<Ty> {
        let mut cur_l = l_idx;
        if !field.is_empty() && field.contains('.') {
            let parts: Vec<&str> = field.split('.').collect();
            for (pi, seg) in parts.iter().enumerate() {
                let sf = self.layouts[cur_l]
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && f.name == *seg)?;
                if pi + 1 == parts.len() {
                    return Some(sf.ty.clone());
                }
                if let Ty::Named(ref inner) = sf.ty {
                    cur_l = self.find_layout_idx(inner)?;
                } else {
                    return None;
                }
            }
        }
        fn find_by_name_or_off(
            ctx: &EmitCtx<'_>,
            fields: &[SolvedField],
            field: &str,
            rel_off: usize,
        ) -> Option<Ty> {
            if !field.is_empty()
                && let Some(sf) = fields.iter().find(|f| !f.is_padding && f.name == field)
            {
                return Some(sf.ty.clone());
            }
            for f in fields {
                if f.is_padding {
                    continue;
                }
                if f.offset == rel_off {
                    return Some(f.ty.clone());
                }
                if rel_off > f.offset
                    && rel_off < f.offset + f.size
                    && let Ty::Named(ref inner) = f.ty
                    && let Some(sub_li) = ctx.find_layout_idx(inner)
                    && let Some(sub_ty) = find_by_name_or_off(
                        ctx,
                        &ctx.layouts[sub_li].fields,
                        field,
                        rel_off - f.offset,
                    )
                {
                    return Some(sub_ty);
                }
            }
            None
        }
        find_by_name_or_off(self, &self.layouts[l_idx].fields, field, offset_bytes)
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

pub(super) fn is_child_of_rel(rel: &str) -> bool {
    rel == "ChildOf" || rel.ends_with("::ChildOf") || rel == bamabi_sys::BAM_CHILD_OF_NAME
}

pub(super) fn custom_rel_parent_comp(rel: &str) -> String {
    format!("__strata_rel_parent_{}", short_name(rel))
}

fn merge_term_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    if a == b {
        return a;
    }
    if matches!(a, TermAccessMode::StreamRead | TermAccessMode::StreamWrite)
        && matches!(b, TermAccessMode::StreamRead | TermAccessMode::StreamWrite)
    {
        return if a == TermAccessMode::StreamWrite || b == TermAccessMode::StreamWrite {
            TermAccessMode::StreamWrite
        } else {
            TermAccessMode::StreamRead
        };
    }
    let classify = |m: TermAccessMode| -> (bool, bool, bool) {
        match m {
            TermAccessMode::Write => (true, true, false),
            TermAccessMode::SelectiveWrite => (true, true, true),
            TermAccessMode::OptionalWrite => (false, true, false),
            TermAccessMode::OptionalRead => (false, false, false),
            _ => (true, false, false),
        }
    };
    let (ra, wa, sa) = classify(a);
    let (rb, wb, sb) = classify(b);
    let req = ra || rb;
    let write = wa || wb;
    let sel = (wa && sa || !wa) && (wb && sb || !wb) && (sa || sb);
    match (req, write, sel) {
        (true, true, true) => TermAccessMode::SelectiveWrite,
        (true, true, false) => TermAccessMode::Write,
        (true, false, _) => TermAccessMode::Read,
        (false, true, _) => TermAccessMode::OptionalWrite,
        (false, false, _) => TermAccessMode::OptionalRead,
    }
}

fn pack_bitset_bytes(val: &MirConstVal, byte_len: usize) -> Vec<u8> {
    let mut packed = vec![0u8; byte_len];
    match val {
        MirConstVal::Int(bits) => {
            let le = (*bits as u64).to_le_bytes();
            let n = byte_len.min(le.len());
            packed[..n].copy_from_slice(&le[..n]);
        }
        MirConstVal::Array(elems) => {
            for ev in elems {
                if let MirConstVal::Int(b) = ev
                    && *b >= 0
                    && ((*b as usize) / 8) < packed.len()
                {
                    let bi = *b as usize;
                    packed[bi / 8] |= 1u8 << (bi % 8);
                }
            }
        }
        _ => {}
    }
    packed
}

fn flatten_mat_floats(elems: &[MirConstVal], count: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(count);
    for e in elems {
        if out.len() >= count {
            break;
        }
        match e {
            MirConstVal::Float(f) => out.push(*f as f32),
            MirConstVal::Int(i) => out.push(*i as f32),
            MirConstVal::Vec3(v) => {
                for &x in v {
                    if out.len() < count {
                        out.push(x as f32);
                    }
                }
            }
            MirConstVal::Vec4(v) => {
                for &x in v {
                    if out.len() < count {
                        out.push(x as f32);
                    }
                }
            }
            MirConstVal::Vec2(v) => {
                for &x in v {
                    if out.len() < count {
                        out.push(x as f32);
                    }
                }
            }
            _ => {}
        }
    }
    while out.len() < count {
        out.push(0.0f32);
    }
    out
}

fn parse_mir_debug_ty(s: &str) -> Option<Ty> {
    let s = s.trim();
    match s {
        "Bool" => Some(Ty::Bool),
        "U8" => Some(Ty::U8),
        "I8" => Some(Ty::I8),
        "U16" => Some(Ty::U16),
        "I16" => Some(Ty::I16),
        "U32" => Some(Ty::U32),
        "I32" => Some(Ty::I32),
        "Fix32" => Some(Ty::Fix32),
        "Sym" => Some(Ty::Sym),
        "Rgba8" => Some(Ty::Rgba8),
        "U64" => Some(Ty::U64),
        "I64" => Some(Ty::I64),
        "Fix64" => Some(Ty::Fix64),
        "F32" => Some(Ty::F32),
        "F64" => Some(Ty::F64),
        "Vec2" => Some(Ty::Vec2),
        "Vec3" => Some(Ty::Vec3),
        "Vec3a" => Some(Ty::Vec3a),
        "Vec4" => Some(Ty::Vec4),
        "Quat" => Some(Ty::Quat),
        "Rgba" => Some(Ty::Rgba),
        "IVec2" => Some(Ty::IVec2),
        "IVec3" => Some(Ty::IVec3),
        "UVec2" => Some(Ty::UVec2),
        "Mat3" => Some(Ty::Mat3),
        "Mat4" => Some(Ty::Mat4),
        "GraceWindow" => Some(Ty::GraceWindow),
        _ if s.starts_with("UnitScalar") => Some(Ty::F32),
        _ if s.starts_with("BitSet(") && s.ends_with(')') => {
            let b = s["BitSet(".len()..s.len() - 1].trim().parse().ok()?;
            Some(Ty::BitSet(b))
        }
        _ if s.starts_with("InlineStr(") && s.ends_with(')') => {
            let cap = s["InlineStr(".len()..s.len() - 1].trim().parse().ok()?;
            Some(Ty::InlineStr(cap))
        }
        _ if s.starts_with("Named(") && s.ends_with(')') => {
            let inner = s["Named(".len()..s.len() - 1].trim().trim_matches('"');
            Some(Ty::Named(inner.to_owned()))
        }
        _ if s.starts_with("Ref(") && s.ends_with(')') => {
            let inner = s["Ref(".len()..s.len() - 1].trim().trim_matches('"');
            Some(Ty::Ref(inner.to_owned()))
        }
        _ if s.starts_with("InputBuffer") => {
            if let Some(cap_pos) = s.rfind("cap:") {
                let after = &s[cap_pos + 4..];
                let digits: String = after
                    .trim_start()
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                let cap = digits.parse().ok()?;
                return Some(Ty::InputBuffer {
                    action: String::new(),
                    cap,
                });
            }
            None
        }
        _ if s.starts_with("SmallVec") => {
            if let Some(elem_pos) = s.find("elem:")
                && let Some(cap_pos) = s.rfind(", cap:")
            {
                let elem_s = &s[elem_pos + 5..cap_pos];
                let cap_s = s[cap_pos + 6..].trim().trim_end_matches('}').trim();
                let elem = parse_mir_debug_ty(elem_s)?;
                let cap = cap_s.parse().ok()?;
                return Some(Ty::SmallVec {
                    elem: Box::new(elem),
                    cap,
                });
            }
            None
        }
        _ if s.starts_with("Array") => {
            if let Some(elem_pos) = s.find("elem:")
                && let Some(len_pos) = s.rfind(", len:")
            {
                let elem_s = &s[elem_pos + 5..len_pos];
                let len_s = s[len_pos + 6..].trim().trim_end_matches('}').trim();
                let elem = parse_mir_debug_ty(elem_s)?;
                let len = len_s.parse().ok()?;
                return Some(Ty::Array {
                    elem: Box::new(elem),
                    len,
                });
            }
            None
        }
        _ => None,
    }
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
        MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => (8, 4),
        MirType::Vec3 | MirType::IVec3 => (12, 4),
        MirType::Vec4 => (16, 4),
        MirType::Array { elem, len } => {
            let (sz, al) = approx_mir_size_align(elem);
            (sz.saturating_mul(*len as u32), al)
        }
    }
}

fn c99_schedule_nodes_contain(nodes: &[HirScheduleGroup], fn_name: &str) -> bool {
    let fshort = short_name(fn_name);
    nodes.iter().any(|n| {
        (n.kind == "leaf" && (n.name == fn_name || short_name(&n.name) == fshort))
            || c99_schedule_nodes_contain(&n.children, fn_name)
    })
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

fn c_i32_lit(v: i32) -> String {
    if v == i32::MIN {
        "((int32_t)(-2147483647 - 1))".to_string()
    } else {
        format!("((int32_t){v})")
    }
}

fn c_i64_lit(v: i64) -> String {
    if v == i64::MIN {
        "((int64_t)(-9223372036854775807ll - 1ll))".to_string()
    } else {
        format!("((int64_t){v}ll)")
    }
}

fn c_f32(v: f32) -> String {
    if v.is_nan() {
        return "NAN".to_string();
    }
    if v.is_infinite() {
        return if v.is_sign_positive() {
            "INFINITY".to_string()
        } else {
            "(-INFINITY)".to_string()
        };
    }
    let s = format!("{v}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        format!("{s}f")
    } else {
        format!("{s}.0f")
    }
}

fn c_f64(v: f64) -> String {
    if v.is_nan() {
        return "((double)NAN)".to_string();
    }
    if v.is_infinite() {
        return if v.is_sign_positive() {
            "((double)INFINITY)".to_string()
        } else {
            "((double)(-INFINITY))".to_string()
        };
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
            | (Ty::IVec2, MirType::IVec2)
            | (Ty::IVec3, MirType::IVec3)
            | (Ty::UVec2, MirType::UVec2)
    ) || matches!(
        (sema, mir),
        (Ty::Named(a), MirType::Named(b)) if a == b || short_name(a) == short_name(b)
    ) || matches!((sema, mir), (Ty::Named(_), MirType::I32))
}
