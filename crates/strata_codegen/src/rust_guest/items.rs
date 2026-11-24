//! RustGuest catalog collection, crate/layout/net emission, and bridge pointer helpers.

use super::*;

#[derive(Clone)]
pub(super) struct ComponentEntry {
    pub(super) id: usize,
    pub(super) struct_name: String,
    pub(super) handle_field: String,
    pub(super) variant_name: String,
    pub(super) canonical_name: String,
    pub(super) short_name: String,
    pub(super) layout: SolvedLayout,
    pub(super) register_dynamic: bool,
}

impl ComponentEntry {
    pub(super) fn is_resource_like(&self) -> bool {
        matches!(
            self.layout.item_kind,
            SchemaItemKind::Resource | SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
        )
    }
}

#[derive(Clone)]
pub(super) struct RelationEntry {
    pub(super) handle_field: String,
    pub(super) canonical_name: String,
    pub(super) flags: Vec<String>,
    pub(super) uuid_bytes: [u8; 16],
    pub(super) payload_comp_id: Option<usize>,
}

#[derive(Clone)]
pub(super) struct TableEntry {
    pub(super) name: String,
    pub(super) struct_name: String,
    pub(super) variant_name: String,
    pub(super) lookup_fn: String,
    pub(super) fields: Vec<(String, Ty)>,
}

pub(super) struct GuestCatalog {
    pub(super) components: Vec<ComponentEntry>,
    pub(super) topo_order: Vec<usize>,
    pub(super) relations: Vec<RelationEntry>,
    pub(super) tables: Vec<TableEntry>,
}

impl GuestCatalog {
    pub(super) fn build(mir: &MirModule, stem: &str) -> Self {
        let mut components = Vec::new();
        for (idx, layout) in mir.layouts.iter().enumerate() {
            let ident = sanitize_ident(&layout.canonical_name);
            let struct_name = format!("Strata{ident}_{idx}");
            let handle_field = format!("comp_{idx}_{ident}");
            let variant_name = format!("L{idx}_{ident}");
            let short_name = layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&layout.canonical_name)
                .to_owned();
            let register_dynamic = is_ecs_component_kind(layout.item_kind)
                || matches!(
                    layout.item_kind,
                    SchemaItemKind::Resource
                        | SchemaItemKind::Event
                        | SchemaItemKind::Stream
                        | SchemaItemKind::SpatialGrid
                        | SchemaItemKind::SpatialHistory
                );
            components.push(ComponentEntry {
                id: idx,
                struct_name,
                handle_field,
                variant_name,
                canonical_name: layout.canonical_name.clone(),
                short_name,
                layout: layout.clone(),
                register_dynamic,
            });
        }

        // Collect all external/tag component names referenced across MIR not already in mir.layouts.
        let mut extra_tags: BTreeSet<String> = BTreeSet::new();
        let mut maybe_add_tag = |name: &str| {
            let trimmed = name.trim();
            if trimmed.is_empty()
                || trimmed == "Entity"
                || trimmed == "entity"
                || trimmed == "()"
                || trimmed.starts_with('[')
            {
                return;
            }
            if find_comp_idx(&components, trimmed).is_none()
                && !mir.tables.iter().any(|t| t.name == trimmed)
                && !mir.enums.iter().any(|e| {
                    e.canonical_name == trimmed
                        || e.canonical_name.rsplit("::").next() == Some(trimmed)
                })
            {
                extra_tags.insert(trimmed.to_owned());
            }
        };

        for func in mir.functions.iter().chain(mir.fns.iter()) {
            if let MirFnKind::Observer {
                event, target_comp, ..
            } = &func.kind
            {
                maybe_add_tag(event);
                if let Some(tc) = target_comp {
                    maybe_add_tag(tc);
                }
            }
            for r in &func.resources {
                maybe_add_tag(&r.canonical_name);
            }
            for qb in &func.query_bindings {
                for t in &qb.terms {
                    maybe_add_tag(&t.canonical_component);
                }
                for f in &qb.with_filters {
                    maybe_add_tag(f);
                }
                for f in &qb.without_filters {
                    maybe_add_tag(f);
                }
            }
            for bb in &func.blocks {
                for st in &bb.stmts {
                    match &st.inst {
                        Inst::CmdSpawn { components: cs, .. }
                        | Inst::CmdSpawnBatch { components: cs, .. }
                        | Inst::SpawnBatchPush { components: cs, .. } => {
                            for (c, _) in cs {
                                maybe_add_tag(c);
                            }
                        }
                        Inst::SpawnBatchBegin { components: cs, .. } => {
                            for c in cs {
                                maybe_add_tag(c);
                            }
                        }
                        Inst::CmdDespawnAll { filter } => {
                            for (_, cname) in parse_despawn_filter_terms(filter) {
                                maybe_add_tag(cname);
                            }
                        }
                        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
                            maybe_add_tag(component);
                        }
                        Inst::CmdTrigger { event, .. }
                        | Inst::TriggerPayload { event }
                        | Inst::StreamEmit { stream: event, .. } => maybe_add_tag(event),
                        Inst::SpatialRebuildCsr { over_component, .. } => {
                            maybe_add_tag(over_component);
                        }
                        _ => {}
                    }
                }
            }
        }
        for obj in &mir.objects {
            for c in &obj.components {
                maybe_add_tag(c);
            }
            for init in &obj.inits {
                let cname = init
                    .canonical_component
                    .as_deref()
                    .unwrap_or(&init.component);
                maybe_add_tag(cname);
            }
        }
        for rel in &mir.relations {
            if let Some(ref pl) = rel.payload_layout {
                maybe_add_tag(&pl.canonical_name);
            }
        }

        // Deduplicate tags by sanitized short/canonical identity (prefer qualified canonical name).
        let mut seen_tag_shorts: HashMap<String, String> = HashMap::new();
        for raw in extra_tags {
            let short = raw.rsplit("::").next().unwrap_or(&raw).to_owned();
            let entry = seen_tag_shorts.entry(short).or_insert_with(|| raw.clone());
            if raw.contains("::") && !entry.contains("::") {
                *entry = raw;
            }
        }
        let _ = stem;
        for (_short, canon_or_short) in seen_tag_shorts {
            if find_comp_idx(&components, &canon_or_short).is_some() {
                continue;
            }
            let id = components.len();
            // Check relation payload layout if matching
            let layout = if let Some(pl) = mir.relations.iter().find_map(|r| {
                r.payload_layout.as_ref().filter(|l| {
                    l.canonical_name == canon_or_short
                        || l.canonical_name.rsplit("::").next() == Some(canon_or_short.as_str())
                })
            }) {
                pl.clone()
            } else {
                let canon_name = if canon_or_short.contains("::") || mir.module_path.is_empty() {
                    canon_or_short
                } else {
                    format!("{}::{canon_or_short}", mir.module_path)
                };
                let (uuid, fp) = compute_wire_identity(&canon_name, 0, 1, 0, true, &[]);
                SolvedLayout {
                    canonical_name: canon_name,
                    item_kind: SchemaItemKind::Component,
                    fields: Vec::new(),
                    size: 0,
                    align: 1,
                    is_abi_pod: true,
                    component_flags: 0,
                    uuid_bytes: *uuid.as_bytes(),
                    uuid_hex: format!("{uuid:?}"),
                    schema_fingerprint: fp,
                    required_components: Vec::new(),
                    explicit_pad_bytes: 0,
                }
            };
            let ident = sanitize_ident(&layout.canonical_name);
            let short_name = layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&layout.canonical_name)
                .to_owned();
            components.push(ComponentEntry {
                id,
                struct_name: format!("StrataTag_{ident}_{id}"),
                handle_field: format!("comp_{id}_{ident}"),
                variant_name: format!("L{id}_{ident}"),
                canonical_name: layout.canonical_name.clone(),
                short_name,
                layout,
                register_dynamic: true,
            });
        }

        // Topological sort by `required_components` so dependencies register before dependents.
        let mut topo_order = Vec::with_capacity(components.len());
        let mut visited = vec![0u8; components.len()];
        fn visit(
            id: usize,
            components: &[ComponentEntry],
            visited: &mut [u8],
            out: &mut Vec<usize>,
        ) {
            if visited[id] != 0 {
                return;
            }
            visited[id] = 1;
            for req in &components[id].layout.required_components {
                if let Some(dep_id) = find_comp_idx(components, req) {
                    visit(dep_id, components, visited, out);
                }
            }
            visited[id] = 2;
            out.push(id);
        }
        for i in 0..components.len() {
            visit(i, &components, &mut visited, &mut topo_order);
        }

        let mut relations = Vec::with_capacity(mir.relations.len());
        for (idx, rel) in mir.relations.iter().enumerate() {
            let ident = sanitize_ident(&rel.canonical_name);
            let (sz, al) = rel
                .payload_layout
                .as_ref()
                .map_or((0usize, 1usize), |l| (l.size, l.align.max(1)));
            let payload_comp_id = rel
                .payload_layout
                .as_ref()
                .and_then(|l| find_comp_idx(&components, &l.canonical_name));
            let schema_hash = rel
                .payload_layout
                .as_ref()
                .map_or(0, |l| l.schema_fingerprint);
            let uuid =
                bamabi_sys::ComponentUuid::from_parts(&rel.canonical_name, sz, al, schema_hash);
            relations.push(RelationEntry {
                handle_field: format!("rel_{idx}_{ident}"),
                canonical_name: rel.canonical_name.clone(),
                flags: rel.flags.clone(),
                uuid_bytes: *uuid.as_bytes(),
                payload_comp_id,
            });
        }

        let mut tables = Vec::with_capacity(mir.tables.len());
        for (idx, t) in mir.tables.iter().enumerate() {
            let ident = sanitize_ident(&t.name);
            tables.push(TableEntry {
                name: t.name.clone(),
                struct_name: format!("StrataTableRow_{ident}_{idx}"),
                variant_name: format!("T{idx}_{ident}"),
                lookup_fn: format!("strata_table_lookup_{ident}_{idx}"),
                fields: t.fields.clone(),
            });
        }

        Self {
            components,
            topo_order,
            relations,
            tables,
        }
    }

    pub(super) fn resolve_comp(&self, key: &str) -> Option<&ComponentEntry> {
        find_comp_idx(&self.components, key).map(|id| &self.components[id])
    }

    pub(super) fn resolve_rel(&self, key: &str) -> Option<&RelationEntry> {
        let short = key.rsplit("::").next().unwrap_or(key);
        self.relations.iter().find(|r| {
            r.canonical_name == key
                || r.canonical_name.rsplit("::").next() == Some(short)
                || sanitize_ident(&r.canonical_name) == sanitize_ident(key)
        })
    }

    pub(super) fn resolve_table(&self, key: &str) -> Option<&TableEntry> {
        let short = key.rsplit("::").next().unwrap_or(key);
        self.tables.iter().find(|t| {
            t.name == key || t.name == short || sanitize_ident(&t.name) == sanitize_ident(key)
        })
    }
}

pub(super) fn parse_despawn_filter_terms(filter: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    for raw in filter.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(inner) = t
            .strip_prefix("With<")
            .or_else(|| t.strip_prefix("with<"))
            .and_then(|s| s.strip_suffix('>'))
        {
            out.push((false, inner.trim()));
        } else if let Some(inner) = t
            .strip_prefix("Without<")
            .or_else(|| t.strip_prefix("without<"))
            .and_then(|s| s.strip_suffix('>'))
        {
            out.push((true, inner.trim()));
        } else {
            out.push((false, t));
        }
    }
    out
}

pub(super) fn find_comp_idx(components: &[ComponentEntry], key: &str) -> Option<usize> {
    let base = key.trim();
    if base.is_empty() {
        return None;
    }
    // Try full name first (preserving `PlayerBody::hot` / `CombatantBody::caps`)
    if let Some(pos) = components.iter().position(|c| c.canonical_name == base) {
        return Some(pos);
    }
    let prefix = base.split('.').next().unwrap_or(base);
    if let Some(pos) = components.iter().position(|c| c.canonical_name == prefix) {
        return Some(pos);
    }
    let short = prefix.rsplit("::").next().unwrap_or(prefix);
    if let Some(pos) = components.iter().position(|c| {
        c.short_name == short
            || c.canonical_name.ends_with(&format!("::{prefix}"))
            || sanitize_ident(&c.canonical_name) == sanitize_ident(prefix)
    }) {
        return Some(pos);
    }
    components.iter().position(|c| {
        c.canonical_name
            .rsplit("::")
            .next()
            .is_some_and(|s| s == short)
            || sanitize_ident(&c.short_name) == sanitize_ident(short)
    })
}

/// Physical query representation deduplicating terms that project different fields of the same
/// component (e.g. `hp: &mut? DroneHull.hp, heat: &mut? DroneHull.heat` -> 1 `DroneHull` column).
#[derive(Clone)]
pub(super) struct PhysicalQueryTerm {
    pub(super) comp_id: usize,
    pub(super) mode: TermAccessMode,
    pub(super) is_sparse: bool,
    pub(super) changed_filter: bool,
    pub(super) added_filter: bool,
}

#[derive(Clone)]
pub(super) struct PhysicalQuery {
    pub(super) terms: Vec<PhysicalQueryTerm>,
    pub(super) with_filters: Vec<usize>,
    pub(super) without_filters: Vec<usize>,
    pub(super) extra_changed_filters: Vec<usize>,
    pub(super) extra_added_filters: Vec<usize>,
    /// Maps MIR `term_idx` -> `phys_col`
    pub(super) term_to_phys: HashMap<u32, usize>,
}

pub(super) fn build_physical_queries(func: &MirFunction, cat: &GuestCatalog) -> Vec<PhysicalQuery> {
    func.query_bindings
        .iter()
        .map(|qb| build_one_physical_query(func, qb, cat))
        .collect()
}

pub(super) fn build_one_physical_query(
    func: &MirFunction,
    qb: &MirQueryBinding,
    cat: &GuestCatalog,
) -> PhysicalQuery {
    let mut terms: Vec<PhysicalQueryTerm> = Vec::new();
    let mut with_filters: Vec<usize> = Vec::new();
    let mut without_filters: Vec<usize> = Vec::new();
    let mut extra_changed_filters: Vec<usize> = Vec::new();
    let mut extra_added_filters: Vec<usize> = Vec::new();
    let mut comp_to_phys: HashMap<usize, usize> = HashMap::new();
    let mut term_to_phys: HashMap<u32, usize> = HashMap::new();

    for t in &qb.terms {
        let Some(comp) = cat.resolve_comp(&t.canonical_component) else {
            continue;
        };
        if t.mode == TermAccessMode::With {
            if !comp_to_phys.contains_key(&comp.id) && !with_filters.contains(&comp.id) {
                with_filters.push(comp.id);
            }
            continue;
        }
        if t.mode == TermAccessMode::Without {
            if !comp_to_phys.contains_key(&comp.id) && !without_filters.contains(&comp.id) {
                without_filters.push(comp.id);
            }
            continue;
        }
        let is_changed = func.changed_terms.iter().any(|ct| {
            ct.query_idx == qb.query_idx
                && (ct.term_idx == t.term_idx || ct.canonical_component == t.canonical_component)
        });
        let is_added = func.added_terms.iter().any(|at| {
            at.query_idx == qb.query_idx
                && (at.term_idx == t.term_idx || at.canonical_component == t.canonical_component)
        });
        if let Some(&existing_phys) = comp_to_phys.get(&comp.id) {
            let pt = &mut terms[existing_phys];
            pt.mode = merge_access_mode(pt.mode, t.mode);
            pt.is_sparse |= t.is_sparse;
            pt.changed_filter |= is_changed;
            pt.added_filter |= is_added;
            term_to_phys.insert(t.term_idx, existing_phys);
        } else {
            let phys_col = terms.len();
            comp_to_phys.insert(comp.id, phys_col);
            term_to_phys.insert(t.term_idx, phys_col);
            terms.push(PhysicalQueryTerm {
                comp_id: comp.id,
                mode: t.mode,
                is_sparse: (comp.layout.component_flags
                    & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                    != 0,
                changed_filter: is_changed,
                added_filter: is_added,
            });
        }
    }

    for f in &qb.with_filters {
        if let Some(c) = cat.resolve_comp(f)
            && !comp_to_phys.contains_key(&c.id)
            && !with_filters.contains(&c.id)
        {
            with_filters.push(c.id);
        }
    }
    for f in &qb.without_filters {
        if let Some(c) = cat.resolve_comp(f)
            && !comp_to_phys.contains_key(&c.id)
            && !without_filters.contains(&c.id)
        {
            without_filters.push(c.id);
        }
    }
    if let Some(qdesc) = func.queries.get(qb.query_idx as usize) {
        for cf in &qdesc.changed_filters {
            if let Some(c) = cat.resolve_comp(cf)
                && !comp_to_phys.contains_key(&c.id)
                && !extra_changed_filters.contains(&c.id)
            {
                extra_changed_filters.push(c.id);
            }
        }
    }
    for (qi, af) in &func.added_filters {
        if *qi == qb.query_idx
            && let Some(c) = cat.resolve_comp(af)
            && !comp_to_phys.contains_key(&c.id)
            && !extra_added_filters.contains(&c.id)
        {
            extra_added_filters.push(c.id);
        }
    }

    // Remove redundant `With` if already present as data term
    with_filters.retain(|id| !comp_to_phys.contains_key(id));

    PhysicalQuery {
        terms,
        with_filters,
        without_filters,
        extra_changed_filters,
        extra_added_filters,
        term_to_phys,
    }
}

pub(super) fn compute_guest_query_emit_plan(
    phys_queries: &[PhysicalQuery],
) -> (Vec<u32>, Vec<usize>) {
    #[derive(Default)]
    struct QueryAccessSummary {
        with_set: HashSet<usize>,
        without_set: HashSet<usize>,
        reads: HashSet<usize>,
        writes: HashSet<usize>,
    }

    let n = phys_queries.len();
    if n <= 1 {
        return (vec![0; n], (0..n).collect());
    }

    let mut summaries: Vec<QueryAccessSummary> = Vec::with_capacity(n);
    for pq in phys_queries {
        let mut sum = QueryAccessSummary::default();
        for pt in &pq.terms {
            match pt.mode {
                TermAccessMode::With => {
                    sum.with_set.insert(pt.comp_id);
                }
                TermAccessMode::Without => {
                    sum.without_set.insert(pt.comp_id);
                }
                TermAccessMode::Read => {
                    sum.with_set.insert(pt.comp_id);
                    sum.reads.insert(pt.comp_id);
                }
                TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                    sum.with_set.insert(pt.comp_id);
                    sum.writes.insert(pt.comp_id);
                }
                TermAccessMode::OptionalRead => {
                    sum.reads.insert(pt.comp_id);
                    if pt.changed_filter || pt.added_filter {
                        sum.with_set.insert(pt.comp_id);
                    }
                }
                TermAccessMode::OptionalWrite => {
                    sum.writes.insert(pt.comp_id);
                    if pt.changed_filter || pt.added_filter {
                        sum.with_set.insert(pt.comp_id);
                    }
                }
                TermAccessMode::StreamRead | TermAccessMode::ResRead => {
                    sum.reads.insert(pt.comp_id);
                }
                TermAccessMode::StreamWrite | TermAccessMode::ResWrite => {
                    sum.writes.insert(pt.comp_id);
                }
                TermAccessMode::Allow | TermAccessMode::Has | TermAccessMode::RemovedRead => {}
            }
        }
        for &cid in &pq.with_filters {
            sum.with_set.insert(cid);
        }
        for &cid in &pq.without_filters {
            sum.without_set.insert(cid);
        }
        for &cid in &pq.extra_changed_filters {
            sum.with_set.insert(cid);
            if !sum.writes.contains(&cid) {
                sum.reads.insert(cid);
            }
        }
        for &cid in &pq.extra_added_filters {
            sum.with_set.insert(cid);
            if !sum.writes.contains(&cid) {
                sum.reads.insert(cid);
            }
        }
        summaries.push(sum);
    }

    let mut adj = vec![Vec::new(); n];
    for i in 0..n {
        for j in (i + 1)..n {
            let a = &summaries[i];
            let b = &summaries[j];
            if !a.with_set.is_disjoint(&b.without_set) || !b.with_set.is_disjoint(&a.without_set) {
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

    let mut remap = vec![0usize; n];
    let mut emitted_groups: HashSet<u32> = HashSet::new();
    let mut next_emitted = 0usize;
    for qi in 0..n {
        let g = groups[qi];
        if g == 0 {
            remap[qi] = next_emitted;
            next_emitted += 1;
        } else if emitted_groups.insert(g) {
            for qj in 0..n {
                if groups[qj] == g {
                    remap[qj] = next_emitted;
                    next_emitted += 1;
                }
            }
        }
    }

    (groups, remap)
}

#[inline]
pub(super) fn remap_qi(query_remap: &[usize], mir_qi: usize) -> usize {
    query_remap.get(mir_qi).copied().unwrap_or(mir_qi)
}

pub(super) fn merge_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    use TermAccessMode as M;
    match (a, b) {
        (M::Write, _) | (_, M::Write) => M::Write,
        (M::SelectiveWrite, _) | (_, M::SelectiveWrite) => M::SelectiveWrite,
        (M::OptionalWrite, _) | (_, M::OptionalWrite) => M::OptionalWrite,
        (M::Read, _) | (_, M::Read) => M::Read,
        (M::OptionalRead, _) | (_, M::OptionalRead) => M::OptionalRead,
        (M::Has, _) | (_, M::Has) => M::Has,
        _ => a,
    }
}

// ============================================================================
// Header, Enums, Constants, Tables, Curves, Layouts
// ============================================================================

pub(super) fn emit_crate_header(out: &mut String) {
    writeln!(out, "#![forbid(unsafe_code)]").ok();
    writeln!(
        out,
        "#![allow(unused_imports, dead_code, unused_variables, unused_mut, unused_parens, non_camel_case_types, non_snake_case, non_upper_case_globals, clippy::all)]"
    )
    .ok();
    writeln!(
        out,
        "//! Auto-generated Safe Rust Guest mod (`#![forbid(unsafe_code)]`, zero `bevy*` deps)."
    )
    .ok();
    writeln!(out).ok();
    writeln!(
        out,
        "use bamabi_guest::{{BAM_STORAGE_FLAG_MESSAGE, BAM_STORAGE_FLAG_RESOURCE}};"
    )
    .ok();
    writeln!(out, "use bamabi_guest::SymbolEntry;").ok();
    writeln!(out, "use bamabi_guest::commands::SpawnBatchColumn;").ok();
    writeln!(out, "use bamabi_guest::prelude::*;").ok();
    writeln!(out, "use bamabi_guest::raw::BamTermDesc;").ok();
    writeln!(out, "use core::ffi::CStr;").ok();
    writeln!(out, "use std::collections::HashMap;").ok();
    writeln!(out, "use std::sync::{{Arc, Mutex}};").ok();
    writeln!(out).ok();
}

pub(super) fn emit_enums_and_consts(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, en) in mir.enums.iter().enumerate() {
        let ident = sanitize_ident(&en.canonical_name);
        writeln!(out, "pub mod enum_{ident}_{idx} {{").ok();
        for (vname, disc) in &en.variants {
            let vident = sanitize_rust_ident(vname);
            writeln!(out, "    pub const {vident}: i64 = {disc};").ok();
        }
        writeln!(out, "}}").ok();
    }
    for c in &mir.consts {
        if let Some(ref expr) = c.expr {
            let val_s = format_hir_expr_rust(expr, &c.ty, mir, cat);
            let rty = const_rust_ty(&c.ty, mir, cat);
            let cname = sanitize_ident(&c.name).to_ascii_uppercase();
            writeln!(out, "pub const STRATA_CONST_{cname}: {rty} = {val_s};").ok();
        }
    }
    if !mir.enums.is_empty() || !mir.consts.is_empty() {
        writeln!(out).ok();
    }
}

pub(super) fn parse_mir_smallvec_debug(name: &str) -> Option<(Ty, usize)> {
    let inner = name.strip_prefix("SmallVec<")?.strip_suffix('>')?;
    let (elem_str, cap_str) = inner.rsplit_once(',')?;
    let cap = cap_str.trim().parse::<usize>().ok()?;
    let elem = parse_sema_debug_ty(elem_str.trim())?;
    Some((elem, cap))
}

pub(super) fn parse_mir_input_buffer(name: &str) -> Option<(String, usize)> {
    let inner = name.strip_prefix("InputBuffer<")?.strip_suffix('>')?;
    let (act, cap_str) = inner.rsplit_once(',')?;
    let cap = cap_str.trim().parse::<usize>().ok()?;
    Some((act.trim().to_owned(), cap))
}

pub(super) fn parse_sema_debug_ty(s: &str) -> Option<Ty> {
    let s = s.trim();
    match s {
        "Unit" => Some(Ty::Unit),
        "Bool" => Some(Ty::Bool),
        "U8" => Some(Ty::U8),
        "I8" => Some(Ty::I8),
        "U16" => Some(Ty::U16),
        "I16" => Some(Ty::I16),
        "U32" => Some(Ty::U32),
        "I32" => Some(Ty::I32),
        "U64" => Some(Ty::U64),
        "I64" => Some(Ty::I64),
        "F32" => Some(Ty::F32),
        "F64" => Some(Ty::F64),
        "Fix32" => Some(Ty::Fix32),
        "Fix64" => Some(Ty::Fix64),
        "Sym" => Some(Ty::Sym),
        "Rgba8" => Some(Ty::Rgba8),
        "Vec2" => Some(Ty::Vec2),
        "Vec3" => Some(Ty::Vec3),
        "Vec3a" => Some(Ty::Vec3a),
        "Vec4" => Some(Ty::Vec4),
        "IVec2" => Some(Ty::IVec2),
        "IVec3" => Some(Ty::IVec3),
        "UVec2" => Some(Ty::UVec2),
        "Quat" => Some(Ty::Quat),
        "Rgba" => Some(Ty::Rgba),
        "Mat3" => Some(Ty::Mat3),
        "Mat4" => Some(Ty::Mat4),
        "GraceWindow" => Some(Ty::GraceWindow),
        _ if s.starts_with("BitSet(") && s.ends_with(')') => s
            .strip_prefix("BitSet(")?
            .strip_suffix(')')?
            .trim()
            .parse::<usize>()
            .ok()
            .map(Ty::BitSet),
        _ if s.starts_with("InlineStr(") && s.ends_with(')') => s
            .strip_prefix("InlineStr(")?
            .strip_suffix(')')?
            .trim()
            .parse::<usize>()
            .ok()
            .map(Ty::InlineStr),
        _ if s.starts_with("Named(\"") && s.ends_with("\")") => Some(Ty::Named(
            s.strip_prefix("Named(\"")?.strip_suffix("\")")?.to_owned(),
        )),
        _ if s.starts_with("Ref(\"") && s.ends_with("\")") => Some(Ty::Ref(
            s.strip_prefix("Ref(\"")?.strip_suffix("\")")?.to_owned(),
        )),
        _ => None,
    }
}

pub(super) fn mir_ty_to_guest_ty_hint(mty: &MirType, mir: &MirModule) -> Option<Ty> {
    Some(match mty {
        MirType::Unit => Ty::Unit,
        MirType::Bool => Ty::Bool,
        MirType::U8 => Ty::U8,
        MirType::I8 => Ty::I8,
        MirType::U16 => Ty::U16,
        MirType::I16 => Ty::I16,
        MirType::U32 => Ty::U32,
        MirType::I32 => Ty::I32,
        MirType::U64 => Ty::U64,
        MirType::I64 => Ty::I64,
        MirType::F32 => Ty::F32,
        MirType::F64 => Ty::F64,
        MirType::Fix32 => Ty::Fix32,
        MirType::Fix64 => Ty::Fix64,
        MirType::Sym => Ty::Sym,
        MirType::Vec2 => Ty::Vec2,
        MirType::Vec3 => Ty::Vec3,
        MirType::Vec4 => Ty::Vec4,
        MirType::IVec2 => Ty::IVec2,
        MirType::IVec3 => Ty::IVec3,
        MirType::UVec2 => Ty::UVec2,
        MirType::Entity => Ty::Ref("Entity".to_owned()),
        MirType::Array { elem, len } => Ty::Array {
            elem: Box::new(mir_ty_to_guest_ty_hint(elem, mir)?),
            len: *len,
        },
        MirType::Tuple(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(mir_ty_to_guest_ty_hint(it, mir)?);
            }
            Ty::Tuple(out)
        }
        MirType::Named(n) => {
            if n == "mat3" || n == "Mat3" {
                Ty::Mat3
            } else if n == "mat4" || n == "Mat4" {
                Ty::Mat4
            } else if n == "GraceWindow" {
                Ty::GraceWindow
            } else if let Some(bits) = n
                .strip_prefix("BitSet<")
                .and_then(|s| s.strip_suffix('>'))
                .and_then(|s| s.parse::<usize>().ok())
            {
                Ty::BitSet(bits)
            } else if let Some(cap) = n
                .strip_prefix("InlineStr<")
                .and_then(|s| s.strip_suffix('>'))
                .and_then(|s| s.parse::<usize>().ok())
            {
                Ty::InlineStr(cap)
            } else if let Some((elem, cap)) = parse_mir_smallvec_debug(n) {
                Ty::SmallVec {
                    elem: Box::new(elem),
                    cap,
                }
            } else if let Some((action, cap)) = parse_mir_input_buffer(n) {
                Ty::InputBuffer { action, cap }
            } else if find_enum_repr(n, mir).is_some()
                || mir.layouts.iter().any(|l| {
                    l.canonical_name == *n
                        || l.canonical_name.rsplit("::").next() == Some(n.as_str())
                })
            {
                Ty::Named(n.clone())
            } else {
                return None;
            }
        }
        _ => return None,
    })
}

pub(super) fn guest_ty_abi_size_align(ty: &Ty, mir: &MirModule) -> (usize, usize) {
    match ty {
        Ty::Unit => (0, 1),
        Ty::Bool | Ty::U8 | Ty::I8 => (1, 1),
        Ty::U16 | Ty::I16 => (2, 2),
        Ty::U64 | Ty::I64 | Ty::Fix64 | Ty::F64 | Ty::Vec2 | Ty::IVec2 | Ty::UVec2 | Ty::Ref(_) => {
            (8, 8)
        }
        Ty::Vec3 | Ty::IVec3 => (12, 4),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => (16, 16),
        Ty::Mat3 => (36, 4),
        Ty::Mat4 => (64, 4),
        Ty::Asset(_) => (32, 8),
        Ty::BitSet(bits) => ((*bits).div_ceil(32).max(1) * 4, 4),
        Ty::InlineStr(cap) => ((1 + cap.div_ceil(4)) * 4, 4),
        Ty::InputBuffer { cap, .. } => ((*cap).max(1) * 8, 4),
        Ty::Array { elem, len } => {
            let (es, ea) = guest_ty_abi_size_align(elem, mir);
            let stride = if ea > 1 { es.div_ceil(ea) * ea } else { es };
            (stride * (*len), ea)
        }
        Ty::SmallVec { elem, cap } => {
            let (es, ea) = guest_ty_abi_size_align(elem, mir);
            let align = ea.max(4);
            let stride = if ea > 1 { es.div_ceil(ea) * ea } else { es };
            (8 + stride * (*cap), align)
        }
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut max_align = 1usize;
            for it in items {
                let (s, a) = guest_ty_abi_size_align(it, mir);
                let a = a.max(1);
                max_align = max_align.max(a);
                cursor = cursor.div_ceil(a) * a + s;
            }
            (cursor.div_ceil(max_align) * max_align, max_align)
        }
        Ty::Named(n) => {
            if let Some((sz, _)) = find_enum_repr(n, mir) {
                return (sz, sz.max(1));
            }
            if let Some(l) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n
                    || l.canonical_name.rsplit("::").next() == Some(n.as_str())
                    || sanitize_ident(&l.canonical_name) == sanitize_ident(n)
            }) {
                return (l.size, l.align.max(1));
            }
            (4, 4)
        }
        _ => (4, 4),
    }
}

pub(super) fn emit_const_pack_smallvec_expr(
    elem_exprs: &[String],
    elem_ty: &Ty,
    sv_bytes: usize,
    sv_align: usize,
    cap: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    let (elem_sz, elem_al) = guest_ty_abi_size_align(elem_ty, mir);
    let elem_al = elem_al.max(1);
    let elem_stride = elem_sz.div_ceil(elem_al) * elem_al;
    let count = elem_exprs.len().min(cap);

    fn write_const_elem_to_bytes(
        out: &mut String,
        val_var: &str,
        ty: &Ty,
        off_expr: &str,
        sz: usize,
        mir: &MirModule,
        cat: &GuestCatalog,
    ) {
        match ty {
            Ty::Bool => {
                writeln!(out, "        __b[{off_expr}] = ({val_var}).0;").ok();
            }
            Ty::U8 => {
                writeln!(out, "        __b[{off_expr}] = {val_var};").ok();
            }
            Ty::I8 => {
                writeln!(out, "        __b[{off_expr}] = ({val_var}) as u8;").ok();
            }
            Ty::U16
            | Ty::I16
            | Ty::U32
            | Ty::I32
            | Ty::Fix32
            | Ty::U64
            | Ty::I64
            | Ty::Fix64
            | Ty::F32
            | Ty::F64
            | Ty::UnitScalar { .. }
            | Ty::Sym
            | Ty::Rgba8
            | Ty::GraceWindow => {
                writeln!(
                    out,
                    "        let __eb = ({val_var}).to_le_bytes(); let mut __k = 0usize; while __k < __eb.len() && ({off_expr}) + __k < __b.len() {{ __b[({off_expr}) + __k] = __eb[__k]; __k += 1; }}"
                )
                .ok();
            }
            Ty::Ref(_) => {
                writeln!(
                    out,
                    "        let __eb = ({val_var}).to_bits().to_le_bytes(); let mut __k = 0usize; while __k < 8 && ({off_expr}) + __k < __b.len() {{ __b[({off_expr}) + __k] = __eb[__k]; __k += 1; }}"
                )
                .ok();
            }
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
            | Ty::BitSet(_)
            | Ty::InlineStr(_) => {
                writeln!(
                    out,
                    "        let mut __wi = 0usize; while __wi < ({val_var}).len() {{ let __eb = ({val_var})[__wi].to_le_bytes(); let __wstep = __eb.len(); let mut __k = 0usize; while __k < __wstep && ({off_expr}) + __wi * __wstep + __k < __b.len() {{ __b[({off_expr}) + __wi * __wstep + __k] = __eb[__k]; __k += 1; }} __wi += 1; }}"
                )
                .ok();
            }
            Ty::Named(n) => {
                if find_enum_repr(n, mir).is_some() {
                    writeln!(
                        out,
                        "        let __eb = ({val_var}).to_le_bytes(); let mut __k = 0usize; while __k < __eb.len() && ({off_expr}) + __k < __b.len() {{ __b[({off_expr}) + __k] = __eb[__k]; __k += 1; }}"
                    )
                    .ok();
                } else if let Some(comp) = cat.resolve_comp(n) {
                    let sname = &comp.struct_name;
                    writeln!(
                        out,
                        "        let __eb = {sname}::strata_to_u8_bytes(&({val_var})); let mut __k = 0usize; while __k < __eb.len() && ({off_expr}) + __k < __b.len() {{ __b[({off_expr}) + __k] = __eb[__k]; __k += 1; }}"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "        let mut __wi = 0usize; while __wi < ({val_var}).len() {{ let __eb = ({val_var})[__wi].to_le_bytes(); let __wstep = __eb.len(); let mut __k = 0usize; while __k < __wstep && ({off_expr}) + __wi * __wstep + __k < __b.len() {{ __b[({off_expr}) + __wi * __wstep + __k] = __eb[__k]; __k += 1; }} __wi += 1; }}"
                    )
                    .ok();
                }
            }
            _ => {
                let _ = sz;
            }
        }
    }

    let mut body = String::new();
    writeln!(body, "{{").ok();
    writeln!(body, "    let mut __b = [0u8; {sv_bytes}];").ok();
    writeln!(
        body,
        "    let __lb = ({count}u32).to_le_bytes(); __b[0] = __lb[0]; __b[1] = __lb[1]; __b[2] = __lb[2]; __b[3] = __lb[3];"
    )
    .ok();
    for (i, expr) in elem_exprs.iter().take(count).enumerate() {
        let off = 8 + i * elem_stride;
        writeln!(body, "    {{").ok();
        writeln!(body, "        let __ev = {expr};").ok();
        write_const_elem_to_bytes(
            &mut body,
            "__ev",
            elem_ty,
            &format!("{off}usize"),
            elem_sz,
            mir,
            cat,
        );
        writeln!(body, "    }}").ok();
    }
    let blob_ty = aligned_blob_type(sv_bytes, sv_align);
    if let Some(cnt_s) = blob_ty
        .strip_prefix("[u64; ")
        .and_then(|s| s.strip_suffix(']'))
    {
        let cnt = cnt_s.trim();
        writeln!(
            body,
            "    let mut __out = [0u64; {cnt}]; let mut __wi = 0usize; while __wi < {cnt} {{ let __p = __wi * 8; if __p + 8 <= {sv_bytes} {{ __out[__wi] = u64::from_le_bytes([__b[__p], __b[__p+1], __b[__p+2], __b[__p+3], __b[__p+4], __b[__p+5], __b[__p+6], __b[__p+7]]); }} __wi += 1; }} __out"
        )
        .ok();
    } else if let Some(cnt_s) = blob_ty
        .strip_prefix("[u32; ")
        .and_then(|s| s.strip_suffix(']'))
    {
        let cnt = cnt_s.trim();
        writeln!(
            body,
            "    let mut __out = [0u32; {cnt}]; let mut __wi = 0usize; while __wi < {cnt} {{ let __p = __wi * 4; if __p + 4 <= {sv_bytes} {{ __out[__wi] = u32::from_le_bytes([__b[__p], __b[__p+1], __b[__p+2], __b[__p+3]]); }} __wi += 1; }} __out"
        )
        .ok();
    } else if let Some(cnt_s) = blob_ty
        .strip_prefix("[u16; ")
        .and_then(|s| s.strip_suffix(']'))
    {
        let cnt = cnt_s.trim();
        writeln!(
            body,
            "    let mut __out = [0u16; {cnt}]; let mut __wi = 0usize; while __wi < {cnt} {{ let __p = __wi * 2; if __p + 2 <= {sv_bytes} {{ __out[__wi] = u16::from_le_bytes([__b[__p], __b[__p+1]]); }} __wi += 1; }} __out"
        )
        .ok();
    } else {
        writeln!(body, "    __b").ok();
    }
    writeln!(body, "}}").ok();
    body
}

pub(super) fn const_rust_ty(ty: &Ty, mir: &MirModule, cat: &GuestCatalog) -> String {
    match ty {
        Ty::Bool => "bool".to_owned(),
        Ty::U8 => "u8".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "i32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Vec2 => "[f32; 2]".to_owned(),
        Ty::Vec3 => "[f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[f32; 4]".to_owned(),
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(cap) => format!("[u32; {}]", 1 + cap.div_ceil(4)),
        Ty::Array { elem, len } => format!("[{}; {len}]", const_rust_ty(elem, mir, cat)),
        Ty::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(|t| const_rust_ty(t, mir, cat)).collect();
            format!("({})", parts.join(", "))
        }
        Ty::SmallVec { .. } | Ty::InputBuffer { .. } => {
            let (sz, al) = guest_ty_abi_size_align(ty, mir);
            aligned_blob_type(sz, al)
        }
        Ty::Named(n) => {
            if let Some(comp) = cat.resolve_comp(n) {
                comp.struct_name.clone()
            } else if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                match (sz, is_signed) {
                    (1, _) => "u8".to_owned(),
                    (2, _) => "u16".to_owned(),
                    (_, true) => "i32".to_owned(),
                    _ => "u32".to_owned(),
                }
            } else {
                rust_abi_type_for_ty(ty, 4, mir)
            }
        }
        _ => rust_abi_type_for_ty(ty, 4, mir),
    }
}

pub(super) fn emit_tables_and_curves(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, t) in mir.tables.iter().enumerate() {
        let te = &cat.tables[idx];
        writeln!(out, "#[derive(Clone, Copy, Debug, Default)]").ok();
        writeln!(out, "pub struct {} {{", te.struct_name).ok();
        for (fname, fty) in &t.fields {
            let rname = sanitize_rust_ident(fname);
            let rty = table_field_rust_ty(fty, mir, cat);
            writeln!(out, "    pub {rname}: {rty},").ok();
        }
        writeln!(out, "}}").ok();

        let row_count = t.typed_rows.len();
        let ident_upper = sanitize_ident(&t.name).to_ascii_uppercase();
        writeln!(
            out,
            "static STRATA_TABLE_{ident_upper}_{idx}: [{sname}; {row_count}] = [",
            sname = te.struct_name
        )
        .ok();
        for (vname, fields) in &t.typed_rows {
            writeln!(out, "    {} {{", te.struct_name).ok();
            for (fname, fty) in &t.fields {
                let rname = sanitize_rust_ident(fname);
                let val_s = if let Some((_, fexpr)) = fields.iter().find(|(n, _)| n == fname) {
                    if matches!(fty, Ty::InlineStr(_)) {
                        match fexpr {
                            strata_sema::hir::HirExpr::StringLit(s) => {
                                format!("\"{}\"", escape_rust_str(s))
                            }
                            _ => "\"\"".to_owned(),
                        }
                    } else {
                        format_hir_expr_rust(fexpr, fty, mir, cat)
                    }
                } else {
                    table_field_default(fty, mir)
                };
                writeln!(out, "        {rname}: {val_s},").ok();
            }
            writeln!(out, "    }}, // {vname}").ok();
        }
        writeln!(out, "];").ok();

        writeln!(
            out,
            "fn {}(key: i64) -> {} {{",
            te.lookup_fn, te.struct_name
        )
        .ok();
        writeln!(out, "    match key {{").ok();
        for (row_idx, (vname, _)) in t.typed_rows.iter().enumerate() {
            let disc = lookup_enum_variant_disc(&t.key_enum, vname, mir).unwrap_or(row_idx as i64);
            writeln!(
                out,
                "        {disc} => STRATA_TABLE_{ident_upper}_{idx}[{row_idx}].clone(),"
            )
            .ok();
        }
        writeln!(out, "        _ => {}::default(),", te.struct_name).ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "}}\n").ok();
    }

    for (idx, c) in mir.curves.iter().enumerate() {
        let ident = sanitize_ident(&c.name);
        let npts = c.points.len();
        writeln!(
            out,
            "static STRATA_CURVE_{ident}_{idx}: [(f64, f64); {npts}] = ["
        )
        .ok();
        for (x, y) in &c.points {
            writeln!(out, "    ({}, {}),", fmt_f64(*x), fmt_f64(*y)).ok();
        }
        writeln!(out, "];").ok();
        writeln!(
            out,
            "fn strata_curve_sample_{ident}(x: f64) -> f64 {{\n\
             \x20   strata_sample_curve_slice(&STRATA_CURVE_{ident}_{idx}, x)\n\
             }}\n"
        )
        .ok();
    }
}

pub(super) fn table_field_rust_ty(ty: &Ty, mir: &MirModule, cat: &GuestCatalog) -> String {
    match ty {
        Ty::Bool => "bool".to_owned(),
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(_) => "&'static str".to_owned(),
        _ => const_rust_ty(ty, mir, cat),
    }
}

pub(super) fn table_field_default(ty: &Ty, mir: &MirModule) -> String {
    match ty {
        Ty::Bool => "false".to_owned(),
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(_) => "\"\"".to_owned(),
        _ => rust_default_expr_for_ty(ty, 4, mir),
    }
}

pub(super) fn emit_layouts_and_tags(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for c in &cat.components {
        let layout = &c.layout;
        let struct_name = &c.struct_name;
        let is_zst = layout.size == 0 || layout.fields.is_empty();

        if !is_zst && layout.align > 1 {
            writeln!(out, "#[repr(C, align({}))]", layout.align).ok();
        } else {
            writeln!(out, "#[repr(C)]").ok();
        }
        if is_zst {
            writeln!(
                out,
                "#[derive(Clone, Copy, Default, Debug, PartialEq, AbiPod)]"
            )
            .ok();
            writeln!(out, "pub struct {struct_name};").ok();
        } else {
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, AbiPod)]").ok();
            writeln!(out, "pub struct {struct_name} {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                let rty = rust_abi_type_for_field(field, mir);
                writeln!(out, "    pub {fname}: {rty},").ok();
            }
            writeln!(out, "}}").ok();
            writeln!(out, "impl {struct_name} {{").ok();
            writeln!(out, "    const fn strata_const_default() -> Self {{").ok();
            writeln!(out, "        Self {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                let def = field_default_expr_honoring_mir(layout, field, mir, cat);
                writeln!(out, "            {fname}: {def},").ok();
            }
            writeln!(out, "        }}").ok();
            writeln!(out, "    }}").ok();
            writeln!(out, "}}").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{").ok();
            writeln!(out, "        Self::strata_const_default()").ok();
            writeln!(out, "    }}").ok();
            writeln!(out, "}}").ok();
            writeln!(
                out,
                "static {struct_name}_DEFAULT_BYTES: [u8; {sz}] = {struct_name}::strata_const_default().strata_to_u8_bytes();",
                sz = layout.size
            )
            .ok();
        }

        writeln!(out, "#[repr(C)]").ok();
        writeln!(out, "#[derive(Clone, Copy)]").ok();
        writeln!(out, "pub struct {struct_name}VTable {{").ok();
        writeln!(out, "    header: VTableHeader,").ok();
        writeln!(out, "}}").ok();

        writeln!(out, "static {struct_name}_FIELDS: &[BamFieldDesc] = &[").ok();
        for field in &layout.fields {
            let kind = rust_field_kind(field.bam_field_kind);
            let esc_name = escape_rust_str(&field.name);
            let esc_tag = escape_rust_str(&field.type_tag);
            writeln!(
                out,
                "    BamFieldDesc::new({kind}, StrView::from_str(\"{esc_name}\"), StrView::from_str(\"{esc_tag}\"), {off}, {sz}, {al}),",
                off = field.offset,
                sz = field.size,
                al = field.align
            )
            .ok();
        }
        writeln!(out, "];").ok();

        let req_uuids: Vec<String> = layout
            .required_components
            .iter()
            .filter_map(|req| cat.resolve_comp(req))
            .map(|rc| {
                if rc.layout.size > 0 && !rc.layout.fields.is_empty() {
                    format!(
                        "BamRequiredComponent::by_uuid(<{} as ModComponent>::UUID).with_custom_bytes(&{}_DEFAULT_BYTES)",
                        rc.struct_name, rc.struct_name
                    )
                } else {
                    format!(
                        "BamRequiredComponent::by_uuid(<{} as ModComponent>::UUID)",
                        rc.struct_name
                    )
                }
            })
            .collect();
        if req_uuids.is_empty() {
            writeln!(
                out,
                "static {struct_name}_REQS: &[BamRequiredComponent] = &[];"
            )
            .ok();
        } else {
            writeln!(
                out,
                "static {struct_name}_REQS: &[BamRequiredComponent] = &[{}];",
                req_uuids.join(", ")
            )
            .ok();
        }

        let uuid_lit = format_u8_array_16(&layout.uuid_bytes);
        writeln!(
            out,
            "static {struct_name}_VTABLE: {struct_name}VTable = {struct_name}VTable {{\n\
             \x20   header: VTableHeader::new::<{struct_name}VTable, {struct_name}>(ComponentUuid::from_bytes({uuid_lit})),\n\
             }};\n\
             static {struct_name}_SYMS: &[SymbolEntry] = &[];"
        )
        .ok();

        let esc_canon = escape_rust_str(&layout.canonical_name);
        writeln!(
            out,
            "impl ModComponent for {struct_name} {{\n\
             \x20   const CANONICAL_NAME: &'static str = \"{esc_canon}\";\n\
             \x20   const COMPONENT_CSTR: &'static CStr = c\"{esc_canon}\";\n\
             \x20   const UUID: ComponentUuid = ComponentUuid::from_bytes({uuid_lit});\n\
             \x20   const IS_ABI_POD: bool = {is_pod};\n\
             \x20   const IS_RAW_INSERTABLE: bool = true;\n\
             \x20   const COMPONENT_FLAGS: u32 = 0x{flags:08X};\n\
             \x20   const SCHEMA_FINGERPRINT: u64 = 0x{fp:016X};\n\
             \x20   const BAM_FIELDS: &'static [BamFieldDesc] = {struct_name}_FIELDS;\n\
             \x20   const REQUIRED_COMPONENTS: &'static [BamRequiredComponent] = {struct_name}_REQS;\n\
             \x20   type VTable = {struct_name}VTable;\n\
             \x20   fn vtable() -> &'static Self::VTable {{ &{struct_name}_VTABLE }}\n\
             \x20   fn symbols() -> &'static [SymbolEntry] {{ {struct_name}_SYMS }}\n\
             }}",
            is_pod = layout.is_abi_pod,
            flags = if matches!(layout.item_kind, SchemaItemKind::Stream) {
                layout.component_flags | bamabi_sys::BAM_STORAGE_FLAG_MESSAGE
            } else {
                layout.component_flags
            },
            fp = layout.schema_fingerprint,
        )
        .ok();

        writeln!(
            out,
            "impl GuestComponent for {struct_name} {{\n\
             \x20   const NAME: &'static CStr = <Self as ModComponent>::COMPONENT_CSTR;\n\
             \x20   const FLAGS: u32 = <Self as ModComponent>::COMPONENT_FLAGS;\n\
             \x20   const UUID: ComponentUuid = <Self as ModComponent>::UUID;\n\
             }}"
        )
        .ok();

        writeln!(
            out,
            "const _: () = {{\n\
             \x20   assert!(core::mem::size_of::<{struct_name}>() == {sz});\n\
             \x20   assert!(core::mem::align_of::<{struct_name}>() == {al});\n\
             }};\n",
            sz = layout.size,
            al = layout.align.max(1)
        )
        .ok();
    }
}

pub(crate) fn rust_abi_type_for_mir_ty(ty: &MirType, byte_size: u32, mir: &MirModule) -> String {
    match ty {
        MirType::Bool => "FfiBool".to_owned(),
        MirType::U8 => "u8".to_owned(),
        MirType::I8 => "i8".to_owned(),
        MirType::U16 => "u16".to_owned(),
        MirType::I16 => "i16".to_owned(),
        MirType::U32 | MirType::Sym => "u32".to_owned(),
        MirType::I32 | MirType::Fix32 => "i32".to_owned(),
        MirType::U64 => "u64".to_owned(),
        MirType::I64 | MirType::Fix64 => "i64".to_owned(),
        MirType::F32 => "f32".to_owned(),
        MirType::F64 => "f64".to_owned(),
        MirType::Entity => "FfiEntity".to_owned(),
        MirType::Vec2 => "[f32; 2]".to_owned(),
        MirType::Vec3 => "[f32; 3]".to_owned(),
        MirType::Vec4 => "[f32; 4]".to_owned(),
        MirType::IVec2 => "[i32; 2]".to_owned(),
        MirType::IVec3 => "[i32; 3]".to_owned(),
        MirType::UVec2 => "[u32; 2]".to_owned(),
        MirType::Array { elem, len } => {
            let elem_sz = (byte_size as usize / (*len).max(1)) as u32;
            let ety = rust_abi_type_for_mir_ty(elem, elem_sz, mir);
            format!("[{ety}; {len}]")
        }
        MirType::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                return match (sz, is_signed) {
                    (1, _) => "u8".to_owned(),
                    (2, _) => "u16".to_owned(),
                    (_, true) => "i32".to_owned(),
                    _ => "u32".to_owned(),
                };
            }
            if n.starts_with("Asset<") {
                "FfiAssetHandle".to_owned()
            } else if n.contains("IVec2") {
                "[i32; 2]".to_owned()
            } else if n.contains("IVec3") {
                "[i32; 3]".to_owned()
            } else if n.contains("UVec2") {
                "[u32; 2]".to_owned()
            } else if n.contains("Vec3a") && byte_size == 12 {
                "[f32; 3]".to_owned()
            } else if n.contains("Vec3a")
                || n.contains("Vec4")
                || n.contains("Quat")
                || n.contains("Rgba")
            {
                "[f32; 4]".to_owned()
            } else {
                aligned_blob_type(byte_size as usize, 1)
            }
        }
        _ => aligned_blob_type(byte_size as usize, 1),
    }
}

pub(super) fn rust_default_expr_for_mir_ty(
    ty: &MirType,
    byte_size: u32,
    mir: &MirModule,
) -> String {
    match ty {
        MirType::Bool => "FfiBool::FALSE".to_owned(),
        MirType::U8 => "0u8".to_owned(),
        MirType::I8 => "0i8".to_owned(),
        MirType::U16 => "0u16".to_owned(),
        MirType::I16 => "0i16".to_owned(),
        MirType::U32 | MirType::Sym => "0u32".to_owned(),
        MirType::I32 | MirType::Fix32 => "0i32".to_owned(),
        MirType::U64 => "0u64".to_owned(),
        MirType::I64 | MirType::Fix64 => "0i64".to_owned(),
        MirType::F32 => "0.0f32".to_owned(),
        MirType::F64 => "0.0f64".to_owned(),
        MirType::Entity => "FfiEntity::NULL".to_owned(),
        MirType::Vec2 => "[0.0f32; 2]".to_owned(),
        MirType::Vec3 => "[0.0f32; 3]".to_owned(),
        MirType::Vec4 => "[0.0f32; 4]".to_owned(),
        MirType::IVec2 => "[0i32; 2]".to_owned(),
        MirType::IVec3 => "[0i32; 3]".to_owned(),
        MirType::UVec2 => "[0u32; 2]".to_owned(),
        MirType::Array { elem, len } => {
            let elem_sz = (byte_size as usize / (*len).max(1)) as u32;
            let edef = rust_default_expr_for_mir_ty(elem, elem_sz, mir);
            format!("[{edef}; {len}]")
        }
        MirType::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                return match (sz, is_signed) {
                    (1, _) => "0u8".to_owned(),
                    (2, _) => "0u16".to_owned(),
                    (_, true) => "0i32".to_owned(),
                    _ => "0u32".to_owned(),
                };
            }
            if n.starts_with("Asset<") {
                "FfiAssetHandle::NONE".to_owned()
            } else if n.contains("IVec2") {
                "[0i32; 2]".to_owned()
            } else if n.contains("IVec3") {
                "[0i32; 3]".to_owned()
            } else if n.contains("UVec2") {
                "[0u32; 2]".to_owned()
            } else if n.contains("Vec3a") && byte_size == 12 {
                "[0.0f32; 3]".to_owned()
            } else if n.contains("Vec3a")
                || n.contains("Vec4")
                || n.contains("Quat")
                || n.contains("Rgba")
            {
                "[0.0f32; 4]".to_owned()
            } else {
                aligned_blob_default(byte_size as usize, 1)
            }
        }
        _ => aligned_blob_default(byte_size as usize, 1),
    }
}

pub(crate) fn emit_rust_wire_field_encode(
    out: &mut String,
    wf: &MirNetFieldSpec,
    fname: &str,
    rust_ty: &str,
    src_var: &str,
) -> Result<(), CodegenError> {
    let field_target = if src_var.is_empty() {
        fname.to_owned()
    } else {
        format!("{src_var}.{fname}")
    };
    if let Some(ref q) = wf.quantize {
        let min_s = format!("{:?}f64", q.min);
        let max_s = format!("{:?}f64", q.max);
        let step_s = match q.step {
            Some(s) => format!("Some({s:?}f64)"),
            None => "None".to_owned(),
        };
        let bits = q.bits;
        let val_to_f64 = |expr: &str| -> String {
            if rust_ty == "Fixed32" {
                format!("(({expr}.0 as f64) / 65_536.0_f64)")
            } else if rust_ty == "Fixed64" {
                format!("(({expr}.0 as f64) / 4_294_967_296.0_f64)")
            } else if matches!(wf.ty, MirType::Fix32) {
                format!("(({expr} as f64) / 65_536.0_f64)")
            } else if matches!(wf.ty, MirType::Fix64) {
                format!("(({expr} as f64) / 4_294_967_296.0_f64)")
            } else {
                format!("{expr} as f64")
            }
        };
        if q.lane_count == 1 {
            let val_s = val_to_f64(&field_target);
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {}, {bits}, strata_net_quantize_scalar_f64({val_s}, {min_s}, {max_s}, {bits}, {step_s}));",
                wf.bit_offset
            )
            .ok();
        } else {
            for li in 0..(q.lane_count as usize) {
                let boff = wf.bit_offset + (li as u32) * u32::from(bits);
                let val_s = val_to_f64(&format!("{field_target}[{li}]"));
                writeln!(
                    out,
                    "    strata_net_pack_bits_le(&mut pkt.payload, {boff}, {bits}, strata_net_quantize_scalar_f64({val_s}, {min_s}, {max_s}, {bits}, {step_s}));"
                )
                .ok();
            }
        }
        return Ok(());
    }

    let boff_expr = format!("{}", wf.bit_offset);
    emit_rust_wire_expr_encode(
        out,
        &boff_expr,
        wf.byte_size,
        rust_ty,
        &field_target,
        &wf.field_name,
        0,
    )
}

pub(super) fn emit_rust_wire_expr_encode(
    out: &mut String,
    boff_expr: &str,
    byte_size: u32,
    rust_ty: &str,
    val_expr: &str,
    field_name: &str,
    depth: usize,
) -> Result<(), CodegenError> {
    match rust_ty {
        "()" => Ok(()),
        "bool" | "u8" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 8, u64::from({val_expr}));"
            )
            .ok();
            Ok(())
        }
        "FfiBool" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 8, u64::from({val_expr}.get()));"
            )
            .ok();
            Ok(())
        }
        "i8" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 8, u64::from({val_expr} as u8));"
            )
            .ok();
            Ok(())
        }
        "u16" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 16, u64::from({val_expr}));"
            )
            .ok();
            Ok(())
        }
        "i16" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 16, u64::from({val_expr} as u16));"
            )
            .ok();
            Ok(())
        }
        "u32" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 32, u64::from({val_expr}));"
            )
            .ok();
            Ok(())
        }
        "i32" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 32, u64::from({val_expr} as u32));"
            )
            .ok();
            Ok(())
        }
        "u64" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 64, {val_expr});"
            )
            .ok();
            Ok(())
        }
        "i64" | "usize" | "isize" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 64, {val_expr} as u64);"
            )
            .ok();
            Ok(())
        }
        "f32" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 32, u64::from({val_expr}.to_bits()));"
            )
            .ok();
            Ok(())
        }
        "f64" | "FfiEntity" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 64, {val_expr}.to_bits());"
            )
            .ok();
            Ok(())
        }
        "Fixed32" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 32, u64::from({val_expr}.0 as u32));"
            )
            .ok();
            Ok(())
        }
        "Fixed64" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 64, {val_expr}.0 as u64);"
            )
            .ok();
            Ok(())
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "    strata_net_pack_bits_le(&mut pkt.payload, {boff_expr}, 8, u64::from({val_expr}.kind));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 8, 8, u64::from({val_expr}.reserved0[0]));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 16, 8, u64::from({val_expr}.reserved0[1]));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 24, 8, u64::from({val_expr}.reserved0[2]));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 32, 32, u64::from({val_expr}.asset_type.to_raw()));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 64, 32, u64::from({val_expr}.index));\n\
                 \x20   strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 96, 32, u64::from({val_expr}.generation));\n\
                 \x20   for (__bi, __b) in {val_expr}.uuid.as_bytes().iter().enumerate() {{\n\
                 \x20       strata_net_pack_bits_le(&mut pkt.payload, {boff_expr} + 128 + (__bi as u32) * 8, 8, u64::from(*__b));\n\
                 \x20   }}"
            )
            .ok();
            Ok(())
        }
        other => {
            if byte_size == 0 {
                return Ok(());
            }
            if let Some((elem_ty, len)) = parse_fixed_array_rust_ty(other) {
                if len == 0 {
                    return Ok(());
                }
                let elem_byte_sz = (byte_size as usize / len).max(1) as u32;
                let elem_bits = rust_wire_type_bits(elem_ty).unwrap_or(elem_byte_sz * 8);
                let idx_var = format!("__i_{depth}");
                let elem_var = format!("__v_{depth}");
                writeln!(
                    out,
                    "    for ({idx_var}, {elem_var}) in {val_expr}.iter().take({len}).enumerate() {{"
                )
                .ok();
                let child_boff = format!("{boff_expr} + ({idx_var} as u32) * {elem_bits}");
                let child_val = format!("(*{elem_var})");
                emit_rust_wire_expr_encode(
                    out,
                    &child_boff,
                    elem_byte_sz,
                    elem_ty,
                    &child_val,
                    field_name,
                    depth + 1,
                )?;
                writeln!(out, "    }}").ok();
                return Ok(());
            }
            Err(CodegenError::Unsupported {
                context: format!("rust_wire_encode({field_name})"),
                detail: format!("unsupported Rust wire field type `{other}`"),
            })
        }
    }
}

pub(super) fn rust_wire_type_bits(rust_ty: &str) -> Option<u32> {
    match rust_ty {
        "bool" | "FfiBool" | "u8" | "i8" => Some(8),
        "u16" | "i16" => Some(16),
        "u32" | "i32" | "f32" | "Fixed32" => Some(32),
        "u64" | "i64" | "usize" | "isize" | "f64" | "FfiEntity" | "Fixed64" => Some(64),
        "FfiAssetHandle" => Some(256),
        _ => parse_fixed_array_rust_ty(rust_ty)
            .and_then(|(elem, len)| rust_wire_type_bits(elem).map(|b| b * (len as u32))),
    }
}

pub(crate) fn emit_rust_wire_field_decode(
    out: &mut String,
    wf: &MirNetFieldSpec,
    fname: &str,
    rust_ty: &str,
    dst_var: &str,
) -> Result<(), CodegenError> {
    let field_target = if dst_var.is_empty() {
        fname.to_owned()
    } else {
        format!("{dst_var}.{fname}")
    };
    if let Some(ref q) = wf.quantize {
        let min_s = format!("{:?}f64", q.min);
        let max_s = format!("{:?}f64", q.max);
        let step_s = match q.step {
            Some(s) => format!("Some({s:?}f64)"),
            None => "None".to_owned(),
        };
        let bits = q.bits;
        let cast_val = |deq_expr: &str, lane_ty: &str| -> String {
            if lane_ty == "Fixed32" {
                return format!("Fixed32((({deq_expr}) * 65_536.0_f64).round() as i32)");
            }
            if lane_ty == "Fixed64" {
                return format!("Fixed64((({deq_expr}) * 4_294_967_296.0_f64).round() as i64)");
            }
            if matches!(wf.ty, MirType::Fix32) {
                return format!("(({deq_expr}) * 65_536.0_f64).round() as i32");
            }
            if matches!(wf.ty, MirType::Fix64) {
                return format!("(({deq_expr}) * 4_294_967_296.0_f64).round() as i64");
            }
            match lane_ty {
                "f64" => deq_expr.to_owned(),
                "i8" => format!("({deq_expr}).round() as i8"),
                "i16" => format!("({deq_expr}).round() as i16"),
                "i32" | "[i32; 2]" | "[i32; 3]" => format!("({deq_expr}).round() as i32"),
                "i64" => format!("({deq_expr}).round() as i64"),
                "u8" => format!("({deq_expr}).round().max(0.0) as u8"),
                "u16" => format!("({deq_expr}).round().max(0.0) as u16"),
                "u32" | "[u32; 2]" => format!("({deq_expr}).round().max(0.0) as u32"),
                "u64" => format!("({deq_expr}).round().max(0.0) as u64"),
                _ => format!("({deq_expr}) as f32"),
            }
        };
        if q.lane_count == 1 {
            let deq = format!(
                "strata_net_dequantize_scalar_f64(strata_net_unpack_bits_le(&pkt.payload, {}, {bits}), {min_s}, {max_s}, {bits}, {step_s})",
                wf.bit_offset
            );
            let assigned = cast_val(&deq, rust_ty);
            writeln!(out, "    {field_target} = {assigned};").ok();
        } else {
            for li in 0..(q.lane_count as usize) {
                let boff = wf.bit_offset + (li as u32) * u32::from(bits);
                let deq = format!(
                    "strata_net_dequantize_scalar_f64(strata_net_unpack_bits_le(&pkt.payload, {boff}, {bits}), {min_s}, {max_s}, {bits}, {step_s})"
                );
                let assigned = cast_val(&deq, rust_ty);
                writeln!(out, "    {field_target}[{li}] = {assigned};").ok();
            }
        }
        return Ok(());
    }

    let boff_expr = format!("{}", wf.bit_offset);
    emit_rust_wire_expr_decode(
        out,
        &boff_expr,
        wf.byte_size,
        rust_ty,
        &field_target,
        &wf.field_name,
        0,
    )
}

pub(super) fn emit_rust_wire_expr_decode(
    out: &mut String,
    boff_expr: &str,
    byte_size: u32,
    rust_ty: &str,
    dst_expr: &str,
    field_name: &str,
    depth: usize,
) -> Result<(), CodegenError> {
    match rust_ty {
        "()" => Ok(()),
        "bool" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 8) != 0;"
            )
            .ok();
            Ok(())
        }
        "FfiBool" => {
            writeln!(
                out,
                "    {dst_expr} = FfiBool::from_bool(strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 8) != 0);"
            )
            .ok();
            Ok(())
        }
        "u8" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 8) as u8;"
            )
            .ok();
            Ok(())
        }
        "i8" => {
            writeln!(
                out,
                "    {dst_expr} = (strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 8) as u8) as i8;"
            )
            .ok();
            Ok(())
        }
        "u16" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 16) as u16;"
            )
            .ok();
            Ok(())
        }
        "i16" => {
            writeln!(
                out,
                "    {dst_expr} = (strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 16) as u16) as i16;"
            )
            .ok();
            Ok(())
        }
        "u32" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 32) as u32;"
            )
            .ok();
            Ok(())
        }
        "i32" => {
            writeln!(
                out,
                "    {dst_expr} = (strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 32) as u32) as i32;"
            )
            .ok();
            Ok(())
        }
        "u64" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64);"
            )
            .ok();
            Ok(())
        }
        "i64" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64) as i64;"
            )
            .ok();
            Ok(())
        }
        "usize" => {
            writeln!(
                out,
                "    {dst_expr} = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64) as usize;"
            )
            .ok();
            Ok(())
        }
        "isize" => {
            writeln!(
                out,
                "    {dst_expr} = (strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64) as i64) as isize;"
            )
            .ok();
            Ok(())
        }
        "f32" => {
            writeln!(
                out,
                "    {dst_expr} = f32::from_bits(strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 32) as u32);"
            )
            .ok();
            Ok(())
        }
        "f64" => {
            writeln!(
                out,
                "    {dst_expr} = f64::from_bits(strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64));"
            )
            .ok();
            Ok(())
        }
        "FfiEntity" => {
            writeln!(
                out,
                "    {dst_expr} = FfiEntity::from_bits(strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64));"
            )
            .ok();
            Ok(())
        }
        "Fixed32" => {
            writeln!(
                out,
                "    {dst_expr} = Fixed32((strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 32) as u32) as i32);"
            )
            .ok();
            Ok(())
        }
        "Fixed64" => {
            writeln!(
                out,
                "    {dst_expr} = Fixed64(strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 64) as i64);"
            )
            .ok();
            Ok(())
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "    {dst_expr}.kind = strata_net_unpack_bits_le(&pkt.payload, {boff_expr}, 8) as u8;\n\
                 \x20   {dst_expr}.reserved0 = [\n\
                 \x20       strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 8, 8) as u8,\n\
                 \x20       strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 16, 8) as u8,\n\
                 \x20       strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 24, 8) as u8,\n\
                 \x20   ];\n\
                 \x20   {dst_expr}.asset_type = BamComponent::from_raw(strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 32, 32) as u32);\n\
                 \x20   {dst_expr}.index = strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 64, 32) as u32;\n\
                 \x20   {dst_expr}.generation = strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 96, 32) as u32;\n\
                 \x20   let mut __uuid_b = [0u8; 16];\n\
                 \x20   for (__bi, __slot) in __uuid_b.iter_mut().enumerate() {{\n\
                 \x20       *__slot = strata_net_unpack_bits_le(&pkt.payload, {boff_expr} + 128 + (__bi as u32) * 8, 8) as u8;\n\
                 \x20   }}\n\
                 \x20   {dst_expr}.uuid = ComponentUuid::from_bytes(__uuid_b);"
            )
            .ok();
            Ok(())
        }
        other => {
            if byte_size == 0 {
                return Ok(());
            }
            if let Some((elem_ty, len)) = parse_fixed_array_rust_ty(other) {
                if len == 0 {
                    return Ok(());
                }
                let elem_byte_sz = (byte_size as usize / len).max(1) as u32;
                let elem_bits = rust_wire_type_bits(elem_ty).unwrap_or(elem_byte_sz * 8);
                let idx_var = format!("__i_{depth}");
                let slot_var = format!("__slot_{depth}");
                writeln!(
                    out,
                    "    for ({idx_var}, {slot_var}) in {dst_expr}.iter_mut().take({len}).enumerate() {{"
                )
                .ok();
                let child_boff = format!("{boff_expr} + ({idx_var} as u32) * {elem_bits}");
                let child_dst = format!("(*{slot_var})");
                emit_rust_wire_expr_decode(
                    out,
                    &child_boff,
                    elem_byte_sz,
                    elem_ty,
                    &child_dst,
                    field_name,
                    depth + 1,
                )?;
                writeln!(out, "    }}").ok();
                return Ok(());
            }
            Err(CodegenError::Unsupported {
                context: format!("rust_wire_decode({field_name})"),
                detail: format!("unsupported Rust wire field type `{other}`"),
            })
        }
    }
}

pub(super) fn parse_fixed_array_rust_ty(s: &str) -> Option<(&str, usize)> {
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    let (elem, len_s) = inner.rsplit_once(';')?;
    let len = len_s.trim().parse::<usize>().ok()?;
    Some((elem.trim(), len))
}

pub(super) fn emit_net_protocol_and_codecs(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> Result<(), CodegenError> {
    let mod_fp = mir.net_handshake.module_net_fingerprint;
    let pkt_uuid = stratanet_packet_uuid();
    let pkt_uuid_lit = format_u8_array_16(pkt_uuid.as_bytes());
    let esc_canon = escape_rust_str(STRATA_NET_PACKET_CANONICAL_NAME);

    writeln!(
        out,
        "pub const STRATA_NET_PACKET_CANONICAL_NAME: &str = \"{esc_canon}\";\n\
         pub const STRATA_NET_PACKET_MAGIC: u32 = 0x{magic:08X};\n\
         pub const STRATA_NET_WIRE_VERSION: u16 = {ver};\n\
         pub const STRATA_NET_MAX_PAYLOAD_BYTES: usize = {max_p};\n\
         pub const STRATA_NET_PACKET_SIZE: usize = {pkt_sz};\n\
         pub const STRATA_NET_PACKET_ALIGN: usize = {pkt_al};\n\
         pub const STRATA_NET_MODULE_FINGERPRINT: u64 = 0x{mod_fp:016X};\n\
         pub const STRATA_NET_PACKET_SCHEMA_FINGERPRINT: u64 = 0x{pkt_fp:016X};\n\
         pub const PACKET_KIND_HANDSHAKE: u8 = 0;\n\
         pub const PACKET_KIND_COMPONENT_DELTA: u8 = {k_comp};\n\
         pub const PACKET_KIND_RESOURCE_DELTA: u8 = {k_res};\n\
         pub const PACKET_KIND_RPC: u8 = {k_rpc};\n\
         pub const FLAG_IS_RPC: u16 = {f_rpc};\n\
         pub const FLAG_IS_RELIABLE: u16 = {f_rel};\n\
         pub const FLAG_IS_HANDSHAKE: u16 = 4;\n\
         pub const FLAG_IS_PREDICTED: u16 = {f_pred};\n\
         pub const FLAG_IS_RESOURCE: u16 = {f_res};\n\n\
         #[repr(C)]\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq, AbiPod)]\n\
         pub struct StrataNetPacket {{\n\
         \x20   pub module_net_fingerprint: u64,\n\
         \x20   pub item_schema_fingerprint: u64,\n\
         \x20   pub target_id: u64,\n\
         \x20   pub entity_bits: u64,\n\
         \x20   pub magic: u32,\n\
         \x20   pub tick_or_seq: u32,\n\
         \x20   pub version: u16,\n\
         \x20   pub payload_bits: u16,\n\
         \x20   pub flags: u16,\n\
         \x20   pub kind: u8,\n\
         \x20   pub channel: u8,\n\
         \x20   pub payload_bytes: u8,\n\
         \x20   pub client_id: u8,\n\
         \x20   pub _pad: [u8; 6],\n\
         \x20   pub payload: [u8; 128],\n\
         }}\n\n\
         impl Default for StrataNetPacket {{\n\
         \x20   fn default() -> Self {{\n\
         \x20       Self {{\n\
         \x20           module_net_fingerprint: 0,\n\
         \x20           item_schema_fingerprint: 0,\n\
         \x20           target_id: 0,\n\
         \x20           entity_bits: 0,\n\
         \x20           magic: STRATA_NET_PACKET_MAGIC,\n\
         \x20           tick_or_seq: 0,\n\
         \x20           version: STRATA_NET_WIRE_VERSION,\n\
         \x20           payload_bits: 0,\n\
         \x20           flags: 0,\n\
         \x20           kind: PACKET_KIND_HANDSHAKE,\n\
         \x20           channel: 0,\n\
         \x20           payload_bytes: 0,\n\
         \x20           client_id: 0,\n\
         \x20           _pad: [0; 6],\n\
         \x20           payload: [0; STRATA_NET_MAX_PAYLOAD_BYTES],\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n\n\
         #[repr(C)]\n\
         #[derive(Clone, Copy)]\n\
         pub struct StrataNetPacketVTable {{\n\
         \x20   header: VTableHeader,\n\
         }}\n",
        magic = STRATA_NET_PACKET_MAGIC,
        ver = STRATA_NET_WIRE_VERSION,
        max_p = STRATA_NET_MAX_PAYLOAD_BYTES,
        pkt_sz = STRATA_NET_PACKET_SIZE,
        pkt_al = STRATA_NET_PACKET_ALIGN,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
        k_comp = PACKET_KIND_COMPONENT_DELTA,
        k_res = PACKET_KIND_RESOURCE_DELTA,
        k_rpc = PACKET_KIND_RPC,
        f_rpc = FLAG_IS_RPC,
        f_rel = FLAG_IS_RELIABLE,
        f_pred = FLAG_IS_PREDICTED,
        f_res = FLAG_IS_RESOURCE,
    )
    .ok();

    writeln!(out, "static STRATA_NET_PACKET_FIELDS: &[BamFieldDesc] = &[").ok();
    for f in STRATA_NET_PACKET_FIELDS {
        let kind = rust_field_kind(f.kind.0);
        let en = escape_rust_str(f.name);
        let et = escape_rust_str(f.type_tag);
        writeln!(
            out,
            "    BamFieldDesc::new({kind}, StrView::from_str(\"{en}\"), StrView::from_str(\"{et}\"), {}, {}, {}),",
            f.offset, f.size, f.align
        )
        .ok();
    }
    writeln!(
        out,
        "];\n\
         static STRATA_NET_PACKET_VTABLE: StrataNetPacketVTable = StrataNetPacketVTable {{\n\
         \x20   header: VTableHeader::new::<StrataNetPacketVTable, StrataNetPacket>(ComponentUuid::from_bytes({pkt_uuid_lit})),\n\
         }};\n\
         static STRATA_NET_PACKET_SYMS: &[SymbolEntry] = &[];\n\
         static STRATA_NET_PACKET_REQS: &[BamRequiredComponent] = &[];\n\
         impl ModComponent for StrataNetPacket {{\n\
         \x20   const CANONICAL_NAME: &'static str = STRATA_NET_PACKET_CANONICAL_NAME;\n\
         \x20   const COMPONENT_CSTR: &'static CStr = c\"{esc_canon}\";\n\
         \x20   const UUID: ComponentUuid = ComponentUuid::from_bytes({pkt_uuid_lit});\n\
         \x20   const IS_ABI_POD: bool = true;\n\
         \x20   const IS_RAW_INSERTABLE: bool = true;\n\
         \x20   const COMPONENT_FLAGS: u32 = 0;\n\
         \x20   const SCHEMA_FINGERPRINT: u64 = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;\n\
         \x20   const BAM_FIELDS: &'static [BamFieldDesc] = STRATA_NET_PACKET_FIELDS;\n\
         \x20   const REQUIRED_COMPONENTS: &'static [BamRequiredComponent] = STRATA_NET_PACKET_REQS;\n\
         \x20   type VTable = StrataNetPacketVTable;\n\
         \x20   fn vtable() -> &'static Self::VTable {{ &STRATA_NET_PACKET_VTABLE }}\n\
         \x20   fn symbols() -> &'static [SymbolEntry] {{ STRATA_NET_PACKET_SYMS }}\n\
         }}\n\
         impl GuestComponent for StrataNetPacket {{\n\
         \x20   const NAME: &'static CStr = <Self as ModComponent>::COMPONENT_CSTR;\n\
         \x20   const FLAGS: u32 = <Self as ModComponent>::COMPONENT_FLAGS;\n\
         \x20   const UUID: ComponentUuid = <Self as ModComponent>::UUID;\n\
         }}\n\
         const _: () = {{\n\
         \x20   assert!(core::mem::size_of::<StrataNetPacket>() == STRATA_NET_PACKET_SIZE);\n\
         \x20   assert!(core::mem::align_of::<StrataNetPacket>() == STRATA_NET_PACKET_ALIGN);\n\
         }};\n\n\
         pub fn strata_net_quantize_scalar_f64(val: f64, min: f64, max: f64, bits: u8, step: Option<f64>) -> u64 {{\n\
         \x20   if bits == 0 || !min.is_finite() || !max.is_finite() || min >= max {{ return 0; }}\n\
         \x20   let eff_bits = bits.min(32);\n\
         \x20   let max_q = (1u64 << eff_bits) - 1;\n\
         \x20   let eff_step = match step {{ Some(s) if s.is_finite() && s > 0.0 => s, _ => (max - min) / (max_q.max(1) as f64) }};\n\
         \x20   if !eff_step.is_finite() || eff_step <= 0.0 {{ return 0; }}\n\
         \x20   let clamped = if val.is_nan() {{ min }} else {{ val.clamp(min, max) }};\n\
         \x20   ((clamped - min) / eff_step).round().clamp(0.0, max_q as f64) as u64\n\
         }}\n\n\
         pub fn strata_net_dequantize_scalar_f64(raw: u64, min: f64, max: f64, bits: u8, step: Option<f64>) -> f64 {{\n\
         \x20   if bits == 0 || !min.is_finite() || !max.is_finite() || min >= max {{ return min; }}\n\
         \x20   let eff_bits = bits.min(32);\n\
         \x20   let max_q = (1u64 << eff_bits) - 1;\n\
         \x20   let q = raw & max_q;\n\
         \x20   let eff_step = match step {{ Some(s) if s.is_finite() && s > 0.0 => s, _ => (max - min) / (max_q.max(1) as f64) }};\n\
         \x20   if !eff_step.is_finite() || eff_step <= 0.0 {{ return min; }}\n\
         \x20   (min + (q as f64) * eff_step).clamp(min, max)\n\
         }}\n\n\
         pub fn strata_net_pack_bits_le(buf: &mut [u8], bit_offset: u32, bits: u8, val: u64) {{\n\
         \x20   let eff_bits = bits.min(64);\n\
         \x20   if eff_bits == 0 {{ return; }}\n\
         \x20   let mask = if eff_bits == 64 {{ u64::MAX }} else {{ (1u64 << eff_bits) - 1 }};\n\
         \x20   let mut src = val & mask;\n\
         \x20   let mut remaining = eff_bits;\n\
         \x20   let mut cur_bit = bit_offset as usize;\n\
         \x20   while remaining > 0 {{\n\
         \x20       let byte_idx = cur_bit / 8;\n\
         \x20       if byte_idx >= buf.len() {{ break; }}\n\
         \x20       let bit_in_byte = cur_bit % 8;\n\
         \x20       let take = (8 - bit_in_byte).min(remaining as usize);\n\
         \x20       let low_mask = ((1u16 << take) - 1) as u8;\n\
         \x20       let chunk_mask = low_mask << bit_in_byte;\n\
         \x20       let chunk_bits = ((src & u64::from(low_mask)) as u8) << bit_in_byte;\n\
         \x20       buf[byte_idx] = (buf[byte_idx] & !chunk_mask) | chunk_bits;\n\
         \x20       src >>= take;\n\
         \x20       cur_bit += take;\n\
         \x20       remaining -= take as u8;\n\
         \x20   }}\n\
         }}\n\n\
         pub fn strata_net_unpack_bits_le(buf: &[u8], bit_offset: u32, bits: u8) -> u64 {{\n\
         \x20   let eff_bits = bits.min(64);\n\
         \x20   if eff_bits == 0 {{ return 0; }}\n\
         \x20   let mut remaining = eff_bits;\n\
         \x20   let mut cur_bit = bit_offset as usize;\n\
         \x20   let mut out = 0u64;\n\
         \x20   let mut shift = 0u32;\n\
         \x20   while remaining > 0 {{\n\
         \x20       let byte_idx = cur_bit / 8;\n\
         \x20       if byte_idx >= buf.len() {{ break; }}\n\
         \x20       let bit_in_byte = cur_bit % 8;\n\
         \x20       let take = (8 - bit_in_byte).min(remaining as usize);\n\
         \x20       let low_mask = ((1u16 << take) - 1) as u8;\n\
         \x20       let chunk = (buf[byte_idx] >> bit_in_byte) & low_mask;\n\
         \x20       out |= u64::from(chunk) << shift;\n\
         \x20       shift += take as u32;\n\
         \x20       cur_bit += take;\n\
         \x20       remaining -= take as u8;\n\
         \x20   }}\n\
         \x20   out\n\
         }}\n\n\
         pub fn strata_net_verify_handshake(pkt: &StrataNetPacket, expected_item_fp: u64) -> bool {{\n\
         \x20   pkt.magic == STRATA_NET_PACKET_MAGIC\n\
         \x20       && pkt.version == STRATA_NET_WIRE_VERSION\n\
         \x20       && pkt.module_net_fingerprint == STRATA_NET_MODULE_FINGERPRINT\n\
         \x20       && pkt.module_net_fingerprint != 0\n\
         \x20       && pkt.item_schema_fingerprint == expected_item_fp\n\
         \x20       && expected_item_fp != 0\n\
         \x20       && (pkt.payload_bytes as usize) <= STRATA_NET_MAX_PAYLOAD_BYTES\n\
         }}\n"
    )
    .ok();

    for rpc in &mir.rpcs {
        emit_rust_rpc_struct_and_codec(out, mir, rpc)?;
    }
    for nc in &mir.net_components {
        if nc.is_replicated || !nc.quantize_specs.is_empty() {
            emit_rust_net_component_codec(out, mir, cat, nc)?;
        }
    }
    Ok(())
}

pub(super) fn net_comp_strata<'a>(
    nc: &MirNetComponent,
    cat: &'a GuestCatalog,
) -> Result<Vec<(String, &'a ComponentEntry)>, CodegenError> {
    let mut strata: Vec<(String, &'a ComponentEntry)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for wf in &nc.wire_fields {
        let cname = wf.stratum_layout.as_deref().unwrap_or(&nc.canonical_name);
        if seen.iter().any(|s| s == cname) {
            continue;
        }
        let Some(comp) = cat.resolve_comp(cname) else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::net_component({})", nc.canonical_name),
                detail: format!("missing solved layout for stratum `{cname}`"),
            });
        };
        seen.push(cname.to_owned());
        strata.push((cname.to_owned(), comp));
    }
    if strata.is_empty() {
        let Some(comp) = cat.resolve_comp(&nc.canonical_name) else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::net_component({})", nc.canonical_name),
                detail: "missing solved layout for network component".to_owned(),
            });
        };
        strata.push((nc.canonical_name.clone(), comp));
    }
    Ok(strata)
}

pub(super) fn emit_rust_net_component_codec(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    nc: &MirNetComponent,
) -> Result<(), CodegenError> {
    let strata = net_comp_strata(nc, cat)?;
    let ident = sanitize_ident(&nc.name);
    let fp = nc.schema_fingerprint;
    let target_id = fnv1a_64_str(&nc.canonical_name);
    let kind_expr = if nc.is_resource {
        "PACKET_KIND_RESOURCE_DELTA"
    } else {
        "PACKET_KIND_COMPONENT_DELTA"
    };
    let mut flags_parts = Vec::new();
    if matches!(nc.reliability, strata_sema::hir::NetReliability::Reliable) {
        flags_parts.push("FLAG_IS_RELIABLE");
    }
    if nc.is_predicted || nc.authority == strata_sema::hir::AuthorityKind::Predicted {
        flags_parts.push("FLAG_IS_PREDICTED");
    }
    if nc.is_resource {
        flags_parts.push("FLAG_IS_RESOURCE");
    }
    let flags_expr = if flags_parts.is_empty() {
        "0".to_owned()
    } else {
        flags_parts.join(" | ")
    };

    let multi = strata.len() > 1;
    let enc_params = if multi {
        strata
            .iter()
            .enumerate()
            .map(|(i, (_, c))| format!("src_{i}: &{}", c.struct_name))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!("src: &{}", strata[0].1.struct_name)
    };
    writeln!(
        out,
        "pub fn strata_net_encode_{ident}({enc_params}, entity_bits: u64, tick_or_seq: u32, client_id: u8) -> StrataNetPacket {{\n\
         \x20   let mut pkt = StrataNetPacket::default();\n\
         \x20   pkt.module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;\n\
         \x20   pkt.item_schema_fingerprint = 0x{fp:016X};\n\
         \x20   pkt.target_id = 0x{target_id:016X};\n\
         \x20   pkt.entity_bits = entity_bits;\n\
         \x20   pkt.tick_or_seq = tick_or_seq;\n\
         \x20   pkt.payload_bits = {pbits};\n\
         \x20   pkt.flags = {flags_expr};\n\
         \x20   pkt.kind = {kind_expr};\n\
         \x20   pkt.channel = {ch};\n\
         \x20   pkt.payload_bytes = {pbytes};\n\
         \x20   pkt.client_id = client_id;",
        pbits = nc.packed_bits,
        ch = nc.channel,
        pbytes = nc.packed_bytes,
    )
    .ok();
    for wf in &nc.wire_fields {
        let cname = wf.stratum_layout.as_deref().unwrap_or(&nc.canonical_name);
        let (si, comp) = strata
            .iter()
            .enumerate()
            .find(|(_, (n, _))| n == cname)
            .map(|(i, (_, c))| (i, *c))
            .unwrap_or((0, strata[0].1));
        let src_var = if multi {
            format!("src_{si}")
        } else {
            "src".to_owned()
        };
        if let Some(sf) = comp.layout.fields.iter().find(|f| f.name == wf.field_name) {
            let fname = sanitize_rust_ident(&sf.name);
            let rty = rust_abi_type_for_field(sf, mir);
            emit_rust_wire_field_encode(out, wf, &fname, &rty, &src_var)?;
        } else if wf.field_name.contains('.')
            && super::fn_emit::resolve_guest_field_ty_in_fields(
                cat,
                &comp.layout.fields,
                &wf.field_name,
                wf.byte_offset as usize,
            )
            .is_some()
        {
            let rty = rust_abi_type_for_mir_ty(&wf.ty, wf.byte_size, mir);
            let def = rust_default_expr_for_mir_ty(&wf.ty, wf.byte_size, mir);
            writeln!(
                out,
                "    {{\n\
                 \x20       let b = {src_var}.strata_to_u8_bytes();\n\
                 \x20       let mut __wf: {rty} = {def};"
            )
            .ok();
            emit_read_field_from_bytes(
                out,
                "__wf",
                &rty,
                wf.byte_offset as usize,
                wf.byte_size as usize,
            );
            emit_rust_wire_field_encode(out, wf, "__wf", &rty, "")?;
            writeln!(out, "    }}").ok();
        } else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::net_component({})", nc.canonical_name),
                detail: format!(
                    "wire field `{}` missing from solved layout `{}`",
                    wf.field_name, comp.layout.canonical_name
                ),
            });
        }
    }
    writeln!(out, "    pkt\n}}\n").ok();

    let dec_params = if multi {
        strata
            .iter()
            .enumerate()
            .map(|(i, (_, c))| format!("out_{i}: &mut {}", c.struct_name))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!("out_val: &mut {}", strata[0].1.struct_name)
    };
    let len_check = if nc.packed_bytes > 0 {
        format!(" || pkt.payload_bytes < {}", nc.packed_bytes)
    } else {
        String::new()
    };
    writeln!(
        out,
        "pub fn strata_net_decode_{ident}(pkt: &StrataNetPacket, {dec_params}) -> bool {{\n\
         \x20   if !strata_net_verify_handshake(pkt, 0x{fp:016X}) || pkt.item_schema_fingerprint != 0x{fp:016X} {{\n\
         \x20       return false;\n\
         \x20   }}\n\
         \x20   if pkt.target_id != 0x{target_id:016X} || pkt.kind != {kind_expr}{len_check} {{\n\
         \x20       return false;\n\
         \x20   }}",
    )
    .ok();
    for wf in &nc.wire_fields {
        let cname = wf.stratum_layout.as_deref().unwrap_or(&nc.canonical_name);
        let (si, comp) = strata
            .iter()
            .enumerate()
            .find(|(_, (n, _))| n == cname)
            .map(|(i, (_, c))| (i, *c))
            .unwrap_or((0, strata[0].1));
        let dst_var = if multi {
            format!("out_{si}")
        } else {
            "out_val".to_owned()
        };
        if let Some(sf) = comp.layout.fields.iter().find(|f| f.name == wf.field_name) {
            let fname = sanitize_rust_ident(&sf.name);
            let rty = rust_abi_type_for_field(sf, mir);
            emit_rust_wire_field_decode(out, wf, &fname, &rty, &dst_var)?;
        } else if wf.field_name.contains('.')
            && super::fn_emit::resolve_guest_field_ty_in_fields(
                cat,
                &comp.layout.fields,
                &wf.field_name,
                wf.byte_offset as usize,
            )
            .is_some()
        {
            let rty = rust_abi_type_for_mir_ty(&wf.ty, wf.byte_size, mir);
            let def = rust_default_expr_for_mir_ty(&wf.ty, wf.byte_size, mir);
            writeln!(
                out,
                "    {{\n\
                 \x20       let mut out = {dst_var}.strata_to_u8_bytes();\n\
                 \x20       let mut __wf: {rty} = {def};\n\
                 \x20       {{ let b = &out[..];"
            )
            .ok();
            emit_read_field_from_bytes(
                out,
                "__wf",
                &rty,
                wf.byte_offset as usize,
                wf.byte_size as usize,
            );
            writeln!(out, "        }}").ok();
            emit_rust_wire_field_decode(out, wf, "__wf", &rty, "")?;
            emit_write_field_to_bytes(
                out,
                "__wf",
                &rty,
                wf.byte_offset as usize,
                wf.byte_size as usize,
            );
            writeln!(out, "        {dst_var}.strata_from_u8_bytes(&out);\n    }}").ok();
        } else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::net_component({})", nc.canonical_name),
                detail: format!(
                    "wire field `{}` missing from solved layout `{}`",
                    wf.field_name, comp.layout.canonical_name
                ),
            });
        }
    }
    writeln!(out, "    true\n}}\n").ok();
    Ok(())
}

pub(super) fn emit_rust_rpc_struct_and_codec(
    out: &mut String,
    mir: &MirModule,
    rpc: &MirRpc,
) -> Result<(), CodegenError> {
    let ident = sanitize_ident(&rpc.name);
    let rty = format!("StrataRpc_{ident}");
    if rpc.fields.is_empty() {
        writeln!(
            out,
            "#[repr(C)]\n#[derive(Clone, Copy, Debug, Default, PartialEq)]\npub struct {rty};\n"
        )
        .ok();
    } else {
        writeln!(
            out,
            "#[repr(C)]\n#[derive(Clone, Copy, Debug, PartialEq)]\npub struct {rty} {{"
        )
        .ok();
        for (fname, mty, _, sz) in &rpc.fields {
            let rf = sanitize_rust_ident(fname);
            let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
            writeln!(out, "    pub {rf}: {rt},").ok();
        }
        writeln!(
            out,
            "}}\nimpl Default for {rty} {{\n    fn default() -> Self {{\n        Self {{"
        )
        .ok();
        for (fname, mty, _, sz) in &rpc.fields {
            let rf = sanitize_rust_ident(fname);
            let def = rust_default_expr_for_mir_ty(mty, *sz, mir);
            writeln!(out, "            {rf}: {def},").ok();
        }
        writeln!(out, "        }}\n    }}\n}}\n").ok();
    }

    let fp = rpc.schema_fingerprint;
    let rpc_id = rpc.rpc_id;
    let mut flags_parts = vec!["FLAG_IS_RPC"];
    if matches!(rpc.reliability, strata_sema::hir::NetReliability::Reliable) {
        flags_parts.push("FLAG_IS_RELIABLE");
    }
    let flags_expr = flags_parts.join(" | ");

    writeln!(
        out,
        "pub fn strata_net_encode_rpc_{ident}(rpc: &{rty}, tick_or_seq: u32, client_id: u8) -> StrataNetPacket {{\n\
         \x20   let mut pkt = StrataNetPacket::default();\n\
         \x20   pkt.module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;\n\
         \x20   pkt.item_schema_fingerprint = 0x{fp:016X};\n\
         \x20   pkt.target_id = 0x{rpc_id:016X};\n\
         \x20   pkt.entity_bits = 0;\n\
         \x20   pkt.tick_or_seq = tick_or_seq;\n\
         \x20   pkt.payload_bits = {pbits};\n\
         \x20   pkt.flags = {flags_expr};\n\
         \x20   pkt.kind = PACKET_KIND_RPC;\n\
         \x20   pkt.channel = {ch};\n\
         \x20   pkt.payload_bytes = {pbytes};\n\
         \x20   pkt.client_id = client_id;",
        pbits = rpc.packed_bits,
        ch = rpc.channel,
        pbytes = rpc.packed_bytes,
    )
    .ok();
    for wf in &rpc.wire_fields {
        if let Some((_, mty, _, sz)) = rpc.fields.iter().find(|(n, _, _, _)| n == &wf.field_name) {
            let rf = sanitize_rust_ident(&wf.field_name);
            let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
            emit_rust_wire_field_encode(out, wf, &rf, &rt, "rpc")?;
        } else if let Some(root) = wf.field_name.split('.').next()
            && let Some((root_name, root_mty, root_off, root_sz)) =
                rpc.fields.iter().find(|(n, _, _, _)| n == root)
        {
            let root_rf = sanitize_rust_ident(root_name);
            let root_rt = rust_abi_type_for_mir_ty(root_mty, *root_sz, mir);
            if root_rt.starts_with("[u8;") {
                let rty = rust_abi_type_for_mir_ty(&wf.ty, wf.byte_size, mir);
                let def = rust_default_expr_for_mir_ty(&wf.ty, wf.byte_size, mir);
                let rel_off = wf.byte_offset.saturating_sub(*root_off) as usize;
                writeln!(
                    out,
                    "    {{\n\
                     \x20       let b = &rpc.{root_rf}[..];\n\
                     \x20       let mut __wf: {rty} = {def};"
                )
                .ok();
                emit_read_field_from_bytes(out, "__wf", &rty, rel_off, wf.byte_size as usize);
                emit_rust_wire_field_encode(out, wf, "__wf", &rty, "")?;
                writeln!(out, "    }}").ok();
            } else {
                return Err(CodegenError::Unsupported {
                    context: format!("rust_guest::rpc({})", rpc.canonical_name),
                    detail: format!(
                        "nested RPC field `{}` root `{root_name}` has unsupported backing `{root_rt}`",
                        wf.field_name
                    ),
                });
            }
        } else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::rpc({})", rpc.canonical_name),
                detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
            });
        }
    }
    writeln!(out, "    pkt\n}}\n").ok();

    let len_check = if rpc.packed_bytes > 0 {
        format!(" || pkt.payload_bytes < {}", rpc.packed_bytes)
    } else {
        String::new()
    };
    writeln!(
        out,
        "pub fn strata_net_decode_rpc_{ident}(pkt: &StrataNetPacket, out_rpc: &mut {rty}) -> bool {{\n\
         \x20   if !strata_net_verify_handshake(pkt, 0x{fp:016X}) || pkt.item_schema_fingerprint != 0x{fp:016X} {{\n\
         \x20       return false;\n\
         \x20   }}\n\
         \x20   if pkt.target_id != 0x{rpc_id:016X} || pkt.kind != PACKET_KIND_RPC{len_check} {{\n\
         \x20       return false;\n\
         \x20   }}",
    )
    .ok();
    for wf in &rpc.wire_fields {
        if let Some((_, mty, _, sz)) = rpc.fields.iter().find(|(n, _, _, _)| n == &wf.field_name) {
            let rf = sanitize_rust_ident(&wf.field_name);
            let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
            emit_rust_wire_field_decode(out, wf, &rf, &rt, "out_rpc")?;
        } else if let Some(root) = wf.field_name.split('.').next()
            && let Some((root_name, root_mty, root_off, root_sz)) =
                rpc.fields.iter().find(|(n, _, _, _)| n == root)
        {
            let root_rf = sanitize_rust_ident(root_name);
            let root_rt = rust_abi_type_for_mir_ty(root_mty, *root_sz, mir);
            if root_rt.starts_with("[u8;") {
                let rty = rust_abi_type_for_mir_ty(&wf.ty, wf.byte_size, mir);
                let def = rust_default_expr_for_mir_ty(&wf.ty, wf.byte_size, mir);
                let rel_off = wf.byte_offset.saturating_sub(*root_off) as usize;
                writeln!(
                    out,
                    "    {{\n\
                     \x20       let out = &mut out_rpc.{root_rf}[..];\n\
                     \x20       let mut __wf: {rty} = {def};\n\
                     \x20       {{ let b = &out[..];"
                )
                .ok();
                emit_read_field_from_bytes(out, "__wf", &rty, rel_off, wf.byte_size as usize);
                writeln!(out, "        }}").ok();
                emit_rust_wire_field_decode(out, wf, "__wf", &rty, "")?;
                emit_write_field_to_bytes(out, "__wf", &rty, rel_off, wf.byte_size as usize);
                writeln!(out, "    }}").ok();
            } else {
                return Err(CodegenError::Unsupported {
                    context: format!("rust_guest::rpc({})", rpc.canonical_name),
                    detail: format!(
                        "nested RPC field `{}` root `{root_name}` has unsupported backing `{root_rt}`",
                        wf.field_name
                    ),
                });
            }
        } else {
            return Err(CodegenError::Unsupported {
                context: format!("rust_guest::rpc({})", rpc.canonical_name),
                detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
            });
        }
    }
    writeln!(out, "    true\n}}\n").ok();
    Ok(())
}

pub(super) fn emit_net_synthesized_systems(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    let rep_comps: Vec<&MirNetComponent> = mir
        .net_components
        .iter()
        .filter(|nc| nc.is_replicated)
        .collect();
    if rep_comps.is_empty() {
        return;
    }
    let max_per_sys = bamabi_sys::MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
    for (chunk_idx, chunk) in rep_comps.chunks(max_per_sys).enumerate() {
        // RX system
        writeln!(
            out,
            "fn strata_net_rx_{chunk_idx}(ctx: &mut SystemContext<'_>, world: &Arc<Mutex<StrataWorldState>>, handles: &StrataHandles, msg_decl_idx: usize) -> FfiResult {{\n\
             \x20   let _ = world;\n\
             \x20   let _ = handles;\n\
             \x20   let Ok(pkts) = ctx.read_messages::<StrataNetPacket>(msg_decl_idx) else {{ return FfiResult::OK; }};\n\
             \x20   if pkts.is_empty() {{ return FfiResult::OK; }}"
        )
        .ok();
        let mut qi = 0usize;
        let mut res_decl_idx = 0usize;
        for nc in chunk {
            let ident = sanitize_ident(&nc.name);
            let target_id = fnv1a_64_str(&nc.canonical_name);
            if nc.is_resource {
                let Some(comp) = cat.resolve_comp(&nc.canonical_name) else {
                    continue;
                };
                let sname = &comp.struct_name;
                let hf = &comp.handle_field;
                let r_idx = res_decl_idx;
                res_decl_idx += 1;
                writeln!(
                    out,
                    "    if handles.is_host_res_{cid} {{\n\
                     \x20       if let Some(last_pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_RESOURCE_DELTA && p.target_id == 0x{target_id:016X}) {{\n\
                     \x20           if let Some(mut res) = ctx.res_mut_by_handle::<{sname}>(handles.{hf}) {{\n\
                     \x20               let mut decoded = *res;\n\
                     \x20               if strata_net_decode_{ident}(last_pkt, &mut decoded) && decoded.strata_to_u8_bytes() != res.strata_to_u8_bytes() {{\n\
                     \x20                   *res = decoded;\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}\n\
                     \x20       let _ = {r_idx};\n\
                     \x20   }} else if let Some(last_pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_RESOURCE_DELTA && p.target_id == 0x{target_id:016X}) {{\n\
                     \x20       if let Ok(mut w) = world.lock() {{\n\
                     \x20           let mut decoded = w.mod_res_{cid};\n\
                     \x20           if strata_net_decode_{ident}(last_pkt, &mut decoded) {{\n\
                     \x20               let dec_bytes = decoded.strata_to_u8_bytes();\n\
                     \x20               if dec_bytes != w.mod_res_{cid}.strata_to_u8_bytes() {{\n\
                     \x20                   w.mod_res_{cid} = decoded;\n\
                     \x20               }}\n\
                     \x20               w.mod_res_{cid}_shadow = dec_bytes;\n\
                     \x20           }}\n\
                     \x20       }}\n\
                     \x20   }}",
                    cid = comp.id,
                )
                .ok();
            } else {
                let Ok(strata) = net_comp_strata(nc, cat) else {
                    continue;
                };
                if strata.is_empty() {
                    continue;
                }
                let cur_qi = qi;
                qi += 1;
                writeln!(
                    out,
                    "    if pkts.iter().any(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X}) {{\n\
                     \x20       if let Some(it) = ctx.query_mut({cur_qi}) {{\n\
                     \x20           while let Some(len) = it.next_chunk() {{"
                )
                .ok();
                if strata.len() == 1 {
                    let comp = strata[0].1;
                    let sname = &comp.struct_name;
                    let is_sparse = (comp.layout.component_flags
                        & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    if is_sparse {
                        writeln!(
                            out,
                            "                let mut dirty_rows: Vec<usize> = Vec::new();\n\
                             \x20               {{\n\
                             \x20                   let ents = it.entities().to_vec();\n\
                             \x20                   if let Some(mut rows) = it.component_rows_mut::<{sname}>(0) {{\n\
                             \x20                       for row in 0..len.min(ents.len()).min(rows.len()) {{\n\
                             \x20                           let ebits = ents[row].to_bits();\n\
                             \x20                           if let Some(pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X} && p.entity_bits == ebits) {{\n\
                             \x20                               if let Some(cur) = rows.get_mut(row) {{\n\
                             \x20                                   let mut decoded = *cur;\n\
                             \x20                                   if strata_net_decode_{ident}(pkt, &mut decoded) && decoded.strata_to_u8_bytes() != cur.strata_to_u8_bytes() {{\n\
                             \x20                                       *cur = decoded;\n\
                             \x20                                       dirty_rows.push(row);\n\
                             \x20                                   }}\n\
                             \x20                               }}\n\
                             \x20                           }}\n\
                             \x20                       }}\n\
                             \x20                   }}\n\
                             \x20               }}\n\
                             \x20               for row in dirty_rows {{ let _ = it.mark_changed_range(0, row, 1); }}"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                let mut dirty_rows: Vec<usize> = Vec::new();\n\
                             \x20               {{\n\
                             \x20                   let ents = it.entities().to_vec();\n\
                             \x20                   if let Some(slice) = it.mutable_slice_untracked(0).as_component_slice_mut::<{sname}>() {{\n\
                             \x20                       for row in 0..len.min(ents.len()).min(slice.len()) {{\n\
                             \x20                           let ebits = ents[row].to_bits();\n\
                             \x20                           if let Some(pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X} && p.entity_bits == ebits) {{\n\
                             \x20                               let mut decoded = slice[row];\n\
                             \x20                               if strata_net_decode_{ident}(pkt, &mut decoded) && decoded.strata_to_u8_bytes() != slice[row].strata_to_u8_bytes() {{\n\
                             \x20                                   slice[row] = decoded;\n\
                             \x20                                   dirty_rows.push(row);\n\
                             \x20                               }}\n\
                             \x20                           }}\n\
                             \x20                       }}\n\
                             \x20                   }}\n\
                             \x20               }}\n\
                             \x20               for row in dirty_rows {{ let _ = it.mark_changed_range(0, row, 1); }}"
                        )
                        .ok();
                    }
                } else {
                    writeln!(
                        out,
                        "                let ents = it.entities().to_vec();\n\
                         \x20               let mut matched: Vec<(usize, &StrataNetPacket)> = Vec::new();\n\
                         \x20               for row in 0..len.min(ents.len()) {{\n\
                         \x20                   let ebits = ents[row].to_bits();\n\
                         \x20                   if let Some(pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X} && p.entity_bits == ebits) {{\n\
                         \x20                       matched.push((row, pkt));\n\
                         \x20                   }}\n\
                         \x20               }}\n\
                         \x20               if !matched.is_empty() {{"
                    )
                    .ok();
                    for (si, (_, comp)) in strata.iter().enumerate() {
                        let sname = &comp.struct_name;
                        let is_sparse = (comp.layout.component_flags
                            & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                            != 0;
                        writeln!(
                            out,
                            "                    let mut cur_{si}: Vec<{sname}> = vec![{sname}::default(); matched.len()];\n\
                             \x20                   let mut dirty_{si}: Vec<(usize, {sname})> = Vec::new();"
                        )
                        .ok();
                        if is_sparse {
                            writeln!(
                                out,
                                "                    if let Some(rows) = it.component_rows_mut::<{sname}>({si}) {{\n\
                                 \x20                       for (mi, &(row, _)) in matched.iter().enumerate() {{\n\
                                 \x20                           if let Some(v) = rows.get(row) {{ cur_{si}[mi] = *v; }}\n\
                                 \x20                       }}\n\
                                 \x20                   }}"
                            )
                            .ok();
                        } else {
                            writeln!(
                                out,
                                "                    if let Some(slice) = it.mutable_slice_untracked({si}).as_component_slice_mut::<{sname}>() {{\n\
                                 \x20                       for (mi, &(row, _)) in matched.iter().enumerate() {{\n\
                                 \x20                           if let Some(v) = slice.get(row) {{ cur_{si}[mi] = *v; }}\n\
                                 \x20                       }}\n\
                                 \x20                   }}"
                            )
                            .ok();
                        }
                    }
                    let dec_args = (0..strata.len())
                        .map(|si| format!("&mut d_{si}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        out,
                        "                    for (mi, &(row, pkt)) in matched.iter().enumerate() {{"
                    )
                    .ok();
                    for si in 0..strata.len() {
                        writeln!(
                            out,
                            "                        let mut d_{si} = cur_{si}[mi];"
                        )
                        .ok();
                    }
                    writeln!(
                        out,
                        "                        if strata_net_decode_{ident}(pkt, {dec_args}) {{"
                    )
                    .ok();
                    for si in 0..strata.len() {
                        writeln!(
                            out,
                            "                            if d_{si}.strata_to_u8_bytes() != cur_{si}[mi].strata_to_u8_bytes() {{ dirty_{si}.push((row, d_{si})); }}"
                        )
                        .ok();
                    }
                    writeln!(out, "                        }}\n                    }}").ok();
                    for (si, (_, comp)) in strata.iter().enumerate() {
                        let sname = &comp.struct_name;
                        let is_sparse = (comp.layout.component_flags
                            & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                            != 0;
                        writeln!(out, "                    if !dirty_{si}.is_empty() {{").ok();
                        if is_sparse {
                            writeln!(
                                out,
                                "                        if let Some(mut rows) = it.component_rows_mut::<{sname}>({si}) {{\n\
                                 \x20                           for &(row, val) in &dirty_{si} {{\n\
                                 \x20                               if let Some(dst) = rows.get_mut(row) {{ *dst = val; }}\n\
                                 \x20                           }}\n\
                                 \x20                       }}"
                            )
                            .ok();
                        } else {
                            writeln!(
                                out,
                                "                        if let Some(slice) = it.mutable_slice_untracked({si}).as_component_slice_mut::<{sname}>() {{\n\
                                 \x20                           for &(row, val) in &dirty_{si} {{\n\
                                 \x20                               if let Some(dst) = slice.get_mut(row) {{ *dst = val; }}\n\
                                 \x20                           }}\n\
                                 \x20                       }}"
                            )
                            .ok();
                        }
                        writeln!(
                            out,
                            "                        for &(row, _) in &dirty_{si} {{ let _ = it.mark_changed_range({si}, row, 1); }}\n\
                             \x20                   }}"
                        )
                        .ok();
                    }
                    writeln!(out, "                }}").ok();
                }
                writeln!(out, "            }}\n        }}\n    }}").ok();
            }
        }
        writeln!(out, "    FfiResult::OK\n}}\n").ok();

        // TX system
        writeln!(
            out,
            "fn strata_net_tx_{chunk_idx}(ctx: &mut SystemContext<'_>, world: &Arc<Mutex<StrataWorldState>>, handles: &StrataHandles, msg_decl_idx: usize) -> FfiResult {{\n\
             \x20   let _ = world;\n\
             \x20   let _ = handles;\n\
             \x20   let mut out_pkts: Vec<StrataNetPacket> = Vec::new();"
        )
        .ok();
        let has_res_in_chunk = chunk
            .iter()
            .any(|nc| nc.is_resource && cat.resolve_comp(&nc.canonical_name).is_some());
        if has_res_in_chunk {
            writeln!(out, "    let mut _tx_res_decl: usize = 0;").ok();
        }
        let mut tx_qi = 0usize;
        for nc in chunk {
            let ident = sanitize_ident(&nc.name);
            if nc.is_resource {
                let Some(comp) = cat.resolve_comp(&nc.canonical_name) else {
                    continue;
                };
                let sname = &comp.struct_name;
                writeln!(
                    out,
                    "    if handles.is_host_res_{cid} {{\n\
                     \x20       let _cur_res_decl = _tx_res_decl;\n\
                     \x20       _tx_res_decl += 1;\n\
                     \x20       if let Ok(gres) = ctx.res_with_ticks::<{sname}>(_cur_res_decl) {{\n\
                     \x20           if gres.is_changed() {{\n\
                     \x20               out_pkts.push(strata_net_encode_{ident}(&gres, 0, gres.ticks().this_run, 0));\n\
                     \x20           }}\n\
                     \x20       }}\n\
                     \x20   }} else if let Ok(mut w) = world.lock() {{\n\
                     \x20       let cur_bytes = w.mod_res_{cid}.strata_to_u8_bytes();\n\
                     \x20       if cur_bytes != w.mod_res_{cid}_shadow {{\n\
                     \x20           w.mod_res_{cid}_shadow = cur_bytes;\n\
                     \x20           out_pkts.push(strata_net_encode_{ident}(&w.mod_res_{cid}, 0, 0, 0));\n\
                     \x20       }}\n\
                     \x20   }}",
                    cid = comp.id,
                )
                .ok();
            } else {
                let Ok(strata) = net_comp_strata(nc, cat) else {
                    continue;
                };
                if strata.is_empty() {
                    continue;
                }
                let cur_qi = tx_qi;
                tx_qi += 1;
                writeln!(out, "    if let Some(it) = ctx.query_mut({cur_qi}) {{").ok();
                writeln!(out, "        while let Some(len) = it.next_chunk() {{").ok();
                if strata.len() == 1 {
                    let comp = strata[0].1;
                    let sname = &comp.struct_name;
                    let is_sparse = (comp.layout.component_flags
                        & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    if is_sparse {
                        writeln!(
                            out,
                            "            let ents = it.entities().to_vec();\n\
                             \x20           if let Some(rows) = it.component_rows::<{sname}>(0) {{\n\
                             \x20               for row in 0..len.min(ents.len()).min(rows.len()) {{\n\
                             \x20                   out_pkts.push(strata_net_encode_{ident}(&rows[row], ents[row].to_bits(), 0, 0));\n\
                             \x20               }}\n\
                             \x20           }}"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "            let ents = it.entities();\n\
                             \x20           if let Some(slice) = it.readonly_slice(0).as_component_slice::<{sname}>() {{\n\
                             \x20               for row in 0..len.min(ents.len()).min(slice.len()) {{\n\
                             \x20                   out_pkts.push(strata_net_encode_{ident}(&slice[row], ents[row].to_bits(), 0, 0));\n\
                             \x20               }}\n\
                             \x20           }}"
                        )
                        .ok();
                    }
                } else {
                    writeln!(out, "            let ents = it.entities();").ok();
                    let mut conds = Vec::new();
                    for (si, (_, comp)) in strata.iter().enumerate() {
                        let sname = &comp.struct_name;
                        let is_sparse = (comp.layout.component_flags
                            & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                            != 0;
                        if is_sparse {
                            conds.push(format!(
                                "let Some(_col_{si}) = it.component_rows::<{sname}>({si})"
                            ));
                        } else {
                            conds.push(format!("let Some(_col_{si}) = it.readonly_slice({si}).as_component_slice::<{sname}>()"));
                        }
                    }
                    let row_bounds = (0..strata.len())
                        .fold("len.min(ents.len())".to_owned(), |acc, si| {
                            format!("{acc}.min(_col_{si}.len())")
                        });
                    let enc_args = (0..strata.len())
                        .map(|si| format!("&_col_{si}[row]"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        out,
                        "            if {cond_expr} {{\n\
                         \x20               for row in 0..{row_bounds} {{\n\
                         \x20                   out_pkts.push(strata_net_encode_{ident}({enc_args}, ents[row].to_bits(), 0, 0));\n\
                         \x20               }}\n\
                         \x20           }}",
                        cond_expr = conds.join(" && "),
                    )
                    .ok();
                }
                writeln!(out, "        }}\n    }}").ok();
            }
        }
        writeln!(
            out,
            "    if !out_pkts.is_empty() {{\n\
             \x20       let _ = ctx.send_messages::<StrataNetPacket>(msg_decl_idx, &out_pkts);\n\
             \x20   }}\n\
             \x20   FfiResult::OK\n\
             }}\n"
        )
        .ok();
    }
}

pub(super) fn field_default_expr_honoring_mir(
    layout: &SolvedLayout,
    field: &SolvedField,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    let lookup_short = layout
        .canonical_name
        .rsplit("::")
        .next()
        .unwrap_or(&layout.canonical_name);
    let const_val = mir
        .field_defaults
        .get(&layout.canonical_name)
        .and_then(|m| m.get(&field.name))
        .or_else(|| {
            mir.field_defaults
                .iter()
                .find(|(k, _)| {
                    *k == &layout.canonical_name || k.rsplit("::").next() == Some(lookup_short)
                })
                .and_then(|(_, m)| m.get(&field.name))
        });

    if let Some(cv) = const_val {
        return format_mir_const_for_field(cv, &field.ty, field.size, field.align, mir, cat);
    }

    guest_default_expr_for_ty(&field.ty, field.size, field.align, mir, cat)
}

pub(super) fn guest_default_expr_for_ty(
    ty: &Ty,
    byte_size: usize,
    align: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match ty {
        Ty::Named(n) if find_enum_layout_or_def(n, mir).is_none() => {
            if let Some(nested) = cat.resolve_comp(n)
                && nested.layout.size == byte_size
                && !nested.layout.fields.is_empty()
            {
                return pack_nested_default_expr(nested, byte_size, align);
            }
            rust_default_expr_for_ty(ty, byte_size, mir)
        }
        Ty::Array { elem, len } => {
            let elem_sz = byte_size / (*len).max(1);
            let elem_align = match &**elem {
                Ty::Named(n) => cat
                    .resolve_comp(n)
                    .map_or(align, |nested| nested.layout.align),
                _ => align,
            };
            let elem_def = guest_default_expr_for_ty(elem, elem_sz, elem_align, mir, cat);
            format!("[{elem_def}; {len}]")
        }
        _ => rust_default_expr_for_ty(ty, byte_size, mir),
    }
}

pub(super) fn pack_nested_default_expr(comp: &ComponentEntry, size: usize, align: usize) -> String {
    let sname = &comp.struct_name;
    let blob_ty = aligned_blob_type(size, align);
    format!(
        "{{ let _v = {sname}::strata_const_default(); _v.strata_to_blob_{sz}_{al}() }}",
        sz = size,
        al = align.max(1)
    )
    .replace(
        &format!("strata_to_blob_{size}_{}", align.max(1)),
        if blob_ty.starts_with("[u64;") {
            "strata_to_u64_words"
        } else if blob_ty.starts_with("[u32;") {
            "strata_to_u32_words"
        } else if blob_ty.starts_with("[u16;") {
            "strata_to_u16_words"
        } else {
            "strata_to_u8_bytes"
        },
    )
}

pub(super) fn format_mir_const_for_field(
    cv: &MirConstVal,
    ty: &Ty,
    byte_size: usize,
    align: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match (cv, ty) {
        (MirConstVal::Bool(b), Ty::Bool) => {
            if *b {
                "FfiBool::TRUE".to_owned()
            } else {
                "FfiBool::FALSE".to_owned()
            }
        }
        (MirConstVal::Int(v), Ty::U8) => format!("{v}i64 as u8"),
        (MirConstVal::Int(v), Ty::I8) => format!("{v}i64 as i8"),
        (MirConstVal::Int(v), Ty::U16) => format!("{v}i64 as u16"),
        (MirConstVal::Int(v), Ty::I16) => format!("{v}i64 as i16"),
        (MirConstVal::Int(v), Ty::U32 | Ty::Sym | Ty::Rgba8) => format!("{v}i64 as u32"),
        (MirConstVal::Int(v), Ty::I32) => format!("{v}i64 as i32"),
        (MirConstVal::Int(v), Ty::Fix32) => format_fix32_i32_lit(scale_int_fix32(*v)),
        (MirConstVal::Int(v), Ty::U64) => format!("{v}i64 as u64"),
        (MirConstVal::Int(v), Ty::I64) => format!("{v}i64"),
        (MirConstVal::Int(v), Ty::Fix64) => format_fix64_i64_lit(scale_int_fix64(*v)),
        (MirConstVal::Int(v), Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow) => {
            format!("{}f32", *v as f32)
        }
        (MirConstVal::Int(v), Ty::F64) => format!("{}f64", *v as f64),
        (MirConstVal::Float(v), Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow) => {
            fmt_f32(*v as f32)
        }
        (MirConstVal::Float(v), Ty::F64) => fmt_f64(*v),
        (MirConstVal::Float(v), Ty::Fix32) => format_fix32_i32_lit(scale_float_fix32(*v)),
        (MirConstVal::Float(v), Ty::Fix64) => format_fix64_i64_lit(scale_float_fix64(*v)),
        (MirConstVal::Int(v), Ty::Bool) => {
            if *v != 0 {
                "FfiBool::TRUE".to_owned()
            } else {
                "FfiBool::FALSE".to_owned()
            }
        }
        (MirConstVal::Vec2(v), Ty::Vec2) => {
            format!("[{}, {}]", fmt_f32(v[0] as f32), fmt_f32(v[1] as f32))
        }
        (MirConstVal::Vec3(v), Ty::Vec3) => format!(
            "[{}, {}, {}]",
            fmt_f32(v[0] as f32),
            fmt_f32(v[1] as f32),
            fmt_f32(v[2] as f32)
        ),
        (MirConstVal::Vec4(v), Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba) => format!(
            "[{}, {}, {}, {}]",
            fmt_f32(v[0] as f32),
            fmt_f32(v[1] as f32),
            fmt_f32(v[2] as f32),
            fmt_f32(v[3] as f32)
        ),
        (MirConstVal::Vec2(v), Ty::IVec2) => format!("[{}i32, {}i32]", v[0] as i32, v[1] as i32),
        (MirConstVal::Vec3(v), Ty::IVec3) => format!(
            "[{}i32, {}i32, {}i32]",
            v[0] as i32, v[1] as i32, v[2] as i32
        ),
        (MirConstVal::Vec2(v), Ty::UVec2) => format!("[{}u32, {}u32]", v[0] as u32, v[1] as u32),
        (MirConstVal::Int(v), Ty::BitSet(bits)) => {
            let words = (*bits).div_ceil(32).max(1);
            let mask = *v as u64;
            let mut out_words = Vec::with_capacity(words);
            for w in 0..words {
                let word = if w == 0 {
                    mask as u32
                } else if w == 1 {
                    (mask >> 32) as u32
                } else {
                    0
                };
                out_words.push(format!("{word}u32"));
            }
            format!("[{}]", out_words.join(", "))
        }
        (MirConstVal::String(s), Ty::InlineStr(cap)) => {
            let words = 1 + cap.div_ceil(4);
            let mut out_words = vec![0u32; words];
            let mut end = s.len().min(*cap);
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            out_words[0] = end as u32;
            for (wi, chunk) in s.as_bytes()[..end].chunks(4).enumerate() {
                let mut arr = [0u8; 4];
                arr[..chunk.len()].copy_from_slice(chunk);
                out_words[1 + wi] = u32::from_le_bytes(arr);
            }
            let parts: Vec<String> = out_words.iter().map(|w| format!("{w}u32")).collect();
            format!("[{}]", parts.join(", "))
        }
        (MirConstVal::Int(v), Ty::Named(n)) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                match (sz, is_signed) {
                    (1, _) => format!("{v}i64 as u8"),
                    (2, _) => format!("{v}i64 as u16"),
                    (_, true) => format!("{v}i64 as i32"),
                    _ => format!("{v}i64 as u32"),
                }
            } else {
                rust_default_expr_for_ty(ty, byte_size, mir)
            }
        }
        (MirConstVal::Array(items), Ty::BitSet(bits)) => {
            let words = (*bits).div_ceil(32).max(1);
            let mut mask_words = vec![0u32; words];
            for item in items {
                if let MirConstVal::Int(bit) = item
                    && *bit >= 0
                {
                    let b = *bit as usize;
                    if b / 32 < words {
                        mask_words[b / 32] |= 1u32 << (b % 32);
                    }
                }
            }
            let parts: Vec<String> = mask_words.iter().map(|w| format!("{w}u32")).collect();
            format!("[{}]", parts.join(", "))
        }
        (MirConstVal::Array(items), Ty::Mat3) => {
            let mut vals: Vec<String> = items
                .iter()
                .take(9)
                .map(|it| match it {
                    MirConstVal::Float(f) => fmt_f32(*f as f32),
                    MirConstVal::Int(i) => fmt_f32(*i as f32),
                    _ => "0.0f32".to_owned(),
                })
                .collect();
            while vals.len() < 9 {
                vals.push("0.0f32".to_owned());
            }
            format!("[{}]", vals.join(", "))
        }
        (MirConstVal::Array(items), Ty::Mat4) => {
            let mut vals: Vec<String> = items
                .iter()
                .take(16)
                .map(|it| match it {
                    MirConstVal::Float(f) => fmt_f32(*f as f32),
                    MirConstVal::Int(i) => fmt_f32(*i as f32),
                    _ => "0.0f32".to_owned(),
                })
                .collect();
            while vals.len() < 16 {
                vals.push("0.0f32".to_owned());
            }
            format!("[{}]", vals.join(", "))
        }
        (MirConstVal::Array(items), Ty::SmallVec { elem, cap }) => {
            let (elem_sz, elem_align) = guest_ty_abi_size_align(elem, mir);
            let elem_exprs: Vec<String> = items
                .iter()
                .take(*cap)
                .map(|it| format_mir_const_for_field(it, elem, elem_sz, elem_align, mir, cat))
                .collect();
            emit_const_pack_smallvec_expr(&elem_exprs, elem, byte_size, align, *cap, mir, cat)
        }
        (MirConstVal::Array(items), Ty::Array { elem, len }) => {
            let elem_sz = byte_size / (*len).max(1);
            let elem_align = match &**elem {
                Ty::Named(n) => cat
                    .resolve_comp(n)
                    .map_or(align, |nested| nested.layout.align),
                _ => align,
            };
            let mut rendered: Vec<String> = items
                .iter()
                .take(*len)
                .map(|it| format_mir_const_for_field(it, elem, elem_sz, elem_align, mir, cat))
                .collect();
            while rendered.len() < *len {
                rendered.push(guest_default_expr_for_ty(
                    elem, elem_sz, elem_align, mir, cat,
                ));
            }
            format!("[{}]", rendered.join(", "))
        }
        (MirConstVal::Struct { name, fields }, Ty::Named(tn)) => {
            if let Some(nested) = cat.resolve_comp(name).or_else(|| cat.resolve_comp(tn))
                && nested.layout.size == byte_size
                && !nested.layout.fields.is_empty()
            {
                let mut f_inits = Vec::new();
                for (fname, val) in fields {
                    if let Some(sf) = nested.layout.fields.iter().find(|f| f.name == *fname) {
                        let rname = sanitize_rust_ident(fname);
                        let val_s =
                            format_mir_const_for_field(val, &sf.ty, sf.size, sf.align, mir, cat);
                        f_inits.push(format!("{rname}: {val_s}"));
                    }
                }
                let sname = &nested.struct_name;
                let blob_ty = aligned_blob_type(byte_size, align);
                let conv = if blob_ty.starts_with("[u64;") {
                    "strata_to_u64_words"
                } else if blob_ty.starts_with("[u32;") {
                    "strata_to_u32_words"
                } else if blob_ty.starts_with("[u16;") {
                    "strata_to_u16_words"
                } else {
                    "strata_to_u8_bytes"
                };
                return if f_inits.is_empty() {
                    format!("{sname}::strata_const_default().{conv}()")
                } else {
                    format!(
                        "{{ let _v = {sname} {{ {}, ..{sname}::strata_const_default() }}; _v.{conv}() }}",
                        f_inits.join(", ")
                    )
                };
            }
            guest_default_expr_for_ty(ty, byte_size, align, mir, cat)
        }
        _ => guest_default_expr_for_ty(ty, byte_size, align, mir, cat),
    }
}

// ============================================================================
// Unified Safe Runtime Support (`StrataVal`, `StrataObj`, `StrataPtr`, Spatial, WorldState)
// ============================================================================

pub(super) fn emit_runtime_core(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    // 1. Per-component & relation BamComponent handle table + shared World state
    writeln!(out, "#[derive(Clone, Copy, Debug)]").ok();
    writeln!(out, "struct StrataHandles {{").ok();
    for c in &cat.components {
        writeln!(out, "    {}: BamComponent,", c.handle_field).ok();
        if c.is_resource_like() {
            writeln!(out, "    is_host_res_{}: bool,", c.id).ok();
        }
    }
    for r in &cat.relations {
        writeln!(out, "    {}: BamComponent,", r.handle_field).ok();
    }
    writeln!(out, "    bam_child_of: BamComponent,").ok();
    writeln!(out, "}}").ok();

    writeln!(out, "impl Default for StrataHandles {{").ok();
    writeln!(out, "    fn default() -> Self {{").ok();
    writeln!(out, "        Self {{").ok();
    for c in &cat.components {
        writeln!(
            out,
            "            {}: BamComponent::INVALID,",
            c.handle_field
        )
        .ok();
        if c.is_resource_like() {
            writeln!(out, "            is_host_res_{}: false,", c.id).ok();
        }
    }
    for r in &cat.relations {
        writeln!(
            out,
            "            {}: BamComponent::INVALID,",
            r.handle_field
        )
        .ok();
    }
    writeln!(out, "            bam_child_of: BamComponent::INVALID,").ok();
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}\n").ok();

    writeln!(
        out,
        "#[derive(Clone, Debug, Default)]
         struct StrataSpatialCsrFrame {{
             count: u32,
             cell_offsets: Vec<u32>,
             entities: Vec<FfiEntity>,
             positions: Vec<[f32; 4]>,
         }}

         #[derive(Clone, Debug, Default)]
         struct StrataSpatialGridState {{
             frames: usize,
             capacity: usize,
             cols: u32,
             rows: u32,
             cell_count: usize,
             head_tick: usize,
             cell_size: f32,
             inv_cell_size: f32,
             bounds_min: [f32; 2],
             plane_axes: [u8; 2],
             write_cursors: Vec<u32>,
             ring: Vec<StrataSpatialCsrFrame>,
         }}

         impl StrataSpatialGridState {{
             fn new(frames: usize, capacity: usize, cols: u32, rows: u32, cell_size: f32, bounds_min: [f32; 2], plane_axes: [u8; 2]) -> Self {{
                 let f = frames.max(1);
                 let cap = capacity.max(1);
                 let c = cols.max(1);
                 let r = rows.max(1);
                 let cell_count = (c as usize) * (r as usize);
                 let cs = if cell_size > 0.0 {{ cell_size }} else {{ 4.0 }};
                 let mut ring = Vec::with_capacity(f);
                 for _ in 0..f {{
                     ring.push(StrataSpatialCsrFrame {{
                         count: 0,
                         cell_offsets: vec![0u32; cell_count + 1],
                         entities: vec![FfiEntity::NULL; cap],
                         positions: vec![[0.0; 4]; cap],
                     }});
                 }}
                 Self {{
                     frames: f,
                     capacity: cap,
                     cols: c,
                     rows: r,
                     cell_count,
                     head_tick: 0,
                     cell_size: cs,
                     inv_cell_size: 1.0 / cs,
                     bounds_min,
                     plane_axes,
                     write_cursors: vec![0u32; cell_count],
                     ring,
                 }}
             }}

             #[inline]
             fn clamp_cell_coord(coord: f32, bmin: f32, inv_cs: f32, dim: u32) -> u32 {{
                 let max_c = dim.saturating_sub(1) as i32;
                 let f = ((coord - bmin) * inv_cs).floor();
                 if !f.is_finite() {{ return 0; }}
                 (f as i32).clamp(0, max_c) as u32
             }}

             #[inline]
             fn quantize_cell(&self, pos: [f32; 4]) -> usize {{
                 let ax0 = (self.plane_axes[0] as usize).min(2);
                 let ax1 = (self.plane_axes[1] as usize).min(2);
                 let cx = Self::clamp_cell_coord(pos[ax0], self.bounds_min[0], self.inv_cell_size, self.cols);
                 let cy = Self::clamp_cell_coord(pos[ax1], self.bounds_min[1], self.inv_cell_size, self.rows);
                 (cy as usize) * (self.cols as usize) + (cx as usize)
             }}

             fn csr_begin(&mut self) {{
                 if self.ring.is_empty() {{ return; }}
                 if self.frames > 1 {{
                     self.head_tick = (self.head_tick + 1) % self.frames;
                 }} else {{
                     self.head_tick = 0;
                 }}
                 let f = self.head_tick % self.ring.len();
                 let fr = &mut self.ring[f];
                 fr.count = 0;
                 fr.cell_offsets.fill(0);
             }}

             fn csr_count(&mut self, pos: [f32; 4]) {{
                 if self.ring.is_empty() || self.cell_count == 0 {{ return; }}
                 let cell = self.quantize_cell(pos);
                 let f = self.head_tick % self.ring.len();
                 let fr = &mut self.ring[f];
                 if (fr.count as usize) >= self.capacity {{ return; }}
                 fr.count += 1;
                 if cell + 1 < fr.cell_offsets.len() {{
                     fr.cell_offsets[cell + 1] += 1;
                 }}
             }}

             fn csr_prefix_sum(&mut self) {{
                 if self.ring.is_empty() {{ return; }}
                 let f = self.head_tick % self.ring.len();
                 let fr = &mut self.ring[f];
                 if self.write_cursors.len() != self.cell_count {{
                     self.write_cursors.resize(self.cell_count, 0);
                 }}
                 let mut run = 0u32;
                 for c in 0..self.cell_count {{
                     let cnt = fr.cell_offsets[c + 1];
                     fr.cell_offsets[c] = run;
                     self.write_cursors[c] = run;
                     run += cnt;
                 }}
                 fr.cell_offsets[self.cell_count] = run;
             }}

             fn csr_scatter(&mut self, ent: FfiEntity, pos: [f32; 4]) {{
                 if self.ring.is_empty() || self.cell_count == 0 {{ return; }}
                 let cell = self.quantize_cell(pos);
                 let f = self.head_tick % self.ring.len();
                 let fr = &mut self.ring[f];
                 if cell >= self.write_cursors.len() || cell + 1 >= fr.cell_offsets.len() {{ return; }}
                 let slot = self.write_cursors[cell] as usize;
                 let cell_end = fr.cell_offsets[cell + 1] as usize;
                 if slot < cell_end && slot < fr.entities.len() {{
                     self.write_cursors[cell] = (slot + 1) as u32;
                     fr.entities[slot] = ent;
                     fr.positions[slot] = pos;
                 }}
             }}

             #[inline]
             fn csr_cell_range(offsets: &[u32], cell: usize, total: usize) -> Option<(usize, usize)> {{
                 let s = *offsets.get(cell)? as usize;
                 let e = *offsets.get(cell.checked_add(1)?)? as usize;
                 if s > e || e > total {{ return None; }}
                 Some((s, e))
             }}
         }}

         #[derive(Debug)]\n\
          struct StrataWorldState {{\n\
          \x20   named_objects: HashMap<String, FfiEntity>,\n\
          \x20   spatial: HashMap<String, StrataSpatialGridState>,"
    )
    .ok();
    for c in &cat.components {
        if c.is_resource_like() {
            let shadow_sz = if c.layout.fields.is_empty() {
                0
            } else {
                c.layout.size
            };
            writeln!(out, "    mod_res_{}: {},", c.id, c.struct_name).ok();
            writeln!(out, "    mod_res_{}_shadow: [u8; {shadow_sz}],", c.id).ok();
        }
    }
    writeln!(
        out,
        "}}\n\
         impl Default for StrataWorldState {{\n\
         \x20   fn default() -> Self {{\n\
         \x20       Self {{\n\
         \x20           named_objects: HashMap::new(),\n\
         \x20           spatial: HashMap::new(),"
    )
    .ok();
    for c in &cat.components {
        if c.is_resource_like() {
            writeln!(
                out,
                "            mod_res_{}: {}::default(),",
                c.id, c.struct_name
            )
            .ok();
            if c.layout.size == 0 || c.layout.fields.is_empty() {
                writeln!(out, "            mod_res_{}_shadow: [],", c.id).ok();
            } else {
                writeln!(
                    out,
                    "            mod_res_{}_shadow: {}::default().strata_to_u8_bytes(),",
                    c.id, c.struct_name
                )
                .ok();
            }
        }
    }
    writeln!(out, "        }}\n    }}\n}}\n").ok();

    // Safe SoA batch spawn buffer for indexed `SpawnBatchBegin` / `SpawnBatchPush` / `SpawnBatchCommit`.
    writeln!(out, "enum StrataBatchColumn {{").ok();
    writeln!(
        out,
        "    Marker {{ comp_id: usize, handle: BamComponent, count: usize }},"
    )
    .ok();
    for c in &cat.components {
        if !c.is_resource_like() && c.layout.size > 0 && !c.layout.fields.is_empty() {
            writeln!(
                out,
                "    {}(usize, BamComponent, Vec<{}>),",
                c.variant_name, c.struct_name
            )
            .ok();
        }
    }
    writeln!(out, "}}\n").ok();

    writeln!(
        out,
        "struct StrataBatchBuf {{\n\
         \x20   count: usize,\n\
         \x20   cols: Vec<StrataBatchColumn>,\n\
         }}\n\
         \n\
         impl StrataBatchBuf {{\n\
         \x20   fn new(count: usize) -> Self {{\n\
         \x20       Self {{ count, cols: Vec::new() }}\n\
         \x20   }}\n\
         \x20   fn has_col(&self, comp_id: usize) -> bool {{\n\
         \x20       self.cols.iter().any(|c| match c {{\n\
         \x20           StrataBatchColumn::Marker {{ comp_id: cid, .. }} => *cid == comp_id,"
    )
    .ok();
    for c in &cat.components {
        if !c.is_resource_like() && c.layout.size > 0 && !c.layout.fields.is_empty() {
            writeln!(
                out,
                "            StrataBatchColumn::{}(cid, _, _) => *cid == comp_id,",
                c.variant_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "        }})\n\
         \x20   }}\n\
         \x20   fn ensure_col(&mut self, comp_id: usize, handles: &StrataHandles) {{\n\
         \x20       if self.has_col(comp_id) {{ return; }}\n\
         \x20       match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.is_resource_like() {
            continue;
        }
        if c.layout.size == 0 || c.layout.fields.is_empty() {
            writeln!(
                out,
                "            {} => self.cols.push(StrataBatchColumn::Marker {{ comp_id: {}, handle: handles.{}, count: self.count }}),",
                c.id, c.id, c.handle_field
            )
            .ok();
        } else {
            writeln!(
                out,
                "            {} => self.cols.push(StrataBatchColumn::{}({}, handles.{}, vec![{}::default(); self.count])),",
                c.id, c.variant_name, c.id, c.handle_field, c.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "            _ => {{}}\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   fn set_row(&mut self, row: usize, comp_id: usize, val: &StrataVal, handles: &StrataHandles) {{\n\
         \x20       if row >= self.count {{ return; }}\n\
         \x20       self.ensure_col(comp_id, handles);\n\
         \x20       for col in &mut self.cols {{\n\
         \x20           match (col, val) {{"
    )
    .ok();
    for c in &cat.components {
        if !c.is_resource_like() && c.layout.size > 0 && !c.layout.fields.is_empty() {
            writeln!(
                out,
                "                (StrataBatchColumn::{v}(cid, _, vec), StrataVal::Obj(StrataObj::{v}(v))) if *cid == comp_id => {{ if let Some(slot) = vec.get_mut(row) {{ *slot = *v; }} return; }}",
                v = c.variant_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   fn commit(&self, bridge: &mut HostBridge<'_, '_, '_>) {{\n\
         \x20       if self.count == 0 {{ return; }}\n\
         \x20       let mut _cols: Vec<SpawnBatchColumn<'_>> = Vec::with_capacity(self.cols.len());\n\
         \x20       for c in &self.cols {{\n\
         \x20           match c {{\n\
         \x20               StrataBatchColumn::Marker {{ handle, count, .. }} => _cols.push(SpawnBatchColumn::marker(*handle, *count)),"
    )
    .ok();
    for c in &cat.components {
        if !c.is_resource_like() && c.layout.size > 0 && !c.layout.fields.is_empty() {
            writeln!(
                out,
                "                StrataBatchColumn::{}(_, handle, vec) => _cols.push(SpawnBatchColumn::new(*handle, vec)),",
                c.variant_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "            }}\n\
         \x20       }}\n\
         \x20       match bridge {{\n\
         \x20           HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().spawn_batch(&_cols, self.count); }}\n\
         \x20           HostBridge::Commands(cmds) => {{ let _ = cmds.spawn_batch(&_cols, self.count); }}\n\
         \x20           _ => {{}}\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 2. Unified value & aggregate enum (`StrataObj`) covering every layout + table
    writeln!(out, "#[derive(Clone, Debug)]").ok();
    writeln!(out, "enum StrataObj {{").ok();
    writeln!(out, "    Empty,").ok();
    for c in &cat.components {
        writeln!(out, "    {}({}),", c.variant_name, c.struct_name).ok();
    }
    for t in &cat.tables {
        writeln!(out, "    {}({}),", t.variant_name, t.struct_name).ok();
    }
    writeln!(out, "}}\n").ok();

    writeln!(out, "impl Default for StrataObj {{").ok();
    writeln!(out, "    fn default() -> Self {{ Self::Empty }}").ok();
    writeln!(out, "}}\n").ok();

    // Byte serialization helpers on each layout struct (pure safe Rust `.to_le_bytes()`)
    for c in &cat.components {
        emit_struct_byte_and_field_impls(out, mir, cat, c);
    }
    for t in &cat.tables {
        emit_table_field_impls(out, mir, cat, t);
    }

    // `StrataObj` dispatchers
    writeln!(out, "impl StrataObj {{").ok();
    writeln!(
        out,
        "    fn default_for_name(name: &str) -> Self {{\n\
         \x20       match strata_short_key(name) {{"
    )
    .ok();
    for c in &cat.components {
        let esc_c = escape_rust_str(&c.canonical_name);
        let esc_s = escape_rust_str(&c.short_name);
        if esc_c == esc_s {
            writeln!(
                out,
                "            \"{esc_c}\" => Self::{}({}::default()),",
                c.variant_name, c.struct_name
            )
            .ok();
        } else {
            writeln!(
                out,
                "            \"{esc_c}\" | \"{esc_s}\" => Self::{}({}::default()),",
                c.variant_name, c.struct_name
            )
            .ok();
        }
    }
    for t in &cat.tables {
        let esc_t = escape_rust_str(&t.name);
        writeln!(
            out,
            "            \"{esc_t}\" => Self::{}({}::default()),",
            t.variant_name, t.struct_name
        )
        .ok();
    }
    writeln!(out, "            _ => Self::Empty,\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn get_field(&self, off: u32, field: &str) -> StrataVal {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_get(off, field),",
            c.variant_name
        )
        .ok();
    }
    for t in &cat.tables {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_get(off, field),",
            t.variant_name
        )
        .ok();
    }
    writeln!(
        out,
        "            Self::Empty => StrataVal::Unit,\n        }}\n    }}"
    )
    .ok();

    writeln!(
        out,
        "    fn set_field(&mut self, off: u32, field: &str, val: StrataVal) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_set(off, field, val),",
            c.variant_name
        )
        .ok();
    }
    for t in &cat.tables {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_set(off, field, val),",
            t.variant_name
        )
        .ok();
    }
    writeln!(out, "            Self::Empty => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn read_le_bytes(&self) -> Vec<u8> {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_to_u8_bytes().to_vec(),",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => Vec::new(),\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn write_le_bytes(&mut self, bytes: &[u8]) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_from_u8_bytes(bytes),",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn spawn_entry<'a>(&'a self, handles: &StrataHandles) -> Option<SpawnEntry<'a>> {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.layout.size == 0 || c.layout.fields.is_empty() {
            writeln!(
                out,
                "            Self::{}(_) => Some(SpawnEntry::marker(handles.{})),",
                c.variant_name, c.handle_field
            )
            .ok();
        } else {
            writeln!(
                out,
                "            Self::{}(v) => Some(SpawnEntry::new(handles.{}, v)),",
                c.variant_name, c.handle_field
            )
            .ok();
        }
    }
    writeln!(out, "            _ => None,\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_insert(&self, cmds: &mut GuestCommands<'_>, handles: &StrataHandles, entity: FfiEntity, if_new: bool) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => {{ if if_new {{ let _ = cmds.insert_if_new(entity, handles.{}, v); }} else {{ let _ = cmds.insert(entity, handles.{}, v); }} }},",
            c.variant_name, c.handle_field, c.handle_field
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_trigger(&self, cmds: &mut GuestCommands<'_>, handles: &StrataHandles, target: Option<FfiEntity>, propagate: bool) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "            Self::{}(v) => {{\n\
                 \x20               if propagate {{\n\
                 \x20                   let _ = cmds.trigger_propagated_handle(handles.{hf}, target.unwrap_or(FfiEntity::NULL), v, BamComponent::INVALID);\n\
                 \x20               }} else if let Some(t) = target {{\n\
                 \x20                   let _ = cmds.trigger_entity(t, v);\n\
                 \x20               }} else {{\n\
                 \x20                   let _ = cmds.trigger(v);\n\
                 \x20               }}\n\
                 \x20           }},",
                c.variant_name,
                hf = c.handle_field
            )
            .ok();
        }
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_insert_rel(&self, cmds: &mut GuestCommands<'_>, rel_handle: BamComponent, entity: FfiEntity, target: FfiEntity) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => {{ let _ = cmds.insert_relation_with_payload(entity, rel_handle, target, v); }},",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn send_msg(&self, ctx: &mut SystemContext<'_>, decl_idx: usize) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "            Self::{}(v) => {{ let _ = ctx.send_message::<{}>(decl_idx, v); }},",
                c.variant_name, c.struct_name
            )
            .ok();
        }
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();
    writeln!(out, "}}\n").ok();

    // 3. `StrataVal`, `StrataPtr`, `HostBridge`, and pure safe primitive helpers
    out.push_str(STRATA_RUNTIME_PRELUDE);
}

pub(super) fn emit_struct_byte_and_field_impls(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    c: &ComponentEntry,
) {
    let sname = &c.struct_name;
    let sz = c.layout.size;
    let is_zst = sz == 0 || c.layout.fields.is_empty();

    writeln!(out, "impl {sname} {{").ok();
    if is_zst {
        writeln!(
            out,
            "    const fn strata_to_u8_bytes(&self) -> [u8; 0] {{ [] }}"
        )
        .ok();
        writeln!(
            out,
            "    fn strata_from_u8_bytes(&mut self, _b: &[u8]) {{}}"
        )
        .ok();
        writeln!(
            out,
            "    fn strata_get(&self, _off: u32, _field: &str) -> StrataVal {{ StrataVal::Unit }}"
        )
        .ok();
        writeln!(
            out,
            "    fn strata_set(&mut self, _off: u32, _field: &str, _val: StrataVal) {{}}"
        )
        .ok();
    } else {
        writeln!(
            out,
            "    const fn strata_to_u8_bytes(&self) -> [u8; {sz}] {{"
        )
        .ok();
        writeln!(out, "        let mut out = [0u8; {sz}];").ok();
        for f in &c.layout.fields {
            let fname = sanitize_rust_ident(&f.name);
            let off = f.offset;
            let fsz = f.size;
            let rty = rust_abi_type_for_field(f, mir);
            emit_write_field_to_bytes(out, &format!("self.{fname}"), &rty, off, fsz);
        }
        writeln!(out, "        out").ok();
        writeln!(out, "    }}").ok();

        writeln!(out, "    fn strata_from_u8_bytes(&mut self, b: &[u8]) {{").ok();
        writeln!(out, "        if b.len() < {sz} {{ return; }}").ok();
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname = sanitize_rust_ident(&f.name);
            let off = f.offset;
            let fsz = f.size;
            let rty = rust_abi_type_for_field(f, mir);
            emit_read_field_from_bytes(out, &format!("self.{fname}"), &rty, off, fsz);
        }
        writeln!(out, "    }}").ok();

        for (w, ty, elem_sz, conv) in [
            ("u64_words", "u64", 8usize, "u64::from_le_bytes"),
            ("u32_words", "u32", 4usize, "u32::from_le_bytes"),
            ("u16_words", "u16", 2usize, "u16::from_le_bytes"),
        ] {
            if sz >= elem_sz && sz.is_multiple_of(elem_sz) {
                let n = sz / elem_sz;
                writeln!(out, "    const fn strata_to_{w}(&self) -> [{ty}; {n}] {{").ok();
                writeln!(out, "        let bytes = self.strata_to_u8_bytes();").ok();
                writeln!(out, "        let mut out = [0{ty}; {n}];").ok();
                writeln!(out, "        let mut i = 0usize;").ok();
                writeln!(out, "        while i < {n} {{").ok();
                writeln!(out, "            let s = i * {elem_sz};").ok();
                let slice_lit = match elem_sz {
                    8 => {
                        "[bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3], bytes[s + 4], bytes[s + 5], bytes[s + 6], bytes[s + 7]]"
                    }
                    4 => "[bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3]]",
                    _ => "[bytes[s], bytes[s + 1]]",
                };
                writeln!(out, "            out[i] = {conv}({slice_lit});").ok();
                writeln!(out, "            i += 1;").ok();
                writeln!(out, "        }}").ok();
                writeln!(out, "        out").ok();
                writeln!(out, "    }}").ok();
            }
        }

        writeln!(
            out,
            "    fn strata_get(&self, off: u32, field: &str) -> StrataVal {{"
        )
        .ok();
        writeln!(
            out,
            "        if field.is_empty() && off == 0 {{\n\
             \x20           return StrataVal::Obj(StrataObj::{}(*self));\n\
             \x20       }}",
            c.variant_name
        )
        .ok();
        // Dispatch by leaf offset OR field name (including nested fields via byte slice)
        let mut first = true;
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname_esc = escape_rust_str(&f.name);
            let rname = sanitize_rust_ident(&f.name);
            let kw = if first { "if" } else { "else if" };
            first = false;
            writeln!(
                out,
                "        {kw} (field == \"{fname_esc}\" && (off == 0 || off == u32::MAX || off as usize == {off})) || (field.is_empty() && off as usize == {off}) {{\n\
                 \x20           return {};\n\
                 \x20       }}",
                emit_field_val_to_strata_val(&format!("self.{rname}"), &f.ty, f.size, mir, cat),
                off = f.offset
            )
            .ok();
        }
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            if let Ty::Named(ref n) = f.ty
                && find_enum_layout_or_def(n, mir).is_none()
                && let Some(nested) = cat.resolve_comp(n)
                && nested.layout.size == f.size
            {
                let fname_esc = escape_rust_str(&f.name);
                let rname = sanitize_rust_ident(&f.name);
                let sname = &nested.struct_name;
                let f_off = f.offset;
                let f_end = f.offset + f.size;
                let off_cond = if f_off == 0 {
                    format!("(off as usize) < {f_end}")
                } else {
                    format!("(off as usize) >= {f_off} && (off as usize) < {f_end}")
                };
                let sub_off_expr = if f_off == 0 {
                    "off".to_owned()
                } else {
                    format!(
                        "if off == u32::MAX {{ u32::MAX }} else if (off as usize) >= {f_off} {{ off - {f_off}u32 }} else {{ 0 }}"
                    )
                };
                writeln!(
                    out,
                    "        if ((off == 0 || off == u32::MAX) && field.starts_with(\"{fname_esc}.\")) || ((field.starts_with(\"{fname_esc}.\") || field.is_empty()) && {off_cond}) {{\n\
                     \x20           let _sub_field = field.strip_prefix(\"{fname_esc}.\").unwrap_or(\"\");\n\
                     \x20           let _sub_off = {sub_off_expr};\n\
                     \x20           let mut _raw = Vec::with_capacity({});\n\
                     \x20           for _w in &self.{rname} {{ strata_push_le_into(&mut _raw, *_w); }}\n\
                     \x20           let mut _sub = {sname}::default();\n\
                     \x20           _sub.strata_from_u8_bytes(&_raw);\n\
                     \x20           return _sub.strata_get(_sub_off, _sub_field);\n\
                     \x20       }}",
                    f.size
                )
                .ok();
            } else if matches!(
                f.ty,
                Ty::Vec2
                    | Ty::Vec3
                    | Ty::Vec3a
                    | Ty::Vec4
                    | Ty::Quat
                    | Ty::Rgba
                    | Ty::IVec2
                    | Ty::IVec3
                    | Ty::UVec2
            ) {
                let fname_esc = escape_rust_str(&f.name);
                let rname = sanitize_rust_ident(&f.name);
                let to_sv =
                    emit_field_val_to_strata_val(&format!("self.{rname}"), &f.ty, f.size, mir, cat);
                let f_off = f.offset;
                let f_end = f.offset + f.size;
                writeln!(
                    out,
                    "        if (off == 0 || off == u32::MAX || ((off as usize) >= {f_off} && (off as usize) < {f_end}))\n\
                     \x20           && let Some(_swiz) = field.strip_prefix(\"{fname_esc}.\")\n\
                     \x20       {{\n\
                     \x20           if let Some(_v) = strata_vec_swizzle_get(&({to_sv}), _swiz) {{ return _v; }}\n\
                     \x20       }}"
                )
                .ok();
            }
        }
        writeln!(
            out,
            "        let bytes = self.strata_to_u8_bytes();\n\
             \x20       strata_decode_sub_field(&bytes, off as usize, field)"
        )
        .ok();
        writeln!(out, "    }}").ok();

        writeln!(
            out,
            "    fn strata_set(&mut self, off: u32, field: &str, val: StrataVal) {{"
        )
        .ok();
        writeln!(
            out,
            "        if field.is_empty() && off == 0 {{\n\
             \x20           if let StrataVal::Obj(StrataObj::{}(v)) = val {{ *self = v; return; }}\n\
             \x20       }}",
            c.variant_name
        )
        .ok();
        let mut first = true;
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname_esc = escape_rust_str(&f.name);
            let rname = sanitize_rust_ident(&f.name);
            let kw = if first { "if" } else { "else if" };
            first = false;
            let assign_stmt =
                emit_strata_val_assign_to_field(&format!("self.{rname}"), &f.ty, f.size, mir, cat);
            writeln!(
                out,
                "        {kw} (field == \"{fname_esc}\" && (off == 0 || off == u32::MAX || off as usize == {off})) || (field.is_empty() && off as usize == {off}) {{\n\
                 \x20           {assign_stmt}\n\
                 \x20           return;\n\
                 \x20       }}",
                off = f.offset
            )
            .ok();
        }
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            if let Ty::Named(ref n) = f.ty
                && find_enum_layout_or_def(n, mir).is_none()
                && let Some(nested) = cat.resolve_comp(n)
                && nested.layout.size == f.size
            {
                let fname_esc = escape_rust_str(&f.name);
                let rname = sanitize_rust_ident(&f.name);
                let sname = &nested.struct_name;
                let f_off = f.offset;
                let f_end = f.offset + f.size;
                let off_cond = if f_off == 0 {
                    format!("(off as usize) < {f_end}")
                } else {
                    format!("(off as usize) >= {f_off} && (off as usize) < {f_end}")
                };
                let sub_off_expr = if f_off == 0 {
                    "off".to_owned()
                } else {
                    format!(
                        "if off == u32::MAX {{ u32::MAX }} else if (off as usize) >= {f_off} {{ off - {f_off}u32 }} else {{ 0 }}"
                    )
                };
                writeln!(
                    out,
                    "        if ((off == 0 || off == u32::MAX) && field.starts_with(\"{fname_esc}.\")) || ((field.starts_with(\"{fname_esc}.\") || field.is_empty()) && {off_cond}) {{\n\
                     \x20           let _sub_field = field.strip_prefix(\"{fname_esc}.\").unwrap_or(\"\");\n\
                     \x20           let _sub_off = {sub_off_expr};\n\
                     \x20           let mut _raw = Vec::with_capacity({});\n\
                     \x20           for _w in &self.{rname} {{ strata_push_le_into(&mut _raw, *_w); }}\n\
                     \x20           let mut _sub = {sname}::default();\n\
                     \x20           _sub.strata_from_u8_bytes(&_raw);\n\
                     \x20           _sub.strata_set(_sub_off, _sub_field, val);\n\
                     \x20           let _b = _sub.strata_to_u8_bytes();\n\
                     \x20           let mut _idx = 0usize;\n\
                     \x20           for _slot in self.{rname}.iter_mut() {{\n\
                     \x20               let _step = core::mem::size_of_val(_slot);\n\
                     \x20               if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }}\n\
                     \x20           }}\n\
                     \x20           return;\n\
                     \x20       }}",
                    f.size
                )
                .ok();
            } else if matches!(
                f.ty,
                Ty::Vec2
                    | Ty::Vec3
                    | Ty::Vec3a
                    | Ty::Vec4
                    | Ty::Quat
                    | Ty::Rgba
                    | Ty::IVec2
                    | Ty::IVec3
                    | Ty::UVec2
            ) {
                let fname_esc = escape_rust_str(&f.name);
                let rname = sanitize_rust_ident(&f.name);
                let to_sv =
                    emit_field_val_to_strata_val(&format!("self.{rname}"), &f.ty, f.size, mir, cat);
                let assign_stmt = emit_strata_val_assign_to_field(
                    &format!("self.{rname}"),
                    &f.ty,
                    f.size,
                    mir,
                    cat,
                );
                let f_off = f.offset;
                let f_end = f.offset + f.size;
                writeln!(
                    out,
                    "        if (off == 0 || off == u32::MAX || ((off as usize) >= {f_off} && (off as usize) < {f_end}))\n\
                     \x20           && let Some(_swiz) = field.strip_prefix(\"{fname_esc}.\")\n\
                     \x20       {{\n\
                     \x20           let mut _sv = {to_sv};\n\
                     \x20           if strata_vec_swizzle_set(&mut _sv, _swiz, &val) {{\n\
                     \x20               let val = _sv;\n\
                     \x20               {assign_stmt}\n\
                     \x20               return;\n\
                     \x20           }}\n\
                     \x20       }}"
                )
                .ok();
            }
        }
        writeln!(
            out,
            "        let mut bytes = self.strata_to_u8_bytes();\n\
             \x20       strata_encode_sub_field(&mut bytes, off as usize, &val);\n\
             \x20       self.strata_from_u8_bytes(&bytes);"
        )
        .ok();
        writeln!(out, "    }}").ok();
    }
    writeln!(out, "}}\n").ok();
}

pub(super) fn table_field_val_to_strata_val(
    expr: &str,
    fty: &Ty,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match fty {
        Ty::Bool => format!("StrataVal::Bool({expr})"),
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => {
            format!("StrataVal::U32({expr} as u32)")
        }
        Ty::I8 | Ty::I16 | Ty::I32 => format!("StrataVal::I32({expr} as i32)"),
        Ty::Fix32 => format!("StrataVal::Fix32({expr})"),
        Ty::U64 => format!("StrataVal::U64({expr})"),
        Ty::I64 => format!("StrataVal::I64({expr})"),
        Ty::Fix64 => format!("StrataVal::Fix64({expr})"),
        Ty::F32 | Ty::UnitScalar { .. } => format!("StrataVal::F32({expr})"),
        Ty::F64 => format!("StrataVal::F64({expr})"),
        Ty::Vec2 => format!("StrataVal::Vec2({expr})"),
        Ty::Vec3 => format!("StrataVal::Vec3({expr})"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4({expr})"),
        Ty::IVec2 => format!("StrataVal::IVec2({expr})"),
        Ty::IVec3 => format!("StrataVal::IVec3({expr})"),
        Ty::UVec2 => format!("StrataVal::UVec2({expr})"),
        Ty::Mat3 | Ty::Mat4 => {
            format!("StrataVal::Arr({expr}.iter().map(|_x| StrataVal::F32(*_x)).collect())")
        }
        Ty::BitSet(_) => format!("StrataVal::Words({expr}.to_vec())"),
        Ty::InlineStr(_) => format!("StrataVal::Str({expr}.to_owned())"),
        Ty::Array { elem, .. } => {
            let inner = table_field_val_to_strata_val("(*_x)", elem, mir, cat);
            format!("StrataVal::Arr({expr}.iter().map(|_x| {inner}).collect())")
        }
        Ty::Tuple(items) => {
            let parts: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(i, it)| {
                    table_field_val_to_strata_val(&format!("({expr}).{i}"), it, mir, cat)
                })
                .collect();
            format!("StrataVal::Tuple(vec![{}])", parts.join(", "))
        }
        Ty::Named(n) => {
            if find_enum_layout_or_def(n, mir).is_some() {
                if find_enum_repr(n, mir).is_some_and(|(_, s)| s) {
                    format!("StrataVal::I32({expr} as i32)")
                } else {
                    format!("StrataVal::U32({expr} as u32)")
                }
            } else if let Some(comp) = cat.resolve_comp(n) {
                format!("StrataVal::Obj(StrataObj::{}({expr}))", comp.variant_name)
            } else {
                "StrataVal::Unit".to_owned()
            }
        }
        _ => "StrataVal::Unit".to_owned(),
    }
}

pub(super) fn emit_table_field_impls(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    te: &TableEntry,
) {
    let sname = &te.struct_name;
    writeln!(out, "impl {sname} {{").ok();
    writeln!(
        out,
        "    fn strata_get(&self, _off: u32, field: &str) -> StrataVal {{"
    )
    .ok();
    writeln!(out, "        match field {{").ok();
    writeln!(
        out,
        "            \"\" => StrataVal::Obj(StrataObj::{}(self.clone())),",
        te.variant_name
    )
    .ok();
    for (fname, fty) in &te.fields {
        let esc = escape_rust_str(fname);
        let rname = sanitize_rust_ident(fname);
        let conv = table_field_val_to_strata_val(&format!("self.{rname}"), fty, mir, cat);
        writeln!(out, "            \"{esc}\" => {conv},").ok();
    }
    writeln!(out, "            _ => {{").ok();
    for (fname, fty) in &te.fields {
        let esc = escape_rust_str(fname);
        let rname = sanitize_rust_ident(fname);
        if let Ty::Named(n) = fty
            && find_enum_layout_or_def(n, mir).is_none()
            && cat.resolve_comp(n).is_some()
        {
            writeln!(
                out,
                "                if let Some(_rest) = field.strip_prefix(\"{esc}.\") {{ return self.{rname}.strata_get(u32::MAX, _rest); }}"
            )
            .ok();
        } else if matches!(fty, Ty::InlineStr(_)) {
            writeln!(
                out,
                "                if field == \"{esc}.len\" {{ return StrataVal::U32(self.{rname}.len() as u32); }}"
            )
            .ok();
        } else if matches!(
            fty,
            Ty::Vec2
                | Ty::Vec3
                | Ty::Vec3a
                | Ty::Vec4
                | Ty::Quat
                | Ty::Rgba
                | Ty::IVec2
                | Ty::IVec3
                | Ty::UVec2
        ) {
            let sv = table_field_val_to_strata_val(&format!("self.{rname}"), fty, mir, cat);
            writeln!(
                out,
                "                if let Some(_swiz) = field.strip_prefix(\"{esc}.\") {{ if let Some(_v) = strata_vec_swizzle_get(&({sv}), _swiz) {{ return _v; }} }}"
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                StrataVal::Unit\n            }}\n        }}\n    }}"
    )
    .ok();
    writeln!(
        out,
        "    fn strata_set(&mut self, _off: u32, _field: &str, _val: StrataVal) {{}}"
    )
    .ok();
    writeln!(out, "}}\n").ok();
}

pub(crate) fn emit_write_field_to_bytes(
    out: &mut String,
    expr: &str,
    rty: &str,
    off: usize,
    size: usize,
) {
    let off_s = format!("{off}");
    emit_write_field_to_bytes_depth(out, expr, rty, &off_s, size, 0);
}

pub(super) fn emit_write_field_to_bytes_depth(
    out: &mut String,
    expr: &str,
    rty: &str,
    off_expr: &str,
    size: usize,
    depth: usize,
) {
    let ind = "        ".to_owned() + &"    ".repeat(depth);
    match rty {
        "u8" => {
            writeln!(out, "{ind}out[{off_expr}] = {expr};").ok();
        }
        "i8" => {
            writeln!(out, "{ind}out[{off_expr}] = ({expr}) as u8;").ok();
        }
        "FfiBool" => {
            writeln!(out, "{ind}out[{off_expr}] = ({expr}).0;").ok();
        }
        "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
            writeln!(
                out,
                "{ind}strata_write_le_bytes(&mut out, {off_expr}, ({expr}).to_le_bytes());"
            )
            .ok();
        }
        "FfiEntity" => {
            writeln!(
                out,
                "{ind}strata_write_le_bytes(&mut out, {off_expr}, ({expr}).to_bits().to_le_bytes());"
            )
            .ok();
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "{ind}out[{off_expr}] = ({expr}).kind;\n\
                 {ind}strata_write_le_bytes(&mut out, ({off_expr}) + 1, ({expr}).reserved0);\n\
                 {ind}strata_write_le_bytes(&mut out, ({off_expr}) + 4, ({expr}).asset_type.to_raw().to_le_bytes());\n\
                 {ind}strata_write_le_bytes(&mut out, ({off_expr}) + 8, ({expr}).index.to_le_bytes());\n\
                 {ind}strata_write_le_bytes(&mut out, ({off_expr}) + 12, ({expr}).generation.to_le_bytes());\n\
                 {ind}strata_write_le_bytes(&mut out, ({off_expr}) + 16, *(({expr}).uuid.as_bytes()));",
            )
            .ok();
        }
        _ if rty.starts_with('[') => {
            if let Some((elem, len)) = parse_rust_array_type(rty) {
                let elem_sz = size.checked_div(len).unwrap_or(0);
                writeln!(
                    out,
                    "{ind}let mut _ai_{depth} = 0usize;\n\
                     {ind}while _ai_{depth} < {len} {{\n\
                     {ind}    let _ael_{depth} = &({expr})[_ai_{depth}];\n\
                     {ind}    let _ao_{depth} = ({off_expr}) + _ai_{depth} * {elem_sz};"
                )
                .ok();
                emit_write_field_to_bytes_depth(
                    out,
                    &format!("(*_ael_{depth})"),
                    elem,
                    &format!("_ao_{depth}"),
                    elem_sz,
                    depth + 1,
                );
                writeln!(out, "{ind}    _ai_{depth} += 1;\n{ind}}}").ok();
            }
        }
        _ => {}
    }
}

pub(crate) fn emit_read_field_from_bytes(
    out: &mut String,
    expr: &str,
    rty: &str,
    off: usize,
    size: usize,
) {
    let off_s = format!("{off}");
    emit_read_field_from_bytes_depth(out, expr, rty, &off_s, size, 0);
}

pub(super) fn emit_read_field_from_bytes_depth(
    out: &mut String,
    expr: &str,
    rty: &str,
    off_expr: &str,
    size: usize,
    depth: usize,
) {
    let ind = "        ".to_owned() + &"    ".repeat(depth);
    match rty {
        "u8" => {
            writeln!(out, "{ind}{expr} = b[{off_expr}];").ok();
        }
        "i8" => {
            writeln!(out, "{ind}{expr} = b[{off_expr}] as i8;").ok();
        }
        "FfiBool" => {
            writeln!(out, "{ind}{expr} = FfiBool(b[{off_expr}]);").ok();
        }
        "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
            writeln!(
                out,
                "{ind}{expr} = {rty}::from_le_bytes(b[({off_expr})..({off_expr}) + {size}].try_into().unwrap_or([0u8; {size}]));"
            )
            .ok();
        }
        "FfiEntity" => {
            writeln!(
                out,
                "{ind}{expr} = FfiEntity::from_bits(u64::from_le_bytes(b[({off_expr})..({off_expr}) + 8].try_into().unwrap_or([0u8; 8])));"
            )
            .ok();
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "{ind}({expr}).kind = b[{off_expr}];\n\
                 {ind}({expr}).reserved0 = [b[({off_expr}) + 1], b[({off_expr}) + 2], b[({off_expr}) + 3]];\n\
                 {ind}({expr}).asset_type = BamComponent::from_raw(u32::from_le_bytes(b[({off_expr}) + 4..({off_expr}) + 8].try_into().unwrap_or([0u8; 4])));\n\
                 {ind}({expr}).index = u32::from_le_bytes(b[({off_expr}) + 8..({off_expr}) + 12].try_into().unwrap_or([0u8; 4]));\n\
                 {ind}({expr}).generation = u32::from_le_bytes(b[({off_expr}) + 12..({off_expr}) + 16].try_into().unwrap_or([0u8; 4]));\n\
                 {ind}({expr}).uuid = ComponentUuid::from_bytes(b[({off_expr}) + 16..({off_expr}) + 32].try_into().unwrap_or([0u8; 16]));"
            )
            .ok();
        }
        _ if rty.starts_with('[') => {
            if let Some((elem, len)) = parse_rust_array_type(rty) {
                let elem_sz = size.checked_div(len).unwrap_or(0);
                writeln!(
                    out,
                    "{ind}for (_ai_{depth}, _ael_{depth}) in ({expr}).iter_mut().enumerate() {{\n\
                     {ind}    let _ao_{depth} = ({off_expr}) + _ai_{depth} * {elem_sz};"
                )
                .ok();
                emit_read_field_from_bytes_depth(
                    out,
                    &format!("(*_ael_{depth})"),
                    elem,
                    &format!("_ao_{depth}"),
                    elem_sz,
                    depth + 1,
                );
                writeln!(out, "{ind}}}").ok();
            }
        }
        _ => {}
    }
}

pub(super) fn parse_rust_array_type(rty: &str) -> Option<(&str, usize)> {
    let inner = rty.strip_prefix('[')?.strip_suffix(']')?;
    let (elem, len_str) = inner.rsplit_once(';')?;
    let len = len_str.trim().parse::<usize>().ok()?;
    Some((elem.trim(), len))
}

pub(super) fn emit_field_val_to_strata_val(
    expr: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match ty {
        Ty::Bool => format!("StrataVal::Bool({expr}.get())"),
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => {
            format!("StrataVal::U32({expr} as u32)")
        }
        Ty::I8 | Ty::I16 | Ty::I32 => format!("StrataVal::I32({expr} as i32)"),
        Ty::Fix32 => format!("StrataVal::Fix32({expr})"),
        Ty::U64 => format!("StrataVal::U64({expr})"),
        Ty::I64 => format!("StrataVal::I64({expr})"),
        Ty::Fix64 => format!("StrataVal::Fix64({expr})"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => format!("StrataVal::F32({expr})"),
        Ty::F64 => format!("StrataVal::F64({expr})"),
        Ty::Vec2 => format!("StrataVal::Vec2({expr})"),
        Ty::Vec3 => format!("StrataVal::Vec3({expr})"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4({expr})"),
        Ty::IVec2 => format!("StrataVal::IVec2({expr})"),
        Ty::IVec3 => format!("StrataVal::IVec3({expr})"),
        Ty::UVec2 => format!("StrataVal::UVec2({expr})"),
        Ty::Ref(_) => format!("StrataVal::Entity({expr})"),
        Ty::Asset(_) => format!("StrataVal::Asset({expr})"),
        Ty::BitSet(_) => format!("StrataVal::Words({expr}.to_vec())"),
        Ty::InlineStr(cap) => format!("strata_decode_inline_str_words(&{expr}, {cap})"),
        Ty::Mat3 | Ty::Mat4 => {
            format!("StrataVal::Arr({expr}.iter().map(|_x| StrataVal::F32(*_x)).collect())")
        }
        Ty::Array { elem, len } => {
            let elem_sz = byte_size / (*len).max(1);
            let inner = emit_field_val_to_strata_val("(*_x)", elem, elem_sz, mir, cat);
            format!("StrataVal::Arr({expr}.iter().map(|_x| {inner}).collect())")
        }
        Ty::SmallVec { .. } | Ty::InputBuffer { .. } => format!(
            "{{ let _tmp = {expr}; let mut _raw = Vec::with_capacity({byte_size}); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} StrataVal::Bytes(_raw) }}"
        ),
        Ty::Tuple(items) => {
            let mut sub_reads = Vec::new();
            let mut cursor = 0usize;
            for it in items {
                let (sz, al) = guest_ty_abi_size_align(it, mir);
                let al = al.max(1);
                cursor = cursor.div_ceil(al) * al;
                let part =
                    emit_runtime_read_ty_from_bytes("_raw", &format!("{cursor}"), it, sz, mir, cat);
                sub_reads.push(part);
                cursor += sz;
            }
            format!(
                "{{ let _tmp = {expr}; let mut _raw = Vec::with_capacity({byte_size}); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} StrataVal::Tuple(vec![{}]) }}",
                sub_reads.join(", ")
            )
        }
        Ty::Named(n) => {
            if let Some((_, is_signed)) = find_enum_repr(n, mir) {
                if is_signed {
                    format!("StrataVal::I32({expr} as i32)")
                } else {
                    format!("StrataVal::U32({expr} as u32)")
                }
            } else if let Some(nested) = cat.resolve_comp(n)
                && nested.layout.size == byte_size
            {
                let vname = &nested.variant_name;
                let sname = &nested.struct_name;
                format!(
                    "{{ let _tmp = {expr}; let mut _raw = Vec::with_capacity({byte_size}); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} let mut _dst = {sname}::default(); _dst.strata_from_u8_bytes(&_raw); StrataVal::Obj(StrataObj::{vname}(_dst)) }}"
                )
            } else {
                format!(
                    "{{ let _tmp = {expr}; let mut _raw = Vec::with_capacity({byte_size}); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} StrataVal::Bytes(_raw) }}"
                )
            }
        }
        _ => "StrataVal::Unit".to_owned(),
    }
}

pub(super) fn emit_runtime_write_ty_into_bytes(
    buf_var: &str,
    off_expr: &str,
    val_var: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
) -> String {
    match ty {
        Ty::Bool => format!(
            "if ({off_expr}) < {buf_var}.len() {{ {buf_var}[{off_expr}] = u8::from({val_var}.as_bool()); }}"
        ),
        Ty::U8 => format!(
            "if ({off_expr}) < {buf_var}.len() {{ {buf_var}[{off_expr}] = {val_var}.as_u8(); }}"
        ),
        Ty::I8 => format!(
            "if ({off_expr}) < {buf_var}.len() {{ {buf_var}[{off_expr}] = {val_var}.as_i8() as u8; }}"
        ),
        Ty::U16 => format!(
            "if ({off_expr}) + 2 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 2].copy_from_slice(&{val_var}.as_u16().to_le_bytes()); }}"
        ),
        Ty::I16 => format!(
            "if ({off_expr}) + 2 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 2].copy_from_slice(&{val_var}.as_i16().to_le_bytes()); }}"
        ),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => format!(
            "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_u32().to_le_bytes()); }}"
        ),
        Ty::I32 => format!(
            "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_i32().to_le_bytes()); }}"
        ),
        Ty::Fix32 => format!(
            "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_fix32().to_le_bytes()); }}"
        ),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => format!(
            "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_f32().to_le_bytes()); }}"
        ),
        Ty::U64 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 8].copy_from_slice(&{val_var}.as_u64().to_le_bytes()); }}"
        ),
        Ty::I64 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 8].copy_from_slice(&{val_var}.as_i64().to_le_bytes()); }}"
        ),
        Ty::Fix64 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 8].copy_from_slice(&{val_var}.as_fix64().to_le_bytes()); }}"
        ),
        Ty::F64 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 8].copy_from_slice(&{val_var}.as_f64().to_le_bytes()); }}"
        ),
        Ty::Ref(_) => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 8].copy_from_slice(&{val_var}.as_entity().to_bits().to_le_bytes()); }}"
        ),
        Ty::Vec2 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ let _v = {val_var}.as_vec2(); {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&_v[0].to_le_bytes()); {buf_var}[{off_expr} + 4..{off_expr} + 8].copy_from_slice(&_v[1].to_le_bytes()); }}"
        ),
        Ty::Vec3 => format!(
            "if ({off_expr}) + 12 <= {buf_var}.len() {{ let _v = {val_var}.as_vec3(); for _j in 0..3 {{ {buf_var}[{off_expr} + _j * 4..{off_expr} + _j * 4 + 4].copy_from_slice(&_v[_j].to_le_bytes()); }} }}"
        ),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!(
            "if ({off_expr}) + 16 <= {buf_var}.len() {{ let _v = {val_var}.as_vec4(); for _j in 0..4 {{ {buf_var}[{off_expr} + _j * 4..{off_expr} + _j * 4 + 4].copy_from_slice(&_v[_j].to_le_bytes()); }} }}"
        ),
        Ty::IVec2 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ let _v = {val_var}.as_ivec2(); {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&_v[0].to_le_bytes()); {buf_var}[{off_expr} + 4..{off_expr} + 8].copy_from_slice(&_v[1].to_le_bytes()); }}"
        ),
        Ty::IVec3 => format!(
            "if ({off_expr}) + 12 <= {buf_var}.len() {{ let _v = {val_var}.as_ivec3(); for _j in 0..3 {{ {buf_var}[{off_expr} + _j * 4..{off_expr} + _j * 4 + 4].copy_from_slice(&_v[_j].to_le_bytes()); }} }}"
        ),
        Ty::UVec2 => format!(
            "if ({off_expr}) + 8 <= {buf_var}.len() {{ let _v = {val_var}.as_uvec2(); {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&_v[0].to_le_bytes()); {buf_var}[{off_expr} + 4..{off_expr} + 8].copy_from_slice(&_v[1].to_le_bytes()); }}"
        ),
        Ty::Mat3 => format!(
            "if let StrataVal::Arr(_xs) = &{val_var} {{ for (_j, _f) in _xs.iter().take(9).enumerate() {{ if ({off_expr}) + _j * 4 + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr} + _j * 4..{off_expr} + _j * 4 + 4].copy_from_slice(&_f.as_f32().to_le_bytes()); }} }} }}"
        ),
        Ty::Mat4 => format!(
            "if let StrataVal::Arr(_xs) = &{val_var} {{ for (_j, _f) in _xs.iter().take(16).enumerate() {{ if ({off_expr}) + _j * 4 + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr} + _j * 4..{off_expr} + _j * 4 + 4].copy_from_slice(&_f.as_f32().to_le_bytes()); }} }} }}"
        ),
        Ty::BitSet(bits) => {
            let words = (*bits).div_ceil(32).max(1);
            format!(
                "if ({off_expr}) <= {buf_var}.len() {{ strata_write_bitset_bytes(&mut {buf_var}[({off_expr})..], {words}, &{val_var}); }}"
            )
        }
        Ty::InlineStr(cap) => format!(
            "if ({off_expr}) <= {buf_var}.len() {{ strata_encode_inline_str_bytes(&mut {buf_var}[({off_expr})..], {byte_size}, {cap}, &{val_var}); }}"
        ),
        Ty::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                match (sz, is_signed) {
                    (1, _) => format!(
                        "if ({off_expr}) < {buf_var}.len() {{ {buf_var}[{off_expr}] = {val_var}.as_u8(); }}"
                    ),
                    (2, _) => format!(
                        "if ({off_expr}) + 2 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 2].copy_from_slice(&{val_var}.as_u16().to_le_bytes()); }}"
                    ),
                    (_, true) => format!(
                        "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_i32().to_le_bytes()); }}"
                    ),
                    _ => format!(
                        "if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[{off_expr}..{off_expr} + 4].copy_from_slice(&{val_var}.as_u32().to_le_bytes()); }}"
                    ),
                }
            } else {
                format!(
                    "if let StrataVal::Obj(_o) = &{val_var} {{ let _ob = _o.read_le_bytes(); let _n = _ob.len().min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_ob[.._n]); }} else if let StrataVal::Bytes(_ob) = &{val_var} {{ let _n = _ob.len().min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_ob[.._n]); }}"
                )
            }
        }
        Ty::Array { elem, len } => {
            let (elem_sz, elem_al) = guest_ty_abi_size_align(elem, mir);
            let elem_al = elem_al.max(1);
            let elem_stride = elem_sz.div_ceil(elem_al) * elem_al;
            let elem_w =
                emit_runtime_write_ty_into_bytes(buf_var, "_a_eoff", "_a_el", elem, elem_sz, mir);
            format!(
                "match &{val_var} {{ StrataVal::Arr(_items) => {{ for (_ai, _a_el) in _items.iter().take({len}).enumerate() {{ let _a_eoff = ({off_expr}) + _ai * {elem_stride}; {elem_w} }} }} StrataVal::Bytes(_bs) => {{ let _n = _bs.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_bs[.._n]); }} _ => {{}} }}"
            )
        }
        Ty::SmallVec { elem, cap } => {
            let (elem_sz, elem_al) = guest_ty_abi_size_align(elem, mir);
            let elem_al = elem_al.max(1);
            let elem_stride = elem_sz.div_ceil(elem_al) * elem_al;
            let elem_w =
                emit_runtime_write_ty_into_bytes(buf_var, "_sv_eoff", "_sv_el", elem, elem_sz, mir);
            format!(
                "match &{val_var} {{ StrataVal::Arr(_items) => {{ let _cnt = _items.len().min({cap}); let _end = ({off_expr} + {byte_size}).min({buf_var}.len()); if ({off_expr}) < _end {{ {buf_var}[({off_expr}).._end].fill(0); }} if ({off_expr}) + 4 <= {buf_var}.len() {{ {buf_var}[({off_expr})..({off_expr}) + 4].copy_from_slice(&(_cnt as u32).to_le_bytes()); }} for (_i, _sv_el) in _items.iter().take({cap}).enumerate() {{ let _sv_eoff = ({off_expr}) + 8 + _i * {elem_stride}; {elem_w} }} }} StrataVal::Bytes(_bs) => {{ let _n = _bs.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_bs[.._n]); }} StrataVal::Words(_ws) => {{ let mut _raw = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _raw.extend_from_slice(&_w.to_le_bytes()); }} let _n = _raw.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_raw[.._n]); }} _ => {{}} }}"
            )
        }
        Ty::InputBuffer { .. } => format!(
            "match &{val_var} {{ StrataVal::Bytes(_bs) => {{ let _n = _bs.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_bs[.._n]); }} StrataVal::Words(_ws) => {{ let mut _raw = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _raw.extend_from_slice(&_w.to_le_bytes()); }} let _n = _raw.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_raw[.._n]); }} _ => {{}} }}"
        ),
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut writes = Vec::new();
            for (i, it) in items.iter().enumerate() {
                let (sz, al) = guest_ty_abi_size_align(it, mir);
                let al = al.max(1);
                cursor = cursor.div_ceil(al) * al;
                let el_w = emit_runtime_write_ty_into_bytes(
                    buf_var,
                    &format!("({off_expr}) + {cursor}"),
                    "_t_el",
                    it,
                    sz,
                    mir,
                );
                writes.push(format!("if let Some(_t_el) = _items.get({i}) {{ {el_w} }}"));
                cursor += sz;
            }
            format!(
                "match &{val_var} {{ StrataVal::Tuple(_items) => {{ {} }} StrataVal::Bytes(_bs) => {{ let _n = _bs.len().min({byte_size}).min({buf_var}.len().saturating_sub({off_expr})); {buf_var}[({off_expr})..({off_expr}) + _n].copy_from_slice(&_bs[.._n]); }} _ => {{}} }}",
                writes.join(" ")
            )
        }
        _ => String::new(),
    }
}

pub(super) fn emit_runtime_read_ty_from_bytes(
    buf_var: &str,
    off_expr: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match ty {
        Ty::Bool => {
            format!("StrataVal::Bool({buf_var}.get({off_expr}).copied().unwrap_or(0) != 0)")
        }
        Ty::U8 => {
            format!("StrataVal::U32(u32::from({buf_var}.get({off_expr}).copied().unwrap_or(0)))")
        }
        Ty::I8 => format!(
            "StrataVal::I32(i32::from({buf_var}.get({off_expr}).copied().unwrap_or(0) as i8))"
        ),
        Ty::U16 => format!(
            "StrataVal::U32(if ({off_expr}) + 2 <= {buf_var}.len() {{ u32::from(u16::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1]])) }} else {{ 0 }})"
        ),
        Ty::I16 => format!(
            "StrataVal::I32(if ({off_expr}) + 2 <= {buf_var}.len() {{ i32::from(i16::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1]])) }} else {{ 0 }})"
        ),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => format!(
            "StrataVal::U32(if ({off_expr}) + 4 <= {buf_var}.len() {{ u32::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1], {buf_var}[({off_expr}) + 2], {buf_var}[({off_expr}) + 3]]) }} else {{ 0 }})"
        ),
        Ty::I32 => format!(
            "StrataVal::I32(if ({off_expr}) + 4 <= {buf_var}.len() {{ i32::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1], {buf_var}[({off_expr}) + 2], {buf_var}[({off_expr}) + 3]]) }} else {{ 0 }})"
        ),
        Ty::Fix32 => format!(
            "StrataVal::Fix32(if ({off_expr}) + 4 <= {buf_var}.len() {{ i32::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1], {buf_var}[({off_expr}) + 2], {buf_var}[({off_expr}) + 3]]) }} else {{ 0 }})"
        ),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
            format!("StrataVal::F32(strata_bytes_read_f32({buf_var}, {off_expr}))")
        }
        Ty::U64 => format!(
            "StrataVal::U64(if ({off_expr}) + 8 <= {buf_var}.len() {{ u64::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 8].try_into().unwrap_or([0u8; 8])) }} else {{ 0 }})"
        ),
        Ty::I64 => format!(
            "StrataVal::I64(if ({off_expr}) + 8 <= {buf_var}.len() {{ i64::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 8].try_into().unwrap_or([0u8; 8])) }} else {{ 0 }})"
        ),
        Ty::Fix64 => format!(
            "StrataVal::Fix64(if ({off_expr}) + 8 <= {buf_var}.len() {{ i64::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 8].try_into().unwrap_or([0u8; 8])) }} else {{ 0 }})"
        ),
        Ty::F64 => format!(
            "StrataVal::F64(if ({off_expr}) + 8 <= {buf_var}.len() {{ f64::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 8].try_into().unwrap_or([0u8; 8])) }} else {{ 0.0 }})"
        ),
        Ty::Ref(_) => format!(
            "StrataVal::Entity(if ({off_expr}) + 8 <= {buf_var}.len() {{ FfiEntity::from_bits(u64::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 8].try_into().unwrap_or([0u8; 8]))) }} else {{ FfiEntity::NULL }})"
        ),
        Ty::Vec2 => format!(
            "StrataVal::Vec2([strata_bytes_read_f32({buf_var}, {off_expr}), strata_bytes_read_f32({buf_var}, ({off_expr}) + 4)])"
        ),
        Ty::Vec3 => format!(
            "StrataVal::Vec3([strata_bytes_read_f32({buf_var}, {off_expr}), strata_bytes_read_f32({buf_var}, ({off_expr}) + 4), strata_bytes_read_f32({buf_var}, ({off_expr}) + 8)])"
        ),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!(
            "StrataVal::Vec4([strata_bytes_read_f32({buf_var}, {off_expr}), strata_bytes_read_f32({buf_var}, ({off_expr}) + 4), strata_bytes_read_f32({buf_var}, ({off_expr}) + 8), strata_bytes_read_f32({buf_var}, ({off_expr}) + 12)])"
        ),
        Ty::IVec2 => format!(
            "StrataVal::IVec2(if ({off_expr}) + 8 <= {buf_var}.len() {{ [i32::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 4].try_into().unwrap_or([0u8; 4])), i32::from_le_bytes({buf_var}[({off_expr}) + 4..({off_expr}) + 8].try_into().unwrap_or([0u8; 4]))] }} else {{ [0, 0] }})"
        ),
        Ty::IVec3 => format!(
            "StrataVal::IVec3(if ({off_expr}) + 12 <= {buf_var}.len() {{ [i32::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 4].try_into().unwrap_or([0u8; 4])), i32::from_le_bytes({buf_var}[({off_expr}) + 4..({off_expr}) + 8].try_into().unwrap_or([0u8; 4])), i32::from_le_bytes({buf_var}[({off_expr}) + 8..({off_expr}) + 12].try_into().unwrap_or([0u8; 4]))] }} else {{ [0, 0, 0] }})"
        ),
        Ty::UVec2 => format!(
            "StrataVal::UVec2(if ({off_expr}) + 8 <= {buf_var}.len() {{ [u32::from_le_bytes({buf_var}[{off_expr}..({off_expr}) + 4].try_into().unwrap_or([0u8; 4])), u32::from_le_bytes({buf_var}[({off_expr}) + 4..({off_expr}) + 8].try_into().unwrap_or([0u8; 4]))] }} else {{ [0, 0] }})"
        ),
        Ty::Mat3 => format!(
            "StrataVal::Arr((0..9).map(|_j| StrataVal::F32(strata_bytes_read_f32({buf_var}, ({off_expr}) + _j * 4))).collect())"
        ),
        Ty::Mat4 => format!(
            "StrataVal::Arr((0..16).map(|_j| StrataVal::F32(strata_bytes_read_f32({buf_var}, ({off_expr}) + _j * 4))).collect())"
        ),
        Ty::BitSet(bits) => {
            let words = (*bits).div_ceil(32).max(1);
            format!(
                "strata_read_bitset_bytes(&{buf_var}[({off_expr}).min({buf_var}.len())..], {words})"
            )
        }
        Ty::InlineStr(cap) => format!(
            "strata_decode_inline_str_bytes(&{buf_var}[({off_expr}).min({buf_var}.len())..], {cap})"
        ),
        Ty::SmallVec { .. } | Ty::InputBuffer { .. } => format!(
            "{{ let _start = ({off_expr}).min({buf_var}.len()); let _end = (_start + {byte_size}).min({buf_var}.len()); StrataVal::Bytes({buf_var}[_start.._end].to_vec()) }}"
        ),
        Ty::Array { elem, len } => {
            let (elem_sz, elem_al) = guest_ty_abi_size_align(elem, mir);
            let elem_al = elem_al.max(1);
            let elem_stride = elem_sz.div_ceil(elem_al) * elem_al;
            let el_r = emit_runtime_read_ty_from_bytes(buf_var, "_a_roff", elem, elem_sz, mir, cat);
            format!(
                "StrataVal::Arr((0..{len}).map(|_ai| {{ let _a_roff = ({off_expr}) + _ai * {elem_stride}; {el_r} }}).collect())"
            )
        }
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut reads = Vec::new();
            for it in items {
                let (sz, al) = guest_ty_abi_size_align(it, mir);
                let al = al.max(1);
                cursor = cursor.div_ceil(al) * al;
                reads.push(emit_runtime_read_ty_from_bytes(
                    buf_var,
                    &format!("({off_expr}) + {cursor}"),
                    it,
                    sz,
                    mir,
                    cat,
                ));
                cursor += sz;
            }
            format!("StrataVal::Tuple(vec![{}])", reads.join(", "))
        }
        Ty::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                match (sz, is_signed) {
                    (1, _) => format!(
                        "StrataVal::U32(u32::from({buf_var}.get({off_expr}).copied().unwrap_or(0)))"
                    ),
                    (2, _) => format!(
                        "StrataVal::U32(if ({off_expr}) + 2 <= {buf_var}.len() {{ u32::from(u16::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1]])) }} else {{ 0 }})"
                    ),
                    (_, true) => format!(
                        "StrataVal::I32(if ({off_expr}) + 4 <= {buf_var}.len() {{ i32::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1], {buf_var}[({off_expr}) + 2], {buf_var}[({off_expr}) + 3]]) }} else {{ 0 }})"
                    ),
                    _ => format!(
                        "StrataVal::U32(if ({off_expr}) + 4 <= {buf_var}.len() {{ u32::from_le_bytes([{buf_var}[{off_expr}], {buf_var}[({off_expr}) + 1], {buf_var}[({off_expr}) + 2], {buf_var}[({off_expr}) + 3]]) }} else {{ 0 }})"
                    ),
                }
            } else if let Some(comp) = cat.resolve_comp(n) {
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                format!(
                    "{{ let mut _o = {sname}::default(); let _start = ({off_expr}).min({buf_var}.len()); _o.strata_from_u8_bytes(&{buf_var}[_start..]); StrataVal::Obj(StrataObj::{vname}(_o)) }}"
                )
            } else {
                format!(
                    "{{ let _start = ({off_expr}).min({buf_var}.len()); let _end = (_start + {byte_size}).min({buf_var}.len()); StrataVal::Bytes({buf_var}[_start.._end].to_vec()) }}"
                )
            }
        }
        _ => "StrataVal::Unit".to_owned(),
    }
}

pub(super) fn emit_strata_val_assign_to_field(
    expr: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match ty {
        Ty::Bool => format!("{expr} = FfiBool::from_bool(val.as_bool());"),
        Ty::U8 => format!("{expr} = val.as_u8();"),
        Ty::I8 => format!("{expr} = val.as_i8();"),
        Ty::U16 => format!("{expr} = val.as_u16();"),
        Ty::I16 => format!("{expr} = val.as_i16();"),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("{expr} = val.as_u32();"),
        Ty::I32 => format!("{expr} = val.as_i32();"),
        Ty::Fix32 => format!("{expr} = val.as_fix32();"),
        Ty::U64 => format!("{expr} = val.as_u64();"),
        Ty::I64 => format!("{expr} = val.as_i64();"),
        Ty::Fix64 => format!("{expr} = val.as_fix64();"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => format!("{expr} = val.as_f32();"),
        Ty::F64 => format!("{expr} = val.as_f64();"),
        Ty::Vec2 => format!("{expr} = val.as_vec2();"),
        Ty::Vec3 => format!("{expr} = val.as_vec3();"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("{expr} = val.as_vec4();"),
        Ty::IVec2 => format!("{expr} = val.as_ivec2();"),
        Ty::IVec3 => format!("{expr} = val.as_ivec3();"),
        Ty::UVec2 => format!("{expr} = val.as_uvec2();"),
        Ty::Mat3 | Ty::Mat4 => format!(
            "match val {{ StrataVal::Arr(_items) => {{ for (_dst, _v) in {expr}.iter_mut().zip(_items.into_iter()) {{ *_dst = _v.as_f32(); }} }} StrataVal::Bytes(_b) => {{ for (_i, _dst) in {expr}.iter_mut().enumerate() {{ if _i * 4 + 4 <= _b.len() {{ *_dst = f32::from_le_bytes([_b[_i * 4], _b[_i * 4 + 1], _b[_i * 4 + 2], _b[_i * 4 + 3]]); }} }} }} _ => {{}} }}"
        ),
        Ty::Ref(_) => format!("{expr} = val.as_entity();"),
        Ty::Asset(_) => format!("if let StrataVal::Asset(a) = val {{ {expr} = a; }}"),
        Ty::BitSet(_) => format!(
            "match val {{ StrataVal::Words(w) => {{ for (dst, src) in {expr}.iter_mut().zip(w.into_iter()) {{ *dst = src; }} }} StrataVal::Arr(_items) => {{ for (dst, src) in {expr}.iter_mut().zip(_items.into_iter()) {{ *dst = src.as_u32(); }} }} _other => {{ let _m = _other.as_u64(); for (_wi, dst) in {expr}.iter_mut().enumerate() {{ *dst = if _wi == 0 {{ _m as u32 }} else if _wi == 1 {{ (_m >> 32) as u32 }} else {{ 0 }}; }} }} }}"
        ),
        Ty::Array { elem, len } => {
            let elem_sz = byte_size / (*len).max(1);
            let inner = emit_strata_val_assign_to_field("(*_dst)", elem, elem_sz, mir, cat);
            if inner.is_empty() {
                String::new()
            } else {
                let read_arr = emit_runtime_read_ty_from_bytes("_b", "0", ty, byte_size, mir, cat);
                format!(
                    "if let StrataVal::Arr(_items) = val {{ for (_dst, val) in {expr}.iter_mut().zip(_items.into_iter()) {{ {inner} }} }} else if let StrataVal::Bytes(ref _b) = val {{ if let StrataVal::Arr(_items) = ({read_arr}) {{ for (_dst, val) in {expr}.iter_mut().zip(_items.into_iter()) {{ {inner} }} }} }}"
                )
            }
        }
        Ty::SmallVec { elem, cap } => {
            let (elem_sz, elem_al) = guest_ty_abi_size_align(elem, mir);
            let elem_al = elem_al.max(1);
            let elem_stride = elem_sz.div_ceil(elem_al) * elem_al;
            let elem_w =
                emit_runtime_write_ty_into_bytes("_raw", "_eoff", "_sv_el", elem, elem_sz, mir);
            format!(
                "match val {{ StrataVal::Arr(_items) => {{ let mut _raw = vec![0u8; {byte_size}]; let _cnt = _items.len().min({cap}); if _raw.len() >= 4 {{ _raw[0..4].copy_from_slice(&(_cnt as u32).to_le_bytes()); }} for (_i, _sv_el) in _items.into_iter().take({cap}).enumerate() {{ let _eoff = 8 + _i * {elem_stride}; {elem_w} }} let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _raw.len() {{ strata_copy_le_slice(_slot, &_raw[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Bytes(ref _b) => {{ let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Words(ref _ws) => {{ let mut _raw = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _raw.extend_from_slice(&_w.to_le_bytes()); }} let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _raw.len() {{ strata_copy_le_slice(_slot, &_raw[_idx.._idx + _step]); _idx += _step; }} }} }} _ => {{}} }}"
            )
        }
        Ty::InputBuffer { .. } => format!(
            "match val {{ StrataVal::Bytes(ref _b) => {{ let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Words(ref _ws) => {{ let mut _raw = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _raw.extend_from_slice(&_w.to_le_bytes()); }} let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _raw.len() {{ strata_copy_le_slice(_slot, &_raw[_idx.._idx + _step]); _idx += _step; }} }} }} _ => {{ let _ = {byte_size}; }} }}"
        ),
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut writes = Vec::new();
            for (i, it) in items.iter().enumerate() {
                let (sz, al) = guest_ty_abi_size_align(it, mir);
                let al = al.max(1);
                cursor = cursor.div_ceil(al) * al;
                let ew = emit_runtime_write_ty_into_bytes(
                    "_raw",
                    &format!("{cursor}"),
                    "_t_el",
                    it,
                    sz,
                    mir,
                );
                writes.push(format!("if let Some(_t_el) = _items.get({i}) {{ {ew} }}"));
                cursor += sz;
            }
            format!(
                "match val {{ StrataVal::Tuple(ref _items) => {{ let mut _raw = vec![0u8; {byte_size}]; {} let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _raw.len() {{ strata_copy_le_slice(_slot, &_raw[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Bytes(ref _b) => {{ let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Words(ref _ws) => {{ let mut _raw = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _raw.extend_from_slice(&_w.to_le_bytes()); }} let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _raw.len() {{ strata_copy_le_slice(_slot, &_raw[_idx.._idx + _step]); _idx += _step; }} }} }} _ => {{}} }}",
                writes.join(" ")
            )
        }
        Ty::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                match (sz, is_signed) {
                    (1, _) => format!("{expr} = val.as_u32() as u8;"),
                    (2, _) => format!("{expr} = val.as_u32() as u16;"),
                    (_, true) => format!("{expr} = val.as_i32();"),
                    _ => format!("{expr} = val.as_u32();"),
                }
            } else {
                format!(
                    "match val {{ StrataVal::Obj(ref o) => {{ let _b = o.read_le_bytes(); let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} StrataVal::Bytes(ref _b) => {{ let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} _ => {{ let _ = {byte_size}; }} }}"
                )
            }
        }
        Ty::InlineStr(cap) => format!(
            "match val {{ StrataVal::Str(ref _s) => {{ for _slot in {expr}.iter_mut() {{ *_slot = 0; }} let _cap = {cap}usize; let _bytes = _s.as_bytes(); let mut _end = _bytes.len().min(_cap); while _end > 0 && !_s.is_char_boundary(_end) {{ _end -= 1; }} if !{expr}.is_empty() {{ {expr}[0] = _end as u32; }} for (_wi, _ch) in _bytes[.._end].chunks(4).enumerate() {{ if 1 + _wi < {expr}.len() {{ let mut _a = [0u8; 4]; _a[.._ch.len()].copy_from_slice(_ch); {expr}[1 + _wi] = u32::from_le_bytes(_a); }} }} }} StrataVal::Words(ref _ws) => {{ for (_dst, _src) in {expr}.iter_mut().zip(_ws.iter()) {{ *_dst = *_src; }} }} StrataVal::Bytes(ref _b) => {{ let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} _ => {{}} }}"
        ),
        _ => String::new(),
    }
}

pub(super) fn emit_bridge_ptr_helpers(out: &mut String, cat: &GuestCatalog) {
    // 1. `strata_val_or_ptr_read` & `strata_ptr_read`
    writeln!(
        out,
        "fn strata_val_or_ptr_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   base: &StrataVal,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
         \x20   handles: &StrataHandles,\n\
         ) -> StrataVal {{\n\
         \x20   match base {{\n\
         \x20       StrataVal::Obj(_o) => _o.get_field(extra_off, field),\n\
         \x20       StrataVal::Tuple(_items) => field.strip_prefix('_').and_then(|_s| _s.parse::<usize>().ok()).and_then(|_i| _items.get(_i).cloned()).unwrap_or(StrataVal::Unit),\n\
         \x20       StrataVal::Str(_s) => if field == \"len\" {{ StrataVal::U32(_s.len() as u32) }} else {{ StrataVal::Unit }},\n\
         \x20       StrataVal::Bytes(_b) => strata_decode_sub_field(_b, extra_off as usize, field),\n\
         \x20       StrataVal::Words(_ws) => {{ let mut _b = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _b.extend_from_slice(&_w.to_le_bytes()); }} strata_decode_sub_field(&_b, extra_off as usize, field) }},\n\
         \x20       StrataVal::Vec2(_) | StrataVal::Vec3(_) | StrataVal::Vec4(_) | StrataVal::IVec2(_) | StrataVal::IVec3(_) | StrataVal::UVec2(_) => strata_vec_swizzle_get(base, field).unwrap_or(StrataVal::Unit),\n\
         \x20       StrataVal::Ptr(p) => strata_ptr_read(bridge, *p, extra_off, field, slots, migrate_src, migrate_dst, trg_payload, world, handles),\n\
         \x20       _ => StrataVal::Unit,\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "fn strata_ptr_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
         \x20   handles: &StrataHandles,\n\
         ) -> StrataVal {{\n\
         \x20   match ptr {{\n\
         \x20       StrataPtr::Slot {{ sid, off }} => match slots.get(sid) {{\n\
         \x20           Some(StrataVal::Obj(_o)) => _o.get_field(off.saturating_add(extra_off), field),\n\
         \x20           Some(StrataVal::Tuple(_items)) if off == 0 && extra_off == 0 && !field.is_empty() => field.strip_prefix('_').and_then(|_s| _s.parse::<usize>().ok()).and_then(|_i| _items.get(_i).cloned()).unwrap_or(StrataVal::Unit),\n\
         \x20           Some(StrataVal::Str(_s)) if off == 0 && extra_off == 0 && field == \"len\" => StrataVal::U32(_s.len() as u32),\n\
         \x20           Some(StrataVal::Bytes(_b)) if !field.is_empty() || off != 0 || extra_off != 0 => strata_decode_sub_field(_b, off.saturating_add(extra_off) as usize, field),\n\
         \x20           Some(StrataVal::Words(_ws)) if !field.is_empty() || off != 0 || extra_off != 0 => {{ let mut _b = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _b.extend_from_slice(&_w.to_le_bytes()); }} strata_decode_sub_field(&_b, off.saturating_add(extra_off) as usize, field) }},\n\
         \x20           Some(v) if off == 0 && extra_off == 0 && !field.is_empty() => strata_vec_swizzle_get(v, field).unwrap_or_else(|| v.clone()),\n\
         \x20           Some(v) => v.clone(),\n\
         \x20           None => StrataVal::Unit,\n\
         \x20       }},\n\
         \x20       StrataPtr::EventPayload {{ off }} => trg_payload.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::MigrateSrc {{ off }} => migrate_src.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::MigrateDst {{ off }} => migrate_dst.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::Res {{ decl_idx, comp_id, off, is_mut }} => {{\n\
         \x20           let _ = (decl_idx, is_mut);\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.is_resource_like() {
            let sname = &c.struct_name;
            let hf = &c.handle_field;
            writeln!(
                out,
                "                {} => if handles.is_host_res_{} {{\n\
                 \x20                   let HostBridge::System(sys_ctx) = bridge else {{ return StrataVal::Unit; }};\n\
                 \x20                   if is_mut {{\n\
                 \x20                       sys_ctx.res_mut_by_handle::<{sname}>(handles.{hf}).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field))\n\
                 \x20                   }} else {{\n\
                 \x20                       sys_ctx.res_by_handle::<{sname}>(handles.{hf}).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field))\n\
                 \x20                   }}\n\
                 \x20               }} else {{\n\
                 \x20                   world.lock().map_or(StrataVal::Unit, |w| w.mod_res_{}.strata_get(eff_off, field))\n\
                 \x20               }},",
                c.id, c.id, c.id
            )
            .ok();
        } else if c.register_dynamic {
            let sname = &c.struct_name;
            let hf = &c.handle_field;
            writeln!(
                out,
                "                {} => {{\n\
                 \x20                   let HostBridge::System(sys_ctx) = bridge else {{ return StrataVal::Unit; }};\n\
                 \x20                   if is_mut {{\n\
                 \x20                       sys_ctx.res_mut_by_handle::<{sname}>(handles.{hf}).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field))\n\
                 \x20                   }} else {{\n\
                 \x20                       sys_ctx.res_by_handle::<{sname}>(handles.{hf}).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field))\n\
                 \x20                   }}\n\
                 \x20               }},",
                c.id
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "                {} => match bridge {{\n\
             \x20                   HostBridge::System(sys_ctx) => sys_ctx.query_mut(qi).and_then(|it| {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           it.component_rows::<{sname}>(phys_col).and_then(|rs| rs.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }} else if is_mut && is_untracked {{\n\
             \x20                           it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>().and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }} else {{\n\
             \x20                           it.readonly_slice(phys_col).as_component_slice::<{sname}>().and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }}\n\
             \x20                   }}).unwrap_or(StrataVal::Unit),\n\
             \x20                   HostBridge::ParChunkReadonly(ch) => ch.component::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit),\n\
             \x20                   HostBridge::ParChunkMut(ch) => {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           ch.component_rows::<{sname}>(phys_col).and_then(|rs| rs.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }} else if is_mut {{\n\
             \x20                           ch.component_mut_untracked::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }} else {{\n\
             \x20                           ch.component::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20                   _ => StrataVal::Unit,\n\
             \x20               }},",
            c.id
        )
        .ok();
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, is_mut }} => {{\n\
         \x20           if entity.is_null() {{ return StrataVal::Unit; }}\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return StrataVal::Unit; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            let sname = &c.struct_name;
            writeln!(
                out,
                "                {} => if is_mut {{ sys_ctx.get_mut::<{sname}>(qi, phys_col, entity).map_or(StrataVal::Unit, |v| v.strata_get(eff_off, field)) }} else {{ sys_ctx.get::<{sname}>(qi, phys_col, entity).map_or(StrataVal::Unit, |v| v.strata_get(eff_off, field)) }},",
                c.id
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => StrataVal::Unit,\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 2. `strata_ptr_write`
    writeln!(
        out,
        "fn strata_ptr_write(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   val: StrataVal,\n\
         \x20   slots: &mut [StrataVal],\n\
         \x20   migrate_dst: &mut StrataObj,\n\
         \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
         \x20   handles: &StrataHandles,\n\
         ) {{\n\
         \x20   match ptr {{\n\
         \x20       StrataPtr::Slot {{ sid, off }} => {{\n\
         \x20           if let Some(slot) = slots.get_mut(sid) {{\n\
         \x20               if let StrataVal::Obj(_o) = slot {{\n\
         \x20                   _o.set_field(off.saturating_add(extra_off), field, val);\n\
         \x20               }} else if off == 0 && extra_off == 0 && field.is_empty() {{\n\
         \x20                   *slot = val;\n\
         \x20               }} else if off == 0 && extra_off == 0 {{\n\
         \x20                   let _ = strata_vec_swizzle_set(slot, field, &val);\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::MigrateDst {{ off }} => migrate_dst.set_field(off.saturating_add(extra_off), field, val),\n\
         \x20       StrataPtr::Res {{ decl_idx, comp_id, off, .. }} => {{\n\
         \x20           let _ = decl_idx;\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.is_resource_like() {
            let sname = &c.struct_name;
            let hf = &c.handle_field;
            writeln!(
                out,
                "                {} => if handles.is_host_res_{} {{\n\
                 \x20                   if let HostBridge::System(sys_ctx) = bridge {{\n\
                 \x20                       if let Some(mut r) = sys_ctx.res_mut_by_handle::<{sname}>(handles.{hf}) {{\n\
                 \x20                           r.strata_set(eff_off, field, val);\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }} else if let Ok(mut w) = world.lock() {{\n\
                 \x20                   w.mod_res_{}.strata_set(eff_off, field, val);\n\
                 \x20               }},",
                c.id, c.id, c.id
            )
            .ok();
        } else if c.register_dynamic {
            let sname = &c.struct_name;
            let hf = &c.handle_field;
            writeln!(
                out,
                "                {} => if let HostBridge::System(sys_ctx) = bridge {{\n\
                 \x20                   if let Some(mut r) = sys_ctx.res_mut_by_handle::<{sname}>(handles.{hf}) {{\n\
                 \x20                       r.strata_set(eff_off, field, val);\n\
                 \x20                   }}\n\
                 \x20               }},",
                c.id
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_untracked, is_sparse, .. }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "                {} => match bridge {{\n\
             \x20                   HostBridge::System(sys_ctx) => if let Some(it) = sys_ctx.query_mut(qi) {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           if let Some(mut rs) = it.component_rows_mut::<{sname}>(phys_col) {{ if let Some(r) = rs.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else if is_untracked {{\n\
             \x20                           if let Some(s) = it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>() {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else {{\n\
             \x20                           if let Some(s) = it.mutable_slice(phys_col).as_component_slice_mut::<{sname}>() {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }}\n\
             \x20                   }},\n\
             \x20                   HostBridge::ParChunkMut(ch) => {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           if let Some(mut rs) = ch.component_rows_mut::<{sname}>(phys_col) {{ if let Some(r) = rs.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else if is_untracked {{\n\
             \x20                           if let Some(s) = ch.component_mut_untracked::<{sname}>(phys_col) {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else {{\n\
             \x20                           if let Some(s) = ch.component_mut::<{sname}>(phys_col) {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20                   _ => {{}}\n\
             \x20               }},",
            c.id
        )
        .ok();
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, .. }} => {{\n\
         \x20           if entity.is_null() {{ return; }}\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "                {} => if let Some(v) = sys_ctx.get_mut::<{}>(qi, phys_col, entity) {{ v.strata_set(eff_off, field, val); }},",
                c.id, c.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => {{}}\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 3. `strata_ptr_bytes_read` & `strata_ptr_bytes_mut`
    writeln!(
        out,
        "fn strata_ptr_bytes_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   val: &StrataVal,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
         \x20   handles: &StrataHandles,\n\
         \x20   f: impl FnOnce(&[u8], usize),\n\
         ) {{\n\
         \x20   match val {{\n\
         \x20       StrataVal::Obj(o) => {{ let _b = o.read_le_bytes(); f(&_b, 0); }}\n\
         \x20       StrataVal::Bytes(b) => {{ f(b, 0); }}\n\
         \x20       StrataVal::Words(ws) => {{ let mut _b = Vec::with_capacity(ws.len() * 4); for _w in ws {{ _b.extend_from_slice(&_w.to_le_bytes()); }} f(&_b, 0); }}\n\
         \x20       StrataVal::Ptr(ptr) => {{\n\
         \x20           if let StrataPtr::Slot {{ sid, off }} = *ptr {{\n\
         \x20               match slots.get(sid) {{\n\
         \x20                   Some(StrataVal::Bytes(_b)) => {{ f(_b, off as usize); return; }}\n\
         \x20                   Some(StrataVal::Words(_ws)) => {{ let mut _b = Vec::with_capacity(_ws.len() * 4); for _w in _ws {{ _b.extend_from_slice(&_w.to_le_bytes()); }} f(&_b, off as usize); return; }}\n\
         \x20                   Some(StrataVal::Str(_s)) => {{ let mut _b = vec![0u8; 4 + _s.len()]; _b[..4].copy_from_slice(&(_s.len() as u32).to_le_bytes()); _b[4..].copy_from_slice(_s.as_bytes()); f(&_b, off as usize); return; }}\n\
         \x20                   _ => {{}}\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20           let obj = match *ptr {{\n\
         \x20               StrataPtr::Slot {{ sid, .. }} => slots.get(sid).and_then(|s| if let StrataVal::Obj(o) = s {{ Some(o.clone()) }} else {{ None }}),\n\
         \x20               StrataPtr::EventPayload {{ .. }} => Some(trg_payload.clone()),\n\
         \x20               StrataPtr::MigrateSrc {{ .. }} => Some(migrate_src.clone()),\n\
         \x20               StrataPtr::MigrateDst {{ .. }} => Some(migrate_dst.clone()),\n\
         \x20               _ => None,\n\
         \x20           }};\n\
         \x20           let (resolved_obj, base_off) = match *ptr {{\n\
         \x20               StrataPtr::Slot {{ off, .. }} | StrataPtr::EventPayload {{ off }} | StrataPtr::MigrateSrc {{ off }} | StrataPtr::MigrateDst {{ off }} => (obj, off as usize),\n\
         \x20               StrataPtr::Res {{ off, .. }} => {{\n\
         \x20                   let o = match strata_ptr_read(bridge, (*ptr).set_exact_offset(0), 0, \"\", slots, migrate_src, migrate_dst, trg_payload, world, handles) {{ StrataVal::Obj(o) => Some(o), _ => None }};\n\
         \x20                   (o, off as usize)\n\
         \x20               }}\n\
         \x20               StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse }} => {{\n\
         \x20                   let o = match strata_ptr_read(bridge, StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off: 0, is_mut, is_untracked, is_sparse }}, 0, \"\", slots, migrate_src, migrate_dst, trg_payload, world, handles) {{ StrataVal::Obj(o) => Some(o), _ => None }};\n\
         \x20                   (o, off as usize)\n\
         \x20               }}\n\
         \x20               StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, is_mut }} => {{\n\
         \x20                   let o = match strata_ptr_read(bridge, StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off: 0, is_mut }}, 0, \"\", slots, migrate_src, migrate_dst, trg_payload, world, handles) {{ StrataVal::Obj(o) => Some(o), _ => None }};\n\
         \x20                   (o, off as usize)\n\
         \x20               }}\n\
         \x20               _ => (None, 0),\n\
         \x20           }};\n\
         \x20           if let Some(o) = resolved_obj {{\n\
         \x20               let _b = o.read_le_bytes();\n\
         \x20               f(&_b, base_off);\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => {{}}\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "fn strata_ptr_bytes_mut(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   slots: &mut [StrataVal],\n\
         \x20   migrate_dst: &mut StrataObj,\n\
         \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
         \x20   handles: &StrataHandles,\n\
         \x20   f: impl FnOnce(&mut [u8], usize),\n\
         ) {{\n\
         \x20   if let StrataPtr::Slot {{ sid, off }} = ptr {{\n\
         \x20       if let Some(slot) = slots.get_mut(sid) {{\n\
         \x20           match slot {{\n\
         \x20               StrataVal::Bytes(_b) => {{ f(_b, off as usize); return; }}\n\
         \x20               StrataVal::Words(_ws) => {{ let mut _b = Vec::with_capacity(_ws.len() * 4); for _w in _ws.iter() {{ _b.extend_from_slice(&_w.to_le_bytes()); }} f(&mut _b, off as usize); for (_wi, _w) in _ws.iter_mut().enumerate() {{ let _p = _wi * 4; if _p + 4 <= _b.len() {{ *_w = u32::from_le_bytes([_b[_p], _b[_p+1], _b[_p+2], _b[_p+3]]); }} }} return; }}\n\
         \x20               _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   let base_off = match ptr {{\n\
         \x20       StrataPtr::Slot {{ off, .. }} | StrataPtr::Res {{ off, .. }} | StrataPtr::ChunkRow {{ off, .. }} | StrataPtr::EntityPoint {{ off, .. }} | StrataPtr::MigrateDst {{ off }} => off as usize,\n\
         \x20       _ => 0,\n\
         \x20   }};\n\
         \x20   let empty = StrataObj::Empty;\n\
         \x20   let cur_obj = match strata_ptr_read(bridge, ptr.set_exact_offset(0), 0, \"\", slots, &empty, migrate_dst, &empty, world, handles) {{\n\
         \x20       StrataVal::Obj(o) => Some(o),\n\
         \x20       _ => None,\n\
         \x20   }};\n\
         \x20   if let Some(mut o) = cur_obj {{\n\
         \x20       let mut _b = o.read_le_bytes();\n\
         \x20       f(&mut _b, base_off);\n\
         \x20       o.write_le_bytes(&_b);\n\
         \x20       strata_ptr_write(bridge, ptr.set_exact_offset(0), 0, \"\", StrataVal::Obj(o), slots, migrate_dst, world, handles);\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 4. `strata_opt_present` & `strata_entity_ptr_validate`
    writeln!(
        out,
        "fn strata_opt_present(bridge: &mut HostBridge<'_, '_, '_>, ptr: StrataPtr) -> bool {{\n\
         \x20   if let StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, is_mut, .. }} = ptr {{\n\
         \x20       return !strata_entity_ptr_validate(bridge, qi, phys_col, comp_id, entity, is_mut).is_null();\n\
         \x20   }}\n\
         \x20   let StrataPtr::ChunkCol {{ qi, phys_col, comp_id, is_mut, is_sparse, .. }} = ptr else {{ return false; }};\n\
         \x20   match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "        {} => match bridge {{\n\
             \x20           HostBridge::System(sys_ctx) => sys_ctx.query_mut(qi).is_some_and(|it| {{\n\
             \x20               if is_sparse {{\n\
             \x20                   it.component_rows::<{sname}>(phys_col).is_some()\n\
             \x20               }} else if is_mut {{\n\
             \x20                   it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>().is_some()\n\
             \x20               }} else {{\n\
             \x20                   it.readonly_slice(phys_col).as_component_slice::<{sname}>().is_some()\n\
             \x20               }}\n\
             \x20           }}),\n\
             \x20           HostBridge::ParChunkReadonly(ch) => ch.component::<{sname}>(phys_col).is_some(),\n\
             \x20           HostBridge::ParChunkMut(ch) => {{\n\
             \x20               if is_sparse {{\n\
             \x20                   ch.component_rows::<{sname}>(phys_col).is_some()\n\
             \x20               }} else if is_mut {{\n\
             \x20                   ch.component_mut_untracked::<{sname}>(phys_col).is_some()\n\
             \x20               }} else {{\n\
             \x20                   ch.component::<{sname}>(phys_col).is_some()\n\
             \x20               }}\n\
             \x20           }}\n\
             \x20           _ => false,\n\
             \x20       }},",
            c.id
        )
        .ok();
    }
    writeln!(out, "        _ => false,\n    }}\n}}\n").ok();

    writeln!(
        out,
        "fn strata_entity_ptr_validate(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   qi: usize,\n\
         \x20   phys_col: usize,\n\
         \x20   comp_id: usize,\n\
         \x20   entity: FfiEntity,\n\
         \x20   is_mut: bool,\n\
         ) -> StrataPtr {{\n\
         \x20   if entity.is_null() {{ return StrataPtr::Null; }}\n\
         \x20   let HostBridge::System(sys_ctx) = bridge else {{ return StrataPtr::Null; }};\n\
         \x20   let present = match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            let sname = &c.struct_name;
            writeln!(
                out,
                "        {} => if is_mut {{ sys_ctx.get_mut::<{sname}>(qi, phys_col, entity).is_some() }} else {{ sys_ctx.get::<{sname}>(qi, phys_col, entity).is_some() }},",
                c.id
            )
            .ok();
        }
    }
    writeln!(
        out,
        "        _ => false,\n\
         \x20   }};\n\
         \x20   if present {{\n\
         \x20       StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off: 0, is_mut }}\n\
         \x20   }} else {{\n\
         \x20       StrataPtr::Null\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();
}

// ============================================================================
// GuestPlugin Registration: Migrations, Components/Tags, Relations, Objects,
// Observers, Schedules (Slots 60-62), & Run Conditions
// ============================================================================
