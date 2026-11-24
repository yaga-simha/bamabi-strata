//! CSR spatial broadphase (`spatial_grid` & `spatial_history`) rebuild synthesis and automatic
//! pre-reader schedule ordering pass.

use crate::ir::{
    Inst, MirFnKind, MirFunction, MirModule, MirQueryBinding, MirQueryTermBinding,
    MirResourceBinding, MirType, Terminator,
};
use crate::lower::{CfgBuilder, MirLowerCtx};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::HirScheduleGroup;

/// Synthesizes deterministic 2-pass counting-sort CSR rebuild systems for every `spatial_grid` and
/// `spatial_history`, ordering each rebuild immediately prior to the earliest scheduled reader.
pub fn run(module: &mut MirModule) {
    if module.spatial_indices.is_empty() {
        return;
    }

    let ctx = MirLowerCtx::from_module(module);
    let mut rebuilds: Vec<(MirFunction, Vec<String>)> = Vec::new();
    let spatial_indices = module.spatial_indices.clone();

    for idx in &spatial_indices {
        let readers = detect_spatial_readers(
            &module.functions,
            &idx.name,
            &idx.resource_layout.canonical_name,
        );
        let rebuild_name = format!("{}__rebuild_csr", idx.name);
        let (pos_comp, pos_field) = match idx.by_field_path.split_once('.') {
            Some((c, f)) => (c.to_owned(), f.to_owned()),
            None => (idx.over_component.clone(), "xy".to_owned()),
        };

        let mut func = MirFunction::new(&rebuild_name, MirFnKind::SynthesizedSpatialCsr);
        func.is_deterministic = module.is_deterministic;

        let pos_canon = ctx.resolve_canonical(&pos_comp);
        let over_canon = ctx.resolve_canonical(&idx.over_component);
        let pos_stride = ctx.find_layout(&pos_canon).map_or(12, |l| l.size as u32);
        let (pos_off, pos_mty, _) = ctx.resolve_field(&pos_canon, &pos_field);
        let pos_sparse = ctx
            .find_layout(&pos_canon)
            .is_some_and(|l| (l.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0);

        let mut b = CfgBuilder::new(func, &ctx);
        b.func.queries.push(QueryAccessDesc {
            terms: vec![
                QueryTerm {
                    storage_key: pos_comp.clone(),
                    field_name: Some(pos_field.clone()),
                    mode: TermAccessMode::Read,
                    byte_start: 0,
                    byte_end: 0,
                },
                QueryTerm {
                    storage_key: idx.over_component.clone(),
                    field_name: None,
                    mode: TermAccessMode::With,
                    byte_start: 0,
                    byte_end: 0,
                },
            ],
            ..Default::default()
        });
        b.func.query_bindings.push(MirQueryBinding {
            query_idx: 0,
            terms: vec![
                MirQueryTermBinding {
                    term_idx: 0,
                    alias: "pos".to_owned(),
                    storage_key: pos_comp,
                    canonical_component: pos_canon.clone(),
                    field_name: Some(pos_field.clone()),
                    mode: TermAccessMode::Read,
                    is_sparse: pos_sparse,
                },
                MirQueryTermBinding {
                    term_idx: 1,
                    alias: "over".to_owned(),
                    storage_key: idx.over_component.clone(),
                    canonical_component: over_canon,
                    field_name: None,
                    mode: TermAccessMode::With,
                    is_sparse: false,
                },
            ],
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });

        let res_local = b.alloc_and_emit(
            &format!("{}_res", idx.name),
            MirType::MutPtr,
            Inst::ResWrite {
                resource: idx.name.clone(),
            },
        );
        b.func.resources.push(MirResourceBinding {
            param_name: idx.name.clone(),
            resource_name: idx.name.clone(),
            canonical_name: idx.resource_layout.canonical_name.clone(),
            mutable: true,
            ptr_local: res_local,
        });

        let count_slot = b.alloc_and_emit(
            "csr_count",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let zero_u = b.alloc_and_emit("z_u", MirType::U32, Inst::ConstInt { value: 0 });
        b.emit_void(Inst::SlotStore {
            slot: count_slot,
            val: zero_u,
        });

        // Pass 1: Counting pass over all matching chunks & rows
        let p1_chunk_hdr = b.new_block("csr_pass1_chunk_hdr");
        let p1_chunk_body = b.new_block("csr_pass1_chunk_body");
        let p1_row_hdr = b.new_block("csr_pass1_row_hdr");
        let p1_row_body = b.new_block("csr_pass1_row_body");
        let prefix_bb = b.new_block("csr_prefix_sum");
        // Pass 2: Scattering pass writing packed entries & finalizing CSR index
        let p2_chunk_hdr = b.new_block("csr_pass2_chunk_hdr");
        let p2_chunk_body = b.new_block("csr_pass2_chunk_body");
        let p2_row_hdr = b.new_block("csr_pass2_row_hdr");
        let p2_row_body = b.new_block("csr_pass2_row_body");
        let exit_bb = b.new_block("csr_exit");

        b.emit_void(Inst::SpatialCsrBegin {
            index_name: idx.name.clone(),
        });
        b.terminate(Terminator::Goto(p1_chunk_hdr));
        b.switch_to(p1_chunk_hdr);
        let p1_has = b.alloc_and_emit(
            "p1_has",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: 0 },
        );
        b.terminate(Terminator::Branch {
            cond: p1_has,
            then_bb: p1_chunk_body,
            else_bb: prefix_bb,
        });

        b.switch_to(p1_chunk_body);
        let p1_len = b.alloc_and_emit("p1_len", MirType::U32, Inst::IterChunkLen { query_idx: 0 });
        let p1_pos_col = b.alloc_and_emit(
            "p1_pos_col",
            MirType::Ptr,
            if pos_sparse {
                Inst::IterColRowsRead {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: idx.by_field_path.clone(),
                }
            } else {
                Inst::IterColRead {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: idx.by_field_path.clone(),
                }
            },
        );
        let p1_rslot = b.alloc_and_emit(
            "p1_rs",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        b.emit_void(Inst::SlotStore {
            slot: p1_rslot,
            val: zero_u,
        });
        b.terminate(Terminator::Goto(p1_row_hdr));

        b.switch_to(p1_row_hdr);
        let p1_i = b.alloc_and_emit("p1_i", MirType::U32, Inst::SlotLoad { slot: p1_rslot });
        let p1_rc = b.alloc_and_emit(
            "p1_rc",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: p1_i,
                rhs: p1_len,
                allow_fma: false,
            },
        );
        b.terminate(Terminator::Branch {
            cond: p1_rc,
            then_bb: p1_row_body,
            else_bb: p1_chunk_hdr,
        });

        b.switch_to(p1_row_body);
        let p1_rptr = b.alloc_and_emit(
            "p1_rptr",
            MirType::Ptr,
            Inst::RowPtr {
                col_ptr: p1_pos_col,
                row_idx: p1_i,
                stride_bytes: pos_stride,
                is_sparse: pos_sparse,
            },
        );
        let p1_pos = b.alloc_and_emit(
            "p1_pos",
            pos_mty.clone(),
            Inst::FieldLoad {
                base_ptr: p1_rptr,
                layout_key: pos_canon.clone(),
                field: pos_field.clone(),
                offset_bytes: pos_off,
                field_ty: pos_mty.clone(),
            },
        );
        b.emit_void(Inst::SpatialCsrCount {
            index_name: idx.name.clone(),
            pos: p1_pos,
        });
        let one = b.alloc_and_emit("one", MirType::U32, Inst::ConstInt { value: 1 });
        let cur_c = b.alloc_and_emit("cur_c", MirType::U32, Inst::SlotLoad { slot: count_slot });
        let nxt_c = b.alloc_and_emit(
            "nxt_c",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: cur_c,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: count_slot,
            val: nxt_c,
        });
        let p1_nxt = b.alloc_and_emit(
            "p1_nxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: p1_i,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: p1_rslot,
            val: p1_nxt,
        });
        b.terminate(Terminator::Goto(p1_row_hdr));

        // Exclusive prefix-sum step over CSR cell offsets
        b.switch_to(prefix_bb);
        let total_entries = b.alloc_and_emit(
            "total_entries",
            MirType::U32,
            Inst::SlotLoad { slot: count_slot },
        );
        b.emit_void(Inst::FieldStore {
            base_ptr: res_local,
            layout_key: idx.resource_layout.canonical_name.clone(),
            field: "count".to_owned(),
            offset_bytes: ctx
                .resolve_field(&idx.resource_layout.canonical_name, "count")
                .0,
            val: total_entries,
        });
        b.emit_void(Inst::SpatialCsrPrefixSum {
            index_name: idx.name.clone(),
        });
        b.emit_void(Inst::IterReset { query_idx: 0 });
        b.terminate(Terminator::Goto(p2_chunk_hdr));

        // Pass 2: Scatter entities and quantized coordinates into dense CSR buckets
        b.switch_to(p2_chunk_hdr);
        let p2_has = b.alloc_and_emit(
            "p2_has",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: 0 },
        );
        b.terminate(Terminator::Branch {
            cond: p2_has,
            then_bb: p2_chunk_body,
            else_bb: exit_bb,
        });

        b.switch_to(p2_chunk_body);
        let p2_len = b.alloc_and_emit("p2_len", MirType::U32, Inst::IterChunkLen { query_idx: 0 });
        let p2_entities = b.alloc_and_emit(
            "entities",
            MirType::Ptr,
            Inst::IterEntities { query_idx: 0 },
        );
        let p2_pos_col = b.alloc_and_emit(
            "positions",
            MirType::Ptr,
            if pos_sparse {
                Inst::IterColRowsRead {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: idx.by_field_path.clone(),
                }
            } else {
                Inst::IterColRead {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: idx.by_field_path.clone(),
                }
            },
        );
        let p2_rslot = b.alloc_and_emit(
            "p2_rs",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        b.emit_void(Inst::SlotStore {
            slot: p2_rslot,
            val: zero_u,
        });
        b.terminate(Terminator::Goto(p2_row_hdr));

        b.switch_to(p2_row_hdr);
        let p2_i = b.alloc_and_emit("p2_i", MirType::U32, Inst::SlotLoad { slot: p2_rslot });
        let p2_rc = b.alloc_and_emit(
            "p2_rc",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: p2_i,
                rhs: p2_len,
                allow_fma: false,
            },
        );
        b.terminate(Terminator::Branch {
            cond: p2_rc,
            then_bb: p2_row_body,
            else_bb: p2_chunk_hdr,
        });

        b.switch_to(p2_row_body);
        let p2_ent = b.alloc_and_emit(
            "p2_ent",
            MirType::Entity,
            Inst::EntityAtRow {
                entities_ptr: p2_entities,
                row_idx: p2_i,
            },
        );
        let p2_rptr = b.alloc_and_emit(
            "p2_rptr",
            MirType::Ptr,
            Inst::RowPtr {
                col_ptr: p2_pos_col,
                row_idx: p2_i,
                stride_bytes: pos_stride,
                is_sparse: pos_sparse,
            },
        );
        let p2_pos = b.alloc_and_emit(
            "p2_pos",
            pos_mty.clone(),
            Inst::FieldLoad {
                base_ptr: p2_rptr,
                layout_key: pos_canon,
                field: pos_field,
                offset_bytes: pos_off,
                field_ty: pos_mty,
            },
        );
        b.emit_void(Inst::SpatialCsrScatter {
            index_name: idx.name.clone(),
            entity: p2_ent,
            pos: p2_pos,
        });
        let p2_nxt = b.alloc_and_emit(
            "p2_nxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: p2_i,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: p2_rslot,
            val: p2_nxt,
        });
        b.terminate(Terminator::Goto(p2_row_hdr));

        b.switch_to(exit_bb);
        b.emit_void(Inst::SpatialRebuildCsr {
            index_name: idx.name.clone(),
            is_history: idx.is_history,
            frames: idx.frames,
            over_component: idx.over_component.clone(),
            by_field_path: idx.by_field_path.clone(),
        });
        b.terminate(Terminator::Return(None));

        rebuilds.push((b.finish(), readers));
    }

    let mut seq_counter = 0usize;
    let mut used_fn_names: std::collections::HashSet<String> =
        module.functions.iter().map(|f| f.name.clone()).collect();

    for (base_fn, readers) in rebuilds {
        let base_name = base_fn.name.clone();
        used_fn_names.insert(base_name.clone());
        let reader_set: std::collections::HashSet<String> = readers.iter().cloned().collect();
        let matching_scheds: Vec<usize> = module
            .schedules
            .iter()
            .enumerate()
            .filter(|(_, sched)| schedule_contains_any_reader(&sched.nodes, &reader_set))
            .map(|(idx, _)| idx)
            .collect();

        if matching_scheds.is_empty() {
            module.functions.push(base_fn);
            if let Some(target_idx) = module
                .schedules
                .iter()
                .position(|s| s.label != "Startup")
                .or_else(|| (!module.schedules.is_empty()).then_some(0))
            {
                module.schedules[target_idx].nodes.insert(
                    0,
                    HirScheduleGroup {
                        kind: "leaf".to_owned(),
                        name: base_name,
                        before: Vec::new(),
                        after: Vec::new(),
                        children: Vec::new(),
                    },
                );
            }
            continue;
        }

        for (match_pos, sched_idx) in matching_scheds.into_iter().enumerate() {
            let sched_name = if match_pos == 0 {
                module.functions.push(base_fn.clone());
                base_name.clone()
            } else {
                let label_slug = sanitize_schedule_suffix(&module.schedules[sched_idx].label);
                let mut cand = format!("{base_name}__{label_slug}");
                let mut suffix_num = 2usize;
                while !used_fn_names.insert(cand.clone()) {
                    cand = format!("{base_name}__{label_slug}_{suffix_num}");
                    suffix_num += 1;
                }
                let mut cloned = base_fn.clone();
                cloned.name = cand.clone();
                module.functions.push(cloned);
                cand
            };
            insert_rebuild_for_schedule(
                &mut module.schedules[sched_idx].nodes,
                &sched_name,
                &reader_set,
                &mut seq_counter,
            );
        }
    }
}

fn sanitize_schedule_suffix(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '_' || !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "sched".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn detect_spatial_readers(
    functions: &[MirFunction],
    index_name: &str,
    canonical_name: &str,
) -> Vec<String> {
    let mut readers: std::collections::HashSet<String> = std::collections::HashSet::new();
    let matches_name =
        |name: &str| name == index_name || (!canonical_name.is_empty() && name == canonical_name);
    for f in functions {
        if matches!(f.kind, crate::ir::MirFnKind::SynthesizedSpatialCsr) {
            continue;
        }
        let uses_resource = f
            .resources
            .iter()
            .any(|r| matches_name(&r.resource_name) || matches_name(&r.canonical_name));
        let uses_inst = f.blocks.iter().any(|bb| {
            bb.stmts.iter().any(|s| match &s.inst {
                Inst::ResRead { resource } | Inst::ResWrite { resource } => matches_name(resource),
                Inst::SpatialQueryDisc { grid_name, .. } => grid_name == index_name,
                Inst::SpatialQuerySegmentAt { history_name, .. } => history_name == index_name,
                _ => false,
            })
        });
        if uses_resource || uses_inst {
            readers.insert(f.name.clone());
        }
    }
    // Propagate through helper calls (`Inst::Call`) so systems invoking helper readers also wait
    // on the spatial CSR rebuild.
    loop {
        let mut added = false;
        for f in functions {
            if matches!(f.kind, crate::ir::MirFnKind::SynthesizedSpatialCsr)
                || readers.contains(&f.name)
            {
                continue;
            }
            let calls_reader = f.blocks.iter().any(|bb| {
                bb.stmts.iter().any(|s| match &s.inst {
                    Inst::Call { callee, .. } => readers.contains(callee),
                    _ => false,
                })
            });
            if calls_reader && readers.insert(f.name.clone()) {
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    let mut out: Vec<String> = readers.into_iter().collect();
    out.sort();
    out
}

fn schedule_contains_any_reader(
    nodes: &[HirScheduleGroup],
    readers: &std::collections::HashSet<String>,
) -> bool {
    nodes.iter().any(|n| node_contains_reader(n, readers))
}

fn node_contains_reader(
    node: &HirScheduleGroup,
    readers: &std::collections::HashSet<String>,
) -> bool {
    if node.kind == "leaf" {
        readers.contains(&node.name)
    } else {
        schedule_contains_any_reader(&node.children, readers)
    }
}

fn collect_subtree_names(node: &HirScheduleGroup, out: &mut std::collections::HashSet<String>) {
    if !node.name.is_empty() {
        out.insert(node.name.clone());
    }
    for child in &node.children {
        collect_subtree_names(child, out);
    }
}

fn collect_reader_leaves(
    nodes: &[HirScheduleGroup],
    readers: &std::collections::HashSet<String>,
    out: &mut Vec<String>,
) {
    for node in nodes {
        if node.kind == "leaf" {
            if readers.contains(&node.name) && !out.contains(&node.name) {
                out.push(node.name.clone());
            }
        } else {
            collect_reader_leaves(&node.children, readers, out);
        }
    }
}

fn collect_schedule_pred_names(
    nodes: &[HirScheduleGroup],
    readers: &std::collections::HashSet<String>,
    rebuild_name: &str,
) -> Vec<String> {
    let mut reader_node_names: std::collections::HashSet<String> = readers.clone();
    fn collect_group_names_with_readers(
        nodes: &[HirScheduleGroup],
        readers: &std::collections::HashSet<String>,
        out: &mut std::collections::HashSet<String>,
    ) {
        for node in nodes {
            if node.kind != "leaf" && node_contains_reader(node, readers) && !node.name.is_empty() {
                out.insert(node.name.clone());
            }
            collect_group_names_with_readers(&node.children, readers, out);
        }
    }
    collect_group_names_with_readers(nodes, readers, &mut reader_node_names);

    let mut preds = Vec::new();
    let mut visit = |node: &HirScheduleGroup| {
        if node_contains_reader(node, readers) {
            for target in &node.after {
                if !reader_node_names.contains(target)
                    && target != rebuild_name
                    && !preds.contains(target)
                {
                    preds.push(target.clone());
                }
            }
        } else if !node.name.is_empty() && node.name != rebuild_name {
            let targets_reader = node.before.iter().any(|b| reader_node_names.contains(b));
            if targets_reader && !preds.contains(&node.name) {
                preds.push(node.name.clone());
            }
        }
    };
    fn walk_all(nodes: &[HirScheduleGroup], f: &mut impl FnMut(&HirScheduleGroup)) {
        for n in nodes {
            f(n);
            walk_all(&n.children, f);
        }
    }
    walk_all(nodes, &mut visit);
    preds
}

fn make_rebuild_leaf(
    rebuild_name: &str,
    sched_readers: &[String],
    sched_preds: &[String],
    blocked_after: &std::collections::HashSet<String>,
) -> HirScheduleGroup {
    let mut after = Vec::new();
    for p in sched_preds {
        if !blocked_after.contains(p) && !after.contains(p) {
            after.push(p.clone());
        }
    }
    HirScheduleGroup {
        kind: "leaf".to_owned(),
        name: rebuild_name.to_owned(),
        before: sched_readers.to_vec(),
        after,
        children: Vec::new(),
    }
}

/// Topologically orders sibling indices in `indices` respecting `before`/`after` edges
/// among `nodes` (and breaking ties by original sibling index). Falls back gracefully
/// to original order for any remaining cycle nodes.
fn topo_sort_sibling_indices(nodes: &[HirScheduleGroup], indices: &[usize]) -> Vec<usize> {
    if indices.len() <= 1 {
        return indices.to_vec();
    }
    let k = indices.len();
    let mut names_at: Vec<std::collections::HashSet<String>> = Vec::with_capacity(k);
    for &idx in indices {
        let mut s = std::collections::HashSet::new();
        collect_subtree_names(&nodes[idx], &mut s);
        names_at.push(s);
    }

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); k];
    let mut indeg = vec![0usize; k];
    for (u_pos, &u_idx) in indices.iter().enumerate() {
        let u = &nodes[u_idx];
        for (v_pos, _) in indices.iter().enumerate() {
            if u_pos == v_pos {
                continue;
            }
            let u_before_v = u.before.iter().any(|b| names_at[v_pos].contains(b));
            let v_after_u = nodes[indices[v_pos]]
                .after
                .iter()
                .any(|a| names_at[u_pos].contains(a));
            if (u_before_v || v_after_u) && !adj[u_pos].contains(&v_pos) {
                adj[u_pos].push(v_pos);
                indeg[v_pos] += 1;
            }
        }
    }

    let mut ready: std::collections::BTreeSet<usize> = indeg
        .iter()
        .enumerate()
        .filter(|&(_, &d)| d == 0)
        .map(|(pos, _)| pos)
        .collect();
    let mut ordered_positions = Vec::with_capacity(k);
    while let Some(pos) = ready.pop_first() {
        ordered_positions.push(pos);
        for &next in &adj[pos] {
            indeg[next] -= 1;
            if indeg[next] == 0 {
                ready.insert(next);
            }
        }
    }
    for pos in 0..k {
        if !ordered_positions.contains(&pos) {
            ordered_positions.push(pos);
        }
    }
    ordered_positions.into_iter().map(|p| indices[p]).collect()
}

/// Finds non-reader sibling indices in `nodes` constrained strictly BEFORE any index in
/// `reader_indices` via `before`/`after` (including transitive non-reader predecessors),
/// excluding any sibling constrained strictly AFTER a reader.
fn find_sibling_predecessors(nodes: &[HirScheduleGroup], reader_indices: &[usize]) -> Vec<usize> {
    let n = nodes.len();
    let mut names_at: Vec<std::collections::HashSet<String>> = Vec::with_capacity(n);
    for node in nodes {
        let mut s = std::collections::HashSet::new();
        collect_subtree_names(node, &mut s);
        names_at.push(s);
    }
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    for u in 0..n {
        for v in 0..n {
            if u == v {
                continue;
            }
            let u_before_v = nodes[u].before.iter().any(|b| names_at[v].contains(b));
            let v_after_u = nodes[v].after.iter().any(|a| names_at[u].contains(a));
            if u_before_v || v_after_u {
                edges[u].push(v);
            }
        }
    }
    // Compute forward reachability from every reader to avoid pulling post-reader nodes.
    let mut after_reader = vec![false; n];
    let mut stack = reader_indices.to_vec();
    for &r in reader_indices {
        after_reader[r] = true;
    }
    while let Some(cur) = stack.pop() {
        for &nxt in &edges[cur] {
            if !after_reader[nxt] {
                after_reader[nxt] = true;
                stack.push(nxt);
            }
        }
    }

    // Reverse reachability from `reader_indices`.
    let mut rev_edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (u, outs) in edges.iter().enumerate() {
        for &v in outs {
            rev_edges[v].push(u);
        }
    }
    let mut is_pred = vec![false; n];
    let mut rstack = reader_indices.to_vec();
    while let Some(cur) = rstack.pop() {
        for &prev in &rev_edges[cur] {
            if !after_reader[prev] && !is_pred[prev] {
                is_pred[prev] = true;
                rstack.push(prev);
            }
        }
    }
    is_pred
        .into_iter()
        .enumerate()
        .filter(|&(_, b)| b)
        .map(|(i, _)| i)
        .collect()
}

fn insert_rebuild_for_schedule(
    nodes: &mut Vec<HirScheduleGroup>,
    rebuild_name: &str,
    readers: &std::collections::HashSet<String>,
    seq_counter: &mut usize,
) -> bool {
    let mut sched_readers = Vec::new();
    collect_reader_leaves(nodes, readers, &mut sched_readers);
    if sched_readers.is_empty() {
        return false;
    }
    let sched_preds = collect_schedule_pred_names(nodes, readers, rebuild_name);
    let blocked_after = std::collections::HashSet::new();
    place_in_container(
        nodes,
        "root",
        rebuild_name,
        readers,
        &sched_readers,
        &sched_preds,
        &blocked_after,
        seq_counter,
    )
}

#[allow(clippy::too_many_arguments)]
fn place_in_container(
    nodes: &mut Vec<HirScheduleGroup>,
    container_kind: &str,
    rebuild_name: &str,
    readers: &std::collections::HashSet<String>,
    sched_readers: &[String],
    sched_preds: &[String],
    blocked_after: &std::collections::HashSet<String>,
    seq_counter: &mut usize,
) -> bool {
    let reader_indices: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| node_contains_reader(n, readers))
        .map(|(i, _)| i)
        .collect();
    if reader_indices.is_empty() {
        return false;
    }

    let is_seq = matches!(container_kind, "seq" | "seq_weak");
    if is_seq {
        let earliest = reader_indices[0];
        if reader_indices.len() == 1 && nodes[earliest].kind != "leaf" {
            let mut next_blocked = blocked_after.clone();
            for node in &nodes[earliest + 1..] {
                collect_subtree_names(node, &mut next_blocked);
            }
            let child = &mut nodes[earliest];
            let child_kind = child.kind.clone();
            if place_in_container(
                &mut child.children,
                &child_kind,
                rebuild_name,
                readers,
                sched_readers,
                sched_preds,
                &next_blocked,
                seq_counter,
            ) {
                return true;
            }
        }
        let mut next_blocked = blocked_after.clone();
        for node in &nodes[earliest..] {
            collect_subtree_names(node, &mut next_blocked);
        }
        nodes.insert(
            earliest,
            make_rebuild_leaf(rebuild_name, sched_readers, sched_preds, &next_blocked),
        );
        return true;
    }

    // Non-`seq` container (`"root"`, `"par"`, `"set"`): enforce explicit ordering around readers!
    if reader_indices.len() == 1 && nodes[reader_indices[0]].kind != "leaf" {
        let r_idx = reader_indices[0];
        let pred_indices = find_sibling_predecessors(nodes, &reader_indices);
        if pred_indices.is_empty() {
            let child = &mut nodes[r_idx];
            let child_kind = child.kind.clone();
            return place_in_container(
                &mut child.children,
                &child_kind,
                rebuild_name,
                readers,
                sched_readers,
                sched_preds,
                blocked_after,
                seq_counter,
            );
        }
        // Pull sibling predecessors before `nodes[r_idx]` inside a `seq`, while still placing
        // `rebuild_name` accurately inside `nodes[r_idx]` (so internal non-readers can precede
        // the inner reader too).
        let sorted_preds = topo_sort_sibling_indices(nodes, &pred_indices);
        let child = &mut nodes[r_idx];
        let child_kind = child.kind.clone();
        let placed = place_in_container(
            &mut child.children,
            &child_kind,
            rebuild_name,
            readers,
            sched_readers,
            sched_preds,
            blocked_after,
            seq_counter,
        );
        if !placed {
            return false;
        }
        let mut remove_set: std::collections::HashSet<usize> =
            sorted_preds.iter().copied().collect();
        remove_set.insert(r_idx);
        let mut seq_children: Vec<HirScheduleGroup> =
            sorted_preds.iter().map(|&i| nodes[i].clone()).collect();
        seq_children.push(nodes[r_idx].clone());
        replace_siblings_with_seq(nodes, &remove_set, seq_children, seq_counter);
        return true;
    }

    // Wrap the earliest/all sibling reader subtrees (plus any sibling non-reader predecessors)
    // into a synthesized `seq` so non-`seq` and `par` blocks execute CSR rebuild before readers.
    let pred_indices = find_sibling_predecessors(nodes, &reader_indices);
    let sorted_preds = topo_sort_sibling_indices(nodes, &pred_indices);
    let sorted_readers = topo_sort_sibling_indices(nodes, &reader_indices);

    let mut next_blocked = blocked_after.clone();
    for &r_idx in &sorted_readers {
        collect_subtree_names(&nodes[r_idx], &mut next_blocked);
    }
    let rebuild_leaf = make_rebuild_leaf(rebuild_name, sched_readers, sched_preds, &next_blocked);

    let mut seq_children = Vec::with_capacity(sorted_preds.len() + 1 + sorted_readers.len());
    for &p_idx in &sorted_preds {
        seq_children.push(nodes[p_idx].clone());
    }
    seq_children.push(rebuild_leaf);
    for &r_idx in &sorted_readers {
        seq_children.push(nodes[r_idx].clone());
    }

    let mut remove_set: std::collections::HashSet<usize> = sorted_preds.into_iter().collect();
    remove_set.extend(sorted_readers);
    replace_siblings_with_seq(nodes, &remove_set, seq_children, seq_counter);
    true
}

fn replace_siblings_with_seq(
    nodes: &mut Vec<HirScheduleGroup>,
    remove_set: &std::collections::HashSet<usize>,
    mut seq_children: Vec<HirScheduleGroup>,
    seq_counter: &mut usize,
) {
    let insert_at = *remove_set.iter().min().unwrap_or(&0);
    let mut kept = Vec::with_capacity(nodes.len() - remove_set.len() + 1);
    let mut inserted_seq = false;
    for (i, item) in std::mem::take(nodes).into_iter().enumerate() {
        if remove_set.contains(&i) {
            if i == insert_at && !inserted_seq {
                *seq_counter += 1;
                kept.push(HirScheduleGroup {
                    kind: "seq".to_owned(),
                    name: format!("__csr_seq_{}", *seq_counter),
                    before: Vec::new(),
                    after: Vec::new(),
                    children: std::mem::take(&mut seq_children),
                });
                inserted_seq = true;
            }
        } else {
            kept.push(item);
        }
    }
    *nodes = kept;
}

/// Resolves the validated half-open CSR slice `[start, end)` for spatial bucket `cell`,
/// returning `None` if `cell + 1 >= offsets.len()`, `offsets[cell] > offsets[cell + 1]`, or
/// `offsets[cell + 1] > total_entries`.
///
/// Enforces monotonic bounds safety before indexing flattened spatial entity/position storage.
#[inline]
#[must_use]
pub fn csr_cell_range(
    offsets: &[u32],
    cell: usize,
    total_entries: usize,
) -> Option<(usize, usize)> {
    let start = *offsets.get(cell)? as usize;
    let end = *offsets.get(cell.checked_add(1)?)? as usize;
    if start > end || end > total_entries {
        return None;
    }
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use strata_sema::{Severity, analyze_source, hir::HirScheduleGroup};

    use super::{csr_cell_range, insert_rebuild_for_schedule};
    use crate::{MirFnKind, lower_to_mir, verify::verify_mir};

    fn compile_mir(src: &str) -> crate::MirModule {
        let sema = analyze_source("test.strata", src);
        let errors: Vec<_> = sema
            .diagnostics
            .iter()
            .filter(|d| matches!(d.severity, Severity::Error))
            .collect();
        assert!(errors.is_empty(), "sema errors: {errors:?}");
        let mir = lower_to_mir(&sema);
        verify_mir(&mir).expect("lowered MIR should verify cleanly");
        mir
    }

    fn collect_seq_order(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
        for n in nodes {
            if n.kind == "leaf" {
                out.push(n.name.clone());
            } else {
                collect_seq_order(&n.children, out);
            }
        }
    }

    fn find_rebuild_in_node<'a>(
        nodes: &'a [HirScheduleGroup],
        prefix: &str,
    ) -> Option<&'a HirScheduleGroup> {
        for n in nodes {
            if n.kind == "leaf" && n.name.starts_with(prefix) {
                return Some(n);
            }
            if let Some(found) = find_rebuild_in_node(&n.children, prefix) {
                return Some(found);
            }
        }
        None
    }

    /// Verifies `csr_cell_range` returns contiguous half-open cell partitions and rejects
    /// non-monotonic or out-of-bounds CSR offsets cleanly.
    #[test]
    fn csr_cell_range_valid_and_adversarial() {
        let offsets = [0u32, 3, 3, 7];
        assert_eq!(csr_cell_range(&offsets, 0, 7), Some((0, 3)));
        assert_eq!(csr_cell_range(&offsets, 1, 7), Some((3, 3)));
        assert_eq!(csr_cell_range(&offsets, 2, 7), Some((3, 7)));
        assert_eq!(csr_cell_range(&offsets, 3, 7), None);
        assert_eq!(csr_cell_range(&[0u32, 5, 2], 1, 5), None);
        assert_eq!(csr_cell_range(&[0u32, 8], 0, 7), None);
    }

    /// BUG-SW-03: Startup and every schedule referencing the spatial grid must receive a
    /// dedicated CSR rebuild function ordered before its readers.
    #[test]
    fn csr_rebuild_inserted_in_startup_and_every_referencing_schedule() {
        let src = r#"
component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
resource Out { startup_hits: u32 = 0, fixed_hits: u32 = 0, update_hits: u32 = 0 }

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos2 by Pos2.xy;

sys scan_startup(g: &res Grid2D, out: &mut res Out) {
    for _e in g.query_disc(vec2(0.0, 0.0), 2.0_m) {
        out.startup_hits += 1;
    }
}

sys scan_fixed(g: &res Grid2D, out: &mut res Out) {
    for _e in g.query_disc(vec2(0.0, 0.0), 2.0_m) {
        out.fixed_hits += 1;
    }
}

sys scan_update(g: &res Grid2D, out: &mut res Out) {
    for _e in g.query_disc(vec2(10.0, 0.0), 2.0_m) {
        out.update_hits += 1;
    }
}

sys unrelated(out: &mut res Out) {
    let _x: u32 = out.fixed_hits;
}

schedule Startup { seq S { scan_startup } }
schedule FixedUpdate { seq F { scan_fixed } }
schedule Update { seq U { scan_update } }
schedule Last { seq L { unrelated } }
"#;
        let mir = compile_mir(src);
        let rebuild_fns: Vec<_> = mir
            .functions
            .iter()
            .filter(|f| matches!(f.kind, MirFnKind::SynthesizedSpatialCsr))
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(
            rebuild_fns.len(),
            3,
            "expected 3 rebuild fns: {rebuild_fns:?}"
        );

        for (label, expected_reader) in [
            ("Startup", "scan_startup"),
            ("FixedUpdate", "scan_fixed"),
            ("Update", "scan_update"),
        ] {
            let sched = mir
                .schedules
                .iter()
                .find(|s| s.label == label)
                .expect("schedule missing");
            let mut order = Vec::new();
            collect_seq_order(&sched.nodes, &mut order);
            let rebuild_pos = order
                .iter()
                .position(|n| n.starts_with("Grid2D__rebuild_csr"))
                .unwrap_or_else(|| panic!("missing rebuild in {label}: {order:?}"));
            let reader_pos = order
                .iter()
                .position(|n| n == expected_reader)
                .expect("missing reader");
            assert!(
                rebuild_pos < reader_pos,
                "rebuild must precede {expected_reader} in {label}: {order:?}"
            );
        }

        let last_sched = mir
            .schedules
            .iter()
            .find(|s| s.label == "Last")
            .expect("Last schedule missing");
        assert!(find_rebuild_in_node(&last_sched.nodes, "Grid2D__rebuild_csr").is_none());
    }

    /// BUG-SW-03: Non-`seq` top-level and `par` blocks wrap readers into synthesized `seq`
    /// ordering CSR rebuild before readers, while honoring `before`/`after` constraints.
    #[test]
    fn non_seq_par_and_before_after_ordering_enforced() {
        let src = r#"
component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
resource Out { hits: u32 = 0 }

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos2 by Pos2.xy;

sys step_move() {
    for row in query(pos: &mut Pos2) {
        row.pos.xy = vec2(5.0, 0.0);
    }
}

sys scan_noseq(g: &res Grid2D, out: &mut res Out) {
    for _e in g.query_disc(vec2(5.0, 0.0), 2.0_m) {
        out.hits += 1;
    }
}

sys scan_par(g: &res Grid2D, out: &mut res Out) {
    for _e in g.query_disc(vec2(5.0, 0.0), 2.0_m) {
        out.hits += 1;
    }
}

schedule FixedUpdate {
    step_move
    scan_noseq
    par MainPar {
        scan_par
    }
}
"#;
        let mir = compile_mir(src);
        let sched = mir
            .schedules
            .iter()
            .find(|s| s.label == "FixedUpdate")
            .expect("FixedUpdate missing");
        let seqs: Vec<_> = sched.nodes.iter().filter(|n| n.kind == "seq").collect();
        assert_eq!(
            seqs.len(),
            1,
            "top-level readers must be wrapped in seq: {:#?}",
            sched.nodes
        );
        let top_seq_order: Vec<_> = seqs[0].children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(top_seq_order[0], "Grid2D__rebuild_csr");
        assert!(top_seq_order.contains(&"scan_noseq"));
        assert!(top_seq_order.contains(&"MainPar"));

        // Verify explicit `before`/`after` handling on non-`seq` and `par` trees.
        let readers: std::collections::HashSet<String> = ["scan_a".to_owned(), "scan_b".to_owned()]
            .into_iter()
            .collect();
        let mut nodes = vec![
            HirScheduleGroup {
                kind: "leaf".to_owned(),
                name: "scan_b".to_owned(),
                before: Vec::new(),
                after: vec!["scan_a".to_owned()],
                children: Vec::new(),
            },
            HirScheduleGroup {
                kind: "leaf".to_owned(),
                name: "step_move".to_owned(),
                before: vec!["scan_a".to_owned()],
                after: Vec::new(),
                children: Vec::new(),
            },
            HirScheduleGroup {
                kind: "leaf".to_owned(),
                name: "scan_a".to_owned(),
                before: Vec::new(),
                after: vec!["step_move".to_owned()],
                children: Vec::new(),
            },
        ];
        let mut ctr = 0usize;
        assert!(insert_rebuild_for_schedule(
            &mut nodes,
            "Grid2D__rebuild_csr",
            &readers,
            &mut ctr,
        ));
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].kind, "seq");
        let order: Vec<_> = nodes[0].children.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(
            order,
            vec!["step_move", "Grid2D__rebuild_csr", "scan_a", "scan_b"]
        );
        let rebuild = &nodes[0].children[1];
        assert_eq!(rebuild.after, vec!["step_move".to_owned()]);
        assert_eq!(
            rebuild.before,
            vec!["scan_b".to_owned(), "scan_a".to_owned()]
        );
    }
}
