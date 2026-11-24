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
    let mut readers_by_index: Vec<(String, Vec<String>)> = Vec::new();
    let spatial_indices = module.spatial_indices.clone();

    for idx in &spatial_indices {
        let readers = detect_spatial_readers(&module.functions, &idx.name);
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

        module.functions.push(b.finish());
        readers_by_index.push((rebuild_name, readers));
    }

    for (rebuild_name, readers) in readers_by_index {
        let mut inserted = false;
        for sched in &mut module.schedules {
            if sched.label == "Startup" {
                continue;
            }
            if insert_before_earliest_reader(&mut sched.nodes, &rebuild_name, &readers) {
                inserted = true;
                break;
            }
        }
        if !inserted
            && let Some(target_idx) = module
                .schedules
                .iter()
                .position(|s| s.label != "Startup")
                .or_else(|| (!module.schedules.is_empty()).then_some(0))
        {
            module.schedules[target_idx].nodes.insert(
                0,
                HirScheduleGroup {
                    kind: "leaf".to_owned(),
                    name: rebuild_name,
                    children: Vec::new(),
                },
            );
        }
    }
}

fn detect_spatial_readers(functions: &[MirFunction], index_name: &str) -> Vec<String> {
    let mut readers = Vec::new();
    for f in functions {
        let uses_resource = f.resources.iter().any(|r| r.resource_name == index_name);
        let uses_inst = f.blocks.iter().any(|bb| {
            bb.stmts.iter().any(|s| match &s.inst {
                Inst::ResRead { resource } => resource == index_name,
                Inst::SpatialQueryDisc { grid_name, .. } => grid_name == index_name,
                Inst::SpatialQuerySegmentAt { history_name, .. } => history_name == index_name,
                _ => false,
            })
        });
        if uses_resource || uses_inst {
            readers.push(f.name.clone());
        }
    }
    readers
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

fn insert_before_earliest_reader(
    nodes: &mut Vec<HirScheduleGroup>,
    rebuild_name: &str,
    readers: &[String],
) -> bool {
    for i in 0..nodes.len() {
        if nodes[i].kind == "leaf" && readers.contains(&nodes[i].name) {
            nodes.insert(
                i,
                HirScheduleGroup {
                    kind: "leaf".to_owned(),
                    name: rebuild_name.to_owned(),
                    children: Vec::new(),
                },
            );
            return true;
        }
        if insert_before_earliest_reader(&mut nodes[i].children, rebuild_name, readers) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::csr_cell_range;

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
}
