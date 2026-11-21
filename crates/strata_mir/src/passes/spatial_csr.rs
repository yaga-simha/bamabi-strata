//! CSR spatial broadphase (`spatial_grid` & `spatial_history`) rebuild synthesis and automatic
//! pre-reader schedule ordering pass.

use crate::ir::{BasicBlock, BlockId, Inst, MirFunction, MirModule, MirStmt, MirType, Terminator};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::HirScheduleGroup;

/// Synthesizes deterministic 2-pass counting-sort CSR rebuild systems for every `spatial_grid` and
/// `spatial_history`, ordering each rebuild immediately prior to the earliest scheduled reader.
pub fn run(module: &mut MirModule) {
    if module.spatial_indices.is_empty() {
        return;
    }

    // Map system_name -> list of spatial indices read via `&res <Index>`.
    let mut readers_by_index: Vec<(String, Vec<String>)> = Vec::new();
    for idx in &module.spatial_indices {
        let mut readers = Vec::new();
        for f in &module.functions {
            if f.source_body.contains(&format!("{}.query_", idx.name))
                || f.source_body.contains(&format!("res {}", idx.name))
                || f.source_body.contains(&format!("res {}", idx.name))
            {
                readers.push(f.name.clone());
            }
        }
        let rebuild_name = format!("{}__rebuild_csr", idx.name);
        let pos_comp = idx
            .by_field_path
            .split('.')
            .next()
            .unwrap_or(&idx.over_component)
            .to_owned();

        let mut func = MirFunction {
            name: rebuild_name.clone(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: module.is_deterministic,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: vec![QueryAccessDesc {
                terms: vec![
                    QueryTerm {
                        storage_key: pos_comp,
                        field_name: None,
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
            }],
            source_body: String::new(),
        };

        let res_local = func.alloc_local(format!("{}_res", idx.name), MirType::MutPtr);
        let entities_local = func.alloc_local("entities", MirType::Ptr);
        let pos_local = func.alloc_local("positions", MirType::Ptr);

        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "rebuild_csr_2pass".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(res_local),
                    inst: Inst::ResWrite {
                        resource: idx.name.clone(),
                    },
                },
                MirStmt {
                    dst: Some(entities_local),
                    inst: Inst::IterEntities { query_idx: 0 },
                },
                MirStmt {
                    dst: Some(pos_local),
                    inst: Inst::IterColRead {
                        query_idx: 0,
                        term_idx: 0,
                        storage_key: idx.by_field_path.clone(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SpatialRebuildCsr {
                        index_name: idx.name.clone(),
                        is_history: idx.is_history,
                        frames: idx.frames,
                        over_component: idx.over_component.clone(),
                        by_field_path: idx.by_field_path.clone(),
                    },
                },
            ],
            terminator: Terminator::Return(None),
        });
        module.functions.push(func);
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
