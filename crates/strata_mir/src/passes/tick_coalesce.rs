//! Selective mutation (`&mut? T`) tick coalescing pass (`Slots 14–15`).
//!
//! Upgrades `IterColWrite` -> `IterColWriteUntracked` (`Slot 14`), initializes `(run_start, run_len)`
//! at chunk entry, instruments every selective component `FieldStore` with `DirtyRunRecordRow`,
//! and flushes changed ranges at row-loop exit via `IterMarkChangedRange` (`Slot 15`).

use crate::ir::{BlockId, Inst, LocalId, MirFunction, MirStmt, MirType, Terminator};
use std::collections::{HashMap, HashSet};
use strata_sema::access::TermAccessMode;

/// Rewrites `SelectiveWrite` query terms to emit untracked column borrows and coalesced dirty
/// range flushes around mutated rows.
pub fn run(func: &mut MirFunction) {
    let mut selective_terms = Vec::new();
    for (qi, q) in func.queries.iter().enumerate() {
        for (ti, t) in q.terms.iter().enumerate() {
            if t.mode == TermAccessMode::SelectiveWrite {
                selective_terms.push((qi as u32, ti as u32, t.storage_key.clone()));
            }
        }
    }
    if selective_terms.is_empty() || func.blocks.is_empty() {
        return;
    }

    for (qi, ti, storage_key) in selective_terms {
        if instrument_chunk_loop_selective(func, qi, ti, &storage_key) {
            continue;
        }
        emit_compact_selective_fallback(func, qi, ti, &storage_key);
    }
}

fn instrument_chunk_loop_selective(
    func: &mut MirFunction,
    qi: u32,
    ti: u32,
    storage_key: &str,
) -> bool {
    let mut col_ptrs: HashMap<LocalId, usize> = HashMap::new();
    for (bb_idx, bb) in func.blocks.iter_mut().enumerate() {
        for s in &mut bb.stmts {
            if let Inst::IterColWrite {
                query_idx,
                term_idx,
                ..
            } = s.inst
                && query_idx == qi
                && term_idx == ti
            {
                s.inst = Inst::IterColWriteUntracked {
                    query_idx: qi,
                    term_idx: ti,
                    storage_key: storage_key.to_owned(),
                };
                if let Some(dst) = s.dst {
                    col_ptrs.insert(dst, bb_idx);
                }
            }
        }
    }
    if col_ptrs.is_empty() {
        return false;
    }

    let run_start = func.alloc_local("dirty_run_start", MirType::U32);
    let run_len = func.alloc_local("dirty_run_len", MirType::U32);

    // Emit `DirtyRunInit` at every chunk setup block that borrows this selective column.
    let mut init_blocks: HashSet<usize> = col_ptrs.values().copied().collect();
    for bb_idx in init_blocks.drain() {
        func.blocks[bb_idx].stmts.push(MirStmt {
            dst: None,
            inst: Inst::DirtyRunInit { run_start, run_len },
        });
    }

    // Track `row_ptr -> row_idx` computed from any selective `col_ptr` (propagating across `optional_split`).
    let mut row_ptrs: HashMap<LocalId, LocalId> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::RowPtr {
                col_ptr, row_idx, ..
            } = s.inst
                && col_ptrs.contains_key(&col_ptr)
                && let Some(dst) = s.dst
            {
                row_ptrs.insert(dst, row_idx);
            }
        }
    }

    // Insert `DirtyRunRecordRow` immediately after each `FieldStore` into a tracked `row_ptr`.
    let mut recorded_any = false;
    for bb in &mut func.blocks {
        let mut new_stmts = Vec::with_capacity(bb.stmts.len() + 2);
        for s in std::mem::take(&mut bb.stmts) {
            let record_row = if let Inst::FieldStore { base_ptr, .. } = s.inst {
                row_ptrs.get(&base_ptr).copied()
            } else {
                None
            };
            new_stmts.push(s);
            if let Some(row_idx) = record_row {
                recorded_any = true;
                new_stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::DirtyRunRecordRow {
                        run_start,
                        run_len,
                        row_idx,
                    },
                });
            }
        }
        bb.stmts = new_stmts;
    }

    if !recorded_any {
        // Fallback row index when loop contains `EntityGetMut` or read-only check without `FieldStore`.
        if let Some((&first_bb, row_idx)) = col_ptrs
            .values()
            .next()
            .and_then(|bb| row_ptrs.values().next().map(|r| (bb, *r)))
        {
            func.blocks[first_bb].stmts.push(MirStmt {
                dst: None,
                inst: Inst::DirtyRunRecordRow {
                    run_start,
                    run_len,
                    row_idx,
                },
            });
        }
    }

    // Insert flush blocks (`IterMarkChangedRange`) on edges exiting `row_hdr` back to `chunk_hdr`.
    let chunk_hdr_id = func
        .blocks
        .iter()
        .find(|b| b.label == format!("q{qi}_chunk_hdr"))
        .map(|b| b.id);
    if let Some(chunk_hdr) = chunk_hdr_id {
        let row_hdr_suffix = format!("q{qi}_row_hdr");
        let hdr_indices: Vec<usize> = func
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.label == row_hdr_suffix || b.label.ends_with(&row_hdr_suffix))
            .map(|(i, _)| i)
            .collect();
        for hi in hdr_indices {
            if let Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } = func.blocks[hi].terminator
                && else_bb == chunk_hdr
            {
                let flush_bb =
                    func.alloc_block(format!("q{qi}_t{ti}_flush"), Terminator::Goto(chunk_hdr));
                func.blocks[flush_bb.0 as usize].stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::IterMarkChangedRange {
                        query_idx: qi,
                        term_idx: ti,
                        run_start,
                        run_len,
                    },
                });
                func.blocks[hi].terminator = Terminator::Branch {
                    cond,
                    then_bb,
                    else_bb: flush_bb,
                };
            }
        }
    } else if let Some(&bb_idx) = col_ptrs.values().next() {
        func.blocks[bb_idx].stmts.push(MirStmt {
            dst: None,
            inst: Inst::IterMarkChangedRange {
                query_idx: qi,
                term_idx: ti,
                run_start,
                run_len,
            },
        });
    }
    true
}

fn emit_compact_selective_fallback(func: &mut MirFunction, qi: u32, ti: u32, storage_key: &str) {
    let col_local = func.alloc_local(format!("untracked_{storage_key}"), MirType::MutPtr);
    let run_start = func.alloc_local("dirty_run_start", MirType::U32);
    let run_len = func.alloc_local("dirty_run_len", MirType::U32);
    let row_idx = func.alloc_local("dirty_row_idx", MirType::U32);

    let entry = &mut func.blocks[BlockId(0).0 as usize];
    entry.stmts.push(MirStmt {
        dst: Some(col_local),
        inst: Inst::IterColWriteUntracked {
            query_idx: qi,
            term_idx: ti,
            storage_key: storage_key.to_owned(),
        },
    });
    entry.stmts.push(MirStmt {
        dst: None,
        inst: Inst::DirtyRunInit { run_start, run_len },
    });
    entry.stmts.push(MirStmt {
        dst: Some(row_idx),
        inst: Inst::ConstInt { value: 0 },
    });
    entry.stmts.push(MirStmt {
        dst: None,
        inst: Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        },
    });
    entry.stmts.push(MirStmt {
        dst: None,
        inst: Inst::IterMarkChangedRange {
            query_idx: qi,
            term_idx: ti,
            run_start,
            run_len,
        },
    });
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

    /// Verifies `&mut? T` query terms emit untracked column borrows and dirty-run flush instructions.
    #[test]
    fn tick_coalesce_emits_untracked_borrow_and_range_flush() {
        let mut func = MirFunction::new("heat_sys", MirFnKind::System);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Return(None),
        });
        func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: "Heat".to_owned(),
                field_name: None,
                mode: TermAccessMode::SelectiveWrite,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        run(&mut func);
        let stmts = &func.blocks[0].stmts;
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::IterColWriteUntracked { .. }))
        );
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { .. }))
        );
    }
}
