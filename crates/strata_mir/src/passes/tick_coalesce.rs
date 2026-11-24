//! Selective mutation (`&mut? T`) tick coalescing pass (`Slots 14–15`).
//!
//! Upgrades `IterColWrite` -> `IterColWriteUntracked` (`Slot 14`), initializes `(run_start, run_len)`
//! at chunk entry, instruments every selective component `FieldStore` with `DirtyRunRecordRow`,
//! and flushes changed ranges at row-loop exit via `IterMarkChangedRange` (`Slot 15`).

use crate::ir::{BlockId, Inst, LocalId, MirFunction, MirStmt, MirType, Terminator};
use std::collections::{HashMap, HashSet, VecDeque};
use strata_sema::access::TermAccessMode;

/// Rewrites `SelectiveWrite` and `OptionalWrite` query terms to emit untracked column borrows
/// and coalesced dirty range flushes around mutated rows (`opt_present_*` only for `OptionalWrite`).
pub fn run(func: &mut MirFunction) {
    let mut selective_terms = Vec::new();
    for (qi, q) in func.queries.iter().enumerate() {
        if q.is_point_lookup {
            continue;
        }
        for (ti, t) in q.terms.iter().enumerate() {
            let is_sparse = func
                .query_bindings
                .iter()
                .find(|qb| qb.query_idx == qi as u32)
                .and_then(|qb| qb.terms.iter().find(|bt| bt.term_idx == ti as u32))
                .is_some_and(|bt| bt.is_sparse);
            let is_opt = t.mode == TermAccessMode::OptionalWrite;
            if matches!(
                t.mode,
                TermAccessMode::SelectiveWrite | TermAccessMode::OptionalWrite
            ) && !is_sparse
            {
                selective_terms.push((qi as u32, ti as u32, t.storage_key.clone(), is_opt));
            }
        }
    }
    if selective_terms.is_empty() || func.blocks.is_empty() {
        return;
    }

    for (qi, ti, storage_key, is_opt) in selective_terms {
        if instrument_chunk_loop_selective(func, qi, ti, &storage_key, is_opt) {
            continue;
        }
        if !is_opt {
            emit_compact_selective_fallback(func, qi, ti, &storage_key);
        }
    }
}

fn instrument_chunk_loop_selective(
    func: &mut MirFunction,
    qi: u32,
    ti: u32,
    storage_key: &str,
    is_opt: bool,
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

    // Track `row_ptr -> row_idx` computed from any selective `col_ptr` (propagating across
    // `optional_split`, `Copy`, `FieldPtr`, and unambiguous `SlotStore` -> `SlotLoad` aliases).
    let mut row_ptrs: HashMap<LocalId, LocalId> = HashMap::new();
    let mut slot_row_ptrs: HashMap<LocalId, Option<LocalId>> = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for bb in &func.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::RowPtr {
                        col_ptr, row_idx, ..
                    } if col_ptrs.contains_key(col_ptr) => {
                        if let Some(dst) = s.dst
                            && row_ptrs.insert(dst, *row_idx) != Some(*row_idx)
                        {
                            changed = true;
                        }
                    }
                    Inst::Copy { val } => {
                        if let Some(dst) = s.dst
                            && let Some(&ridx) = row_ptrs.get(val)
                            && row_ptrs.insert(dst, ridx) != Some(ridx)
                        {
                            changed = true;
                        }
                    }
                    Inst::FieldPtr { base_ptr, .. } => {
                        if let Some(dst) = s.dst
                            && let Some(&ridx) = row_ptrs.get(base_ptr)
                            && row_ptrs.insert(dst, ridx) != Some(ridx)
                        {
                            changed = true;
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(&ridx) = row_ptrs.get(val) {
                            match slot_row_ptrs.get(slot) {
                                None => {
                                    slot_row_ptrs.insert(*slot, Some(ridx));
                                    changed = true;
                                }
                                Some(Some(prev)) if *prev != ridx => {
                                    slot_row_ptrs.insert(*slot, None);
                                    changed = true;
                                }
                                _ => {}
                            }
                        } else if !matches!(slot_row_ptrs.get(slot), Some(None))
                            && slot_row_ptrs.contains_key(slot)
                        {
                            slot_row_ptrs.insert(*slot, None);
                            changed = true;
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(dst) = s.dst
                            && let Some(Some(ridx)) = slot_row_ptrs.get(slot).copied()
                            && row_ptrs.insert(dst, ridx) != Some(ridx)
                        {
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // For `OptionalWrite`, determine the exact subset of blocks where THIS term's
    // `OptionalChunkIsPresent` local is specialized to `false` (handles multi-`Option` queries).
    let chunk_hdr_id = func
        .blocks
        .iter()
        .find(|b| b.label == format!("q{qi}_chunk_hdr"))
        .map(|b| b.id);
    let chunk_exit_id =
        chunk_hdr_id.and_then(|chid| match func.blocks[chid.0 as usize].terminator {
            Terminator::Branch { else_bb, .. } => Some(else_bb),
            _ => None,
        });
    let absent_blocks: HashSet<BlockId> = if is_opt {
        let cond_local = col_ptrs.values().find_map(|&bb_idx| {
            func.blocks[bb_idx].stmts.iter().find_map(|s| {
                if let Inst::OptionalChunkIsPresent { slice_ptr, .. } = s.inst
                    && col_ptrs.contains_key(&slice_ptr)
                {
                    s.dst
                } else {
                    None
                }
            })
        });
        collect_term_absent_blocks(func, cond_local, chunk_hdr_id, chunk_exit_id)
    } else {
        HashSet::new()
    };
    let is_absent_bb = |bb_id: BlockId, label: &str| -> bool {
        if !is_opt {
            return false;
        }
        if !absent_blocks.is_empty() {
            absent_blocks.contains(&bb_id)
        } else {
            label.starts_with("opt_absent_")
        }
    };

    // Insert `DirtyRunRecordRow` immediately after each `FieldStore` into a tracked `row_ptr`
    // (never inside blocks where this `OptionalWrite` term is absent).
    let mut recorded_any = false;
    for bb in &mut func.blocks {
        if is_absent_bb(bb.id, &bb.label) {
            continue;
        }
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

    if !recorded_any && !is_opt {
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
    if let Some(chunk_hdr) = chunk_hdr_id {
        let row_hdr_suffix = format!("q{qi}_row_hdr");
        let hdr_indices: Vec<usize> = func
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                let matches_hdr = b.label == row_hdr_suffix || b.label.ends_with(&row_hdr_suffix);
                matches_hdr && !is_absent_bb(b.id, &b.label)
            })
            .map(|(i, _)| i)
            .collect();
        let flush_prefix = format!("q{qi}_t");
        for hi in hdr_indices {
            if let Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } = func.blocks[hi].terminator
                && (else_bb == chunk_hdr
                    || func.blocks.get(else_bb.0 as usize).is_some_and(|b| {
                        b.label.starts_with(&flush_prefix) && b.label.ends_with("_flush")
                    }))
            {
                let flush_bb =
                    func.alloc_block(format!("q{qi}_t{ti}_flush"), Terminator::Goto(else_bb));
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
    } else if !is_opt && let Some(&bb_idx) = col_ptrs.values().next() {
        func.blocks[bb_idx].stmts.push(MirStmt {
            dst: None,
            inst: Inst::IterMarkChangedRange {
                query_idx: qi,
                term_idx: ti,
                run_start,
                run_len,
            },
        });
    } else if is_opt
        && let Some(present_bb) = func
            .blocks
            .iter_mut()
            .find(|b| b.label.starts_with("opt_present_"))
    {
        present_bb.stmts.push(MirStmt {
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

fn collect_term_absent_blocks(
    func: &MirFunction,
    cond_local: Option<LocalId>,
    chunk_hdr_id: Option<BlockId>,
    chunk_exit_id: Option<BlockId>,
) -> HashSet<BlockId> {
    let mut absent = HashSet::new();
    let Some(cond) = cond_local else {
        return absent;
    };
    let mut queue = VecDeque::new();
    for bb in &func.blocks {
        if bb
            .stmts
            .iter()
            .any(|s| s.dst == Some(cond) && matches!(s.inst, Inst::ConstBool { value: false }))
            && absent.insert(bb.id)
        {
            queue.push_back(bb.id);
        }
    }
    while let Some(bid) = queue.pop_front() {
        let term = &func.blocks[bid.0 as usize].terminator;
        let succs: Vec<BlockId> = match term {
            Terminator::Return(_) => Vec::new(),
            Terminator::Goto(b) => vec![*b],
            Terminator::Branch {
                then_bb, else_bb, ..
            } => vec![*then_bb, *else_bb],
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                let mut v: Vec<BlockId> = cases.iter().map(|(_, b)| *b).collect();
                v.push(*default_bb);
                v
            }
        };
        for succ in succs {
            if Some(succ) == chunk_hdr_id || Some(succ) == chunk_exit_id {
                continue;
            }
            let resets_true = func.blocks[succ.0 as usize]
                .stmts
                .iter()
                .any(|s| s.dst == Some(cond) && matches!(s.inst, Inst::ConstBool { value: true }));
            if !resets_true && absent.insert(succ) {
                queue.push_back(succ);
            }
        }
    }
    absent
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
