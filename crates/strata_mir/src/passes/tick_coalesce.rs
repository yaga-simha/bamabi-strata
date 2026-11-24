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
                    Inst::ArrayIndex { base, .. } => {
                        if let Some(dst) = s.dst
                            && let Some(&ridx) = row_ptrs.get(base)
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

    // Compute all blocks inside this query's chunk loop (excluding `chunk_hdr` and `chunk_exit`).
    let starts: Vec<usize> = col_ptrs.values().copied().collect();
    let loop_blocks = collect_loop_blocks(func, &starts, chunk_hdr_id, chunk_exit_id, qi);
    let atomic_scopes = discover_atomic_scopes(func, &loop_blocks, &is_absent_bb);
    let mut scope_slots: Vec<Option<(LocalId, LocalId)>> = vec![None; atomic_scopes.len()];

    // Collect mutations to apply `(bb_idx, stmt_idx, row_idx, active_scope_opt)`.
    let mut deferred_ckpt_inits: HashSet<usize> = HashSet::new();
    for bb_idx in 0..func.blocks.len() {
        let bb_id = func.blocks[bb_idx].id;
        if is_absent_bb(bb_id, &func.blocks[bb_idx].label) {
            continue;
        }
        let stmts = std::mem::take(&mut func.blocks[bb_idx].stmts);
        let mut new_stmts = Vec::with_capacity(stmts.len() + 4);
        for (stmt_idx, s) in stmts.into_iter().enumerate() {
            let record_row = mutation_row_idx(&s.inst, &row_ptrs);
            new_stmts.push(s);
            if let Some(row_idx) = record_row {
                if let Some(s_idx) = innermost_atomic_scope(&atomic_scopes, bb_id, stmt_idx) {
                    let mut cur = Some(s_idx);
                    while let Some(id) = cur {
                        if scope_slots[id].is_none() {
                            let d = func.alloc_local("tx_dirty", MirType::Bool);
                            let r = func.alloc_local("tx_dirty_row", MirType::U32);
                            scope_slots[id] = Some((d, r));
                        }
                        deferred_ckpt_inits.insert(id);
                        cur = atomic_scopes[id].parent_idx;
                    }
                    let (tx_dirty, tx_row) = scope_slots[s_idx].expect("allocated above");
                    let ct = func.alloc_local("tx_dirty_t", MirType::Bool);
                    new_stmts.push(MirStmt {
                        dst: Some(ct),
                        inst: Inst::ConstBool { value: true },
                    });
                    new_stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: tx_dirty,
                            val: ct,
                        },
                    });
                    new_stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: tx_row,
                            val: row_idx,
                        },
                    });
                } else {
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
        }
        func.blocks[bb_idx].stmts = new_stmts;
    }

    // Wire active `atomic` scopes (innermost-to-outermost): reset `tx_dirty = false` just before
    // `CmdCheckpoint` and emit conditional commit recording ONLY on non-rollback commit edges!
    for s_idx in (0..atomic_scopes.len()).rev() {
        let Some((tx_dirty, tx_row)) = scope_slots[s_idx] else {
            continue;
        };
        let scope = &atomic_scopes[s_idx];
        // Initialize `tx_dirty = false`, `tx_row = 0` immediately before `CmdCheckpoint`.
        let ckpt_idx = scope.ckpt_bb.0 as usize;
        if let Some(pos) = func.blocks[ckpt_idx]
            .stmts
            .iter()
            .position(|s| matches!(s.inst, Inst::CmdCheckpoint))
        {
            let cf = func.alloc_local("tx_dirty_init", MirType::Bool);
            let cz = func.alloc_local("tx_row_init", MirType::U32);
            let init_stmts = [
                MirStmt {
                    dst: Some(cf),
                    inst: Inst::ConstBool { value: false },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: tx_dirty,
                        val: cf,
                    },
                },
                MirStmt {
                    dst: Some(cz),
                    inst: Inst::ConstInt { value: 0 },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: tx_row,
                        val: cz,
                    },
                },
            ];
            func.blocks[ckpt_idx].stmts.splice(pos..pos, init_stmts);
        }

        // Redirect non-rollback commit edges entering `scope.merge_bb` to `tx_chk_bb`.
        let emit_bb = func.alloc_block(
            format!("q{qi}_t{ti}_tx_dirty_rec"),
            Terminator::Goto(scope.merge_bb),
        );
        let loaded_row = func.alloc_local("tx_rec_row", MirType::U32);
        func.blocks[emit_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(loaded_row),
            inst: Inst::SlotLoad { slot: tx_row },
        });
        if let Some(parent_idx) = scope.parent_idx
            && let Some((parent_dirty, parent_row)) = scope_slots[parent_idx]
        {
            let ct = func.alloc_local("tx_parent_dirty", MirType::Bool);
            func.blocks[emit_bb.0 as usize].stmts.push(MirStmt {
                dst: Some(ct),
                inst: Inst::ConstBool { value: true },
            });
            func.blocks[emit_bb.0 as usize].stmts.push(MirStmt {
                dst: None,
                inst: Inst::SlotStore {
                    slot: parent_dirty,
                    val: ct,
                },
            });
            func.blocks[emit_bb.0 as usize].stmts.push(MirStmt {
                dst: None,
                inst: Inst::SlotStore {
                    slot: parent_row,
                    val: loaded_row,
                },
            });
        } else {
            func.blocks[emit_bb.0 as usize].stmts.push(MirStmt {
                dst: None,
                inst: Inst::DirtyRunRecordRow {
                    run_start,
                    run_len,
                    row_idx: loaded_row,
                },
            });
        }

        let loaded_dirty = func.alloc_local("tx_chk_dirty", MirType::Bool);
        let chk_bb = func.alloc_block(
            format!("q{qi}_t{ti}_tx_dirty_chk"),
            Terminator::Branch {
                cond: loaded_dirty,
                then_bb: emit_bb,
                else_bb: scope.merge_bb,
            },
        );
        func.blocks[chk_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(loaded_dirty),
            inst: Inst::SlotLoad { slot: tx_dirty },
        });

        for b_idx in 0..func.blocks.len() {
            let b_id = func.blocks[b_idx].id;
            if b_id == emit_bb || b_id == chk_bb {
                continue;
            }
            let in_commit_path = (scope.body_blocks.contains(&b_id) || b_id == scope.ckpt_bb)
                && !scope.rollback_blocks.contains(&b_id);
            if !in_commit_path {
                continue;
            }
            redirect_target_in_terminator(
                &mut func.blocks[b_idx].terminator,
                |t| t == scope.merge_bb,
                chk_bb,
            );
        }
    }

    // Insert flush blocks (`IterMarkChangedRange`) on edges exiting `row_hdr` back to `chunk_hdr`,
    // plus on early `break` edges (`-> chunk_exit`) and `return` exits inside loop blocks (`EQ-06b`).
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
                        b.label.starts_with(&flush_prefix)
                            && b.label.ends_with("_flush")
                            && !b.label.ends_with("_break_flush")
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

        // Flush on `break` edges (targeting `chunk_exit_id` or earlier terms' `_break_flush`) and
        // `Terminator::Return` exits from inside the query loop body.
        let mut break_flush_by_target: HashMap<BlockId, BlockId> = HashMap::new();
        let loop_vec: Vec<BlockId> = loop_blocks.iter().copied().collect();
        for b_id in loop_vec {
            let b_idx = b_id.0 as usize;
            let label = func.blocks[b_idx].label.clone();
            if is_absent_bb(b_id, &label)
                || Some(b_id) == chunk_hdr_id
                || Some(b_id) == chunk_exit_id
                || (label.starts_with(&flush_prefix)
                    && (label.ends_with("_flush") || label.ends_with("_break_flush")))
            {
                continue;
            }
            if let Some(chunk_exit) = chunk_exit_id {
                let mut exit_targets: Vec<BlockId> = Vec::new();
                collect_matching_targets(
                    &func.blocks[b_idx].terminator,
                    |t| {
                        t == chunk_exit
                            || func.blocks.get(t.0 as usize).is_some_and(|tb| {
                                tb.label.starts_with(&flush_prefix)
                                    && tb.label.ends_with("_break_flush")
                            })
                    },
                    &mut exit_targets,
                );
                for orig_target in exit_targets {
                    let flush_bb = if let Some(&existing) = break_flush_by_target.get(&orig_target)
                    {
                        existing
                    } else {
                        let nb = func.alloc_block(
                            format!("q{qi}_t{ti}_break_flush"),
                            Terminator::Goto(orig_target),
                        );
                        func.blocks[nb.0 as usize].stmts.push(MirStmt {
                            dst: None,
                            inst: Inst::IterMarkChangedRange {
                                query_idx: qi,
                                term_idx: ti,
                                run_start,
                                run_len,
                            },
                        });
                        break_flush_by_target.insert(orig_target, nb);
                        nb
                    };
                    let entry_bb = wrap_tx_dirty_before_exit(
                        func,
                        b_id,
                        flush_bb,
                        &atomic_scopes,
                        &scope_slots,
                        run_start,
                        run_len,
                        qi,
                        ti,
                    );
                    redirect_target_in_terminator(
                        &mut func.blocks[b_idx].terminator,
                        |t| t == orig_target,
                        entry_bb,
                    );
                }
            }
            if let Terminator::Return(ret_val) = func.blocks[b_idx].terminator {
                let active_chain = active_scope_chain_at(&atomic_scopes, &scope_slots, b_id);
                if active_chain.is_empty() {
                    func.blocks[b_idx].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::IterMarkChangedRange {
                            query_idx: qi,
                            term_idx: ti,
                            run_start,
                            run_len,
                        },
                    });
                } else {
                    let ret_bb = func.alloc_block(
                        format!("q{qi}_t{ti}_ret_flush"),
                        Terminator::Return(ret_val),
                    );
                    func.blocks[ret_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::IterMarkChangedRange {
                            query_idx: qi,
                            term_idx: ti,
                            run_start,
                            run_len,
                        },
                    });
                    let entry_bb = wrap_tx_dirty_before_exit(
                        func,
                        b_id,
                        ret_bb,
                        &atomic_scopes,
                        &scope_slots,
                        run_start,
                        run_len,
                        qi,
                        ti,
                    );
                    func.blocks[b_idx].terminator = Terminator::Goto(entry_bb);
                }
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
        for succ in term_succs(&func.blocks[bid.0 as usize].terminator) {
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

struct AtomicTxScope {
    ckpt_bb: BlockId,
    ckpt_stmt_idx: usize,
    merge_bb: BlockId,
    body_blocks: HashSet<BlockId>,
    rollback_blocks: HashSet<BlockId>,
    parent_idx: Option<usize>,
}

fn term_succs(term: &Terminator) -> Vec<BlockId> {
    match term {
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
    }
}

fn collect_matching_targets(
    term: &Terminator,
    mut pred: impl FnMut(BlockId) -> bool,
    out: &mut Vec<BlockId>,
) {
    for t in term_succs(term) {
        if pred(t) && !out.contains(&t) {
            out.push(t);
        }
    }
}

fn redirect_target_in_terminator(
    term: &mut Terminator,
    mut pred: impl FnMut(BlockId) -> bool,
    new_bb: BlockId,
) {
    match term {
        Terminator::Return(_) => {}
        Terminator::Goto(b) => {
            if pred(*b) {
                *b = new_bb;
            }
        }
        Terminator::Branch {
            then_bb, else_bb, ..
        } => {
            if pred(*then_bb) {
                *then_bb = new_bb;
            }
            if pred(*else_bb) {
                *else_bb = new_bb;
            }
        }
        Terminator::Switch {
            cases, default_bb, ..
        } => {
            for (_, b) in cases {
                if pred(*b) {
                    *b = new_bb;
                }
            }
            if pred(*default_bb) {
                *default_bb = new_bb;
            }
        }
    }
}

fn mutation_row_idx(inst: &Inst, row_ptrs: &HashMap<LocalId, LocalId>) -> Option<LocalId> {
    match inst {
        Inst::FieldStore { base_ptr, .. } | Inst::ArrayStore { base_ptr, .. } => {
            row_ptrs.get(base_ptr).copied()
        }
        Inst::BitSetSet { ptr, .. }
        | Inst::BitSetClear { ptr, .. }
        | Inst::GraceArm { ptr, .. }
        | Inst::GraceClear { ptr }
        | Inst::GraceTick { ptr, .. }
        | Inst::InputBufPush { ptr, .. }
        | Inst::InputBufConsume { ptr, .. }
        | Inst::InputBufTick { ptr, .. } => row_ptrs.get(ptr).copied(),
        Inst::Call { args, .. } => args.iter().find_map(|a| row_ptrs.get(a).copied()),
        _ => None,
    }
}

fn collect_loop_blocks(
    func: &MirFunction,
    starts: &[usize],
    chunk_hdr_id: Option<BlockId>,
    chunk_exit_id: Option<BlockId>,
    qi: u32,
) -> HashSet<BlockId> {
    let mut blocks = HashSet::new();
    let mut queue = VecDeque::new();
    let flush_prefix = format!("q{qi}_t");
    for &start_idx in starts {
        if let Some(bb) = func.blocks.get(start_idx)
            && Some(bb.id) != chunk_hdr_id
            && Some(bb.id) != chunk_exit_id
            && blocks.insert(bb.id)
        {
            queue.push_back(bb.id);
        }
    }
    while let Some(bid) = queue.pop_front() {
        for succ in term_succs(&func.blocks[bid.0 as usize].terminator) {
            if Some(succ) == chunk_hdr_id || Some(succ) == chunk_exit_id {
                continue;
            }
            let lbl = &func.blocks[succ.0 as usize].label;
            if lbl.starts_with(&flush_prefix) && lbl.ends_with("_break_flush") {
                continue;
            }
            if blocks.insert(succ) {
                queue.push_back(succ);
            }
        }
    }
    blocks
}

fn find_tx_merge_bb(func: &MirFunction, ckpt_bb: BlockId, rollback_bb: BlockId) -> Option<BlockId> {
    // Depth-balanced BFS starting from successors of `ckpt_bb` (not entering `rollback_bb`).
    let mut queue = VecDeque::new();
    let mut best_depth: HashMap<BlockId, usize> = HashMap::new();
    for succ in term_succs(&func.blocks[ckpt_bb.0 as usize].terminator) {
        if succ != rollback_bb {
            best_depth.insert(succ, 0);
            queue.push_back((succ, 0usize));
        }
    }
    while let Some((bid, depth)) = queue.pop_front() {
        let bb = &func.blocks[bid.0 as usize];
        if bb.label == "atomic_merge" && bid != ckpt_bb && depth == 0 {
            return Some(bid);
        }
        let next_depth = if bb
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::CmdCheckpoint))
        {
            depth + 1
        } else if bb.label == "atomic_merge" {
            depth.saturating_sub(1)
        } else {
            depth
        };
        for succ in term_succs(&bb.terminator) {
            if succ == rollback_bb || best_depth.contains_key(&succ) {
                continue;
            }
            best_depth.insert(succ, next_depth);
            queue.push_back((succ, next_depth));
        }
    }
    match func.blocks[rollback_bb.0 as usize].terminator {
        Terminator::Goto(target) if func.blocks[target.0 as usize].label == "atomic_merge" => {
            Some(target)
        }
        _ => None,
    }
}

fn collect_reachable_until(
    func: &MirFunction,
    starts: &[BlockId],
    stop_at: BlockId,
    exclude: &HashSet<BlockId>,
) -> HashSet<BlockId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for &s in starts {
        if s != stop_at && !exclude.contains(&s) && visited.insert(s) {
            queue.push_back(s);
        }
    }
    while let Some(bid) = queue.pop_front() {
        for succ in term_succs(&func.blocks[bid.0 as usize].terminator) {
            if succ != stop_at && !exclude.contains(&succ) && visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }
    visited
}

fn discover_atomic_scopes(
    func: &MirFunction,
    loop_blocks: &HashSet<BlockId>,
    is_absent: &impl Fn(BlockId, &str) -> bool,
) -> Vec<AtomicTxScope> {
    let mut scopes = Vec::new();
    for bb in &func.blocks {
        if !loop_blocks.contains(&bb.id) || is_absent(bb.id, &bb.label) {
            continue;
        }
        for (stmt_idx, s) in bb.stmts.iter().enumerate() {
            if !matches!(s.inst, Inst::CmdCheckpoint) {
                continue;
            }
            let Some(ckpt_local) = s.dst else {
                continue;
            };
            let Some(rollback_bb) = func.blocks.iter().find_map(|rb| {
                rb.stmts
                    .iter()
                    .any(|rs| {
                        matches!(
                            rs.inst,
                            Inst::CmdRollback { checkpoint } if checkpoint == ckpt_local
                        )
                    })
                    .then_some(rb.id)
            }) else {
                continue;
            };
            let Some(merge_bb) = find_tx_merge_bb(func, bb.id, rollback_bb) else {
                continue;
            };
            if !loop_blocks.contains(&merge_bb)
                || is_absent(merge_bb, &func.blocks[merge_bb.0 as usize].label)
            {
                continue;
            }
            let empty_ex = HashSet::new();
            let rollback_blocks =
                collect_reachable_until(func, &[rollback_bb], merge_bb, &empty_ex);
            let ckpt_succs = term_succs(&func.blocks[bb.id.0 as usize].terminator);
            let body_blocks =
                collect_reachable_until(func, &ckpt_succs, merge_bb, &rollback_blocks);
            scopes.push(AtomicTxScope {
                ckpt_bb: bb.id,
                ckpt_stmt_idx: stmt_idx,
                merge_bb,
                body_blocks,
                rollback_blocks,
                parent_idx: None,
            });
        }
    }
    // Sort outermost-to-innermost (larger body_blocks first; deterministic tie-break on ckpt_bb).
    scopes.sort_by(|a, b| {
        b.body_blocks
            .len()
            .cmp(&a.body_blocks.len())
            .then_with(|| a.ckpt_bb.0.cmp(&b.ckpt_bb.0))
    });
    for i in 0..scopes.len() {
        let ckpt_bb = scopes[i].ckpt_bb;
        scopes[i].parent_idx = (0..i)
            .rev()
            .find(|&p| scopes[p].body_blocks.contains(&ckpt_bb));
    }
    scopes
}

fn innermost_atomic_scope(
    scopes: &[AtomicTxScope],
    bb_id: BlockId,
    stmt_idx: usize,
) -> Option<usize> {
    (0..scopes.len()).rev().find(|&i| {
        let s = &scopes[i];
        !s.rollback_blocks.contains(&bb_id)
            && (s.body_blocks.contains(&bb_id)
                || (bb_id == s.ckpt_bb && stmt_idx > s.ckpt_stmt_idx))
    })
}

fn active_scope_chain_at(
    scopes: &[AtomicTxScope],
    scope_slots: &[Option<(LocalId, LocalId)>],
    bb_id: BlockId,
) -> Vec<(LocalId, LocalId)> {
    let mut chain = Vec::new();
    let Some(mut cur) = (0..scopes.len()).rev().find(|&i| {
        !scopes[i].rollback_blocks.contains(&bb_id) && scopes[i].body_blocks.contains(&bb_id)
    }) else {
        return chain;
    };
    loop {
        if let Some(pair) = scope_slots[cur] {
            chain.push(pair);
        }
        match scopes[cur].parent_idx {
            Some(p) => cur = p,
            None => break,
        }
    }
    chain
}

#[allow(clippy::too_many_arguments)]
fn wrap_tx_dirty_before_exit(
    func: &mut MirFunction,
    exit_bb: BlockId,
    flush_bb: BlockId,
    scopes: &[AtomicTxScope],
    scope_slots: &[Option<(LocalId, LocalId)>],
    run_start: LocalId,
    run_len: LocalId,
    qi: u32,
    ti: u32,
) -> BlockId {
    let active_chain = active_scope_chain_at(scopes, scope_slots, exit_bb);
    if active_chain.is_empty() {
        return flush_bb;
    }
    // Check from innermost to outermost; record the active dirty row once, then flush.
    let mut next_dest = flush_bb;
    for (tx_dirty, tx_row) in active_chain.into_iter().rev() {
        let rec_bb = func.alloc_block(
            format!("q{qi}_t{ti}_tx_exit_rec"),
            Terminator::Goto(flush_bb),
        );
        let r = func.alloc_local("tx_exit_row", MirType::U32);
        func.blocks[rec_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(r),
            inst: Inst::SlotLoad { slot: tx_row },
        });
        func.blocks[rec_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx: r,
            },
        });
        let d = func.alloc_local("tx_exit_dirty", MirType::Bool);
        let chk_bb = func.alloc_block(
            format!("q{qi}_t{ti}_tx_exit_chk"),
            Terminator::Branch {
                cond: d,
                then_bb: rec_bb,
                else_bb: next_dest,
            },
        );
        func.blocks[chk_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(d),
            inst: Inst::SlotLoad { slot: tx_dirty },
        });
        next_dest = chk_bb;
    }
    next_dest
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

    fn lower_and_verify(src: &str) -> crate::MirModule {
        let sema = strata_sema::analyze_source("tick_test.strata", src);
        let errs: Vec<_> = sema
            .diagnostics
            .iter()
            .filter(|d| matches!(d.severity, strata_sema::Severity::Error))
            .collect();
        assert!(errs.is_empty(), "sema errors: {errs:?}");
        let mir = crate::lower_to_mir(&sema);
        crate::verify::verify_mir(&mir).expect("MIR must verify cleanly");
        mir
    }

    /// EQ-06a: `Call(&mut T)` and `ArrayStore` inside `&mut?` record `DirtyRunRecordRow` at the
    /// actual row index inside the row block — never on `q0_chunk_body` at `row_idx == 0`.
    #[test]
    fn selective_call_and_array_store_record_actual_row_idx() {
        let src = r#"
component Bag { flag: i32 = 0, scores: [i32; 4] = [0, 0, 0, 0] }

fn touch_bag(b: &mut Bag) {
    b.flag += 1;
}

sys step_call() {
    for row in query(b: &mut? Bag) {
        if row.b.flag == 1 {
            touch_bag(row.b);
        }
    }
}

sys step_arr() {
    for row in query(b: &mut? Bag) {
        if row.b.flag == 2 {
            row.b.scores[0] = 99;
        }
    }
}

sys step_readonly() {
    let acc: i32 = 0;
    for row in query(b: &mut? Bag) {
        acc += row.b.flag;
    }
}
"#;
        let mir = lower_and_verify(src);
        for fname in ["step_call", "step_arr"] {
            let f = mir.functions.iter().find(|f| f.name == fname).unwrap();
            let chunk_body = f
                .blocks
                .iter()
                .find(|b| b.label == "q0_chunk_body")
                .expect("missing q0_chunk_body");
            assert!(
                !chunk_body
                    .stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::DirtyRunRecordRow { .. })),
                "{fname}: chunk header must not emit fallback DirtyRunRecordRow"
            );
            let rec_blocks: Vec<_> = f
                .blocks
                .iter()
                .filter(|b| {
                    b.stmts
                        .iter()
                        .any(|s| matches!(s.inst, Inst::DirtyRunRecordRow { .. }))
                })
                .collect();
            assert_eq!(
                rec_blocks.len(),
                1,
                "{fname}: expected row-level DirtyRunRecordRow"
            );
            let has_call_or_arr = rec_blocks[0]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::Call { .. } | Inst::ArrayStore { .. }));
            assert!(
                has_call_or_arr,
                "{fname}: DirtyRunRecordRow should follow Call/ArrayStore in block {}",
                rec_blocks[0].label
            );
        }

        let ro = mir
            .functions
            .iter()
            .find(|f| f.name == "step_readonly")
            .unwrap();
        assert!(
            !ro.blocks.iter().any(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::DirtyRunRecordRow { .. }))
            }),
            "read-only `&mut?` loop must not dirty row 0"
        );
    }

    /// EQ-06b: Early `break` and `return` inside `&mut?` loops emit `IterMarkChangedRange`.
    #[test]
    fn selective_break_and_return_flush_dirty_ranges() {
        let src = r#"
component ItemA { hp: i32 = 10 }
component ItemB { alt: i32 = 0 }

sys break_sys() {
    for row in query(a: &mut? ItemA, b: &mut? ItemB) {
        row.a.hp += 1;
        row.b.alt += 1;
        if row.a.hp > 5 {
            break;
        }
    }
}

sys return_sys() {
    for row in query(a: &mut? ItemA) {
        row.a.hp += 2;
        if row.a.hp > 5 {
            return;
        }
    }
}
"#;
        let mir = lower_and_verify(src);
        let bf = mir
            .functions
            .iter()
            .find(|f| f.name == "break_sys")
            .unwrap();
        let t0_break_flushes = bf
            .blocks
            .iter()
            .filter(|b| b.label.contains("t0_break_flush"))
            .filter(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { term_idx: 0, .. }))
            })
            .count();
        let t1_break_flushes = bf
            .blocks
            .iter()
            .filter(|b| b.label.contains("t1_break_flush"))
            .filter(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { term_idx: 1, .. }))
            })
            .count();
        assert!(t0_break_flushes >= 1, "missing t0 break flush");
        assert!(t1_break_flushes >= 1, "missing t1 break flush");

        let rf = mir
            .functions
            .iter()
            .find(|f| f.name == "return_sys")
            .unwrap();
        let ret_flushes = rf
            .blocks
            .iter()
            .filter(|b| matches!(b.terminator, Terminator::Return(..)) && b.label != "entry")
            .filter(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { .. }))
            })
            .count();
        assert!(
            ret_flushes >= 1,
            "expected IterMarkChangedRange on early return inside loop"
        );
    }

    /// GF-12 / EQ-06e: Rolled-back `atomic` mutations inside `&mut?` must not mark dirty rows.
    #[test]
    fn selective_atomic_rollback_suppresses_dirty_record() {
        let src = r#"
component WatchTick { val: i32 = 0 }

sys atomic_sel() {
    for row in query(w: &mut? WatchTick) {
        atomic {
            row.w.val += 50;
            require_true(row.w.val < 0);
        }
    }
}
"#;
        let mir = lower_and_verify(src);
        let f = mir
            .functions
            .iter()
            .find(|f| f.name == "atomic_sel")
            .unwrap();
        let rec_blocks: Vec<_> = f
            .blocks
            .iter()
            .filter(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::DirtyRunRecordRow { .. }))
            })
            .collect();
        assert_eq!(rec_blocks.len(), 1);
        assert!(
            rec_blocks[0].label.contains("tx_dirty_rec"),
            "expected DirtyRunRecordRow to be deferred to tx_dirty_rec commit path, got {}",
            rec_blocks[0].label
        );
        // Ensure `atomic_rollback` never passes through `tx_dirty_chk`.
        for rb in f.blocks.iter().filter(|b| b.label == "atomic_rollback") {
            if let Terminator::Goto(target) = rb.terminator {
                assert_eq!(
                    f.blocks[target.0 as usize].label, "atomic_merge",
                    "rollback must bypass tx_dirty_chk directly to atomic_merge"
                );
            }
        }
    }
}
