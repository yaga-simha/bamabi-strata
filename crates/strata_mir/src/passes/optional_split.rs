//! Chunk-level `OptionalChunkIsPresent` splitting pass for optional `?&T` / `?&mut T` terms.
//!
//! Eliminates per-row null checks inside hot inner loops by hoisting `term_slice != null` above
//! the row loop and duplicating the real row-loop CFG into `opt_present_*` and `opt_absent_*`
//! specialized loops without any `OpaqueExpr` placeholders.

use crate::ir::{BlockId, Inst, LocalId, MirFunction, MirStmt, MirType, Terminator};
use std::collections::{HashMap, HashSet, VecDeque};
use strata_sema::access::TermAccessMode;

/// Hoists optional query term checks above the inner row loop, splitting the real loop CFG into
/// `opt_present_*` and `opt_absent_*` paths.
pub fn run(func: &mut MirFunction) {
    let mut optional_terms: Vec<(u32, u32, String, bool)> = Vec::new();
    for (qi, q) in func.queries.iter().enumerate() {
        if q.is_point_lookup {
            continue;
        }
        for (ti, t) in q.terms.iter().enumerate() {
            match t.mode {
                TermAccessMode::OptionalRead => {
                    optional_terms.push((qi as u32, ti as u32, t.storage_key.clone(), false));
                }
                TermAccessMode::OptionalWrite => {
                    optional_terms.push((qi as u32, ti as u32, t.storage_key.clone(), true));
                }
                _ => {}
            }
        }
    }
    if optional_terms.is_empty() || func.blocks.is_empty() {
        return;
    }

    for (qi, ti, storage_key, is_mut) in optional_terms {
        if split_chunk_loop_if_present(func, qi, ti, &storage_key) {
            continue;
        }
        // Fallback for compact single-block CFGs where optional column borrow is synthesized at entry
        split_single_block_optional(func, qi, ti, &storage_key, is_mut);
    }
}

fn find_chunk_cond_local(
    stmts: &[MirStmt],
    qi: u32,
    ti: u32,
    storage_key: &str,
) -> Option<LocalId> {
    let col_ptr = stmts.iter().find_map(|s| match s.inst {
        Inst::IterColRead {
            query_idx,
            term_idx,
            ..
        }
        | Inst::IterColWrite {
            query_idx,
            term_idx,
            ..
        }
        | Inst::IterColWriteUntracked {
            query_idx,
            term_idx,
            ..
        }
        | Inst::IterColRowsRead {
            query_idx,
            term_idx,
            ..
        }
        | Inst::IterColRowsWrite {
            query_idx,
            term_idx,
            ..
        } if query_idx == qi && term_idx == ti => s.dst,
        _ => None,
    });
    if let Some(cp) = col_ptr
        && let Some(cond) = stmts.iter().find_map(|s| {
            if let Inst::OptionalChunkIsPresent { slice_ptr, .. } = s.inst
                && slice_ptr == cp
            {
                s.dst
            } else {
                None
            }
        })
    {
        return Some(cond);
    }
    stmts.iter().find_map(|s| {
        if let Inst::OptionalChunkIsPresent {
            storage_key: ref sk,
            ..
        } = s.inst
            && sk == storage_key
        {
            s.dst
        } else {
            None
        }
    })
}

fn split_chunk_loop_if_present(
    func: &mut MirFunction,
    qi: u32,
    ti: u32,
    storage_key: &str,
) -> bool {
    let chunk_label = format!("q{qi}_chunk_body");
    let chunk_hdr_label = format!("q{qi}_chunk_hdr");

    let Some(chunk_bb_idx) = func.blocks.iter().position(|b| b.label == chunk_label) else {
        return false;
    };
    let Some(chunk_hdr_idx) = func.blocks.iter().position(|b| b.label == chunk_hdr_label) else {
        return false;
    };

    let Some(cond_local) =
        find_chunk_cond_local(&func.blocks[chunk_bb_idx].stmts, qi, ti, storage_key)
    else {
        return false;
    };

    let chunk_hdr_id = func.blocks[chunk_hdr_idx].id;
    let chunk_exit_id = match func.blocks[chunk_hdr_idx].terminator {
        Terminator::Branch { else_bb, .. } => Some(else_bb),
        _ => None,
    };

    let old_term = func.blocks[chunk_bb_idx].terminator.clone();
    let (entry_id, present_entry_label) = match old_term {
        Terminator::Goto(target) if target != chunk_hdr_id && Some(target) != chunk_exit_id => {
            (target, format!("opt_present_entry_{storage_key}"))
        }
        Terminator::Goto(_) | Terminator::Return(_) => return false,
        other_term => {
            let dispatch_bb =
                func.alloc_block(format!("opt_dispatch_t{ti}_{storage_key}"), other_term);
            (
                dispatch_bb,
                format!("opt_present_entry_t{ti}_{storage_key}"),
            )
        }
    };

    // Collect every block belonging to this query's inner row loop (excluding chunk_hdr & chunk_exit)
    let loop_blocks = collect_reachable_until(func, entry_id, chunk_hdr_id, chunk_exit_id);
    if loop_blocks.is_empty() {
        return false;
    }

    // Rename original row-loop blocks for `opt_present_*` and clone once for `opt_absent_*`.
    let absent_entry = clone_specialized_loop(func, &loop_blocks, cond_local, false, "opt_absent");
    for &bid in &loop_blocks {
        let lbl = &mut func.blocks[bid.0 as usize].label;
        *lbl = format!("opt_present_{lbl}");
    }
    let present_pre = func.alloc_block(present_entry_label, Terminator::Goto(entry_id));
    func.blocks[present_pre.0 as usize].stmts.push(MirStmt {
        dst: Some(cond_local),
        inst: Inst::ConstBool { value: true },
    });

    // Point `chunk_body` terminator to branch on `cond_local`
    func.blocks[chunk_bb_idx].terminator = Terminator::Branch {
        cond: cond_local,
        then_bb: present_pre,
        else_bb: absent_entry,
    };
    true
}

fn collect_reachable_until(
    func: &MirFunction,
    start: BlockId,
    stop: BlockId,
    stop_alt: Option<BlockId>,
) -> Vec<BlockId> {
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut queue = VecDeque::new();
    let is_stop = |b: BlockId| b == stop || stop_alt == Some(b);
    if is_stop(start) {
        return order;
    }
    visited.insert(start);
    queue.push_back(start);

    while let Some(bid) = queue.pop_front() {
        if is_stop(bid) {
            continue;
        }
        order.push(bid);
        let term = &func.blocks[bid.0 as usize].terminator;
        for succ in terminator_successors(term) {
            if !is_stop(succ) && visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }
    order
}

fn clone_specialized_loop(
    func: &mut MirFunction,
    loop_blocks: &[BlockId],
    cond_local: LocalId,
    is_present: bool,
    prefix: &str,
) -> BlockId {
    let mut remap: HashMap<BlockId, BlockId> = HashMap::with_capacity(loop_blocks.len());
    for &orig in loop_blocks {
        let orig_label = func.blocks[orig.0 as usize].label.clone();
        let new_id = func.alloc_block(format!("{prefix}_{orig_label}"), Terminator::Return(None));
        remap.insert(orig, new_id);
    }

    for &orig in loop_blocks {
        let orig_stmts = func.blocks[orig.0 as usize].stmts.clone();
        let orig_term = func.blocks[orig.0 as usize].terminator.clone();
        let new_id = remap[&orig];

        // Seed specialized boolean binding at loop header/entry
        if orig == loop_blocks[0] {
            func.blocks[new_id.0 as usize].stmts.push(MirStmt {
                dst: Some(cond_local),
                inst: Inst::ConstBool { value: is_present },
            });
        }
        func.blocks[new_id.0 as usize].stmts.extend(orig_stmts);
        func.blocks[new_id.0 as usize].terminator = remap_terminator(orig_term, &remap);
    }

    remap[&loop_blocks[0]]
}

fn split_single_block_optional(
    func: &mut MirFunction,
    qi: u32,
    ti: u32,
    storage_key: &str,
    is_mut: bool,
) {
    let slice_local = func.alloc_local(
        format!("opt_{storage_key}_ptr"),
        if is_mut {
            MirType::MutPtr
        } else {
            MirType::Ptr
        },
    );
    let cond_local = func.alloc_local(format!("has_{storage_key}"), MirType::Bool);

    let orig_stmts = func.blocks[0].stmts.clone();
    let old_term = func.blocks[0].terminator.clone();
    let present_bb = func.alloc_block(
        format!("opt_present_{storage_key}"),
        Terminator::Return(None),
    );
    let absent_bb = func.alloc_block(
        format!("opt_absent_{storage_key}"),
        Terminator::Return(None),
    );
    let merge_bb = func.alloc_block(format!("opt_merge_{storage_key}"), old_term);

    func.blocks[0].stmts.push(MirStmt {
        dst: Some(slice_local),
        inst: if is_mut {
            Inst::IterColWrite {
                query_idx: qi,
                term_idx: ti,
                storage_key: storage_key.to_owned(),
            }
        } else {
            Inst::IterColRead {
                query_idx: qi,
                term_idx: ti,
                storage_key: storage_key.to_owned(),
            }
        },
    });
    func.blocks[0].stmts.push(MirStmt {
        dst: Some(cond_local),
        inst: Inst::OptionalChunkIsPresent {
            storage_key: storage_key.to_owned(),
            slice_ptr: slice_local,
        },
    });
    func.blocks[0].terminator = Terminator::Branch {
        cond: cond_local,
        then_bb: present_bb,
        else_bb: absent_bb,
    };

    func.blocks[present_bb.0 as usize].stmts = orig_stmts.clone();
    func.blocks[present_bb.0 as usize].stmts.push(MirStmt {
        dst: None,
        inst: Inst::OptionalChunkIsPresent {
            storage_key: storage_key.to_owned(),
            slice_ptr: slice_local,
        },
    });
    func.blocks[present_bb.0 as usize].terminator = Terminator::Goto(merge_bb);

    func.blocks[absent_bb.0 as usize].stmts = orig_stmts;
    func.blocks[absent_bb.0 as usize].terminator = Terminator::Goto(merge_bb);
}

fn terminator_successors(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::Return(_) => Vec::new(),
        Terminator::Goto(b) => vec![*b],
        Terminator::Branch {
            then_bb, else_bb, ..
        } => vec![*then_bb, *else_bb],
        Terminator::Switch {
            cases, default_bb, ..
        } => {
            let mut out: Vec<BlockId> = cases.iter().map(|(_, b)| *b).collect();
            out.push(*default_bb);
            out
        }
    }
}

fn remap_terminator(term: Terminator, remap: &HashMap<BlockId, BlockId>) -> Terminator {
    match term {
        Terminator::Return(v) => Terminator::Return(v),
        Terminator::Goto(b) => Terminator::Goto(*remap.get(&b).unwrap_or(&b)),
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => Terminator::Branch {
            cond,
            then_bb: *remap.get(&then_bb).unwrap_or(&then_bb),
            else_bb: *remap.get(&else_bb).unwrap_or(&else_bb),
        },
        Terminator::Switch {
            scrutinee,
            cases,
            default_bb,
        } => Terminator::Switch {
            scrutinee,
            cases: cases
                .into_iter()
                .map(|(k, b)| (k, *remap.get(&b).unwrap_or(&b)))
                .collect(),
            default_bb: *remap.get(&default_bb).unwrap_or(&default_bb),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

    /// Verifies optional `?T` query terms hoist a chunk-level presence branch around fast-path blocks.
    #[test]
    fn optional_split_inserts_chunk_presence_branch() {
        let mut func = MirFunction::new("opt_sys", MirFnKind::System);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Return(None),
        });
        func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: "Shield".to_owned(),
                field_name: None,
                mode: TermAccessMode::OptionalRead,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        run(&mut func);
        assert!(func.blocks.len() >= 4);
        assert!(
            func.blocks[0]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::OptionalChunkIsPresent { .. }))
        );
        assert!(matches!(
            func.blocks[0].terminator,
            Terminator::Branch { .. }
        ));
    }

    /// Verifies chunk loops with 2+ optional terms split cleanly inside the chunk loop without
    /// falling back to `split_single_block_optional` on entry block `0`.
    #[test]
    fn optional_split_multi_term_chunk_loop_keeps_entry_clean() {
        let mut func = MirFunction::new("multi_opt_sys", MirFnKind::System);
        let has_chunk = func.alloc_local("has_chunk", MirType::Bool);
        let col0 = func.alloc_local("col_a", MirType::Ptr);
        let pres0 = func.alloc_local("opt_a", MirType::Bool);
        let col1 = func.alloc_local("col_b", MirType::MutPtr);
        let pres1 = func.alloc_local("opt_b", MirType::Bool);
        let row_cond = func.alloc_local("row_cond", MirType::Bool);

        let entry = func.alloc_block("entry", Terminator::Goto(BlockId(1)));
        let chunk_hdr = func.alloc_block(
            "q0_chunk_hdr",
            Terminator::Branch {
                cond: has_chunk,
                then_bb: BlockId(2),
                else_bb: BlockId(5),
            },
        );
        let chunk_body = func.alloc_block("q0_chunk_body", Terminator::Goto(BlockId(3)));
        let row_hdr = func.alloc_block(
            "q0_row_hdr",
            Terminator::Branch {
                cond: row_cond,
                then_bb: BlockId(4),
                else_bb: chunk_hdr,
            },
        );
        let row_body = func.alloc_block("q0_row_body", Terminator::Goto(row_hdr));
        let _chunk_exit = func.alloc_block("q0_chunk_exit", Terminator::Return(None));

        func.blocks[chunk_hdr.0 as usize].stmts.push(MirStmt {
            dst: Some(has_chunk),
            inst: Inst::IterNextChunk { query_idx: 0 },
        });
        func.blocks[chunk_body.0 as usize].stmts.extend([
            MirStmt {
                dst: Some(col0),
                inst: Inst::IterColRead {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: "OptRO".to_owned(),
                },
            },
            MirStmt {
                dst: Some(pres0),
                inst: Inst::OptionalChunkIsPresent {
                    storage_key: "OptRO".to_owned(),
                    slice_ptr: col0,
                },
            },
            MirStmt {
                dst: Some(col1),
                inst: Inst::IterColWrite {
                    query_idx: 0,
                    term_idx: 1,
                    storage_key: "OptRW".to_owned(),
                },
            },
            MirStmt {
                dst: Some(pres1),
                inst: Inst::OptionalChunkIsPresent {
                    storage_key: "OptRW".to_owned(),
                    slice_ptr: col1,
                },
            },
        ]);
        func.blocks[row_hdr.0 as usize].stmts.push(MirStmt {
            dst: Some(row_cond),
            inst: Inst::ConstBool { value: true },
        });
        let _ = (entry, row_body);

        func.queries.push(QueryAccessDesc {
            terms: vec![
                QueryTerm {
                    storage_key: "OptRO".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::OptionalRead,
                    byte_start: 0,
                    byte_end: 0,
                },
                QueryTerm {
                    storage_key: "OptRW".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::OptionalWrite,
                    byte_start: 0,
                    byte_end: 0,
                },
            ],
            ..Default::default()
        });

        run(&mut func);

        // Entry block 0 must remain untouched (no fallback IterCol*/OptionalChunkIsPresent in block 0).
        assert!(func.blocks[0].stmts.is_empty());
        assert!(matches!(func.blocks[0].terminator, Terminator::Goto(_)));
        // q0_chunk_body must branch on `pres1`, with 4 specialized `row_hdr` leaves total.
        assert!(matches!(
            func.blocks[chunk_body.0 as usize].terminator,
            Terminator::Branch { cond, .. } if cond == pres1
        ));
        let row_hdr_count = func
            .blocks
            .iter()
            .filter(|b| b.label.ends_with("q0_row_hdr"))
            .count();
        assert_eq!(row_hdr_count, 4, "expected 4 specialized row_hdr copies");
    }
}
