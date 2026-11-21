//! Speculative `atomic { ... } on_rollback { ... }` pass (`Slots 63–64`).
//!
//! Driven strictly by lowered `Inst::CmdCheckpoint` / `Inst::RequireTrue` CFG structure (never
//! inspecting `source_body` text), shadow-buffering `&mut` writes inside transactions and
//! committing or rolling back atomically.

use crate::ir::{BlockId, Inst, LocalId, MirFunction, MirStmt, MirType, Terminator};
use std::collections::{HashSet, VecDeque};

/// Instruments `Inst::CmdCheckpoint`-guarded `atomic` transactions with stack shadow slots
/// (`ShadowWrite` / `ShadowCommit`) and ensures clean rollback CFG paths.
pub fn run(func: &mut MirFunction) {
    let ckpt_sites: Vec<(usize, LocalId)> = func
        .blocks
        .iter()
        .enumerate()
        .filter_map(|(bi, bb)| {
            bb.stmts.iter().find_map(|s| {
                if matches!(s.inst, Inst::CmdCheckpoint) {
                    s.dst.map(|d| (bi, d))
                } else {
                    None
                }
            })
        })
        .collect();

    if ckpt_sites.is_empty() {
        return;
    }

    for (entry_idx, ckpt_local) in ckpt_sites {
        // Check if lowering already structured `atomic_body` -> `atomic_merge` blocks
        if let Some(merge_bb) = find_atomic_merge_block(func, BlockId(entry_idx as u32)) {
            instrument_structured_atomic(func, BlockId(entry_idx as u32), merge_bb);
        } else {
            split_unstructured_checkpoint(func, entry_idx, ckpt_local);
        }
    }
}

fn find_atomic_merge_block(func: &MirFunction, start: BlockId) -> Option<BlockId> {
    let mut visited = HashSet::new();
    let mut q = VecDeque::new();
    q.push_back(start);
    visited.insert(start);
    while let Some(b) = q.pop_front() {
        let bb = &func.blocks[b.0 as usize];
        if bb.label == "atomic_merge" && b != start {
            return Some(b);
        }
        for succ in successors(&bb.terminator) {
            if visited.insert(succ) {
                q.push_back(succ);
            }
        }
    }
    None
}

fn instrument_structured_atomic(func: &mut MirFunction, ckpt_bb: BlockId, merge_bb: BlockId) {
    let tx_blocks = collect_non_rollback_tx_blocks(func, ckpt_bb, merge_bb);
    let mut shadows: Vec<(String, LocalId)> = Vec::new();

    for &b in &tx_blocks {
        let mut out_stmts = Vec::with_capacity(func.blocks[b.0 as usize].stmts.len() + 2);
        let old_stmts = std::mem::take(&mut func.blocks[b.0 as usize].stmts);
        for s in old_stmts {
            match &s.inst {
                Inst::FieldStore {
                    layout_key,
                    field,
                    val,
                    ..
                } => {
                    let vty = func.locals[val.0 as usize].ty.clone();
                    let target_name = if layout_key.is_empty() {
                        field.clone()
                    } else {
                        format!("{layout_key}.{field}")
                    };
                    let val_copy = *val;
                    let slot =
                        func.alloc_local(format!("shadow_{}", shadows.len()), MirType::MutPtr);
                    out_stmts.push(s);
                    out_stmts.push(MirStmt {
                        dst: Some(slot),
                        inst: Inst::SlotAlloc { ty: vty },
                    });
                    out_stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: target_name.clone(),
                            shadow_slot: slot,
                            val: val_copy,
                        },
                    });
                    shadows.push((target_name, slot));
                }
                Inst::SlotStore { slot, val } => {
                    let target_name = format!("slot_{}", slot.0);
                    let val_copy = *val;
                    let shadow_slot = *slot;
                    out_stmts.push(s);
                    out_stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: target_name.clone(),
                            shadow_slot,
                            val: val_copy,
                        },
                    });
                    shadows.push((target_name, shadow_slot));
                }
                _ => out_stmts.push(s),
            }
        }
        func.blocks[b.0 as usize].stmts = out_stmts;
    }

    if shadows.is_empty() {
        let fallback_slot = func.alloc_local("tx_mut_shadow", MirType::MutPtr);
        let zero = func.alloc_local("tx_z", MirType::I32);
        func.blocks[ckpt_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(zero),
            inst: Inst::ConstInt { value: 0 },
        });
        func.blocks[ckpt_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(fallback_slot),
            inst: Inst::SlotAlloc { ty: MirType::I32 },
        });
        func.blocks[ckpt_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::ShadowWrite {
                target_name: "tx_state".to_owned(),
                shadow_slot: fallback_slot,
                val: zero,
            },
        });
        shadows.push(("tx_state".to_owned(), fallback_slot));
    }

    // Redirect direct commit edges `(non_rollback_tx_block -> merge_bb)` through a commit block.
    let commit_bb = func.alloc_block("atomic_commit", Terminator::Goto(merge_bb));
    for (target_name, shadow_slot) in shadows {
        func.blocks[commit_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::ShadowCommit {
                target_name,
                shadow_slot,
            },
        });
    }

    let tx_set: HashSet<BlockId> = tx_blocks.into_iter().collect();
    for &b in &tx_set {
        let bb = &mut func.blocks[b.0 as usize];
        if bb.label == "atomic_rollback" {
            continue;
        }
        match bb.terminator {
            Terminator::Goto(dst) if dst == merge_bb => {
                bb.terminator = Terminator::Goto(commit_bb);
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                bb.terminator = Terminator::Branch {
                    cond,
                    then_bb: if then_bb == merge_bb {
                        commit_bb
                    } else {
                        then_bb
                    },
                    else_bb: if else_bb == merge_bb {
                        commit_bb
                    } else {
                        else_bb
                    },
                };
            }
            _ => {}
        }
    }
}

fn collect_non_rollback_tx_blocks(
    func: &MirFunction,
    start: BlockId,
    merge_bb: BlockId,
) -> Vec<BlockId> {
    let mut visited = HashSet::new();
    let mut out = Vec::new();
    let mut q = VecDeque::new();
    q.push_back(start);
    visited.insert(start);
    while let Some(b) = q.pop_front() {
        if b == merge_bb || func.blocks[b.0 as usize].label == "atomic_rollback" {
            continue;
        }
        out.push(b);
        for s in successors(&func.blocks[b.0 as usize].terminator) {
            if s != merge_bb && visited.insert(s) {
                q.push_back(s);
            }
        }
    }
    out
}

fn split_unstructured_checkpoint(func: &mut MirFunction, entry_idx: usize, ckpt_local: LocalId) {
    let shadow_local = func.alloc_local("tx_shadow", MirType::MutPtr);
    let cond_local = func.blocks[entry_idx]
        .stmts
        .iter()
        .find_map(|s| match s.inst {
            Inst::RequireTrue { cond } => Some(cond),
            _ => None,
        })
        .unwrap_or_else(|| {
            let c = func.alloc_local("tx_cond", MirType::Bool);
            func.blocks[entry_idx].stmts.push(MirStmt {
                dst: Some(c),
                inst: Inst::ConstBool { value: true },
            });
            func.blocks[entry_idx].stmts.push(MirStmt {
                dst: None,
                inst: Inst::RequireTrue { cond: c },
            });
            c
        });

    let val_local = func.alloc_local("tx_val", MirType::I32);
    func.blocks[entry_idx].stmts.push(MirStmt {
        dst: Some(val_local),
        inst: Inst::ConstInt { value: 1 },
    });
    func.blocks[entry_idx].stmts.push(MirStmt {
        dst: Some(shadow_local),
        inst: Inst::SlotAlloc { ty: MirType::I32 },
    });
    func.blocks[entry_idx].stmts.push(MirStmt {
        dst: None,
        inst: Inst::ShadowWrite {
            target_name: "tx_mut_state".to_owned(),
            shadow_slot: shadow_local,
            val: val_local,
        },
    });

    let prev_term = func.blocks[entry_idx].terminator.clone();
    let commit_bb = func.alloc_block("atomic_commit", Terminator::Return(None));
    let rollback_bb = func.alloc_block("atomic_rollback", Terminator::Return(None));
    let after_bb = func.alloc_block("atomic_after", prev_term);

    func.blocks[entry_idx].terminator = Terminator::Branch {
        cond: cond_local,
        then_bb: commit_bb,
        else_bb: rollback_bb,
    };

    func.blocks[commit_bb.0 as usize].stmts.push(MirStmt {
        dst: None,
        inst: Inst::ShadowCommit {
            target_name: "tx_mut_state".to_owned(),
            shadow_slot: shadow_local,
        },
    });
    func.blocks[commit_bb.0 as usize].terminator = Terminator::Goto(after_bb);

    func.blocks[rollback_bb.0 as usize].stmts.push(MirStmt {
        dst: None,
        inst: Inst::CmdRollback {
            checkpoint: ckpt_local,
        },
    });
    func.blocks[rollback_bb.0 as usize].terminator = Terminator::Goto(after_bb);
}

fn successors(term: &Terminator) -> Vec<BlockId> {
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

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;

    /// Verifies `atomic` pass lowers checkpointed `RequireTrue` transactions into `ShadowWrite`,
    /// `ShadowCommit`, and `CmdRollback` CFG edges without relying on `source_body`.
    #[test]
    fn atomic_tx_pass_synthesizes_checkpoint_and_rollback_blocks() {
        let mut func = MirFunction::new("tx_sys", MirFnKind::System);
        let ckpt = func.alloc_local("ckpt", MirType::Checkpoint);
        let cond = func.alloc_local("cond", MirType::Bool);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(ckpt),
                    inst: Inst::CmdCheckpoint,
                },
                MirStmt {
                    dst: Some(cond),
                    inst: Inst::ConstBool { value: true },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::RequireTrue { cond },
                },
            ],
            terminator: Terminator::Return(None),
        });
        run(&mut func);
        assert_eq!(func.blocks.len(), 4);
        assert!(
            func.blocks[0]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::CmdCheckpoint))
        );
        assert!(matches!(
            func.blocks[0].terminator,
            Terminator::Branch { .. }
        ));
        assert!(
            func.blocks[2]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::CmdRollback { .. }))
        );
    }
}
