//! Speculative `atomic { ... } on_rollback { ... }` pass (`Slots 63–64`).
//!
//! Driven strictly by lowered `Inst::CmdCheckpoint` / `Inst::RequireTrue` CFG structure (never
//! inspecting `source_body` text), capturing pre-image undo logs before `&mut` writes inside
//! transactions and restoring exact pre-transaction state in reverse order on rollback.

use crate::ir::{BlockId, Inst, LocalId, MirFunction, MirStmt, MirType, Terminator};
use crate::lower::MirLowerCtx;
use std::collections::{HashMap, HashSet, VecDeque};

/// Instruments `Inst::CmdCheckpoint`-guarded `atomic` transactions with pre-image undo logs
/// (`FieldLoad` + `SlotAlloc` before `FieldStore`, outer `SlotStore` snapshots, and reverse-order
/// restoration in `atomic_rollback`).
pub fn run(func: &mut MirFunction) {
    run_inner(func, None);
}

/// Runs `atomic_tx` with full [`MirLowerCtx`] layout metadata for exact field type resolution.
pub(crate) fn run_with_ctx(func: &mut MirFunction, ctx: &MirLowerCtx) {
    run_inner(func, Some(ctx));
}

enum UndoOp {
    Slot {
        slot: LocalId,
        undo_slot: LocalId,
        ty: MirType,
    },
    Field {
        saved_flag: LocalId,
        undo_slot: LocalId,
        base_ptr: LocalId,
        layout_key: String,
        field: String,
        offset_bytes: u32,
        field_ty: MirType,
    },
}

fn run_inner(func: &mut MirFunction, ctx: Option<&MirLowerCtx>) {
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
            instrument_structured_atomic(
                func,
                BlockId(entry_idx as u32),
                ckpt_local,
                merge_bb,
                ctx,
            );
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

fn emit_typed_zero_init(
    func: &mut MirFunction,
    stmts: &mut Vec<MirStmt>,
    slot: LocalId,
    ty: &MirType,
    tag: usize,
) {
    let inst = match ty {
        MirType::Bool => Some(Inst::ConstBool { value: false }),
        MirType::U8
        | MirType::U16
        | MirType::U32
        | MirType::U64
        | MirType::I8
        | MirType::I16
        | MirType::I32
        | MirType::I64
        | MirType::Fix32
        | MirType::Fix64
        | MirType::Entity
        | MirType::Sym => Some(Inst::ConstInt { value: 0 }),
        MirType::F32 | MirType::F64 => Some(Inst::ConstFloat { value: 0.0 }),
        MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => Some(Inst::ConstVec {
            dims: 2,
            values: [0.0; 4],
        }),
        MirType::Vec3 | MirType::IVec3 => Some(Inst::ConstVec {
            dims: 3,
            values: [0.0; 4],
        }),
        MirType::Vec4 => Some(Inst::ConstVec {
            dims: 4,
            values: [0.0; 4],
        }),
        // Aggregate / pointer slots are zero-initialized at function entry by all 4 backends.
        _ => None,
    };
    if let Some(init_inst) = inst {
        let z = func.alloc_local(format!("tx_z_{tag}"), ty.clone());
        stmts.push(MirStmt {
            dst: Some(z),
            inst: init_inst,
        });
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::SlotStore { slot, val: z },
        });
    }
}

fn instrument_structured_atomic(
    func: &mut MirFunction,
    ckpt_bb: BlockId,
    ckpt_local: LocalId,
    merge_bb: BlockId,
    ctx: Option<&MirLowerCtx>,
) {
    let tx_blocks = collect_non_rollback_tx_blocks(func, ckpt_bb, merge_bb);

    // Collect every local defined inside the transaction blocks so we only snapshot pre-existing
    // outer stack slots (`let mut x = ...` declared before `atomic`).
    let mut defined_in_tx: HashSet<LocalId> = HashSet::new();
    for &b in &tx_blocks {
        for s in &func.blocks[b.0 as usize].stmts {
            if let Some(d) = s.dst {
                defined_in_tx.insert(d);
            }
        }
    }

    let mut slot_types: HashMap<LocalId, MirType> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let (Some(dst), Inst::SlotAlloc { ty }) = (s.dst, &s.inst) {
                slot_types.insert(dst, ty.clone());
            }
        }
    }

    let mut undo_ops: Vec<UndoOp> = Vec::new();
    let mut shadows: Vec<(String, LocalId)> = Vec::new();
    let mut seen_outer_slots: HashSet<LocalId> = HashSet::new();
    let mut ckpt_setup_stmts: Vec<MirStmt> = Vec::new();

    // 1. Snapshot outer mutable stack slots once at `ckpt_bb` (immediately after `CmdCheckpoint`).
    let mut outer_slots_to_snapshot: Vec<(LocalId, MirType)> = Vec::new();
    for &b in &tx_blocks {
        for s in &func.blocks[b.0 as usize].stmts {
            if let Inst::SlotStore { slot, val } = s.inst
                && !defined_in_tx.contains(&slot)
                && seen_outer_slots.insert(slot)
            {
                let sty = slot_types
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| func.locals[val.0 as usize].ty.clone());
                outer_slots_to_snapshot.push((slot, sty));
            }
        }
    }
    for (slot, sty) in outer_slots_to_snapshot {
        let undo_slot = func.alloc_local(format!("tx_undo_slot_{}", slot.0), MirType::MutPtr);
        let pre_val = func.alloc_local(format!("tx_pre_slot_{}", slot.0), sty.clone());
        ckpt_setup_stmts.push(MirStmt {
            dst: Some(undo_slot),
            inst: Inst::SlotAlloc { ty: sty.clone() },
        });
        ckpt_setup_stmts.push(MirStmt {
            dst: Some(pre_val),
            inst: Inst::SlotLoad { slot },
        });
        ckpt_setup_stmts.push(MirStmt {
            dst: None,
            inst: Inst::SlotStore {
                slot: undo_slot,
                val: pre_val,
            },
        });
        let target_name = format!("slot_{}", slot.0);
        shadows.push((target_name, undo_slot));
        undo_ops.push(UndoOp::Slot {
            slot,
            undo_slot,
            ty: sty,
        });
    }

    // 2. Instrument each `FieldStore` inside `tx_blocks` with shadow-before-mutate pre-image capture:
    //    if !saved_flag { undo_slot = FieldLoad(...); saved_flag = true; } FieldStore(...);
    let mut all_tx_blocks = tx_blocks.clone();
    for &b in &tx_blocks {
        let has_field_store = func.blocks[b.0 as usize]
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::FieldStore { .. }));
        if !has_field_store {
            continue;
        }

        let old_stmts = std::mem::take(&mut func.blocks[b.0 as usize].stmts);
        let orig_term = func.blocks[b.0 as usize].terminator.clone();
        let mut cur_bb = b;

        for s in old_stmts {
            if let Inst::FieldStore {
                base_ptr,
                ref layout_key,
                ref field,
                offset_bytes,
                val,
            } = s.inst
            {
                let field_ty = ctx
                    .and_then(|c| c.resolve_field_opt(layout_key, field))
                    .unwrap_or_else(|| func.locals[val.0 as usize].ty.clone());
                let site_idx = undo_ops.len();

                let saved_flag = func.alloc_local(format!("tx_saved_{site_idx}"), MirType::MutPtr);
                ckpt_setup_stmts.push(MirStmt {
                    dst: Some(saved_flag),
                    inst: Inst::SlotAlloc { ty: MirType::Bool },
                });
                let init_false = func.alloc_local(format!("tx_init_f_{site_idx}"), MirType::Bool);
                ckpt_setup_stmts.push(MirStmt {
                    dst: Some(init_false),
                    inst: Inst::ConstBool { value: false },
                });
                ckpt_setup_stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: saved_flag,
                        val: init_false,
                    },
                });

                let undo_slot = func.alloc_local(format!("tx_undo_{site_idx}"), MirType::MutPtr);
                ckpt_setup_stmts.push(MirStmt {
                    dst: Some(undo_slot),
                    inst: Inst::SlotAlloc {
                        ty: field_ty.clone(),
                    },
                });
                emit_typed_zero_init(func, &mut ckpt_setup_stmts, undo_slot, &field_ty, site_idx);

                let already = func.alloc_local(format!("tx_already_{site_idx}"), MirType::Bool);
                let not_saved = func.alloc_local(format!("tx_not_saved_{site_idx}"), MirType::Bool);
                func.blocks[cur_bb.0 as usize].stmts.push(MirStmt {
                    dst: Some(already),
                    inst: Inst::SlotLoad { slot: saved_flag },
                });
                func.blocks[cur_bb.0 as usize].stmts.push(MirStmt {
                    dst: Some(not_saved),
                    inst: Inst::UnOp {
                        op: "!".to_owned(),
                        val: already,
                    },
                });

                let save_bb = func.alloc_block("tx_save_pre", Terminator::Return(None));
                let store_bb = func.alloc_block("tx_do_store", Terminator::Return(None));
                all_tx_blocks.push(store_bb);

                func.blocks[cur_bb.0 as usize].terminator = Terminator::Branch {
                    cond: not_saved,
                    then_bb: save_bb,
                    else_bb: store_bb,
                };

                let old_val = func.alloc_local(format!("tx_pre_{site_idx}"), field_ty.clone());
                let t_bool = func.alloc_local(format!("tx_t_{site_idx}"), MirType::Bool);
                func.blocks[save_bb.0 as usize].stmts.push(MirStmt {
                    dst: Some(old_val),
                    inst: Inst::FieldLoad {
                        base_ptr,
                        layout_key: layout_key.clone(),
                        field: field.clone(),
                        offset_bytes,
                        field_ty: field_ty.clone(),
                    },
                });
                func.blocks[save_bb.0 as usize].stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: undo_slot,
                        val: old_val,
                    },
                });
                func.blocks[save_bb.0 as usize].stmts.push(MirStmt {
                    dst: Some(t_bool),
                    inst: Inst::ConstBool { value: true },
                });
                func.blocks[save_bb.0 as usize].stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: saved_flag,
                        val: t_bool,
                    },
                });
                func.blocks[save_bb.0 as usize].terminator = Terminator::Goto(store_bb);

                let target_name = if layout_key.is_empty() {
                    field.clone()
                } else {
                    format!("{layout_key}.{field}")
                };
                let layout_clone = layout_key.clone();
                let field_clone = field.clone();
                let val_copy = val;

                func.blocks[store_bb.0 as usize].stmts.push(s);
                func.blocks[store_bb.0 as usize].stmts.push(MirStmt {
                    dst: None,
                    inst: Inst::ShadowWrite {
                        target_name: target_name.clone(),
                        shadow_slot: undo_slot,
                        val: val_copy,
                    },
                });

                undo_ops.push(UndoOp::Field {
                    saved_flag,
                    undo_slot,
                    base_ptr,
                    layout_key: layout_clone,
                    field: field_clone,
                    offset_bytes,
                    field_ty,
                });
                shadows.push((target_name, undo_slot));

                cur_bb = store_bb;
            } else {
                func.blocks[cur_bb.0 as usize].stmts.push(s);
            }
        }
        func.blocks[cur_bb.0 as usize].terminator = orig_term;
    }

    if shadows.is_empty() {
        let fallback_slot = func.alloc_local("tx_mut_shadow", MirType::MutPtr);
        let zero = func.alloc_local("tx_z", MirType::I32);
        ckpt_setup_stmts.push(MirStmt {
            dst: Some(zero),
            inst: Inst::ConstInt { value: 0 },
        });
        ckpt_setup_stmts.push(MirStmt {
            dst: Some(fallback_slot),
            inst: Inst::SlotAlloc { ty: MirType::I32 },
        });
        ckpt_setup_stmts.push(MirStmt {
            dst: None,
            inst: Inst::ShadowWrite {
                target_name: "tx_state".to_owned(),
                shadow_slot: fallback_slot,
                val: zero,
            },
        });
        shadows.push(("tx_state".to_owned(), fallback_slot));
    }

    func.blocks[ckpt_bb.0 as usize]
        .stmts
        .extend(ckpt_setup_stmts);

    // 3. Emit reverse-order pre-image restoration in `atomic_rollback` BEFORE `on_rollback` stmts.
    if !undo_ops.is_empty()
        && let Some(rollback_bb) = find_rollback_block(func, ckpt_local)
    {
        let old_rb_stmts = std::mem::take(&mut func.blocks[rollback_bb.0 as usize].stmts);
        let orig_rb_term = func.blocks[rollback_bb.0 as usize].terminator.clone();
        let rb_split_idx = old_rb_stmts
            .iter()
            .position(|s| {
                matches!(
                    s.inst,
                    Inst::CmdRollback { checkpoint } if checkpoint == ckpt_local
                )
            })
            .unwrap_or(0);

        let split_at = (rb_split_idx + 1).min(old_rb_stmts.len());
        let (prefix_stmts, on_rollback_stmts) = old_rb_stmts.split_at(split_at);
        func.blocks[rollback_bb.0 as usize].stmts = prefix_stmts.to_vec();

        let mut cur_rb = rollback_bb;
        for (ri, op) in undo_ops.into_iter().rev().enumerate() {
            match op {
                UndoOp::Slot {
                    slot,
                    undo_slot,
                    ty,
                } => {
                    let old_val = func.alloc_local(format!("tx_rb_slot_{ri}"), ty);
                    func.blocks[cur_rb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_val),
                        inst: Inst::SlotLoad { slot: undo_slot },
                    });
                    func.blocks[cur_rb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore { slot, val: old_val },
                    });
                }
                UndoOp::Field {
                    saved_flag,
                    undo_slot,
                    base_ptr,
                    layout_key,
                    field,
                    offset_bytes,
                    field_ty,
                } => {
                    let was_saved = func.alloc_local(format!("tx_rb_chk_{ri}"), MirType::Bool);
                    func.blocks[cur_rb.0 as usize].stmts.push(MirStmt {
                        dst: Some(was_saved),
                        inst: Inst::SlotLoad { slot: saved_flag },
                    });
                    let restore_bb = func.alloc_block("tx_undo_field", Terminator::Return(None));
                    let next_rb_bb = func.alloc_block("tx_undo_next", Terminator::Return(None));
                    func.blocks[cur_rb.0 as usize].terminator = Terminator::Branch {
                        cond: was_saved,
                        then_bb: restore_bb,
                        else_bb: next_rb_bb,
                    };

                    let old_val = func.alloc_local(format!("tx_rb_fld_{ri}"), field_ty);
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_val),
                        inst: Inst::SlotLoad { slot: undo_slot },
                    });
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::FieldStore {
                            base_ptr,
                            layout_key,
                            field,
                            offset_bytes,
                            val: old_val,
                        },
                    });
                    func.blocks[restore_bb.0 as usize].terminator = Terminator::Goto(next_rb_bb);
                    cur_rb = next_rb_bb;
                }
            }
        }
        func.blocks[cur_rb.0 as usize]
            .stmts
            .extend(on_rollback_stmts.iter().cloned());
        func.blocks[cur_rb.0 as usize].terminator = orig_rb_term;
    }

    // 4. Redirect direct commit edges `(non_rollback_tx_block -> merge_bb)` through a commit block.
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

    for &b in &all_tx_blocks {
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

fn find_rollback_block(func: &MirFunction, ckpt_local: LocalId) -> Option<BlockId> {
    func.blocks
        .iter()
        .find(|bb| {
            bb.stmts.iter().any(|s| {
                matches!(
                    s.inst,
                    Inst::CmdRollback { checkpoint } if checkpoint == ckpt_local
                )
            })
        })
        .map(|bb| bb.id)
}

fn collect_non_rollback_tx_blocks(
    func: &MirFunction,
    ckpt_bb: BlockId,
    merge_bb: BlockId,
) -> Vec<BlockId> {
    let mut visited = HashSet::new();
    let mut out = Vec::new();
    let mut q = VecDeque::new();
    visited.insert(ckpt_bb);
    for s in successors(&func.blocks[ckpt_bb.0 as usize].terminator) {
        if s != merge_bb
            && func.blocks[s.0 as usize].label != "atomic_rollback"
            && visited.insert(s)
        {
            q.push_back(s);
        }
    }
    while let Some(b) = q.pop_front() {
        if b == merge_bb || func.blocks[b.0 as usize].label == "atomic_rollback" {
            continue;
        }
        out.push(b);
        for s in successors(&func.blocks[b.0 as usize].terminator) {
            if s != merge_bb
                && func.blocks[s.0 as usize].label != "atomic_rollback"
                && visited.insert(s)
            {
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
