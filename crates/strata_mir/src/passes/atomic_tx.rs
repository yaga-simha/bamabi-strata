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
    Array {
        saved_flag: LocalId,
        saved_idx_slot: LocalId,
        undo_slot: LocalId,
        base_ptr: LocalId,
        elem_ty: MirType,
    },
    BitSet {
        saved_flag: LocalId,
        saved_bit_slot: LocalId,
        undo_slot: LocalId,
        ptr: LocalId,
        words: u32,
    },
    Grace {
        saved_flag: LocalId,
        undo_slot: LocalId,
        ptr: LocalId,
    },
}

#[derive(Clone)]
struct FieldPtrOrigin {
    base_ptr: LocalId,
    layout_key: String,
    field: String,
    offset_bytes: u32,
}

/// Validates that no `atomic` transaction contains a query-row (`RowPtr`) mutation inside a
/// loop within the transaction body (`GF-09`), using nesting-aware balanced checkpoint/merge
/// matching so valid nested or per-entity `for row in query { atomic { ... } }` blocks pass.
///
/// # Errors
/// Returns a diagnostic message describing the offending function and block if a multi-entity
/// query loop mutates ECS component storage inside an `atomic` checkpoint scope.
pub fn validate_no_multi_entity_loops(func: &MirFunction) -> Result<(), String> {
    let row_derived = collect_row_derived_locals(func);
    if row_derived.is_empty() {
        return Ok(());
    }
    let ckpt_sites = collect_checkpoint_sites(func);
    for (entry_idx, ckpt_local) in ckpt_sites {
        let ckpt_bb = BlockId(entry_idx as u32);
        let rb_bb = find_rollback_block(func, ckpt_local);
        let Some(merge_bb) = find_atomic_merge_block_balanced(func, ckpt_bb, rb_bb) else {
            continue;
        };
        let tx_blocks = collect_non_rollback_tx_blocks(func, ckpt_bb, rb_bb, merge_bb);
        let cycle_blocks = collect_tx_cycle_blocks(func, &tx_blocks);
        for b in cycle_blocks {
            let has_row_mut = func.blocks[b.0 as usize]
                .stmts
                .iter()
                .any(|s| mutation_ptr(&s.inst).is_some_and(|p| row_derived.contains(&p)));
            if has_row_mut {
                return Err(format!(
                    "function `{}` mutates multiple query entities inside an `atomic` loop at block `{}`",
                    func.name, func.blocks[b.0 as usize].label
                ));
            }
        }
    }
    Ok(())
}

fn collect_checkpoint_sites(func: &MirFunction) -> Vec<(usize, LocalId)> {
    func.blocks
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
        .collect()
}

fn run_inner(func: &mut MirFunction, ctx: Option<&MirLowerCtx>) {
    let ckpt_sites = collect_checkpoint_sites(func);
    if ckpt_sites.is_empty() {
        return;
    }

    // Match every checkpoint to its exact balanced `atomic_merge` block and process structured
    // scopes innermost-to-outermost so inner rollbacks never read/clobber outer undo slots.
    let mut structured: Vec<(usize, BlockId, LocalId, Option<BlockId>, BlockId)> = Vec::new();
    let mut unstructured: Vec<(usize, LocalId)> = Vec::new();
    for (entry_idx, ckpt_local) in ckpt_sites {
        let ckpt_bb = BlockId(entry_idx as u32);
        let rollback_bb = find_rollback_block(func, ckpt_local);
        if let Some(merge_bb) = find_atomic_merge_block_balanced(func, ckpt_bb, rollback_bb) {
            let scope_len =
                collect_non_rollback_tx_blocks(func, ckpt_bb, rollback_bb, merge_bb).len();
            structured.push((scope_len, ckpt_bb, ckpt_local, rollback_bb, merge_bb));
        } else {
            unstructured.push((entry_idx, ckpt_local));
        }
    }

    structured.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.0.cmp(&a.1.0)));

    for (_, ckpt_bb, ckpt_local, rollback_bb, merge_bb) in structured {
        instrument_structured_atomic(func, ckpt_bb, ckpt_local, rollback_bb, merge_bb, ctx);
    }
    for (entry_idx, ckpt_local) in unstructured {
        split_unstructured_checkpoint(func, entry_idx, ckpt_local);
    }
}

fn find_atomic_merge_block_balanced(
    func: &MirFunction,
    start: BlockId,
    own_rollback: Option<BlockId>,
) -> Option<BlockId> {
    let mut visited: HashSet<BlockId> = HashSet::new();
    let mut q: VecDeque<(BlockId, usize)> = VecDeque::new();
    visited.insert(start);
    for succ in successors(&func.blocks[start.0 as usize].terminator) {
        if Some(succ) != own_rollback && visited.insert(succ) {
            q.push_back((succ, 0));
        }
    }
    while let Some((b, depth)) = q.pop_front() {
        let bb = &func.blocks[b.0 as usize];
        if bb.label == "atomic_merge" && b != start && depth == 0 {
            return Some(b);
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
        for succ in successors(&bb.terminator) {
            if Some(succ) != own_rollback && visited.insert(succ) {
                q.push_back((succ, next_depth));
            }
        }
    }
    if let Some(rb) = own_rollback
        && let Terminator::Goto(target) = func.blocks[rb.0 as usize].terminator
        && func
            .blocks
            .get(target.0 as usize)
            .is_some_and(|b| b.label == "atomic_merge")
    {
        return Some(target);
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

struct GuardBranch {
    saved_flag: LocalId,
    undo_slot: LocalId,
    save_bb: BlockId,
    store_bb: BlockId,
}

fn begin_guard_branch(
    func: &mut MirFunction,
    cur_bb: BlockId,
    ckpt_setup_stmts: &mut Vec<MirStmt>,
    undo_slot_ty: &MirType,
    site_idx: usize,
) -> GuardBranch {
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
            ty: undo_slot_ty.clone(),
        },
    });
    emit_typed_zero_init(func, ckpt_setup_stmts, undo_slot, undo_slot_ty, site_idx);

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
    func.blocks[cur_bb.0 as usize].terminator = Terminator::Branch {
        cond: not_saved,
        then_bb: save_bb,
        else_bb: store_bb,
    };

    GuardBranch {
        saved_flag,
        undo_slot,
        save_bb,
        store_bb,
    }
}

fn alloc_zero_u32_slot(
    func: &mut MirFunction,
    ckpt_setup_stmts: &mut Vec<MirStmt>,
    name: String,
    site_idx: usize,
) -> LocalId {
    let slot = func.alloc_local(name, MirType::MutPtr);
    ckpt_setup_stmts.push(MirStmt {
        dst: Some(slot),
        inst: Inst::SlotAlloc { ty: MirType::U32 },
    });
    emit_typed_zero_init(func, ckpt_setup_stmts, slot, &MirType::U32, site_idx);
    slot
}

fn finish_save_mark(
    func: &mut MirFunction,
    save_bb: BlockId,
    saved_flag: LocalId,
    store_bb: BlockId,
    site_idx: usize,
) {
    let t_bool = func.alloc_local(format!("tx_t_{site_idx}"), MirType::Bool);
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
}

fn collect_field_ptr_origins(func: &MirFunction) -> HashMap<LocalId, FieldPtrOrigin> {
    let mut origins: HashMap<LocalId, FieldPtrOrigin> = HashMap::new();
    let mut slot_origins: HashMap<LocalId, Option<FieldPtrOrigin>> = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for bb in &func.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::FieldPtr {
                        base_ptr,
                        layout_key,
                        field,
                        offset_bytes,
                    } => {
                        if let Some(dst) = s.dst
                            && !origins.contains_key(&dst)
                        {
                            origins.insert(
                                dst,
                                FieldPtrOrigin {
                                    base_ptr: *base_ptr,
                                    layout_key: layout_key.clone(),
                                    field: field.clone(),
                                    offset_bytes: *offset_bytes,
                                },
                            );
                            changed = true;
                        }
                    }
                    Inst::Copy { val } => {
                        if let Some(dst) = s.dst
                            && !origins.contains_key(&dst)
                            && let Some(orig) = origins.get(val).cloned()
                        {
                            origins.insert(dst, orig);
                            changed = true;
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(orig) = origins.get(val).cloned() {
                            match slot_origins.get(slot) {
                                None => {
                                    slot_origins.insert(*slot, Some(orig));
                                    changed = true;
                                }
                                Some(Some(prev))
                                    if prev.base_ptr != orig.base_ptr
                                        || prev.offset_bytes != orig.offset_bytes =>
                                {
                                    slot_origins.insert(*slot, None);
                                    changed = true;
                                }
                                _ => {}
                            }
                        } else if !matches!(slot_origins.get(slot), Some(None))
                            && slot_origins.contains_key(slot)
                        {
                            slot_origins.insert(*slot, None);
                            changed = true;
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(dst) = s.dst
                            && !origins.contains_key(&dst)
                            && let Some(Some(orig)) = slot_origins.get(slot)
                        {
                            origins.insert(dst, orig.clone());
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    origins
}

fn find_matching_array_field_ty(
    func: &MirFunction,
    layout_key: &str,
    field: &str,
) -> Option<MirType> {
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::FieldLoad {
                layout_key: lk,
                field: fl,
                field_ty,
                ..
            } = &s.inst
                && lk == layout_key
                && fl == field
                && matches!(field_ty, MirType::Array { .. })
            {
                return Some(field_ty.clone());
            }
        }
    }
    None
}

fn grace_pre_load_inst(ptr: LocalId, origins: &HashMap<LocalId, FieldPtrOrigin>) -> Inst {
    if let Some(orig) = origins.get(&ptr) {
        Inst::FieldLoad {
            base_ptr: orig.base_ptr,
            layout_key: orig.layout_key.clone(),
            field: orig.field.clone(),
            offset_bytes: orig.offset_bytes,
            field_ty: MirType::F32,
        }
    } else {
        Inst::FieldLoad {
            base_ptr: ptr,
            layout_key: String::new(),
            field: String::new(),
            offset_bytes: 0,
            field_ty: MirType::F32,
        }
    }
}

fn is_atomic_internal_block_label(label: &str) -> bool {
    matches!(
        label,
        "tx_undo_field" | "tx_undo_chk" | "tx_undo_next" | "tx_save_pre" | "atomic_commit"
    )
}

fn mutation_ptr(inst: &Inst) -> Option<LocalId> {
    match inst {
        Inst::FieldStore { base_ptr, .. } | Inst::ArrayStore { base_ptr, .. } => Some(*base_ptr),
        Inst::BitSetSet { ptr, .. }
        | Inst::BitSetClear { ptr, .. }
        | Inst::GraceArm { ptr, .. }
        | Inst::GraceClear { ptr }
        | Inst::GraceTick { ptr, .. }
        | Inst::InputBufPush { ptr, .. }
        | Inst::InputBufConsume { ptr, .. }
        | Inst::InputBufTick { ptr, .. } => Some(*ptr),
        _ => None,
    }
}

fn collect_row_derived_locals(func: &MirFunction) -> HashSet<LocalId> {
    let mut row_derived: HashSet<LocalId> = HashSet::new();
    let mut slot_row_derived: HashMap<LocalId, bool> = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for bb in &func.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::RowPtr { .. } => {
                        if let Some(d) = s.dst
                            && row_derived.insert(d)
                        {
                            changed = true;
                        }
                    }
                    Inst::Copy { val }
                    | Inst::FieldPtr { base_ptr: val, .. }
                    | Inst::ArrayIndex { base: val, .. } => {
                        if row_derived.contains(val)
                            && let Some(d) = s.dst
                            && row_derived.insert(d)
                        {
                            changed = true;
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if row_derived.contains(val)
                            && !slot_row_derived.get(slot).copied().unwrap_or(false)
                        {
                            slot_row_derived.insert(*slot, true);
                            changed = true;
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if slot_row_derived.get(slot).copied().unwrap_or(false)
                            && let Some(d) = s.dst
                            && row_derived.insert(d)
                        {
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    row_derived
}

fn collect_tx_cycle_blocks(func: &MirFunction, tx_blocks: &[BlockId]) -> HashSet<BlockId> {
    let tx_set: HashSet<BlockId> = tx_blocks.iter().copied().collect();
    let mut in_cycle = HashSet::new();
    for &b in tx_blocks {
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        for succ in successors(&func.blocks[b.0 as usize].terminator) {
            if tx_set.contains(&succ) && seen.insert(succ) {
                q.push_back(succ);
            }
        }
        while let Some(cur) = q.pop_front() {
            if cur == b {
                in_cycle.insert(b);
                break;
            }
            for succ in successors(&func.blocks[cur.0 as usize].terminator) {
                if tx_set.contains(&succ) && seen.insert(succ) {
                    q.push_back(succ);
                }
            }
        }
    }
    in_cycle
}

fn instrument_structured_atomic(
    func: &mut MirFunction,
    ckpt_bb: BlockId,
    ckpt_local: LocalId,
    own_rollback_bb: Option<BlockId>,
    merge_bb: BlockId,
    ctx: Option<&MirLowerCtx>,
) {
    let tx_blocks = collect_non_rollback_tx_blocks(func, ckpt_bb, own_rollback_bb, merge_bb);
    let own_rb_blocks = collect_rollback_blocks(func, own_rollback_bb, merge_bb);
    let row_derived = collect_row_derived_locals(func);
    let cycle_blocks = collect_tx_cycle_blocks(func, &tx_blocks);
    let field_ptr_origins = collect_field_ptr_origins(func);

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
        if is_atomic_internal_block_label(&func.blocks[b.0 as usize].label) {
            continue;
        }
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

    // 2. Instrument `FieldStore`, `ArrayStore`, `BitSetSet`/`BitSetClear`, and
    //    `GraceArm`/`GraceClear` inside `tx_blocks` with guarded first-write pre-image capture.
    //    Skip inner undo-restore blocks and multi-entity `RowPtr` loop stores (`GF-09`).
    let mut all_tx_blocks = tx_blocks.clone();
    for &b in &tx_blocks {
        if is_atomic_internal_block_label(&func.blocks[b.0 as usize].label) {
            continue;
        }
        let is_cyclic_blk = cycle_blocks.contains(&b);
        let has_tracked_mut = func.blocks[b.0 as usize].stmts.iter().any(|s| {
            matches!(
                s.inst,
                Inst::FieldStore { .. }
                    | Inst::ArrayStore { .. }
                    | Inst::BitSetSet { .. }
                    | Inst::BitSetClear { .. }
                    | Inst::GraceArm { .. }
                    | Inst::GraceClear { .. }
            ) && !(is_cyclic_blk && mutation_ptr(&s.inst).is_some_and(|p| row_derived.contains(&p)))
        });
        if !has_tracked_mut {
            continue;
        }

        let old_stmts = std::mem::take(&mut func.blocks[b.0 as usize].stmts);
        let orig_term = func.blocks[b.0 as usize].terminator.clone();
        let mut cur_bb = b;

        for s in old_stmts {
            let skip_cyclic =
                is_cyclic_blk && mutation_ptr(&s.inst).is_some_and(|p| row_derived.contains(&p));
            if skip_cyclic {
                func.blocks[cur_bb.0 as usize].stmts.push(s);
                continue;
            }
            match &s.inst {
                Inst::FieldStore {
                    base_ptr,
                    layout_key,
                    field,
                    offset_bytes,
                    val,
                } => {
                    let base_ptr = *base_ptr;
                    let layout_key = layout_key.clone();
                    let field = field.clone();
                    let offset_bytes = *offset_bytes;
                    let val = *val;
                    let field_ty = ctx
                        .and_then(|c| c.resolve_field_opt(&layout_key, &field))
                        .unwrap_or_else(|| func.locals[val.0 as usize].ty.clone());
                    let site_idx = undo_ops.len();
                    let g = begin_guard_branch(
                        func,
                        cur_bb,
                        &mut ckpt_setup_stmts,
                        &field_ty,
                        site_idx,
                    );
                    all_tx_blocks.push(g.store_bb);

                    let old_val = func.alloc_local(format!("tx_pre_{site_idx}"), field_ty.clone());
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_val),
                        inst: Inst::FieldLoad {
                            base_ptr,
                            layout_key: layout_key.clone(),
                            field: field.clone(),
                            offset_bytes,
                            field_ty: field_ty.clone(),
                        },
                    });
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: g.undo_slot,
                            val: old_val,
                        },
                    });
                    finish_save_mark(func, g.save_bb, g.saved_flag, g.store_bb, site_idx);

                    let target_name = if layout_key.is_empty() {
                        field.clone()
                    } else {
                        format!("{layout_key}.{field}")
                    };
                    func.blocks[g.store_bb.0 as usize].stmts.push(s);
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: target_name.clone(),
                            shadow_slot: g.undo_slot,
                            val,
                        },
                    });

                    undo_ops.push(UndoOp::Field {
                        saved_flag: g.saved_flag,
                        undo_slot: g.undo_slot,
                        base_ptr,
                        layout_key,
                        field,
                        offset_bytes,
                        field_ty,
                    });
                    shadows.push((target_name, g.undo_slot));
                    cur_bb = g.store_bb;
                }
                Inst::ArrayStore {
                    base_ptr,
                    index,
                    val,
                    elem_ty,
                } => {
                    let base_ptr = *base_ptr;
                    let index = *index;
                    let val = *val;
                    let elem_ty = elem_ty.clone();
                    let origin = field_ptr_origins.get(&base_ptr).cloned();
                    let arr_ty_opt = if let Some(ref orig) = origin {
                        ctx.and_then(|c| c.resolve_field_opt(&orig.layout_key, &orig.field))
                            .or_else(|| {
                                find_matching_array_field_ty(func, &orig.layout_key, &orig.field)
                            })
                    } else if let Some(sty @ MirType::Array { .. }) = slot_types.get(&base_ptr) {
                        Some(sty.clone())
                    } else {
                        None
                    };
                    let Some(arr_ty) = arr_ty_opt else {
                        func.blocks[cur_bb.0 as usize].stmts.push(s);
                        continue;
                    };
                    let arr_len = match &arr_ty {
                        MirType::Array { len, .. } => *len,
                        _ => 0,
                    };
                    let site_idx = undo_ops.len();
                    let saved_idx_slot = alloc_zero_u32_slot(
                        func,
                        &mut ckpt_setup_stmts,
                        format!("tx_arr_idx_{site_idx}"),
                        site_idx,
                    );
                    let g =
                        begin_guard_branch(func, cur_bb, &mut ckpt_setup_stmts, &elem_ty, site_idx);
                    all_tx_blocks.push(g.store_bb);

                    let idx_u32 = if func.locals[index.0 as usize].ty == MirType::U32 {
                        index
                    } else {
                        let casted =
                            func.alloc_local(format!("tx_arr_iu32_{site_idx}"), MirType::U32);
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(casted),
                            inst: Inst::Cast {
                                val: index,
                                target_ty: MirType::U32,
                            },
                        });
                        casted
                    };
                    let cap_bb = if arr_len > 0 {
                        let len_l =
                            func.alloc_local(format!("tx_arr_len_{site_idx}"), MirType::U32);
                        let in_b =
                            func.alloc_local(format!("tx_arr_inb_{site_idx}"), MirType::Bool);
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(len_l),
                            inst: Inst::ConstInt {
                                value: arr_len as i64,
                            },
                        });
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(in_b),
                            inst: Inst::BinOp {
                                op: "<".to_owned(),
                                lhs: idx_u32,
                                rhs: len_l,
                                allow_fma: false,
                            },
                        });
                        let cb = func.alloc_block("tx_save_arr", Terminator::Return(None));
                        func.blocks[g.save_bb.0 as usize].terminator = Terminator::Branch {
                            cond: in_b,
                            then_bb: cb,
                            else_bb: g.store_bb,
                        };
                        cb
                    } else {
                        g.save_bb
                    };

                    let arr_val =
                        func.alloc_local(format!("tx_arr_val_{site_idx}"), arr_ty.clone());
                    if let Some(ref orig) = origin {
                        func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(arr_val),
                            inst: Inst::FieldLoad {
                                base_ptr: orig.base_ptr,
                                layout_key: orig.layout_key.clone(),
                                field: orig.field.clone(),
                                offset_bytes: orig.offset_bytes,
                                field_ty: arr_ty,
                            },
                        });
                    } else {
                        func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(arr_val),
                            inst: Inst::SlotLoad { slot: base_ptr },
                        });
                    }
                    let old_elem =
                        func.alloc_local(format!("tx_arr_pre_{site_idx}"), elem_ty.clone());
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_elem),
                        inst: Inst::ArrayIndex {
                            base: arr_val,
                            index: idx_u32,
                        },
                    });
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: saved_idx_slot,
                            val: idx_u32,
                        },
                    });
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: g.undo_slot,
                            val: old_elem,
                        },
                    });
                    finish_save_mark(func, cap_bb, g.saved_flag, g.store_bb, site_idx);

                    let target_name = origin.as_ref().map_or_else(
                        || "array".to_owned(),
                        |o| format!("{}.{}", o.layout_key, o.field),
                    );
                    func.blocks[g.store_bb.0 as usize].stmts.push(s);
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: target_name.clone(),
                            shadow_slot: g.undo_slot,
                            val,
                        },
                    });

                    undo_ops.push(UndoOp::Array {
                        saved_flag: g.saved_flag,
                        saved_idx_slot,
                        undo_slot: g.undo_slot,
                        base_ptr,
                        elem_ty,
                    });
                    shadows.push((target_name, g.undo_slot));
                    cur_bb = g.store_bb;
                }
                Inst::BitSetSet { ptr, words, bit } | Inst::BitSetClear { ptr, words, bit } => {
                    let is_set = matches!(s.inst, Inst::BitSetSet { .. });
                    let ptr = *ptr;
                    let words = *words;
                    let bit = *bit;
                    let site_idx = undo_ops.len();
                    let saved_bit_slot = alloc_zero_u32_slot(
                        func,
                        &mut ckpt_setup_stmts,
                        format!("tx_bs_bit_{site_idx}"),
                        site_idx,
                    );
                    let g = begin_guard_branch(
                        func,
                        cur_bb,
                        &mut ckpt_setup_stmts,
                        &MirType::Bool,
                        site_idx,
                    );
                    all_tx_blocks.push(g.store_bb);

                    let bit_u32 = if func.locals[bit.0 as usize].ty == MirType::U32 {
                        bit
                    } else {
                        let casted =
                            func.alloc_local(format!("tx_bs_bu32_{site_idx}"), MirType::U32);
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(casted),
                            inst: Inst::Cast {
                                val: bit,
                                target_ty: MirType::U32,
                            },
                        });
                        casted
                    };
                    let total_bits = words.saturating_mul(32);
                    let cap_bb = if total_bits > 0 {
                        let max_l = func.alloc_local(format!("tx_bs_max_{site_idx}"), MirType::U32);
                        let in_b = func.alloc_local(format!("tx_bs_inb_{site_idx}"), MirType::Bool);
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(max_l),
                            inst: Inst::ConstInt {
                                value: total_bits as i64,
                            },
                        });
                        func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                            dst: Some(in_b),
                            inst: Inst::BinOp {
                                op: "<".to_owned(),
                                lhs: bit_u32,
                                rhs: max_l,
                                allow_fma: false,
                            },
                        });
                        let cb = func.alloc_block("tx_save_bit", Terminator::Return(None));
                        func.blocks[g.save_bb.0 as usize].terminator = Terminator::Branch {
                            cond: in_b,
                            then_bb: cb,
                            else_bb: g.store_bb,
                        };
                        cb
                    } else {
                        g.save_bb
                    };

                    let pre_bit = func.alloc_local(format!("tx_bs_pre_{site_idx}"), MirType::Bool);
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(pre_bit),
                        inst: Inst::BitSetGet {
                            ptr,
                            words,
                            bit: bit_u32,
                        },
                    });
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: saved_bit_slot,
                            val: bit_u32,
                        },
                    });
                    func.blocks[cap_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: g.undo_slot,
                            val: pre_bit,
                        },
                    });
                    finish_save_mark(func, cap_bb, g.saved_flag, g.store_bb, site_idx);

                    let shadow_val =
                        func.alloc_local(format!("tx_bs_nv_{site_idx}"), MirType::Bool);
                    func.blocks[g.store_bb.0 as usize].stmts.push(s);
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(shadow_val),
                        inst: Inst::ConstBool { value: is_set },
                    });
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: "bitset".to_owned(),
                            shadow_slot: g.undo_slot,
                            val: shadow_val,
                        },
                    });

                    undo_ops.push(UndoOp::BitSet {
                        saved_flag: g.saved_flag,
                        saved_bit_slot,
                        undo_slot: g.undo_slot,
                        ptr,
                        words,
                    });
                    shadows.push(("bitset".to_owned(), g.undo_slot));
                    cur_bb = g.store_bb;
                }
                Inst::GraceArm { ptr, duration_sec } => {
                    let ptr = *ptr;
                    let duration_sec = *duration_sec;
                    let site_idx = undo_ops.len();
                    let g = begin_guard_branch(
                        func,
                        cur_bb,
                        &mut ckpt_setup_stmts,
                        &MirType::F32,
                        site_idx,
                    );
                    all_tx_blocks.push(g.store_bb);

                    let old_rem =
                        func.alloc_local(format!("tx_grace_pre_{site_idx}"), MirType::F32);
                    let load_inst = grace_pre_load_inst(ptr, &field_ptr_origins);
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_rem),
                        inst: load_inst,
                    });
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: g.undo_slot,
                            val: old_rem,
                        },
                    });
                    finish_save_mark(func, g.save_bb, g.saved_flag, g.store_bb, site_idx);

                    func.blocks[g.store_bb.0 as usize].stmts.push(s);
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: "grace".to_owned(),
                            shadow_slot: g.undo_slot,
                            val: duration_sec,
                        },
                    });

                    undo_ops.push(UndoOp::Grace {
                        saved_flag: g.saved_flag,
                        undo_slot: g.undo_slot,
                        ptr,
                    });
                    shadows.push(("grace".to_owned(), g.undo_slot));
                    cur_bb = g.store_bb;
                }
                Inst::GraceClear { ptr } => {
                    let ptr = *ptr;
                    let site_idx = undo_ops.len();
                    let g = begin_guard_branch(
                        func,
                        cur_bb,
                        &mut ckpt_setup_stmts,
                        &MirType::F32,
                        site_idx,
                    );
                    all_tx_blocks.push(g.store_bb);

                    let old_rem =
                        func.alloc_local(format!("tx_grace_pre_{site_idx}"), MirType::F32);
                    let load_inst = grace_pre_load_inst(ptr, &field_ptr_origins);
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_rem),
                        inst: load_inst,
                    });
                    func.blocks[g.save_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::SlotStore {
                            slot: g.undo_slot,
                            val: old_rem,
                        },
                    });
                    finish_save_mark(func, g.save_bb, g.saved_flag, g.store_bb, site_idx);

                    let z_f = func.alloc_local(format!("tx_grace_zf_{site_idx}"), MirType::F32);
                    func.blocks[g.store_bb.0 as usize].stmts.push(s);
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(z_f),
                        inst: Inst::ConstFloat { value: 0.0 },
                    });
                    func.blocks[g.store_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ShadowWrite {
                            target_name: "grace".to_owned(),
                            shadow_slot: g.undo_slot,
                            val: z_f,
                        },
                    });

                    undo_ops.push(UndoOp::Grace {
                        saved_flag: g.saved_flag,
                        undo_slot: g.undo_slot,
                        ptr,
                    });
                    shadows.push(("grace".to_owned(), g.undo_slot));
                    cur_bb = g.store_bb;
                }
                _ => {
                    func.blocks[cur_bb.0 as usize].stmts.push(s);
                }
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
        && let Some(rollback_bb) = own_rollback_bb
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
                UndoOp::Array {
                    saved_flag,
                    saved_idx_slot,
                    undo_slot,
                    base_ptr,
                    elem_ty,
                } => {
                    let was_saved = func.alloc_local(format!("tx_rb_achk_{ri}"), MirType::Bool);
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

                    let idx_val = func.alloc_local(format!("tx_rb_aidx_{ri}"), MirType::U32);
                    let old_val = func.alloc_local(format!("tx_rb_aelem_{ri}"), elem_ty.clone());
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(idx_val),
                        inst: Inst::SlotLoad {
                            slot: saved_idx_slot,
                        },
                    });
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_val),
                        inst: Inst::SlotLoad { slot: undo_slot },
                    });
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::ArrayStore {
                            base_ptr,
                            index: idx_val,
                            val: old_val,
                            elem_ty,
                        },
                    });
                    func.blocks[restore_bb.0 as usize].terminator = Terminator::Goto(next_rb_bb);
                    cur_rb = next_rb_bb;
                }
                UndoOp::BitSet {
                    saved_flag,
                    saved_bit_slot,
                    undo_slot,
                    ptr,
                    words,
                } => {
                    let was_saved = func.alloc_local(format!("tx_rb_bchk_{ri}"), MirType::Bool);
                    func.blocks[cur_rb.0 as usize].stmts.push(MirStmt {
                        dst: Some(was_saved),
                        inst: Inst::SlotLoad { slot: saved_flag },
                    });
                    let chk_bb = func.alloc_block("tx_undo_chk", Terminator::Return(None));
                    let next_rb_bb = func.alloc_block("tx_undo_next", Terminator::Return(None));
                    func.blocks[cur_rb.0 as usize].terminator = Terminator::Branch {
                        cond: was_saved,
                        then_bb: chk_bb,
                        else_bb: next_rb_bb,
                    };

                    let pre_bit = func.alloc_local(format!("tx_rb_bpre_{ri}"), MirType::Bool);
                    let bit_val = func.alloc_local(format!("tx_rb_bit_{ri}"), MirType::U32);
                    func.blocks[chk_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(pre_bit),
                        inst: Inst::SlotLoad { slot: undo_slot },
                    });
                    func.blocks[chk_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(bit_val),
                        inst: Inst::SlotLoad {
                            slot: saved_bit_slot,
                        },
                    });
                    let set_bb = func.alloc_block("tx_undo_field", Terminator::Goto(next_rb_bb));
                    let clr_bb = func.alloc_block("tx_undo_field", Terminator::Goto(next_rb_bb));
                    func.blocks[set_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::BitSetSet {
                            ptr,
                            words,
                            bit: bit_val,
                        },
                    });
                    func.blocks[clr_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::BitSetClear {
                            ptr,
                            words,
                            bit: bit_val,
                        },
                    });
                    func.blocks[chk_bb.0 as usize].terminator = Terminator::Branch {
                        cond: pre_bit,
                        then_bb: set_bb,
                        else_bb: clr_bb,
                    };
                    cur_rb = next_rb_bb;
                }
                UndoOp::Grace {
                    saved_flag,
                    undo_slot,
                    ptr,
                } => {
                    let was_saved = func.alloc_local(format!("tx_rb_gchk_{ri}"), MirType::Bool);
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

                    let old_rem = func.alloc_local(format!("tx_rb_grace_{ri}"), MirType::F32);
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: Some(old_rem),
                        inst: Inst::SlotLoad { slot: undo_slot },
                    });
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::GraceClear { ptr },
                    });
                    func.blocks[restore_bb.0 as usize].stmts.push(MirStmt {
                        dst: None,
                        inst: Inst::GraceArm {
                            ptr,
                            duration_sec: old_rem,
                        },
                    });
                    func.blocks[restore_bb.0 as usize].terminator = Terminator::Goto(next_rb_bb);
                    cur_rb = next_rb_bb;
                }
            }
        }
        if !on_rollback_stmts.is_empty()
            && func.blocks[cur_rb.0 as usize].label != "atomic_rollback"
        {
            let on_rb_bb = func.alloc_block("atomic_on_rollback", orig_rb_term);
            func.blocks[on_rb_bb.0 as usize].stmts = on_rollback_stmts.to_vec();
            func.blocks[cur_rb.0 as usize].terminator = Terminator::Goto(on_rb_bb);
        } else {
            func.blocks[cur_rb.0 as usize]
                .stmts
                .extend(on_rollback_stmts.iter().cloned());
            func.blocks[cur_rb.0 as usize].terminator = orig_rb_term;
        }
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
        if own_rb_blocks.contains(&b) {
            continue;
        }
        let bb = &mut func.blocks[b.0 as usize];
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

fn collect_rollback_blocks(
    func: &MirFunction,
    own_rollback_bb: Option<BlockId>,
    merge_bb: BlockId,
) -> HashSet<BlockId> {
    let mut rb_blocks = HashSet::new();
    let Some(rb) = own_rollback_bb else {
        return rb_blocks;
    };
    let mut q = VecDeque::new();
    if rb != merge_bb && rb_blocks.insert(rb) {
        q.push_back(rb);
    }
    while let Some(b) = q.pop_front() {
        for s in successors(&func.blocks[b.0 as usize].terminator) {
            if s != merge_bb && rb_blocks.insert(s) {
                q.push_back(s);
            }
        }
    }
    rb_blocks
}

fn collect_non_rollback_tx_blocks(
    func: &MirFunction,
    ckpt_bb: BlockId,
    own_rollback_bb: Option<BlockId>,
    merge_bb: BlockId,
) -> Vec<BlockId> {
    let own_rb = collect_rollback_blocks(func, own_rollback_bb, merge_bb);
    let mut visited = HashSet::new();
    let mut out = Vec::new();
    let mut q = VecDeque::new();
    visited.insert(ckpt_bb);
    for s in successors(&func.blocks[ckpt_bb.0 as usize].terminator) {
        if s != merge_bb && !own_rb.contains(&s) && visited.insert(s) {
            q.push_back(s);
        }
    }
    while let Some(b) = q.pop_front() {
        if b == merge_bb || own_rb.contains(&b) {
            continue;
        }
        out.push(b);
        for s in successors(&func.blocks[b.0 as usize].terminator) {
            if s != merge_bb && !own_rb.contains(&s) && visited.insert(s) {
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

    fn lower_ok(src: &str) -> crate::MirModule {
        let sema = strata_sema::analyze_source("atomic_test.strata", src);
        let errs: Vec<_> = sema
            .diagnostics
            .iter()
            .filter(|d| matches!(d.severity, strata_sema::Severity::Error))
            .collect();
        assert!(errs.is_empty(), "sema errors: {errs:?}");
        let mir = crate::lower_to_mir(&sema);
        crate::verify::verify_mir(&mir).expect("MIR should verify cleanly");
        mir
    }

    /// GF-07: Rollback snapshots and restores `ArrayStore`, `BitSetSet`, and `GraceArm` inside
    /// `"tx_undo_field"` blocks cleanly.
    #[test]
    fn atomic_tx_snapshots_and_restores_array_bitset_and_grace() {
        let src = r#"
resource Vault {
    scores: [i32; 4] = [10, 20, 30, 40],
    flags: BitSet<64> = BitSet<64>(),
    coyote: GraceWindow = GraceWindow(),
}

sys tx_primitives(v: &mut res Vault) {
    atomic {
        v.scores[0] = 999;
        v.flags.set(5);
        v.coyote.arm(5.0_s);
        require_true(false);
    }
}
"#;
        let mir = lower_ok(src);
        let f = mir
            .functions
            .iter()
            .find(|f| f.name == "tx_primitives")
            .unwrap();
        let has_pre_arr = f.blocks.iter().any(|b| {
            b.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::ArrayIndex { .. }))
        });
        let has_pre_bit = f.blocks.iter().any(|b| {
            b.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::BitSetGet { .. }))
        });
        assert!(has_pre_arr, "expected ArrayIndex pre-image capture");
        assert!(has_pre_bit, "expected BitSetGet pre-image capture");

        let undo_blocks: Vec<_> = f
            .blocks
            .iter()
            .filter(|b| b.label == "tx_undo_field")
            .collect();
        assert!(
            undo_blocks.iter().any(|b| b
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::ArrayStore { .. }))),
            "expected ArrayStore restore in tx_undo_field"
        );
        assert!(
            undo_blocks.iter().any(|b| b
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::BitSetSet { .. }))),
            "expected BitSetSet restore in tx_undo_field"
        );
        assert!(
            undo_blocks.iter().any(|b| b
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::BitSetClear { .. }))),
            "expected BitSetClear restore in tx_undo_field"
        );
        assert!(
            undo_blocks.iter().any(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::GraceClear { .. }))
                    && b.stmts
                        .iter()
                        .any(|s| matches!(s.inst, Inst::GraceArm { .. }))
            }),
            "expected GraceClear followed by GraceArm restore in tx_undo_field"
        );
    }

    /// GF-08 (nested `atomic` checkpoint stack): Inner rollback restores ONLY inner pre-image and
    /// preserves outer committed writes without merging into outer checkpoint/merge.
    #[test]
    fn nested_atomic_rollback_preserves_outer_tx_state() {
        let src = r#"
resource Bank { gold: i32 = 100 }

sys nested_tx(b: &mut res Bank) {
    let mut local_gold: i32 = 100;
    atomic {
        b.gold += 10;
        local_gold += 10;
        atomic {
            b.gold += 20;
            local_gold += 20;
            require_true(false);
        }
        b.gold += 5;
        local_gold += 5;
        require_true(true);
    }
}
"#;
        let mir = lower_ok(src);
        let f = mir
            .functions
            .iter()
            .find(|f| f.name == "nested_tx")
            .unwrap();
        let merge_count = f
            .blocks
            .iter()
            .filter(|b| b.label == "atomic_merge")
            .count();
        let commit_count = f
            .blocks
            .iter()
            .filter(|b| b.label == "atomic_commit")
            .count();
        assert_eq!(merge_count, 2);
        assert_eq!(commit_count, 2);

        // Two distinct rollback chains: inner rollback chain must only check/restore inner writes
        // (`saved_flag` allocated inside inner's ckpt_bb), never outer's `tx_saved` or `tx_undo`.
        let rbs: Vec<BlockId> = f
            .blocks
            .iter()
            .filter(|b| b.label == "atomic_rollback")
            .map(|b| b.id)
            .collect();
        assert_eq!(rbs.len(), 2);

        // Collect all locals defined in each `atomic_rollback`'s corresponding checkpoint block
        // (`CmdCheckpoint` block) and verify its rollback chain only reads those undo slots.
        let rb_to_ckpt: std::collections::HashMap<LocalId, BlockId> = f
            .blocks
            .iter()
            .flat_map(|b| {
                b.stmts.iter().filter_map(move |s| {
                    matches!(s.inst, Inst::CmdCheckpoint)
                        .then_some(s.dst.map(|d| (d, b.id)))
                        .flatten()
                })
            })
            .collect();
        for rb_id in rbs {
            let ckpt_local = f.blocks[rb_id.0 as usize]
                .stmts
                .iter()
                .find_map(|s| match s.inst {
                    Inst::CmdRollback { checkpoint } => Some(checkpoint),
                    _ => None,
                })
                .expect("atomic_rollback must hold CmdRollback");
            let ckpt_bb = rb_to_ckpt[&ckpt_local];
            let own_ckpt_defs: std::collections::HashSet<LocalId> = f.blocks[ckpt_bb.0 as usize]
                .stmts
                .iter()
                .filter_map(|s| s.dst)
                .collect();
            let mut chain = Vec::new();
            let mut q = std::collections::VecDeque::from([rb_id]);
            let mut seen = std::collections::HashSet::from([rb_id]);
            while let Some(b) = q.pop_front() {
                if f.blocks[b.0 as usize].label == "atomic_merge" {
                    continue;
                }
                chain.push(b);
                for s in super::successors(&f.blocks[b.0 as usize].terminator) {
                    if f.blocks[s.0 as usize].label != "atomic_merge" && seen.insert(s) {
                        q.push_back(s);
                    }
                }
            }
            let slot_restores: usize = chain
                .iter()
                .map(|b| {
                    f.blocks[b.0 as usize]
                        .stmts
                        .iter()
                        .filter(|s| matches!(s.inst, Inst::SlotStore { .. }))
                        .count()
                })
                .sum();
            assert_eq!(
                slot_restores, 1,
                "rollback chain starting at {:?} should restore local_gold once",
                rb_id
            );
            for b in chain {
                for st in &f.blocks[b.0 as usize].stmts {
                    if let Inst::SlotLoad { slot } = st.inst {
                        assert!(
                            own_ckpt_defs.contains(&slot),
                            "rollback {:?} referenced foreign undo/saved slot {:?} outside its own checkpoint {:?}",
                            rb_id,
                            slot,
                            ckpt_bb
                        );
                    }
                }
            }
        }
        // `validate_no_multi_entity_loops` passes on nested single-entity `atomic`.
        assert!(super::validate_no_multi_entity_loops(f).is_ok());
    }

    /// GF-09: Reject multi-entity `atomic` query loops cleanly while allowing valid single-entity
    /// `atomic` inside query loops and read-only query loops inside `atomic`.
    #[test]
    fn multi_entity_atomic_query_loop_rejected_and_single_entity_allowed() {
        let bad_src = r#"
component Vault { gold: i32 = 100 }

sys bad_multi_entity() {
    atomic {
        for row in query(v: &mut Vault) {
            row.v.gold += 50;
        }
        require_true(false);
    }
}
"#;
        let bad_sema = strata_sema::analyze_source("bad_tx.strata", bad_src);
        let bad_mir = crate::lower_to_mir(&bad_sema);
        let bad_f = bad_mir
            .functions
            .iter()
            .find(|f| f.name == "bad_multi_entity")
            .unwrap();
        assert!(
            super::validate_no_multi_entity_loops(bad_f).is_err(),
            "expected multi-entity atomic query loop to be rejected"
        );
        assert!(
            crate::verify::verify_mir(&bad_mir).is_err(),
            "expected verify_mir to reject multi-entity atomic loop"
        );
        assert!(
            !bad_f.blocks.iter().any(|b| b.label == "tx_undo_field"),
            "multi-entity loop must not synthesize broken out-of-scope tx_undo_field"
        );

        let good_src = r#"
component Vault { gold: i32 = 100 }
component Tag { bonus: i32 = 5 }
resource Summary { total: i32 = 0 }

sys valid_single_entity(s: &mut res Summary) {
    for row in query(v: &mut Vault) {
        atomic {
            row.v.gold += 50;
            require_true(row.v.gold < 1000);
        }
    }
    atomic {
        let mut acc: i32 = 0;
        for ro in query(t: &Tag) {
            acc += ro.t.bonus;
        }
        s.total += acc;
        require_true(true);
    }
}
"#;
        let good_mir = lower_ok(good_src);
        let good_f = good_mir
            .functions
            .iter()
            .find(|f| f.name == "valid_single_entity")
            .unwrap();
        assert!(super::validate_no_multi_entity_loops(good_f).is_ok());
    }
}
