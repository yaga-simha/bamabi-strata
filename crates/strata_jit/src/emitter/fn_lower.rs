//! Function/callback lowering, strength reduction, `FnLowerer` core state, and Cranelift IR helpers.

use super::*;

pub(super) fn helper_uses_out_ptr(ret_ty: &MirType) -> bool {
    matches!(ret_ty, MirType::Vec3 | MirType::Vec4 | MirType::IVec3)
}

pub(super) fn build_helper_signature(
    hfn: &MirFunction,
    ptr_ty: Type,
    cc: CallConv,
    enums_by_name: &HashMap<String, EnumDef>,
) -> Signature {
    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // state_ptr
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    if helper_uses_out_ptr(&hfn.ret_ty) {
        sig.params.push(AbiParam::new(ptr_ty)); // sret out_ptr for 3/4-lane vecs
    }
    for p in &hfn.params {
        push_abi_params_for_mir_type(&mut sig.params, &p.ty, ptr_ty, enums_by_name);
    }
    if !helper_uses_out_ptr(&hfn.ret_ty) {
        push_abi_params_for_mir_type(&mut sig.returns, &hfn.ret_ty, ptr_ty, enums_by_name);
    }
    sig
}

pub(super) fn push_abi_params_for_mir_type(
    out: &mut Vec<AbiParam>,
    ty: &MirType,
    ptr_ty: Type,
    enums_by_name: &HashMap<String, EnumDef>,
) {
    match ty {
        MirType::Unit => {}
        MirType::Vec2 => {
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
        }
        MirType::Vec3 => {
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
        }
        MirType::Vec4 => {
            for _ in 0..4 {
                out.push(AbiParam::new(types::F32));
            }
        }
        MirType::IVec2 | MirType::UVec2 => {
            out.push(AbiParam::new(types::I32));
            out.push(AbiParam::new(types::I32));
        }
        MirType::IVec3 => {
            out.push(AbiParam::new(types::I32));
            out.push(AbiParam::new(types::I32));
            out.push(AbiParam::new(types::I32));
        }
        MirType::Bool | MirType::U8 | MirType::I8 => out.push(AbiParam::new(types::I8)),
        MirType::U16 | MirType::I16 => out.push(AbiParam::new(types::I16)),
        MirType::U32 | MirType::I32 | MirType::Sym | MirType::Fix32 => {
            out.push(AbiParam::new(types::I32))
        }
        MirType::U64 | MirType::I64 | MirType::Fix64 | MirType::Entity => {
            out.push(AbiParam::new(types::I64))
        }
        MirType::F32 => out.push(AbiParam::new(types::F32)),
        MirType::F64 => out.push(AbiParam::new(types::F64)),
        MirType::Named(n) => {
            if let Some(ed) = lookup_name_ref(enums_by_name, n) {
                let scalar = match (ed.repr_bytes, ed.is_signed) {
                    (1, _) => MirType::U8,
                    (2, _) => MirType::U16,
                    (4, true) => MirType::I32,
                    (4, false) => MirType::U32,
                    _ => MirType::U64,
                };
                push_abi_params_for_mir_type(out, &scalar, ptr_ty, enums_by_name);
            } else {
                out.push(AbiParam::new(ptr_ty));
            }
        }
        _ => out.push(AbiParam::new(ptr_ty)),
    }
}

pub(super) fn emit_fix64_div_helper(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let fid = ctx.fix64_div_fn;
    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature.call_conv = ctx.call_conv;
    fn_ctx.func.signature.params.push(AbiParam::new(types::I64));
    fn_ctx.func.signature.params.push(AbiParam::new(types::I64));
    fn_ctx
        .func
        .signature
        .returns
        .push(AbiParam::new(types::I64));

    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let a = b.block_params(entry)[0];
        let divisor = b.block_params(entry)[1];
        let zero64 = b.ins().iconst(types::I64, 0);

        let zero_bb = b.create_block();
        let nz_bb = b.create_block();
        let hdr_bb = b.create_block();
        let body_bb = b.create_block();
        let done_bb = b.create_block();

        let is_zero = b.ins().icmp_imm_s(IntCC::Equal, divisor, 0);
        b.ins().brif(is_zero, zero_bb, &[], nz_bb, &[]);

        b.switch_to_block(zero_bb);
        b.seal_block(zero_bb);
        b.ins().return_(&[zero64]);

        b.switch_to_block(nz_bb);
        b.seal_block(nz_bb);
        let xor_ab = b.ins().bxor(a, divisor);
        let is_neg_res = b.ins().icmp_imm_s(IntCC::SignedLessThan, xor_ab, 0);

        let a_neg = b.ins().icmp_imm_s(IntCC::SignedLessThan, a, 0);
        let a_abs = b.ins().ineg(a);
        let ua = b.ins().select(a_neg, a_abs, a);

        let b_neg = b.ins().icmp_imm_s(IntCC::SignedLessThan, divisor, 0);
        let b_abs = b.ins().ineg(divisor);
        let ub = b.ins().select(b_neg, b_abs, divisor);

        let ua_hi = b.ins().ushr_imm_u(ua, 32);
        let rem_init = b.ins().urem(ua_hi, ub);
        let lo_init = b.ins().ishl_imm_u(ua, 32);

        let rem_var = b.declare_var(types::I64);
        let lo_var = b.declare_var(types::I64);
        let quo_var = b.declare_var(types::I64);
        let idx_var = b.declare_var(types::I32);
        let zero32 = b.ins().iconst(types::I32, 0);

        b.def_var(rem_var, rem_init);
        b.def_var(lo_var, lo_init);
        b.def_var(quo_var, zero64);
        b.def_var(idx_var, zero32);
        b.ins().jump(hdr_bb, &[]);

        b.switch_to_block(hdr_bb);
        let i = b.use_var(idx_var);
        let cond = b.ins().icmp_imm_s(IntCC::UnsignedLessThan, i, 64);
        b.ins().brif(cond, body_bb, &[], done_bb, &[]);

        b.switch_to_block(body_bb);
        b.seal_block(body_bb);
        let rem_cur = b.use_var(rem_var);
        let lo_cur = b.use_var(lo_var);
        let quo_cur = b.use_var(quo_var);

        let carry = b.ins().ushr_imm_u(rem_cur, 63);
        let lo_msb = b.ins().ushr_imm_u(lo_cur, 63);
        let rem_sh = b.ins().ishl_imm_u(rem_cur, 1);
        let rem_next = b.ins().bor(rem_sh, lo_msb);
        let lo_next = b.ins().ishl_imm_u(lo_cur, 1);
        let quo_sh = b.ins().ishl_imm_u(quo_cur, 1);

        let carry_nz = b.ins().icmp_imm_s(IntCC::NotEqual, carry, 0);
        let ge_ub = b
            .ins()
            .icmp(IntCC::UnsignedGreaterThanOrEqual, rem_next, ub);
        let take = b.ins().bor(carry_nz, ge_ub);
        let rem_sub = b.ins().isub(rem_next, ub);
        let quo_set = b.ins().bor_imm_u(quo_sh, 1);
        let rem_fin = b.ins().select(take, rem_sub, rem_next);
        let quo_fin = b.ins().select(take, quo_set, quo_sh);

        b.def_var(rem_var, rem_fin);
        b.def_var(lo_var, lo_next);
        b.def_var(quo_var, quo_fin);
        let next_i = b.ins().iadd_imm_s(i, 1);
        b.def_var(idx_var, next_i);
        b.ins().jump(hdr_bb, &[]);

        b.seal_block(hdr_bb);
        b.switch_to_block(done_bb);
        b.seal_block(done_bb);
        let quo_out = b.use_var(quo_var);
        let neg_quo = b.ins().ineg(quo_out);
        let res = b.ins().select(is_neg_res, neg_quo, quo_out);
        b.ins().return_(&[res]);

        b.finalize(ctx.fe_cfg);
    }
    define_fn_checked(&mut ctx.obj_mod, fid, &mut fn_ctx, "__strata_fix64_div")
}

pub(super) fn emit_all_helpers(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    for hi in 0..ctx.mir.fns.len() {
        let hfn = &ctx.mir.fns[hi];
        let (fid, _) = ctx.helper_funcs[&hfn.name];
        emit_mir_function_body(ctx, hfn, fid, MirCallbackMode::Helper, None)?;
    }
    Ok(())
}

pub(super) fn emit_all_migrations(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let items: Vec<(usize, FuncId)> = ctx
        .mir
        .functions
        .iter()
        .enumerate()
        .filter_map(|(fi, f)| {
            if let MirFnKind::Migration { component, .. } = &f.kind {
                let lidx = lookup_name_in_map(&ctx.layout_map, component)?;
                let fid = *ctx.migrations_by_layout.get(&lidx)?;
                Some((fi, fid))
            } else {
                None
            }
        })
        .collect();
    for (fi, fid) in items {
        let f = &ctx.mir.functions[fi];
        emit_mir_function_body(ctx, f, fid, MirCallbackMode::Migration, None)?;
    }
    Ok(())
}

pub(super) fn emit_all_observers(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let count = ctx.observers.len();
    for oi in 0..count {
        let entry = ctx.observers[oi].sys_entry.clone();
        let f = &ctx.mir.functions[entry.fn_idx];
        emit_mir_function_body(
            ctx,
            f,
            entry.func_id,
            MirCallbackMode::Observer,
            Some(&entry),
        )?;
    }
    Ok(())
}

pub(super) fn emit_all_systems(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let count = ctx.systems.len();
    for si in 0..count {
        let entry = ctx.systems[si].clone();
        let f = &ctx.mir.functions[entry.fn_idx];
        emit_mir_function_body(ctx, f, entry.func_id, MirCallbackMode::System, Some(&entry))?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MirCallbackMode {
    System,
    Observer,
    Migration,
    Helper,
}

#[derive(Clone)]
pub(super) enum LocalRep {
    Scalar(Variable),
    Vec([Variable; 4]),
    AggVar(Variable),
}

pub(super) struct StrengthPlan {
    /// `(row_slot_local, base_ptr_local) -> (stride_bytes, ptr_var, is_indirect_entities)`
    pub(super) reduced: HashMap<(u32, u32), (u32, Variable, bool)>,
    /// `row_slot_local -> Vec<(base_ptr_local, stride_bytes, ptr_var)>`
    pub(super) by_slot: HashMap<u32, Vec<(u32, u32, Variable)>>,
    /// `base_ptr_local -> Vec<ptr_var>`
    pub(super) by_base: HashMap<u32, Vec<Variable>>,
    /// Literal `0` locals and `(base_slot + 1)` increment locals detected for `row_slot`.
    pub(super) zero_locals: HashSet<u32>,
    /// `step_val_local -> row_slot_local` where `step = SlotLoad(row_slot) + 1`.
    pub(super) step_inc_map: HashMap<u32, u32>,
}

pub(super) fn analyze_strength_reduction(
    func: &MirFunction,
    b: &mut FunctionBuilder<'_>,
    ptr_ty: Type,
) -> StrengthPlan {
    let mut zero_locals = HashSet::new();
    let mut one_locals = HashSet::new();
    let mut slot_loads: HashMap<u32, u32> = HashMap::new(); // loaded_local -> slot_local
    let mut add_one_locals: HashMap<u32, u32> = HashMap::new(); // sum_local -> loaded_local
    let mut def_block: HashMap<u32, usize> = HashMap::new();

    for (bi, bb) in func.blocks.iter().enumerate() {
        for s in &bb.stmts {
            if let Some(dst) = s.dst {
                def_block.insert(dst.0, bi);
                match &s.inst {
                    Inst::ConstInt { value: 0 } => {
                        zero_locals.insert(dst.0);
                    }
                    Inst::ConstInt { value: 1 } => {
                        one_locals.insert(dst.0);
                    }
                    Inst::SlotLoad { slot } => {
                        slot_loads.insert(dst.0, slot.0);
                    }
                    Inst::BinOp { op, lhs, rhs, .. } if op == "+" => {
                        if one_locals.contains(&rhs.0)
                            && let Some(&sl) = slot_loads.get(&lhs.0)
                        {
                            add_one_locals.insert(dst.0, sl);
                        } else if one_locals.contains(&lhs.0)
                            && let Some(&sl) = slot_loads.get(&rhs.0)
                        {
                            add_one_locals.insert(dst.0, sl);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Check which SlotAlloc locals ONLY receive `0` or `SlotLoad(slot) + 1`.
    let mut clean_slots = HashSet::new();
    let mut non_clean_slots = HashSet::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::SlotStore { slot, val } = &s.inst {
                let ok =
                    zero_locals.contains(&val.0) || add_one_locals.get(&val.0) == Some(&slot.0);
                if ok {
                    clean_slots.insert(slot.0);
                } else {
                    non_clean_slots.insert(slot.0);
                }
            }
        }
    }
    for bad in &non_clean_slots {
        clean_slots.remove(bad);
    }

    // Collect `IterColRead` / `IterColWrite` / `IterColWriteUntracked` / `IterEntities` base locals
    // that are computed outside the row-loop blocks (never redefined across steps without resetting slot 0).
    // Exclude optional component column pointers so absent chunks preserve `0` (null) on all rows.
    let mut opt_excluded_cols = HashSet::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::OptionalChunkIsPresent { slice_ptr, .. } = s.inst {
                opt_excluded_cols.insert(slice_ptr.0);
            }
        }
    }
    let is_optional_term = |query_idx: u32, term_idx: u32| -> bool {
        func.query_bindings
            .iter()
            .find(|qb| qb.query_idx == query_idx)
            .and_then(|qb| qb.terms.get(term_idx as usize))
            .is_some_and(|t| {
                matches!(
                    t.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                )
            })
    };
    let mut base_kinds: HashMap<u32, bool> = HashMap::new(); // local -> is_entities_array
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Some(dst) = s.dst {
                match s.inst {
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
                    } => {
                        if !opt_excluded_cols.contains(&dst.0)
                            && !is_optional_term(query_idx, term_idx)
                        {
                            base_kinds.insert(dst.0, false);
                        }
                    }
                    Inst::IterEntities { .. } => {
                        base_kinds.insert(dst.0, true);
                    }
                    _ => {}
                }
            }
        }
    }

    let mut reduced: HashMap<(u32, u32), (u32, Variable, bool)> = HashMap::new();
    let mut by_slot: HashMap<u32, Vec<(u32, u32, Variable)>> = HashMap::new();
    let mut by_base: HashMap<u32, Vec<Variable>> = HashMap::new();

    for bb in &func.blocks {
        for s in &bb.stmts {
            match s.inst {
                Inst::RowPtr {
                    col_ptr,
                    row_idx,
                    stride_bytes,
                    is_sparse: false,
                } if stride_bytes > 0 => {
                    if let Some(&slot_id) = slot_loads.get(&row_idx.0)
                        && clean_slots.contains(&slot_id)
                        && base_kinds.get(&col_ptr.0) == Some(&false)
                    {
                        reduced.entry((slot_id, col_ptr.0)).or_insert_with(|| {
                            let var = b.declare_var(ptr_ty);
                            by_slot.entry(slot_id).or_default().push((
                                col_ptr.0,
                                stride_bytes,
                                var,
                            ));
                            by_base.entry(col_ptr.0).or_default().push(var);
                            (stride_bytes, var, false)
                        });
                    }
                }
                Inst::EntityAtRow {
                    entities_ptr,
                    row_idx,
                } => {
                    if let Some(&slot_id) = slot_loads.get(&row_idx.0)
                        && clean_slots.contains(&slot_id)
                        && base_kinds.get(&entities_ptr.0) == Some(&true)
                    {
                        reduced.entry((slot_id, entities_ptr.0)).or_insert_with(|| {
                            let var = b.declare_var(ptr_ty);
                            by_slot
                                .entry(slot_id)
                                .or_default()
                                .push((entities_ptr.0, 8, var));
                            by_base.entry(entities_ptr.0).or_default().push(var);
                            (8, var, true)
                        });
                    }
                }
                _ => {}
            }
        }
    }

    StrengthPlan {
        reduced,
        by_slot,
        by_base,
        zero_locals,
        step_inc_map: add_one_locals,
    }
}

pub(super) struct ParSubCfgInfo {
    query_idx: u32,
    is_readonly: bool,
    chunk_hdr_bb: usize,
    chunk_exit_bb: usize,
    sub_blocks: Vec<usize>,
    live_in_locals: Vec<u32>,
}

pub(super) fn find_par_subcfg_info(
    func: &MirFunction,
    par_stmt_bb: usize,
    query_idx: u32,
    is_readonly: bool,
    deterministic_order: bool,
    enums_by_name: &HashMap<String, EnumDef>,
    unsafe_par_fns: &HashSet<String>,
) -> Option<ParSubCfgInfo> {
    if is_readonly && deterministic_order {
        return None;
    }
    let chunk_hdr_bb = match func.blocks[par_stmt_bb].terminator {
        Terminator::Goto(b) => b.0 as usize,
        _ => return None,
    };
    let (then_bb, else_bb) = match func.blocks.get(chunk_hdr_bb)?.terminator {
        Terminator::Branch {
            then_bb, else_bb, ..
        } => (then_bb.0 as usize, else_bb.0 as usize),
        _ => return None,
    };

    // Walk reachable blocks starting at `then_bb` stopping at `chunk_hdr_bb` or `else_bb`.
    let mut visited = HashSet::new();
    let mut queue = vec![then_bb];
    let mut sub_blocks = Vec::new();
    visited.insert(chunk_hdr_bb);
    while let Some(bi) = queue.pop() {
        if bi == else_bb || !visited.insert(bi) {
            continue;
        }
        sub_blocks.push(bi);
        match &func.blocks[bi].terminator {
            Terminator::Goto(dst) => queue.push(dst.0 as usize),
            Terminator::Branch {
                then_bb: a,
                else_bb: b,
                ..
            } => {
                queue.push(a.0 as usize);
                queue.push(b.0 as usize);
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, c) in cases {
                    queue.push(c.0 as usize);
                }
                queue.push(default_bb.0 as usize);
            }
            Terminator::Return(_) => return None,
        }
    }
    sub_blocks.insert(0, chunk_hdr_bb);
    let sub_set: HashSet<usize> = sub_blocks.iter().copied().collect();

    // Reject if sub-CFG uses commands, host EntityGet, writes outer slots, or defines values used outside.
    let mut defined_inside = HashSet::new();
    let mut allocs_inside = HashSet::new();
    for &bi in &sub_blocks {
        for s in &func.blocks[bi].stmts {
            if let Some(d) = s.dst {
                defined_inside.insert(d.0);
                if matches!(s.inst, Inst::SlotAlloc { .. }) {
                    allocs_inside.insert(d.0);
                }
            }
            match &s.inst {
                Inst::CmdSpawn { .. }
                | Inst::CmdSpawnBatch { .. }
                | Inst::SpawnBatchBegin { .. }
                | Inst::SpawnBatchPush { .. }
                | Inst::SpawnBatchCommit { .. }
                | Inst::CmdDespawn { .. }
                | Inst::CmdDespawnAll { .. }
                | Inst::CmdInsert { .. }
                | Inst::CmdRemove { .. }
                | Inst::CmdTrigger { .. }
                | Inst::StreamEmit { .. }
                | Inst::CmdCheckpoint
                | Inst::CmdRollback { .. }
                | Inst::CmdInsertRelation { .. }
                | Inst::CmdRemoveRelation { .. }
                | Inst::EntityGet { .. }
                | Inst::EntityGetMut { .. }
                | Inst::ResolveNamedObject { .. }
                | Inst::BindNamedObject { .. }
                | Inst::ReduceInit { .. }
                | Inst::ReduceAccum { .. }
                | Inst::DirtyRunInit { .. }
                | Inst::DirtyRunRecordRow { .. }
                | Inst::ParForEachChunk { .. }
                | Inst::ParForEachChunkReadonly { .. }
                | Inst::SpatialRebuildCsr { .. }
                | Inst::SpatialCsrBegin { .. }
                | Inst::SpatialCsrCount { .. }
                | Inst::SpatialCsrPrefixSum { .. }
                | Inst::SpatialCsrScatter { .. }
                | Inst::IterReset { .. }
                | Inst::IterCount { .. }
                | Inst::IterUpCascade { .. }
                | Inst::ResRead { .. }
                | Inst::ResWrite { .. }
                | Inst::SpatialQueryDisc { .. }
                | Inst::SpatialQuerySegmentAt { .. } => return None,
                Inst::Call { callee, .. }
                    if unsafe_par_fns.contains(callee.as_str())
                        || callee
                            .rsplit("::")
                            .next()
                            .is_some_and(|s| unsafe_par_fns.contains(s)) =>
                {
                    return None;
                }
                Inst::SlotStore { slot, .. } if !allocs_inside.contains(&slot.0) => return None,
                _ => {}
            }
        }
    }

    let mut used_inside = Vec::new();
    let mut used_seen = HashSet::new();
    for &bi in &sub_blocks {
        for s in &func.blocks[bi].stmts {
            for r in inst_read_locals(&s.inst) {
                if !defined_inside.contains(&r) && used_seen.insert(r) {
                    let rty = &func.locals[r as usize].ty;
                    let is_named_agg = matches!(
                        rty,
                        MirType::Named(n) if lookup_name_ref(enums_by_name, n).is_none()
                    );
                    if is_named_agg
                        || matches!(
                            rty,
                            MirType::Array { .. } | MirType::Tuple(_) | MirType::QueryIter
                        )
                    {
                        return None;
                    }
                    used_inside.push(r);
                }
            }
        }
        for r in term_read_locals(&func.blocks[bi].terminator) {
            if !defined_inside.contains(&r) && used_seen.insert(r) {
                used_inside.push(r);
            }
        }
    }

    // Verify nothing outside `sub_set` reads anything `defined_inside`.
    for (bi, bb) in func.blocks.iter().enumerate() {
        if sub_set.contains(&bi) {
            continue;
        }
        for s in &bb.stmts {
            for r in inst_read_locals(&s.inst) {
                if defined_inside.contains(&r) {
                    return None;
                }
            }
        }
        for r in term_read_locals(&bb.terminator) {
            if defined_inside.contains(&r) {
                return None;
            }
        }
    }

    Some(ParSubCfgInfo {
        query_idx,
        is_readonly,
        chunk_hdr_bb,
        chunk_exit_bb: else_bb,
        sub_blocks,
        live_in_locals: used_inside,
    })
}

pub(super) fn inst_read_locals(inst: &Inst) -> Vec<u32> {
    let mut out = Vec::new();
    match inst {
        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::IterUpCascade { entity: val, .. }
        | Inst::SpatialCsrCount { pos: val, .. }
        | Inst::CurveSample { x: val, .. }
        | Inst::TableLoad { key: val, .. } => out.push(val.0),
        Inst::SlotStore { slot, val } => {
            out.push(slot.0);
            out.push(val.0);
        }
        Inst::BinOp { lhs, rhs, .. }
        | Inst::VecInsert {
            vec: lhs, val: rhs, ..
        }
        | Inst::ArrayIndex {
            base: lhs,
            index: rhs,
        }
        | Inst::FieldStore {
            base_ptr: lhs,
            val: rhs,
            ..
        }
        | Inst::RowPtr {
            col_ptr: lhs,
            row_idx: rhs,
            ..
        }
        | Inst::EntityAtRow {
            entities_ptr: lhs,
            row_idx: rhs,
        }
        | Inst::SpatialCsrScatter {
            entity: lhs,
            pos: rhs,
            ..
        }
        | Inst::GraceArm {
            ptr: lhs,
            duration_sec: rhs,
        }
        | Inst::GraceTick {
            ptr: lhs,
            dt_sec: rhs,
        }
        | Inst::InputBufTick {
            ptr: lhs,
            dt_sec: rhs,
            ..
        } => {
            out.push(lhs.0);
            out.push(rhs.0);
        }
        Inst::GraceIsActive { ptr }
        | Inst::GraceClear { ptr }
        | Inst::TimelineInWindow { ptr, .. } => {
            out.push(ptr.0);
        }
        Inst::TimelineAdvance {
            cursor_ptr, dt_sec, ..
        } => {
            out.push(cursor_ptr.0);
            out.push(dt_sec.0);
        }
        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => {
            out.push(ptr.0);
            out.push(action_id.0);
            out.push(window_sec.0);
        }
        Inst::InputBufConsume { ptr, action_id, .. }
        | Inst::InputBufPeek { ptr, action_id, .. }
        | Inst::BitSetSet {
            ptr,
            bit: action_id,
            ..
        }
        | Inst::BitSetGet {
            ptr,
            bit: action_id,
            ..
        }
        | Inst::BitSetClear {
            ptr,
            bit: action_id,
            ..
        } => {
            out.push(ptr.0);
            out.push(action_id.0);
        }
        Inst::IntrinsicMath { args, .. }
        | Inst::Call { args, .. }
        | Inst::ArrayInit { elems: args } => {
            for a in args {
                out.push(a.0);
            }
        }
        Inst::StructInit { fields, .. } => {
            for (_, v) in fields {
                out.push(v.0);
            }
        }
        Inst::SpawnBatchBegin { count, .. } => {
            out.push(count.0);
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            out.push(batch.0);
            out.push(index.0);
            for (_, v) in components {
                out.push(v.0);
            }
        }
        Inst::SpawnBatchCommit { batch } => {
            out.push(batch.0);
        }
        Inst::ArrayStore {
            base_ptr,
            index,
            val,
            ..
        } => {
            out.push(base_ptr.0);
            out.push(index.0);
            out.push(val.0);
        }
        _ => {}
    }
    out
}

pub(super) fn term_read_locals(term: &Terminator) -> Vec<u32> {
    match term {
        Terminator::Return(Some(l)) => vec![l.0],
        Terminator::Branch { cond, .. } => vec![cond.0],
        Terminator::Switch { scrutinee, .. } => vec![scrutinee.0],
        _ => Vec::new(),
    }
}

pub(super) fn define_fn_checked(
    obj_mod: &mut ObjectModule,
    fid: FuncId,
    fn_ctx: &mut cranelift_codegen::Context,
    label: &str,
) -> Result<(), JitError> {
    if let Err(err) = obj_mod.define_function(fid, fn_ctx) {
        let verify_detail =
            match cranelift_codegen::verify_function(&fn_ctx.func, obj_mod.isa().flags()) {
                Ok(()) => String::new(),
                Err(errs) => format!("\nVerifier details:\n{errs}\nCLIF IR:\n{}", fn_ctx.func),
            };
        return Err(JitError::Codegen(format!("{label}: {err}{verify_detail}")));
    }
    Ok(())
}

pub(super) fn collect_slot_elem_tys(
    mir_fn: &MirFunction,
    enums_by_name: &HashMap<String, EnumDef>,
) -> HashMap<u32, MirType> {
    let mut slot_elem_tys = HashMap::new();
    for bb in &mir_fn.blocks {
        for s in &bb.stmts {
            if let Some(d) = s.dst
                && let Inst::SlotAlloc { ty } = &s.inst
            {
                let is_agg = match ty {
                    MirType::Named(n) => lookup_name_ref(enums_by_name, n).is_none(),
                    MirType::Array { .. } | MirType::Tuple(_) => true,
                    _ => false,
                };
                if !is_agg {
                    slot_elem_tys.insert(d.0, ty.clone());
                }
            }
        }
    }
    // Recover vector local types for `vec * scalar` / `ivec * i32` where upstream Sema/MIR
    // fell back to scalar `I32`/`F32` on the intermediate `BinOp`/`UnOp`/`SlotLoad` local.
    let eff = |map: &HashMap<u32, MirType>, id: LocalId| -> MirType {
        map.get(&id.0)
            .unwrap_or(&mir_fn.locals[id.0 as usize].ty)
            .clone()
    };
    for _pass in 0..4 {
        let mut changed = false;
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::BinOp { op, lhs, rhs, .. } if !is_cmp_op(op) => {
                        if let Some(d) = s.dst {
                            let dty = eff(&slot_elem_tys, d);
                            if vec_dims(&dty).is_none() {
                                let lty = eff(&slot_elem_tys, *lhs);
                                let rty = eff(&slot_elem_tys, *rhs);
                                let vty = if vec_dims(&lty).is_some() {
                                    Some(lty)
                                } else if vec_dims(&rty).is_some() {
                                    Some(rty)
                                } else {
                                    None
                                };
                                if let Some(vt) = vty
                                    && slot_elem_tys.get(&d.0) != Some(&vt)
                                {
                                    slot_elem_tys.insert(d.0, vt);
                                    changed = true;
                                }
                            }
                        }
                    }
                    Inst::UnOp { op, val } if op == "-" => {
                        if let Some(d) = s.dst {
                            let dty = eff(&slot_elem_tys, d);
                            let vty = eff(&slot_elem_tys, *val);
                            if vec_dims(&dty).is_none()
                                && vec_dims(&vty).is_some()
                                && slot_elem_tys.get(&d.0) != Some(&vty)
                            {
                                slot_elem_tys.insert(d.0, vty);
                                changed = true;
                            }
                        }
                    }
                    Inst::IntrinsicMath { name, .. } | Inst::Call { callee: name, .. } => {
                        if let Some(d) = s.dst {
                            let short = name.rsplit("::").next().unwrap_or(name.as_str());
                            let mty = match short {
                                "mat3" | "Mat3" => Some(MirType::Named("mat3".to_owned())),
                                "mat4" | "Mat4" => Some(MirType::Named("mat4".to_owned())),
                                _ => None,
                            };
                            if let Some(mt) = mty
                                && mir_fn.locals[d.0 as usize].ty == MirType::Unit
                                && slot_elem_tys.get(&d.0) != Some(&mt)
                            {
                                slot_elem_tys.insert(d.0, mt);
                                changed = true;
                            }
                        }
                    }
                    Inst::Copy { val } | Inst::SlotLoad { slot: val } => {
                        if let Some(d) = s.dst {
                            let dty = eff(&slot_elem_tys, d);
                            let vty = eff(&slot_elem_tys, *val);
                            let prop_agg = dty == MirType::Unit
                                && matches!(vty, MirType::Named(ref n) if n == "mat3" || n == "mat4");
                            if ((vec_dims(&dty).is_none() && vec_dims(&vty).is_some()) || prop_agg)
                                && slot_elem_tys.get(&d.0) != Some(&vty)
                            {
                                slot_elem_tys.insert(d.0, vty);
                                changed = true;
                            }
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        let st_raw = &mir_fn.locals[slot.0 as usize].ty;
                        if matches!(st_raw, MirType::MutPtr | MirType::Ptr) {
                            let sty = eff(&slot_elem_tys, *slot);
                            let vty = eff(&slot_elem_tys, *val);
                            let prop_agg = sty == MirType::Unit
                                && matches!(vty, MirType::Named(ref n) if n == "mat3" || n == "mat4");
                            if ((vec_dims(&sty).is_none() && vec_dims(&vty).is_some()) || prop_agg)
                                && slot_elem_tys.get(&slot.0) != Some(&vty)
                            {
                                slot_elem_tys.insert(slot.0, vty);
                                changed = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }
    slot_elem_tys
}

pub(super) fn emit_mir_function_body(
    ctx: &mut ModuleContext<'_>,
    mir_fn: &MirFunction,
    fid: FuncId,
    mode: MirCallbackMode,
    sys_entry: Option<&SystemRegistrationEntry>,
) -> Result<(), JitError> {
    // Check if any `@par` sub-CFG can be outlined to `BamChunkTaskFn`.
    let slot_elem_tys = collect_slot_elem_tys(mir_fn, &ctx.enums_by_name);
    let mut par_tasks: HashMap<usize, (ParSubCfgInfo, FuncId, Vec<usize>)> = HashMap::new();
    let mut skip_blocks: HashSet<usize> = HashSet::new();
    for (bi, bb) in mir_fn.blocks.iter().enumerate() {
        for s in &bb.stmts {
            let par_spec = match s.inst {
                Inst::ParForEachChunk { query_idx, .. } => Some((query_idx, false, false)),
                Inst::ParForEachChunkReadonly {
                    query_idx,
                    deterministic_order,
                    ..
                } => Some((query_idx, true, deterministic_order)),
                _ => None,
            };
            if let Some((qi, ro, det)) = par_spec
                && mode == MirCallbackMode::System
                && let Some(info) = find_par_subcfg_info(
                    mir_fn,
                    bi,
                    qi,
                    ro,
                    det,
                    &ctx.enums_by_name,
                    &ctx.unsafe_par_fns,
                )
            {
                let mut offsets = Vec::with_capacity(info.live_in_locals.len() + 1);
                let mut off = ctx.ptr_bytes; // offset 0 = state_ptr
                for &lid in &info.live_in_locals {
                    off = align_up(off, 8);
                    offsets.push(off);
                    let mty = slot_elem_tys
                        .get(&lid)
                        .unwrap_or(&mir_fn.locals[lid as usize].ty);
                    off += match mty {
                        MirType::Vec2
                        | MirType::Vec3
                        | MirType::Vec4
                        | MirType::IVec2
                        | MirType::IVec3
                        | MirType::UVec2 => 16,
                        _ => 8,
                    };
                }
                let task_sym = format!("strata_par_{}_b{bi}_q{qi}", sanitize_ident(&mir_fn.name));
                let mut tsig = Signature::new(ctx.call_conv);
                tsig.params.push(AbiParam::new(ctx.ptr_ty)); // sub_iter
                tsig.params.push(AbiParam::new(ctx.ptr_ty)); // par_frame user_data
                tsig.returns.push(AbiParam::new(types::I32));
                let task_fid = ctx
                    .obj_mod
                    .declare_function(&task_sym, Linkage::Local, &tsig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                for &sb in &info.sub_blocks {
                    skip_blocks.insert(sb);
                }
                par_tasks.insert(bi, (info, task_fid, offsets));
            }
        }
    }

    // Emit any outlined `BamChunkTaskFn` functions first!
    for (info, task_fid, offsets) in par_tasks.values() {
        emit_par_task_function(ctx, mir_fn, info, *task_fid, offsets, sys_entry)?;
    }

    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = match mode {
        MirCallbackMode::Helper => {
            build_helper_signature(mir_fn, ptr_ty, call_conv, &ctx.enums_by_name)
        }
        MirCallbackMode::Observer => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(types::I64));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
        MirCallbackMode::Migration => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
        MirCallbackMode::System => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
    };

    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let cl_blocks: Vec<Block> = (0..mir_fn.blocks.len()).map(|_| b.create_block()).collect();
        if cl_blocks.is_empty() {
            let entry = b.create_block();
            b.append_block_params_for_function_params(entry);
            b.switch_to_block(entry);
            b.seal_block(entry);
            let ok = b.ins().iconst(types::I32, i64::from(FFI_OK));
            b.ins().return_(&[ok]);
            b.finalize(ctx.fe_cfg);
            define_fn_checked(
                &mut ctx.obj_mod,
                fid,
                &mut fn_ctx,
                &format!("empty MIR function `{}`", mir_fn.name),
            )?;
            return Ok(());
        }

        b.append_block_params_for_function_params(cl_blocks[0]);
        b.switch_to_block(cl_blocks[0]);

        let params = b.block_params(cl_blocks[0]).to_vec();
        let (sys_ctx, state_ptr, obs_entity, obs_event_data, obs_commands, mig_src, mig_dst) =
            match mode {
                MirCallbackMode::System => (params[0], params[1], None, None, None, None, None),
                MirCallbackMode::Observer => (
                    params[2],
                    params[3],
                    Some(params[0]),
                    Some(params[1]),
                    None,
                    None,
                    None,
                ),
                MirCallbackMode::Migration => (
                    b.ins().iconst(ptr_ty, 0),
                    params[2],
                    None,
                    None,
                    None,
                    Some(params[0]),
                    Some(params[1]),
                ),
                MirCallbackMode::Helper => (params[1], params[0], None, None, None, None, None),
            };

        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );

        let sr_plan = analyze_strength_reduction(mir_fn, &mut b, ptr_ty);
        if mode == MirCallbackMode::System
            && let Some(entry) = sys_entry
            && let Some((ref guard_expr, res_lidx_opt)) = entry.run_if_guard
        {
            let (res_layout, rptr) = match res_lidx_opt {
                Some(res_lidx) => (
                    Some(&ctx.mir_layouts_sorted[res_lidx]),
                    Some(emit_res_ptr_lookup(
                        ctx, &mut b, api_ptr, sys_ctx, state_ptr, res_lidx, false,
                    )),
                ),
                None => (None, None),
            };
            if let Some(cond) =
                eval_hir_run_if(res_layout, &ctx.consts_by_name, &mut b, rptr, guard_expr)
            {
                let run_bb = b.create_block();
                let skip_bb = b.create_block();
                b.ins().brif(cond, run_bb, &[], skip_bb, &[]);
                b.switch_to_block(skip_bb);
                b.seal_block(skip_bb);
                let ok_ret = b.ins().iconst(types::I32, i64::from(FFI_OK));
                b.ins().return_(&[ok_ret]);
                b.switch_to_block(run_bb);
                b.seal_block(run_bb);
            }
        }
        let mut lowerer = FnLowerer::new(
            ctx,
            mir_fn,
            &mut b,
            cl_blocks.clone(),
            mode,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            obs_entity,
            obs_event_data,
            obs_commands,
            mig_src,
            mig_dst,
            sr_plan,
        );

        // Bind `HelperFn` parameters onto `MirParam.local`.
        if mode == MirCallbackMode::Helper {
            let mut p_off = if helper_uses_out_ptr(&mir_fn.ret_ty) {
                lowerer.helper_out_ptr = Some(params[2]);
                3usize
            } else {
                2usize
            };
            for p in &mir_fn.params {
                let count = match p.ty {
                    MirType::Unit => 0,
                    MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => 2,
                    MirType::Vec3 | MirType::IVec3 => 3,
                    MirType::Vec4 => 4,
                    _ => 1,
                };
                if let Some(lid) = p.local {
                    lowerer.bind_param_val(lid, &params[p_off..p_off + count], &p.ty);
                }
                p_off += count;
            }
        } else if matches!(mode, MirCallbackMode::System | MirCallbackMode::Observer) {
            lowerer.bind_stream_in_params()?;
        }

        // Lower all reachable/participating MIR basic blocks in order.
        for (bi, bb) in mir_fn.blocks.iter().enumerate() {
            if bi != 0 {
                lowerer.b.switch_to_block(cl_blocks[bi]);
            }
            if skip_blocks.contains(&bi) {
                let zero = lowerer.b.ins().iconst(types::I32, 0);
                if matches!(
                    mode,
                    MirCallbackMode::System
                        | MirCallbackMode::Observer
                        | MirCallbackMode::Migration
                ) {
                    lowerer.b.ins().return_(&[zero]);
                } else {
                    lowerer.emit_default_helper_return();
                }
                continue;
            }

            let mut par_jumped = false;
            for s in &bb.stmts {
                if matches!(
                    s.inst,
                    Inst::ParForEachChunk { .. } | Inst::ParForEachChunkReadonly { .. }
                ) && let Some((info, task_fid, offsets)) = par_tasks.get(&bi)
                {
                    lowerer.emit_par_dispatch(info, *task_fid, offsets)?;
                    let exit_cl = cl_blocks[info.chunk_exit_bb];
                    lowerer.b.ins().jump(exit_cl, &[]);
                    par_jumped = true;
                    break;
                }
                lowerer.lower_stmt(s)?;
            }
            if !par_jumped {
                lowerer.lower_terminator(&bb.terminator);
            }
        }

        drop(lowerer);
        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        &format!("MIR function `{}`", mir_fn.name),
    )
}

pub(super) fn emit_par_task_function(
    ctx: &mut ModuleContext<'_>,
    mir_fn: &MirFunction,
    info: &ParSubCfgInfo,
    task_fid: FuncId,
    offsets: &[usize],
    sys_entry: Option<&SystemRegistrationEntry>,
) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature.call_conv = call_conv;
    fn_ctx.func.signature.params.push(AbiParam::new(ptr_ty)); // sub_iter
    fn_ctx.func.signature.params.push(AbiParam::new(ptr_ty)); // par_frame
    fn_ctx
        .func
        .signature
        .returns
        .push(AbiParam::new(types::I32));

    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);

        let sub_iter = b.block_params(entry)[0];
        let par_frame = b.block_params(entry)[1];
        let state_ptr = b.ins().load(ptr_ty, MemFlagsData::trusted(), par_frame, 0);
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );
        let sys_ctx = b.ins().iconst(ptr_ty, 0);

        let mut cl_blocks: Vec<Block> = (0..mir_fn.blocks.len()).map(|_| entry).collect();
        let exit_bb = b.create_block();
        for &sb in &info.sub_blocks {
            cl_blocks[sb] = b.create_block();
        }
        cl_blocks[info.chunk_exit_bb] = exit_bb;

        let sr_plan = analyze_strength_reduction(mir_fn, &mut b, ptr_ty);
        let mut lowerer = FnLowerer::new(
            ctx,
            mir_fn,
            &mut b,
            cl_blocks.clone(),
            MirCallbackMode::System,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            None,
            None,
            None,
            None,
            None,
            sr_plan,
        );

        // Pre-populate `iter_vars[query_idx]` with `sub_iter`.
        let qi = info.query_idx as usize;
        if qi < lowerer.iter_vars.len() {
            lowerer.b.def_var(lowerer.iter_vars[qi], sub_iter);
        }

        // Load captured live-in locals from `par_frame`.
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let mty = lowerer.effective_local_mir_ty(LocalId(lid)).clone();
            lowerer.load_local_from_mem(LocalId(lid), &mty, par_frame, off as i32);
        }

        let hdr_cl = cl_blocks[info.chunk_hdr_bb];
        lowerer.b.ins().jump(hdr_cl, &[]);

        for &sb in &info.sub_blocks {
            lowerer.b.switch_to_block(cl_blocks[sb]);
            let bb = &mir_fn.blocks[sb];
            for s in &bb.stmts {
                lowerer.lower_stmt(s)?;
            }
            lowerer.lower_terminator(&bb.terminator);
        }

        lowerer.b.switch_to_block(exit_bb);
        let ok = lowerer.b.ins().iconst(types::I32, i64::from(FFI_OK));
        lowerer.b.ins().return_(&[ok]);
        drop(lowerer);
        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        task_fid,
        &mut fn_ctx,
        "par chunk task define failed",
    )
}

pub(super) fn sema_ty_vec_dims(ty: &Ty) -> Option<u8> {
    match ty {
        Ty::Vec2 => Some(2),
        Ty::Vec3 => Some(3),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Some(4),
        _ => None,
    }
}

pub(super) fn find_layout_vec_hint(
    ctx: &ModuleContext<'_>,
    comp_name: &str,
    projected_field: Option<&str>,
) -> Option<(i32, u8)> {
    let lidx = lookup_name_in_map(&ctx.layout_map, comp_name)?;
    let layout = &ctx.mir_layouts_sorted[lidx];
    if let Some(fname) = projected_field
        && let Some(sf) = layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == fname)
        && let Some(dims) = sema_ty_vec_dims(&sf.ty)
    {
        return Some((sf.offset as i32, dims));
    }
    let mut found: Option<(i32, u8)> = None;
    for sf in layout.fields.iter().filter(|f| !f.is_padding) {
        if let Some(dims) = sema_ty_vec_dims(&sf.ty) {
            if found.is_some() {
                return None;
            }
            found = Some((sf.offset as i32, dims));
        }
    }
    found
}

pub(super) fn compute_ptr_vec_hints(
    ctx: &ModuleContext<'_>,
    mir_fn: &MirFunction,
) -> HashMap<u32, (i32, u8)> {
    let mut hints: HashMap<u32, (i32, u8)> = HashMap::new();
    let mut slot_hints: HashMap<u32, (i32, u8)> = HashMap::new();
    for _pass in 0..3 {
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColRowsRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColRowsWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::EntityGet {
                        query_idx,
                        term_idx,
                        storage_key,
                        ..
                    }
                    | Inst::EntityGetMut {
                        query_idx,
                        term_idx,
                        storage_key,
                        ..
                    } => {
                        if let Some(d) = s.dst {
                            let proj = mir_fn
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.get(*term_idx as usize))
                                .and_then(|t| t.field_name.as_deref());
                            if let Some(h) = find_layout_vec_hint(ctx, storage_key, proj) {
                                hints.insert(d.0, h);
                            }
                        }
                    }
                    Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                        if let Some(d) = s.dst
                            && let Some(h) = find_layout_vec_hint(ctx, resource, None)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::RowPtr { col_ptr, .. } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = hints.get(&col_ptr.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::FieldPtr {
                        layout_key, field, ..
                    } => {
                        if let Some(d) = s.dst
                            && let Some((_, dims)) =
                                find_layout_vec_hint(ctx, layout_key, Some(field))
                        {
                            hints.insert(d.0, (0, dims));
                        }
                    }
                    Inst::Copy { val } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = hints.get(&val.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(&h) = hints.get(&val.0) {
                            slot_hints.insert(slot.0, h);
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = slot_hints.get(&slot.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    hints
}

pub(super) struct FnLowerer<'a, 'b, 'f> {
    pub(super) ctx: &'a mut ModuleContext<'b>,
    pub(super) mir_fn: &'a MirFunction,
    pub(super) b: &'a mut FunctionBuilder<'f>,
    pub(super) cl_blocks: Vec<Block>,
    pub(super) mode: MirCallbackMode,
    pub(super) sys_entry: Option<&'a SystemRegistrationEntry>,
    pub(super) api_ptr: Value,
    pub(super) host_ctx: Value,
    pub(super) state_ptr: Value,
    pub(super) sys_ctx: Value,
    pub(super) obs_entity: Option<Value>,
    pub(super) obs_event_data: Option<Value>,
    pub(super) obs_commands: Option<Value>,
    pub(super) mig_src: Option<Value>,
    pub(super) mig_dst: Option<Value>,
    pub(super) helper_out_ptr: Option<Value>,
    pub(super) local_reps: Vec<LocalRep>,
    pub(super) slot_elem_tys: HashMap<u32, MirType>,
    pub(super) agg_slots: HashMap<u32, StackSlot>,
    pub(super) agg_slot_tys: HashMap<u32, MirType>,
    pub(super) dirty_targets: HashMap<(u32, u32), (u32, u32)>,
    pub(super) iter_vars: Vec<Variable>,
    pub(super) chunk_len_vars: Vec<Variable>,
    pub(super) commands_var: Variable,
    pub(super) sr_plan: StrengthPlan,
    pub(super) ptr_vec_hints: HashMap<u32, (i32, u8)>,
    pub(super) const_strings: HashMap<u32, (DataId, usize)>,
    pub(super) const_string_texts: HashMap<u32, String>,
    pub(super) batch_schemas: HashMap<u32, Vec<usize>>,
    pub(super) const_defs: HashMap<u32, MirConstVal>,
    pub(super) array_elems: HashMap<u32, Vec<LocalId>>,
    pub(super) array_ptr_lens: HashMap<u32, usize>,
    pub(super) ptr_elem_tys: HashMap<u32, MirType>,
    pub(super) ptr_pointee_tys: HashMap<u32, MirType>,
    pub(super) slot_ptr_elem_tys: HashMap<u32, MirType>,
    pub(super) slot_ptr_pointee_tys: HashMap<u32, MirType>,
    pub(super) slot_array_lens: HashMap<u32, usize>,
}

impl<'a, 'b, 'f> FnLowerer<'a, 'b, 'f> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        ctx: &'a mut ModuleContext<'b>,
        mir_fn: &'a MirFunction,
        b: &'a mut FunctionBuilder<'f>,
        cl_blocks: Vec<Block>,
        mode: MirCallbackMode,
        sys_entry: Option<&'a SystemRegistrationEntry>,
        api_ptr: Value,
        host_ctx: Value,
        state_ptr: Value,
        sys_ctx: Value,
        obs_entity: Option<Value>,
        obs_event_data: Option<Value>,
        obs_commands: Option<Value>,
        mig_src: Option<Value>,
        mig_dst: Option<Value>,
        sr_plan: StrengthPlan,
    ) -> Self {
        let ptr_ty = ctx.ptr_ty;

        let mut dirty_targets = HashMap::new();
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                if let Inst::IterMarkChangedRange {
                    query_idx,
                    term_idx,
                    run_start,
                    run_len,
                } = &s.inst
                {
                    dirty_targets.insert((run_start.0, run_len.0), (*query_idx, *term_idx));
                }
            }
        }

        let zero_ptr = b.ins().iconst(ptr_ty, 0);
        let zero_i32 = b.ins().iconst(types::I32, 0);
        let zero_f32 = b.ins().f32const(0.0);
        let zero_f64 = b.ins().f64const(0.0);
        let slot_elem_tys = collect_slot_elem_tys(mir_fn, &ctx.enums_by_name);
        let mut agg_slots = HashMap::new();
        let mut agg_slot_tys = HashMap::new();
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                if let Some(d) = s.dst
                    && let Inst::SlotAlloc { ty } = &s.inst
                    && ctx.is_agg_mir_ty(ty)
                {
                    let sz = ctx.layout_size_of_mir_ty(ty).max(8);
                    let slot = alloc_zero_slot(b, sz, ptr_ty);
                    agg_slots.insert(d.0, slot);
                    agg_slot_tys.insert(d.0, ty.clone());
                }
            }
        }

        let mut array_ptr_lens = HashMap::new();
        let mut ptr_elem_tys = HashMap::new();
        let mut ptr_pointee_tys = HashMap::new();
        for (li, loc) in mir_fn.locals.iter().enumerate() {
            if let MirType::Array { elem, len } = &loc.ty {
                array_ptr_lens.insert(li as u32, *len);
                ptr_elem_tys.insert(li as u32, (**elem).clone());
                ptr_pointee_tys.insert(li as u32, loc.ty.clone());
            } else if let MirType::Named(n) = &loc.ty
                && n.starts_with("SmallVec<")
            {
                ptr_pointee_tys.insert(li as u32, loc.ty.clone());
            }
        }
        for (&sid, ty) in &agg_slot_tys {
            if let MirType::Array { elem, len } = ty {
                array_ptr_lens.insert(sid, *len);
                ptr_elem_tys.insert(sid, (**elem).clone());
                ptr_pointee_tys.insert(sid, ty.clone());
            } else if let MirType::Named(n) = ty
                && n.starts_with("SmallVec<")
            {
                ptr_pointee_tys.insert(sid, ty.clone());
            }
        }

        let mut local_reps = Vec::with_capacity(mir_fn.locals.len());

        for (li, loc) in mir_fn.locals.iter().enumerate() {
            let eff_ty = slot_elem_tys.get(&(li as u32)).unwrap_or(&loc.ty);
            match eff_ty {
                MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                    let vs = [
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                    ];
                    for v in vs {
                        b.def_var(v, zero_f32);
                    }
                    local_reps.push(LocalRep::Vec(vs));
                }
                MirType::IVec2 | MirType::IVec3 | MirType::UVec2 => {
                    let vs = [
                        b.declare_var(types::I32),
                        b.declare_var(types::I32),
                        b.declare_var(types::I32),
                        b.declare_var(types::I32),
                    ];
                    for v in vs {
                        b.def_var(v, zero_i32);
                    }
                    local_reps.push(LocalRep::Vec(vs));
                }
                _ if ctx.is_agg_mir_ty(eff_ty) => {
                    let var = b.declare_var(ptr_ty);
                    b.def_var(var, zero_ptr);
                    local_reps.push(LocalRep::AggVar(var));
                }
                _ => {
                    let cl_ty = ctx.cl_type_for_mir_val(eff_ty);
                    let var = b.declare_var(cl_ty);
                    let z = if cl_ty == types::F32 {
                        zero_f32
                    } else if cl_ty == types::F64 {
                        zero_f64
                    } else {
                        b.ins().iconst(cl_ty, 0)
                    };
                    b.def_var(var, z);
                    local_reps.push(LocalRep::Scalar(var));
                }
            }
        }

        // Initialize strength-reduced pointer variables on entry so all paths dominate.
        for vars in sr_plan.by_base.values() {
            for &v in vars {
                b.def_var(v, zero_ptr);
            }
        }

        let max_q = mir_fn
            .query_bindings
            .len()
            .max(sys_entry.map_or(0, |e| {
                e.wire_queries.len()
                    + e.resource_queries.len()
                    + e.extra_obj_queries.len()
                    + e.stream_queries.len()
            }))
            .max(1);
        let mut iter_vars = Vec::with_capacity(max_q);
        let mut chunk_len_vars = Vec::with_capacity(max_q);
        let zero_i32 = b.ins().iconst(types::I32, 0);
        for _ in 0..max_q {
            let iv = b.declare_var(ptr_ty);
            b.def_var(iv, zero_ptr);
            iter_vars.push(iv);
            let cv = b.declare_var(types::I32);
            b.def_var(cv, zero_i32);
            chunk_len_vars.push(cv);
        }

        let commands_var = b.declare_var(ptr_ty);
        b.def_var(commands_var, obs_commands.unwrap_or(zero_ptr));

        let ptr_vec_hints = compute_ptr_vec_hints(ctx, mir_fn);
        Self {
            ctx,
            mir_fn,
            b,
            cl_blocks,
            mode,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            obs_entity,
            obs_event_data,
            obs_commands,
            mig_src,
            mig_dst,
            helper_out_ptr: None,
            local_reps,
            slot_elem_tys,
            agg_slots,
            agg_slot_tys,
            dirty_targets,
            iter_vars,
            chunk_len_vars,
            commands_var,
            sr_plan,
            ptr_vec_hints,
            const_strings: HashMap::new(),
            const_string_texts: HashMap::new(),
            batch_schemas: HashMap::new(),
            const_defs: HashMap::new(),
            array_elems: HashMap::new(),
            array_ptr_lens,
            ptr_elem_tys,
            ptr_pointee_tys,
            slot_ptr_elem_tys: HashMap::new(),
            slot_ptr_pointee_tys: HashMap::new(),
            slot_array_lens: HashMap::new(),
        }
    }

    pub(super) fn bind_param_val(&mut self, lid: LocalId, vals: &[Value], ty: &MirType) {
        match (&self.local_reps[lid.0 as usize], ty) {
            (LocalRep::Vec(vs), MirType::Vec2 | MirType::IVec2 | MirType::UVec2)
                if vals.len() >= 2 =>
            {
                self.b.def_var(vs[0], vals[0]);
                self.b.def_var(vs[1], vals[1]);
            }
            (LocalRep::Vec(vs), MirType::Vec3 | MirType::IVec3) if vals.len() >= 3 => {
                self.b.def_var(vs[0], vals[0]);
                self.b.def_var(vs[1], vals[1]);
                self.b.def_var(vs[2], vals[2]);
            }
            (LocalRep::Vec(vs), MirType::Vec4) if vals.len() >= 4 => {
                for i in 0..4 {
                    self.b.def_var(vs[i], vals[i]);
                }
            }
            (LocalRep::Scalar(v) | LocalRep::AggVar(v), _) if !vals.is_empty() => {
                self.b.def_var(*v, vals[0]);
            }
            _ => {}
        }
    }

    pub(super) fn use_scalar(&mut self, lid: LocalId) -> Value {
        match self.local_reps[lid.0 as usize] {
            LocalRep::Scalar(v) | LocalRep::AggVar(v) => self.b.use_var(v),
            LocalRep::Vec(vs) => self.b.use_var(vs[0]),
        }
    }

    pub(super) fn effective_local_mir_ty(&self, lid: LocalId) -> &MirType {
        self.slot_elem_tys
            .get(&lid.0)
            .unwrap_or(&self.mir_fn.locals[lid.0 as usize].ty)
    }

    pub(super) fn is_query_term_sparse(
        &self,
        query_idx: u32,
        term_idx: u32,
        storage_key: &str,
    ) -> bool {
        if let Some(qb) = self
            .mir_fn
            .query_bindings
            .iter()
            .find(|qb| qb.query_idx == query_idx)
            && let Some(t) = qb.terms.iter().find(|t| {
                t.term_idx == term_idx || (!storage_key.is_empty() && t.storage_key == storage_key)
            })
            && t.is_sparse
        {
            return true;
        }
        if !storage_key.is_empty()
            && let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, storage_key)
            && (self.ctx.mir_layouts_sorted[lidx].component_flags & BAM_COMPONENT_FLAG_SPARSE_SET)
                != 0
        {
            return true;
        }
        false
    }

    pub(super) fn effective_vec_dims(&self, lid: LocalId) -> Option<u8> {
        vec_dims(self.effective_local_mir_ty(lid))
            .or_else(|| self.ptr_vec_hints.get(&lid.0).map(|&(_, dims)| dims))
    }

    pub(super) fn use_vec(&mut self, lid: LocalId) -> [Value; 4] {
        self.use_vec_dims(lid, 4)
    }

    pub(super) fn use_vec_dims(&mut self, lid: LocalId, fallback_dims: u8) -> [Value; 4] {
        match self.local_reps[lid.0 as usize] {
            LocalRep::Vec(vs) => [
                self.b.use_var(vs[0]),
                self.b.use_var(vs[1]),
                self.b.use_var(vs[2]),
                self.b.use_var(vs[3]),
            ],
            LocalRep::Scalar(v) => {
                let s = self.b.use_var(v);
                let z = self.b.ins().f32const(0.0);
                if matches!(
                    self.effective_local_mir_ty(lid),
                    MirType::Ptr | MirType::MutPtr
                ) {
                    let (off, dims) = self
                        .ptr_vec_hints
                        .get(&lid.0)
                        .copied()
                        .unwrap_or((0, fallback_dims));
                    return self.load_vec_from_ptr(s, off, dims, z);
                }
                let f = coerce_cl_val(self.b, s, types::F32, self.ctx.ptr_ty);
                [f, z, z, z]
            }
            LocalRep::AggVar(v) => {
                let ptr = self.b.use_var(v);
                let eff_ty = self.effective_local_mir_ty(lid).clone();
                let dims = vec_dims(&eff_ty).unwrap_or(fallback_dims);
                if is_ivec_mir_ty(&eff_ty) {
                    let zero = self.b.ins().iconst(types::I32, 0);
                    self.load_ivec_from_ptr(ptr, 0, dims, zero)
                } else {
                    let zero = self.b.ins().f32const(0.0);
                    self.load_vec_from_ptr(ptr, 0, dims, zero)
                }
            }
        }
    }

    pub(super) fn def_vec(&mut self, dst: LocalId, vals: [Value; 4]) {
        match self.local_reps[dst.0 as usize] {
            LocalRep::Vec(vs) => {
                for i in 0..4 {
                    self.b.def_var(vs[i], vals[i]);
                }
            }
            LocalRep::AggVar(v) => {
                let sz = self
                    .ctx
                    .layout_size_of_mir_ty(&self.mir_fn.locals[dst.0 as usize].ty)
                    .max(16);
                let slot = alloc_zero_slot(self.b, sz, self.ctx.ptr_ty);
                let p = self.b.ins().stack_addr(self.ctx.ptr_ty, slot, 0);
                for (i, &lv) in vals.iter().enumerate() {
                    if i * 4 < sz {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), lv, p, (i * 4) as i32);
                    }
                }
                self.b.def_var(v, p);
            }
            LocalRep::Scalar(v) => {
                let target_ty = self.expected_cl_ty(dst);
                let coerced = coerce_cl_val(self.b, vals[0], target_ty, self.ctx.ptr_ty);
                self.b.def_var(v, coerced);
            }
        }
    }

    pub(super) fn expected_cl_ty(&self, lid: LocalId) -> Type {
        self.ctx
            .cl_type_for_mir_val(self.effective_local_mir_ty(lid))
    }

    pub(super) fn def_scalar_typed(&mut self, dst: LocalId, val: Value) {
        let target_ty = self.expected_cl_ty(dst);
        let coerced = coerce_cl_val(self.b, val, target_ty, self.ctx.ptr_ty);
        match self.local_reps[dst.0 as usize] {
            LocalRep::Scalar(v) | LocalRep::AggVar(v) => self.b.def_var(v, coerced),
            LocalRep::Vec(vs) => {
                let lane_ty = if is_ivec_mir_ty(self.effective_local_mir_ty(dst)) {
                    types::I32
                } else {
                    types::F32
                };
                let fv = coerce_cl_val(self.b, val, lane_ty, self.ctx.ptr_ty);
                for v in vs {
                    self.b.def_var(v, fv);
                }
            }
        }
        if let Some(vars) = self.sr_plan.by_base.get(&dst.0) {
            for &pv in vars {
                self.b.def_var(pv, coerced);
            }
        }
    }

    pub(super) fn load_local_from_mem(
        &mut self,
        lid: LocalId,
        mty: &MirType,
        ptr: Value,
        offset: i32,
    ) {
        match mty {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let zero = self.b.ins().f32const(0.0);
                let vals = self.load_vec_from_ptr(ptr, offset, dims, zero);
                self.def_vec(lid, vals);
            }
            MirType::IVec2 | MirType::IVec3 | MirType::UVec2 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let zero = self.b.ins().iconst(types::I32, 0);
                let vals = self.load_ivec_from_ptr(ptr, offset, dims, zero);
                self.def_vec(lid, vals);
            }
            _ => {
                let mem_ty = self.ctx.cl_type_for_mir_val(mty);
                let val = self.b.ins().load(mem_ty, MemFlagsData::new(), ptr, offset);
                let dst_mty = self.effective_local_mir_ty(lid).clone();
                if dst_mty == MirType::Bool {
                    let bval = cast_to_bool(self.b, val, mty);
                    self.def_scalar_typed(lid, bval);
                } else {
                    let target_ty = self.expected_cl_ty(lid);
                    let coerced = cast_value(
                        self.b,
                        val,
                        mty,
                        is_signed_int_ty(mty),
                        target_ty,
                        is_signed_int_ty(&dst_mty),
                        self.ctx.ptr_ty,
                    );
                    self.def_scalar_typed(lid, coerced);
                }
            }
        }
    }

    pub(super) fn coerce_val_to_mir_ty(&mut self, lid: LocalId, dst_mty: &MirType) -> Value {
        let src_mty = self.effective_local_mir_ty(lid).clone();
        let val = self.use_scalar(lid);
        let cdef = self.const_defs.get(&lid.0).cloned();
        self.coerce_raw_val_to_mir_ty(val, &src_mty, cdef.as_ref(), dst_mty)
    }

    pub(super) fn coerce_raw_val_to_mir_ty(
        &mut self,
        val: Value,
        src_mty: &MirType,
        const_def: Option<&MirConstVal>,
        dst_mty: &MirType,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;

        match dst_mty {
            MirType::Fix32 => {
                if *src_mty == MirType::Fix32 {
                    return coerce_cl_val(self.b, val, types::I32, ptr_ty);
                }
                if *src_mty == MirType::Fix64 {
                    let i64v = coerce_cl_val(self.b, val, types::I64, ptr_ty);
                    let sh = self.b.ins().sshr_imm_u(i64v, 16);
                    return self.b.ins().ireduce(types::I32, sh);
                }
                if matches!(src_mty, MirType::F32 | MirType::F64) {
                    if let Some(&MirConstVal::Float(v)) = const_def {
                        let q = if v.is_finite() {
                            (v * 65_536.0).round() as i32
                        } else {
                            0
                        };
                        return self.b.ins().iconst(types::I32, i64::from(q));
                    }
                    let f64v = coerce_cl_val(self.b, val, types::F64, ptr_ty);
                    let abs_f = self.b.ins().fabs(f64v);
                    let inf_f = self.b.ins().f64const(f64::INFINITY);
                    let is_finite = self.b.ins().fcmp(FloatCC::LessThan, abs_f, inf_f);
                    let scale = self.b.ins().f64const(65_536.0);
                    let scaled = self.b.ins().fmul(f64v, scale);
                    let rref = self
                        .ctx
                        .obj_mod
                        .declare_func_in_func(self.ctx.round_fn, self.b.func);
                    let rcall = self.b.ins().call(rref, &[scaled]);
                    let rounded = self.b.inst_results(rcall)[0];
                    let sat = self.b.ins().fcvt_to_sint_sat(types::I32, rounded);
                    let zero = self.b.ins().iconst(types::I32, 0);
                    return self.b.ins().select(is_finite, sat, zero);
                }
                if is_int_mir_ty(src_mty) {
                    if let Some(&MirConstVal::Int(v)) = const_def {
                        let q = v.saturating_mul(65_536) as i32;
                        return self.b.ins().iconst(types::I32, i64::from(q));
                    }
                    let iv = cast_value(
                        self.b,
                        val,
                        src_mty,
                        is_signed_int_ty(src_mty),
                        types::I32,
                        true,
                        ptr_ty,
                    );
                    return self.b.ins().ishl_imm_u(iv, 16);
                }
            }
            MirType::Fix64 => {
                if *src_mty == MirType::Fix64 {
                    return coerce_cl_val(self.b, val, types::I64, ptr_ty);
                }
                if *src_mty == MirType::Fix32 {
                    let i32v = coerce_cl_val(self.b, val, types::I32, ptr_ty);
                    let i64v = self.b.ins().sextend(types::I64, i32v);
                    return self.b.ins().ishl_imm_u(i64v, 16);
                }
                if matches!(src_mty, MirType::F32 | MirType::F64) {
                    if let Some(&MirConstVal::Float(v)) = const_def {
                        let q = if v.is_finite() {
                            (v * 4_294_967_296.0).round() as i64
                        } else {
                            0
                        };
                        return self.b.ins().iconst(types::I64, q);
                    }
                    let f64v = coerce_cl_val(self.b, val, types::F64, ptr_ty);
                    let abs_f = self.b.ins().fabs(f64v);
                    let inf_f = self.b.ins().f64const(f64::INFINITY);
                    let is_finite = self.b.ins().fcmp(FloatCC::LessThan, abs_f, inf_f);
                    let scale = self.b.ins().f64const(4_294_967_296.0);
                    let scaled = self.b.ins().fmul(f64v, scale);
                    let rref = self
                        .ctx
                        .obj_mod
                        .declare_func_in_func(self.ctx.round_fn, self.b.func);
                    let rcall = self.b.ins().call(rref, &[scaled]);
                    let rounded = self.b.inst_results(rcall)[0];
                    let sat = self.b.ins().fcvt_to_sint_sat(types::I64, rounded);
                    let zero = self.b.ins().iconst(types::I64, 0);
                    return self.b.ins().select(is_finite, sat, zero);
                }
                if is_int_mir_ty(src_mty) {
                    if let Some(&MirConstVal::Int(v)) = const_def {
                        return self.b.ins().iconst(types::I64, v.wrapping_shl(32));
                    }
                    let iv = cast_value(
                        self.b,
                        val,
                        src_mty,
                        is_signed_int_ty(src_mty),
                        types::I64,
                        true,
                        ptr_ty,
                    );
                    return self.b.ins().ishl_imm_u(iv, 32);
                }
            }
            MirType::F32 | MirType::F64 => {
                if *src_mty == MirType::Fix32 {
                    let i32v = coerce_cl_val(self.b, val, types::I32, ptr_ty);
                    let f = self.b.ins().fcvt_from_sint(types::F64, i32v);
                    let scale = self.b.ins().f64const(1.0 / 65_536.0);
                    let scaled = self.b.ins().fmul(f, scale);
                    return if *dst_mty == MirType::F32 {
                        self.b.ins().fdemote(types::F32, scaled)
                    } else {
                        scaled
                    };
                }
                if *src_mty == MirType::Fix64 {
                    let i64v = coerce_cl_val(self.b, val, types::I64, ptr_ty);
                    let f = self.b.ins().fcvt_from_sint(types::F64, i64v);
                    let scale = self.b.ins().f64const(1.0 / 4_294_967_296.0);
                    let scaled = self.b.ins().fmul(f, scale);
                    return if *dst_mty == MirType::F32 {
                        self.b.ins().fdemote(types::F32, scaled)
                    } else {
                        scaled
                    };
                }
                if *dst_mty == MirType::F64
                    && *src_mty == MirType::F32
                    && let Some(&MirConstVal::Float(v)) = const_def
                {
                    return self.b.ins().f64const(v);
                }
            }
            _ => {}
        }

        let target_ty = self.ctx.cl_type_for_mir_val(dst_mty);
        if *src_mty == MirType::Fix32 && (is_int_mir_ty(dst_mty) || *dst_mty == MirType::Sym) {
            let i32v = coerce_cl_val(self.b, val, types::I32, ptr_ty);
            let divisor = self.b.ins().iconst(types::I32, 65_536);
            let trunc = self.b.ins().sdiv(i32v, divisor);
            return cast_value(
                self.b,
                trunc,
                &MirType::I32,
                true,
                target_ty,
                is_signed_int_ty(dst_mty),
                ptr_ty,
            );
        }
        if *src_mty == MirType::Fix64 && (is_int_mir_ty(dst_mty) || *dst_mty == MirType::Sym) {
            let i64v = coerce_cl_val(self.b, val, types::I64, ptr_ty);
            let divisor = self.b.ins().iconst(types::I64, 4_294_967_296);
            let trunc = self.b.ins().sdiv(i64v, divisor);
            return cast_value(
                self.b,
                trunc,
                &MirType::I64,
                true,
                target_ty,
                is_signed_int_ty(dst_mty),
                ptr_ty,
            );
        }
        if *dst_mty == MirType::Bool {
            return cast_to_bool(self.b, val, src_mty);
        }
        cast_value(
            self.b,
            val,
            src_mty,
            is_signed_int_ty(src_mty),
            target_ty,
            is_signed_int_ty(dst_mty),
            ptr_ty,
        )
    }

    pub(super) fn store_local_to_mem(
        &mut self,
        lid: LocalId,
        mty: &MirType,
        ptr: Value,
        offset: i32,
    ) {
        match mty {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let vals = self.use_vec(lid);
                for (i, &v) in vals.iter().take(dims as usize).enumerate() {
                    let fv = coerce_cl_val(self.b, v, types::F32, self.ctx.ptr_ty);
                    self.b
                        .ins()
                        .store(MemFlagsData::new(), fv, ptr, offset + (i * 4) as i32);
                }
            }
            MirType::IVec2 | MirType::IVec3 | MirType::UVec2 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let vals = self.use_vec(lid);
                for (i, &v) in vals.iter().take(dims as usize).enumerate() {
                    let iv = coerce_cl_val(self.b, v, types::I32, self.ctx.ptr_ty);
                    self.b
                        .ins()
                        .store(MemFlagsData::new(), iv, ptr, offset + (i * 4) as i32);
                }
            }
            MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
                if self.ctx.is_agg_mir_ty(mty) =>
            {
                let src_ptr = self.use_scalar(lid);
                let sz = self.ctx.layout_size_of_mir_ty(mty);
                let dst_addr = self.b.ins().iadd_imm_s(ptr, i64::from(offset));
                emit_memcpy(self.b, dst_addr, src_ptr, sz);
            }
            _ => {
                let coerced = self.coerce_val_to_mir_ty(lid, mty);
                self.b
                    .ins()
                    .store(MemFlagsData::new(), coerced, ptr, offset);
            }
        }
    }

    pub(super) fn load_vec_from_ptr(
        &mut self,
        ptr: Value,
        offset: i32,
        dims: u8,
        zero: Value,
    ) -> [Value; 4] {
        let mut out = [zero; 4];
        for (i, slot) in out.iter_mut().enumerate().take(usize::from(dims.min(4))) {
            *slot = self.b.ins().load(
                types::F32,
                MemFlagsData::new(),
                ptr,
                offset + (i * 4) as i32,
            );
        }
        out
    }

    pub(super) fn load_ivec_from_ptr(
        &mut self,
        ptr: Value,
        offset: i32,
        dims: u8,
        zero: Value,
    ) -> [Value; 4] {
        let mut out = [zero; 4];
        for (i, slot) in out.iter_mut().enumerate().take(usize::from(dims.min(4))) {
            *slot = self.b.ins().load(
                types::I32,
                MemFlagsData::new(),
                ptr,
                offset + (i * 4) as i32,
            );
        }
        out
    }

    pub(super) fn wire_term_index(&self, query_idx: u32, term_idx: u32) -> usize {
        if let Some(entry) = self.sys_entry
            && let Some(wq) = entry.wire_queries.get(query_idx as usize)
            && let Some(&mapped) = wq.term_map.get(term_idx as usize)
        {
            return mapped;
        }
        term_idx as usize
    }

    pub(super) fn ensure_query_iter(&mut self, query_idx: u32) -> Value {
        let qi = query_idx as usize;
        if qi >= self.iter_vars.len() {
            return self.b.ins().iconst(self.ctx.ptr_ty, 0);
        }
        let iv = self.iter_vars[qi];
        let cur = self.b.use_var(iv);
        let ptr_ty = self.ctx.ptr_ty;
        let need_fetch = self.b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let do_call = self.b.ins().band(need_fetch, ctx_ok);

        let fetch_bb = self.b.create_block();
        let cont_bb = self.b.create_block();
        self.b.ins().brif(do_call, fetch_bb, &[], cont_bb, &[]);

        self.b.switch_to_block(fetch_bb);
        self.b.seal_block(fetch_bb);
        let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        let qv = self.b.ins().iconst(ptr_ty, i64::from(query_idx));
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::SYS_QUERY,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, qv, out_ptr],
        );
        let fetched = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
        self.b.def_var(iv, fetched);
        self.b.ins().jump(cont_bb, &[]);

        self.b.switch_to_block(cont_bb);
        self.b.seal_block(cont_bb);
        self.b.use_var(iv)
    }

    pub(super) fn ensure_commands(&mut self) -> Value {
        if let Some(c) = self.obs_commands {
            return c;
        }
        let ptr_ty = self.ctx.ptr_ty;
        let cur = self.b.use_var(self.commands_var);
        let need_fetch = self.b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let do_call = self.b.ins().band(need_fetch, ctx_ok);

        let fetch_bb = self.b.create_block();
        let cont_bb = self.b.create_block();
        self.b.ins().brif(do_call, fetch_bb, &[], cont_bb, &[]);

        self.b.switch_to_block(fetch_bb);
        self.b.seal_block(fetch_bb);
        let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::SYS_COMMANDS,
            &[ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, out_ptr],
        );
        let fetched = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
        self.b.def_var(self.commands_var, fetched);
        self.b.ins().jump(cont_bb, &[]);

        self.b.switch_to_block(cont_bb);
        self.b.seal_block(cont_bb);
        self.b.use_var(self.commands_var)
    }

    pub(super) fn emit_par_dispatch(
        &mut self,
        info: &ParSubCfgInfo,
        task_fid: FuncId,
        offsets: &[usize],
    ) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(info.query_idx);
        let mut frame_bytes = self.ctx.ptr_bytes;
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let extra = match self.effective_local_mir_ty(LocalId(lid)) {
                MirType::Vec2
                | MirType::Vec3
                | MirType::Vec4
                | MirType::IVec2
                | MirType::IVec3
                | MirType::UVec2 => 16,
                _ => 8,
            };
            frame_bytes = frame_bytes.max(off + extra);
        }
        let frame_slot = alloc_zero_slot(self.b, frame_bytes, ptr_ty);
        let frame_ptr = self.b.ins().stack_addr(ptr_ty, frame_slot, 0);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), self.state_ptr, frame_ptr, 0);
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let mty = self.effective_local_mir_ty(LocalId(lid)).clone();
            self.store_local_to_mem(LocalId(lid), &mty, frame_ptr, off as i32);
        }
        let fref = self.ctx.obj_mod.declare_func_in_func(task_fid, self.b.func);
        let fn_addr = self.b.ins().func_addr(ptr_ty, fref);
        let vtable_slot = if info.is_readonly {
            api_slots::PAR_FOR_EACH_CHUNK_READONLY
        } else {
            api_slots::PAR_FOR_EACH_CHUNK
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, fn_addr, frame_ptr],
        );
        Ok(())
    }

    pub(super) fn lower_terminator(&mut self, term: &Terminator) {
        match term {
            Terminator::Return(opt_val) => {
                if self.mode == MirCallbackMode::Helper {
                    self.emit_helper_return(*opt_val);
                } else {
                    let ok = self.b.ins().iconst(types::I32, i64::from(FFI_OK));
                    self.b.ins().return_(&[ok]);
                }
            }
            Terminator::Goto(dst) => {
                let target = self.cl_blocks[dst.0 as usize];
                self.b.ins().jump(target, &[]);
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let c = self.use_scalar(*cond);
                let tb = self.cl_blocks[then_bb.0 as usize];
                let eb = self.cl_blocks[else_bb.0 as usize];
                self.b.ins().brif(c, tb, &[], eb, &[]);
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                let sv = self.use_scalar(*scrutinee);
                let mut sw = Switch::new();
                for &(k, bb) in cases {
                    sw.set_entry(u128::from(k), self.cl_blocks[bb.0 as usize]);
                }
                sw.emit(self.b, sv, self.cl_blocks[default_bb.0 as usize]);
            }
        }
    }

    pub(super) fn emit_helper_return(&mut self, opt_val: Option<LocalId>) {
        if self.mir_fn.ret_ty == MirType::Unit {
            self.b.ins().return_(&[]);
            return;
        }
        let Some(lid) = opt_val else {
            self.emit_default_helper_return();
            return;
        };
        match self.mir_fn.ret_ty {
            MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => {
                let vs = self.use_vec(lid);
                self.b.ins().return_(&[vs[0], vs[1]]);
            }
            MirType::Vec3 | MirType::IVec3 => {
                let vs = self.use_vec(lid);
                if let Some(out_ptr) = self.helper_out_ptr {
                    for (i, &v) in vs[..3].iter().enumerate() {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), v, out_ptr, (i * 4) as i32);
                    }
                    self.b.ins().return_(&[]);
                } else {
                    self.b.ins().return_(&[vs[0], vs[1], vs[2]]);
                }
            }
            MirType::Vec4 => {
                let vs = self.use_vec(lid);
                if let Some(out_ptr) = self.helper_out_ptr {
                    for (i, &v) in vs.iter().enumerate() {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), v, out_ptr, (i * 4) as i32);
                    }
                    self.b.ins().return_(&[]);
                } else {
                    self.b.ins().return_(&vs);
                }
            }
            _ => {
                let ret_mty = self.mir_fn.ret_ty.clone();
                let v = if matches!(ret_mty, MirType::Ptr | MirType::MutPtr)
                    || self.ctx.is_agg_mir_ty(&ret_mty)
                {
                    self.use_scalar(lid)
                } else {
                    self.coerce_val_to_mir_ty(lid, &ret_mty)
                };
                let rty = self.b.func.signature.returns[0].value_type;
                let cv = coerce_cl_val(self.b, v, rty, self.ctx.ptr_ty);
                self.b.ins().return_(&[cv]);
            }
        }
    }

    pub(super) fn emit_default_helper_return(&mut self) {
        if let Some(out_ptr) = self.helper_out_ptr {
            let zero = self.b.ins().iconst(types::I64, 0);
            self.b.ins().store(MemFlagsData::new(), zero, out_ptr, 0);
            self.b.ins().store(MemFlagsData::new(), zero, out_ptr, 8);
            self.b.ins().return_(&[]);
            return;
        }
        let rets: Vec<Type> = self
            .b
            .func
            .signature
            .returns
            .iter()
            .map(|r| r.value_type)
            .collect();
        let vals: Vec<Value> = rets
            .into_iter()
            .map(|t| zero_for_cl_type(self.b, t))
            .collect();
        self.b.ins().return_(&vals);
    }
}

pub(super) fn vec_dims(ty: &MirType) -> Option<u8> {
    match ty {
        MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => Some(2),
        MirType::Vec3 | MirType::IVec3 => Some(3),
        MirType::Vec4 => Some(4),
        _ => None,
    }
}

pub(super) fn is_ivec_mir_ty(ty: &MirType) -> bool {
    matches!(ty, MirType::IVec2 | MirType::IVec3 | MirType::UVec2)
}

pub(super) fn is_signed_int_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64 | MirType::Fix32 | MirType::Fix64
    )
}

pub(super) fn is_int_mir_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
    )
}

pub(super) fn common_int_ty(
    a: &MirType,
    b: &MirType,
    dst: &MirType,
    ptr_ty: Type,
    cc: CallConv,
) -> Type {
    if matches!(
        a,
        MirType::Ptr
            | MirType::MutPtr
            | MirType::Entity
            | MirType::U64
            | MirType::I64
            | MirType::QueryIter
            | MirType::Checkpoint
    ) || matches!(
        b,
        MirType::Ptr
            | MirType::MutPtr
            | MirType::Entity
            | MirType::U64
            | MirType::I64
            | MirType::QueryIter
            | MirType::Checkpoint
    ) {
        return if ptr_ty == types::I32 {
            types::I64
        } else {
            ptr_ty
        };
    }
    if matches!(a, MirType::U32 | MirType::I32 | MirType::Sym)
        || matches!(b, MirType::U32 | MirType::I32 | MirType::Sym)
    {
        return types::I32;
    }
    if matches!(a, MirType::U16 | MirType::I16) || matches!(b, MirType::U16 | MirType::I16) {
        return types::I16;
    }
    if *dst == MirType::Bool {
        return types::I8;
    }
    scalar_cl_type(a, cc)
}

pub(super) fn is_cmp_op(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=")
}

pub(super) fn float_binop(
    b: &mut FunctionBuilder<'_>,
    fty: Type,
    op: &str,
    l: Value,
    r: Value,
) -> Value {
    match op {
        "+" => b.ins().fadd(l, r),
        "-" => b.ins().fsub(l, r),
        "*" => b.ins().fmul(l, r),
        "/" => b.ins().fdiv(l, r),
        "%" => {
            let q = b.ins().fdiv(l, r);
            let tq = b.ins().trunc(q);
            let p = b.ins().fmul(tq, r);
            b.ins().fsub(l, p)
        }
        _ => {
            let _ = fty;
            l
        }
    }
}

pub(super) fn float_cmp(b: &mut FunctionBuilder<'_>, op: &str, l: Value, r: Value) -> Value {
    let cc = match op {
        "!=" => FloatCC::NotEqual,
        "<" => FloatCC::LessThan,
        "<=" => FloatCC::LessThanOrEqual,
        ">" => FloatCC::GreaterThan,
        ">=" => FloatCC::GreaterThanOrEqual,
        _ => FloatCC::Equal,
    };
    b.ins().fcmp(cc, l, r)
}

fn signed_div_rem_guarded(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    is_rem: bool,
    l: Value,
    r: Value,
) -> Value {
    let min_bits: i64 = match ty {
        types::I8 => i64::from(i8::MIN),
        types::I16 => i64::from(i16::MIN),
        types::I32 => i64::from(i32::MIN),
        _ => i64::MIN,
    };
    let is_zero = b.ins().icmp_imm_s(IntCC::Equal, r, 0);
    let min_v = b.ins().iconst(ty, min_bits);
    let is_min = b.ins().icmp(IntCC::Equal, l, min_v);
    let is_neg1 = b.ins().icmp_imm_s(IntCC::Equal, r, -1);
    let is_overflow = b.ins().band(is_min, is_neg1);
    let bad = b.ins().bor(is_zero, is_overflow);

    let ok_bb = b.create_block();
    let bad_bb = b.create_block();
    let done_bb = b.create_block();
    b.append_block_param(done_bb, ty);
    b.ins().brif(bad, bad_bb, &[], ok_bb, &[]);

    b.switch_to_block(ok_bb);
    b.seal_block(ok_bb);
    let q = if is_rem {
        b.ins().srem(l, r)
    } else {
        b.ins().sdiv(l, r)
    };
    b.ins().jump(done_bb, &[BlockArg::Value(q)]);

    b.switch_to_block(bad_bb);
    b.seal_block(bad_bb);
    let z = b.ins().iconst(ty, 0);
    let fallback = if is_rem {
        z
    } else {
        b.ins().select(is_overflow, l, z)
    };
    b.ins().jump(done_bb, &[BlockArg::Value(fallback)]);

    b.switch_to_block(done_bb);
    b.seal_block(done_bb);
    b.block_params(done_bb)[0]
}

pub(super) fn guarded_sdiv(b: &mut FunctionBuilder<'_>, ty: Type, l: Value, r: Value) -> Value {
    signed_div_rem_guarded(b, ty, false, l, r)
}

pub(super) fn self_block_div(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    signed: bool,
    is_rem: bool,
    l: Value,
    r: Value,
    ok_bb: Block,
    zero_bb: Block,
    done_bb: Block,
) -> Value {
    b.switch_to_block(ok_bb);
    b.seal_block(ok_bb);
    let q = match (signed, is_rem) {
        (true, false) => b.ins().sdiv(l, r),
        (false, false) => b.ins().udiv(l, r),
        (true, true) => b.ins().srem(l, r),
        (false, true) => b.ins().urem(l, r),
    };
    b.ins().jump(done_bb, &[BlockArg::Value(q)]);

    b.switch_to_block(zero_bb);
    b.seal_block(zero_bb);
    let z = b.ins().iconst(ty, 0);
    b.ins().jump(done_bb, &[BlockArg::Value(z)]);

    b.switch_to_block(done_bb);
    b.seal_block(done_bb);
    b.block_params(done_bb)[0]
}

pub(super) fn int_binop_or_cmp(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    signed: bool,
    op: &str,
    l: Value,
    r: Value,
) -> Value {
    match op {
        "+" => b.ins().iadd(l, r),
        "-" => b.ins().isub(l, r),
        "*" => b.ins().imul(l, r),
        "/" => {
            if signed {
                signed_div_rem_guarded(b, ty, false, l, r)
            } else {
                let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
                let ok_bb = b.create_block();
                let zero_bb = b.create_block();
                let done_bb = b.create_block();
                b.append_block_param(done_bb, ty);
                b.ins().brif(nz, ok_bb, &[], zero_bb, &[]);
                self_block_div(b, ty, false, false, l, r, ok_bb, zero_bb, done_bb)
            }
        }
        "%" => {
            if signed {
                signed_div_rem_guarded(b, ty, true, l, r)
            } else {
                let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
                let ok_bb = b.create_block();
                let zero_bb = b.create_block();
                let done_bb = b.create_block();
                b.append_block_param(done_bb, ty);
                b.ins().brif(nz, ok_bb, &[], zero_bb, &[]);
                self_block_div(b, ty, false, true, l, r, ok_bb, zero_bb, done_bb)
            }
        }
        "&" | "&&" => b.ins().band(l, r),
        "|" | "||" => b.ins().bor(l, r),
        "^" => b.ins().bxor(l, r),
        "<<" => b.ins().ishl(l, r),
        ">>" => {
            if signed {
                b.ins().sshr(l, r)
            } else {
                b.ins().ushr(l, r)
            }
        }
        "==" => b.ins().icmp(IntCC::Equal, l, r),
        "!=" => b.ins().icmp(IntCC::NotEqual, l, r),
        "<" => b.ins().icmp(
            if signed {
                IntCC::SignedLessThan
            } else {
                IntCC::UnsignedLessThan
            },
            l,
            r,
        ),
        "<=" => b.ins().icmp(
            if signed {
                IntCC::SignedLessThanOrEqual
            } else {
                IntCC::UnsignedLessThanOrEqual
            },
            l,
            r,
        ),
        ">" => b.ins().icmp(
            if signed {
                IntCC::SignedGreaterThan
            } else {
                IntCC::UnsignedGreaterThan
            },
            l,
            r,
        ),
        ">=" => b.ins().icmp(
            if signed {
                IntCC::SignedGreaterThanOrEqual
            } else {
                IntCC::UnsignedGreaterThanOrEqual
            },
            l,
            r,
        ),
        _ => l,
    }
}

pub(super) fn apply_min_max(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    is_min: bool,
    signed: bool,
    a: Value,
    v: Value,
) -> Value {
    if ty == types::F32 || ty == types::F64 {
        if is_min {
            b.ins().fmin(a, v)
        } else {
            b.ins().fmax(a, v)
        }
    } else if signed {
        if is_min {
            b.ins().smin(a, v)
        } else {
            b.ins().smax(a, v)
        }
    } else if is_min {
        b.ins().umin(a, v)
    } else {
        b.ins().umax(a, v)
    }
}

pub(super) fn cast_to_bool(b: &mut FunctionBuilder<'_>, val: Value, src_mty: &MirType) -> Value {
    let from = b.func.dfg.value_type(val);
    if matches!(src_mty, MirType::F32 | MirType::F64) || from == types::F32 || from == types::F64 {
        let z = if from == types::F64 {
            b.ins().f64const(0.0)
        } else {
            b.ins().f32const(0.0)
        };
        return b.ins().fcmp(FloatCC::NotEqual, val, z);
    }
    b.ins().icmp_imm_s(IntCC::NotEqual, val, 0)
}

fn emit_fcvt_to_sint_sat(b: &mut FunctionBuilder<'_>, to: Type, val: Value) -> Value {
    if to == types::I8 || to == types::I16 {
        let wide = b.ins().fcvt_to_sint_sat(types::I32, val);
        let (min_v, max_v) = if to == types::I8 {
            (i64::from(i8::MIN), i64::from(i8::MAX))
        } else {
            (i64::from(i16::MIN), i64::from(i16::MAX))
        };
        let min_c = b.ins().iconst(types::I32, min_v);
        let max_c = b.ins().iconst(types::I32, max_v);
        let lo = b.ins().smax(wide, min_c);
        let clamped = b.ins().smin(lo, max_c);
        b.ins().ireduce(to, clamped)
    } else {
        b.ins().fcvt_to_sint_sat(to, val)
    }
}

fn emit_fcvt_to_uint_sat(b: &mut FunctionBuilder<'_>, to: Type, val: Value) -> Value {
    if to == types::I8 || to == types::I16 {
        let wide = b.ins().fcvt_to_uint_sat(types::I32, val);
        let max_v = if to == types::I8 {
            i64::from(u8::MAX)
        } else {
            i64::from(u16::MAX)
        };
        let max_c = b.ins().iconst(types::I32, max_v);
        let clamped = b.ins().umin(wide, max_c);
        b.ins().ireduce(to, clamped)
    } else {
        b.ins().fcvt_to_uint_sat(to, val)
    }
}

pub(super) fn coerce_cl_val(
    b: &mut FunctionBuilder<'_>,
    val: Value,
    to: Type,
    ptr_ty: Type,
) -> Value {
    let from = b.func.dfg.value_type(val);
    if from == to {
        return val;
    }
    if from == types::F32 && to == types::F64 {
        return b.ins().fpromote(types::F64, val);
    }
    if from == types::F64 && to == types::F32 {
        return b.ins().fdemote(types::F32, val);
    }
    if (from == types::F32 || from == types::F64) && to.is_int() {
        return emit_fcvt_to_sint_sat(b, to, val);
    }
    if from.is_int() && (to == types::F32 || to == types::F64) {
        return b.ins().fcvt_from_sint(to, val);
    }
    if from.is_int() && to.is_int() {
        let fb = from.bits();
        let tb = to.bits();
        if tb > fb {
            return b.ins().uextend(to, val);
        }
        return b.ins().ireduce(to, val);
    }
    let _ = ptr_ty;
    val
}

pub(super) fn cast_value(
    b: &mut FunctionBuilder<'_>,
    val: Value,
    src_mty: &MirType,
    src_signed: bool,
    dst_ty: Type,
    dst_signed: bool,
    ptr_ty: Type,
) -> Value {
    let from = b.func.dfg.value_type(val);
    if from == dst_ty {
        return val;
    }
    if *src_mty == MirType::Bool && (dst_ty == types::F32 || dst_ty == types::F64) {
        return b.ins().fcvt_from_uint(dst_ty, val);
    }
    if (from == types::F32 || from == types::F64) && dst_ty.is_int() {
        if dst_signed {
            return emit_fcvt_to_sint_sat(b, dst_ty, val);
        }
        return emit_fcvt_to_uint_sat(b, dst_ty, val);
    }
    if from.is_int() && (dst_ty == types::F32 || dst_ty == types::F64) {
        if src_signed {
            return b.ins().fcvt_from_sint(dst_ty, val);
        }
        return b.ins().fcvt_from_uint(dst_ty, val);
    }
    if from == types::F32 && dst_ty == types::F64 {
        return b.ins().fpromote(types::F64, val);
    }
    if from == types::F64 && dst_ty == types::F32 {
        return b.ins().fdemote(types::F32, val);
    }
    if from.is_int() && dst_ty.is_int() {
        let fb = from.bits();
        let tb = dst_ty.bits();
        if tb > fb {
            if src_signed {
                return b.ins().sextend(dst_ty, val);
            }
            return b.ins().uextend(dst_ty, val);
        }
        return b.ins().ireduce(dst_ty, val);
    }
    coerce_cl_val(b, val, dst_ty, ptr_ty)
}

pub(super) fn zero_for_cl_type(b: &mut FunctionBuilder<'_>, ty: Type) -> Value {
    if ty == types::F32 {
        b.ins().f32const(0.0)
    } else if ty == types::F64 {
        b.ins().f64const(0.0)
    } else {
        b.ins().iconst(ty, 0)
    }
}

pub(super) fn emit_memcpy(b: &mut FunctionBuilder<'_>, dst: Value, src: Value, size: usize) {
    let mut off = 0usize;
    while off + 8 <= size {
        let v = b
            .ins()
            .load(types::I64, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 8;
    }
    while off + 4 <= size {
        let v = b
            .ins()
            .load(types::I32, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 4;
    }
    while off < size {
        let v = b
            .ins()
            .load(types::I8, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 1;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_vtable(
    module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ret: Option<Type>,
    ptr_ty: Type,
    call_conv: CallConv,
    args: &[Value],
) -> Value {
    let mut sig = Signature::new(call_conv);
    for &p in params {
        sig.params.push(AbiParam::new(p));
    }
    if let Some(r) = ret {
        sig.returns.push(AbiParam::new(r));
    }
    let sig_ref = b.import_signature(sig);
    let _ = module;
    let fn_ptr = b
        .ins()
        .load(ptr_ty, MemFlagsData::trusted(), api_ptr, slot_offset as i32);
    let coerced_args: Vec<Value> = args
        .iter()
        .zip(params.iter())
        .map(|(&a, &p)| coerce_cl_val(b, a, p, ptr_ty))
        .collect();
    let call = b.ins().call_indirect(sig_ref, fn_ptr, &coerced_args);
    b.inst_results(call)
        .first()
        .copied()
        .unwrap_or_else(|| b.ins().iconst(types::I32, 0))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_vtable_guarded(
    module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ret: Type,
    ptr_ty: Type,
    call_conv: CallConv,
    guard_ptr: Value,
    args: &[Value],
) -> Value {
    let ok = b.ins().icmp_imm_s(IntCC::NotEqual, guard_ptr, 0);
    let call_bb = b.create_block();
    let skip_bb = b.create_block();
    let merge_bb = b.create_block();
    b.append_block_param(merge_bb, ret);
    b.ins().brif(ok, call_bb, &[], skip_bb, &[]);

    b.switch_to_block(call_bb);
    b.seal_block(call_bb);
    let r = call_vtable(
        module,
        b,
        api_ptr,
        slot_offset,
        params,
        Some(ret),
        ptr_ty,
        call_conv,
        args,
    );
    b.ins().jump(merge_bb, &[BlockArg::Value(r)]);

    b.switch_to_block(skip_bb);
    b.seal_block(skip_bb);
    let z = zero_for_cl_type(b, ret);
    b.ins().jump(merge_bb, &[BlockArg::Value(z)]);

    b.switch_to_block(merge_bb);
    b.seal_block(merge_bb);
    b.block_params(merge_bb)[0]
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_vtable_opt(
    _module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ret: Option<Type>,
    ptr_ty: Type,
    call_conv: CallConv,
    args: &[Value],
) -> Value {
    let fn_ptr = b
        .ins()
        .load(ptr_ty, MemFlagsData::trusted(), api_ptr, slot_offset as i32);
    let ok = b.ins().icmp_imm_s(IntCC::NotEqual, fn_ptr, 0);
    let call_bb = b.create_block();
    let skip_bb = b.create_block();
    let merge_bb = b.create_block();
    let merge_ty = ret.unwrap_or(types::I32);
    b.append_block_param(merge_bb, merge_ty);
    b.ins().brif(ok, call_bb, &[], skip_bb, &[]);

    b.switch_to_block(call_bb);
    b.seal_block(call_bb);
    let mut sig = Signature::new(call_conv);
    for &p in params {
        sig.params.push(AbiParam::new(p));
    }
    if let Some(r) = ret {
        sig.returns.push(AbiParam::new(r));
    }
    let sig_ref = b.import_signature(sig);
    let coerced_args: Vec<Value> = args
        .iter()
        .zip(params.iter())
        .map(|(&a, &p)| coerce_cl_val(b, a, p, ptr_ty))
        .collect();
    let call = b.ins().call_indirect(sig_ref, fn_ptr, &coerced_args);
    let r = b
        .inst_results(call)
        .first()
        .copied()
        .unwrap_or_else(|| zero_for_cl_type(b, merge_ty));
    b.ins().jump(merge_bb, &[BlockArg::Value(r)]);

    b.switch_to_block(skip_bb);
    b.seal_block(skip_bb);
    let z = zero_for_cl_type(b, merge_ty);
    b.ins().jump(merge_bb, &[BlockArg::Value(z)]);

    b.switch_to_block(merge_bb);
    b.seal_block(merge_bb);
    b.block_params(merge_bb)[0]
}

pub(super) fn alloc_zero_slot(b: &mut FunctionBuilder<'_>, size: usize, ptr_ty: Type) -> StackSlot {
    let aligned_sz = align_up(size.max(8), 8) as u32;
    let slot = b.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        aligned_sz,
        3, // 8-byte alignment
    ));
    zero_slot(b, slot, aligned_sz as usize, ptr_ty);
    slot
}

pub(super) fn zero_slot(b: &mut FunctionBuilder<'_>, slot: StackSlot, size: usize, ptr_ty: Type) {
    let words = size.div_ceil(8);
    let z64 = b.ins().iconst(types::I64, 0);
    for w in 0..words {
        b.ins().stack_store(ptr_ty, z64, slot, (w * 8) as i32);
    }
}
