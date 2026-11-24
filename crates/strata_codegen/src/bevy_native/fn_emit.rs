//! BevyNative function, chunk loop, `@par`, statement, and terminator emission.

use super::*;

pub(super) fn emit_helper_functions(
    out: &mut String,
    ctx: &NativeCtx<'_>,
) -> Result<(), CodegenError> {
    for hf in &ctx.mir.fns {
        emit_single_function(out, hf, ctx)?;
    }
    Ok(())
}

pub(super) fn emit_native_functions(
    out: &mut String,
    ctx: &NativeCtx<'_>,
) -> Result<(), CodegenError> {
    for func in &ctx.mir.functions {
        emit_single_function(out, func, ctx)?;
    }
    Ok(())
}

pub(super) fn emit_single_function(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
) -> Result<(), CodegenError> {
    if func.blocks.is_empty() {
        let fname = sanitize_ident(&func.name);
        match &func.kind {
            MirFnKind::HelperFn => writeln!(out, "fn strata_fn_{fname}() {{}}\n").ok(),
            MirFnKind::Migration { .. } => writeln!(out, "pub fn strata_mig_{fname}() {{}}\n").ok(),
            MirFnKind::Observer { .. } => writeln!(out, "fn strata_obs_{fname}() {{}}\n").ok(),
            _ => writeln!(out, "fn strata_sys_{fname}() {{}}\n").ok(),
        };
        return Ok(());
    }

    let (query_plans, up_plans) = build_query_plans(func, ctx);
    let chunk_loops = collect_chunk_loops(func, ctx, &query_plans, &up_plans);
    let analysis = analyze_function(func, ctx, &query_plans, &up_plans, &chunk_loops);

    let fname = sanitize_ident(&func.name);
    let mut sig_params = Vec::new();
    let mut is_observer = false;
    let mut obs_event_info: Option<(String, bool, Option<String>)> = None;

    match &func.kind {
        MirFnKind::HelperFn => {
            let resolve_ref_ty = |pt_opt: Option<&PtrTarget>, fallback_ty: &MirType| -> String {
                if let Some(PtrTarget::ParamPtr {
                    layout_key,
                    projected,
                    ..
                }) = pt_opt
                {
                    if let Some((_, _, fvt)) = projected {
                        return fvt.rust_type();
                    }
                    if let Some(entry) = ctx.find_layout_entry(layout_key) {
                        return entry.struct_name.clone();
                    }
                    let short = layout_key
                        .rsplit("::")
                        .next()
                        .unwrap_or(layout_key.as_str());
                    if let Some(&tidx) = ctx
                        .tags_by_key
                        .get(layout_key.as_str())
                        .or_else(|| ctx.tags_by_key.get(short))
                    {
                        return ctx.tags[tidx].struct_name.clone();
                    }
                    if let Some(en) = ctx
                        .enums_by_key
                        .get(layout_key.as_str())
                        .or_else(|| ctx.enums_by_key.get(short))
                    {
                        return en.rust_repr().to_owned();
                    }
                }
                ValTy::from_mir(fallback_ty, ctx).rust_type()
            };
            for p in &func.params {
                let pname = format!("arg_{}", sanitize_rust_ident(&p.name));
                let pty = match p.kind {
                    HirParamKind::Ref => {
                        let s = resolve_ref_ty(
                            p.local.and_then(|l| analysis.ptr_targets.get(&l)),
                            &p.ty,
                        );
                        format!("&{s}")
                    }
                    HirParamKind::RefMut => {
                        let s = resolve_ref_ty(
                            p.local.and_then(|l| analysis.ptr_targets.get(&l)),
                            &p.ty,
                        );
                        format!("&mut {s}")
                    }
                    _ => ValTy::from_mir(&p.ty, ctx).rust_type(),
                };
                sig_params.push(format!("{pname}: {pty}"));
            }
            for (canon, (vname, is_mut, sname)) in &analysis.implicit_res_map {
                if func.resources.iter().any(|r| r.canonical_name == *canon) {
                    continue;
                }
                if *is_mut {
                    sig_params.push(format!("{vname}: &mut {sname}"));
                } else {
                    sig_params.push(format!("{vname}: &{sname}"));
                }
            }
            let ret_ty = ValTy::from_mir(&func.ret_ty, ctx).rust_type();
            if ret_ty == "()" {
                writeln!(
                    out,
                    "pub(crate) fn strata_fn_{fname}({}) {{",
                    sig_params.join(", ")
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "pub(crate) fn strata_fn_{fname}({}) -> {ret_ty} {{",
                    sig_params.join(", ")
                )
                .ok();
            }
        }
        MirFnKind::Migration {
            src_layout,
            dst_layout,
            ..
        } => {
            let src_s = ctx
                .find_layout_entry(src_layout)
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            let dst_s = ctx
                .find_layout_entry(dst_layout)
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            writeln!(
                out,
                "pub fn strata_mig_{fname}(old_row: &{src_s}, dst_row: &mut {dst_s}) {{"
            )
            .ok();
        }
        MirFnKind::Observer { event, target_comp } => {
            is_observer = true;
            let ev_entry = ctx.find_layout_entry(event);
            let ev_struct = ev_entry
                .as_ref()
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            let is_entity_ev = ev_entry
                .as_ref()
                .is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name));
            obs_event_info = Some((ev_struct.clone(), is_entity_ev, target_comp.clone()));
            sig_params.push(format!("on: On<{ev_struct}>"));
        }
        _ => {}
    }

    if !matches!(func.kind, MirFnKind::HelperFn | MirFnKind::Migration { .. }) {
        // Resources
        for (vname, is_mut, sname) in analysis.res_map.values() {
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{sname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{sname}>"));
            }
        }
        for (idx_name, (vname, is_mut)) in &analysis.spatial_res_map {
            let sname = format!("StrataSpatialBacking_{}", sanitize_ident(idx_name));
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{sname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{sname}>"));
            }
        }
        for (rel_name, (vname, is_mut)) in &analysis.relation_res_map {
            let rname = format!("StrataRelation_{}", sanitize_ident(rel_name));
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{rname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{rname}>"));
            }
        }
        for (canon_stream, mw_name) in &analysis.stream_writers {
            if let Some(entry) = ctx.find_layout_entry(canon_stream) {
                sig_params.push(format!(
                    "mut {mw_name}: MessageWriter<{}>",
                    entry.struct_name
                ));
            }
        }
        for (mr_var, sname, _) in &analysis.stream_readers {
            sig_params.push(format!("mut {mr_var}: MessageReader<{sname}>"));
        }
        if analysis.needs_par_commands {
            sig_params.push("par_commands: ParallelCommands".to_owned());
        } else if analysis.needs_commands {
            sig_params.push("mut commands: Commands".to_owned());
        }
        if analysis.needs_named_objects {
            if analysis.named_objects_mut {
                sig_params.push("mut named_objects: ResMut<StrataNamedObjects>".to_owned());
            } else {
                sig_params.push("named_objects: Res<StrataNamedObjects>".to_owned());
            }
        }
        for (q_var, comp_struct) in analysis.object_queries.values() {
            sig_params.push(format!("{q_var}: Query<Entity, With<{comp_struct}>>"));
        }
        if analysis.needs_trigger_stack {
            sig_params.push("trigger_targets: Res<StrataTriggerTargetStack>".to_owned());
        }
        if let Some((_, _, Some(ref tc))) = obs_event_info
            && let Some(tc_struct) = ctx.resolve_ecs_struct_name(tc)
        {
            sig_params.push(format!("obs_target_q: Query<(), With<{tc_struct}>>"));
        }

        // Queries: non-ParamSet direct Query params + single ParamSet if conflicts exist.
        let mut pset_types = Vec::new();
        for qp in &query_plans {
            let (d_ty, f_ty) = query_rust_types(qp);
            if qp.param_set_idx.is_some() {
                pset_types.push(format!("Query<'static, 'static, {d_ty}, {f_ty}>"));
            } else if qp.has_any_mut {
                sig_params.push(format!("mut {}: Query<{d_ty}, {f_ty}>", qp.param_name));
            } else {
                sig_params.push(format!("{}: Query<{d_ty}, {f_ty}>", qp.param_name));
            }
        }
        for up in &up_plans {
            let up_d_ty = if up.is_mut {
                format!("&'static mut {}", up.struct_name)
            } else {
                format!("&'static {}", up.struct_name)
            };
            if up.param_set_idx.is_some() {
                pset_types.push(format!("Query<'static, 'static, {up_d_ty}>"));
            } else if up.is_mut {
                sig_params.push(format!("mut {}: Query<{up_d_ty}>", up.param_name));
            } else {
                sig_params.push(format!("{}: Query<{up_d_ty}>", up.param_name));
            }
        }
        if analysis.needs_child_of_query {
            sig_params.push("up_child_of_q: Query<&ChildOf>".to_owned());
        }
        if !pset_types.is_empty() {
            sig_params.push(format!("mut q_set: ParamSet<({})>", pset_types.join(", ")));
        }

        if is_observer {
            writeln!(out, "fn strata_obs_{fname}({}) {{", sig_params.join(", ")).ok();
        } else {
            writeln!(out, "fn strata_sys_{fname}({}) {{", sig_params.join(", ")).ok();
        }
    }

    // Observer target component guard
    if let Some((_, is_entity_ev, Some(_))) = &obs_event_info {
        if *is_entity_ev {
            writeln!(
                out,
                "    if obs_target_q.get(on.event().event_target()).is_err() {{ return; }}"
            )
            .ok();
        } else {
            writeln!(
                out,
                "    let __obs_tgt = trigger_targets.0.last().copied().unwrap_or(FfiEntity::NULL);\n\
                 \x20   let Some(__obs_ent) = Entity::try_from_bits(__obs_tgt.to_bits()) else {{ return; }};\n\
                 \x20   if obs_target_q.get(__obs_ent).is_err() {{ return; }}"
            )
            .ok();
        }
    }

    // Bind `StreamIn` parameters from `MessageReader<M>`.
    for (mr_var, _sname, arg_var) in &analysis.stream_readers {
        writeln!(
            out,
            "    let {arg_var}_val = {mr_var}.read().last().copied().unwrap_or_default();\n\
             \x20   let {arg_var} = &{arg_var}_val;"
        )
        .ok();
    }

    // Bind `Value` parameters into their `SlotAlloc` locals for helper functions.
    for p in &func.params {
        if matches!(func.kind, MirFnKind::HelperFn)
            && p.kind == HirParamKind::Value
            && let Some(pl) = p.local
        {
            let vt = &analysis.val_tys[pl.0 as usize];
            writeln!(
                out,
                "    let mut __loc_{}: {} = arg_{};",
                pl.0,
                vt.rust_type(),
                sanitize_rust_ident(&p.name)
            )
            .ok();
        }
    }

    // Determine which locals are strictly inside one chunk loop vs outer function scope.
    let mut block_to_loop: HashMap<BlockId, usize> = HashMap::new();
    for (li, cl) in chunk_loops.iter().enumerate() {
        for &bid in &cl.loop_blocks {
            block_to_loop.insert(bid, li);
        }
    }

    let reachable_blocks = compute_reachable_blocks(func);
    let mut local_used_outer = vec![false; func.locals.len()];
    let mut local_loops: Vec<HashSet<usize>> = vec![HashSet::new(); func.locals.len()];
    for p in &func.params {
        if let Some(pl) = p.local {
            local_used_outer[pl.0 as usize] = true;
        }
    }
    for bb in &func.blocks {
        if !reachable_blocks.contains(&bb.id) {
            continue;
        }
        let loop_opt = block_to_loop.get(&bb.id).copied();
        for st in &bb.stmts {
            if let Some(d) = st.dst {
                if let Some(li) = loop_opt {
                    local_loops[d.0 as usize].insert(li);
                } else {
                    local_used_outer[d.0 as usize] = true;
                }
            }
            for l in inst_used_locals(&st.inst) {
                if let Some(li) = loop_opt {
                    local_loops[l.0 as usize].insert(li);
                } else {
                    local_used_outer[l.0 as usize] = true;
                }
            }
        }
        for l in terminator_used_locals(&bb.terminator) {
            if let Some(li) = loop_opt {
                local_loops[l.0 as usize].insert(li);
            } else {
                local_used_outer[l.0 as usize] = true;
            }
        }
    }

    // Declare outer locals (excluding PtrMarker unless unused, and excluding Value helper params already bound).
    let param_value_locals: HashSet<LocalId> = if matches!(func.kind, MirFnKind::HelperFn) {
        func.params
            .iter()
            .filter(|p| p.kind == HirParamKind::Value)
            .filter_map(|p| p.local)
            .collect()
    } else {
        HashSet::new()
    };

    let has_chunk_return = chunk_loops.iter().any(|cl| {
        !cl.use_par
            && cl.loop_blocks.iter().any(|bid| {
                matches!(
                    func.blocks[bid.0 as usize].terminator,
                    Terminator::Return(_)
                )
            })
    });
    let has_tx_ret_val = analysis.has_checkpoint
        && matches!(func.kind, MirFnKind::HelperFn)
        && !matches!(func.ret_ty, MirType::Unit);

    for (idx, vt) in analysis.val_tys.iter().enumerate() {
        let lid = LocalId(idx as u32);
        if param_value_locals.contains(&lid) {
            continue;
        }
        let is_outer = local_used_outer[idx] || local_loops[idx].len() > 1;
        if is_outer {
            if analysis.array_ptr_locals.contains(&lid) {
                writeln!(out, "    let mut __arr_ptr_idx_{idx}: usize = 0usize;").ok();
            } else if let Some(slot_vt) = analysis.slot_tys.get(&lid) {
                writeln!(
                    out,
                    "    let mut __slot_{idx}: {} = {};",
                    slot_vt.rust_type(),
                    slot_vt.default_expr()
                )
                .ok();
                if analysis.up_cascade_slots.contains(&lid) {
                    writeln!(
                        out,
                        "    let mut __up_flag_{idx}: bool = false;\n    let mut __up_ent_{idx}: Option<Entity> = None;"
                    )
                    .ok();
                }
            } else if analysis.up_cascade_locals.contains(&lid) {
                writeln!(out, "    let mut __up_ent_{idx}: Option<Entity> = None;").ok();
            } else if *vt != ValTy::PtrMarker && *vt != ValTy::Unit {
                writeln!(
                    out,
                    "    let mut __loc_{idx}: {} = {};",
                    vt.rust_type(),
                    vt.default_expr()
                )
                .ok();
            }
        }
    }

    for bp in &analysis.spawn_batches {
        if bp.only_chunk_loop.is_none() {
            writeln!(
                out,
                "    let mut {}: Vec<{}> = Vec::new();",
                bp.var_name, bp.bundle_ty
            )
            .ok();
        }
    }

    if has_chunk_return {
        writeln!(out, "    let mut __returned = false;").ok();
    }
    if has_tx_ret_val {
        let rvt = ValTy::from_mir_ret(&func.ret_ty);
        let def_e = if matches!(func.ret_ty, MirType::Named(_)) {
            "Default::default()".to_owned()
        } else {
            rvt.default_expr()
        };
        let rty = if matches!(func.ret_ty, MirType::Named(_)) {
            ValTy::from_mir(&func.ret_ty, ctx).rust_type()
        } else {
            rvt.rust_type()
        };
        writeln!(out, "    let mut __tx_ret_val: {rty} = {def_e};").ok();
    }

    let tx_streams: Vec<(String, String, String)> = analysis
        .stream_writers
        .iter()
        .enumerate()
        .filter_map(|(i, (canon, mw_var))| {
            ctx.find_layout_entry(canon)
                .map(|e| (format!("Stream_{i}"), mw_var.clone(), e.struct_name.clone()))
        })
        .collect();
    let tx_rels: Vec<(String, String, String)> = analysis
        .relation_res_map
        .iter()
        .enumerate()
        .filter(|(_, (_, (_, is_mut)))| *is_mut)
        .map(|(i, (rel_name, (rel_var, _)))| {
            let p_ty = ctx
                .mir
                .relations
                .iter()
                .find(|r| r.name == *rel_name)
                .and_then(|r| r.payload_layout.as_ref())
                .and_then(|pl| ctx.find_layout_entry(&pl.canonical_name))
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            (format!("Rel_{i}"), rel_var.clone(), p_ty)
        })
        .collect();

    if analysis.has_checkpoint {
        let mut variants = vec!["Spawn(Box<dyn FnOnce(&mut Commands) + Send + Sync>)".to_owned()];
        for (vtag, _, stype) in &tx_streams {
            variants.push(format!("{vtag}({stype})"));
        }
        for (vtag, _, p_ty) in &tx_rels {
            variants.push(format!("{vtag}Insert(Entity, Entity, {p_ty})"));
            variants.push(format!("{vtag}Remove(Entity, Entity)"));
        }
        writeln!(
            out,
            "    #[allow(dead_code)]\n\
             \x20   enum __StrataTxCmd {{ {} }}\n\
             \x20   let mut __tx_cmds: Vec<__StrataTxCmd> = Vec::new();\n\
             \x20   let mut __tx_depth: u32 = 0;\n\
             \x20   let mut __tx_active = false;",
            variants.join(", ")
        )
        .ok();
    }

    // Emit outer CFG loop
    writeln!(
        out,
        "    let mut __bb: u32 = 0;\n    loop {{\n        match __bb {{"
    )
    .ok();
    for bb in &func.blocks {
        if !reachable_blocks.contains(&bb.id) || block_to_loop.contains_key(&bb.id) {
            continue;
        }
        if let Some(cl_idx) = chunk_loops.iter().position(|c| c.hdr_bb == bb.id) {
            let cl = &chunk_loops[cl_idx];
            writeln!(out, "            {} => {{", bb.id.0).ok();
            emit_chunk_loop(
                out,
                func,
                ctx,
                &query_plans,
                &chunk_loops,
                cl,
                &analysis,
                &local_used_outer,
                &local_loops,
                cl_idx,
                has_chunk_return,
            )?;
            if has_chunk_return {
                writeln!(out, "                if __returned {{ break; }}").ok();
            }
            writeln!(out, "                __bb = {};", cl.exit_bb.0).ok();
            writeln!(out, "            }}").ok();
            continue;
        }

        writeln!(out, "            {} => {{", bb.id.0).ok();
        for (si, st) in bb.stmts.iter().enumerate() {
            emit_stmt(
                out,
                func,
                ctx,
                &query_plans,
                &analysis,
                bb.id.0 as usize,
                si,
                st,
                "                ",
                None,
                &HashMap::new(),
            )?;
        }
        emit_terminator(
            out,
            func,
            ctx,
            &analysis,
            &bb.terminator,
            "                ",
            None,
        );
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "            _ => break,\n        }}\n    }}").ok();

    if analysis.has_checkpoint {
        let mut arms = Vec::new();
        if analysis.needs_commands {
            arms.push("__StrataTxCmd::Spawn(f) => f(&mut commands),".to_owned());
        } else {
            arms.push("__StrataTxCmd::Spawn(_) => {},".to_owned());
        }
        for (vtag, mw_var, _) in &tx_streams {
            arms.push(format!(
                "__StrataTxCmd::{vtag}(ev) => {{ {mw_var}.write(ev); }}"
            ));
        }
        for (vtag, rel_var, _) in &tx_rels {
            arms.push(format!(
                "__StrataTxCmd::{vtag}Insert(s, d, p) => {{ {rel_var}.insert(s, d, p); }}"
            ));
            arms.push(format!(
                "__StrataTxCmd::{vtag}Remove(s, d) => {{ {rel_var}.remove(s, d); }}"
            ));
        }
        writeln!(
            out,
            "    for cmd in __tx_cmds {{\n\
             \x20       match cmd {{ {} }}\n\
             \x20   }}",
            arms.join(" ")
        )
        .ok();
    }

    if has_tx_ret_val {
        writeln!(out, "    return __tx_ret_val;").ok();
    } else if matches!(func.kind, MirFnKind::HelperFn) && !matches!(func.ret_ty, MirType::Unit) {
        if matches!(func.ret_ty, MirType::Named(_)) {
            writeln!(out, "    Default::default()").ok();
        } else {
            writeln!(
                out,
                "    {}",
                ValTy::from_mir_ret(&func.ret_ty).default_expr()
            )
            .ok();
        }
    }

    writeln!(out, "}}\n").ok();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_chunk_loop(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    chunk_loops: &[ChunkLoopInfo],
    cl: &ChunkLoopInfo,
    analysis: &FnAnalysis,
    local_used_outer: &[bool],
    local_loops: &[HashSet<usize>],
    cl_idx: usize,
    has_chunk_return: bool,
) -> Result<(), CodegenError> {
    let plan = query_plans
        .iter()
        .find(|p| p.query_idx == cl.query_idx)
        .ok_or_else(|| CodegenError::Unsupported {
            context: func.name.clone(),
            detail: format!("missing QueryEmitPlan for query {}", cl.query_idx),
        })?;

    // Collect outer reduction slots written via ReduceAccum inside this loop.
    let mut reduce_info: Vec<(LocalId, String, ValTy)> = Vec::new();
    for &bid in &cl.loop_blocks {
        for st in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotStore { slot, val } = st.inst
                && local_used_outer[slot.0 as usize]
                && let Some(op_s) = cl.loop_blocks.iter().find_map(|b| {
                    func.blocks[b.0 as usize].stmts.iter().find_map(|s| {
                        if s.dst == Some(val)
                            && let Inst::ReduceAccum { ref op, .. } = s.inst
                        {
                            Some(op.clone())
                        } else {
                            None
                        }
                    })
                })
                && !reduce_info.iter().any(|(l, _, _)| *l == slot)
            {
                let vty = analysis.slot_tys.get(&slot).cloned().unwrap_or(ValTy::F32);
                reduce_info.push((slot, op_s, vty));
            }
        }
    }

    let mut slot_remap: HashMap<LocalId, String> = HashMap::new();
    if cl.use_par && !reduce_info.is_empty() {
        let types: Vec<String> = reduce_info.iter().map(|(_, _, t)| t.rust_type()).collect();
        let vals: Vec<String> = reduce_info
            .iter()
            .map(|(l, _, _)| format!("__slot_{}", l.0))
            .collect();
        let mut tuple_init = vals.join(", ");
        if vals.len() == 1 {
            tuple_init.push(',');
        }
        writeln!(
            out,
            "                let __par_red = std::sync::Mutex::new(({tuple_init}));",
        )
        .ok();
        let _ = types;
    }

    // Capture `on.event()` value before `.for_each` if this is a @par observer.
    if cl.use_par && matches!(func.kind, MirFnKind::Observer { .. }) {
        writeln!(out, "                let __obs_ev_copy = *on.event();").ok();
    }

    let q_access = if let Some(pidx) = plan.param_set_idx {
        format!("q_set.p{pidx}()")
    } else {
        plan.param_name.clone()
    };

    let mut pat_elems = Vec::new();
    if plan.needs_entity {
        pat_elems.push(if plan.uses_row_iter() {
            format!("__q{}_ent", plan.query_idx)
        } else {
            format!("__q{}_entities", plan.query_idx)
        });
    }
    for slot in &plan.slots {
        let mut p = format!("__q{}_raw_{}", plan.query_idx, slot.slot_idx);
        if slot.mode == TermAccessMode::Write || slot.mode == TermAccessMode::OptionalWrite {
            p = format!("mut {p}");
        }
        pat_elems.push(p);
    }
    let pat_str = if pat_elems.is_empty() {
        "_".to_owned()
    } else {
        format!("({},)", pat_elems.join(", "))
    };

    if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut pat_elems_ro = Vec::new();
        let mut map_elems = Vec::new();
        if plan.needs_entity {
            pat_elems_ro.push("__se".to_owned());
            map_elems.push("__se".to_owned());
        }
        for slot in &plan.slots {
            let si = slot.slot_idx;
            pat_elems_ro.push(format!("__s{si}"));
            match slot.mode {
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite => {
                    map_elems.push(format!("__s{si}.copied()"));
                }
                _ => map_elems.push(format!("*__s{si}")),
            }
            if slot.mode == TermAccessMode::SelectiveWrite
                || (slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked)
            {
                map_elems.push("false".to_owned());
            }
        }
        let pat_ro = format!("({},)", pat_elems_ro.join(", "));
        let map_out = format!("({},)", map_elems.join(", "));
        writeln!(
            out,
            "                let mut __q{qi}_snap: Vec<_> = {q_access}.iter().map(|{pat_ro}| {map_out}).collect();\n\
             \x20               #[allow(unused_mut)]\n\
             \x20               let mut __broke_loop = false;\n\
             \x20               for __q{qi}_srow in &mut __q{qi}_snap {{\n\
             \x20                   if __broke_loop {{ break; }}"
        )
        .ok();
    } else if plan.uses_row_iter() {
        let iter_m = if plan.has_any_mut {
            "iter_mut()"
        } else {
            "iter()"
        };
        writeln!(
            out,
            "                #[allow(unused_mut)]\n\
             \x20               let mut __broke_loop = false;\n\
             \x20               for {pat_str} in {q_access}.{iter_m} {{\n\
             \x20                   if __broke_loop {{ break; }}"
        )
        .ok();
    } else if cl.use_par {
        let par_m = if plan.has_any_mut {
            "strata_contiguous_par_iter_mut()"
        } else {
            "strata_contiguous_par_iter()"
        };
        writeln!(
            out,
            "                if let Ok(__par_it) = {q_access}.{par_m} {{\n\
             \x20                   __par_it.for_each(|{pat_str}| {{"
        )
        .ok();
    } else {
        let seq_m = if plan.has_any_mut {
            "strata_contiguous_iter_mut()"
        } else {
            "strata_contiguous_iter()"
        };
        writeln!(
            out,
            "                if let Ok(__chunks) = {q_access}.{seq_m} {{\n\
             \x20                   #[allow(unused_mut)]\n\
             \x20                   let mut __broke_loop = false;\n\
             \x20                   for {pat_str} in __chunks {{\n\
             \x20                       if __broke_loop {{ break; }}"
        )
        .ok();
    }

    let indent = "                        ";
    // Convert chunk raw slices / sparse items into uniform per-slot accessors.
    if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut snap_idx = 0usize;
        if plan.needs_entity {
            writeln!(out, "{indent}let __q{qi}_ent = __q{qi}_srow.0;").ok();
            snap_idx = 1;
        }
        for slot in &plan.slots {
            let si = slot.slot_idx;
            match slot.mode {
                TermAccessMode::SelectiveWrite => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_sel_{si} = &mut __q{qi}_srow.{snap_idx};\n\
                         {indent}let mut __q{qi}_dirty_{si} = false;"
                    )
                    .ok();
                    if analysis.has_checkpoint {
                        writeln!(out, "{indent}let mut __q{qi}_tx_dirty_{si} = false;").ok();
                    }
                    snap_idx += 2;
                }
                TermAccessMode::Write => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = &mut __q{qi}_srow.{snap_idx};"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::OptionalWrite if slot.is_untracked => {
                    writeln!(
                        out,
                        "{indent}let mut __q{qi}_sel_{si} = __q{qi}_srow.{snap_idx}.as_mut();\n\
                         {indent}let mut __q{qi}_dirty_{si} = false;"
                    )
                    .ok();
                    if analysis.has_checkpoint {
                        writeln!(out, "{indent}let mut __q{qi}_tx_dirty_{si} = false;").ok();
                    }
                    snap_idx += 2;
                }
                TermAccessMode::OptionalWrite => {
                    writeln!(
                        out,
                        "{indent}let mut __q{qi}_col_{si} = __q{qi}_srow.{snap_idx}.as_mut();"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::OptionalRead => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = __q{qi}_srow.{snap_idx}.as_ref();"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::Read => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = &__q{qi}_srow.{snap_idx};"
                    )
                    .ok();
                    snap_idx += 1;
                }
                _ => {}
            }
        }
    } else {
        for slot in &plan.slots {
            let qi = plan.query_idx;
            let si = slot.slot_idx;
            if plan.uses_row_iter() || cl.is_up_cascade {
                match slot.mode {
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_dirty_{si} = false;"
                        )
                        .ok();
                        if analysis.has_checkpoint {
                            writeln!(out, "{indent}let mut __q{qi}_tx_dirty_{si} = false;").ok();
                        }
                    }
                    TermAccessMode::Write => {
                        writeln!(out, "{indent}let mut __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    TermAccessMode::OptionalWrite if slot.is_untracked => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_dirty_{si} = false;"
                        )
                        .ok();
                        if analysis.has_checkpoint {
                            writeln!(out, "{indent}let mut __q{qi}_tx_dirty_{si} = false;").ok();
                        }
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_opt_own_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_col_{si} = __q{qi}_opt_own_{si}.as_deref_mut();"
                        )
                        .ok();
                    }
                    TermAccessMode::Read | TermAccessMode::OptionalRead => {
                        writeln!(out, "{indent}let __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    _ => {}
                }
            } else {
                match slot.mode {
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = SelectiveMutSlice::from_contiguous_mut(__q{qi}_raw_{si});"
                        )
                        .ok();
                        if analysis.has_checkpoint {
                            writeln!(
                                out,
                                "{indent}let mut __q{qi}_tx_rows_{si}: Vec<usize> = Vec::new();"
                            )
                            .ok();
                        }
                    }
                    TermAccessMode::Write => {
                        writeln!(
                            out,
                            "{indent}let __q{qi}_col_{si} = &mut *__q{qi}_raw_{si};"
                        )
                        .ok();
                    }
                    TermAccessMode::OptionalWrite if slot.is_untracked => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = __q{qi}_raw_{si}.map(SelectiveMutSlice::from_contiguous_mut);"
                        )
                        .ok();
                        if analysis.has_checkpoint {
                            writeln!(
                                out,
                                "{indent}let mut __q{qi}_tx_rows_{si}: Vec<usize> = Vec::new();"
                            )
                            .ok();
                        }
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_opt_own_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_col_{si} = __q{qi}_opt_own_{si}.as_deref_mut();"
                        )
                        .ok();
                    }
                    TermAccessMode::Read | TermAccessMode::OptionalRead => {
                        writeln!(out, "{indent}let __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    _ => {}
                }
            }
        }
    }

    // Declare inner-loop-only locals
    for (idx, vt) in analysis.val_tys.iter().enumerate() {
        let lid = LocalId(idx as u32);
        if !local_used_outer[idx]
            && local_loops[idx].len() == 1
            && local_loops[idx].contains(&cl_idx)
        {
            if analysis.array_ptr_locals.contains(&lid) {
                writeln!(out, "{indent}let mut __arr_ptr_idx_{idx}: usize = 0usize;").ok();
            } else if let Some(slot_vt) = analysis.slot_tys.get(&lid) {
                writeln!(
                    out,
                    "{indent}let mut __slot_{idx}: {} = {};",
                    slot_vt.rust_type(),
                    slot_vt.default_expr()
                )
                .ok();
                if analysis.up_cascade_slots.contains(&lid) {
                    writeln!(
                        out,
                        "{indent}let mut __up_flag_{idx}: bool = false;\n{indent}let mut __up_ent_{idx}: Option<Entity> = None;"
                    )
                    .ok();
                }
            } else if analysis.up_cascade_locals.contains(&lid) {
                writeln!(
                    out,
                    "{indent}let mut __up_ent_{idx}: Option<Entity> = None;"
                )
                .ok();
            } else if *vt != ValTy::PtrMarker && *vt != ValTy::Unit {
                writeln!(
                    out,
                    "{indent}let mut __loc_{idx}: {} = {};",
                    vt.rust_type(),
                    vt.default_expr()
                )
                .ok();
            }
        }
    }

    for bp in &analysis.spawn_batches {
        if bp.only_chunk_loop == Some(cl_idx) {
            writeln!(
                out,
                "{indent}let mut {}: Vec<{}> = Vec::new();",
                bp.var_name, bp.bundle_ty
            )
            .ok();
        }
    }

    if cl.use_par && !reduce_info.is_empty() {
        for (ri, (slot_l, op, vty)) in reduce_info.iter().enumerate() {
            let local_var = format!("__chunk_red_{ri}");
            let init_v = reduce_identity_expr(op, vty);
            writeln!(
                out,
                "{indent}let mut {local_var}: {} = {init_v};",
                vty.rust_type()
            )
            .ok();
            slot_remap.insert(*slot_l, local_var);
        }
    }

    writeln!(
        out,
        "{indent}let mut __inner_bb: u32 = {};\n\
         {indent}loop {{\n\
         {indent}    match __inner_bb {{",
        cl.chunk_body_bb.0
    )
    .ok();

    let mut ordered_blocks: Vec<BlockId> = cl.loop_blocks.iter().copied().collect();
    ordered_blocks.sort_by_key(|b| b.0);
    for bid in ordered_blocks {
        if let Some(sub_cl_idx) = chunk_loops
            .iter()
            .position(|c| c.hdr_bb == bid && c.hdr_bb != cl.hdr_bb)
        {
            let sub_cl = &chunk_loops[sub_cl_idx];
            writeln!(out, "{indent}        {} => {{", bid.0).ok();
            emit_chunk_loop(
                out,
                func,
                ctx,
                query_plans,
                chunk_loops,
                sub_cl,
                analysis,
                local_used_outer,
                local_loops,
                sub_cl_idx,
                has_chunk_return,
            )?;
            if has_chunk_return {
                if cl.use_par {
                    writeln!(out, "{indent}            if __returned {{ break; }}").ok();
                } else {
                    writeln!(
                        out,
                        "{indent}            if __returned {{ __broke_loop = true; break; }}"
                    )
                    .ok();
                }
            }
            if sub_cl.exit_bb == cl.hdr_bb {
                writeln!(out, "{indent}            break;").ok();
            } else if sub_cl.exit_bb == cl.exit_bb {
                if cl.use_par {
                    writeln!(out, "{indent}            break;").ok();
                } else {
                    writeln!(
                        out,
                        "{indent}            __broke_loop = true;\n{indent}            break;"
                    )
                    .ok();
                }
            } else {
                writeln!(
                    out,
                    "{indent}            __inner_bb = {};",
                    sub_cl.exit_bb.0
                )
                .ok();
            }
            writeln!(out, "{indent}        }}").ok();
            continue;
        }
        let bb = &func.blocks[bid.0 as usize];
        writeln!(out, "{indent}        {} => {{", bid.0).ok();
        for (si, st) in bb.stmts.iter().enumerate() {
            emit_stmt(
                out,
                func,
                ctx,
                query_plans,
                analysis,
                bid.0 as usize,
                si,
                st,
                "                                    ",
                Some(cl),
                &slot_remap,
            )?;
        }
        emit_terminator(
            out,
            func,
            ctx,
            analysis,
            &bb.terminator,
            "                                    ",
            Some(cl),
        );
        writeln!(out, "{indent}        }}").ok();
    }

    writeln!(
        out,
        "{indent}        _ => break,\n\
         {indent}    }}\n\
         {indent}}}"
    )
    .ok();

    // Flush sparse selective change ticks if any (for non-snapshot loops)
    if (plan.uses_row_iter() || cl.is_up_cascade) && !cl.is_pset_snap {
        for slot in &plan.slots {
            let qi = plan.query_idx;
            let si = slot.slot_idx;
            if slot.mode == TermAccessMode::SelectiveWrite {
                writeln!(
                    out,
                    "{indent}if __q{qi}_dirty_{si} {{ __q{qi}_sel_{si}.set_changed(); }}"
                )
                .ok();
            } else if slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked {
                writeln!(
                    out,
                    "{indent}if __q{qi}_dirty_{si} {{ if let Some(ref mut __opt_sel) = __q{qi}_sel_{si} {{ __opt_sel.set_changed(); }} }}"
                )
                .ok();
            }
        }
    }

    if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut snap_idx = usize::from(plan.needs_entity);
        for slot in &plan.slots {
            let si = slot.slot_idx;
            if slot.mode == TermAccessMode::SelectiveWrite
                || (slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked)
            {
                writeln!(
                    out,
                    "{indent}__q{qi}_srow.{} = __q{qi}_dirty_{si};",
                    snap_idx + 1
                )
                .ok();
                snap_idx += 2;
            } else {
                snap_idx += 1;
            }
        }
    }

    if cl.use_par && !reduce_info.is_empty() {
        writeln!(out, "{indent}if let Ok(mut __g) = __par_red.lock() {{").ok();
        for (ri, (_, op, vty)) in reduce_info.iter().enumerate() {
            let expr =
                reduce_merge_expr(op, vty, &format!("__g.{ri}"), &format!("__chunk_red_{ri}"));
            writeln!(out, "{indent}    __g.{ri} = {expr};").ok();
        }
        writeln!(out, "{indent}}}").ok();
    }

    if cl.is_pset_snap {
        writeln!(out, "                }}").ok();
        if plan.has_any_mut {
            let qi = plan.query_idx;
            writeln!(
                out,
                "                for __q{qi}_srow in __q{qi}_snap {{\n\
                 \x20                   if let Ok(mut __wb) = {q_access}.get_mut(__q{qi}_srow.0) {{"
            )
            .ok();
            let mut snap_idx = usize::from(plan.needs_entity);
            for (tup_idx_base, slot) in plan.slots.iter().enumerate() {
                let tup_idx = tup_idx_base + usize::from(plan.needs_entity);
                match slot.mode {
                    TermAccessMode::Write => {
                        writeln!(
                            out,
                            "                        *__wb.{tup_idx} = __q{qi}_srow.{snap_idx};"
                        )
                        .ok();
                        snap_idx += 1;
                    }
                    TermAccessMode::OptionalWrite if slot.is_untracked => {
                        writeln!(
                            out,
                            "                        if __q{qi}_srow.{} {{ if let (Some(mut __dst), Some(__src)) = (__wb.{tup_idx}, __q{qi}_srow.{snap_idx}) {{ *__dst = __src; }} }}",
                            snap_idx + 1
                        )
                        .ok();
                        snap_idx += 2;
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "                        if let (Some(mut __dst), Some(__src)) = (__wb.{tup_idx}, __q{qi}_srow.{snap_idx}) {{ *__dst = __src; }}"
                        )
                        .ok();
                        snap_idx += 1;
                    }
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "                        if __q{qi}_srow.{} {{ *__wb.{tup_idx} = __q{qi}_srow.{snap_idx}; }}",
                            snap_idx + 1
                        )
                        .ok();
                        snap_idx += 2;
                    }
                    _ => {
                        snap_idx += 1;
                    }
                }
            }
            writeln!(out, "                    }}\n                }}").ok();
        }
    } else if plan.uses_row_iter() {
        writeln!(out, "                }}").ok();
    } else if cl.use_par {
        writeln!(out, "                    }});\n                }}").ok();
        for (ri, (slot_l, _, _)) in reduce_info.iter().enumerate() {
            writeln!(
                out,
                "                if let Ok(__g) = __par_red.lock() {{ __slot_{} = __g.{ri}; }}",
                slot_l.0
            )
            .ok();
        }
    } else {
        writeln!(out, "                    }}\n                }}").ok();
    }
    Ok(())
}

pub(super) fn reduce_identity_expr(op: &str, vty: &ValTy) -> String {
    match op {
        "min" => match vty {
            ValTy::F32 => "f32::MAX".to_owned(),
            ValTy::F64 => "f64::MAX".to_owned(),
            ValTy::U32 => "u32::MAX".to_owned(),
            ValTy::U64 => "u64::MAX".to_owned(),
            ValTy::I32 => "i32::MAX".to_owned(),
            ValTy::I64 => "i64::MAX".to_owned(),
            ValTy::Fix32 => "Fixed32(i32::MAX)".to_owned(),
            ValTy::Fix64 => "Fixed64(i64::MAX)".to_owned(),
            ValTy::Vec2 => "[f32::MAX; 2]".to_owned(),
            ValTy::Vec3 => "[f32::MAX; 3]".to_owned(),
            ValTy::Vec4 => "[f32::MAX; 4]".to_owned(),
            ValTy::IVec2 => "[i32::MAX; 2]".to_owned(),
            ValTy::IVec3 => "[i32::MAX; 3]".to_owned(),
            ValTy::UVec2 => "[u32::MAX; 2]".to_owned(),
            _ => vty.default_expr(),
        },
        "max" => match vty {
            ValTy::F32 => "f32::MIN".to_owned(),
            ValTy::F64 => "f64::MIN".to_owned(),
            ValTy::U32 => "0u32".to_owned(),
            ValTy::U64 => "0u64".to_owned(),
            ValTy::I32 => "i32::MIN".to_owned(),
            ValTy::I64 => "i64::MIN".to_owned(),
            ValTy::Fix32 => "Fixed32(i32::MIN)".to_owned(),
            ValTy::Fix64 => "Fixed64(i64::MIN)".to_owned(),
            ValTy::Vec2 => "[f32::MIN; 2]".to_owned(),
            ValTy::Vec3 => "[f32::MIN; 3]".to_owned(),
            ValTy::Vec4 => "[f32::MIN; 4]".to_owned(),
            ValTy::IVec2 => "[i32::MIN; 2]".to_owned(),
            ValTy::IVec3 => "[i32::MIN; 3]".to_owned(),
            ValTy::UVec2 => "[0u32; 2]".to_owned(),
            _ => vty.default_expr(),
        },
        "prod" => match vty {
            ValTy::F32 => "1.0_f32".to_owned(),
            ValTy::F64 => "1.0_f64".to_owned(),
            ValTy::U8 => "1u8".to_owned(),
            ValTy::U16 => "1u16".to_owned(),
            ValTy::U32 => "1u32".to_owned(),
            ValTy::U64 => "1u64".to_owned(),
            ValTy::I8 => "1i8".to_owned(),
            ValTy::I16 => "1i16".to_owned(),
            ValTy::I32 => "1i32".to_owned(),
            ValTy::I64 => "1i64".to_owned(),
            ValTy::Fix32 => "Fixed32(65536)".to_owned(),
            ValTy::Fix64 => "Fixed64(4294967296)".to_owned(),
            ValTy::Vec2 => "[1.0_f32; 2]".to_owned(),
            ValTy::Vec3 => "[1.0_f32; 3]".to_owned(),
            ValTy::Vec4 => "[1.0_f32; 4]".to_owned(),
            ValTy::IVec2 => "[1i32; 2]".to_owned(),
            ValTy::IVec3 => "[1i32; 3]".to_owned(),
            ValTy::UVec2 => "[1u32; 2]".to_owned(),
            _ => vty.default_expr(),
        },
        "all" => "true".to_owned(),
        _ => vty.default_expr(),
    }
}

pub(super) fn reduce_combine_same_ty(op: &str, vty: &ValTy, acc: &str, rhs: &str) -> String {
    if let Some(d) = vty.is_vec() {
        let lanes: Vec<String> = match op {
            "min" => (0..d)
                .map(|i| format!("__rl[{i}].min(__rr[{i}])"))
                .collect(),
            "max" => (0..d)
                .map(|i| format!("__rl[{i}].max(__rr[{i}])"))
                .collect(),
            "prod" => (0..d).map(|i| format!("__rl[{i}] * __rr[{i}]")).collect(),
            _ => (0..d).map(|i| format!("__rl[{i}] + __rr[{i}]")).collect(),
        };
        return format!(
            "{{ let __rl = {acc}; let __rr = {rhs}; [{}] }}",
            lanes.join(", ")
        );
    }
    if let Some(d) = vty.is_ivec() {
        let lanes: Vec<String> = match op {
            "min" => (0..d)
                .map(|i| format!("__rl[{i}].min(__rr[{i}])"))
                .collect(),
            "max" => (0..d)
                .map(|i| format!("__rl[{i}].max(__rr[{i}])"))
                .collect(),
            "prod" => (0..d)
                .map(|i| format!("__rl[{i}].wrapping_mul(__rr[{i}])"))
                .collect(),
            _ => (0..d)
                .map(|i| format!("__rl[{i}].wrapping_add(__rr[{i}])"))
                .collect(),
        };
        return format!(
            "{{ let __rl = {acc}; let __rr = {rhs}; [{}] }}",
            lanes.join(", ")
        );
    }
    match op {
        "min" => format!("({acc}).min({rhs})"),
        "max" => format!("({acc}).max({rhs})"),
        "prod" => match vty {
            ValTy::Fix32 => {
                format!("Fixed32(((({acc}).0 as i64).wrapping_mul(({rhs}).0 as i64) >> 16) as i32)")
            }
            ValTy::Fix64 => format!(
                "Fixed64(((({acc}).0 as i128).wrapping_mul(({rhs}).0 as i128) >> 32) as i64)"
            ),
            t if t.is_int() => format!("({acc}).wrapping_mul({rhs})"),
            _ => format!("({acc}) * ({rhs})"),
        },
        "any" => format!("({acc}) || ({rhs})"),
        "all" => format!("({acc}) && ({rhs})"),
        _ => {
            if vty.is_int() {
                format!("({acc}).wrapping_add({rhs})")
            } else {
                format!("({acc}) + ({rhs})")
            }
        }
    }
}

pub(super) fn reduce_accum_expr(
    op: &str,
    acc_vt: &ValTy,
    val_vt: &ValTy,
    acc: &str,
    val: &str,
) -> String {
    match op {
        "count" => {
            let inc = if *val_vt == ValTy::Bool {
                format!("(if {val} {{ 1 }} else {{ 0 }})")
            } else if val_vt.is_int() {
                format!("(if ({val}) != 0 {{ 1 }} else {{ 0 }})")
            } else {
                coerce_expr(val, val_vt, acc_vt)
            };
            if acc_vt.is_int() {
                format!("({acc}).wrapping_add({inc})")
            } else {
                format!("({acc}) + ({inc})")
            }
        }
        "any" | "all" => {
            let b = coerce_expr(val, val_vt, &ValTy::Bool);
            reduce_combine_same_ty(op, &ValTy::Bool, acc, &b)
        }
        _ => {
            let rhs = coerce_expr(val, val_vt, acc_vt);
            reduce_combine_same_ty(op, acc_vt, acc, &rhs)
        }
    }
}

pub(super) fn reduce_merge_expr(op: &str, vty: &ValTy, acc: &str, partial: &str) -> String {
    reduce_combine_same_ty(op, vty, acc, partial)
}

fn resolve_entity_local_expr(
    tgt: LocalId,
    func: &MirFunction,
    analysis: &FnAnalysis,
    in_chunk: Option<&ChunkLoopInfo>,
) -> String {
    if analysis.val_tys[tgt.0 as usize] == ValTy::Entity {
        return format!("__loc_{}", tgt.0);
    }
    match analysis.ptr_targets.get(&tgt) {
        Some(PtrTarget::EntityRow { entity_local, .. }) => {
            return resolve_entity_local_expr(*entity_local, func, analysis, in_chunk);
        }
        Some(PtrTarget::QueryRow {
            query_idx,
            row_idx_local,
            ..
        })
        | Some(PtrTarget::QueryEntityRow {
            query_idx,
            row_idx_local,
        }) => {
            return format!(
                "FfiEntity::from_bits(__q{query_idx}_entities[__loc_{} as usize].to_bits())",
                row_idx_local.0
            );
        }
        _ => {}
    }
    if let Some(cl) = in_chunk {
        for &bid in &cl.loop_blocks {
            for s in &func.blocks[bid.0 as usize].stmts {
                if matches!(s.inst, Inst::EntityAtRow { .. })
                    && let Some(ed) = s.dst
                    && analysis.val_tys[ed.0 as usize] == ValTy::Entity
                {
                    return format!("__loc_{}", ed.0);
                }
            }
        }
    }
    "FfiEntity::NULL".to_owned()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_stmt(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    bb_idx: usize,
    _stmt_idx: usize,
    st: &MirStmt,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
    slot_remap: &HashMap<LocalId, String>,
) -> Result<(), CodegenError> {
    let dst_s = st.dst.map(|d| format!("__loc_{}", d.0));
    let dst_ty = st.dst.map(|d| &analysis.val_tys[d.0 as usize]);

    match &st.inst {
        Inst::ConstInt { value } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::PtrMarker || *dt == ValTy::Unit {
                    return Ok(());
                }
                let val_expr = if let Some(&qiter_l) = analysis.sp_lim_clamp.get(&d) {
                    format!("(__loc_{}.len().min({value}) as u32)", qiter_l.0)
                } else {
                    match dt {
                        ValTy::Entity => {
                            if *value == 0 {
                                "FfiEntity::NULL".to_owned()
                            } else {
                                format!("FfiEntity::from_bits(({value}i64) as u64)")
                            }
                        }
                        ValTy::F32 => format_f32_lit(*value as f64),
                        ValTy::F64 => format_f64_lit(*value as f64),
                        ValTy::Fix32 => {
                            format!("Fixed32({})", format_fix32_i32_lit(scale_int_fix32(*value)))
                        }
                        ValTy::Fix64 => {
                            format!("Fixed64({})", format_fix64_i64_lit(scale_int_fix64(*value)))
                        }
                        ValTy::Bool => format!("({value} != 0)"),
                        _ => format!("({value}i64 as {})", dt.rust_type()),
                    }
                };
                writeln!(out, "{indent}__loc_{} = {val_expr};", d.0).ok();
            }
        }
        Inst::ConstFloat { value } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let val_expr = match dt {
                    ValTy::F64 => format_f64_lit(*value),
                    ValTy::Fix32 => format!(
                        "Fixed32({})",
                        format_fix32_i32_lit(scale_float_fix32(*value))
                    ),
                    ValTy::Fix64 => format!(
                        "Fixed64({})",
                        format_fix64_i64_lit(scale_float_fix64(*value))
                    ),
                    _ => format_f32_lit(*value),
                };
                writeln!(out, "{indent}__loc_{} = {val_expr};", d.0).ok();
            }
        }
        Inst::ConstBool { value } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                writeln!(out, "{indent}__loc_{} = {value};", d.0).ok();
            }
        }
        Inst::ConstVec { dims, values } => {
            if let Some(d) = st.dst {
                let expr = match &analysis.val_tys[d.0 as usize] {
                    ValTy::IVec2 => format!("[{}i32, {}i32]", values[0] as i32, values[1] as i32),
                    ValTy::IVec3 => format!(
                        "[{}i32, {}i32, {}i32]",
                        values[0] as i32, values[1] as i32, values[2] as i32
                    ),
                    ValTy::UVec2 => format!("[{}u32, {}u32]", values[0] as u32, values[1] as u32),
                    _ => match dims {
                        2 => format!(
                            "[{}, {}]",
                            format_f32_lit(values[0]),
                            format_f32_lit(values[1])
                        ),
                        3 => format!(
                            "[{}, {}, {}]",
                            format_f32_lit(values[0]),
                            format_f32_lit(values[1]),
                            format_f32_lit(values[2])
                        ),
                        _ => format!(
                            "[{}, {}, {}, {}]",
                            format_f32_lit(values[0]),
                            format_f32_lit(values[1]),
                            format_f32_lit(values[2]),
                            format_f32_lit(values[3])
                        ),
                    },
                };
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::ConstString { value } => {
            if let Some(d) = st.dst {
                let words = match analysis.val_tys[d.0 as usize] {
                    ValTy::InlineStr(cap) => 1 + cap.div_ceil(4),
                    _ => 17,
                };
                writeln!(
                    out,
                    "{indent}__loc_{} = strata_inline_str_pack::<{words}>({value:?});",
                    d.0
                )
                .ok();
            }
        }
        Inst::Copy { val } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::PtrMarker
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                let (src_vt, src_e) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let coerced = coerce_expr(&src_e, &src_vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::BinOp {
            op,
            lhs,
            rhs,
            allow_fma: _,
        } => {
            if let Some(d) = st.dst {
                let expr = emit_binop_expr(
                    op,
                    *lhs,
                    *rhs,
                    &analysis.val_tys[d.0 as usize],
                    analysis,
                    query_plans,
                    in_chunk,
                    ctx,
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::UnOp { op, val } => {
            if let Some(d) = st.dst {
                let (vt, v) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let dt = &analysis.val_tys[d.0 as usize];
                let expr = match op.as_str() {
                    "-" => match vt.is_ivec() {
                        Some(2) => format!("[({v}[0]).wrapping_neg(), ({v}[1]).wrapping_neg()]"),
                        Some(3) => format!(
                            "[({v}[0]).wrapping_neg(), ({v}[1]).wrapping_neg(), ({v}[2]).wrapping_neg()]"
                        ),
                        _ => match vt.is_vec() {
                            Some(2) => format!("[-{v}[0], -{v}[1]]"),
                            Some(3) => format!("[-{v}[0], -{v}[1], -{v}[2]]"),
                            Some(4) => format!("[-{v}[0], -{v}[1], -{v}[2], -{v}[3]]"),
                            _ if matches!(vt, ValTy::Fix32) => {
                                format!("Fixed32(({v}).0.wrapping_neg())")
                            }
                            _ if matches!(vt, ValTy::Fix64) => {
                                format!("Fixed64(({v}).0.wrapping_neg())")
                            }
                            _ if matches!(vt, ValTy::I8 | ValTy::I16 | ValTy::I32 | ValTy::I64) => {
                                format!("({v}).wrapping_neg()")
                            }
                            _ => format!("(-{v})"),
                        },
                    },
                    "!" | "~" => format!("(!{v})"),
                    _ => v,
                };
                let coerced = if op == "-"
                    && analysis.const_floats.contains_key(&d)
                    && matches!(dt, ValTy::Fix32 | ValTy::Fix64 | ValTy::F64)
                {
                    coerce_local_expr(Some(d), &expr, &vt, dt, analysis)
                } else {
                    coerce_expr(&expr, &vt, dt)
                };
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::Cast { val, target_ty } => {
            if let Some(d) = st.dst {
                let (from_vt, ve) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let to_vt = ValTy::from_mir(target_ty, ctx);
                let coerced = coerce_local_expr(Some(*val), &ve, &from_vt, &to_vt, analysis);
                let final_e = coerce_expr(&coerced, &to_vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {final_e};", d.0).ok();
            }
        }
        Inst::VecExtract { vec, lane } => {
            if let Some(d) = st.dst {
                let (_, ve) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                writeln!(out, "{indent}__loc_{} = {ve}[{lane}];", d.0).ok();
            }
        }
        Inst::VecInsert { vec, lane, val } => {
            if let Some(d) = st.dst {
                let (v_vt, v) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                let (val_vt, val_e) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let dt = &analysis.val_tys[d.0 as usize];
                let lane_vt = match dt {
                    ValTy::IVec2 | ValTy::IVec3 => ValTy::I32,
                    ValTy::UVec2 => ValTy::U32,
                    _ => ValTy::F32,
                };
                let scalar = coerce_expr(&val_e, &val_vt, &lane_vt);
                writeln!(
                    out,
                    "{indent}{{ let mut __tv: {} = {}; __tv[{lane}] = {scalar}; __loc_{} = __tv; }}",
                    dt.rust_type(),
                    coerce_expr(&v, &v_vt, dt),
                    d.0
                )
                .ok();
            }
        }
        Inst::VecSwizzle { vec, lanes } => {
            if let Some(d) = st.dst {
                let (_, v) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                let elems: Vec<String> = lanes.iter().map(|l| format!("{v}[{l}]")).collect();
                writeln!(out, "{indent}__loc_{} = [{}];", d.0, elems.join(", ")).ok();
            }
        }
        Inst::IntrinsicMath {
            name,
            args,
            deterministic: _,
        } => {
            if let Some(d) = st.dst {
                let expr = emit_intrinsic_math(
                    name,
                    args,
                    &analysis.val_tys[d.0 as usize],
                    analysis,
                    query_plans,
                    in_chunk,
                    ctx,
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::Call { callee, args } => {
            let hf_opt =
                ctx.helpers_by_key
                    .get(callee.as_str())
                    .copied()
                    .or_else(|| {
                        let short = callee.rsplit("::").next().unwrap_or(callee);
                        ctx.mir.fns.iter().find(|f| {
                            f.name == *callee || f.name.rsplit("::").next() == Some(short)
                        })
                    });
            let needs_places_or_imp = hf_opt.is_some_and(|hf| {
                let mut hres = BTreeMap::new();
                collect_helper_implicit_res(&hf.name, ctx, &mut hres, &mut HashSet::new());
                let has_imp = hres
                    .keys()
                    .any(|canon| !hf.resources.iter().any(|r| r.canonical_name == *canon));
                has_imp
                    || hf
                        .params
                        .iter()
                        .any(|p| matches!(p.kind, HirParamKind::Ref | HirParamKind::RefMut))
            });
            if let Some(hf) = hf_opt
                && needs_places_or_imp
            {
                let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
                emit_helper_call_with_places(
                    out,
                    func,
                    hf,
                    args,
                    st.dst,
                    ctx,
                    analysis,
                    query_plans,
                    indent,
                    in_chunk,
                    in_undo,
                );
            } else {
                let expr =
                    emit_call_expr(callee, args, dst_ty, ctx, analysis, query_plans, in_chunk)?;
                if let Some(d) = st.dst {
                    let dt = &analysis.val_tys[d.0 as usize];
                    if *dt != ValTy::Unit && *dt != ValTy::PtrMarker {
                        writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
                    } else {
                        writeln!(out, "{indent}let _ = {expr};").ok();
                    }
                } else {
                    writeln!(out, "{indent}{expr};").ok();
                }
            }
        }
        Inst::StructInit { type_name, fields } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::Unit || *dt == ValTy::PtrMarker {
                    return Ok(());
                }
                if type_name == "tuple" {
                    let parts: Vec<String> = fields
                        .iter()
                        .enumerate()
                        .map(|(idx, (_, l))| {
                            let (src_vt, raw_expr) = effective_local_val_and_expr(
                                *l,
                                analysis,
                                query_plans,
                                in_chunk,
                                ctx,
                            );
                            let local_opt =
                                (analysis.val_tys[l.0 as usize] != ValTy::PtrMarker).then_some(*l);
                            if let ValTy::Tuple(ref item_tys) = *dt
                                && let Some(dst_item_vt) = item_tys.get(idx)
                            {
                                coerce_local_expr(
                                    local_opt,
                                    &raw_expr,
                                    &src_vt,
                                    dst_item_vt,
                                    analysis,
                                )
                            } else {
                                raw_expr
                            }
                        })
                        .collect();
                    writeln!(out, "{indent}__loc_{} = ({});", d.0, parts.join(", ")).ok();
                } else if ctx.is_zst_component(type_name) {
                    let sname = ctx
                        .resolve_ecs_struct_name(type_name)
                        .unwrap_or_else(|| dt.rust_type());
                    writeln!(out, "{indent}__loc_{} = {sname};", d.0).ok();
                } else if let Some(entry) = ctx.find_layout_entry(type_name) {
                    let mut finits = Vec::new();
                    for (fname, flocal) in fields {
                        let rfname = sanitize_rust_ident(fname);
                        let (mut src_vt, mut raw_expr) = effective_local_val_and_expr(
                            *flocal,
                            analysis,
                            query_plans,
                            in_chunk,
                            ctx,
                        );
                        let fval = if let Some(sf) =
                            entry.layout.fields.iter().find(|f| f.name == *fname)
                        {
                            let dst_vt = ValTy::from_solved_field(sf, ctx);
                            if dst_vt == ValTy::Entity && src_vt != ValTy::Entity {
                                raw_expr =
                                    resolve_entity_local_expr(*flocal, func, analysis, in_chunk);
                                src_vt = ValTy::Entity;
                            }
                            let local_opt = (analysis.val_tys[flocal.0 as usize]
                                != ValTy::PtrMarker)
                                .then_some(*flocal);
                            let e =
                                coerce_local_expr(local_opt, &raw_expr, &src_vt, &dst_vt, analysis);
                            wrap_abi_field_store(
                                &e,
                                sf,
                                ctx,
                                entry.layout.item_kind == SchemaItemKind::Event
                                    && ctx.entity_events.contains(&entry.layout.canonical_name),
                            )
                        } else {
                            raw_expr
                        };
                        finits.push(format!("{rfname}: {fval}"));
                    }
                    if finits.is_empty() {
                        writeln!(
                            out,
                            "{indent}__loc_{} = {}::default();",
                            d.0, entry.struct_name
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "{indent}__loc_{} = {} {{ {}, ..Default::default() }};",
                            d.0,
                            entry.struct_name,
                            finits.join(", ")
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::ArrayInit { elems } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let elem_vt = match dt {
                    ValTy::Array(ev, _) | ValTy::SmallVec { elem: ev, .. } => Some(ev.as_ref()),
                    _ => None,
                };
                let parts: Vec<String> = elems
                    .iter()
                    .map(|l| {
                        let (src_vt, raw) =
                            effective_local_val_and_expr(*l, analysis, query_plans, in_chunk, ctx);
                        let local_opt =
                            (analysis.val_tys[l.0 as usize] != ValTy::PtrMarker).then_some(*l);
                        if let Some(target_ev) = elem_vt {
                            coerce_local_expr(local_opt, &raw, &src_vt, target_ev, analysis)
                        } else {
                            raw
                        }
                    })
                    .collect();
                let arr_expr = format!("[{}]", parts.join(", "));
                let final_expr = if matches!(dt, ValTy::SmallVec { .. }) {
                    let src_arr = ValTy::Array(
                        Box::new(elem_vt.cloned().unwrap_or(ValTy::U32)),
                        elems.len(),
                    );
                    coerce_expr(&arr_expr, &src_arr, dt)
                } else {
                    arr_expr
                };
                writeln!(out, "{indent}__loc_{} = {final_expr};", d.0).ok();
            }
        }
        Inst::ArrayIndex { base, index } => {
            if let Some(d) = st.dst {
                let idx_e = coerce_expr(
                    &format!("__loc_{}", index.0),
                    &analysis.val_tys[index.0 as usize],
                    &ValTy::U64,
                );
                if analysis.array_ptr_locals.contains(&d) {
                    writeln!(out, "{indent}__arr_ptr_idx_{} = ({idx_e}) as usize;", d.0).ok();
                    return Ok(());
                }
                let dt = &analysis.val_tys[d.0 as usize];
                let def_e = dt.default_expr();
                if analysis.ptr_targets.contains_key(base) {
                    let meta = analysis
                        .field_ptr_array_meta
                        .get(base)
                        .cloned()
                        .or_else(|| {
                            analysis
                                .smallvec_ptr_meta
                                .get(base)
                                .map(|(et, es, ea, cap)| (et.clone(), *es, *ea, true, *cap))
                        });
                    if let Some((sema_elem_ty, elem_sz, elem_align, is_sv, sv_cap)) = meta {
                        let ea = elem_align.max(1);
                        let stride = elem_sz.div_ceil(ea) * ea;
                        let elem_rust_ty = match &sema_elem_ty {
                            Ty::Named(n) => {
                                let short = n.rsplit("::").next().unwrap_or(n);
                                if !ctx.enums_by_key.contains_key(n.as_str())
                                    && !ctx.enums_by_key.contains_key(short)
                                    && let Some(entry) = ctx.find_layout_entry(n)
                                    && entry.layout.size > 0
                                    && !entry.layout.fields.is_empty()
                                {
                                    entry.struct_name.clone()
                                } else {
                                    rust_abi_type_for_ty(&sema_elem_ty, elem_sz, ctx.mir)
                                }
                            }
                            Ty::SmallVec { .. } | Ty::Tuple(_) | Ty::InputBuffer { .. } => {
                                aligned_blob_type(elem_sz, elem_align)
                            }
                            _ => rust_abi_type_for_ty(&sema_elem_ty, elem_sz, ctx.mir),
                        };
                        let unpacked = unwrap_abi_ty_load(
                            "__el_raw",
                            &sema_elem_ty,
                            elem_sz,
                            elem_align,
                            ctx,
                            0,
                        );
                        let load_expr = emit_place_ref_expr(
                            *base,
                            analysis,
                            query_plans,
                            in_chunk,
                            |place| {
                                if is_sv {
                                    if elem_sz == 0 {
                                        let (raw_e, raw_vt) =
                                            (&format!("{elem_rust_ty}::default()"), dt.clone());
                                        let _ = raw_vt;
                                        raw_e.clone()
                                    } else {
                                        let conv = if unpacked.0 == "__el_raw" {
                                            coerce_expr("__el_raw", &unpacked.1, dt)
                                        } else {
                                            coerce_expr(&unpacked.0, &unpacked.1, dt)
                                        };
                                        format!(
                                            "{{ let __ai = ({idx_e}) as usize; if __ai < {sv_cap} {{ let mut __eb = [0u8; {elem_sz}]; ({place}).strata_pod_read_sub(8 + __ai * {stride}, &mut __eb); let __el_raw = <{elem_rust_ty} as StrataPodBytes>::strata_pod_from_bytes(&__eb); {conv} }} else {{ {def_e} }} }}"
                                        )
                                    }
                                } else {
                                    let conv = coerce_expr(&unpacked.0, &unpacked.1, dt);
                                    format!(
                                        "{{ let __ai = ({idx_e}) as usize; if __ai < ({place}).len() {{ let __el_raw = ({place})[__ai]; {conv} }} else {{ {def_e} }} }}"
                                    )
                                }
                            },
                            &def_e,
                        );
                        writeln!(out, "{indent}__loc_{} = {load_expr};", d.0).ok();
                        return Ok(());
                    }
                }
                let base_expr = if analysis.slot_tys.contains_key(base) {
                    format!("__slot_{}", base.0)
                } else {
                    format!("__loc_{}", base.0)
                };
                match &analysis.val_tys[base.0 as usize] {
                    ValTy::SmallVec {
                        elem,
                        cap,
                        elem_size,
                        elem_align,
                    } => {
                        let ea = (*elem_align).max(1);
                        let stride = elem_size.div_ceil(ea) * ea;
                        let sema_elem = val_ty_to_sema_hint(elem);
                        let elem_rust_ty = match &sema_elem {
                            Ty::Named(n) => ctx
                                .find_layout_entry(n)
                                .map_or_else(|| elem.rust_type(), |e| e.struct_name.clone()),
                            Ty::SmallVec { .. } => aligned_blob_type(*elem_size, *elem_align),
                            _ => rust_abi_type_for_ty(&sema_elem, *elem_size, ctx.mir),
                        };
                        let unpacked = unwrap_abi_ty_load(
                            "__el_raw",
                            &sema_elem,
                            *elem_size,
                            *elem_align,
                            ctx,
                            0,
                        );
                        let conv = coerce_expr(&unpacked.0, &unpacked.1, dt);
                        writeln!(
                            out,
                            "{indent}__loc_{} = if (({idx_e}) as usize) < {cap} {{ let mut __eb = [0u8; {elem_size}]; {base_expr}.strata_pod_read_sub(8 + (({idx_e}) as usize) * {stride}, &mut __eb); let __el_raw = <{elem_rust_ty} as StrataPodBytes>::strata_pod_from_bytes(&__eb); {conv} }} else {{ {def_e} }};",
                            d.0
                        )
                        .ok();
                    }
                    ValTy::Array(elem_vt, _) => {
                        let elem_raw = format!("{base_expr}[__arr_idx]");
                        let expr = coerce_expr(&elem_raw, elem_vt, dt);
                        writeln!(
                            out,
                            "{indent}let __arr_idx = ({idx_e}) as usize;\n\
                             {indent}__loc_{} = if __arr_idx < {base_expr}.len() {{ {expr} }} else {{ {def_e} }};",
                            d.0
                        )
                        .ok();
                    }
                    _ => {
                        writeln!(
                            out,
                            "{indent}let __arr_idx = ({idx_e}) as usize;\n\
                             {indent}__loc_{} = if __arr_idx < {base_expr}.len() {{ {base_expr}[__arr_idx] }} else {{ {def_e} }};",
                            d.0
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::SlotLoad { slot } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::PtrMarker
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                let slot_name = slot_remap
                    .get(slot)
                    .cloned()
                    .unwrap_or_else(|| format!("__slot_{}", slot.0));
                let slot_vt = analysis
                    .slot_tys
                    .get(slot)
                    .unwrap_or(&analysis.val_tys[d.0 as usize]);
                let coerced = coerce_expr(&slot_name, slot_vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::SlotStore { slot, val } => {
            if analysis.up_cascade_slots.contains(slot) {
                match analysis.ptr_targets.get(val) {
                    Some(PtrTarget::UpCascadeDirect { up_local, .. }) => {
                        writeln!(
                            out,
                            "{indent}__up_flag_{} = true;\n{indent}__up_ent_{} = __up_ent_{};",
                            slot.0, slot.0, up_local.0
                        )
                        .ok();
                    }
                    Some(PtrTarget::UpCascadeSlot {
                        slot_local: src_slot,
                        ..
                    }) => {
                        writeln!(
                            out,
                            "{indent}__up_flag_{} = __up_flag_{};\n{indent}__up_ent_{} = __up_ent_{};",
                            slot.0, src_slot.0, slot.0, src_slot.0
                        )
                        .ok();
                    }
                    _ => {
                        writeln!(
                            out,
                            "{indent}__up_flag_{} = false;\n{indent}__up_ent_{} = None;",
                            slot.0, slot.0
                        )
                        .ok();
                    }
                }
                return Ok(());
            }
            let slot_name = slot_remap
                .get(slot)
                .cloned()
                .unwrap_or_else(|| format!("__slot_{}", slot.0));
            let (eff_vt, eff_expr) =
                effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
            if eff_vt == ValTy::PtrMarker || eff_vt == ValTy::Unit {
                return Ok(());
            }
            let local_opt = (analysis.val_tys[val.0 as usize] != ValTy::PtrMarker).then_some(*val);
            let slot_vt = analysis.slot_tys.get(slot).unwrap_or(&eff_vt);
            let coerced = coerce_local_expr(local_opt, &eff_expr, &eff_vt, slot_vt, analysis);
            writeln!(out, "{indent}{slot_name} = {coerced};").ok();
        }
        Inst::SlotAlloc { .. }
        | Inst::FieldPtr { .. }
        | Inst::IterNextChunk { .. }
        | Inst::IterReset { .. }
        | Inst::IterEntities { .. }
        | Inst::IterColRead { .. }
        | Inst::IterColWrite { .. }
        | Inst::IterColWriteUntracked { .. }
        | Inst::IterColRowsRead { .. }
        | Inst::IterColRowsWrite { .. }
        | Inst::RowPtr { .. }
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::TriggerPayload { .. }
        | Inst::MigrateSrcPtr { .. }
        | Inst::MigrateDstPtr { .. }
        | Inst::DirtyRunInit { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::FsmDispatch { .. }
        | Inst::TaskStep { .. }
        | Inst::RequireTrue { .. }
        | Inst::ShadowWrite { .. }
        | Inst::SpatialRebuildCsr { .. } => {}

        Inst::IterUpCascade {
            relation, entity, ..
        } => {
            if let Some(d) = st.dst
                && let Some(PtrTarget::UpCascadeDirect { up_q_expr, .. }) =
                    analysis.ptr_targets.get(&d)
            {
                let resolved_rel = resolve_custom_relation_name(ctx, relation);
                let parent_step = if !is_child_of_relation(relation)
                    && let Some((rel_var, _)) = analysis.relation_res_map.get(resolved_rel)
                {
                    format!(
                        "{rel_var}.edges.iter().find_map(|&(s, d, _)| (s == __cur).then_some(d))"
                    )
                } else {
                    "up_child_of_q.get(__cur).ok().map(|__co| __co.parent())".to_owned()
                };
                writeln!(
                    out,
                    "{indent}__up_ent_{} = {{\n\
                     {indent}    let mut __found: Option<Entity> = None;\n\
                     {indent}    if let Some(mut __cur) = Entity::try_from_bits(__loc_{}.to_bits()) {{\n\
                     {indent}        let mut __slow = __cur;\n\
                     {indent}        let mut __steps: u32 = 0;\n\
                     {indent}        let mut __pow: u32 = 1;\n\
                     {indent}        while let Some(__parent) = {parent_step} {{\n\
                     {indent}            if __parent == __slow {{ break; }}\n\
                     {indent}            if {up_q_expr}.get(__parent).is_ok() {{\n\
                     {indent}                __found = Some(__parent);\n\
                     {indent}                break;\n\
                     {indent}            }}\n\
                     {indent}            __steps += 1;\n\
                     {indent}            if __steps == __pow {{\n\
                     {indent}                __slow = __parent;\n\
                     {indent}                __pow <<= 1;\n\
                     {indent}                __steps = 0;\n\
                     {indent}            }}\n\
                     {indent}            __cur = __parent;\n\
                     {indent}        }}\n\
                     {indent}    }}\n\
                     {indent}    __found\n\
                     {indent}}};",
                    d.0, entity.0
                )
                .ok();
            }
        }
        Inst::SpatialCsrBegin { index_name } => {
            let resolved = resolve_spatial_name(ctx, func, index_name);
            if let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str()) {
                writeln!(out, "{indent}{vname}.csr_begin();").ok();
            }
        }
        Inst::SpatialCsrCount { index_name, pos } => {
            let resolved = resolve_spatial_name(ctx, func, index_name);
            if let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str()) {
                if analysis.val_tys[pos.0 as usize] == ValTy::Vec2 {
                    writeln!(
                        out,
                        "{indent}let __sp_pos = {vname}.lift_vec2(__loc_{});\n{indent}{vname}.csr_count(__sp_pos);",
                        pos.0
                    )
                    .ok();
                } else {
                    writeln!(out, "{indent}{vname}.csr_count(__loc_{});", pos.0).ok();
                }
            }
        }
        Inst::SpatialCsrPrefixSum { index_name } => {
            let resolved = resolve_spatial_name(ctx, func, index_name);
            if let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str()) {
                writeln!(out, "{indent}{vname}.csr_prefix_sum();").ok();
            }
        }
        Inst::SpatialCsrScatter {
            index_name,
            entity,
            pos,
        } => {
            let resolved = resolve_spatial_name(ctx, func, index_name);
            if let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str()) {
                if analysis.val_tys[pos.0 as usize] == ValTy::Vec2 {
                    writeln!(
                        out,
                        "{indent}if let Some(__ce) = Entity::try_from_bits(__loc_{}.to_bits()) {{ let __sp_pos = {vname}.lift_vec2(__loc_{}); {vname}.csr_scatter(__ce, __sp_pos); }}",
                        entity.0, pos.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "{indent}if let Some(__ce) = Entity::try_from_bits(__loc_{}.to_bits()) {{ {vname}.csr_scatter(__ce, __loc_{}); }}",
                        entity.0, pos.0
                    )
                    .ok();
                }
            }
        }
        Inst::ArrayStore {
            base_ptr,
            index,
            val,
            elem_ty,
        } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let meta = analysis
                .field_ptr_array_meta
                .get(base_ptr)
                .cloned()
                .or_else(|| {
                    analysis
                        .smallvec_ptr_meta
                        .get(base_ptr)
                        .map(|(et, es, ea, cap)| (et.clone(), *es, *ea, true, *cap))
                });
            let target_elem_vt = if let Some((ref sema_elem_ty, _, _, _, _)) = meta {
                ValTy::from_sema_ty(sema_elem_ty, ctx)
            } else {
                ValTy::from_mir(elem_ty, ctx)
            };
            let (src_vt, src_raw_expr) =
                effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
            let local_id_opt = if analysis.val_tys[val.0 as usize] != ValTy::PtrMarker {
                Some(*val)
            } else {
                None
            };
            let coerced = coerce_local_expr(
                local_id_opt,
                &src_raw_expr,
                &src_vt,
                &target_elem_vt,
                analysis,
            );
            let wrapped_val = if let Some((ref sema_elem_ty, elem_sz, elem_align, _, _)) = meta {
                wrap_abi_ty_store(&coerced, sema_elem_ty, elem_sz, elem_align, ctx, 0)
            } else {
                coerced
            };
            let idx_expr = format!("(__loc_{} as usize)", index.0);
            let sv_dims = meta
                .as_ref()
                .and_then(|(_, es, ea, is_sv, cap)| is_sv.then_some((*es, *ea, *cap)))
                .or_else(|| {
                    let vt = analysis
                        .ptr_targets
                        .get(base_ptr)
                        .and_then(|pt| match pt {
                            PtrTarget::SlotRef { slot_local } => analysis.slot_tys.get(slot_local),
                            _ => None,
                        })
                        .unwrap_or(&analysis.val_tys[base_ptr.0 as usize]);
                    if let ValTy::SmallVec {
                        cap,
                        elem_size,
                        elem_align,
                        ..
                    } = vt
                    {
                        Some((*elem_size, *elem_align, *cap))
                    } else {
                        None
                    }
                });
            if analysis.ptr_targets.contains_key(base_ptr) {
                emit_place_mut(
                    out,
                    *base_ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    indent,
                    in_undo,
                    |place| {
                        if let Some((elem_sz, elem_align, sv_cap)) = sv_dims {
                            if elem_sz == 0 {
                                format!("let _ = {wrapped_val};")
                            } else {
                                let ea = elem_align.max(1);
                                let stride = elem_sz.div_ceil(ea) * ea;
                                format!(
                                    "let __arr_idx = {idx_expr}; if __arr_idx < {sv_cap} {{ let __wv = {wrapped_val}; let mut __wb = [0u8; {elem_sz}]; __wv.strata_pod_read_sub(0, &mut __wb); ({place}).strata_pod_write_bytes(8 + __arr_idx * {stride}, &__wb); }}"
                                )
                            }
                        } else {
                            format!(
                                "let __arr_idx = {idx_expr}; if __arr_idx < {place}.len() {{ {place}[__arr_idx] = {wrapped_val}; }}"
                            )
                        }
                    },
                );
            } else {
                let base_expr = if analysis.slot_tys.contains_key(base_ptr) {
                    format!("__slot_{}", base_ptr.0)
                } else {
                    format!("__loc_{}", base_ptr.0)
                };
                if let Some((elem_sz, elem_align, sv_cap)) = sv_dims {
                    if elem_sz == 0 {
                        writeln!(out, "{indent}let _ = {wrapped_val};").ok();
                    } else {
                        let ea = elem_align.max(1);
                        let stride = elem_sz.div_ceil(ea) * ea;
                        writeln!(
                            out,
                            "{indent}let __arr_idx = {idx_expr}; if __arr_idx < {sv_cap} {{ let __wv = {wrapped_val}; let mut __wb = [0u8; {elem_sz}]; __wv.strata_pod_read_sub(0, &mut __wb); {base_expr}.strata_pod_write_bytes(8 + __arr_idx * {stride}, &__wb); }}"
                        )
                        .ok();
                    }
                } else {
                    writeln!(
                        out,
                        "{indent}let __arr_idx = {idx_expr}; if __arr_idx < {base_expr}.len() {{ {base_expr}[__arr_idx] = {wrapped_val}; }}"
                    )
                    .ok();
                }
            }
        }

        Inst::IterChunkLen { query_idx } => {
            if let Some(d) = st.dst {
                let expr = chunk_len_expr(*query_idx, query_plans, in_chunk);
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::EntityAtRow {
            entities_ptr,
            row_idx,
        } => {
            if let Some(d) = st.dst {
                if let Some(PtrTarget::EntitiesSlice { query_idx }) =
                    analysis.ptr_targets.get(entities_ptr)
                {
                    let plan = query_plans.iter().find(|p| p.query_idx == *query_idx);
                    if plan.is_some_and(QueryEmitPlan::uses_row_iter)
                        || in_chunk.is_some_and(ChunkLoopInfo::is_1row)
                    {
                        writeln!(
                            out,
                            "{indent}__loc_{} = FfiEntity::from_bits(__q{query_idx}_ent.to_bits());",
                            d.0
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "{indent}__loc_{} = FfiEntity::from_bits(__q{query_idx}_entities[__loc_{} as usize].to_bits());",
                            d.0, row_idx.0
                        )
                        .ok();
                    }
                } else {
                    writeln!(
                        out,
                        "{indent}__loc_{} = __loc_{}.get(__loc_{} as usize).copied().unwrap_or(FfiEntity::NULL);",
                        d.0, entities_ptr.0, row_idx.0
                    )
                    .ok();
                }
            }
        }
        Inst::FieldLoad {
            base_ptr,
            layout_key,
            field,
            ..
        } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let load_expr = emit_field_load_expr(
                    *base_ptr,
                    layout_key,
                    field,
                    dt,
                    func,
                    ctx,
                    query_plans,
                    analysis,
                    in_chunk,
                );
                writeln!(out, "{indent}__loc_{} = {load_expr};", d.0).ok();
            }
        }
        Inst::FieldStore {
            base_ptr,
            layout_key,
            field,
            val,
            ..
        } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            emit_field_store_stmt(
                out,
                *base_ptr,
                layout_key,
                field,
                *val,
                ctx,
                query_plans,
                analysis,
                indent,
                in_chunk,
                in_undo,
            );
        }
        Inst::DirtyRunRecordRow { row_idx, .. } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            if !in_undo
                && let Some(cl) = in_chunk
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == cl.query_idx)
            {
                for slot in &plan.slots {
                    if slot.mode == TermAccessMode::SelectiveWrite
                        || (slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked)
                    {
                        let qi = plan.query_idx;
                        let si = slot.slot_idx;
                        if plan.uses_row_iter() || cl.is_1row() {
                            if analysis.has_checkpoint {
                                writeln!(
                                    out,
                                    "{indent}if __tx_active {{ __q{qi}_tx_dirty_{si} = true; }} else {{ __q{qi}_dirty_{si} = true; }}"
                                )
                                .ok();
                            } else {
                                writeln!(out, "{indent}__q{qi}_dirty_{si} = true;").ok();
                            }
                        } else if slot.mode == TermAccessMode::OptionalWrite {
                            if analysis.has_checkpoint {
                                writeln!(
                                    out,
                                    "{indent}if __tx_active {{ __q{qi}_tx_rows_{si}.push(__loc_{0} as usize); }} else if let Some(ref mut __opt_sel) = __q{qi}_sel_{si} {{ __opt_sel.mark_dirty_row(__loc_{0} as usize); }}",
                                    row_idx.0
                                )
                                .ok();
                            } else {
                                writeln!(
                                    out,
                                    "{indent}if let Some(ref mut __opt_sel) = __q{qi}_sel_{si} {{ __opt_sel.mark_dirty_row(__loc_{} as usize); }}",
                                    row_idx.0
                                )
                                .ok();
                            }
                        } else if analysis.has_checkpoint {
                            writeln!(
                                out,
                                "{indent}if __tx_active {{ __q{qi}_tx_rows_{si}.push(__loc_{0} as usize); }} else {{ __q{qi}_sel_{si}.mark_dirty_row(__loc_{0} as usize); }}",
                                row_idx.0
                            )
                            .ok();
                        } else {
                            writeln!(
                                out,
                                "{indent}__q{qi}_sel_{si}.mark_dirty_row(__loc_{} as usize);",
                                row_idx.0
                            )
                            .ok();
                        }
                    }
                }
            }
        }
        Inst::IterMarkChangedRange { query_idx, .. } => {
            if let Some(cl) = in_chunk
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                && !plan.uses_row_iter()
                && !cl.is_1row()
            {
                for slot in &plan.slots {
                    if slot.mode == TermAccessMode::SelectiveWrite {
                        writeln!(
                            out,
                            "{indent}let _ = __q{}_sel_{}.flush_dirty_runs();",
                            plan.query_idx, slot.slot_idx
                        )
                        .ok();
                    } else if slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked {
                        writeln!(
                            out,
                            "{indent}if let Some(ref mut __opt_sel) = __q{}_sel_{} {{ let _ = __opt_sel.flush_dirty_runs(); }}",
                            plan.query_idx, slot.slot_idx
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::IterCount { query_idx } => {
            if let Some(d) = st.dst
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
            {
                let qa = query_access_expr(plan);
                writeln!(out, "{indent}__loc_{} = {qa}.iter().count() as u32;", d.0).ok();
            }
        }
        Inst::ReduceInit { op, identity } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let iv = coerce_expr(
                    &format!("__loc_{}", identity.0),
                    &analysis.val_tys[identity.0 as usize],
                    dt,
                );
                let _ = op;
                writeln!(out, "{indent}__loc_{} = {iv};", d.0).ok();
            }
        }
        Inst::ReduceAccum { acc, op, val } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let (val_vt, val_expr) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let expr =
                    reduce_accum_expr(op, dt, &val_vt, &format!("__loc_{}", acc.0), &val_expr);
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::EntityGet {
            query_idx, entity, ..
        }
        | Inst::EntityGetMut {
            query_idx, entity, ..
        } => {
            if let Some(d) = st.dst
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
            {
                let qa = query_access_expr(plan);
                writeln!(
                    out,
                    "{indent}__loc_{} = Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).is_ok());",
                    d.0, entity.0
                )
                .ok();
            }
        }
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
            if let Some(d) = st.dst {
                let cond_expr = match analysis.ptr_targets.get(slice_ptr) {
                    Some(PtrTarget::QueryCol {
                        query_idx,
                        slot_idx,
                        selective,
                        optional,
                        ..
                    })
                    | Some(PtrTarget::QueryRow {
                        query_idx,
                        slot_idx,
                        selective,
                        optional,
                        ..
                    }) => {
                        if !*optional {
                            "true".to_owned()
                        } else if *selective {
                            format!("__q{query_idx}_sel_{slot_idx}.is_some()")
                        } else {
                            format!("__q{query_idx}_col_{slot_idx}.is_some()")
                        }
                    }
                    Some(PtrTarget::EntityRow {
                        query_idx,
                        slot_idx,
                        entity_local,
                        optional,
                        ..
                    }) => {
                        let plan = &query_plans[*query_idx as usize];
                        let qa = query_access_expr(plan);
                        let tup_idx = slot_idx + usize::from(plan.needs_entity);
                        if *optional {
                            format!(
                                "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).ok().is_some_and(|__row| __row.{tup_idx}.is_some()))",
                                entity_local.0
                            )
                        } else {
                            format!(
                                "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).is_ok())",
                                entity_local.0
                            )
                        }
                    }
                    _ => "false".to_owned(),
                };
                writeln!(out, "{indent}__loc_{} = {cond_expr};", d.0).ok();
            }
        }
        Inst::BindNamedObject { name } => {
            if let Some((q_var, _)) = analysis.object_queries.get(name.as_str()) {
                writeln!(
                    out,
                    "{indent}if named_objects.get({name:?}).is_none() {{\n\
                     {indent}    if let Some(__e) = {q_var}.iter().next() {{ named_objects.bind({name:?}, __e); }}\n\
                     {indent}}}"
                )
                .ok();
            }
        }
        Inst::ResolveNamedObject { name } => {
            if let Some(d) = st.dst {
                let fallback = if let Some((q_var, _)) = analysis.object_queries.get(name.as_str())
                {
                    format!(".or_else(|| {q_var}.iter().next())")
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "{indent}__loc_{} = named_objects.get({name:?}){fallback}.map_or(FfiEntity::NULL, |e| FfiEntity::from_bits(e.to_bits()));",
                    d.0
                )
                .ok();
            }
        }
        Inst::InternSymbol { symbol } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::Entity {
                    writeln!(out, "{indent}__loc_{} = FfiEntity::NULL;", d.0).ok();
                } else if *dt != ValTy::Unit && *dt != ValTy::PtrMarker {
                    writeln!(
                        out,
                        "{indent}__loc_{} = (fnv1a_64_str({symbol:?}) as u32) as {};",
                        d.0,
                        dt.rust_type()
                    )
                    .ok();
                }
            }
        }
        Inst::TriggerTarget => {
            if let Some(d) = st.dst {
                let is_entity_ev = matches!(&func.kind, MirFnKind::Observer { event, .. } if ctx.find_layout_entry(event).is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name)));
                if is_entity_ev {
                    writeln!(
                        out,
                        "{indent}__loc_{} = FfiEntity::from_bits(on.event().event_target().to_bits());",
                        d.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "{indent}__loc_{} = trigger_targets.0.last().copied().unwrap_or(FfiEntity::NULL);",
                        d.0
                    )
                    .ok();
                }
            }
        }

        // Gameplay primitives
        Inst::GraceArm { ptr, duration_sec } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let dur = coerce_expr(
                &format!("__loc_{}", duration_sec.0),
                &analysis.val_tys[duration_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| format!("let __d = {dur}; if __d > *{place} {{ *{place} = __d; }}"),
            );
        }
        Inst::GraceTick { ptr, dt_sec } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let dt = coerce_expr(
                &format!("__loc_{}", dt_sec.0),
                &analysis.val_tys[dt_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| {
                    format!(
                        "let __dt = {dt}; if *{place} > 0.0_f32 {{ *{place} = (*{place} - __dt).max(0.0_f32); }}"
                    )
                },
            );
        }
        Inst::GraceIsActive { ptr } => {
            if let Some(d) = st.dst {
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("(*{place} > 0.0_f32)"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::GraceClear { ptr } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| format!("*{place} = 0.0_f32;"),
            );
        }
        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let aid = format!("(__loc_{} as u16)", action_id.0);
            let win = coerce_expr(
                &format!("__loc_{}", window_sec.0),
                &analysis.val_tys[window_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| format!("strata_input_buf_push({place}.as_mut_slice(), {aid}, {win});"),
            );
        }
        Inst::InputBufConsume { ptr, action_id, .. } => {
            if let Some(d) = st.dst {
                let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
                let aid = format!("(__loc_{} as u16)", action_id.0);
                let mut wrote = false;
                if let Some(place_expr) = emit_place_mut_res_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    in_undo,
                    |place| format!("strata_input_buf_consume({place}.as_mut_slice(), {aid})"),
                ) {
                    writeln!(out, "{indent}__loc_{} = {place_expr};", d.0).ok();
                    wrote = true;
                }
                if !wrote {
                    writeln!(out, "{indent}__loc_{} = false;", d.0).ok();
                }
            }
        }
        Inst::InputBufPeek { ptr, action_id, .. } => {
            if let Some(d) = st.dst {
                let aid = format!("(__loc_{} as u16)", action_id.0);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("strata_input_buf_peek({place}.as_slice(), {aid})"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::InputBufTick { ptr, dt_sec, .. } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let dt = coerce_expr(
                &format!("__loc_{}", dt_sec.0),
                &analysis.val_tys[dt_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| format!("strata_input_buf_tick({place}.as_mut_slice(), {dt});"),
            );
        }
        Inst::BitSetSet { ptr, bit, .. } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let b = format!("(__loc_{} as u32)", bit.0);
            if analysis.ptr_targets.contains_key(ptr) {
                emit_place_mut(
                    out,
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    indent,
                    in_undo,
                    |place| format!("strata_bitset_set({place}.as_mut_slice(), {b});"),
                );
            } else if analysis.val_tys[ptr.0 as usize] != ValTy::PtrMarker {
                writeln!(
                    out,
                    "{indent}strata_bitset_set(__loc_{}.as_mut_slice(), {b});",
                    ptr.0
                )
                .ok();
            }
        }
        Inst::BitSetClear { ptr, bit, .. } => {
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            let b = format!("(__loc_{} as u32)", bit.0);
            if analysis.ptr_targets.contains_key(ptr) {
                emit_place_mut(
                    out,
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    indent,
                    in_undo,
                    |place| format!("strata_bitset_clear({place}.as_mut_slice(), {b});"),
                );
            } else if analysis.val_tys[ptr.0 as usize] != ValTy::PtrMarker {
                writeln!(
                    out,
                    "{indent}strata_bitset_clear(__loc_{}.as_mut_slice(), {b});",
                    ptr.0
                )
                .ok();
            }
        }
        Inst::BitSetGet { ptr, bit, .. } => {
            if let Some(d) = st.dst {
                let b = format!("(__loc_{} as u32)", bit.0);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("strata_bitset_get({place}.as_slice(), {b})"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::TimelineInWindow { ptr, window_bit } => {
            if let Some(d) = st.dst {
                let mask = 1u32 << (*window_bit).min(31);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("(({place}.active_mask & 0x{mask:08X}u32) != 0)"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::TimelineAdvance {
            cursor_ptr,
            rate_hz,
            window_masks,
            ..
        } => {
            let hz = (*rate_hz).max(1) as f32;
            let frame_dt = format_f32_lit(1.0 / f64::from(hz));
            let win_lit: Vec<String> = window_masks
                .iter()
                .map(|(_, s, e, m)| format!("({s}u32, {e}u32, 0x{m:08X}u32)"))
                .collect();
            let win_arr = format!("[{}]", win_lit.join(", "));
            let in_undo = func.blocks[bb_idx].label == "tx_undo_field";
            emit_place_mut(
                out,
                *cursor_ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                in_undo,
                |place| {
                    format!(
                        "let mut __cf = {place}.cur_frame;\n\
                         let mut __acc = {place}.accum_sec;\n\
                         while __acc >= {frame_dt} {{\n\
                         \x20   __acc -= {frame_dt};\n\
                         \x20   __cf = __cf.saturating_add(1);\n\
                         }}\n\
                         {place}.cur_frame = __cf;\n\
                         {place}.accum_sec = __acc;\n\
                         let mut __mask = 0u32;\n\
                         for &(ws, we, wm) in &{win_arr} {{\n\
                         \x20   if (__cf as u32) >= ws && (__cf as u32) < we {{ __mask |= wm; }}\n\
                         }}\n\
                         {place}.active_mask = __mask;"
                    )
                },
            );
        }

        // Tables & Curves & Spatial
        Inst::TableLoad {
            table_name,
            key,
            field,
        } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let tident = sanitize_ident(table_name);
                let row_e = format!("strata_table_get_{tident}((__loc_{}) as i64)", key.0);
                if field.is_empty() {
                    writeln!(out, "{indent}__loc_{} = {row_e};", d.0).ok();
                } else {
                    let access = resolve_blob_field_access(table_name, field, ctx);
                    let loaded = build_field_load_from_place("__trow", &access, dt, ctx);
                    writeln!(
                        out,
                        "{indent}{{ let __trow = {row_e}; __loc_{} = {loaded}; }}",
                        d.0
                    )
                    .ok();
                }
            }
        }
        Inst::CurveSample { curve_name, x } => {
            if let Some(d) = st.dst {
                let cident = sanitize_ident(curve_name);
                let xe = coerce_expr(
                    &format!("__loc_{}", x.0),
                    &analysis.val_tys[x.0 as usize],
                    &ValTy::F32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = strata_sample_curve(STRATA_CURVE_{cident}, {xe});",
                    d.0
                )
                .ok();
            }
        }
        Inst::SpatialQueryDisc {
            grid_name,
            center,
            radius,
        } => {
            let resolved = resolve_spatial_name(ctx, func, grid_name);
            if let Some(d) = st.dst
                && let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str())
            {
                let c3 = match analysis.val_tys[center.0 as usize] {
                    ValTy::Vec2 => format!("{vname}.lift_vec2(__loc_{})", center.0),
                    _ => format!("__loc_{}", center.0),
                };
                let r = coerce_expr(
                    &format!("__loc_{}", radius.0),
                    &analysis.val_tys[radius.0 as usize],
                    &ValTy::F32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = {vname}.query_disc({c3}, {r});",
                    d.0
                )
                .ok();
            }
        }
        Inst::SpatialQuerySegmentAt {
            history_name,
            start,
            end,
            radius,
            tick_offset,
        } => {
            let resolved = resolve_spatial_name(ctx, func, history_name);
            if let Some(d) = st.dst
                && let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str())
            {
                let s3 = match analysis.val_tys[start.0 as usize] {
                    ValTy::Vec2 => format!("{vname}.lift_vec2(__loc_{})", start.0),
                    _ => format!("__loc_{}", start.0),
                };
                let e3 = match analysis.val_tys[end.0 as usize] {
                    ValTy::Vec2 => format!("{vname}.lift_vec2(__loc_{})", end.0),
                    _ => format!("__loc_{}", end.0),
                };
                let r = coerce_expr(
                    &format!("__loc_{}", radius.0),
                    &analysis.val_tys[radius.0 as usize],
                    &ValTy::F32,
                );
                let toff = coerce_expr(
                    &format!("__loc_{}", tick_offset.0),
                    &analysis.val_tys[tick_offset.0 as usize],
                    &ValTy::U32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = {vname}.query_segment_at({toff}, {s3}, {e3}, {r});",
                    d.0
                )
                .ok();
            }
        }

        // Deferred Commands & Transactions
        Inst::CmdSpawn { components, .. } => {
            let bundle_parts: Vec<String> = components
                .iter()
                .filter_map(|(cname, l)| {
                    if ctx.is_zst_component(cname) {
                        ctx.resolve_ecs_struct_name(cname)
                    } else {
                        Some(format!("__loc_{}", l.0))
                    }
                })
                .collect();
            let bundle_expr = format_bundle_tuple(&bundle_parts);
            emit_cmd_block(out, analysis, indent, |cmds| {
                if let Some(d) = st.dst
                    && analysis.val_tys[d.0 as usize] == ValTy::Entity
                {
                    format!(
                        "let __sp = {cmds}.spawn({bundle_expr}).id(); __loc_{} = FfiEntity::from_bits(__sp.to_bits());",
                        d.0
                    )
                } else {
                    format!("{cmds}.spawn({bundle_expr});")
                }
            });
        }
        Inst::CmdSpawnBatch { count, components } => {
            let bundle_parts: Vec<String> = components
                .iter()
                .filter_map(|(cname, l)| {
                    if ctx.is_zst_component(cname) {
                        ctx.resolve_ecs_struct_name(cname)
                    } else {
                        Some(format!("__loc_{}", l.0))
                    }
                })
                .collect();
            let bundle_expr = format_bundle_tuple(&bundle_parts);
            let cnt_e = format!("(__loc_{} as usize)", count.0);
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!("{cmds}.spawn_batch((0..{cnt_e}).map(move |_| {bundle_expr}));")
            });
        }
        Inst::SpawnBatchBegin { count, .. } => {
            if let Some(d) = st.dst
                && let Some(bp) = analysis.spawn_batches.iter().find(|b| b.dst_local == d)
            {
                writeln!(
                    out,
                    "{indent}{} = Vec::with_capacity(__loc_{} as usize);\n\
                     {indent}__loc_{} = {}u64;",
                    bp.var_name, count.0, d.0, bp.id
                )
                .ok();
            }
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            if let Some(srcs) = analysis.batch_sources.get(batch) {
                let emit_push_for = |out: &mut String, bp: &SpawnBatchPlan, arm_indent: &str| {
                    let row_parts: Vec<String> = bp
                        .slots
                        .iter()
                        .map(|slot| {
                            if slot.is_zst {
                                slot.struct_name.clone()
                            } else if let Some((_, val_l)) = components.iter().rfind(|(cn, _)| {
                                ctx.resolve_ecs_struct_name(cn).as_deref()
                                    == Some(slot.struct_name.as_str())
                            }) {
                                format!("__loc_{}", val_l.0)
                            } else {
                                format!("{}::default()", slot.struct_name)
                            }
                        })
                        .collect();
                    let row_expr = format_bundle_tuple(&row_parts);
                    let var = &bp.var_name;
                    writeln!(
                        out,
                        "{arm_indent}{{\n\
                         {arm_indent}    let __batch_row = {row_expr};\n\
                         {arm_indent}    let __batch_idx = __loc_{} as usize;\n\
                         {arm_indent}    if __batch_idx == {var}.len() {{\n\
                         {arm_indent}        {var}.push(__batch_row);\n\
                         {arm_indent}    }} else if __batch_idx < {var}.len() {{\n\
                         {arm_indent}        {var}[__batch_idx] = __batch_row;\n\
                         {arm_indent}    }} else {{\n\
                         {arm_indent}        {var}.resize_with(__batch_idx + 1, Default::default);\n\
                         {arm_indent}        {var}[__batch_idx] = __batch_row;\n\
                         {arm_indent}    }}\n\
                         {arm_indent}}}",
                        index.0
                    )
                    .ok();
                };
                if srcs.len() == 1 {
                    if let Some(&id) = srcs.iter().next()
                        && let Some(bp) = analysis.spawn_batches.get(id)
                    {
                        emit_push_for(out, bp, indent);
                    }
                } else if !srcs.is_empty() {
                    writeln!(out, "{indent}match __loc_{} {{", batch.0).ok();
                    let arm_ind = format!("{indent}        ");
                    for &id in srcs {
                        if let Some(bp) = analysis.spawn_batches.get(id) {
                            writeln!(out, "{indent}    {id}u64 => {{").ok();
                            emit_push_for(out, bp, &arm_ind);
                            writeln!(out, "{indent}    }}").ok();
                        }
                    }
                    writeln!(out, "{indent}    _ => {{}}\n{indent}}}").ok();
                }
            }
        }
        Inst::SpawnBatchCommit { batch } => {
            if let Some(srcs) = analysis.batch_sources.get(batch) {
                let emit_commit_for = |out: &mut String, bp: &SpawnBatchPlan, arm_indent: &str| {
                    writeln!(
                        out,
                        "{arm_indent}{{\n\
                         {arm_indent}    let __batch_rows = core::mem::take(&mut {});",
                        bp.var_name
                    )
                    .ok();
                    let inner_ind = format!("{arm_indent}    ");
                    emit_cmd_block(out, analysis, &inner_ind, |cmds| {
                        format!("{cmds}.spawn_batch(__batch_rows);")
                    });
                    writeln!(out, "{arm_indent}}}").ok();
                };
                if srcs.len() == 1 {
                    if let Some(&id) = srcs.iter().next()
                        && let Some(bp) = analysis.spawn_batches.get(id)
                    {
                        emit_commit_for(out, bp, indent);
                    }
                } else if !srcs.is_empty() {
                    writeln!(out, "{indent}match __loc_{} {{", batch.0).ok();
                    let arm_ind = format!("{indent}        ");
                    for &id in srcs {
                        if let Some(bp) = analysis.spawn_batches.get(id) {
                            writeln!(out, "{indent}    {id}u64 => {{").ok();
                            emit_commit_for(out, bp, &arm_ind);
                            writeln!(out, "{indent}    }}").ok();
                        }
                    }
                    writeln!(out, "{indent}    _ => {{}}\n{indent}}}").ok();
                }
            }
        }
        Inst::CmdDespawn { entity } => {
            let ent = resolve_entity_local_expr(*entity, func, analysis, in_chunk);
            writeln!(out, "{indent}let __cmd_ent = {ent};").ok();
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!(
                    "if let Some(__e) = Entity::try_from_bits(__cmd_ent.to_bits()) {{ {cmds}.entity(__e).despawn(); }}"
                )
            });
        }
        Inst::CmdDespawnAll { filter } => {
            let parsed = parse_despawn_filters(filter);
            let mut f_parts = Vec::new();
            for (kind, cname) in parsed {
                if let Some(sname) = ctx.resolve_ecs_struct_name(&cname) {
                    f_parts.push(format!("{kind}<{sname}>"));
                }
            }
            let filter_ty = if f_parts.is_empty() {
                "()".to_owned()
            } else if f_parts.len() == 1 {
                f_parts[0].clone()
            } else {
                format!("({})", f_parts.join(", "))
            };
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!("{cmds}.despawn_all::<{filter_ty}>();")
            });
        }
        Inst::CmdInsert {
            entity,
            component,
            data,
            if_new,
        } => {
            let ent = resolve_entity_local_expr(*entity, func, analysis, in_chunk);
            let val_expr = if let Some(d) = data {
                if ctx.is_zst_component(component) {
                    ctx.resolve_ecs_struct_name(component)
                        .unwrap_or_else(|| "()".to_owned())
                } else {
                    format!("__loc_{}", d.0)
                }
            } else {
                format!(
                    "{}::default()",
                    ctx.resolve_ecs_struct_name(component)
                        .unwrap_or_else(|| "()".to_owned())
                )
            };
            let method = if *if_new { "insert_if_new" } else { "insert" };
            writeln!(
                out,
                "{indent}let __cmd_ent = {ent};\n{indent}let __cmd_val = {val_expr};"
            )
            .ok();
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!(
                    "if let Some(__e) = Entity::try_from_bits(__cmd_ent.to_bits()) {{ {cmds}.entity(__e).{method}(__cmd_val); }}"
                )
            });
        }
        Inst::CmdRemove { entity, component } => {
            if let Some(sname) = ctx.resolve_ecs_struct_name(component) {
                let ent = resolve_entity_local_expr(*entity, func, analysis, in_chunk);
                writeln!(out, "{indent}let __cmd_ent = {ent};").ok();
                emit_cmd_block(out, analysis, indent, |cmds| {
                    format!(
                        "if let Some(__e) = Entity::try_from_bits(__cmd_ent.to_bits()) {{ {cmds}.entity(__e).remove::<{sname}>(); }}"
                    )
                });
            }
        }
        Inst::CmdTrigger {
            event,
            target,
            payload,
            propagate,
        } => {
            if let Some(ev_entry) = ctx.find_layout_entry(event) {
                let is_zst_ev = ev_entry.layout.size == 0 || ev_entry.layout.fields.is_empty();
                let mut ev_expr = if let Some(pl) = payload {
                    if is_zst_ev {
                        ev_entry.struct_name.clone()
                    } else if analysis.val_tys[pl.0 as usize] == ValTy::PtrMarker {
                        if matches!(
                            analysis.ptr_targets.get(pl),
                            Some(PtrTarget::TriggerPayload)
                        ) {
                            if in_chunk.is_some_and(|c| c.use_par) {
                                "__obs_ev_copy".to_owned()
                            } else {
                                "(*on.event())".to_owned()
                            }
                        } else if analysis.ptr_targets.contains_key(pl) {
                            let def_s = format!("{}::default()", ev_entry.struct_name);
                            emit_place_ref_expr(
                                *pl,
                                analysis,
                                query_plans,
                                in_chunk,
                                |place| format!("(*({place}))"),
                                &def_s,
                            )
                        } else {
                            format!("{}::default()", ev_entry.struct_name)
                        }
                    } else {
                        format!("__loc_{}", pl.0)
                    }
                } else if is_zst_ev {
                    ev_entry.struct_name.clone()
                } else {
                    format!("{}::default()", ev_entry.struct_name)
                };
                let is_entity_ev = ctx.entity_events.contains(&ev_entry.layout.canonical_name);
                let resolve_trig_target = |tgt: LocalId| -> String {
                    resolve_entity_local_expr(tgt, func, analysis, in_chunk)
                };
                if *propagate {
                    let t_expr_opt = target.map(resolve_trig_target);
                    if let Some(ref t_expr) = t_expr_opt {
                        writeln!(
                            out,
                            "{indent}let __trig_ev = {ev_expr}; let __trig_tgt = {t_expr};"
                        )
                        .ok();
                    } else {
                        writeln!(out, "{indent}let __trig_ev = {ev_expr};").ok();
                    }
                    let start_ent = if is_entity_ev {
                        if t_expr_opt.is_some() {
                            "if __trig_ev.entity.0 == FfiEntity::NULL { __trig_tgt } else { __trig_ev.entity.0 }"
                        } else {
                            "__trig_ev.entity.0"
                        }
                    } else {
                        "__trig_tgt"
                    };
                    if t_expr_opt.is_some() || is_entity_ev {
                        emit_cmd_block(out, analysis, indent, |cmds| {
                            if is_entity_ev {
                                format!(
                                    "{cmds}.queue(move |__w: &mut World| {{\n\
                                     \x20   let mut __cur_opt = Entity::try_from_bits(({start_ent}).to_bits());\n\
                                     \x20   let mut __guard = 0u32;\n\
                                     \x20   while let Some(__ce) = __cur_opt {{\n\
                                     \x20       if __guard >= 256 {{ break; }}\n\
                                     \x20       __guard += 1;\n\
                                     \x20       let mut __ev = __trig_ev;\n\
                                     \x20       __ev.entity = StrataTargetEntity(FfiEntity::from_bits(__ce.to_bits()));\n\
                                     \x20       __w.trigger(__ev);\n\
                                     \x20       __cur_opt = __w.get::<ChildOf>(__ce).map(|__co| __co.parent());\n\
                                     \x20   }}\n\
                                     }});"
                                )
                            } else {
                                format!(
                                    "{cmds}.queue(move |__w: &mut World| {{\n\
                                     \x20   let mut __cur_opt = Entity::try_from_bits(({start_ent}).to_bits());\n\
                                     \x20   let mut __guard = 0u32;\n\
                                     \x20   while let Some(__ce) = __cur_opt {{\n\
                                     \x20       if __guard >= 256 {{ break; }}\n\
                                     \x20       __guard += 1;\n\
                                     \x20       let __has = __w.contains_resource::<StrataTriggerTargetStack>();\n\
                                     \x20       if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.push(FfiEntity::from_bits(__ce.to_bits())); }}\n\
                                     \x20       __w.trigger(__trig_ev);\n\
                                     \x20       if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.pop(); }}\n\
                                     \x20       __cur_opt = __w.get::<ChildOf>(__ce).map(|__co| __co.parent());\n\
                                     \x20   }}\n\
                                     }});"
                                )
                            }
                        });
                    } else {
                        emit_cmd_block(out, analysis, indent, |cmds| {
                            format!("{cmds}.trigger(__trig_ev);")
                        });
                    }
                } else if is_entity_ev {
                    if let Some(tgt) = target {
                        let t_expr = resolve_trig_target(*tgt);
                        ev_expr = format!(
                            "{{ let mut __ev = {ev_expr}; if __ev.entity.0 == FfiEntity::NULL {{ __ev.entity = StrataTargetEntity({t_expr}); }} __ev }}"
                        );
                    }
                    writeln!(out, "{indent}let __trig_ev = {ev_expr};").ok();
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!("{cmds}.trigger(__trig_ev);")
                    });
                } else if let Some(tgt) = target {
                    let t_expr = resolve_trig_target(*tgt);
                    writeln!(
                        out,
                        "{indent}let __ev_p = {ev_expr}; let __ev_t = {t_expr};"
                    )
                    .ok();
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!(
                            "{cmds}.queue(move |__w: &mut World| {{\n\
                             \x20   let __has = __w.contains_resource::<StrataTriggerTargetStack>();\n\
                             \x20   if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.push(__ev_t); }}\n\
                             \x20   __w.trigger(__ev_p);\n\
                             \x20   if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.pop(); }}\n\
                             }});"
                        )
                    });
                } else {
                    writeln!(out, "{indent}let __trig_ev = {ev_expr};").ok();
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!("{cmds}.trigger(__trig_ev);")
                    });
                }
            }
        }
        Inst::StreamEmit { stream, payload } => {
            if let Some(entry) = ctx.find_layout_entry(stream) {
                let p_expr = if entry.layout.size == 0 || entry.layout.fields.is_empty() {
                    entry.struct_name.clone()
                } else if analysis.val_tys[payload.0 as usize] == ValTy::PtrMarker {
                    if matches!(
                        analysis.ptr_targets.get(payload),
                        Some(PtrTarget::TriggerPayload)
                    ) {
                        if in_chunk.is_some_and(|c| c.use_par) {
                            "__obs_ev_copy".to_owned()
                        } else {
                            "(*on.event())".to_owned()
                        }
                    } else if analysis.ptr_targets.contains_key(payload) {
                        let def_s = format!("{}::default()", entry.struct_name);
                        emit_place_ref_expr(
                            *payload,
                            analysis,
                            query_plans,
                            in_chunk,
                            |place| format!("(*({place}))"),
                            &def_s,
                        )
                    } else {
                        format!("{}::default()", entry.struct_name)
                    }
                } else {
                    format!("__loc_{}", payload.0)
                };
                if in_chunk.is_some_and(|c| c.use_par) {
                    writeln!(
                        out,
                        "{indent}par_commands.command_scope(|mut __c| {{ __c.write_message({p_expr}); }});"
                    )
                    .ok();
                } else if let Some(mw_name) =
                    analysis.stream_writers.get(&entry.layout.canonical_name)
                {
                    if analysis.has_checkpoint
                        && let Some(s_idx) = analysis
                            .stream_writers
                            .keys()
                            .position(|k| k == &entry.layout.canonical_name)
                    {
                        writeln!(
                            out,
                            "{indent}if __tx_active {{ __tx_cmds.push(__StrataTxCmd::Stream_{s_idx}({p_expr})); }} else {{ {mw_name}.write({p_expr}); }}"
                        )
                        .ok();
                    } else {
                        writeln!(out, "{indent}{mw_name}.write({p_expr});").ok();
                    }
                }
            }
        }
        Inst::CmdCheckpoint => {
            if let Some(d) = st.dst {
                writeln!(
                    out,
                    "{indent}__loc_{} = __tx_cmds.len(); __tx_depth += 1; __tx_active = true;",
                    d.0
                )
                .ok();
            }
        }
        Inst::CmdRollback { checkpoint } => {
            writeln!(
                out,
                "{indent}__tx_cmds.truncate(__loc_{}); __tx_depth = __tx_depth.saturating_sub(1); __tx_active = __tx_depth > 0;",
                checkpoint.0
            )
            .ok();
            if let Some(cl) = in_chunk
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == cl.query_idx)
            {
                let qi = plan.query_idx;
                for slot in &plan.slots {
                    if slot.mode == TermAccessMode::SelectiveWrite
                        || (slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked)
                    {
                        let si = slot.slot_idx;
                        if plan.uses_row_iter() || cl.is_pset_snap {
                            writeln!(
                                out,
                                "{indent}if !__tx_active {{ __q{qi}_tx_dirty_{si} = false; }}"
                            )
                            .ok();
                        } else {
                            writeln!(
                                out,
                                "{indent}if !__tx_active {{ __q{qi}_tx_rows_{si}.clear(); }}"
                            )
                            .ok();
                        }
                    }
                }
            }
        }
        Inst::ShadowCommit { .. } => {
            if analysis.has_checkpoint {
                writeln!(
                    out,
                    "{indent}__tx_depth = __tx_depth.saturating_sub(1); __tx_active = __tx_depth > 0;"
                )
                .ok();
                if let Some(cl) = in_chunk
                    && let Some(plan) = query_plans.iter().find(|p| p.query_idx == cl.query_idx)
                {
                    let qi = plan.query_idx;
                    for slot in &plan.slots {
                        if slot.mode == TermAccessMode::SelectiveWrite
                            || (slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked)
                        {
                            let si = slot.slot_idx;
                            if plan.uses_row_iter() || cl.is_pset_snap {
                                writeln!(
                                    out,
                                    "{indent}if !__tx_active {{ __q{qi}_dirty_{si} |= core::mem::take(&mut __q{qi}_tx_dirty_{si}); }}"
                                )
                                .ok();
                            } else if slot.mode == TermAccessMode::OptionalWrite {
                                writeln!(
                                    out,
                                    "{indent}if !__tx_active {{ if let Some(ref mut __opt_sel) = __q{qi}_sel_{si} {{ for __r in __q{qi}_tx_rows_{si}.drain(..) {{ __opt_sel.mark_dirty_row(__r); }} }} else {{ __q{qi}_tx_rows_{si}.clear(); }} }}"
                                )
                                .ok();
                            } else {
                                writeln!(
                                    out,
                                    "{indent}if !__tx_active {{ for __r in __q{qi}_tx_rows_{si}.drain(..) {{ __q{qi}_sel_{si}.mark_dirty_row(__r); }} }}"
                                )
                                .ok();
                            }
                        }
                    }
                }
            }
        }
        Inst::CmdInsertRelation {
            relation,
            entity,
            target,
            payload,
        } => {
            let ent = resolve_entity_local_expr(*entity, func, analysis, in_chunk);
            let tgt = resolve_entity_local_expr(*target, func, analysis, in_chunk);
            if is_child_of_relation(relation) {
                writeln!(
                    out,
                    "{indent}let __cmd_ent = {ent};\n{indent}let __cmd_tgt = {tgt};"
                )
                .ok();
                emit_cmd_block(out, analysis, indent, |cmds| {
                    format!(
                        "if let (Some(__s), Some(__d)) = (Entity::try_from_bits(__cmd_ent.to_bits()), Entity::try_from_bits(__cmd_tgt.to_bits())) {{ {cmds}.entity(__s).insert(ChildOf(__d)); }}"
                    )
                });
            } else {
                let resolved_rel = resolve_custom_relation_name(ctx, relation);
                if let Some((vname, _)) = analysis.relation_res_map.get(resolved_rel) {
                    let p_expr = payload
                        .map(|p| format!("__loc_{}", p.0))
                        .unwrap_or_else(|| "()".to_owned());
                    let r_idx_opt = analysis
                        .relation_res_map
                        .keys()
                        .position(|k| k == resolved_rel);
                    if analysis.has_checkpoint
                        && let Some(r_idx) = r_idx_opt
                    {
                        writeln!(
                            out,
                            "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits({ent}.to_bits()), Entity::try_from_bits({tgt}.to_bits())) {{\n\
                             {indent}    if __tx_active {{ __tx_cmds.push(__StrataTxCmd::Rel_{r_idx}Insert(__s, __d, {p_expr})); }} else {{ {vname}.insert(__s, __d, {p_expr}); }}\n\
                             {indent}}}"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits({ent}.to_bits()), Entity::try_from_bits({tgt}.to_bits())) {{\n\
                             {indent}    {vname}.insert(__s, __d, {p_expr});\n\
                             {indent}}}"
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::CmdRemoveRelation {
            relation,
            entity,
            target,
        } => {
            let ent = resolve_entity_local_expr(*entity, func, analysis, in_chunk);
            if is_child_of_relation(relation) {
                writeln!(out, "{indent}let __cmd_ent = {ent};").ok();
                emit_cmd_block(out, analysis, indent, |cmds| {
                    format!(
                        "if let Some(__s) = Entity::try_from_bits(__cmd_ent.to_bits()) {{ {cmds}.entity(__s).remove::<ChildOf>(); }}"
                    )
                });
            } else {
                let tgt = resolve_entity_local_expr(*target, func, analysis, in_chunk);
                let resolved_rel = resolve_custom_relation_name(ctx, relation);
                if let Some((vname, _)) = analysis.relation_res_map.get(resolved_rel) {
                    let r_idx_opt = analysis
                        .relation_res_map
                        .keys()
                        .position(|k| k == resolved_rel);
                    if analysis.has_checkpoint
                        && let Some(r_idx) = r_idx_opt
                    {
                        writeln!(
                            out,
                            "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits({ent}.to_bits()), Entity::try_from_bits({tgt}.to_bits())) {{\n\
                             {indent}    if __tx_active {{ __tx_cmds.push(__StrataTxCmd::Rel_{r_idx}Remove(__s, __d)); }} else {{ {vname}.remove(__s, __d); }}\n\
                             {indent}}}"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits({ent}.to_bits()), Entity::try_from_bits({tgt}.to_bits())) {{\n\
                             {indent}    {vname}.remove(__s, __d);\n\
                             {indent}}}"
                        )
                        .ok();
                    }
                }
            }
        }
    }
    let _ = dst_s;
    Ok(())
}

pub(super) fn format_bundle_tuple(parts: &[String]) -> String {
    if parts.is_empty() {
        return "()".to_owned();
    }
    if parts.len() <= 12 {
        return format!("({},)", parts.join(", "));
    }
    let chunks: Vec<String> = parts.chunks(12).map(format_bundle_tuple).collect();
    format_bundle_tuple(&chunks)
}

pub(super) fn emit_cmd_block(
    out: &mut String,
    analysis: &FnAnalysis,
    indent: &str,
    build: impl FnOnce(&str) -> String,
) {
    if analysis.needs_par_commands {
        let body = build("__cmds");
        writeln!(
            out,
            "{indent}par_commands.command_scope(|mut __cmds| {{ {body} }});"
        )
        .ok();
    } else if analysis.has_checkpoint {
        let body = build("__cmds");
        writeln!(
            out,
            "{indent}if __tx_active {{\n\
             {indent}    __tx_cmds.push(__StrataTxCmd::Spawn(Box::new(move |mut __cmds| {{ {body} }})));\n\
             {indent}}} else {{\n\
             {indent}    let __cmds = &mut commands;\n\
             {indent}    {body}\n\
             {indent}}}"
        )
        .ok();
    } else {
        let body = build("commands");
        writeln!(out, "{indent}{body}").ok();
    }
}

pub(super) fn query_access_expr(plan: &QueryEmitPlan) -> String {
    if let Some(pidx) = plan.param_set_idx {
        format!("q_set.p{pidx}()")
    } else {
        plan.param_name.clone()
    }
}

pub(super) fn chunk_len_expr(
    query_idx: u32,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
) -> String {
    let Some(plan) = query_plans.iter().find(|p| p.query_idx == query_idx) else {
        return "0u32".to_owned();
    };
    if plan.uses_row_iter() || in_chunk.is_some_and(ChunkLoopInfo::is_1row) {
        return "1u32".to_owned();
    }
    if plan.needs_entity {
        return format!("(__q{query_idx}_entities.len() as u32)");
    }
    if let Some(slot) = plan.slots.first() {
        let si = slot.slot_idx;
        if slot.mode == TermAccessMode::SelectiveWrite {
            return format!("(__q{query_idx}_sel_{si}.len() as u32)");
        }
        if slot.mode == TermAccessMode::OptionalWrite && slot.is_untracked {
            return format!("(__q{query_idx}_sel_{si}.as_ref().map_or(0, |s| s.len()) as u32)");
        }
        if matches!(
            slot.mode,
            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
        ) {
            return format!("(__q{query_idx}_col_{si}.as_ref().map_or(0, |s| s.len()) as u32)");
        }
        return format!("(__q{query_idx}_col_{si}.len() as u32)");
    }
    "0u32".to_owned()
}

pub(super) fn emit_terminator(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    analysis: &FnAnalysis,
    term: &Terminator,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
) {
    let ret_val_expr = |l: LocalId| -> String {
        let ret_vt = ValTy::from_mir_ret(&func.ret_ty);
        if matches!(func.ret_ty, MirType::Named(_)) {
            let (vt, ve) = effective_local_val_and_expr(l, analysis, &[], in_chunk, ctx);
            let _ = vt;
            ve
        } else {
            coerce_local_expr(
                Some(l),
                &format!("__loc_{}", l.0),
                &analysis.val_tys[l.0 as usize],
                &ret_vt,
                analysis,
            )
        }
    };
    let has_tx_ret_val = analysis.has_checkpoint
        && matches!(func.kind, MirFnKind::HelperFn)
        && !matches!(func.ret_ty, MirType::Unit);
    match term {
        Terminator::Return(opt_l) => {
            if let Some(cl) = in_chunk {
                if !cl.use_par {
                    if has_tx_ret_val
                        && let Some(l) = opt_l
                        && analysis.val_tys[l.0 as usize] != ValTy::Unit
                    {
                        writeln!(out, "{indent}__tx_ret_val = {};", ret_val_expr(*l)).ok();
                    }
                    writeln!(
                        out,
                        "{indent}__returned = true;\n{indent}__broke_loop = true;"
                    )
                    .ok();
                }
                writeln!(out, "{indent}break;").ok();
            } else if analysis.has_checkpoint {
                if has_tx_ret_val
                    && let Some(l) = opt_l
                    && analysis.val_tys[l.0 as usize] != ValTy::Unit
                {
                    writeln!(out, "{indent}__tx_ret_val = {};", ret_val_expr(*l)).ok();
                }
                writeln!(out, "{indent}break;").ok();
            } else if let Some(l) = opt_l
                && matches!(func.kind, MirFnKind::HelperFn)
                && analysis.val_tys[l.0 as usize] != ValTy::Unit
            {
                writeln!(out, "{indent}return {};", ret_val_expr(*l)).ok();
            } else {
                writeln!(out, "{indent}return;").ok();
            }
        }
        Terminator::Goto(dst) => {
            if let Some(cl) = in_chunk {
                if *dst == cl.hdr_bb {
                    writeln!(out, "{indent}break;").ok();
                } else if *dst == cl.exit_bb {
                    if !cl.use_par {
                        writeln!(out, "{indent}__broke_loop = true;").ok();
                    }
                    writeln!(out, "{indent}break;").ok();
                } else {
                    writeln!(out, "{indent}__inner_bb = {};", dst.0).ok();
                }
            } else {
                writeln!(out, "{indent}__bb = {};", dst.0).ok();
            }
        }
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            let c_expr = format!("__loc_{}", cond.0);
            let then_arm = format_branch_target(*then_bb, in_chunk);
            let else_arm = format_branch_target(*else_bb, in_chunk);
            writeln!(
                out,
                "{indent}if {c_expr} {{ {then_arm} }} else {{ {else_arm} }}"
            )
            .ok();
        }
        Terminator::Switch {
            scrutinee,
            cases,
            default_bb,
        } => {
            writeln!(out, "{indent}match __loc_{} as u32 {{", scrutinee.0).ok();
            for (disc, target) in cases {
                let arm = format_branch_target(*target, in_chunk);
                writeln!(out, "{indent}    {disc} => {{ {arm} }}").ok();
            }
            let def_arm = format_branch_target(*default_bb, in_chunk);
            writeln!(out, "{indent}    _ => {{ {def_arm} }}\n{indent}}}").ok();
        }
    }
}

pub(super) fn format_branch_target(target: BlockId, in_chunk: Option<&ChunkLoopInfo>) -> String {
    if let Some(cl) = in_chunk {
        if target == cl.hdr_bb {
            "break;".to_owned()
        } else if target == cl.exit_bb {
            if cl.use_par {
                "break;".to_owned()
            } else {
                "__broke_loop = true; break;".to_owned()
            }
        } else {
            format!("__inner_bb = {};", target.0)
        }
    } else {
        format!("__bb = {};", target.0)
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_helper_call_with_places(
    out: &mut String,
    caller: &MirFunction,
    hf: &MirFunction,
    args: &[LocalId],
    dst: Option<LocalId>,
    ctx: &NativeCtx<'_>,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
    in_undo: bool,
) {
    let mut prebound: Vec<Option<String>> = vec![None; args.len()];
    for (i, &a) in args.iter().enumerate() {
        let kind = hf.params.get(i).map_or(HirParamKind::Value, |p| p.kind);
        if kind == HirParamKind::Value {
            let expr = if let Some(p) = hf.params.get(i) {
                let target_vt = ValTy::from_mir(&p.ty, ctx);
                let (avt, aexpr) =
                    effective_local_val_and_expr(a, analysis, query_plans, in_chunk, ctx);
                coerce_expr(&aexpr, &avt, &target_vt)
            } else {
                effective_local_val_and_expr(a, analysis, query_plans, in_chunk, ctx).1
            };
            let vname = format!("__carg_{i}");
            writeln!(out, "{indent}let {vname} = {expr};").ok();
            prebound[i] = Some(vname);
        }
    }

    let mut callee_implicit_res = BTreeMap::new();
    collect_helper_implicit_res(&hf.name, ctx, &mut callee_implicit_res, &mut HashSet::new());
    let mut extra_res_args = Vec::new();
    let caller_is_helper = matches!(caller.kind, MirFnKind::HelperFn);
    for (canon, (vname, is_mut, _)) in &callee_implicit_res {
        if hf.resources.iter().any(|r| r.canonical_name == *canon) {
            continue;
        }
        if caller_is_helper
            && let Some((cvname, caller_mut, _)) = analysis.implicit_res_map.get(canon)
        {
            if *caller_mut && !*is_mut {
                extra_res_args.push(format!("(&*{cvname})"));
            } else {
                extra_res_args.push(cvname.clone());
            }
        } else if *is_mut {
            extra_res_args.push(format!("(&mut *{vname})"));
        } else {
            extra_res_args.push(format!("(&*{vname})"));
        }
    }

    let fn_ident = sanitize_ident(&hf.name);
    #[allow(clippy::too_many_arguments)]
    fn build_step(
        idx: usize,
        hf: &MirFunction,
        fn_ident: &str,
        args: &[LocalId],
        prebound: &[Option<String>],
        bound_args: &mut Vec<String>,
        extra_res_args: &[String],
        dst: Option<LocalId>,
        ctx: &NativeCtx<'_>,
        analysis: &FnAnalysis,
        query_plans: &[QueryEmitPlan],
        in_chunk: Option<&ChunkLoopInfo>,
        in_undo: bool,
    ) -> String {
        if idx >= args.len() {
            let mut all_args = bound_args.clone();
            all_args.extend(extra_res_args.iter().cloned());
            let call_expr = format!("strata_fn_{fn_ident}({})", all_args.join(", "));
            if let Some(d) = dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt != ValTy::Unit && *dt != ValTy::PtrMarker {
                    let ret_vt = ValTy::from_mir(&hf.ret_ty, ctx);
                    let coerced = coerce_expr(&call_expr, &ret_vt, dt);
                    return format!("__loc_{} = {coerced};", d.0);
                }
            }
            return format!("let _ = {call_expr};");
        }
        if let Some(pre) = &prebound[idx] {
            bound_args.push(pre.clone());
            let s = build_step(
                idx + 1,
                hf,
                fn_ident,
                args,
                prebound,
                bound_args,
                extra_res_args,
                dst,
                ctx,
                analysis,
                query_plans,
                in_chunk,
                in_undo,
            );
            bound_args.pop();
            return s;
        }
        let a = args[idx];
        let kind = hf.params.get(idx).map_or(HirParamKind::Value, |p| p.kind);
        match kind {
            HirParamKind::RefMut => match analysis.ptr_targets.get(&a) {
                Some(PtrTarget::ParamPtr { var_name, .. }) => {
                    bound_args.push(var_name.clone());
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
                Some(PtrTarget::Resource { var_name, .. }) => {
                    bound_args.push(format!("(&mut *{var_name})"));
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
                Some(pt) => {
                    let mut sub = String::new();
                    if let Some((canon, pf, fvt)) = ptr_projected_field(pt) {
                        let access = resolve_blob_field_access(canon, pf, ctx);
                        let rty = fvt.rust_type();
                        emit_place_mut_for_target(
                            &mut sub,
                            pt,
                            analysis,
                            query_plans,
                            in_chunk,
                            "",
                            in_undo,
                            &|place| {
                                let ld = build_field_load_from_place(place, &access, fvt, ctx);
                                let mut next_args = bound_args.clone();
                                next_args.push("(&mut __pmut_arg)".to_owned());
                                let call_s = build_step(
                                    idx + 1,
                                    hf,
                                    fn_ident,
                                    args,
                                    prebound,
                                    &mut next_args,
                                    extra_res_args,
                                    dst,
                                    ctx,
                                    analysis,
                                    query_plans,
                                    in_chunk,
                                    in_undo,
                                );
                                let wb = if let Some(sf) = access.sf_opt {
                                    wrap_abi_field_store("__pmut_arg", sf, ctx, false)
                                } else {
                                    "__pmut_arg".to_owned()
                                };
                                let assign = if access.steps.is_empty() {
                                    format!("{place}.{} = {wb};", access.leaf_chain)
                                } else {
                                    let mut stmts = Vec::new();
                                    for (sidx, step) in access.steps.iter().enumerate() {
                                        let src_e = if sidx == 0 {
                                            format!("{place}.{}", step.rfname)
                                        } else {
                                            format!("__pbs_{}.{}", sidx - 1, step.rfname)
                                        };
                                        stmts.push(format!(
                                            "let mut __pbs_{sidx} = {}::{}(&{src_e});",
                                            step.struct_name, step.unpack_fn
                                        ));
                                    }
                                    let last = access.steps.len() - 1;
                                    stmts.push(format!(
                                        "__pbs_{last}.{} = {wb};",
                                        access.leaf_chain
                                    ));
                                    for sidx in (1..access.steps.len()).rev() {
                                        let step = &access.steps[sidx];
                                        stmts.push(format!(
                                            "__pbs_{}.{} = __pbs_{sidx}.{}();",
                                            sidx - 1,
                                            step.rfname,
                                            step.pack_fn
                                        ));
                                    }
                                    let first = &access.steps[0];
                                    stmts.push(format!(
                                        "{place}.{} = __pbs_0.{}();",
                                        first.rfname, first.pack_fn
                                    ));
                                    stmts.join(" ")
                                };
                                format!("let mut __pmut_arg: {rty} = {ld}; {call_s} {assign}")
                            },
                        );
                    } else {
                        emit_place_mut_for_target(
                            &mut sub,
                            pt,
                            analysis,
                            query_plans,
                            in_chunk,
                            "",
                            in_undo,
                            &|ref_e| {
                                let mut next_args = bound_args.clone();
                                next_args.push(ref_e.to_owned());
                                build_step(
                                    idx + 1,
                                    hf,
                                    fn_ident,
                                    args,
                                    prebound,
                                    &mut next_args,
                                    extra_res_args,
                                    dst,
                                    ctx,
                                    analysis,
                                    query_plans,
                                    in_chunk,
                                    in_undo,
                                )
                            },
                        );
                    }
                    sub
                }
                None => {
                    bound_args.push(format!("(&mut __loc_{})", a.0));
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
            },
            HirParamKind::Ref => match analysis.ptr_targets.get(&a) {
                Some(PtrTarget::ParamPtr { var_name, .. }) => {
                    bound_args.push(var_name.clone());
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
                Some(PtrTarget::Resource { var_name, .. }) => {
                    bound_args.push(format!("(&*{var_name})"));
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
                Some(pt) => {
                    let expr = if let Some((canon, pf, fvt)) = ptr_projected_field(pt) {
                        let access = resolve_blob_field_access(canon, pf, ctx);
                        let rty = fvt.rust_type();
                        emit_place_ref_for_target(
                            pt,
                            analysis,
                            query_plans,
                            in_chunk,
                            &|place| {
                                let ld = build_field_load_from_place(place, &access, fvt, ctx);
                                let mut next_args = bound_args.clone();
                                next_args.push("(&__pref_arg)".to_owned());
                                let s = build_step(
                                    idx + 1,
                                    hf,
                                    fn_ident,
                                    args,
                                    prebound,
                                    &mut next_args,
                                    extra_res_args,
                                    dst,
                                    ctx,
                                    analysis,
                                    query_plans,
                                    in_chunk,
                                    in_undo,
                                );
                                format!("{{ let __pref_arg: {rty} = {ld}; {s} }}")
                            },
                            "{}",
                        )
                    } else {
                        emit_place_ref_for_target(
                            pt,
                            analysis,
                            query_plans,
                            in_chunk,
                            &|ref_e| {
                                let mut next_args = bound_args.clone();
                                next_args.push(ref_e.to_owned());
                                let s = build_step(
                                    idx + 1,
                                    hf,
                                    fn_ident,
                                    args,
                                    prebound,
                                    &mut next_args,
                                    extra_res_args,
                                    dst,
                                    ctx,
                                    analysis,
                                    query_plans,
                                    in_chunk,
                                    in_undo,
                                );
                                format!("{{ {s} }}")
                            },
                            "{}",
                        )
                    };
                    format!("let _ = {expr};")
                }
                None => {
                    bound_args.push(format!("(&__loc_{})", a.0));
                    let s = build_step(
                        idx + 1,
                        hf,
                        fn_ident,
                        args,
                        prebound,
                        bound_args,
                        extra_res_args,
                        dst,
                        ctx,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                    );
                    bound_args.pop();
                    s
                }
            },
            _ => unreachable!(),
        }
    }

    let mut bound_args = Vec::with_capacity(args.len());
    let body = build_step(
        0,
        hf,
        &fn_ident,
        args,
        &prebound,
        &mut bound_args,
        &extra_res_args,
        dst,
        ctx,
        analysis,
        query_plans,
        in_chunk,
        in_undo,
    );
    for line in body.lines() {
        if !line.is_empty() {
            writeln!(out, "{indent}{line}").ok();
        }
    }
}
