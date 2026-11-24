//! RustGuest CFG block, instruction, `@par` chunk, and terminator emission.

use super::*;

/// Builds the Rust expression initializing a default `StrataVal` for a stack slot of `ty`.
fn guest_slot_default_expr(ty: &MirType, mir: &MirModule, cat: &GuestCatalog) -> String {
    match ty {
        MirType::Named(n) => {
            if let Some(rc) = cat.resolve_comp(n) {
                format!(
                    "StrataVal::Obj(StrataObj::{}({}::default()))",
                    rc.variant_name, rc.struct_name
                )
            } else if let Some(bits) = n
                .strip_prefix("BitSet<")
                .and_then(|s| s.strip_suffix('>'))
                .and_then(|s| s.parse::<usize>().ok())
            {
                format!("StrataVal::Words(vec![0u32; {}])", bits.div_ceil(32).max(1))
            } else if n.starts_with("InlineStr<") {
                "StrataVal::Str(String::new())".to_owned()
            } else if n == "mat3" || n == "Mat3" {
                "StrataVal::Arr(vec![StrataVal::F32(0.0); 9])".to_owned()
            } else if n == "mat4" || n == "Mat4" {
                "StrataVal::Arr(vec![StrataVal::F32(0.0); 16])".to_owned()
            } else if let Some(sty) = mir_ty_to_guest_ty_hint(ty, mir) {
                let (sz, _) = guest_ty_abi_size_align(&sty, mir);
                format!("StrataVal::Bytes(vec![0u8; {}])", sz.max(1))
            } else {
                default_strata_val_for_mir_ty(ty).to_owned()
            }
        }
        MirType::Array { .. } => {
            let sz = if let Some(sty) = mir_ty_to_guest_ty_hint(ty, mir) {
                guest_ty_abi_size_align(&sty, mir).0
            } else {
                guest_mir_elem_byte_size(ty, cat)
            };
            format!("StrataVal::Bytes(vec![0u8; {}])", sz.max(1))
        }
        MirType::Tuple(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|it| default_strata_val_for_mir_ty(it).to_owned())
                .collect();
            format!("StrataVal::Tuple(vec![{}])", parts.join(", "))
        }
        _ => default_strata_val_for_mir_ty(ty).to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_cfg_body(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    query_remap: &[usize],
    stream_decls: &[(String, bool)],
    named_fallback_queries: &HashMap<String, usize>,
    migrate_vars: Option<(&str, &str)>,
    observer_vars: Option<(&str, &str)>,
) {
    let local_count = func.locals.len().max(1);
    writeln!(
        out,
        "    let mut locals: [StrataVal; {local_count}] = [const {{ StrataVal::Unit }}; {local_count}];"
    )
    .ok();
    for (p_idx, p) in func.params.iter().enumerate() {
        if let Some(lid) = p.local {
            writeln!(
                out,
                "    if let Some(_arg) = args.get({p_idx}) {{ locals[{li}] = _arg.clone(); }}",
                li = lid.0
            )
            .ok();
        }
    }
    writeln!(
        out,
        "    let mut slots: [StrataVal; {local_count}] = [const {{ StrataVal::Unit }}; {local_count}];\n\
         \x20   let mut spatial_hits: Vec<Vec<(FfiEntity, [f32; 4])>> = Vec::new();\n\
         \x20   let mut spawn_batches: Vec<Option<StrataBatchBuf>> = Vec::new();\n\
         \x20   let mut par_consumed: [bool; {nq}] = [false; {nq}];\n\
         \x20   let mut iter_started_once: [bool; {nq}] = [false; {nq}];\n\
         \x20   let mut dirty_runs: HashMap<usize, (u32, u32)> = HashMap::new();",
        nq = phys_queries.len().max(1)
    )
    .ok();

    let mut stream_read_idx = 0usize;
    for p in &func.params {
        if p.kind == HirParamKind::StreamIn
            && let Some(lid) = p.local
        {
            let stream_op = func
                .stream_ops
                .iter()
                .filter(|op| op.kind == MirStreamOpKind::StreamRead)
                .nth(stream_read_idx);
            stream_read_idx += 1;
            if let Some(op) = stream_op
                && let Some(comp) = cat
                    .resolve_comp(&op.canonical_stream)
                    .or_else(|| cat.resolve_comp(&op.stream))
            {
                let decl_idx = stream_decl_index(stream_decls, cat, &op.canonical_stream);
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                let li = lid.0;
                writeln!(
                    out,
                    "    if let HostBridge::System(ref mut sys_ctx) = *bridge {{\n\
                     \x20       let _msg = sys_ctx.read_messages::<{sname}>(stream_base + {decl_idx}).ok().and_then(|v| v.into_iter().last()).unwrap_or_default();\n\
                     \x20       slots[{li}] = StrataVal::Obj(StrataObj::{vname}(_msg));\n\
                     \x20       locals[{li}] = StrataVal::Ptr(StrataPtr::Slot {{ sid: {li}, off: 0 }});\n\
                     \x20   }}"
                )
                .ok();
            }
        }
    }

    if func.blocks.is_empty() {
        emit_default_fn_return(out, func, migrate_vars);
        return;
    }

    let const_info = collect_guest_fn_const_info(func, mir, cat);

    let mut def_counts: HashMap<u32, usize> = HashMap::new();
    for p in &func.params {
        if let Some(lid) = p.local {
            *def_counts.entry(lid.0).or_insert(0) += 1;
        }
    }
    let mut single_slot_allocs: Vec<(u32, MirType)> = Vec::new();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Some(d) = st.dst {
                *def_counts.entry(d.0).or_insert(0) += 1;
                if let Inst::SlotAlloc { ty } = &st.inst {
                    single_slot_allocs.push((d.0, ty.clone()));
                }
            }
        }
    }
    for (sid, ty) in single_slot_allocs {
        if def_counts.get(&sid) == Some(&1) {
            let def = guest_slot_default_expr(&ty, mir, cat);
            writeln!(
                out,
                "    slots[{sid}] = {def};\n\
                 \x20   locals[{sid}] = StrataVal::Ptr(StrataPtr::Slot {{ sid: {sid}, off: 0 }});"
            )
            .ok();
        }
    }

    let fast_loops = if migrate_vars.is_none()
        && observer_vars.is_none()
        && !matches!(
            func.kind,
            MirFnKind::HelperFn | MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
        ) {
        analyze_guest_fast_loops(mir, cat, func, phys_queries)
    } else {
        Vec::new()
    };

    let mut par_fast_by_bb: HashMap<u32, usize> = HashMap::new();
    let mut par_seq_skip_by_bb: HashSet<u32> = HashSet::new();
    let mut hdr_fast_by_bb: HashMap<u32, usize> = HashMap::new();
    let mut skip_fast_blocks: HashSet<u32> = HashSet::new();
    for (idx, fl) in fast_loops.iter().enumerate() {
        if fl.use_par
            && let Some(pbb) = fl.par_bb
        {
            par_fast_by_bb.insert(pbb.0, idx);
            skip_fast_blocks.insert(fl.hdr_bb.0);
        } else {
            if let Some(pbb) = fl.par_bb {
                par_seq_skip_by_bb.insert(pbb.0);
            }
            hdr_fast_by_bb.insert(fl.hdr_bb.0, idx);
        }
        for &lb in &fl.loop_blocks {
            skip_fast_blocks.insert(lb.0);
        }
    }

    // Emit local helper methods for field read/write on Ptr inside this function's stack/bridge!
    writeln!(out, "    let mut __bb: u32 = 0;").ok();
    writeln!(out, "    loop {{").ok();
    writeln!(out, "        match __bb {{").ok();
    for (bi, bb) in func.blocks.iter().enumerate() {
        if skip_fast_blocks.contains(&(bi as u32)) {
            continue;
        }
        writeln!(out, "            {bi} => {{").ok();
        if let Some(&fl_idx) = par_fast_by_bb.get(&(bi as u32)) {
            let fl = &fast_loops[fl_idx];
            let prefix_len = bb.stmts.len().saturating_sub(1);
            for stmt in &bb.stmts[..prefix_len] {
                emit_inst(
                    out,
                    mir,
                    cat,
                    func,
                    phys_queries,
                    query_remap,
                    stream_decls,
                    named_fallback_queries,
                    &const_info,
                    migrate_vars,
                    observer_vars,
                    stmt,
                    bb,
                );
            }
            emit_guest_fast_loop(out, mir, cat, func, phys_queries, query_remap, fl);
            writeln!(out, "                __bb = {};", fl.exit_bb.0).ok();
            writeln!(out, "            }}").ok();
            continue;
        }
        if let Some(&fl_idx) = hdr_fast_by_bb.get(&(bi as u32)) {
            let fl = &fast_loops[fl_idx];
            emit_guest_fast_loop(out, mir, cat, func, phys_queries, query_remap, fl);
            writeln!(out, "                __bb = {};", fl.exit_bb.0).ok();
            writeln!(out, "            }}").ok();
            continue;
        }
        let stmts_to_emit = if par_seq_skip_by_bb.contains(&(bi as u32)) {
            let prefix_len = bb.stmts.len().saturating_sub(1);
            &bb.stmts[..prefix_len]
        } else {
            &bb.stmts[..]
        };
        for stmt in stmts_to_emit {
            emit_inst(
                out,
                mir,
                cat,
                func,
                phys_queries,
                query_remap,
                stream_decls,
                named_fallback_queries,
                &const_info,
                migrate_vars,
                observer_vars,
                stmt,
                bb,
            );
        }
        emit_terminator(out, func, &bb.terminator, &const_info, migrate_vars);
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "            _ => break,").ok();
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    emit_default_fn_return(out, func, migrate_vars);
}

pub(super) fn emit_default_fn_return(
    out: &mut String,
    func: &MirFunction,
    migrate_vars: Option<(&str, &str)>,
) {
    if migrate_vars.is_some() {
        writeln!(out, "    migrate_dst").ok();
    } else {
        match func.kind {
            MirFnKind::HelperFn => writeln!(out, "    StrataVal::Unit").ok(),
            MirFnKind::Observer { .. } => writeln!(out).ok(),
            _ => writeln!(out, "    FfiResult::OK").ok(),
        };
    }
}

pub(super) fn emit_terminator(
    out: &mut String,
    func: &MirFunction,
    term: &Terminator,
    const_info: &GuestFnConstInfo,
    migrate_vars: Option<(&str, &str)>,
) {
    match term {
        Terminator::Return(opt) => {
            if migrate_vars.is_some() {
                writeln!(out, "                return migrate_dst;").ok();
            } else {
                match func.kind {
                    MirFnKind::HelperFn => {
                        if let Some(lid) = opt {
                            let ret_expr = guest_coerce_val_expr_for_mir_ty(
                                &func.ret_ty,
                                *lid,
                                func,
                                const_info,
                            );
                            writeln!(out, "                return {ret_expr};").ok();
                        } else {
                            writeln!(out, "                return StrataVal::Unit;").ok();
                        }
                    }
                    MirFnKind::Observer { .. } => {
                        writeln!(out, "                return;").ok();
                    }
                    _ => {
                        writeln!(out, "                return FfiResult::OK;").ok();
                    }
                }
            }
        }
        Terminator::Goto(BlockId(dst)) => {
            writeln!(out, "                __bb = {dst};").ok();
        }
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            writeln!(
                out,
                "                __bb = if locals[{}].as_bool() {{ {} }} else {{ {} }};",
                cond.0, then_bb.0, else_bb.0
            )
            .ok();
        }
        Terminator::Switch {
            scrutinee,
            cases,
            default_bb,
        } => {
            writeln!(
                out,
                "                __bb = match locals[{}].as_u32() {{",
                scrutinee.0
            )
            .ok();
            for (val, BlockId(dst)) in cases {
                writeln!(out, "                    {val} => {dst},").ok();
            }
            writeln!(out, "                    _ => {},", default_bb.0).ok();
            writeln!(out, "                }};").ok();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_inst(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    query_remap: &[usize],
    stream_decls: &[(String, bool)],
    named_fallback_queries: &HashMap<String, usize>,
    const_info: &GuestFnConstInfo,
    _migrate_vars: Option<(&str, &str)>,
    observer_vars: Option<(&str, &str)>,
    stmt: &strata_mir::MirStmt,
    cur_bb: &BasicBlock,
) {
    let assign_dst = |out: &mut String, expr: &str| {
        if let Some(dst) = stmt.dst {
            writeln!(out, "                locals[{}] = {expr};", dst.0).ok();
        } else {
            writeln!(out, "                let _ = {expr};").ok();
        }
    };

    let dst_ty = stmt
        .dst
        .and_then(|d| func.locals.get(d.0 as usize))
        .map_or(MirType::Unit, |l| l.ty.clone());

    match &stmt.inst {
        Inst::ConstInt { value } => {
            let expr = match dst_ty {
                MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => {
                    format!("StrataVal::U32(({value}i64) as u32)")
                }
                MirType::U64 => format!("StrataVal::U64(({value}i64) as u64)"),
                MirType::I64 => format!("StrataVal::I64({value}i64)"),
                MirType::Fix32 => format!(
                    "StrataVal::Fix32({})",
                    format_fix32_i32_lit(scale_int_fix32(*value))
                ),
                MirType::Fix64 => format!(
                    "StrataVal::Fix64({})",
                    format_fix64_i64_lit(scale_int_fix64(*value))
                ),
                MirType::F32 => format!("StrataVal::F32({}f32)", *value as f32),
                MirType::F64 => format!("StrataVal::F64({}f64)", *value as f64),
                MirType::Bool => format!("StrataVal::Bool({})", *value != 0),
                MirType::Entity => {
                    format!("StrataVal::Entity(FfiEntity::from_bits(({value}i64) as u64))")
                }
                MirType::Unit => "StrataVal::Unit".to_owned(),
                _ => format!("StrataVal::I32(({value}i64) as i32)"),
            };
            assign_dst(out, &expr);
        }
        Inst::ConstFloat { value } => {
            let expr = match dst_ty {
                MirType::F64 => format!("StrataVal::F64({})", fmt_f64(*value)),
                MirType::Fix32 => format!(
                    "StrataVal::Fix32({})",
                    format_fix32_i32_lit(scale_float_fix32(*value))
                ),
                MirType::Fix64 => format!(
                    "StrataVal::Fix64({})",
                    format_fix64_i64_lit(scale_float_fix64(*value))
                ),
                _ => format!("StrataVal::F32({})", fmt_f32(*value as f32)),
            };
            assign_dst(out, &expr);
        }
        Inst::ConstBool { value } => {
            if dst_ty == MirType::Unit {
                assign_dst(out, "StrataVal::Unit");
            } else {
                assign_dst(out, &format!("StrataVal::Bool({value})"));
            }
        }
        Inst::ConstVec { dims, values } => {
            let expr = match dst_ty {
                MirType::IVec2 => format!(
                    "StrataVal::IVec2([{}i32, {}i32])",
                    values[0] as i32, values[1] as i32
                ),
                MirType::IVec3 => format!(
                    "StrataVal::IVec3([{}i32, {}i32, {}i32])",
                    values[0] as i32, values[1] as i32, values[2] as i32
                ),
                MirType::UVec2 => format!(
                    "StrataVal::UVec2([{}u32, {}u32])",
                    values[0] as u32, values[1] as u32
                ),
                _ => match dims {
                    2 => format!(
                        "StrataVal::Vec2([{}, {}])",
                        fmt_f32(values[0] as f32),
                        fmt_f32(values[1] as f32)
                    ),
                    3 => format!(
                        "StrataVal::Vec3([{}, {}, {}])",
                        fmt_f32(values[0] as f32),
                        fmt_f32(values[1] as f32),
                        fmt_f32(values[2] as f32)
                    ),
                    _ => format!(
                        "StrataVal::Vec4([{}, {}, {}, {}])",
                        fmt_f32(values[0] as f32),
                        fmt_f32(values[1] as f32),
                        fmt_f32(values[2] as f32),
                        fmt_f32(values[3] as f32)
                    ),
                },
            };
            assign_dst(out, &expr);
        }
        Inst::ConstString { value } => {
            let esc = escape_rust_str(value);
            assign_dst(out, &format!("StrataVal::Str(\"{esc}\".to_owned())"));
        }
        Inst::Copy { val } => {
            assign_dst(out, &format!("locals[{}].clone()", val.0));
        }
        Inst::SlotAlloc { ty } => {
            if let Some(dst) = stmt.dst {
                let def = guest_slot_default_expr(ty, mir, cat);
                writeln!(
                    out,
                    "                slots[{d}] = {def};\n\
                     \x20               locals[{d}] = StrataVal::Ptr(StrataPtr::Slot {{ sid: {d}, off: 0 }});",
                    d = dst.0
                )
                .ok();
            }
        }
        Inst::SlotLoad { slot } => {
            let expr = match const_info.slot_types.get(slot) {
                Some(slot_ty @ MirType::Array { .. }) => {
                    if let Some(sty) = mir_ty_to_guest_ty_hint(slot_ty, mir) {
                        let (sz, _) = guest_ty_abi_size_align(&sty, mir);
                        let unpack = emit_runtime_read_ty_from_bytes("_b", "0", &sty, sz, mir, cat);
                        format!(
                            "match locals[{s}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => match &slots[sid] {{ StrataVal::Bytes(_b) => {unpack}, other => other.clone() }}, _ => locals[{s}].clone() }}",
                            s = slot.0
                        )
                    } else {
                        format!(
                            "match locals[{s}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].clone(), _ => locals[{s}].clone() }}",
                            s = slot.0
                        )
                    }
                }
                _ => format!(
                    "match locals[{s}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].clone(), _ => locals[{s}].clone() }}",
                    s = slot.0
                ),
            };
            assign_dst(out, &expr);
        }
        Inst::SlotStore { slot, val } => {
            let val_expr = if let Some(slot_ty) = const_info.slot_types.get(slot) {
                let raw_expr = guest_coerce_val_expr_for_mir_ty(slot_ty, *val, func, const_info);
                match mir_ty_to_guest_ty_hint(slot_ty, mir) {
                    Some(
                        sty @ (Ty::Array { .. } | Ty::SmallVec { .. } | Ty::InputBuffer { .. }),
                    ) => {
                        let (sz, _) = guest_ty_abi_size_align(&sty, mir);
                        let wr =
                            emit_runtime_write_ty_into_bytes("_buf", "0", "_sv", &sty, sz, mir);
                        format!(
                            "{{ let _sv = {raw_expr}; if let StrataVal::Bytes(mut _b) = _sv {{ _b.resize({sz}, 0); StrataVal::Bytes(_b) }} else {{ let mut _buf = vec![0u8; {sz}]; {wr} StrataVal::Bytes(_buf) }} }}"
                        )
                    }
                    Some(Ty::InlineStr(cap)) => format!(
                        "match {raw_expr} {{ StrataVal::Bytes(ref _b) => strata_decode_inline_str_bytes(_b, {cap}), StrataVal::Words(ref _ws) => strata_decode_inline_str_words(_ws, {cap}), StrataVal::Str(mut _s) => {{ let mut _end = _s.len().min({cap}); while _end > 0 && !_s.is_char_boundary(_end) {{ _end -= 1; }} _s.truncate(_end); StrataVal::Str(_s) }}, other => other }}"
                    ),
                    Some(Ty::Mat3) => format!(
                        "match {raw_expr} {{ StrataVal::Bytes(ref _b) => StrataVal::Arr((0..9).map(|_j| StrataVal::F32(strata_bytes_read_f32(_b, _j * 4))).collect()), other => other }}"
                    ),
                    Some(Ty::Mat4) => format!(
                        "match {raw_expr} {{ StrataVal::Bytes(ref _b) => StrataVal::Arr((0..16).map(|_j| StrataVal::F32(strata_bytes_read_f32(_b, _j * 4))).collect()), other => other }}"
                    ),
                    _ => raw_expr,
                }
            } else {
                format!("locals[{}].clone()", val.0)
            };
            writeln!(
                out,
                "                if let StrataPtr::Slot {{ sid, .. }} = locals[{s}].as_ptr() {{ slots[sid] = {val_expr}; }}",
                s = slot.0
            )
            .ok();
        }
        Inst::BinOp {
            op,
            lhs,
            rhs,
            allow_fma,
        } => {
            let esc = escape_rust_str(op);
            assign_dst(
                out,
                &format!(
                    "strata_binop(\"{esc}\", &locals[{}], &locals[{}], {allow_fma})",
                    lhs.0, rhs.0
                ),
            );
        }
        Inst::UnOp { op, val } => {
            let esc = escape_rust_str(op);
            assign_dst(out, &format!("strata_unop(\"{esc}\", &locals[{}])", val.0));
        }
        Inst::Cast { val, target_ty } => {
            let expr = match target_ty {
                MirType::Bool => format!("StrataVal::Bool(locals[{}].as_bool())", val.0),
                MirType::I8 => format!("StrataVal::I32(i32::from(locals[{}].as_i8()))", val.0),
                MirType::I16 => format!("StrataVal::I32(i32::from(locals[{}].as_i16()))", val.0),
                MirType::I32 => {
                    format!("StrataVal::I32(locals[{}].as_i32())", val.0)
                }
                MirType::U8 => format!("StrataVal::U32(u32::from(locals[{}].as_u8()))", val.0),
                MirType::U16 => format!("StrataVal::U32(u32::from(locals[{}].as_u16()))", val.0),
                MirType::U32 | MirType::Sym => {
                    format!("StrataVal::U32(locals[{}].as_u32())", val.0)
                }
                MirType::I64 => format!("StrataVal::I64(locals[{}].as_i64())", val.0),
                MirType::U64 => format!("StrataVal::U64(locals[{}].as_u64())", val.0),
                MirType::F32 => format!("StrataVal::F32(locals[{}].as_f32())", val.0),
                MirType::Fix32 | MirType::Fix64 | MirType::F64 => {
                    guest_coerce_val_expr_for_mir_ty(target_ty, *val, func, const_info)
                }
                MirType::Entity => format!("StrataVal::Entity(locals[{}].as_entity())", val.0),
                _ => format!("locals[{}].clone()", val.0),
            };
            assign_dst(out, &expr);
        }
        Inst::VecExtract { vec, lane } => {
            let l = *lane as usize;
            assign_dst(
                out,
                &format!(
                    "match &locals[{}] {{ StrataVal::Vec2(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::Vec3(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::Vec4(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::IVec2(v) => StrataVal::I32(*v.get({l}).unwrap_or(&0)), StrataVal::IVec3(v) => StrataVal::I32(*v.get({l}).unwrap_or(&0)), StrataVal::UVec2(v) => StrataVal::U32(*v.get({l}).unwrap_or(&0)), _ => StrataVal::F32(0.0) }}",
                    vec.0
                ),
            );
        }
        Inst::VecInsert { vec, lane, val } => {
            let l = *lane as usize;
            assign_dst(
                out,
                &format!(
                    "match locals[{}].clone() {{ StrataVal::Vec2(mut v) => {{ if {l} < 2 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec2(v) }} StrataVal::Vec3(mut v) => {{ if {l} < 3 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec3(v) }} StrataVal::Vec4(mut v) => {{ if {l} < 4 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec4(v) }} StrataVal::IVec2(mut v) => {{ if {l} < 2 {{ v[{l}] = locals[{}].as_i32(); }} StrataVal::IVec2(v) }} StrataVal::IVec3(mut v) => {{ if {l} < 3 {{ v[{l}] = locals[{}].as_i32(); }} StrataVal::IVec3(v) }} StrataVal::UVec2(mut v) => {{ if {l} < 2 {{ v[{l}] = locals[{}].as_u32(); }} StrataVal::UVec2(v) }} other => other }}",
                    vec.0, val.0, val.0, val.0, val.0, val.0, val.0
                ),
            );
        }
        Inst::VecSwizzle { vec, lanes } => {
            let lane_lits: Vec<String> = lanes.iter().map(|l| format!("{l}u8")).collect();
            let expr = format!(
                "strata_vec_swizzle_lanes(&locals[{}], &[{}])",
                vec.0,
                lane_lits.join(", ")
            );
            assign_dst(out, &expr);
        }
        Inst::IntrinsicMath { name, args, .. } => {
            let short = name.rsplit("::").next().unwrap_or(name);
            let esc = escape_rust_str(short);
            let arg_list: Vec<String> = args
                .iter()
                .map(|a| format!("locals[{}].clone()", a.0))
                .collect();
            assign_dst(
                out,
                &format!("strata_intrinsic(\"{esc}\", &[{}])", arg_list.join(", ")),
            );
        }
        Inst::Call { callee, args } => {
            let arg_list: Vec<String> = args
                .iter()
                .map(|a| format!("locals[{}].clone()", a.0))
                .collect();
            let short = callee.rsplit("::").next().unwrap_or(callee);
            if let Some((h_idx, hf)) = mir
                .fns
                .iter()
                .enumerate()
                .find(|(_, f)| f.name == *callee || f.name == short)
            {
                let hname = format!("strata_helper_{}_{h_idx}", sanitize_ident(&hf.name));
                assign_dst(
                    out,
                    &format!(
                        "{hname}(bridge, world, handles, &[{}])",
                        arg_list.join(", ")
                    ),
                );
            } else if let Some(item_name) = callee.strip_suffix("::start") {
                if let Some(tl) = mir.timelines.iter().find(|tl| {
                    tl.name == item_name
                        || tl.canonical_name == item_name
                        || tl.canonical_name.rsplit("::").next() == Some(item_name)
                }) {
                    let esc_ty = escape_rust_str(&tl.canonical_name);
                    writeln!(
                        out,
                        "                let mut _obj = StrataObj::default_for_name(\"{esc_ty}\");\n\
                         \x20               _obj.set_field(0, \"flags\", StrataVal::U32(1));"
                    )
                    .ok();
                    assign_dst(out, "StrataVal::Obj(_obj)");
                } else if let Some(tk) = mir.tasks.iter().find(|tk| {
                    tk.name == item_name
                        || tk.state_layout.canonical_name == item_name
                        || tk.state_layout.canonical_name.rsplit("::").next() == Some(item_name)
                }) {
                    let esc_ty = escape_rust_str(&tk.state_layout.canonical_name);
                    let comp_opt = cat.resolve_comp(&tk.state_layout.canonical_name);
                    writeln!(
                        out,
                        "                let mut _obj = StrataObj::default_for_name(\"{esc_ty}\");\n\
                         \x20               _obj.set_field(0, \"__pc\", StrataVal::U32(0));\n\
                         \x20               _obj.set_field(0, \"__timer\", StrataVal::F32(0.0));"
                    )
                    .ok();
                    for (pi, tp) in tk.typed_params.iter().enumerate() {
                        if let Some(&arg_l) = args.get(pi) {
                            let esc_f = escape_rust_str(&tp.name);
                            let val_expr = if let Some(sf) = comp_opt.and_then(|c| {
                                c.layout
                                    .fields
                                    .iter()
                                    .find(|f| !f.is_padding && f.name == tp.name)
                            }) {
                                guest_coerce_val_expr_for_sema_ty(&sf.ty, arg_l, func, const_info)
                            } else {
                                format!("locals[{}].clone()", arg_l.0)
                            };
                            writeln!(
                                out,
                                "                _obj.set_field(0, \"{esc_f}\", {val_expr});"
                            )
                            .ok();
                        }
                    }
                    assign_dst(out, "StrataVal::Obj(_obj)");
                } else if let Some(fsm) = mir.fsms.iter().find(|fsm| {
                    fsm.name == item_name
                        || fsm.state_layout.canonical_name == item_name
                        || fsm.state_layout.canonical_name.rsplit("::").next() == Some(item_name)
                }) {
                    let init_idx = fsm
                        .states
                        .iter()
                        .position(|st| st == &fsm.initial_state)
                        .unwrap_or(0);
                    let esc_ty = escape_rust_str(&fsm.state_layout.canonical_name);
                    writeln!(
                        out,
                        "                let mut _obj = StrataObj::default_for_name(\"{esc_ty}\");\n\
                         \x20               _obj.set_field(0, \"__state\", StrataVal::U32({init_idx}u32));"
                    )
                    .ok();
                    assign_dst(out, "StrataVal::Obj(_obj)");
                } else {
                    let esc = escape_rust_str(short);
                    assign_dst(
                        out,
                        &format!("strata_intrinsic(\"{esc}\", &[{}])", arg_list.join(", ")),
                    );
                }
            } else {
                let esc = escape_rust_str(short);
                assign_dst(
                    out,
                    &format!("strata_intrinsic(\"{esc}\", &[{}])", arg_list.join(", ")),
                );
            }
        }
        Inst::StructInit { type_name, fields } => {
            if type_name == "tuple" {
                let mut parts = vec!["StrataVal::Unit".to_owned(); fields.len()];
                for (pos, (fname, vid)) in fields.iter().enumerate() {
                    let idx = fname
                        .strip_prefix('_')
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(pos);
                    if idx < parts.len() {
                        parts[idx] = format!("locals[{}].clone()", vid.0);
                    }
                }
                assign_dst(
                    out,
                    &format!("StrataVal::Tuple(vec![{}])", parts.join(", ")),
                );
            } else {
                let esc_ty = escape_rust_str(type_name);
                let comp_opt = cat.resolve_comp(type_name);
                writeln!(
                    out,
                    "                let mut _obj = StrataObj::default_for_name(\"{esc_ty}\");"
                )
                .ok();
                for (fname, vid) in fields {
                    let esc_f = escape_rust_str(fname);
                    let val_expr = if let Some(sf) = comp_opt.and_then(|c| {
                        c.layout
                            .fields
                            .iter()
                            .find(|f| !f.is_padding && f.name == *fname)
                    }) {
                        guest_coerce_val_expr_for_sema_ty(&sf.ty, *vid, func, const_info)
                    } else {
                        format!("locals[{}].clone()", vid.0)
                    };
                    writeln!(
                        out,
                        "                _obj.set_field(0, \"{esc_f}\", {val_expr});"
                    )
                    .ok();
                }
                assign_dst(out, "StrataVal::Obj(_obj)");
            }
        }
        Inst::ArrayInit { elems } => {
            let parts: Vec<String> = elems
                .iter()
                .map(|e| format!("locals[{}].clone()", e.0))
                .collect();
            assign_dst(out, &format!("StrataVal::Arr(vec![{}])", parts.join(", ")));
        }
        Inst::ArrayIndex { base, index } => {
            let dst_is_ptr = matches!(dst_ty, MirType::Ptr | MirType::MutPtr);
            if dst_is_ptr {
                let elem_sema_opt = match const_info.ptr_sema_tys.get(base) {
                    Some(Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }) => {
                        Some((**elem).clone())
                    }
                    _ => func.locals.get(base.0 as usize).and_then(|l| {
                        if let MirType::Array { elem, .. } = &l.ty {
                            mir_ty_to_guest_ty_hint(elem, mir)
                        } else {
                            None
                        }
                    }),
                };
                let stride = if let Some(ref ety) = elem_sema_opt {
                    let (sz, al) = guest_ty_abi_size_align(ety, mir);
                    let al = al.max(1);
                    sz.div_ceil(al) * al
                } else if let Some(MirType::Array { elem, .. }) =
                    func.locals.get(base.0 as usize).map(|l| &l.ty)
                {
                    guest_mir_elem_byte_size(elem, cat)
                } else {
                    4
                };
                assign_dst(
                    out,
                    &format!(
                        "{{ let _idx_i = locals[{}].as_i64(); if _idx_i >= 0 {{ StrataVal::Ptr(locals[{}].as_ptr().with_added_offset((_idx_i as usize).saturating_mul({stride}) as u32)) }} else {{ StrataVal::Ptr(StrataPtr::Null) }} }}",
                        index.0, base.0
                    ),
                );
            } else {
                let elem_sty_opt = mir_ty_to_guest_ty_hint(&dst_ty, mir);
                let (stride, ptr_read_expr, def_val) = if let Some(ref sty) = elem_sty_opt {
                    let (sz, al) = guest_ty_abi_size_align(sty, mir);
                    let al = al.max(1);
                    (
                        sz.div_ceil(al) * al,
                        emit_runtime_read_ty_from_bytes("_b", "_r_off", sty, sz, mir, cat),
                        default_strata_val_for_mir_ty(&dst_ty).to_owned(),
                    )
                } else {
                    (
                        guest_mir_elem_byte_size(&dst_ty, cat),
                        "StrataVal::Unit".to_owned(),
                        default_strata_val_for_mir_ty(&dst_ty).to_owned(),
                    )
                };
                assign_dst(
                    out,
                    &format!(
                        "{{ let _idx_i = locals[{}].as_i64(); if _idx_i < 0 {{ {def_val} }} else {{ let _idx = _idx_i as usize; match &locals[{}] {{ StrataVal::Arr(a) => a.get(_idx).cloned().unwrap_or_default(), StrataVal::Words(w) => StrataVal::U32(*w.get(_idx).unwrap_or(&0)), StrataVal::Vec2(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), StrataVal::Vec3(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), StrataVal::Vec4(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), StrataVal::IVec2(v) => StrataVal::I32(*v.get(_idx).unwrap_or(&0)), StrataVal::IVec3(v) => StrataVal::I32(*v.get(_idx).unwrap_or(&0)), StrataVal::UVec2(v) => StrataVal::U32(*v.get(_idx).unwrap_or(&0)), StrataVal::Ptr(_) => {{ let mut _res_v = {def_val}; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _base_off| {{ let _r_off = _base_off.saturating_add(_idx.saturating_mul({stride})); _res_v = {ptr_read_expr}; }}); _res_v }}, _ => StrataVal::Unit }} }} }}",
                        index.0, base.0, base.0
                    ),
                );
            }
        }
        Inst::ArrayStore {
            base_ptr,
            index,
            val,
            elem_ty,
        } => {
            let (elem_bytes, write_fn) = if let Some(sty) = mir_ty_to_guest_ty_hint(elem_ty, mir) {
                let (sz, al) = guest_ty_abi_size_align(&sty, mir);
                let al = al.max(1);
                let stride = sz.div_ceil(al) * al;
                let w = emit_runtime_write_ty_into_bytes("_buf", "_w_off", "_raw_v", &sty, sz, mir);
                (stride, w)
            } else {
                (
                    guest_mir_elem_byte_size(elem_ty, cat),
                    guest_mir_elem_write_bytes_expr(elem_ty).to_owned(),
                )
            };
            let coerce_val = guest_mir_coerce_val_expr(elem_ty);
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _idx_i = locals[{}].as_i64();\n\
                 \x20                   if _idx_i >= 0 {{\n\
                 \x20                       let _idx = _idx_i as usize;\n\
                 \x20                       let _raw_v = locals[{}].clone();\n\
                 \x20                       match locals[{}].as_ptr() {{\n\
                 \x20                           StrataPtr::Slot {{ sid, off }} if off == 0 && matches!(slots.get(sid), Some(StrataVal::Arr(_))) => {{\n\
                 \x20                               if let Some(StrataVal::Arr(arr)) = slots.get_mut(sid) {{\n\
                 \x20                                   if _idx < arr.len() {{ arr[_idx] = {coerce_val}; }}\n\
                 \x20                               }}\n\
                 \x20                           }}\n\
                 \x20                           _ptr => {{\n\
                 \x20                               strata_ptr_bytes_mut(bridge, _ptr, &mut slots, &mut migrate_dst, world, handles, |_buf, _base_off| {{\n\
                 \x20                                   let _w_off = _base_off.saturating_add(_idx.saturating_mul({elem_bytes}));\n\
                 \x20                                   {write_fn}\n\
                 \x20                               }});\n\
                 \x20                           }}\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}",
                index.0, val.0, base_ptr.0
            )
            .ok();
        }
        Inst::FieldPtr {
            base_ptr,
            offset_bytes,
            ..
        } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(locals[{}].as_ptr().with_added_offset({offset_bytes}))",
                    base_ptr.0
                ),
            );
        }
        Inst::RowPtr {
            col_ptr,
            row_idx,
            is_sparse,
            ..
        } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(match locals[{}].as_ptr() {{ StrataPtr::ChunkCol {{ qi, phys_col, comp_id, is_mut, is_untracked, is_sparse: cs }} => StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row: locals[{}].as_u32() as usize, off: 0, is_mut, is_untracked, is_sparse: cs || {is_sparse} }}, other => other }})",
                    col_ptr.0, row_idx.0
                ),
            );
        }
        Inst::FieldLoad {
            base_ptr,
            layout_key,
            field,
            offset_bytes,
            field_ty,
        } => {
            let esc_f = escape_rust_str(field);
            let base_is_table = const_info.table_ptrs.contains_key(base_ptr);
            let base_is_vec = matches!(
                const_info.ptr_sema_tys.get(base_ptr),
                Some(
                    Ty::Vec2
                        | Ty::Vec3
                        | Ty::Vec3a
                        | Ty::Vec4
                        | Ty::Quat
                        | Ty::Rgba
                        | Ty::IVec2
                        | Ty::IVec3
                        | Ty::UVec2
                )
            );
            let base_is_tuple = matches!(const_info.ptr_sema_tys.get(base_ptr), Some(Ty::Tuple(_)))
                || layout_key == "tuple";
            let is_ptr_local = matches!(
                func.locals.get(base_ptr.0 as usize).map(|l| &l.ty),
                Some(MirType::Ptr | MirType::MutPtr)
            );
            if is_ptr_local
                && const_info.sub_ptrs.contains(base_ptr)
                && !base_is_table
                && !base_is_vec
                && !base_is_tuple
                && *field_ty != MirType::Unit
                && let Some(sty) = mir_ty_to_guest_ty_hint(field_ty, mir)
            {
                let (sz, _) = guest_ty_abi_size_align(&sty, mir);
                let rd = emit_runtime_read_ty_from_bytes("_b", "_r_off", &sty, sz, mir, cat);
                let def_v = default_strata_val_for_mir_ty(field_ty);
                assign_dst(
                    out,
                    &format!(
                        "{{ let mut _res_v = {def_v}; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _base_off| {{ let _r_off = _base_off.saturating_add({offset_bytes}); _res_v = {rd}; }}); _res_v }}",
                        base_ptr.0
                    ),
                );
            } else {
                assign_dst(
                    out,
                    &format!(
                        "strata_val_or_ptr_read(bridge, &locals[{}], {offset_bytes}, \"{esc_f}\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles)",
                        base_ptr.0
                    ),
                );
            }
        }
        Inst::FieldStore {
            base_ptr,
            layout_key,
            field,
            offset_bytes,
            val,
        } => {
            let esc_f = escape_rust_str(field);
            let fty_opt = resolve_guest_field_ty_path(cat, layout_key, field, *offset_bytes)
                .cloned()
                .or_else(|| {
                    const_info.ptr_sema_tys.get(base_ptr).and_then(|bt| {
                        resolve_guest_ptr_field_ty(bt, layout_key, field, *offset_bytes, cat)
                    })
                })
                .or_else(|| {
                    func.locals
                        .get(val.0 as usize)
                        .and_then(|l| mir_ty_to_guest_ty_hint(&l.ty, mir))
                });
            let val_expr = if let Some(ref fty) = fty_opt {
                guest_coerce_val_expr_for_sema_ty(fty, *val, func, const_info)
            } else {
                format!("locals[{}].clone()", val.0)
            };
            let base_is_table = const_info.table_ptrs.contains_key(base_ptr);
            let base_is_vec = matches!(
                const_info.ptr_sema_tys.get(base_ptr),
                Some(
                    Ty::Vec2
                        | Ty::Vec3
                        | Ty::Vec3a
                        | Ty::Vec4
                        | Ty::Quat
                        | Ty::Rgba
                        | Ty::IVec2
                        | Ty::IVec3
                        | Ty::UVec2
                )
            );
            let base_is_tuple = matches!(const_info.ptr_sema_tys.get(base_ptr), Some(Ty::Tuple(_)))
                || layout_key == "tuple";
            if const_info.sub_ptrs.contains(base_ptr)
                && !base_is_table
                && !base_is_vec
                && !base_is_tuple
                && let Some(ref fty) = fty_opt
                && !matches!(fty, Ty::Asset(_))
            {
                let (sz, _) = guest_ty_abi_size_align(fty, mir);
                let wr = emit_runtime_write_ty_into_bytes("_b", "_w_off", "_w_val", fty, sz, mir);
                if !wr.is_empty() {
                    writeln!(
                        out,
                        "                {{ let _w_val = {val_expr}; strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _base_off| {{ let _w_off = _base_off.saturating_add({offset_bytes}); {wr} }}); }}",
                        base_ptr.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "                strata_ptr_write(bridge, locals[{}].as_ptr(), {offset_bytes}, \"{esc_f}\", {val_expr}, &mut slots, &mut migrate_dst, world, handles);",
                        base_ptr.0
                    )
                    .ok();
                }
            } else {
                writeln!(
                    out,
                    "                strata_ptr_write(bridge, locals[{}].as_ptr(), {offset_bytes}, \"{esc_f}\", {val_expr}, &mut slots, &mut migrate_dst, world, handles);",
                    base_ptr.0
                )
                .ok();
            }
        }
        Inst::ParForEachChunk { query_idx, .. } => {
            emit_par_chunks_dispatch(
                out,
                mir,
                cat,
                func,
                phys_queries,
                query_remap,
                stream_decls,
                named_fallback_queries,
                cur_bb,
                *query_idx as usize,
                false,
                false,
            );
        }
        Inst::ParForEachChunkReadonly {
            query_idx,
            deterministic_order,
            ..
        } => {
            emit_par_chunks_dispatch(
                out,
                mir,
                cat,
                func,
                phys_queries,
                query_remap,
                stream_decls,
                named_fallback_queries,
                cur_bb,
                *query_idx as usize,
                true,
                *deterministic_order,
            );
        }
        Inst::ReduceInit { op, identity } => {
            let _ = op;
            assign_dst(out, &format!("locals[{}].clone()", identity.0));
        }
        Inst::ReduceAccum { acc, op, val } => {
            let esc = escape_rust_str(op);
            assign_dst(
                out,
                &format!(
                    "strata_reduce_accum(&locals[{}], \"{esc}\", &locals[{}])",
                    acc.0, val.0
                ),
            );
        }
        Inst::IterNextChunk { query_idx } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => {{\n\
                     \x20       if par_consumed[{qi}] {{ StrataVal::U32(0) }}\n\
                     \x20       else if let Some(it) = sys_ctx.query_mut({eqi}) {{\n\
                     \x20           StrataVal::U32(it.next_chunk().unwrap_or(0) as u32)\n\
                     \x20       }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   HostBridge::ParChunkReadonly(ch) => {{\n\
                     \x20       if !iter_started_once[{qi}] {{ iter_started_once[{qi}] = true; StrataVal::U32(ch.entities().len() as u32) }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   HostBridge::ParChunkMut(ch) => {{\n\
                     \x20       if !iter_started_once[{qi}] {{ iter_started_once[{qi}] = true; StrataVal::U32(ch.entities().len() as u32) }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::IterChunkLen { query_idx } => {
            let eqi = remap_qi(query_remap, *query_idx as usize);
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.query_mut({eqi}).map_or(0, |it| it.current_len() as u32)),\n\
                     \x20   HostBridge::ParChunkReadonly(ch) => StrataVal::U32(ch.entities().len() as u32),\n\
                     \x20   HostBridge::ParChunkMut(ch) => StrataVal::U32(ch.entities().len() as u32),\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::IterEntities { query_idx } => {
            let eqi = remap_qi(query_remap, *query_idx as usize);
            assign_dst(
                out,
                &format!("StrataVal::Ptr(StrataPtr::ChunkEntities {{ qi: {eqi} }})"),
            );
        }
        Inst::EntityAtRow {
            entities_ptr,
            row_idx,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _row = locals[{}].as_u32() as usize; match locals[{}].as_ptr() {{\n\
                     \x20   StrataPtr::ChunkEntities {{ qi }} => match bridge {{\n\
                     \x20       HostBridge::System(sys_ctx) => StrataVal::Entity(sys_ctx.query_mut(qi).and_then(|it| it.entities().get(_row).copied()).unwrap_or(FfiEntity::NULL)),\n\
                     \x20       HostBridge::ParChunkReadonly(ch) => StrataVal::Entity(ch.entities().get(_row).copied().unwrap_or(FfiEntity::NULL)),\n\
                     \x20       HostBridge::ParChunkMut(ch) => StrataVal::Entity(ch.entities().get(_row).copied().unwrap_or(FfiEntity::NULL)),\n\
                     \x20       _ => StrataVal::Entity(FfiEntity::NULL),\n\
                     \x20   }},\n\
                     \x20   StrataPtr::SpatialHits {{ idx }} => StrataVal::Entity(spatial_hits.get(idx).and_then(|h| h.get(_row)).map_or(FfiEntity::NULL, |e| e.0)),\n\
                     \x20   _ => StrataVal::Entity(FfiEntity::NULL),\n\
                     }} }}",
                    row_idx.0, entities_ptr.0
                ),
            );
        }
        Inst::IterColRead {
            query_idx,
            term_idx,
            storage_key,
        }
        | Inst::IterColRowsRead {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {eqi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: false, is_untracked: false, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColWrite {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {eqi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: false, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColWriteUntracked {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            // Borrow untracked mutable slice once up front to validate column mode cleanly.
            if !is_sparse && let Some(comp) = cat.components.get(comp_id) {
                let sname = &comp.struct_name;
                writeln!(
                    out,
                    "                match bridge {{\n\
                     \x20                   HostBridge::System(sys_ctx) => {{ if let Some(it) = sys_ctx.query_mut({eqi}) {{ let _ = it.mutable_slice_untracked({phys_col}).as_component_slice_mut::<{sname}>(); }} }}\n\
                     \x20                   HostBridge::ParChunkMut(ch) => {{ let _ = ch.component_mut_untracked::<{sname}>({phys_col}); }}\n\
                     \x20                   _ => {{}}\n\
                     \x20               }}"
                )
                .ok();
            }
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {eqi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: true, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColRowsWrite {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {eqi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: false, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterMarkChangedRange {
            query_idx,
            term_idx,
            run_start,
            run_len,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _rs = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => locals[{}].as_u32() }} as usize;\n\
                 \x20                   let _rl = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => locals[{}].as_u32() }} as usize;\n\
                 \x20                   if _rl > 0 {{\n\
                 \x20                       match bridge {{\n\
                 \x20                           HostBridge::System(sys_ctx) => {{ if let Some(it) = sys_ctx.query_mut({eqi}) {{ let _ = it.mark_changed_range({phys_col}, _rs, _rl); }} }}\n\
                 \x20                           HostBridge::ParChunkMut(ch) => {{ let _ = ch.mark_changed_range({phys_col}, _rs, _rl); }}\n\
                 \x20                           _ => {{}}\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}",
                run_start.0, run_start.0, run_len.0, run_len.0
            )
            .ok();
        }
        Inst::DirtyRunInit { run_start, run_len } => {
            writeln!(
                out,
                "                if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(0); }} else {{ locals[{}] = StrataVal::U32(0); }}\n\
                 \x20               if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(0); }} else {{ locals[{}] = StrataVal::U32(0); }}\n\
                 \x20               dirty_runs.insert({}, (0, 0));",
                run_start.0, run_start.0, run_len.0, run_len.0, run_start.0
            )
            .ok();
        }
        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _row = locals[{}].as_u32();\n\
                 \x20                   let _cur_s = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => locals[{}].as_u32() }};\n\
                 \x20                   let _cur_l = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => locals[{}].as_u32() }};\n\
                 \x20                   let (_ns, _nl) = if _cur_l == 0 {{\n\
                 \x20                       (_row, 1)\n\
                 \x20                   }} else if _row == _cur_s + _cur_l {{\n\
                 \x20                       (_cur_s, _cur_l + 1)\n\
                 \x20                   }} else {{\n\
                 \x20                       (_cur_s, (_row + 1).saturating_sub(_cur_s).max(_cur_l))\n\
                 \x20                   }};\n\
                 \x20                   if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(_ns); }} else {{ locals[{}] = StrataVal::U32(_ns); }}\n\
                 \x20                   if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(_nl); }} else {{ locals[{}] = StrataVal::U32(_nl); }}\n\
                 \x20               }}",
                row_idx.0, run_start.0, run_start.0, run_len.0, run_len.0, run_start.0, run_start.0, run_len.0, run_len.0
            )
            .ok();
        }
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Bool(strata_opt_present(bridge, locals[{}].as_ptr()))",
                    slice_ptr.0
                ),
            );
        }
        Inst::IterCount { query_idx } => {
            let eqi = remap_qi(query_remap, *query_idx as usize);
            assign_dst(
                out,
                &format!(
                    "match bridge {{ HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.query_mut({eqi}).and_then(|it| it.count().ok()).unwrap_or(0) as u32), _ => StrataVal::U32(0) }}"
                ),
            );
        }
        Inst::IterUpCascade {
            query_idx,
            relation,
            entity,
            term_idx,
        } => {
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let short_r = relation.rsplit("::").next().unwrap_or(relation.as_str());
            let rel_expr = if relation == "ChildOf" || relation.ends_with("::ChildOf") {
                "BamComponent::INVALID".to_owned()
            } else if let Some(companion) =
                cat.resolve_comp(&format!("__strata_rel_parent_{short_r}"))
            {
                format!("handles.{}", companion.handle_field)
            } else if let Some(rel) = cat.resolve_rel(relation) {
                format!("handles.{}", rel.handle_field)
            } else {
                "BamComponent::INVALID".to_owned()
            };
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let target_comp = pq
                .and_then(|q| q.terms.get(phys_col).or_else(|| q.terms.first()))
                .and_then(|t| cat.components.get(t.comp_id));
            if let Some(comp) = target_comp {
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                assign_dst(
                    out,
                    &format!(
                        "match bridge {{ HostBridge::System(sys_ctx) => {{ let _rel = {rel_expr}; let _e = locals[{}].as_entity(); if let Some(it) = sys_ctx.query_mut({eqi}) {{ if let Ok(Some((_anc, _val))) = it.up_cascade::<{sname}>(_rel, _e, {phys_col}) {{ StrataVal::Obj(StrataObj::{vname}(*_val)) }} else {{ StrataVal::Ptr(StrataPtr::Null) }} }} else {{ StrataVal::Ptr(StrataPtr::Null) }} }}, _ => StrataVal::Ptr(StrataPtr::Null) }}",
                        entity.0
                    ),
                );
            } else {
                assign_dst(out, "StrataVal::Ptr(StrataPtr::Null)");
            }
        }
        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
            let is_mut = matches!(stmt.inst, Inst::ResWrite { .. });
            let decl_idx = func
                .resources
                .iter()
                .position(|r| r.resource_name == *resource || r.canonical_name == *resource)
                .unwrap_or(0);
            let comp_id = func
                .resources
                .get(decl_idx)
                .and_then(|r| {
                    cat.resolve_comp(&r.canonical_name)
                        .or_else(|| cat.resolve_comp(&r.resource_name))
                })
                .or_else(|| cat.resolve_comp(resource))
                .map_or(0, |c| c.id);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::Res {{ decl_idx: {decl_idx}, comp_id: {comp_id}, off: 0, is_mut: {is_mut} }})"
                ),
            );
        }
        Inst::EntityGet {
            query_idx,
            term_idx,
            entity,
            storage_key,
        }
        | Inst::EntityGetMut {
            query_idx,
            term_idx,
            entity,
            storage_key,
        } => {
            let is_mut = matches!(stmt.inst, Inst::EntityGetMut { .. });
            let qi = *query_idx as usize;
            let eqi = remap_qi(query_remap, qi);
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(strata_entity_ptr_validate(bridge, {eqi}, {phys_col}, {comp_id}, locals[{}].as_entity(), {is_mut}))",
                    entity.0
                ),
            );
        }
        Inst::BindNamedObject { name } => {
            let esc = escape_rust_str(name);
            writeln!(
                out,
                "                if let Ok(_w) = world.lock() {{\n\
                 \x20                   if let Some(&_ent) = _w.named_objects.get(\"{esc}\") {{\n\
                 \x20                       if let HostBridge::System(sys_ctx) = bridge {{ let _ = sys_ctx.bind_named_object(\"{esc}\", _ent); }}\n\
                 \x20                   }}\n\
                 \x20               }}"
            )
            .ok();
            assign_dst(out, "StrataVal::Unit");
        }
        Inst::ResolveNamedObject { name } => {
            let esc = escape_rust_str(name);
            let fb_block = if let Some(&fb_qi) = named_fallback_queries.get(name) {
                format!(
                    "if _resolved.is_null() {{\n\
                     \x20   if let HostBridge::System(sys_ctx) = bridge {{\n\
                     \x20       if let Some(it) = sys_ctx.query_mut({fb_qi}) {{\n\
                     \x20           if let Some(_len) = it.next_chunk() {{\n\
                     \x20               if _len > 0 {{\n\
                     \x20                   let _cand = it.entities()[0];\n\
                     \x20                   if !_cand.is_null() {{\n\
                     \x20                       _resolved = _cand;\n\
                     \x20                       if let Ok(mut _w) = world.lock() {{ _w.named_objects.insert(\"{esc}\".to_owned(), _cand); }}\n\
                     \x20                   }}\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20           let _ = it.reset();\n\
                     \x20       }}\n\
                     \x20       if !_resolved.is_null() {{\n\
                     \x20           let _ = sys_ctx.bind_named_object(\"{esc}\", _resolved);\n\
                     \x20       }}\n\
                     \x20   }}\n\
                     }}"
                )
            } else {
                String::new()
            };
            assign_dst(
                out,
                &format!(
                    "{{\n\
                     \x20   let mut _resolved = world.lock().ok().and_then(|_w| _w.named_objects.get(\"{esc}\").copied()).unwrap_or(FfiEntity::NULL);\n\
                     \x20   {fb_block}\n\
                     \x20   StrataVal::Entity(_resolved)\n\
                     }}"
                ),
            );
        }
        Inst::InternSymbol { symbol } => {
            let esc = escape_rust_str(symbol);
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.intern_symbol(\"{esc}\").map_or(0, |s| s.to_raw())),\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::TriggerPayload { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::EventPayload { off: 0 })");
        }
        Inst::TriggerTarget => {
            if let Some((trg_ent_var, _)) = observer_vars {
                assign_dst(out, &format!("StrataVal::Entity({trg_ent_var})"));
            } else {
                assign_dst(out, "StrataVal::Entity(FfiEntity::NULL)");
            }
        }
        Inst::GraceArm { ptr, duration_sec } => {
            writeln!(
                out,
                "                {{ let _dur = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_grace_arm_bytes(_b, _off, _dur)); }}",
                duration_sec.0, ptr.0
            )
            .ok();
        }
        Inst::GraceTick { ptr, dt_sec } => {
            writeln!(
                out,
                "                {{ let _dt = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_grace_tick_bytes(_b, _off, _dt)); }}",
                dt_sec.0, ptr.0
            )
            .ok();
        }
        Inst::GraceIsActive { ptr } => {
            assign_dst(
                out,
                &format!(
                    "{{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _off| {{ _res_b = strata_grace_active_bytes(_b, _off); }}); StrataVal::Bool(_res_b) }}",
                    ptr.0
                ),
            );
        }
        Inst::GraceClear { ptr } => {
            writeln!(
                out,
                "                strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_grace_clear_bytes(_b, _off));",
                ptr.0
            )
            .ok();
        }
        Inst::InputBufPush {
            ptr,
            capacity,
            action_id,
            window_sec,
        } => {
            writeln!(
                out,
                "                {{ let _aid = locals[{}].as_u32() as u16; let _win = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_input_buf_push_bytes(_b, _off, {capacity}, _aid, _win)); }}",
                action_id.0, window_sec.0, ptr.0
            )
            .ok();
        }
        Inst::InputBufConsume {
            ptr,
            capacity,
            action_id,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _aid = locals[{}].as_u32() as u16; let mut _res_b = false; strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| {{ _res_b = strata_input_buf_consume_bytes(_b, _off, {capacity}, _aid); }}); StrataVal::Bool(_res_b) }}",
                    action_id.0, ptr.0
                ),
            );
        }
        Inst::InputBufPeek {
            ptr,
            capacity,
            action_id,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _aid = locals[{}].as_u32() as u16; let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _off| {{ _res_b = strata_input_buf_peek_bytes(_b, _off, {capacity}, _aid); }}); StrataVal::Bool(_res_b) }}",
                    action_id.0, ptr.0
                ),
            );
        }
        Inst::InputBufTick {
            ptr,
            capacity,
            dt_sec,
        } => {
            writeln!(
                out,
                "                {{ let _dt = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_input_buf_tick_bytes(_b, _off, {capacity}, _dt)); }}",
                dt_sec.0, ptr.0
            )
            .ok();
        }
        Inst::BitSetSet { ptr, words, bit } => {
            writeln!(
                out,
                "                {{ let _bit = locals[{}].as_u32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_bitset_set_bytes(_b, _off, {words}, _bit)); }}",
                bit.0, ptr.0
            )
            .ok();
        }
        Inst::BitSetGet { ptr, words, bit } => {
            let expr = if let Some((tbl_row, fpath)) = const_info.table_ptrs.get(ptr) {
                let esc_fp = escape_rust_str(fpath);
                format!(
                    "{{ let _bidx = locals[{}].as_u32(); match strata_val_or_ptr_read(bridge, &locals[{}], 0, \"{esc_fp}\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) {{ StrataVal::Words(ref _ws) => StrataVal::Bool(_ws.get((_bidx / 32) as usize).is_some_and(|w| (*w & (1u32 << (_bidx % 32))) != 0)), StrataVal::Arr(ref _xs) => StrataVal::Bool(_xs.get((_bidx / 32) as usize).is_some_and(|w| (w.as_u32() & (1u32 << (_bidx % 32))) != 0)), _ => StrataVal::Bool(false) }} }}",
                    bit.0, tbl_row.0
                )
            } else {
                format!(
                    "{{ let _bidx = locals[{}].as_u32(); match &locals[{}] {{ StrataVal::Words(_ws) => StrataVal::Bool(_ws.get((_bidx / 32) as usize).is_some_and(|w| (*w & (1u32 << (_bidx % 32))) != 0)), StrataVal::Arr(_xs) => StrataVal::Bool(_xs.get((_bidx / 32) as usize).is_some_and(|w| (w.as_u32() & (1u32 << (_bidx % 32))) != 0)), _ => {{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _off| {{ _res_b = strata_bitset_get_bytes(_b, _off, {words}, _bidx); }}); StrataVal::Bool(_res_b) }} }} }}",
                    bit.0, ptr.0, ptr.0
                )
            };
            assign_dst(out, &expr);
        }
        Inst::BitSetClear { ptr, words, bit } => {
            writeln!(
                out,
                "                {{ let _bit = locals[{}].as_u32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| strata_bitset_clear_bytes(_b, _off, {words}, _bit)); }}",
                bit.0, ptr.0
            )
            .ok();
        }
        Inst::TimelineAdvance {
            cursor_ptr,
            dt_sec,
            rate_hz,
            duration_frames,
            window_masks,
            ..
        } => {
            let win_lit: Vec<String> = window_masks
                .iter()
                .map(|(_, s, e, bit)| format!("({s}u32, {e}u32, {bit}u32)"))
                .collect();
            assign_dst(
                out,
                &format!(
                    "{{ let _dt = locals[{}].as_f32(); let mut _mask = 0u32; strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, world, handles, |_b, _off| {{ _mask = strata_timeline_advance_bytes(_b, _off, _dt, {rate_hz}, {duration_frames}, &[{}]); }}); StrataVal::U32(_mask) }}",
                    dt_sec.0,
                    cursor_ptr.0,
                    win_lit.join(", ")
                ),
            );
        }
        Inst::TimelineInWindow { ptr, window_bit } => {
            assign_dst(
                out,
                &format!(
                    "{{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles, |_b, _off| {{ _res_b = strata_timeline_in_window_bytes(_b, _off, {window_bit}); }}); StrataVal::Bool(_res_b) }}",
                    ptr.0
                ),
            );
        }
        Inst::CmdSpawn {
            persistent,
            components,
        } => {
            writeln!(out, "                {{").ok();
            let parts: Vec<String> = components
                .iter()
                .map(|(cname, lid)| {
                    if let Some(comp) = cat.resolve_comp(cname)
                        && (comp.layout.size == 0 || comp.layout.fields.is_empty())
                    {
                        format!("Some(SpawnEntry::marker(handles.{}))", comp.handle_field)
                    } else {
                        format!(
                            "match &locals[{}] {{ StrataVal::Obj(o) => o.spawn_entry(handles), _ => None }}",
                            lid.0
                        )
                    }
                })
                .collect();
            writeln!(
                out,
                "                    let mut _entries: Vec<SpawnEntry<'_>> = Vec::new();\n\
                 \x20                   for _me in [{list}] {{ if let Some(_e) = _me {{ _entries.push(_e); }} }}\n\
                 \x20                   let _spawned = match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let cmds = sys_ctx.commands(); if {persistent} {{ cmds.spawn_persistent(&_entries) }} else {{ cmds.spawn(&_entries) }} }},\n\
                 \x20                       HostBridge::Commands(cmds) => {{ if {persistent} {{ cmds.spawn_persistent(&_entries) }} else {{ cmds.spawn(&_entries) }} }},\n\
                 \x20                       _ => Err(FfiResult::UNSUPPORTED),\n\
                 \x20                   }}.unwrap_or(FfiEntity::NULL);",
                list = parts.join(", ")
            )
            .ok();
            if let Some(dst) = stmt.dst {
                writeln!(
                    out,
                    "                    locals[{}] = StrataVal::Entity(_spawned);",
                    dst.0
                )
                .ok();
            }
            writeln!(out, "                }}").ok();
        }
        Inst::CmdSpawnBatch { count, components } => {
            writeln!(out, "                {{").ok();
            writeln!(
                out,
                "                    let _cnt = locals[{}].as_u32() as usize;",
                count.0
            )
            .ok();
            for (ci, (cname, lid)) in components.iter().enumerate() {
                if let Some(comp) = cat.resolve_comp(cname)
                    && comp.layout.size > 0
                    && !comp.layout.fields.is_empty()
                {
                    let sname = &comp.struct_name;
                    let vname = &comp.variant_name;
                    writeln!(
                        out,
                        "                    let _col_vec_{ci}: Vec<{sname}> = if let StrataVal::Obj(StrataObj::{vname}(_v)) = &locals[{}] {{ vec![*_v; _cnt] }} else {{ vec![{sname}::default(); _cnt] }};",
                        lid.0
                    )
                    .ok();
                }
            }
            writeln!(
                out,
                "                    let mut _cols: Vec<SpawnBatchColumn<'_>> = Vec::new();"
            )
            .ok();
            for (ci, (cname, _)) in components.iter().enumerate() {
                if let Some(comp) = cat.resolve_comp(cname) {
                    if comp.layout.size == 0 || comp.layout.fields.is_empty() {
                        writeln!(
                            out,
                            "                    _cols.push(SpawnBatchColumn::marker(handles.{}, _cnt));",
                            comp.handle_field
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                    _cols.push(SpawnBatchColumn::new(handles.{}, &_col_vec_{ci}));",
                            comp.handle_field
                        )
                        .ok();
                    }
                }
            }
            writeln!(
                out,
                "                    match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().spawn_batch(&_cols, _cnt); }}\n\
                 \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.spawn_batch(&_cols, _cnt); }}\n\
                 \x20                       _ => {{}}\n\
                 \x20                   }}"
            )
            .ok();
            writeln!(out, "                }}").ok();
        }
        Inst::SpawnBatchBegin { count, components } => {
            writeln!(out, "                {{").ok();
            writeln!(
                out,
                "                    let _cnt = locals[{}].as_u32() as usize;",
                count.0
            )
            .ok();
            writeln!(
                out,
                "                    let mut _b = StrataBatchBuf::new(_cnt);"
            )
            .ok();
            for cname in components {
                if let Some(comp) = cat.resolve_comp(cname) {
                    writeln!(
                        out,
                        "                    _b.ensure_col({}, handles);",
                        comp.id
                    )
                    .ok();
                }
            }
            writeln!(
                out,
                "                    let _bid = spawn_batches.len() as u64;\n\
                 \x20                   spawn_batches.push(Some(_b));"
            )
            .ok();
            if let Some(dst) = stmt.dst {
                writeln!(
                    out,
                    "                    locals[{}] = StrataVal::U64(_bid);",
                    dst.0
                )
                .ok();
            }
            writeln!(out, "                }}").ok();
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            writeln!(out, "                {{").ok();
            writeln!(
                out,
                "                    let _bid = locals[{}].as_u64() as usize;\n\
                 \x20                   let _row = locals[{}].as_u32() as usize;\n\
                 \x20                   if let Some(Some(_b)) = spawn_batches.get_mut(_bid) {{",
                batch.0, index.0
            )
            .ok();
            for (cname, lid) in components {
                if let Some(comp) = cat.resolve_comp(cname) {
                    if comp.layout.size == 0 || comp.layout.fields.is_empty() {
                        writeln!(
                            out,
                            "                        _b.ensure_col({}, handles);",
                            comp.id
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                        _b.set_row(_row, {}, &locals[{}], handles);",
                            comp.id, lid.0
                        )
                        .ok();
                    }
                }
            }
            writeln!(out, "                    }}").ok();
            writeln!(out, "                }}").ok();
        }
        Inst::SpawnBatchCommit { batch } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _bid = locals[{}].as_u64() as usize;\n\
                 \x20                   if let Some(_b) = spawn_batches.get_mut(_bid).and_then(Option::take) {{\n\
                 \x20                       _b.commit(bridge);\n\
                 \x20                   }}\n\
                 \x20               }}",
                batch.0
            )
            .ok();
        }
        Inst::CmdDespawn { entity } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _e = locals[{}].as_entity();\n\
                 \x20                   if !_e.is_null() {{\n\
                 \x20                       match bridge {{\n\
                 \x20                           HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().despawn(_e); }}\n\
                 \x20                           HostBridge::Commands(cmds) => {{ let _ = cmds.despawn(_e); }}\n\
                 \x20                           _ => {{}}\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}",
                entity.0
            )
            .ok();
        }
        Inst::CmdDespawnAll { filter } => {
            let term_exprs: Vec<String> = parse_despawn_filter_terms(filter)
                .into_iter()
                .filter_map(|(is_without, cname)| {
                    cat.resolve_comp(cname).map(|comp| {
                        let mode = if is_without {
                            "AccessMode::WITHOUT"
                        } else {
                            "AccessMode::FILTER_ONLY"
                        };
                        format!("BamTermDesc::new(handles.{}, {mode})", comp.handle_field)
                    })
                })
                .collect();
            if !term_exprs.is_empty() {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _terms = [{list}];\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().despawn_all(&_terms); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.despawn_all(&_terms); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    list = term_exprs.join(", ")
                )
                .ok();
            }
        }
        Inst::CmdInsert {
            entity,
            component,
            data,
            if_new,
        } => {
            let e_idx = entity.0;
            let is_child_of = component == "ChildOf" || component.ends_with("::ChildOf");
            if let Some(lid) = data {
                let l = lid.0;
                if is_child_of {
                    writeln!(
                        out,
                        "                {{\n\
                         \x20                   let _e = locals[{e_idx}].as_entity();\n\
                         \x20                   let _v = if matches!(locals[{l}], StrataVal::Ptr(_)) {{ strata_val_or_ptr_read(bridge, &locals[{l}], 0, \"\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) }} else {{ locals[{l}].clone() }};\n\
                         \x20                   let _parent = match _v {{ StrataVal::Entity(pe) => pe, StrataVal::Obj(ref o) => o.get_field(0, \"parent\").as_entity(), _ => FfiEntity::NULL }};\n\
                         \x20                   if !_parent.is_null() {{\n\
                         \x20                       match bridge {{\n\
                         \x20                           HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().add_child(_parent, _e); }}\n\
                         \x20                           HostBridge::Commands(cmds) => {{ let _ = cmds.add_child(_parent, _e); }}\n\
                         \x20                           _ => {{}}\n\
                         \x20                       }}\n\
                         \x20                   }}\n\
                         \x20               }}"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "                {{\n\
                         \x20                   let _v = if matches!(locals[{l}], StrataVal::Ptr(_)) {{ strata_val_or_ptr_read(bridge, &locals[{l}], 0, \"\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) }} else {{ locals[{l}].clone() }};\n\
                         \x20                   if let StrataVal::Obj(ref _o) = _v {{\n\
                         \x20                       let _e = locals[{e_idx}].as_entity();\n\
                         \x20                       match bridge {{\n\
                         \x20                           HostBridge::System(sys_ctx) => _o.cmd_insert(sys_ctx.commands(), handles, _e, {if_new}),\n\
                         \x20                           HostBridge::Commands(cmds) => _o.cmd_insert(cmds, handles, _e, {if_new}),\n\
                         \x20                           _ => {{}}\n\
                         \x20                       }}\n\
                         \x20                   }}\n\
                         \x20               }}"
                    )
                    .ok();
                }
            } else if let Some(comp) = cat.resolve_comp(component) {
                let sname = &comp.struct_name;
                let hf = &comp.handle_field;
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{e_idx}].as_entity();\n\
                     \x20                   let _def = {sname}::default();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let cmds = sys_ctx.commands(); if {if_new} {{ let _ = cmds.insert_if_new(_e, handles.{hf}, &_def); }} else {{ let _ = cmds.insert(_e, handles.{hf}, &_def); }} }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ if {if_new} {{ let _ = cmds.insert_if_new(_e, handles.{hf}, &_def); }} else {{ let _ = cmds.insert(_e, handles.{hf}, &_def); }} }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}"
                )
                .ok();
            }
        }
        Inst::CmdRemove { entity, component } => {
            if component == "ChildOf" || component.ends_with("::ChildOf") {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().remove_parent(_e); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.remove_parent(_e); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0
                )
                .ok();
            } else if let Some(comp) = cat.resolve_comp(component) {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().remove(_e, handles.{}); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.remove(_e, handles.{}); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0, comp.handle_field, comp.handle_field
                )
                .ok();
            }
        }
        Inst::CmdTrigger {
            event,
            target,
            payload,
            propagate,
        } => {
            let tgt_expr = match target {
                Some(t) => format!("Some(locals[{}].as_entity())", t.0),
                None => "None".to_owned(),
            };
            if let Some(p) = payload {
                let pi = p.0;
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _pv = if matches!(locals[{pi}], StrataVal::Ptr(_)) {{ strata_val_or_ptr_read(bridge, &locals[{pi}], 0, \"\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) }} else {{ locals[{pi}].clone() }};\n\
                     \x20                   if let StrataVal::Obj(ref _o) = _pv {{\n\
                     \x20                       match bridge {{\n\
                     \x20                           HostBridge::System(sys_ctx) => _o.cmd_trigger(sys_ctx.commands(), handles, {tgt_expr}, {propagate}),\n\
                     \x20                           HostBridge::Commands(cmds) => _o.cmd_trigger(cmds, handles, {tgt_expr}, {propagate}),\n\
                     \x20                           _ => {{}}\n\
                     \x20                       }}\n\
                     \x20                   }}\n\
                     \x20               }}"
                )
                .ok();
            } else if let Some(comp) = cat.resolve_comp(event) {
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _o = StrataObj::{vname}({sname}::default());\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => _o.cmd_trigger(sys_ctx.commands(), handles, {tgt_expr}, {propagate}),\n\
                     \x20                       HostBridge::Commands(cmds) => _o.cmd_trigger(cmds, handles, {tgt_expr}, {propagate}),\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}"
                )
                .ok();
            }
        }
        Inst::StreamEmit { stream, payload } => {
            let decl_idx = stream_decl_index(stream_decls, cat, stream);
            let pi = payload.0;
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _sv = if matches!(locals[{pi}], StrataVal::Ptr(_)) {{ strata_val_or_ptr_read(bridge, &locals[{pi}], 0, \"\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) }} else {{ locals[{pi}].clone() }};\n\
                 \x20                   if let StrataVal::Obj(ref _o) = _sv {{\n\
                 \x20                       if let HostBridge::System(sys_ctx) = bridge {{ _o.send_msg(sys_ctx, stream_base + {decl_idx}); }}\n\
                 \x20                   }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::CmdCheckpoint => {
            assign_dst(
                out,
                "match bridge {\n\
                 \x20   HostBridge::System(sys_ctx) => StrataVal::Checkpoint(sys_ctx.commands().checkpoint().unwrap_or(0)),\n\
                 \x20   HostBridge::Commands(cmds) => StrataVal::Checkpoint(cmds.checkpoint().unwrap_or(0)),\n\
                 \x20   _ => StrataVal::Checkpoint(0),\n\
                 }",
            );
        }
        Inst::CmdRollback { checkpoint } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _ckpt = locals[{}].as_checkpoint();\n\
                 \x20                   match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().rollback(_ckpt); }}\n\
                 \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.rollback(_ckpt); }}\n\
                 \x20                       _ => {{}}\n\
                 \x20                   }}\n\
                 \x20               }}",
                checkpoint.0
            )
            .ok();
        }
        Inst::CmdInsertRelation {
            relation,
            entity,
            target,
            payload,
        } => {
            let short_r = relation.rsplit("::").next().unwrap_or(relation.as_str());
            let companion_opt = cat.resolve_comp(&format!("__strata_rel_parent_{short_r}"));
            let companion_stmt = if let Some(comp) = companion_opt {
                let sname = &comp.struct_name;
                let hf = &comp.handle_field;
                format!(
                    "let mut _par_c = {sname}::default(); _par_c.strata_set(0, \"parent\", StrataVal::Entity(_t)); let _ = _cmds.insert(_e, handles.{hf}, &_par_c);"
                )
            } else {
                String::new()
            };
            if relation == "ChildOf" || relation.ends_with("::ChildOf") {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   let _t = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().add_child(_t, _e); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.add_child(_t, _e); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0, target.0
                )
                .ok();
            } else if let Some(rel) = cat.resolve_rel(relation) {
                let rh = &rel.handle_field;
                if let Some(pl) = payload {
                    let pli = pl.0;
                    writeln!(
                        out,
                        "                {{\n\
                         \x20                   let _pv = if matches!(locals[{pli}], StrataVal::Ptr(_)) {{ strata_val_or_ptr_read(bridge, &locals[{pli}], 0, \"\", &slots, &migrate_src, &migrate_dst, &trg_payload, world, handles) }} else {{ locals[{pli}].clone() }};\n\
                         \x20                   if let StrataVal::Obj(ref _o) = _pv {{\n\
                         \x20                       let _e = locals[{}].as_entity();\n\
                         \x20                       let _t = locals[{}].as_entity();\n\
                         \x20                       match bridge {{\n\
                         \x20                           HostBridge::System(sys_ctx) => {{ let _cmds = sys_ctx.commands(); _o.cmd_insert_rel(_cmds, handles.{rh}, _e, _t); {companion_stmt} }}\n\
                         \x20                           HostBridge::Commands(_cmds) => {{ _o.cmd_insert_rel(_cmds, handles.{rh}, _e, _t); {companion_stmt} }}\n\
                         \x20                           _ => {{}}\n\
                         \x20                       }}\n\
                         \x20                   }}\n\
                         \x20               }}",
                        entity.0, target.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "                {{\n\
                         \x20                   let _e = locals[{}].as_entity();\n\
                         \x20                   let _t = locals[{}].as_entity();\n\
                         \x20                   match bridge {{\n\
                         \x20                       HostBridge::System(sys_ctx) => {{ let _cmds = sys_ctx.commands(); let _ = _cmds.insert_relation(_e, handles.{rh}, _t); {companion_stmt} }}\n\
                         \x20                       HostBridge::Commands(_cmds) => {{ let _ = _cmds.insert_relation(_e, handles.{rh}, _t); {companion_stmt} }}\n\
                         \x20                       _ => {{}}\n\
                         \x20                   }}\n\
                         \x20               }}",
                        entity.0, target.0
                    )
                    .ok();
                }
            }
        }
        Inst::CmdRemoveRelation {
            relation,
            entity,
            target,
        } => {
            if relation == "ChildOf" || relation.ends_with("::ChildOf") {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().remove_parent(_e); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.remove_parent(_e); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0
                )
                .ok();
            } else if let Some(rel) = cat.resolve_rel(relation) {
                let short_r = relation.rsplit("::").next().unwrap_or(relation.as_str());
                let rem_companion = if let Some(comp) =
                    cat.resolve_comp(&format!("__strata_rel_parent_{short_r}"))
                {
                    format!("let _ = _cmds.remove(_e, handles.{});", comp.handle_field)
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   let _t = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _cmds = sys_ctx.commands(); let _ = _cmds.remove_relation(_e, handles.{}, _t); {rem_companion} }}\n\
                     \x20                       HostBridge::Commands(_cmds) => {{ let _ = _cmds.remove_relation(_e, handles.{}, _t); {rem_companion} }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0, target.0, rel.handle_field, rel.handle_field
                )
                .ok();
            }
        }
        Inst::SpatialRebuildCsr { .. } | Inst::ShadowCommit { .. } => {}
        Inst::IterReset { query_idx } => {
            let eqi = remap_qi(query_remap, *query_idx as usize);
            writeln!(
                out,
                "                if let HostBridge::System(sys_ctx) = bridge {{\n\
                 \x20                   if let Some(it) = sys_ctx.query_mut({eqi}) {{ let _ = it.reset(); }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::SpatialCsrBegin { index_name } => {
            let resolved = resolve_guest_spatial_name(mir, func, index_name);
            let esc_idx = escape_rust_str(&resolved);
            writeln!(
                out,
                "                if let Ok(mut _w) = world.lock() {{\n\
                 \x20                   if let Some(_g) = _w.spatial.get_mut(\"{esc_idx}\") {{ _g.csr_begin(); }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::SpatialCsrCount { index_name, pos } => {
            let resolved = resolve_guest_spatial_name(mir, func, index_name);
            let esc_idx = escape_rust_str(&resolved);
            let pos_is_vec2 = matches!(
                func.locals.get(pos.0 as usize).map(|l| &l.ty),
                Some(MirType::Vec2)
            );
            let pos_expr = if pos_is_vec2 {
                let axes = mir
                    .spatial_indices
                    .iter()
                    .find(|sp| sp.name == resolved)
                    .map_or([0, 1], |sp| {
                        [sp.plane_axes[0].min(2), sp.plane_axes[1].min(2)]
                    });
                format!(
                    "{{ let mut _sp_p = [0.0f32; 4]; let _v2 = locals[{}].as_vec2(); _sp_p[{}] = _v2[0]; _sp_p[{}] = _v2[1]; _sp_p }}",
                    pos.0, axes[0], axes[1]
                )
            } else {
                format!("locals[{}].as_vec4()", pos.0)
            };
            writeln!(
                out,
                "                if let Ok(mut _w) = world.lock() {{\n\
                 \x20                   if let Some(_g) = _w.spatial.get_mut(\"{esc_idx}\") {{ _g.csr_count({pos_expr}); }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::SpatialCsrPrefixSum { index_name } => {
            let resolved = resolve_guest_spatial_name(mir, func, index_name);
            let esc_idx = escape_rust_str(&resolved);
            writeln!(
                out,
                "                if let Ok(mut _w) = world.lock() {{\n\
                 \x20                   if let Some(_g) = _w.spatial.get_mut(\"{esc_idx}\") {{ _g.csr_prefix_sum(); }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::SpatialCsrScatter {
            index_name,
            entity,
            pos,
        } => {
            let resolved = resolve_guest_spatial_name(mir, func, index_name);
            let esc_idx = escape_rust_str(&resolved);
            let pos_is_vec2 = matches!(
                func.locals.get(pos.0 as usize).map(|l| &l.ty),
                Some(MirType::Vec2)
            );
            let pos_expr = if pos_is_vec2 {
                let axes = mir
                    .spatial_indices
                    .iter()
                    .find(|sp| sp.name == resolved)
                    .map_or([0, 1], |sp| {
                        [sp.plane_axes[0].min(2), sp.plane_axes[1].min(2)]
                    });
                format!(
                    "{{ let mut _sp_p = [0.0f32; 4]; let _v2 = locals[{}].as_vec2(); _sp_p[{}] = _v2[0]; _sp_p[{}] = _v2[1]; _sp_p }}",
                    pos.0, axes[0], axes[1]
                )
            } else {
                format!("locals[{}].as_vec4()", pos.0)
            };
            writeln!(
                out,
                "                if let Ok(mut _w) = world.lock() {{\n\
                 \x20                   if let Some(_g) = _w.spatial.get_mut(\"{esc_idx}\") {{ _g.csr_scatter(locals[{}].as_entity(), {pos_expr}); }}\n\
                 \x20               }}",
                entity.0
            )
            .ok();
        }
        Inst::SpatialQueryDisc {
            grid_name,
            center,
            radius,
        } => {
            let resolved = resolve_guest_spatial_name(mir, func, grid_name);
            let esc = escape_rust_str(&resolved);
            let center_is_vec2 = matches!(
                func.locals.get(center.0 as usize).map(|l| &l.ty),
                Some(MirType::Vec2)
            );
            writeln!(
                out,
                "                let _sh_idx = spatial_hits.len();\n\
                 \x20               spatial_hits.push(strata_query_disc_hits(world, \"{esc}\", locals[{}].as_vec4(), locals[{}].as_f32(), {center_is_vec2}));",
                center.0, radius.0
            )
            .ok();
            assign_dst(
                out,
                "StrataVal::Ptr(StrataPtr::SpatialHits { idx: _sh_idx })",
            );
        }
        Inst::SpatialQuerySegmentAt {
            history_name,
            start,
            end,
            radius,
            tick_offset,
        } => {
            let resolved = resolve_guest_spatial_name(mir, func, history_name);
            let esc = escape_rust_str(&resolved);
            writeln!(
                out,
                "                let _sh_idx = spatial_hits.len();\n\
                 \x20               spatial_hits.push(strata_query_segment_hits(world, \"{esc}\", locals[{}].as_vec4(), locals[{}].as_vec4(), locals[{}].as_f32(), locals[{}].as_u32()));",
                start.0, end.0, radius.0, tick_offset.0
            )
            .ok();
            assign_dst(
                out,
                "StrataVal::Ptr(StrataPtr::SpatialHits { idx: _sh_idx })",
            );
        }
        Inst::TableLoad {
            table_name,
            key,
            field,
        } => {
            if let Some(te) = cat.resolve_table(table_name) {
                let lfn = &te.lookup_fn;
                let esc_f = escape_rust_str(field);
                if field.is_empty() {
                    assign_dst(
                        out,
                        &format!(
                            "StrataVal::Obj(StrataObj::{}({lfn}(locals[{}].as_i64())))",
                            te.variant_name, key.0
                        ),
                    );
                } else {
                    assign_dst(
                        out,
                        &format!(
                            "{lfn}(locals[{}].as_i64()).strata_get(0, \"{esc_f}\")",
                            key.0
                        ),
                    );
                }
            } else {
                assign_dst(out, "StrataVal::Unit");
            }
        }
        Inst::CurveSample { curve_name, x } => {
            let ident = sanitize_ident(curve_name);
            if mir
                .curves
                .iter()
                .any(|c| c.name == *curve_name || sanitize_ident(&c.name) == ident)
            {
                assign_dst(
                    out,
                    &format!(
                        "StrataVal::F32(strata_curve_sample_{ident}(locals[{}].as_f64()) as f32)",
                        x.0
                    ),
                );
            } else {
                assign_dst(out, "StrataVal::F32(0.0)");
            }
        }
        Inst::ShadowWrite { target_name, .. } => {
            // Pre-image was already captured in `undo_slot` (`shadow_slot`) by `tx_save_pre`
            // before `FieldStore`; do NOT overwrite `slots[sid]` with the post-store value.
            let esc_t = escape_rust_str(target_name);
            writeln!(
                out,
                "                /* Shadow write `{esc_t}` (pre-image preserved) */"
            )
            .ok();
        }
        Inst::RequireTrue { cond } => {
            writeln!(out, "                let _ = locals[{}].as_bool();", cond.0).ok();
        }
        Inst::FsmDispatch { transitions, .. } => {
            // Evaluate state discriminant if needed; explicit CFG branches drive state hooks
            let _ = transitions;
            assign_dst(out, "StrataVal::U32(0)");
        }
        Inst::TaskStep { pc_local, .. } => {
            assign_dst(
                out,
                &format!("StrataVal::U32(locals[{}].as_u32())", pc_local.0),
            );
        }
        Inst::MigrateSrcPtr { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::MigrateSrc { off: 0 })");
        }
        Inst::MigrateDstPtr { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::MigrateDst { off: 0 })");
        }
    }
}

pub(super) fn guest_mir_elem_byte_size(ty: &MirType, cat: &GuestCatalog) -> usize {
    match ty {
        MirType::Bool | MirType::U8 | MirType::I8 => 1,
        MirType::U16 | MirType::I16 => 2,
        MirType::U64
        | MirType::I64
        | MirType::F64
        | MirType::Fix64
        | MirType::Entity
        | MirType::Vec2
        | MirType::IVec2
        | MirType::UVec2 => 8,
        MirType::Vec3 | MirType::IVec3 => 12,
        MirType::Vec4 => 16,
        MirType::Array { elem, len } => guest_mir_elem_byte_size(elem, cat) * (*len).max(1),
        MirType::Named(key) => cat.resolve_comp(key).map_or(4, |c| c.layout.size.max(1)),
        _ => 4,
    }
}

pub(super) fn guest_mir_coerce_val_expr(ty: &MirType) -> &'static str {
    match ty {
        MirType::Bool => "StrataVal::Bool(_raw_v.as_bool())",
        MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => {
            "StrataVal::U32(_raw_v.as_u32())"
        }
        MirType::I8 | MirType::I16 | MirType::I32 => "StrataVal::I32(_raw_v.as_i32())",
        MirType::U64 => "StrataVal::U64(_raw_v.as_u64())",
        MirType::I64 => "StrataVal::I64(_raw_v.as_i64())",
        MirType::F32 => "StrataVal::F32(_raw_v.as_f32())",
        MirType::F64 => "StrataVal::F64(_raw_v.as_f64())",
        MirType::Fix32 => "StrataVal::Fix32(_raw_v.as_fix32())",
        MirType::Fix64 => "StrataVal::Fix64(_raw_v.as_fix64())",
        MirType::Entity => "StrataVal::Entity(_raw_v.as_entity())",
        MirType::Vec2 => "StrataVal::Vec2(_raw_v.as_vec2())",
        MirType::Vec3 => "StrataVal::Vec3(_raw_v.as_vec3())",
        MirType::Vec4 => "StrataVal::Vec4(_raw_v.as_vec4())",
        MirType::IVec2 => "StrataVal::IVec2(_raw_v.as_ivec2())",
        MirType::IVec3 => "StrataVal::IVec3(_raw_v.as_ivec3())",
        MirType::UVec2 => "StrataVal::UVec2(_raw_v.as_uvec2())",
        _ => "_raw_v.clone()",
    }
}

pub(super) fn guest_mir_elem_write_bytes_expr(ty: &MirType) -> &'static str {
    match ty {
        MirType::Bool => "if _w_off < _buf.len() { _buf[_w_off] = u8::from(_raw_v.as_bool()); }",
        MirType::U8 => "if _w_off < _buf.len() { _buf[_w_off] = _raw_v.as_u8(); }",
        MirType::I8 => "if _w_off < _buf.len() { _buf[_w_off] = _raw_v.as_i8() as u8; }",
        MirType::U16 => {
            "if _w_off + 2 <= _buf.len() { _buf[_w_off.._w_off + 2].copy_from_slice(&_raw_v.as_u16().to_le_bytes()); }"
        }
        MirType::I16 => {
            "if _w_off + 2 <= _buf.len() { _buf[_w_off.._w_off + 2].copy_from_slice(&_raw_v.as_i16().to_le_bytes()); }"
        }
        MirType::U32 | MirType::Sym => {
            "if _w_off + 4 <= _buf.len() { _buf[_w_off.._w_off + 4].copy_from_slice(&_raw_v.as_u32().to_le_bytes()); }"
        }
        MirType::I32 => {
            "if _w_off + 4 <= _buf.len() { _buf[_w_off.._w_off + 4].copy_from_slice(&_raw_v.as_i32().to_le_bytes()); }"
        }
        MirType::Fix32 => {
            "if _w_off + 4 <= _buf.len() { _buf[_w_off.._w_off + 4].copy_from_slice(&_raw_v.as_fix32().to_le_bytes()); }"
        }
        MirType::F32 => {
            "if _w_off + 4 <= _buf.len() { _buf[_w_off.._w_off + 4].copy_from_slice(&_raw_v.as_f32().to_le_bytes()); }"
        }
        MirType::U64 => {
            "if _w_off + 8 <= _buf.len() { _buf[_w_off.._w_off + 8].copy_from_slice(&_raw_v.as_u64().to_le_bytes()); }"
        }
        MirType::Entity => {
            "if _w_off + 8 <= _buf.len() { _buf[_w_off.._w_off + 8].copy_from_slice(&_raw_v.as_entity().to_bits().to_le_bytes()); }"
        }
        MirType::I64 => {
            "if _w_off + 8 <= _buf.len() { _buf[_w_off.._w_off + 8].copy_from_slice(&_raw_v.as_i64().to_le_bytes()); }"
        }
        MirType::Fix64 => {
            "if _w_off + 8 <= _buf.len() { _buf[_w_off.._w_off + 8].copy_from_slice(&_raw_v.as_fix64().to_le_bytes()); }"
        }
        MirType::F64 => {
            "if _w_off + 8 <= _buf.len() { _buf[_w_off.._w_off + 8].copy_from_slice(&_raw_v.as_f64().to_le_bytes()); }"
        }
        MirType::Vec2 => {
            "if _w_off + 8 <= _buf.len() { let _v = _raw_v.as_vec2(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); }"
        }
        MirType::IVec2 => {
            "if _w_off + 8 <= _buf.len() { let _v = _raw_v.as_ivec2(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); }"
        }
        MirType::UVec2 => {
            "if _w_off + 8 <= _buf.len() { let _v = _raw_v.as_uvec2(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); }"
        }
        MirType::Vec3 => {
            "if _w_off + 12 <= _buf.len() { let _v = _raw_v.as_vec3(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); _buf[_w_off + 8.._w_off + 12].copy_from_slice(&_v[2].to_le_bytes()); }"
        }
        MirType::IVec3 => {
            "if _w_off + 12 <= _buf.len() { let _v = _raw_v.as_ivec3(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); _buf[_w_off + 8.._w_off + 12].copy_from_slice(&_v[2].to_le_bytes()); }"
        }
        MirType::Vec4 => {
            "if _w_off + 16 <= _buf.len() { let _v = _raw_v.as_vec4(); _buf[_w_off.._w_off + 4].copy_from_slice(&_v[0].to_le_bytes()); _buf[_w_off + 4.._w_off + 8].copy_from_slice(&_v[1].to_le_bytes()); _buf[_w_off + 8.._w_off + 12].copy_from_slice(&_v[2].to_le_bytes()); _buf[_w_off + 12.._w_off + 16].copy_from_slice(&_v[3].to_le_bytes()); }"
        }
        _ => {
            "if let StrataVal::Obj(ref _o) = _raw_v { let _ob = _o.read_le_bytes(); let _n = _ob.len().min(_buf.len().saturating_sub(_w_off)); _buf[_w_off.._w_off + _n].copy_from_slice(&_ob[.._n]); }"
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn guest_inst_is_par_unsafe(inst: &Inst, mir: &MirModule, visited: &mut HashSet<String>) -> bool {
    match inst {
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
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::EntityGet { .. }
        | Inst::EntityGetMut { .. }
        | Inst::ResolveNamedObject { .. }
        | Inst::BindNamedObject { .. }
        | Inst::IterUpCascade { .. }
        | Inst::IterCount { .. }
        | Inst::IterReset { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::SpatialRebuildCsr { .. }
        | Inst::SpatialCsrBegin { .. }
        | Inst::SpatialCsrCount { .. }
        | Inst::SpatialCsrPrefixSum { .. }
        | Inst::SpatialCsrScatter { .. }
        | Inst::SpatialQueryDisc { .. }
        | Inst::SpatialQuerySegmentAt { .. }
        | Inst::ShadowWrite { .. }
        | Inst::ShadowCommit { .. }
        | Inst::RequireTrue { .. }
        | Inst::FsmDispatch { .. }
        | Inst::TaskStep { .. } => true,
        Inst::Call { callee, .. } => !guest_helper_is_par_safe(callee, mir, visited),
        _ => false,
    }
}

fn guest_helper_is_par_safe(callee: &str, mir: &MirModule, visited: &mut HashSet<String>) -> bool {
    if !visited.insert(callee.to_owned()) {
        return true;
    }
    let short = callee.rsplit("::").next().unwrap_or(callee);
    let Some(hf) = mir.fns.iter().find(|f| f.name == callee || f.name == short) else {
        return true;
    };
    !hf.blocks.iter().any(|bb| {
        bb.stmts
            .iter()
            .any(|s| guest_inst_is_par_unsafe(&s.inst, mir, visited))
    })
}

pub(super) fn emit_par_chunks_dispatch(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    query_remap: &[usize],
    stream_decls: &[(String, bool)],
    named_fallback_queries: &HashMap<String, usize>,
    cur_bb: &BasicBlock,
    qi: usize,
    read_only: bool,
    deterministic_order: bool,
) {
    if read_only && deterministic_order {
        return;
    }
    // `SystemContext::par_chunks` / `par_chunks_readonly` always dispatch physical query 0.
    // Secondary or subsequent queries in the same system must fall back to sequential iteration.
    if remap_qi(query_remap, qi) != 0 {
        return;
    }
    let Some(hdr_bb_id) = (match cur_bb.terminator {
        Terminator::Goto(b) => Some(b.0 as usize),
        _ => None,
    }) else {
        return;
    };
    let Some(hdr_bb) = func.blocks.get(hdr_bb_id) else {
        return;
    };
    let (body_bb_id, exit_bb_id) = match hdr_bb.terminator {
        Terminator::Branch {
            then_bb, else_bb, ..
        } => (then_bb.0, else_bb.0),
        _ => return,
    };

    // Notice `Chunk` does NOT allow `component_rows` on `&Chunk` (requires `&mut Chunk`),
    // so if `read_only` has any `@sparse` query term, fall back to sequential `chunk_hdr` cleanly.
    let has_sparse_read = phys_queries
        .get(qi)
        .is_some_and(|q| q.terms.iter().any(|t| t.is_sparse));
    if read_only && has_sparse_read {
        return;
    }

    // Collect loop-internal basic blocks (all blocks reachable from body_bb stopping at hdr_bb or exit_bb)
    let loop_blocks = collect_loop_subgraph(
        func,
        BlockId(body_bb_id),
        BlockId(hdr_bb_id as u32),
        BlockId(exit_bb_id),
    );
    let has_return_or_break = loop_blocks.iter().any(|&bid| {
        let term = &func.blocks[bid as usize].terminator;
        matches!(term, Terminator::Return(_))
            || guest_term_succs(term)
                .iter()
                .any(|succ| succ.0 == exit_bb_id)
    });
    if has_return_or_break {
        return;
    }

    // Identify reduction accumulator slots actively updated inside `loop_blocks`.
    let mut red_init_locals: HashMap<u32, String> = HashMap::new();
    let mut outer_red_ops: HashMap<u32, String> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::ReduceInit { op, .. } = &s.inst
                && let Some(d) = s.dst
            {
                red_init_locals.insert(d.0, op.clone());
            }
            if let Inst::SlotStore { slot, val } = &s.inst
                && let Some(op) = red_init_locals.get(&val.0)
            {
                outer_red_ops.insert(slot.0, op.clone());
            }
        }
    }
    let mut reduce_accum_locals: HashSet<u32> = HashSet::new();
    for &bid in &loop_blocks {
        for s in &func.blocks[bid as usize].stmts {
            if let Inst::ReduceAccum { .. } = &s.inst
                && let Some(d) = s.dst
            {
                reduce_accum_locals.insert(d.0);
            }
        }
    }
    let mut reduce_slots: Vec<(usize, String)> = Vec::new();
    let mut seen_red_slots: HashSet<usize> = HashSet::new();
    for &bid in &loop_blocks {
        for s in &func.blocks[bid as usize].stmts {
            if let Inst::SlotStore { slot, val } = &s.inst
                && reduce_accum_locals.contains(&val.0)
                && let Some(op) = outer_red_ops.get(&slot.0)
                && seen_red_slots.insert(slot.0 as usize)
            {
                reduce_slots.push((slot.0 as usize, op.clone()));
            }
        }
    }

    // Check if the loop body (directly or transitively via helper calls) uses `SystemContext`-only features.
    let uses_sys_only = loop_blocks.iter().any(|&bid| {
        func.blocks[bid as usize].stmts.iter().any(|s| {
            guest_inst_is_par_unsafe(&s.inst, mir, &mut HashSet::new())
                || matches!(s.inst, Inst::IterNextChunk { query_idx } if query_idx as usize != qi)
        })
    });
    if uses_sys_only {
        return;
    }

    let _ = (stream_decls, named_fallback_queries);

    writeln!(
        out,
        "                if let HostBridge::System(sys_ctx) = bridge {{\n\
         \x20                   let _par_locals_init = locals.clone();\n\
         \x20                   let _par_slots_init = slots.clone();\n\
         \x20                   let _par_world = Arc::clone(world);\n\
         \x20                   let _par_handles = handles.clone();\n\
         \x20                   let _par_reds = Arc::new(Mutex::new(Vec::<(usize, StrataVal)>::new()));\n\
         \x20                   let _par_reds_c = Arc::clone(&_par_reds);"
    )
    .ok();

    let par_call = if read_only {
        "sys_ctx.par_chunks_readonly(move |chunk: &Chunk<'_, '_>| {"
    } else {
        "sys_ctx.par_chunks(move |mut chunk: Chunk<'_, '_>| {"
    };
    let bridge_ctor = if read_only {
        "HostBridge::ParChunkReadonly(chunk)"
    } else {
        "HostBridge::ParChunkMut(&mut chunk)"
    };
    writeln!(out, "                    let _par_status = {par_call}").ok();
    writeln!(
        out,
        "                        let mut _p_bridge = {bridge_ctor};\n\
         \x20                       let bridge = &mut _p_bridge;\n\
         \x20                       let world = &_par_world;\n\
         \x20                       let handles = &_par_handles;\n\
         \x20                       let stream_base: usize = 0;\n\
         \x20                       let mut spawn_batches: Vec<Option<StrataBatchBuf>> = Vec::new();\n\
         \x20                       let migrate_src = StrataObj::Empty;\n\
         \x20                       let mut migrate_dst = StrataObj::Empty;\n\
         \x20                       let trg_payload = StrataObj::Empty;\n\
         \x20                       let mut locals = _par_locals_init.clone();\n\
         \x20                       let mut slots = _par_slots_init.clone();"
    )
    .ok();
    for (sid, op) in &reduce_slots {
        let esc_op = escape_rust_str(op);
        writeln!(
            out,
            "                        slots[{sid}] = strata_reduce_identity(\"{esc_op}\", &slots[{sid}]);"
        )
        .ok();
    }
    writeln!(
        out,
        "                        let mut spatial_hits: Vec<Vec<(FfiEntity, [f32; 4])>> = Vec::new();\n\
         \x20                       let mut par_consumed: [bool; {nq}] = [false; {nq}];\n\
         \x20                       let mut iter_started_once: [bool; {nq}] = [false; {nq}];\n\
         \x20                       let mut dirty_runs: HashMap<usize, (u32, u32)> = HashMap::new();\n\
         \x20                       let args: [StrataVal; 0] = [];\n\
         \x20                       let mut _pbb: u32 = {body_bb_id};\n\
         \x20                       loop {{\n\
         \x20                           match _pbb {{", nq = phys_queries.len().max(1)
    )
    .ok();

    let const_info = collect_guest_fn_const_info(func, mir, cat);
    for &bid in &loop_blocks {
        let bb = &func.blocks[bid as usize];
        writeln!(out, "                                {bid} => {{").ok();
        let mut inner = String::new();
        for st in &bb.stmts {
            emit_inst(
                &mut inner,
                mir,
                cat,
                func,
                phys_queries,
                query_remap,
                stream_decls,
                named_fallback_queries,
                &const_info,
                None,
                None,
                st,
                bb,
            );
        }
        for line in inner.lines() {
            writeln!(out, "                {line}").ok();
        }
        match bb.terminator {
            Terminator::Goto(BlockId(dst)) => {
                if dst as usize == hdr_bb_id || !loop_blocks.contains(&dst) {
                    writeln!(out, "                                    break;").ok();
                } else {
                    writeln!(out, "                                    _pbb = {dst};").ok();
                }
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let t_step = if then_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&then_bb.0)
                {
                    "break;".to_owned()
                } else {
                    format!("_pbb = {};", then_bb.0)
                };
                let e_step = if else_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&else_bb.0)
                {
                    "break;".to_owned()
                } else {
                    format!("_pbb = {};", else_bb.0)
                };
                writeln!(
                    out,
                    "                                    if locals[{}].as_bool() {{ {t_step} }} else {{ {e_step} }}",
                    cond.0
                )
                .ok();
            }
            Terminator::Switch {
                scrutinee,
                ref cases,
                default_bb,
            } => {
                writeln!(
                    out,
                    "                                    match locals[{}].as_u32() {{",
                    scrutinee.0
                )
                .ok();
                for (cv, BlockId(dst)) in cases {
                    if *dst as usize == hdr_bb_id || !loop_blocks.contains(dst) {
                        writeln!(
                            out,
                            "                                        {cv} => break,"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                                        {cv} => _pbb = {dst},"
                        )
                        .ok();
                    }
                }
                if default_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&default_bb.0) {
                    writeln!(out, "                                        _ => break,").ok();
                } else {
                    writeln!(
                        out,
                        "                                        _ => _pbb = {},",
                        default_bb.0
                    )
                    .ok();
                }
                writeln!(out, "                                    }}").ok();
            }
            Terminator::Return(_) => {
                writeln!(out, "                                    break;").ok();
            }
        }
        writeln!(out, "                                }}").ok();
    }

    writeln!(
        out,
        "                                _ => break,\n\
         \x20                           }}\n\
         \x20                       }}"
    )
    .ok();
    if !reduce_slots.is_empty() {
        writeln!(
            out,
            "                        if let Ok(mut _g) = _par_reds_c.lock() {{"
        )
        .ok();
        for (sid, _) in &reduce_slots {
            writeln!(
                out,
                "                            _g.push(({sid}, slots[{sid}].clone()));"
            )
            .ok();
        }
        writeln!(out, "                        }}").ok();
    }
    writeln!(
        out,
        "                    }});\n\
         \x20                   if _par_status.is_ok() {{\n\
         \x20                       par_consumed[{qi}] = true;"
    )
    .ok();
    if !reduce_slots.is_empty() {
        writeln!(
            out,
            "                        if let Ok(_g) = _par_reds.lock() {{"
        )
        .ok();
        for (sid, op) in &reduce_slots {
            let esc_op = escape_rust_str(op);
            writeln!(
                out,
                "                            for (rsid, rval) in _g.iter() {{ if *rsid == {sid} {{ slots[{sid}] = strata_reduce_merge(&slots[{sid}], \"{esc_op}\", rval); }} }}"
            )
            .ok();
        }
        writeln!(out, "                        }}").ok();
    }
    writeln!(
        out,
        "                    }}\n\
         \x20               }}"
    )
    .ok();
}

pub(super) fn collect_loop_subgraph(
    func: &MirFunction,
    body_start: BlockId,
    hdr: BlockId,
    exit_bb: BlockId,
) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![body_start.0];
    while let Some(bi) = stack.pop() {
        if bi == hdr.0 || bi == exit_bb.0 || bi as usize >= func.blocks.len() || !seen.insert(bi) {
            continue;
        }
        match &func.blocks[bi as usize].terminator {
            Terminator::Goto(b) => stack.push(b.0),
            Terminator::Branch {
                then_bb, else_bb, ..
            } => {
                stack.push(then_bb.0);
                stack.push(else_bb.0);
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, b) in cases {
                    stack.push(b.0);
                }
                stack.push(default_bb.0);
            }
            Terminator::Return(_) => {}
        }
    }
    seen.into_iter().collect()
}

fn resolve_guest_spatial_name(mir: &MirModule, func: &MirFunction, key: &str) -> String {
    let short = key.rsplit("::").next().unwrap_or(key);
    if let Some(sp) = mir
        .spatial_indices
        .iter()
        .find(|sp| sp.name == key || sp.name == short)
    {
        return sp.name.clone();
    }
    for rb in &func.resources {
        if (rb.param_name == key || rb.resource_name == key || rb.canonical_name == key)
            && let Some(sp) = mir
                .spatial_indices
                .iter()
                .find(|sp| sp.name == rb.resource_name)
        {
            return sp.name.clone();
        }
    }
    if let Some(sp) = mir.spatial_indices.iter().find(|sp| {
        sp.resource_layout.canonical_name == key
            || sp.resource_layout.canonical_name.rsplit("::").next() == Some(short)
    }) {
        return sp.name.clone();
    }
    key.to_owned()
}
