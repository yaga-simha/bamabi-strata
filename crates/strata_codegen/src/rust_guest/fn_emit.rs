//! RustGuest function emission and unboxed fast-path query loop emitter.

use super::*;

pub(super) fn emit_helper_functions(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    emit_bridge_ptr_helpers(out, cat);
    for (idx, func) in mir.fns.iter().enumerate() {
        let fname = format!("strata_helper_{}_{idx}", sanitize_ident(&func.name));
        let phys_queries = build_physical_queries(func, cat);
        let (_, query_remap) = compute_guest_query_emit_plan(&phys_queries);
        writeln!(
            out,
            "fn {fname}(\n\
             \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
             \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
             \x20   handles: &StrataHandles,\n\
             \x20   args: &[StrataVal],\n\
             ) -> StrataVal {{"
        )
        .ok();
        writeln!(
            out,
            "    let migrate_src = StrataObj::Empty;\n\
             \x20   let mut migrate_dst = StrataObj::Empty;\n\
             \x20   let trg_payload = StrataObj::Empty;\n\
             \x20   let stream_base: usize = 0;"
        )
        .ok();
        emit_cfg_body(
            out,
            mir,
            cat,
            func,
            &phys_queries,
            &query_remap,
            &Vec::new(),
            &HashMap::new(),
            None,
            None,
        );
        writeln!(out, "}}\n").ok();
    }
}

pub(super) fn emit_system_functions(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, func) in mir.functions.iter().enumerate() {
        let fname = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
        let phys_queries = build_physical_queries(func, cat);
        let (_, query_remap) = compute_guest_query_emit_plan(&phys_queries);
        let stream_decls = collect_func_stream_decls(func, cat);
        let named_fallback_queries = collect_named_fallback_queries(mir, func, &phys_queries, cat);

        if let MirFnKind::Migration { .. } = &func.kind {
            writeln!(
                out,
                "fn {fname}(\n\
                 \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
                 \x20   handles: &StrataHandles,\n\
                 \x20   migrate_src: StrataObj,\n\
                 \x20   mut migrate_dst: StrataObj,\n\
                 ) -> StrataObj {{"
            )
            .ok();
            writeln!(
                out,
                "    let mut pure_bridge = HostBridge::Pure;\n\
                 \x20   let bridge = &mut pure_bridge;\n\
                 \x20   let trg_payload = StrataObj::Empty;\n\
                 \x20   let args: [StrataVal; 0] = [];\n\
                 \x20   let stream_base: usize = 0;"
            )
            .ok();
            emit_cfg_body(
                out,
                mir,
                cat,
                func,
                &phys_queries,
                &query_remap,
                &stream_decls,
                &named_fallback_queries,
                Some(("migrate_src", "migrate_dst")),
                None,
            );
            writeln!(out, "}}\n").ok();
            continue;
        }

        if let MirFnKind::Observer { .. } = &func.kind {
            writeln!(
                out,
                "fn {fname}(\n\
                 \x20   ctx: &mut SystemContext<'_>,\n\
                 \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
                 \x20   handles: &StrataHandles,\n\
                 \x20   stream_base: usize,\n\
                 \x20   trg_entity: FfiEntity,\n\
                 \x20   trg_payload: StrataObj,\n\
                 ) {{"
            )
            .ok();
            writeln!(
                out,
                "    let mut sys_bridge = HostBridge::System(ctx);\n\
                 \x20   let bridge = &mut sys_bridge;\n\
                 \x20   let migrate_src = StrataObj::Empty;\n\
                 \x20   let mut migrate_dst = StrataObj::Empty;\n\
                 \x20   let args: [StrataVal; 0] = [];"
            )
            .ok();
            emit_cfg_body(
                out,
                mir,
                cat,
                func,
                &phys_queries,
                &query_remap,
                &stream_decls,
                &named_fallback_queries,
                None,
                Some(("trg_entity", "trg_payload")),
            );
            writeln!(out, "}}\n").ok();
            continue;
        }

        // Standard / Synthesized ECS System
        writeln!(
            out,
            "fn {fname}(\n\
             \x20   ctx: &mut SystemContext<'_>,\n\
             \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
             \x20   handles: &StrataHandles,\n\
             \x20   stream_base: usize,\n\
             ) -> FfiResult {{"
        )
        .ok();
        if let Some(rif) = find_schedule_run_if(mir, func) {
            let mut res_refs = Vec::new();
            collect_hir_res_refs(rif, &mut res_refs);
            let host_checks: Vec<String> = res_refs
                .iter()
                .filter_map(|rname| cat.resolve_comp(rname))
                .filter(|rc| rc.is_resource_like())
                .map(|rc| format!("handles.is_host_res_{}", rc.id))
                .collect();
            if !host_checks.is_empty() {
                let any_host = host_checks.join(" || ");
                let sys_cond =
                    format_run_if_hir_expr(rif, mir, cat, "world", "handles", Some("ctx"));
                writeln!(
                    out,
                    "    if ({any_host}) && !({sys_cond}).as_bool() {{\n\
                     \x20       return FfiResult::OK;\n\
                     \x20   }}"
                )
                .ok();
            }
        }
        writeln!(
            out,
            "    let mut sys_bridge = HostBridge::System(ctx);\n\
             \x20   let bridge = &mut sys_bridge;\n\
             \x20   let migrate_src = StrataObj::Empty;\n\
             \x20   let mut migrate_dst = StrataObj::Empty;\n\
             \x20   let trg_payload = StrataObj::Empty;\n\
             \x20   let args: [StrataVal; 0] = [];"
        )
        .ok();
        emit_cfg_body(
            out,
            mir,
            cat,
            func,
            &phys_queries,
            &query_remap,
            &stream_decls,
            &named_fallback_queries,
            None,
            None,
        );
        writeln!(out, "}}\n").ok();
    }
}

pub(super) fn collect_func_stream_decls(
    func: &MirFunction,
    cat: &GuestCatalog,
) -> Vec<(String, bool)> {
    let mut decls: Vec<(String, bool)> = Vec::new();
    let mut add_decl = |raw: &str, is_write: bool| {
        let key = cat
            .resolve_comp(raw)
            .map_or_else(|| raw.to_owned(), |c| c.canonical_name.clone());
        if let Some((_, existing_write)) = decls.iter_mut().find(|(k, _)| *k == key) {
            *existing_write |= is_write;
        } else {
            decls.push((key, is_write));
        }
    };
    for op in &func.stream_ops {
        let is_write = matches!(
            op.kind,
            MirStreamOpKind::StreamSend | MirStreamOpKind::StreamWriteBatch
        );
        add_decl(&op.canonical_stream, is_write);
    }
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::StreamEmit { stream, .. } = &st.inst {
                add_decl(stream, true);
            }
        }
    }
    decls
}

pub(super) fn stream_decl_index(decls: &[(String, bool)], cat: &GuestCatalog, key: &str) -> usize {
    let canon = cat
        .resolve_comp(key)
        .map_or_else(|| key.to_owned(), |c| c.canonical_name.clone());
    decls
        .iter()
        .position(|(k, _)| *k == canon || k == key)
        .unwrap_or(0)
}

pub(super) fn find_schedule_run_if<'a>(
    mir: &'a MirModule,
    func: &MirFunction,
) -> Option<&'a HirExpr> {
    if let Some(expr) = mir.schedules.iter().find_map(|s| {
        let mut leaves = HashSet::new();
        collect_schedule_leaf_names(&s.nodes, &mut leaves);
        if leaves.contains(&func.name) {
            s.run_if_expr.as_ref()
        } else {
            None
        }
    }) {
        return Some(expr);
    }
    if matches!(
        func.kind,
        MirFnKind::SynthesizedTimerTick
            | MirFnKind::SynthesizedTimeline
            | MirFnKind::SynthesizedTask
            | MirFnKind::SynthesizedFsm
            | MirFnKind::SynthesizedSpatialCsr
    ) && system_schedule_label(mir, &func.name) == "FixedUpdate"
    {
        return mir
            .schedules
            .iter()
            .find(|s| s.label == "FixedUpdate")
            .and_then(|s| s.run_if_expr.as_ref());
    }
    None
}

pub(super) fn collect_named_fallback_queries(
    mir: &MirModule,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    cat: &GuestCatalog,
) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let mut next_qi = phys_queries.len();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::ResolveNamedObject { name } = &st.inst
                && !map.contains_key(name)
                && next_qi < bamabi_sys::MAX_QUERIES_PER_SYSTEM
                && let Some(obj) = mir.objects.iter().find(|o| o.name == *name)
            {
                let has_comp = obj
                    .components
                    .iter()
                    .find_map(|c| cat.resolve_comp(c))
                    .or_else(|| {
                        obj.inits.iter().find_map(|ci| {
                            let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                            cat.resolve_comp(cname)
                        })
                    })
                    .is_some();
                if has_comp {
                    map.insert(name.clone(), next_qi);
                    next_qi += 1;
                }
            }
        }
    }
    map
}

pub(super) struct GuestFnConstInfo {
    pub(super) const_floats: HashMap<LocalId, f64>,
    pub(super) slot_types: HashMap<LocalId, MirType>,
    pub(super) array_inits: HashMap<LocalId, Vec<LocalId>>,
}

pub(super) fn collect_guest_fn_const_info(func: &MirFunction) -> GuestFnConstInfo {
    let mut def_counts: HashMap<LocalId, usize> = HashMap::new();
    let mut slot_types: HashMap<LocalId, MirType> = HashMap::new();
    let mut array_inits: HashMap<LocalId, Vec<LocalId>> = HashMap::new();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Some(d) = st.dst {
                *def_counts.entry(d).or_insert(0) += 1;
                if let Inst::SlotAlloc { ty } = &st.inst {
                    slot_types.insert(d, ty.clone());
                }
            }
        }
    }
    let mut const_floats: HashMap<LocalId, f64> = HashMap::new();
    for _ in 0..3 {
        let mut changed = false;
        for bb in &func.blocks {
            for st in &bb.stmts {
                let Some(d) = st.dst else {
                    continue;
                };
                if def_counts.get(&d) != Some(&1) {
                    continue;
                }
                if let Inst::ArrayInit { elems } = &st.inst {
                    array_inits.entry(d).or_insert_with(|| elems.clone());
                }
                if const_floats.contains_key(&d) {
                    continue;
                }
                let fv_opt = match &st.inst {
                    Inst::ConstFloat { value } => Some(*value),
                    Inst::UnOp { op, val } if op == "-" || op == "Neg" => {
                        const_floats.get(val).map(|fv| -*fv)
                    }
                    Inst::Copy { val } => const_floats.get(val).copied(),
                    _ => None,
                };
                if let Some(fv) = fv_opt {
                    const_floats.insert(d, fv);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    GuestFnConstInfo {
        const_floats,
        slot_types,
        array_inits,
    }
}

pub(super) fn resolve_guest_field_ty_path<'a>(
    cat: &'a GuestCatalog,
    layout_key: &str,
    field: &str,
    offset_bytes: u32,
) -> Option<&'a Ty> {
    let comp = cat.resolve_comp(layout_key)?;
    resolve_guest_field_ty_in_fields(cat, &comp.layout.fields, field, offset_bytes as usize)
}

pub(super) fn resolve_guest_field_ty_in_fields<'a>(
    cat: &'a GuestCatalog,
    fields: &'a [SolvedField],
    field: &str,
    rel_offset: usize,
) -> Option<&'a Ty> {
    if let Some((first, rest)) = field.split_once('.') {
        let f = fields
            .iter()
            .find(|sf| !sf.is_padding && sf.name == first)?;
        if let Ty::Named(ref n) = f.ty
            && let Some(nested) = cat.resolve_comp(n)
        {
            let sub_off = rel_offset.saturating_sub(f.offset);
            return resolve_guest_field_ty_in_fields(cat, &nested.layout.fields, rest, sub_off);
        }
        return None;
    }
    fields
        .iter()
        .find(|sf| {
            !sf.is_padding
                && ((!field.is_empty() && sf.name == field)
                    || (field.is_empty() && sf.offset == rel_offset))
        })
        .map(|sf| &sf.ty)
}

pub(super) fn leaf_array_ty(ty: &Ty) -> &Ty {
    let mut cur = ty;
    while let Ty::Array { elem, .. } = cur {
        cur = elem;
    }
    cur
}

pub(super) fn leaf_array_mir_ty(ty: &MirType) -> &MirType {
    let mut cur = ty;
    while let MirType::Array { elem, .. } = cur {
        cur = elem;
    }
    cur
}

pub(super) fn guest_coerce_val_expr_for_sema_ty(
    target_ty: &Ty,
    vid: LocalId,
    func: &MirFunction,
    const_info: &GuestFnConstInfo,
) -> String {
    let src_ty = func
        .locals
        .get(vid.0 as usize)
        .map_or(MirType::Unit, |l| l.ty.clone());
    let l_expr = format!("locals[{}].clone()", vid.0);
    match target_ty {
        Ty::Fix32 => {
            if src_ty == MirType::Fix32 {
                l_expr
            } else if let Some(&fv) = const_info.const_floats.get(&vid) {
                format!(
                    "StrataVal::Fix32({})",
                    format_fix32_i32_lit(scale_float_fix32(fv))
                )
            } else {
                format!("StrataVal::Fix32(locals[{}].as_fix32())", vid.0)
            }
        }
        Ty::Fix64 => {
            if src_ty == MirType::Fix64 {
                l_expr
            } else if let Some(&fv) = const_info.const_floats.get(&vid) {
                format!(
                    "StrataVal::Fix64({})",
                    format_fix64_i64_lit(scale_float_fix64(fv))
                )
            } else {
                format!("StrataVal::Fix64(locals[{}].as_fix64())", vid.0)
            }
        }
        Ty::F64 => {
            if src_ty != MirType::F64
                && let Some(&fv) = const_info.const_floats.get(&vid)
            {
                format!("StrataVal::F64({})", fmt_f64(fv))
            } else {
                l_expr
            }
        }
        Ty::Array { elem, .. } => {
            if let Some(elems) = const_info.array_inits.get(&vid) {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|&el| guest_coerce_val_expr_for_sema_ty(elem, el, func, const_info))
                    .collect();
                format!("StrataVal::Arr(vec![{}])", parts.join(", "))
            } else if matches!(leaf_array_ty(elem), Ty::Fix64) {
                format!("strata_coerce_arr_fix64({l_expr})")
            } else if matches!(leaf_array_ty(elem), Ty::Fix32) {
                format!("strata_coerce_arr_fix32({l_expr})")
            } else {
                l_expr
            }
        }
        Ty::BitSet(bits) => {
            let words = (*bits).div_ceil(32).max(1);
            format!(
                "match {l_expr} {{ StrataVal::Words(_w) => StrataVal::Words(_w), StrataVal::Arr(_items) => StrataVal::Words(_items.into_iter().map(|_x| _x.as_u32()).collect()), _other => {{ let _m = _other.as_u64(); let mut _ws = vec![0u32; {words}]; if {words} > 0 {{ _ws[0] = _m as u32; }} if {words} > 1 {{ _ws[1] = (_m >> 32) as u32; }} StrataVal::Words(_ws) }} }}"
            )
        }
        _ => l_expr,
    }
}

pub(super) fn guest_coerce_val_expr_for_mir_ty(
    target_ty: &MirType,
    vid: LocalId,
    func: &MirFunction,
    const_info: &GuestFnConstInfo,
) -> String {
    let src_ty = func
        .locals
        .get(vid.0 as usize)
        .map_or(MirType::Unit, |l| l.ty.clone());
    let l_expr = format!("locals[{}].clone()", vid.0);
    match target_ty {
        MirType::Fix32 => {
            if src_ty == MirType::Fix32 {
                l_expr
            } else if let Some(&fv) = const_info.const_floats.get(&vid) {
                format!(
                    "StrataVal::Fix32({})",
                    format_fix32_i32_lit(scale_float_fix32(fv))
                )
            } else {
                format!("StrataVal::Fix32(locals[{}].as_fix32())", vid.0)
            }
        }
        MirType::Fix64 => {
            if src_ty == MirType::Fix64 {
                l_expr
            } else if let Some(&fv) = const_info.const_floats.get(&vid) {
                format!(
                    "StrataVal::Fix64({})",
                    format_fix64_i64_lit(scale_float_fix64(fv))
                )
            } else {
                format!("StrataVal::Fix64(locals[{}].as_fix64())", vid.0)
            }
        }
        MirType::F64 => {
            if src_ty != MirType::F64
                && let Some(&fv) = const_info.const_floats.get(&vid)
            {
                format!("StrataVal::F64({})", fmt_f64(fv))
            } else {
                l_expr
            }
        }
        MirType::Array { elem, .. } => {
            if let Some(elems) = const_info.array_inits.get(&vid) {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|&el| guest_coerce_val_expr_for_mir_ty(elem, el, func, const_info))
                    .collect();
                format!("StrataVal::Arr(vec![{}])", parts.join(", "))
            } else if matches!(leaf_array_mir_ty(elem), MirType::Fix64) {
                format!("strata_coerce_arr_fix64({l_expr})")
            } else if matches!(leaf_array_mir_ty(elem), MirType::Fix32) {
                format!("strata_coerce_arr_fix32({l_expr})")
            } else {
                l_expr
            }
        }
        MirType::Named(n) if n.starts_with("BitSet<") => {
            let bits = n
                .trim_start_matches("BitSet<")
                .trim_end_matches('>')
                .parse::<usize>()
                .unwrap_or(32);
            let words = bits.div_ceil(32).max(1);
            format!(
                "match {l_expr} {{ StrataVal::Words(_w) => StrataVal::Words(_w), StrataVal::Arr(_items) => StrataVal::Words(_items.into_iter().map(|_x| _x.as_u32()).collect()), _other => {{ let _m = _other.as_u64(); let mut _ws = vec![0u32; {words}]; if {words} > 0 {{ _ws[0] = _m as u32; }} if {words} > 1 {{ _ws[1] = (_m >> 32) as u32; }} StrataVal::Words(_ws) }} }}"
            )
        }
        _ => l_expr,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GuestValTy {
    Unit,
    PtrMarker,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Fix32,
    Fix64,
    Vec2,
    Vec3,
    Vec4,
    IVec2,
    IVec3,
    UVec2,
    Entity,
    Struct(usize),
    TableRow(String),
    BitSet(usize),
    Array(Box<GuestValTy>, usize),
    Tuple(Vec<GuestValTy>),
}

impl GuestValTy {
    fn from_mir(mty: &MirType, mir: &MirModule, cat: &GuestCatalog) -> Option<Self> {
        Some(match mty {
            MirType::Unit => Self::Unit,
            MirType::Ptr | MirType::MutPtr => Self::PtrMarker,
            MirType::Bool => Self::Bool,
            MirType::U8 => Self::U8,
            MirType::U16 => Self::U16,
            MirType::U32 | MirType::Sym => Self::U32,
            MirType::U64 => Self::U64,
            MirType::I8 => Self::I8,
            MirType::I16 => Self::I16,
            MirType::I32 => Self::I32,
            MirType::I64 => Self::I64,
            MirType::F32 => Self::F32,
            MirType::F64 => Self::F64,
            MirType::Fix32 => Self::Fix32,
            MirType::Fix64 => Self::Fix64,
            MirType::Vec2 => Self::Vec2,
            MirType::Vec3 => Self::Vec3,
            MirType::Vec4 => Self::Vec4,
            MirType::IVec2 => Self::IVec2,
            MirType::IVec3 => Self::IVec3,
            MirType::UVec2 => Self::UVec2,
            MirType::Entity => Self::Entity,
            MirType::QueryIter | MirType::Checkpoint => return None,
            MirType::Array { elem, len } => {
                Self::Array(Box::new(Self::from_mir(elem, mir, cat)?), *len)
            }
            MirType::Tuple(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(Self::from_mir(it, mir, cat)?);
                }
                Self::Tuple(out)
            }
            MirType::Named(n) => {
                if n == "GraceWindow" {
                    Self::F32
                } else if let Some(inner) =
                    n.strip_prefix("BitSet<").and_then(|s| s.strip_suffix('>'))
                {
                    Self::BitSet(inner.parse().unwrap_or(32))
                } else if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                    match (sz, is_signed) {
                        (1, _) => Self::U8,
                        (2, _) => Self::U16,
                        (_, true) => Self::I32,
                        _ => Self::U32,
                    }
                } else if let Some(te) = cat.resolve_table(n) {
                    Self::TableRow(te.struct_name.clone())
                } else if let Some(c) = cat.resolve_comp(n) {
                    Self::Struct(c.id)
                } else if n.contains("IVec2") {
                    Self::IVec2
                } else if n.contains("IVec3") {
                    Self::IVec3
                } else if n.contains("UVec2") {
                    Self::UVec2
                } else if n.contains("Vec2") || n == "vec2" {
                    Self::Vec2
                } else if n.contains("Vec3") || n == "vec3" {
                    Self::Vec3
                } else if n.contains("Vec4") || n.contains("Quat") || n.contains("Rgba") {
                    Self::Vec4
                } else {
                    return None;
                }
            }
        })
    }

    fn from_sema_ty(ty: &Ty, mir: &MirModule, cat: &GuestCatalog) -> Option<Self> {
        Some(match ty {
            Ty::Unit => Self::Unit,
            Ty::Bool => Self::Bool,
            Ty::U8 => Self::U8,
            Ty::I8 => Self::I8,
            Ty::U16 => Self::U16,
            Ty::I16 => Self::I16,
            Ty::U32 | Ty::Sym | Ty::Rgba8 => Self::U32,
            Ty::I32 => Self::I32,
            Ty::Fix32 => Self::Fix32,
            Ty::U64 => Self::U64,
            Ty::I64 => Self::I64,
            Ty::Fix64 => Self::Fix64,
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Self::F32,
            Ty::F64 => Self::F64,
            Ty::Vec2 => Self::Vec2,
            Ty::Vec3 => Self::Vec3,
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Self::Vec4,
            Ty::IVec2 => Self::IVec2,
            Ty::IVec3 => Self::IVec3,
            Ty::UVec2 => Self::UVec2,
            Ty::Ref(_) => Self::Entity,
            Ty::BitSet(b) => Self::BitSet(*b),
            Ty::Array { elem, len } => {
                Self::Array(Box::new(Self::from_sema_ty(elem, mir, cat)?), *len)
            }
            Ty::Tuple(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(Self::from_sema_ty(it, mir, cat)?);
                }
                Self::Tuple(out)
            }
            Ty::Named(n) => {
                if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                    match (sz, is_signed) {
                        (1, _) => Self::U8,
                        (2, _) => Self::U16,
                        (_, true) => Self::I32,
                        _ => Self::U32,
                    }
                } else {
                    let te = cat.resolve_table(n)?;
                    Self::TableRow(te.struct_name.clone())
                }
            }
            _ => return None,
        })
    }

    fn rust_type(&self, cat: &GuestCatalog) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::U8 => "u8".to_owned(),
            Self::U16 => "u16".to_owned(),
            Self::U32 => "u32".to_owned(),
            Self::U64 => "u64".to_owned(),
            Self::I8 => "i8".to_owned(),
            Self::I16 => "i16".to_owned(),
            Self::I32 | Self::Fix32 => "i32".to_owned(),
            Self::I64 | Self::Fix64 => "i64".to_owned(),
            Self::F32 => "f32".to_owned(),
            Self::F64 => "f64".to_owned(),
            Self::Vec2 => "[f32; 2]".to_owned(),
            Self::Vec3 => "[f32; 3]".to_owned(),
            Self::Vec4 => "[f32; 4]".to_owned(),
            Self::IVec2 => "[i32; 2]".to_owned(),
            Self::IVec3 => "[i32; 3]".to_owned(),
            Self::UVec2 => "[u32; 2]".to_owned(),
            Self::Entity => "FfiEntity".to_owned(),
            Self::Struct(cid) => cat.components[*cid].struct_name.clone(),
            Self::TableRow(sname) => sname.clone(),
            Self::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::Array(e, n) => format!("[{}; {n}]", e.rust_type(cat)),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(|t| t.rust_type(cat)).collect();
                format!("({})", parts.join(", "))
            }
        }
    }

    fn default_expr(&self) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "false".to_owned(),
            Self::U8 => "0u8".to_owned(),
            Self::U16 => "0u16".to_owned(),
            Self::U32 => "0u32".to_owned(),
            Self::U64 => "0u64".to_owned(),
            Self::I8 => "0i8".to_owned(),
            Self::I16 => "0i16".to_owned(),
            Self::I32 | Self::Fix32 => "0i32".to_owned(),
            Self::I64 | Self::Fix64 => "0i64".to_owned(),
            Self::F32 => "0.0_f32".to_owned(),
            Self::F64 => "0.0_f64".to_owned(),
            Self::Vec2 => "[0.0_f32; 2]".to_owned(),
            Self::Vec3 => "[0.0_f32; 3]".to_owned(),
            Self::Vec4 => "[0.0_f32; 4]".to_owned(),
            Self::IVec2 => "[0i32; 2]".to_owned(),
            Self::IVec3 => "[0i32; 3]".to_owned(),
            Self::UVec2 => "[0u32; 2]".to_owned(),
            Self::Entity => "FfiEntity::NULL".to_owned(),
            Self::Struct(_) | Self::TableRow(_) => "Default::default()".to_owned(),
            Self::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::Array(e, n) => format!("[{}; {n}]", e.default_expr()),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::default_expr).collect();
                format!("({})", parts.join(", "))
            }
        }
    }

    fn is_int(&self) -> bool {
        matches!(
            self,
            Self::U8
                | Self::U16
                | Self::U32
                | Self::U64
                | Self::I8
                | Self::I16
                | Self::I32
                | Self::I64
        )
    }

    fn is_fixed(&self) -> bool {
        matches!(self, Self::Fix32 | Self::Fix64)
    }

    fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    fn is_vec(&self) -> Option<usize> {
        match self {
            Self::Vec2 => Some(2),
            Self::Vec3 => Some(3),
            Self::Vec4 => Some(4),
            _ => None,
        }
    }

    fn is_ivec(&self) -> Option<usize> {
        match self {
            Self::IVec2 | Self::UVec2 => Some(2),
            Self::IVec3 => Some(3),
            _ => None,
        }
    }

    fn extract_from_strata_val(&self, expr: &str, cat: &GuestCatalog) -> Option<String> {
        Some(match self {
            Self::Bool => format!("{expr}.as_bool()"),
            Self::U8 => format!("({expr}.as_u32() as u8)"),
            Self::U16 => format!("({expr}.as_u32() as u16)"),
            Self::U32 => format!("{expr}.as_u32()"),
            Self::U64 => format!("{expr}.as_u64()"),
            Self::I8 => format!("({expr}.as_i32() as i8)"),
            Self::I16 => format!("({expr}.as_i32() as i16)"),
            Self::I32 => format!("{expr}.as_i32()"),
            Self::Fix32 => format!("{expr}.as_fix32()"),
            Self::I64 => format!("{expr}.as_i64()"),
            Self::Fix64 => format!("{expr}.as_fix64()"),
            Self::F32 => format!("{expr}.as_f32()"),
            Self::F64 => format!("{expr}.as_f64()"),
            Self::Vec2 => format!("{expr}.as_vec2()"),
            Self::Vec3 => format!("{expr}.as_vec3()"),
            Self::Vec4 => format!("{expr}.as_vec4()"),
            Self::IVec2 => format!("{expr}.as_ivec2()"),
            Self::IVec3 => format!("{expr}.as_ivec3()"),
            Self::UVec2 => format!("{expr}.as_uvec2()"),
            Self::Entity => format!("{expr}.as_entity()"),
            Self::Struct(cid) => {
                let c = &cat.components[*cid];
                format!(
                    "match &{expr} {{ StrataVal::Obj(StrataObj::{}(_v)) => *_v, _ => {}::default() }}",
                    c.variant_name, c.struct_name
                )
            }
            _ => return None,
        })
    }

    fn to_strata_val(&self, expr: &str, cat: &GuestCatalog) -> Option<String> {
        Some(match self {
            Self::Bool => format!("StrataVal::Bool({expr})"),
            Self::U8 | Self::U16 | Self::U32 => format!("StrataVal::U32(({expr}) as u32)"),
            Self::U64 => format!("StrataVal::U64({expr})"),
            Self::I8 | Self::I16 | Self::I32 => {
                format!("StrataVal::I32(({expr}) as i32)")
            }
            Self::Fix32 => format!("StrataVal::Fix32({expr})"),
            Self::I64 => format!("StrataVal::I64({expr})"),
            Self::Fix64 => format!("StrataVal::Fix64({expr})"),
            Self::F32 => format!("StrataVal::F32({expr})"),
            Self::F64 => format!("StrataVal::F64({expr})"),
            Self::Vec2 => format!("StrataVal::Vec2({expr})"),
            Self::Vec3 => format!("StrataVal::Vec3({expr})"),
            Self::Vec4 => format!("StrataVal::Vec4({expr})"),
            Self::IVec2 => format!("StrataVal::IVec2({expr})"),
            Self::IVec3 => format!("StrataVal::IVec3({expr})"),
            Self::UVec2 => format!("StrataVal::UVec2({expr})"),
            Self::Entity => format!("StrataVal::Entity({expr})"),
            Self::Struct(cid) => {
                let c = &cat.components[*cid];
                format!("StrataVal::Obj(StrataObj::{}({expr}))", c.variant_name)
            }
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) enum GuestPtrTarget {
    Resource {
        comp_id: usize,
        is_mut: bool,
    },
    QueryCol {
        query_idx: u32,
        phys_col: usize,
        comp_id: usize,
        selective: bool,
        optional: bool,
        projected: Option<(String, GuestValTy, Ty)>,
    },
    QueryRow {
        query_idx: u32,
        phys_col: usize,
        comp_id: usize,
        selective: bool,
        optional: bool,
        projected: Option<(String, GuestValTy, Ty)>,
    },
    EntitiesSlice {
        query_idx: u32,
    },
    SlotRef {
        slot_local: LocalId,
    },
    Field {
        base: Box<GuestPtrTarget>,
        field: String,
    },
}

pub(super) struct GuestFastLoop {
    pub(super) query_idx: u32,
    pub(super) hdr_bb: BlockId,
    pub(super) row_hdr_bb: BlockId,
    pub(super) row_body_bb: BlockId,
    pub(super) row_exit_bb: BlockId,
    pub(super) exit_bb: BlockId,
    pub(super) par_bb: Option<BlockId>,
    pub(super) par_is_readonly: bool,
    pub(super) use_par: bool,
    pub(super) needs_entity: bool,
    pub(super) loop_blocks: HashSet<BlockId>,
    pub(super) row_inc_blocks: HashSet<BlockId>,
    pub(super) row_body_blocks: HashSet<BlockId>,
    pub(super) row_idx_slot: LocalId,
    pub(super) row_idx_locals: HashSet<LocalId>,
    pub(super) has_break: bool,
    pub(super) selective_col: Option<usize>,
    pub(super) has_dirty_record_row: bool,
    pub(super) live_in_locals: Vec<u32>,
    pub(super) live_in_slots: Vec<u32>,
    pub(super) outer_slot_writes: Vec<u32>,
    pub(super) reduce_info: Vec<(LocalId, String, GuestValTy)>,
    pub(super) read_res_comp_ids: Vec<usize>,
    pub(super) inner_slots: Vec<LocalId>,
    pub(super) inner_locals: Vec<LocalId>,
    pub(super) val_tys: Vec<GuestValTy>,
    pub(super) slot_tys: HashMap<LocalId, GuestValTy>,
    pub(super) ptr_targets: HashMap<LocalId, GuestPtrTarget>,
    pub(super) const_ints: HashMap<u32, i64>,
    pub(super) const_floats: HashMap<u32, f64>,
}

pub(super) fn guest_inst_read_locals(inst: &Inst) -> Vec<u32> {
    let mut out = Vec::new();
    match inst {
        Inst::ConstInt { .. }
        | Inst::ConstFloat { .. }
        | Inst::ConstBool { .. }
        | Inst::ConstVec { .. }
        | Inst::ConstString { .. }
        | Inst::SlotAlloc { .. }
        | Inst::IterNextChunk { .. }
        | Inst::IterChunkLen { .. }
        | Inst::IterEntities { .. }
        | Inst::IterColRead { .. }
        | Inst::IterColWrite { .. }
        | Inst::IterColWriteUntracked { .. }
        | Inst::IterColRowsRead { .. }
        | Inst::IterColRowsWrite { .. }
        | Inst::IterCount { .. }
        | Inst::IterReset { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::BindNamedObject { .. }
        | Inst::ResolveNamedObject { .. }
        | Inst::InternSymbol { .. }
        | Inst::TriggerPayload { .. }
        | Inst::TriggerTarget
        | Inst::CmdDespawnAll { .. }
        | Inst::CmdCheckpoint
        | Inst::SpatialRebuildCsr { .. }
        | Inst::SpatialCsrBegin { .. }
        | Inst::SpatialCsrPrefixSum { .. }
        | Inst::DirtyRunInit { .. }
        | Inst::FsmDispatch { .. }
        | Inst::MigrateSrcPtr { .. }
        | Inst::MigrateDstPtr { .. } => {}
        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::ReduceInit { identity: val, .. }
        | Inst::EntityGet { entity: val, .. }
        | Inst::EntityGetMut { entity: val, .. }
        | Inst::IterUpCascade { entity: val, .. }
        | Inst::SpatialCsrCount { pos: val, .. }
        | Inst::GraceIsActive { ptr: val }
        | Inst::GraceClear { ptr: val }
        | Inst::TimelineInWindow { ptr: val, .. }
        | Inst::SpawnBatchCommit { batch: val }
        | Inst::CmdDespawn { entity: val }
        | Inst::CmdRemove { entity: val, .. }
        | Inst::StreamEmit { payload: val, .. }
        | Inst::CmdRollback {
            checkpoint: val, ..
        }
        | Inst::TableLoad { key: val, .. }
        | Inst::CurveSample { x: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::ShadowCommit {
            shadow_slot: val, ..
        }
        | Inst::RequireTrue { cond: val } => out.push(val.0),
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
        | Inst::IterMarkChangedRange {
            run_start: lhs,
            run_len: rhs,
            ..
        }
        | Inst::ReduceAccum {
            acc: lhs, val: rhs, ..
        }
        | Inst::GraceArm {
            ptr: lhs,
            duration_sec: rhs,
        }
        | Inst::GraceTick {
            ptr: lhs,
            dt_sec: rhs,
        }
        | Inst::InputBufConsume {
            ptr: lhs,
            action_id: rhs,
            ..
        }
        | Inst::InputBufPeek {
            ptr: lhs,
            action_id: rhs,
            ..
        }
        | Inst::InputBufTick {
            ptr: lhs,
            dt_sec: rhs,
            ..
        }
        | Inst::BitSetSet {
            ptr: lhs, bit: rhs, ..
        }
        | Inst::BitSetGet {
            ptr: lhs, bit: rhs, ..
        }
        | Inst::BitSetClear {
            ptr: lhs, bit: rhs, ..
        }
        | Inst::CmdRemoveRelation {
            entity: lhs,
            target: rhs,
            ..
        }
        | Inst::SpatialQueryDisc {
            center: lhs,
            radius: rhs,
            ..
        }
        | Inst::ShadowWrite {
            shadow_slot: lhs,
            val: rhs,
            ..
        }
        | Inst::TimelineAdvance {
            cursor_ptr: lhs,
            dt_sec: rhs,
            ..
        }
        | Inst::TaskStep {
            pc_local: lhs,
            timer_local: rhs,
            ..
        } => {
            out.push(lhs.0);
            out.push(rhs.0);
        }
        Inst::IntrinsicMath { args, .. } | Inst::Call { args, .. } => {
            for a in args {
                out.push(a.0);
            }
        }
        Inst::StructInit { fields, .. } => {
            for (_, v) in fields {
                out.push(v.0);
            }
        }
        Inst::ArrayInit { elems } => {
            for e in elems {
                out.push(e.0);
            }
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
        Inst::CmdSpawn { components, .. } => {
            for (_, v) in components {
                out.push(v.0);
            }
        }
        Inst::CmdSpawnBatch { count, components } => {
            out.push(count.0);
            for (_, v) in components {
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
        Inst::CmdInsert { entity, data, .. } => {
            out.push(entity.0);
            if let Some(d) = data {
                out.push(d.0);
            }
        }
        Inst::CmdTrigger {
            target, payload, ..
        } => {
            if let Some(t) = target {
                out.push(t.0);
            }
            if let Some(p) = payload {
                out.push(p.0);
            }
        }
        Inst::CmdInsertRelation {
            entity,
            target,
            payload,
            ..
        } => {
            out.push(entity.0);
            out.push(target.0);
            if let Some(p) = payload {
                out.push(p.0);
            }
        }
        Inst::SpatialQuerySegmentAt {
            start,
            end,
            radius,
            tick_offset,
            ..
        } => {
            out.push(start.0);
            out.push(end.0);
            out.push(radius.0);
            out.push(tick_offset.0);
        }
        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        }
        | Inst::ArrayStore {
            base_ptr: run_start,
            index: run_len,
            val: row_idx,
            ..
        } => {
            out.push(run_start.0);
            out.push(run_len.0);
            out.push(row_idx.0);
        }
    }
    out
}

pub(super) fn guest_term_read_locals(term: &Terminator) -> Vec<u32> {
    match term {
        Terminator::Return(Some(v)) => vec![v.0],
        Terminator::Branch { cond, .. } => vec![cond.0],
        Terminator::Switch { scrutinee, .. } => vec![scrutinee.0],
        Terminator::Return(None) | Terminator::Goto(_) => Vec::new(),
    }
}

pub(super) fn guest_term_succs(term: &Terminator) -> Vec<BlockId> {
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

pub(super) fn guest_reachable_blocks(func: &MirFunction) -> HashSet<BlockId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(entry) = func.blocks.first() {
        visited.insert(entry.id);
        queue.push_back(entry.id);
    }
    while let Some(bid) = queue.pop_front() {
        if let Some(bb) = func.blocks.iter().find(|b| b.id == bid) {
            for succ in guest_term_succs(&bb.terminator) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
    visited
}

pub(super) fn resolve_guest_field<'a>(
    cat: &'a GuestCatalog,
    comp_id: usize,
    field_name: &str,
    offset_bytes: u32,
) -> Option<&'a SolvedField> {
    let layout = &cat.components.get(comp_id)?.layout;
    layout.fields.iter().find(|f| {
        !f.is_padding
            && ((!field_name.is_empty() && f.name == field_name)
                || f.offset == offset_bytes as usize)
    })
}

pub(super) fn is_supported_guest_intrinsic(name: &str) -> bool {
    let short = name.rsplit("::").next().unwrap_or(name);
    matches!(
        short,
        "sqrt"
            | "abs"
            | "floor"
            | "ceil"
            | "round"
            | "trunc"
            | "fract"
            | "signum"
            | "sign"
            | "sin"
            | "cos"
            | "tan"
            | "asin"
            | "acos"
            | "atan"
            | "atan2"
            | "exp"
            | "ln"
            | "log"
            | "log2"
            | "log10"
            | "pow"
            | "powf"
            | "min"
            | "max"
            | "clamp"
            | "saturate"
            | "lerp"
            | "mix"
            | "mul_add"
            | "fma"
            | "vec2"
            | "vec3"
            | "vec3a"
            | "Vec3a"
            | "vec4"
            | "dot"
            | "cross"
            | "length"
            | "len"
            | "length_sq"
            | "len_sq"
            | "distance"
            | "dist"
            | "normalize"
            | "norm"
            | "step"
            | "smoothstep"
            | "raw"
            | "to_bits"
            | "is_null"
            | "is_valid"
    )
}

pub(super) fn is_fast_guest_field_ty(ty: &Ty, mir: &MirModule, cat: &GuestCatalog) -> bool {
    fn has_unsupported_array_elem(ty: &Ty, mir: &MirModule) -> bool {
        fn is_excluded_elem(t: &Ty, mir: &MirModule) -> bool {
            match t {
                Ty::Bool
                | Ty::Quat
                | Ty::Rgba
                | Ty::Tuple(_)
                | Ty::Mat3
                | Ty::Mat4
                | Ty::Asset(_)
                | Ty::SmallVec { .. }
                | Ty::InputBuffer { .. }
                | Ty::Unknown => true,
                Ty::Array { elem, .. } => is_excluded_elem(elem, mir),
                Ty::Named(n) => find_enum_layout_or_def(n, mir).is_none(),
                _ => false,
            }
        }
        matches!(ty, Ty::Array { elem, .. } if is_excluded_elem(elem, mir))
    }
    !has_unsupported_array_elem(ty, mir) && GuestValTy::from_sema_ty(ty, mir, cat).is_some()
}

pub(super) fn is_supported_guest_intrinsic_call(
    name: &str,
    args: &[LocalId],
    dst_ty: Option<&GuestValTy>,
    val_tys: &[GuestValTy],
) -> bool {
    if !is_supported_guest_intrinsic(name) {
        return false;
    }
    let short = name.rsplit("::").next().unwrap_or(name);
    let Some(dt) = dst_ty else {
        return true;
    };
    let arg_ty = |i: usize| args.get(i).and_then(|l| val_tys.get(l.0 as usize));
    match short {
        "vec2" => *dt == GuestValTy::Vec2,
        "vec3" => *dt == GuestValTy::Vec3,
        "vec4" => *dt == GuestValTy::Vec4,
        "cross" => {
            *dt == GuestValTy::Vec3
                && arg_ty(0) == Some(&GuestValTy::Vec3)
                && arg_ty(1) == Some(&GuestValTy::Vec3)
        }
        "min" | "max" => {
            let a0 = arg_ty(0);
            let a1 = arg_ty(1);
            if matches!(
                a0,
                Some(GuestValTy::Vec2 | GuestValTy::Vec3 | GuestValTy::Vec4)
            ) {
                a0 == a1 && a0 == Some(dt)
            } else {
                dt.is_int() || dt.is_fixed() || dt.is_float()
            }
        }
        "lerp" | "mix" => {
            let a0 = arg_ty(0);
            if matches!(
                a0,
                Some(GuestValTy::Vec2 | GuestValTy::Vec3 | GuestValTy::Vec4)
            ) {
                a0 == Some(dt)
            } else {
                dt.is_int() || dt.is_fixed() || dt.is_float()
            }
        }
        "normalize" | "norm" => {
            let a0 = arg_ty(0);
            matches!(
                a0,
                Some(GuestValTy::Vec2 | GuestValTy::Vec3 | GuestValTy::Vec4)
            ) && a0 == Some(dt)
        }
        "is_null" | "is_valid" => *dt == GuestValTy::Bool && arg_ty(0) == Some(&GuestValTy::Entity),
        "dot" | "length" | "len" | "length_sq" | "len_sq" | "distance" | "dist" => {
            dt.is_float() || dt.is_int() || dt.is_fixed()
        }
        _ => dt.is_int() || dt.is_fixed() || dt.is_float() || *dt == GuestValTy::Bool,
    }
}

pub(super) fn analyze_guest_fast_loops(
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
) -> Vec<GuestFastLoop> {
    let reachable = guest_reachable_blocks(func);
    let mut val_tys: Vec<GuestValTy> = Vec::with_capacity(func.locals.len());
    for l in &func.locals {
        let Some(vt) = GuestValTy::from_mir(&l.ty, mir, cat) else {
            return Vec::new();
        };
        val_tys.push(vt);
    }

    let mut def_counts: HashMap<u32, usize> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Some(d) = s.dst {
                *def_counts.entry(d.0).or_insert(0) += 1;
            }
        }
    }
    let mut const_ints: HashMap<u32, i64> = HashMap::new();
    let mut const_floats: HashMap<u32, f64> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Some(d) = s.dst
                && def_counts.get(&d.0) == Some(&1)
            {
                match s.inst {
                    Inst::ConstInt { value } => {
                        const_ints.insert(d.0, value);
                    }
                    Inst::ConstFloat { value } => {
                        const_floats.insert(d.0, value);
                    }
                    _ => {}
                }
            }
        }
    }
    for _ in 0..2 {
        for bb in &func.blocks {
            for s in &bb.stmts {
                if let Some(d) = s.dst
                    && def_counts.get(&d.0) == Some(&1)
                {
                    match &s.inst {
                        Inst::Copy { val } => {
                            if let Some(&cv) = const_ints.get(&val.0) {
                                const_ints.insert(d.0, cv);
                            }
                            if let Some(&fv) = const_floats.get(&val.0) {
                                const_floats.insert(d.0, fv);
                            }
                        }
                        Inst::UnOp { op, val } if op == "-" || op == "Neg" => {
                            if let Some(&cv) = const_ints.get(&val.0) {
                                const_ints.insert(d.0, cv.wrapping_neg());
                            }
                            if let Some(&fv) = const_floats.get(&val.0) {
                                const_floats.insert(d.0, -fv);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let mut slot_tys: HashMap<LocalId, GuestValTy> = HashMap::new();
    let mut ptr_targets: HashMap<LocalId, GuestPtrTarget> = HashMap::new();

    for rb in &func.resources {
        if let Some(rc) = cat.resolve_comp(&rb.canonical_name)
            && rc.is_resource_like()
        {
            ptr_targets.insert(
                rb.ptr_local,
                GuestPtrTarget::Resource {
                    comp_id: rc.id,
                    is_mut: rb.mutable,
                },
            );
        }
    }

    for bb in &func.blocks {
        for st in &bb.stmts {
            match &st.inst {
                Inst::SlotAlloc { ty } => {
                    if let Some(d) = st.dst
                        && let Some(vt) = GuestValTy::from_mir(ty, mir, cat)
                    {
                        slot_tys.insert(d, vt);
                    }
                }
                Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                    let is_mut = matches!(st.inst, Inst::ResWrite { .. });
                    if let Some(d) = st.dst
                        && let Some(rc) = cat.resolve_comp(resource)
                        && rc.is_resource_like()
                    {
                        ptr_targets.insert(
                            d,
                            GuestPtrTarget::Resource {
                                comp_id: rc.id,
                                is_mut,
                            },
                        );
                    }
                }
                Inst::IterEntities { query_idx } => {
                    if let Some(d) = st.dst {
                        ptr_targets.insert(
                            d,
                            GuestPtrTarget::EntitiesSlice {
                                query_idx: *query_idx,
                            },
                        );
                    }
                }
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
                    if let Some(d) = st.dst
                        && let Some(pq) = phys_queries.get(*query_idx as usize)
                        && let Some(&phys_col) = pq.term_to_phys.get(term_idx)
                    {
                        let pterm = &pq.terms[phys_col];
                        let qb = func
                            .query_bindings
                            .iter()
                            .find(|q| q.query_idx == *query_idx);
                        let mterm =
                            qb.and_then(|q| q.terms.iter().find(|t| t.term_idx == *term_idx));
                        let projected = mterm.and_then(|t| {
                            let fnm = t.field_name.as_ref()?;
                            let sf = resolve_guest_field(cat, pterm.comp_id, fnm, 0)?;
                            let vt = GuestValTy::from_sema_ty(&sf.ty, mir, cat)?;
                            Some((fnm.clone(), vt, sf.ty.clone()))
                        });
                        ptr_targets.insert(
                            d,
                            GuestPtrTarget::QueryCol {
                                query_idx: *query_idx,
                                phys_col,
                                comp_id: pterm.comp_id,
                                selective: pterm.mode == TermAccessMode::SelectiveWrite
                                    || matches!(st.inst, Inst::IterColWriteUntracked { .. }),
                                optional: matches!(
                                    pterm.mode,
                                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                                ),
                                projected,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    for _ in 0..4 {
        for bb in &func.blocks {
            for st in &bb.stmts {
                match &st.inst {
                    Inst::Copy { val } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = val_tys[val.0 as usize].clone();
                            if let Some(pt) = ptr_targets.get(val).cloned() {
                                ptr_targets.insert(d, pt);
                            }
                        }
                    }
                    Inst::VecInsert { vec, .. } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = val_tys[vec.0 as usize].clone();
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        let vt = &val_tys[val.0 as usize];
                        let cur = slot_tys.get(slot);
                        if *vt != GuestValTy::Unit
                            && *vt != GuestValTy::PtrMarker
                            && (cur.is_none()
                                || matches!(
                                    cur,
                                    Some(
                                        GuestValTy::Unit
                                            | GuestValTy::PtrMarker
                                            | GuestValTy::U64
                                            | GuestValTy::I64
                                    )
                                )
                                || (matches!(cur, Some(GuestValTy::Vec3))
                                    && *vt == GuestValTy::Vec2))
                        {
                            slot_tys.insert(*slot, vt.clone());
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(d) = st.dst
                            && let Some(st_ty) = slot_tys.get(slot)
                            && *st_ty != GuestValTy::Unit
                            && *st_ty != GuestValTy::PtrMarker
                        {
                            val_tys[d.0 as usize] = st_ty.clone();
                        }
                    }
                    Inst::RowPtr { col_ptr, .. } => {
                        if let Some(d) = st.dst
                            && let Some(GuestPtrTarget::QueryCol {
                                query_idx,
                                phys_col,
                                comp_id,
                                selective,
                                optional,
                                projected,
                            }) = ptr_targets.get(col_ptr).cloned()
                        {
                            ptr_targets.insert(
                                d,
                                GuestPtrTarget::QueryRow {
                                    query_idx,
                                    phys_col,
                                    comp_id,
                                    selective,
                                    optional,
                                    projected,
                                },
                            );
                        }
                    }
                    Inst::FieldPtr {
                        base_ptr, field, ..
                    } => {
                        if let Some(d) = st.dst {
                            if let Some(base) = ptr_targets.get(base_ptr).cloned() {
                                ptr_targets.insert(
                                    d,
                                    GuestPtrTarget::Field {
                                        base: Box::new(base),
                                        field: field.clone(),
                                    },
                                );
                            } else if slot_tys.contains_key(base_ptr) {
                                ptr_targets.insert(
                                    d,
                                    GuestPtrTarget::SlotRef {
                                        slot_local: *base_ptr,
                                    },
                                );
                            }
                        }
                    }
                    Inst::FieldLoad {
                        layout_key,
                        field,
                        offset_bytes,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            if let Some(rc) = cat.resolve_comp(layout_key)
                                && let Some(sf) =
                                    resolve_guest_field(cat, rc.id, field, *offset_bytes)
                                && let Some(vt) = GuestValTy::from_sema_ty(&sf.ty, mir, cat)
                            {
                                val_tys[d.0 as usize] = vt;
                            } else if let Some(te) = cat.resolve_table(layout_key)
                                && let Some((_, fty)) =
                                    te.fields.iter().find(|(fnm, _)| fnm == field)
                                && let Some(vt) = GuestValTy::from_sema_ty(fty, mir, cat)
                            {
                                val_tys[d.0 as usize] = vt;
                            }
                        }
                    }
                    Inst::TableLoad {
                        table_name, field, ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(te) = cat.resolve_table(table_name)
                        {
                            if field.is_empty() {
                                val_tys[d.0 as usize] =
                                    GuestValTy::TableRow(te.struct_name.clone());
                            } else if let Some((_, fty)) =
                                te.fields.iter().find(|(fnm, _)| fnm == field)
                                && let Some(vt) = GuestValTy::from_sema_ty(fty, mir, cat)
                            {
                                val_tys[d.0 as usize] = vt;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut claimed_blocks: HashSet<BlockId> = HashSet::new();

    for bb in &func.blocks {
        if !reachable.contains(&bb.id) || claimed_blocks.contains(&bb.id) {
            continue;
        }
        let Some(query_idx) = bb.stmts.iter().find_map(|s| match s.inst {
            Inst::IterNextChunk { query_idx } => Some(query_idx),
            _ => None,
        }) else {
            continue;
        };
        if bb
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterUpCascade { .. }))
        {
            continue;
        }
        let Terminator::Branch {
            then_bb: chunk_body_bb,
            else_bb: exit_bb,
            ..
        } = bb.terminator
        else {
            continue;
        };
        if chunk_body_bb == bb.id || chunk_body_bb == exit_bb || exit_bb.0 == 0 {
            continue;
        }

        // Collect `loop_blocks` reachable from `chunk_body_bb` stopping at `bb.id` (`hdr_bb`) or `exit_bb`.
        let mut loop_blocks = HashSet::new();
        let mut queue = VecDeque::new();
        loop_blocks.insert(chunk_body_bb);
        queue.push_back(chunk_body_bb);
        let mut bad_cfg = false;
        while let Some(cur) = queue.pop_front() {
            let Some(cur_bb) = func.blocks.get(cur.0 as usize) else {
                bad_cfg = true;
                break;
            };
            if matches!(cur_bb.terminator, Terminator::Return(_)) {
                bad_cfg = true;
                break;
            }
            for succ in guest_term_succs(&cur_bb.terminator) {
                if succ != bb.id && succ != exit_bb && loop_blocks.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        if bad_cfg || loop_blocks.contains(&bb.id) {
            continue;
        }

        // Find optional `par_bb` whose last stmt is ParForEachChunk* and terminator is Goto(hdr_bb).
        let mut par_candidate: Option<(BlockId, bool, bool)> = None;
        for pbb in &func.blocks {
            if !reachable.contains(&pbb.id) || loop_blocks.contains(&pbb.id) || pbb.id == bb.id {
                continue;
            }
            if let Terminator::Goto(target) = pbb.terminator
                && target == bb.id
                && let Some(last_st) = pbb.stmts.last()
            {
                match last_st.inst {
                    Inst::ParForEachChunk {
                        query_idx: pq_i, ..
                    } if pq_i == query_idx => {
                        par_candidate = Some((pbb.id, false, false));
                    }
                    Inst::ParForEachChunkReadonly {
                        query_idx: pq_i,
                        deterministic_order,
                        ..
                    } if pq_i == query_idx => {
                        par_candidate = Some((pbb.id, true, deterministic_order));
                    }
                    _ => {}
                }
            }
        }

        let (par_bb, par_is_readonly, deterministic_order) = match par_candidate {
            Some((b, ro, det)) => (Some(b), ro, det),
            None => (None, false, false),
        };

        // Ensure no outside block jumps into `loop_blocks` (or into `hdr_bb` except single pred if `par_bb.is_some()`).
        let mut hdr_preds = 0usize;
        for ob in &func.blocks {
            if !reachable.contains(&ob.id) || loop_blocks.contains(&ob.id) || ob.id == bb.id {
                continue;
            }
            for succ in guest_term_succs(&ob.terminator) {
                if loop_blocks.contains(&succ) {
                    bad_cfg = true;
                    break;
                }
                if succ == bb.id {
                    hdr_preds += 1;
                }
            }
            if bad_cfg {
                break;
            }
        }
        if bad_cfg || (par_bb.is_some() && hdr_preds != 1) {
            continue;
        }

        // Verify canonical single row_hdr pattern (`chunk_body_bb -> Goto(row_hdr_bb)`).
        let Terminator::Goto(row_hdr_bb) = func.blocks[chunk_body_bb.0 as usize].terminator else {
            continue;
        };
        if !loop_blocks.contains(&row_hdr_bb) || row_hdr_bb == chunk_body_bb {
            continue;
        }
        let rh = &func.blocks[row_hdr_bb.0 as usize];
        let Terminator::Branch {
            then_bb: row_body_bb,
            else_bb: row_exit_bb,
            ..
        } = rh.terminator
        else {
            continue;
        };
        if !loop_blocks.contains(&row_body_bb) || row_body_bb == row_hdr_bb {
            continue;
        }
        // `row_exit_bb` must be `hdr_bb` OR a flush block whose terminator is `Goto(hdr_bb)`.
        let valid_row_exit = if row_exit_bb == bb.id {
            true
        } else if loop_blocks.contains(&row_exit_bb) {
            let reb = &func.blocks[row_exit_bb.0 as usize];
            matches!(reb.terminator, Terminator::Goto(t) if t == bb.id)
                && reb.stmts.iter().all(|s| {
                    matches!(
                        s.inst,
                        Inst::IterMarkChangedRange { query_idx: qi, .. } if qi == query_idx
                    )
                })
        } else {
            false
        };
        if !valid_row_exit {
            continue;
        }

        // Find `row_idx_slot` from `row_hdr_bb`'s `SlotLoad` + `BinOp("<", row_idx, chunk_len)`.
        let row_idx_slot_opt = rh.stmts.iter().find_map(|s| match s.inst {
            Inst::SlotLoad { slot } => Some(slot),
            _ => None,
        });
        let Some(row_idx_slot) = row_idx_slot_opt else {
            continue;
        };
        let mut row_idx_locals: HashSet<LocalId> = HashSet::new();
        for s in &rh.stmts {
            if let Inst::SlotLoad { slot } = s.inst
                && slot == row_idx_slot
                && let Some(d) = s.dst
            {
                row_idx_locals.insert(d);
            }
        }

        // Identify `row_inc_blocks` (blocks jumping directly to `row_hdr_bb` that only increment `row_idx_slot`).
        let mut row_inc_blocks = HashSet::new();
        for &bid in &loop_blocks {
            if bid == chunk_body_bb || bid == row_hdr_bb || bid == row_exit_bb {
                continue;
            }
            let rbb = &func.blocks[bid.0 as usize];
            if matches!(rbb.terminator, Terminator::Goto(t) if t == row_hdr_bb)
                && rbb.stmts.iter().all(|s| {
                    matches!(
                        s.inst,
                        Inst::SlotLoad { slot } if slot == row_idx_slot
                    ) || matches!(s.inst, Inst::ConstInt { value: 1 })
                        || matches!(s.inst, Inst::BinOp { ref op, .. } if op == "+")
                        || matches!(s.inst, Inst::SlotStore { slot, .. } if slot == row_idx_slot)
                })
                && rbb
                    .stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::SlotStore { slot, .. } if slot == row_idx_slot))
            {
                row_inc_blocks.insert(bid);
            }
        }

        let mut row_body_blocks = HashSet::new();
        for &bid in &loop_blocks {
            if bid != chunk_body_bb
                && bid != row_hdr_bb
                && bid != row_exit_bb
                && !row_inc_blocks.contains(&bid)
            {
                row_body_blocks.insert(bid);
            }
        }
        if !row_body_blocks.contains(&row_body_bb) {
            continue;
        }
        for &bid in &row_body_blocks {
            for s in &func.blocks[bid.0 as usize].stmts {
                if let Inst::SlotLoad { slot } = s.inst
                    && slot == row_idx_slot
                    && let Some(d) = s.dst
                {
                    row_idx_locals.insert(d);
                }
            }
        }

        // Check `PhysicalQuery` eligibility.
        let Some(pq) = phys_queries.get(query_idx as usize) else {
            continue;
        };
        if !pq.extra_changed_filters.is_empty()
            || pq.terms.iter().any(|t| {
                t.is_sparse
                    || t.changed_filter
                    || t.added_filter
                    || !matches!(
                        t.mode,
                        TermAccessMode::Read
                            | TermAccessMode::Write
                            | TermAccessMode::SelectiveWrite
                            | TermAccessMode::OptionalRead
                            | TermAccessMode::OptionalWrite
                            | TermAccessMode::Allow
                            | TermAccessMode::Has
                    )
            })
        {
            continue;
        }
        let total_bam_terms = pq.terms.len()
            + pq.with_filters.len()
            + pq.without_filters.len()
            + pq.extra_changed_filters.len();
        if total_bam_terms == 0 || total_bam_terms > bamabi_sys::MAX_TERMS_PER_QUERY {
            continue;
        }

        let mut read_locals_in_loop: HashSet<u32> = HashSet::new();
        for &bid in &loop_blocks {
            let b = &func.blocks[bid.0 as usize];
            for s in &b.stmts {
                for r in guest_inst_read_locals(&s.inst) {
                    read_locals_in_loop.insert(r);
                }
            }
            for r in guest_term_read_locals(&b.terminator) {
                read_locals_in_loop.insert(r);
            }
        }
        let uses_entities = loop_blocks.iter().any(|&bid| {
            func.blocks[bid.0 as usize].stmts.iter().any(|s| {
                matches!(
                    s.inst,
                    Inst::EntityAtRow { entities_ptr, .. }
                        if s.dst.is_some_and(|d| read_locals_in_loop.contains(&d.0))
                            && matches!(
                                ptr_targets.get(&entities_ptr),
                                Some(GuestPtrTarget::EntitiesSlice { query_idx: qi }) if *qi == query_idx
                            )
                )
            })
        });
        let all_opt_or_marker = pq.terms.iter().all(|t| {
            matches!(
                t.mode,
                TermAccessMode::OptionalRead
                    | TermAccessMode::OptionalWrite
                    | TermAccessMode::Allow
                    | TermAccessMode::Has
            )
        });
        let needs_entity = uses_entities || all_opt_or_marker;

        let selective_cols: Vec<usize> = pq
            .terms
            .iter()
            .enumerate()
            .filter(|(_, t)| t.mode == TermAccessMode::SelectiveWrite)
            .map(|(i, _)| i)
            .collect();
        let selective_col = if selective_cols.is_empty() {
            let tuple_arity = usize::from(needs_entity) + total_bam_terms;
            if tuple_arity > 16 {
                continue;
            }
            None
        } else {
            if selective_cols.len() != 1 || needs_entity {
                continue;
            }
            if pq.terms.iter().any(|t| {
                matches!(
                    t.mode,
                    TermAccessMode::OptionalRead
                        | TermAccessMode::OptionalWrite
                        | TermAccessMode::Allow
                        | TermAccessMode::Has
                )
            }) {
                continue;
            }
            let other_data_cnt = pq
                .terms
                .iter()
                .filter(|t| matches!(t.mode, TermAccessMode::Read | TermAccessMode::Write))
                .count();
            if other_data_cnt > 2 {
                continue;
            }
            Some(selective_cols[0])
        };

        // Analyze instructions inside `loop_blocks`.
        let mut defined_inside: HashSet<u32> = HashSet::new();
        let mut allocs_inside: HashSet<u32> = HashSet::new();
        let mut dirty_slots: HashSet<u32> = HashSet::new();
        let mut has_dirty_record_row = false;
        for &bid in &loop_blocks {
            for s in &func.blocks[bid.0 as usize].stmts {
                if let Some(d) = s.dst {
                    defined_inside.insert(d.0);
                    if matches!(s.inst, Inst::SlotAlloc { .. }) {
                        allocs_inside.insert(d.0);
                    }
                }
                if let Inst::DirtyRunInit { run_start, run_len } = s.inst {
                    defined_inside.insert(run_start.0);
                    defined_inside.insert(run_len.0);
                    dirty_slots.insert(run_start.0);
                    dirty_slots.insert(run_len.0);
                }
                if matches!(s.inst, Inst::DirtyRunRecordRow { .. }) {
                    has_dirty_record_row = true;
                }
            }
        }

        // Collect reduction accumulators (`ReduceInit` -> `SlotStore` outer, `ReduceAccum` -> `SlotStore`).
        let mut red_init_locals: HashMap<u32, String> = HashMap::new();
        let mut outer_red_ops: HashMap<u32, String> = HashMap::new();
        for ob in &func.blocks {
            for s in &ob.stmts {
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
        let mut reduce_info: Vec<(LocalId, String, GuestValTy)> = Vec::new();
        let mut seen_red_slots: HashSet<u32> = HashSet::new();
        for &bid in &loop_blocks {
            for s in &func.blocks[bid.0 as usize].stmts {
                if let Inst::ReduceAccum { .. } = &s.inst
                    && let Some(d) = s.dst
                {
                    reduce_accum_locals.insert(d.0);
                }
            }
        }

        let mut outer_slot_writes: Vec<u32> = Vec::new();
        let mut seen_outer_writes: HashSet<u32> = HashSet::new();
        let mut read_res_comp_ids: Vec<usize> = Vec::new();
        let mut seen_res_cids: HashSet<usize> = HashSet::new();
        let mut has_break = false;
        let mut unsupported_inst = false;

        for &bid in &loop_blocks {
            let bb_cur = &func.blocks[bid.0 as usize];
            if row_body_blocks.contains(&bid)
                && guest_term_succs(&bb_cur.terminator).contains(&exit_bb)
            {
                has_break = true;
            }
            for s in &bb_cur.stmts {
                match &s.inst {
                    Inst::ConstInt { .. }
                    | Inst::ConstFloat { .. }
                    | Inst::ConstBool { .. }
                    | Inst::ConstVec { .. }
                    | Inst::Copy { .. }
                    | Inst::SlotAlloc { .. }
                    | Inst::BinOp { .. }
                    | Inst::UnOp { .. }
                    | Inst::Cast { .. }
                    | Inst::VecExtract { .. }
                    | Inst::VecInsert { .. }
                    | Inst::VecSwizzle { .. }
                    | Inst::ReduceAccum { .. }
                    | Inst::OptionalChunkIsPresent { .. }
                    | Inst::DirtyRunInit { .. }
                    | Inst::DirtyRunRecordRow { .. }
                    | Inst::TableLoad { .. }
                    | Inst::CurveSample { .. } => {}
                    Inst::IntrinsicMath { name, args, .. } => {
                        if !is_supported_guest_intrinsic_call(
                            name,
                            args,
                            s.dst.map(|d| &val_tys[d.0 as usize]),
                            &val_tys,
                        ) {
                            unsupported_inst = true;
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if !allocs_inside.contains(&slot.0) && !slot_tys.contains_key(slot) {
                            unsupported_inst = true;
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if !allocs_inside.contains(&slot.0) {
                            if reduce_accum_locals.contains(&val.0)
                                && let Some(op) = outer_red_ops.get(&slot.0)
                            {
                                if seen_red_slots.insert(slot.0) {
                                    let Some(vty) = slot_tys.get(slot).cloned() else {
                                        unsupported_inst = true;
                                        break;
                                    };
                                    reduce_info.push((*slot, op.clone(), vty));
                                }
                            } else if seen_outer_writes.insert(slot.0) {
                                outer_slot_writes.push(slot.0);
                            }
                        }
                    }
                    Inst::IterNextChunk { query_idx: qi }
                    | Inst::IterChunkLen { query_idx: qi }
                    | Inst::IterEntities { query_idx: qi }
                    | Inst::IterColRead { query_idx: qi, .. }
                    | Inst::IterColWrite { query_idx: qi, .. }
                    | Inst::IterColWriteUntracked { query_idx: qi, .. }
                    | Inst::IterMarkChangedRange { query_idx: qi, .. }
                        if *qi == query_idx => {}
                    Inst::EntityAtRow { entities_ptr, .. } => {
                        if !matches!(
                            ptr_targets.get(entities_ptr),
                            Some(GuestPtrTarget::EntitiesSlice { query_idx: qi }) if *qi == query_idx
                        ) {
                            unsupported_inst = true;
                        }
                    }
                    Inst::RowPtr { col_ptr, .. } => {
                        if !matches!(
                            ptr_targets.get(col_ptr),
                            Some(GuestPtrTarget::QueryCol { query_idx: qi, .. }) if *qi == query_idx
                        ) {
                            unsupported_inst = true;
                        }
                    }
                    Inst::FieldPtr { base_ptr, .. } => match ptr_targets.get(base_ptr) {
                        Some(GuestPtrTarget::QueryRow { query_idx: qi, .. })
                            if *qi == query_idx => {}
                        Some(GuestPtrTarget::Resource { is_mut: false, .. }) => {}
                        Some(GuestPtrTarget::SlotRef { slot_local })
                            if allocs_inside.contains(&slot_local.0) => {}
                        _ => unsupported_inst = true,
                    },
                    Inst::FieldLoad {
                        base_ptr,
                        field,
                        offset_bytes,
                        ..
                    } => {
                        let ok = match ptr_targets.get(base_ptr) {
                            Some(GuestPtrTarget::QueryRow {
                                query_idx: qi,
                                comp_id,
                                projected,
                                ..
                            }) if *qi == query_idx => {
                                if field.is_empty() && *offset_bytes == 0 && projected.is_some() {
                                    projected.as_ref().is_some_and(|(_, _, st)| {
                                        is_fast_guest_field_ty(st, mir, cat)
                                    })
                                } else {
                                    resolve_guest_field(cat, *comp_id, field, *offset_bytes)
                                        .is_some_and(|sf| is_fast_guest_field_ty(&sf.ty, mir, cat))
                                }
                            }
                            Some(GuestPtrTarget::Resource {
                                comp_id,
                                is_mut: false,
                            }) => {
                                if seen_res_cids.insert(*comp_id) {
                                    read_res_comp_ids.push(*comp_id);
                                }
                                resolve_guest_field(cat, *comp_id, field, *offset_bytes)
                                    .is_some_and(|sf| is_fast_guest_field_ty(&sf.ty, mir, cat))
                            }
                            Some(GuestPtrTarget::Field { base, field: bf }) => {
                                if let GuestPtrTarget::QueryRow {
                                    query_idx: qi,
                                    comp_id,
                                    ..
                                } = base.as_ref()
                                    && *qi == query_idx
                                {
                                    let fname = if field.is_empty() { bf } else { field };
                                    resolve_guest_field(cat, *comp_id, fname, *offset_bytes)
                                        .is_some_and(|sf| is_fast_guest_field_ty(&sf.ty, mir, cat))
                                } else {
                                    false
                                }
                            }
                            _ => matches!(val_tys[base_ptr.0 as usize], GuestValTy::TableRow(_)),
                        };
                        if !ok {
                            unsupported_inst = true;
                        }
                    }
                    Inst::FieldStore {
                        base_ptr,
                        field,
                        offset_bytes,
                        ..
                    } => {
                        let ok = match ptr_targets.get(base_ptr) {
                            Some(GuestPtrTarget::QueryRow {
                                query_idx: qi,
                                comp_id,
                                projected,
                                ..
                            }) if *qi == query_idx => {
                                if field.is_empty() && *offset_bytes == 0 && projected.is_some() {
                                    projected.as_ref().is_some_and(|(_, _, st)| {
                                        is_fast_guest_field_ty(st, mir, cat)
                                    })
                                } else {
                                    resolve_guest_field(cat, *comp_id, field, *offset_bytes)
                                        .is_some_and(|sf| is_fast_guest_field_ty(&sf.ty, mir, cat))
                                }
                            }
                            Some(GuestPtrTarget::Field { base, field: bf }) => {
                                if let GuestPtrTarget::QueryRow {
                                    query_idx: qi,
                                    comp_id,
                                    ..
                                } = base.as_ref()
                                    && *qi == query_idx
                                {
                                    let fname = if field.is_empty() { bf } else { field };
                                    resolve_guest_field(cat, *comp_id, fname, *offset_bytes)
                                        .is_some_and(|sf| is_fast_guest_field_ty(&sf.ty, mir, cat))
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        };
                        if !ok {
                            unsupported_inst = true;
                        }
                    }
                    Inst::GraceArm { ptr, .. }
                    | Inst::GraceTick { ptr, .. }
                    | Inst::GraceIsActive { ptr }
                    | Inst::GraceClear { ptr }
                    | Inst::BitSetSet { ptr, .. }
                    | Inst::BitSetGet { ptr, .. }
                    | Inst::BitSetClear { ptr, .. } => {
                        let ok = match ptr_targets.get(ptr) {
                            Some(GuestPtrTarget::Field { base, .. }) => {
                                matches!(base.as_ref(), GuestPtrTarget::QueryRow { query_idx: qi, .. } if *qi == query_idx)
                            }
                            Some(GuestPtrTarget::QueryRow {
                                query_idx: qi,
                                projected: Some(_),
                                ..
                            }) if *qi == query_idx => true,
                            _ => false,
                        };
                        if !ok {
                            unsupported_inst = true;
                        }
                    }
                    Inst::ResRead { resource } => {
                        if let Some(rc) = cat.resolve_comp(resource)
                            && rc.is_resource_like()
                        {
                            if seen_res_cids.insert(rc.id) {
                                read_res_comp_ids.push(rc.id);
                            }
                        } else {
                            unsupported_inst = true;
                        }
                    }
                    _ => unsupported_inst = true,
                }
                if unsupported_inst {
                    break;
                }
            }
            if unsupported_inst {
                break;
            }
        }
        if unsupported_inst {
            continue;
        }

        // Collect live-in outer locals and outer slots read inside `loop_blocks`.
        let mut live_in_locals = Vec::new();
        let mut live_in_slots = Vec::new();
        let mut live_seen = HashSet::new();
        let mut bad_capture = false;

        let mut record_read = |r: u32| {
            if defined_inside.contains(&r) || !live_seen.insert(r) {
                return;
            }
            let lid = LocalId(r);
            if let Some(pt) = ptr_targets.get(&lid) {
                match pt {
                    GuestPtrTarget::Resource {
                        comp_id,
                        is_mut: false,
                    } => {
                        if seen_res_cids.insert(*comp_id) {
                            read_res_comp_ids.push(*comp_id);
                        }
                        return;
                    }
                    _ => {
                        bad_capture = true;
                        return;
                    }
                }
            }
            if let Some(st_ty) = slot_tys.get(&lid) {
                if st_ty.extract_from_strata_val("_x", cat).is_none() {
                    bad_capture = true;
                    return;
                }
                if !outer_red_ops.contains_key(&r) && !seen_outer_writes.contains(&r) {
                    live_in_slots.push(r);
                }
                return;
            }
            let vt = &val_tys[r as usize];
            if *vt == GuestValTy::Unit || *vt == GuestValTy::PtrMarker {
                return;
            }
            if vt.extract_from_strata_val("_x", cat).is_none() {
                bad_capture = true;
                return;
            }
            live_in_locals.push(r);
        };

        for &bid in &loop_blocks {
            let bb_cur = &func.blocks[bid.0 as usize];
            for s in &bb_cur.stmts {
                for r in guest_inst_read_locals(&s.inst) {
                    record_read(r);
                }
            }
            for r in guest_term_read_locals(&bb_cur.terminator) {
                record_read(r);
            }
        }
        if bad_capture {
            continue;
        }

        // Verify no outer_slot_write is non-convertible to/from StrataVal.
        if outer_slot_writes.iter().any(|&sid| {
            slot_tys.get(&LocalId(sid)).is_none_or(|vt| {
                vt.extract_from_strata_val("_x", cat).is_none()
                    || vt.to_strata_val("_x", cat).is_none()
            })
        }) {
            continue;
        }
        if reduce_info
            .iter()
            .any(|(_, _, vt)| vt.to_strata_val("_x", cat).is_none())
        {
            continue;
        }

        // Verify nothing outside `loop_blocks` reads anything defined inside `loop_blocks`.
        let mut leaked = false;
        for ob in &func.blocks {
            if loop_blocks.contains(&ob.id) {
                continue;
            }
            for s in &ob.stmts {
                if guest_inst_read_locals(&s.inst)
                    .iter()
                    .any(|r| defined_inside.contains(r))
                {
                    leaked = true;
                    break;
                }
            }
            if guest_term_read_locals(&ob.terminator)
                .iter()
                .any(|r| defined_inside.contains(r))
            {
                leaked = true;
            }
            if leaked {
                break;
            }
        }
        if leaked {
            continue;
        }

        let use_par = par_bb.is_some()
            && !(par_is_readonly && deterministic_order)
            && outer_slot_writes.is_empty()
            && !has_break;

        let mut inner_slots: Vec<LocalId> = allocs_inside
            .iter()
            .copied()
            .filter(|&sid| sid != row_idx_slot.0 && !dirty_slots.contains(&sid))
            .map(LocalId)
            .collect();
        inner_slots.sort_by_key(|l| l.0);

        let mut inner_locals: Vec<LocalId> = defined_inside
            .iter()
            .copied()
            .filter(|&lid| {
                let id = LocalId(lid);
                !row_idx_locals.contains(&id)
                    && !allocs_inside.contains(&lid)
                    && !dirty_slots.contains(&lid)
                    && !matches!(
                        val_tys[lid as usize],
                        GuestValTy::Unit | GuestValTy::PtrMarker
                    )
            })
            .map(LocalId)
            .collect();
        inner_locals.sort_by_key(|l| l.0);

        claimed_blocks.insert(bb.id);
        for &lb in &loop_blocks {
            claimed_blocks.insert(lb);
        }

        out.push(GuestFastLoop {
            query_idx,
            hdr_bb: bb.id,
            row_hdr_bb,
            row_body_bb,
            row_exit_bb,
            exit_bb,
            par_bb,
            par_is_readonly,
            use_par,
            needs_entity,
            loop_blocks,
            row_inc_blocks,
            row_body_blocks,
            row_idx_slot,
            row_idx_locals,
            has_break,
            selective_col,
            has_dirty_record_row,
            live_in_locals,
            live_in_slots,
            outer_slot_writes,
            reduce_info,
            read_res_comp_ids,
            inner_slots,
            inner_locals,
            val_tys: val_tys.clone(),
            slot_tys: slot_tys.clone(),
            ptr_targets: ptr_targets.clone(),
            const_ints: const_ints.clone(),
            const_floats: const_floats.clone(),
        });
    }

    out
}

pub(super) fn guest_query_tuple_type(
    cat: &GuestCatalog,
    pq: &PhysicalQuery,
    needs_entity: bool,
) -> String {
    let mut parts = Vec::new();
    if needs_entity {
        parts.push("FfiEntity".to_owned());
    }
    for pt in &pq.terms {
        let sname = &cat.components[pt.comp_id].struct_name;
        let term_ty = match pt.mode {
            TermAccessMode::Write => format!("&'static mut {sname}"),
            TermAccessMode::OptionalWrite => format!("Option<&'static mut {sname}>"),
            TermAccessMode::OptionalRead => format!("Option<&'static {sname}>"),
            TermAccessMode::Allow => format!("Allow<{sname}>"),
            TermAccessMode::Has => format!("Has<{sname}>"),
            _ => format!("&'static {sname}"),
        };
        parts.push(term_ty);
    }
    for &cid in &pq.with_filters {
        parts.push(format!("With<{}>", cat.components[cid].struct_name));
    }
    for &cid in &pq.without_filters {
        parts.push(format!("Without<{}>", cat.components[cid].struct_name));
    }
    format!("({},)", parts.join(", "))
}

pub(super) fn guest_query_tuple_pattern(qi: u32, pq: &PhysicalQuery, needs_entity: bool) -> String {
    let mut parts = Vec::new();
    if needs_entity {
        parts.push(format!("__q{qi}_entities"));
    }
    for (pidx, pt) in pq.terms.iter().enumerate() {
        match pt.mode {
            TermAccessMode::Read | TermAccessMode::Write => {
                parts.push(format!("__q{qi}_col_{pidx}"));
            }
            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite => {
                parts.push(format!("mut __q{qi}_col_{pidx}"));
            }
            _ => parts.push("_".to_owned()),
        }
    }
    for _ in &pq.with_filters {
        parts.push("_".to_owned());
    }
    for _ in &pq.without_filters {
        parts.push("_".to_owned());
    }
    format!("({},)", parts.join(", "))
}

pub(super) fn guest_reduce_identity(op: &str, vty: &GuestValTy) -> String {
    match op {
        "min" | "Min" => match vty {
            GuestValTy::F32 => "f32::MAX".to_owned(),
            GuestValTy::F64 => "f64::MAX".to_owned(),
            GuestValTy::U32 => "u32::MAX".to_owned(),
            GuestValTy::I32 | GuestValTy::Fix32 => "i32::MAX".to_owned(),
            GuestValTy::U64 => "u64::MAX".to_owned(),
            GuestValTy::I64 | GuestValTy::Fix64 => "i64::MAX".to_owned(),
            _ => vty.default_expr(),
        },
        "max" | "Max" => match vty {
            GuestValTy::F32 => "f32::MIN".to_owned(),
            GuestValTy::F64 => "f64::MIN".to_owned(),
            GuestValTy::U32 => "0u32".to_owned(),
            GuestValTy::I32 | GuestValTy::Fix32 => "i32::MIN".to_owned(),
            GuestValTy::U64 => "0u64".to_owned(),
            GuestValTy::I64 | GuestValTy::Fix64 => "i64::MIN".to_owned(),
            _ => vty.default_expr(),
        },
        "prod" | "Prod" | "*" | "*=" => match vty {
            GuestValTy::F32 => "1.0_f32".to_owned(),
            GuestValTy::F64 => "1.0_f64".to_owned(),
            GuestValTy::U32 => "1u32".to_owned(),
            GuestValTy::I32 => "1i32".to_owned(),
            GuestValTy::U64 => "1u64".to_owned(),
            GuestValTy::I64 => "1i64".to_owned(),
            _ => vty.default_expr(),
        },
        "all" | "All" | "&&" => "true".to_owned(),
        _ => vty.default_expr(),
    }
}

pub(super) fn guest_reduce_combine(
    op: &str,
    vty: &GuestValTy,
    acc: &str,
    val: &str,
    cat: &GuestCatalog,
) -> String {
    let rhs = if *vty == GuestValTy::Bool {
        val.to_owned()
    } else {
        format!("({val}) as {}", vty.rust_type(cat))
    };
    match op {
        "min" | "Min" => format!("({acc}).min({rhs})"),
        "max" | "Max" => format!("({acc}).max({rhs})"),
        "prod" | "Prod" | "*" | "*=" => format!("({acc}) * ({rhs})"),
        "any" | "Any" | "||" => format!("({acc}) || ({rhs})"),
        "all" | "All" | "&&" => format!("({acc}) && ({rhs})"),
        "count" | "Count" => format!("({acc}) + u32::from({val})"),
        _ => format!("({acc}) + ({rhs})"),
    }
}

pub(super) fn guest_fast_local_expr(lid: LocalId, fl: &GuestFastLoop) -> String {
    if fl.row_idx_locals.contains(&lid) {
        "(__row as u32)".to_owned()
    } else if fl.live_in_locals.contains(&lid.0) {
        format!("__u_{}", lid.0)
    } else {
        format!("__loc_{}", lid.0)
    }
}

pub(super) fn guest_fast_slot_expr(sid: LocalId, fl: &GuestFastLoop) -> String {
    if let Some((ri, _)) = fl
        .reduce_info
        .iter()
        .enumerate()
        .find(|(_, (sl, _, _))| *sl == sid)
    {
        if fl.use_par {
            return format!("__cred_{ri}");
        }
        return format!("__oslot_{}", sid.0);
    }
    if fl.live_in_slots.contains(&sid.0) {
        format!("__uslot_{}", sid.0)
    } else if fl.outer_slot_writes.contains(&sid.0) {
        format!("__oslot_{}", sid.0)
    } else {
        format!("__slot_{}", sid.0)
    }
}

pub(super) fn guest_fast_coerce(
    expr: &str,
    from: &GuestValTy,
    to: &GuestValTy,
    cat: &GuestCatalog,
) -> String {
    if from == to {
        return expr.to_owned();
    }
    match (from, to) {
        (GuestValTy::Bool, GuestValTy::F32) => {
            format!("(if {expr} {{ 1.0_f32 }} else {{ 0.0_f32 }})")
        }
        (GuestValTy::Bool, GuestValTy::F64) => {
            format!("(if {expr} {{ 1.0_f64 }} else {{ 0.0_f64 }})")
        }
        (GuestValTy::Bool, GuestValTy::Fix32) => {
            format!("(if {expr} {{ 65536i32 }} else {{ 0i32 }})")
        }
        (GuestValTy::Bool, GuestValTy::Fix64) => {
            format!("(if {expr} {{ 4294967296i64 }} else {{ 0i64 }})")
        }
        (GuestValTy::Bool, _) if to.is_int() => {
            format!("(if {expr} {{ 1 }} else {{ 0 }}) as {}", to.rust_type(cat))
        }
        (_, GuestValTy::Bool) if from.is_int() || from.is_fixed() => format!("(({expr}) != 0)"),
        (_, GuestValTy::Bool) if from.is_float() => format!("(({expr}) != 0.0)"),
        (GuestValTy::Entity, GuestValTy::Bool) => format!("(!{expr}.is_null())"),
        (GuestValTy::Entity, _) if to.is_int() => {
            format!("({expr}.to_bits() as {})", to.rust_type(cat))
        }
        (_, GuestValTy::Entity) if from.is_int() || from.is_float() => {
            format!("FfiEntity::from_bits(({expr}) as u64)")
        }
        (GuestValTy::Fix32, GuestValTy::F32) => format!("((({expr}) as f32) / 65536.0_f32)"),
        (GuestValTy::Fix32, GuestValTy::F64) => format!("((({expr}) as f64) / 65536.0_f64)"),
        (GuestValTy::F32 | GuestValTy::F64, GuestValTy::Fix32) => {
            format!(
                "{{ let __v = ({expr}) as f64; if __v.is_finite() {{ (__v * 65536.0_f64).round() as i32 }} else {{ 0 }} }}"
            )
        }
        (GuestValTy::Fix64, GuestValTy::F32) => {
            format!("(((({expr}) as f64) / 4294967296.0_f64) as f32)")
        }
        (GuestValTy::Fix64, GuestValTy::F64) => format!("((({expr}) as f64) / 4294967296.0_f64)"),
        (GuestValTy::F32 | GuestValTy::F64, GuestValTy::Fix64) => {
            format!(
                "{{ let __v = ({expr}) as f64; if __v.is_finite() {{ (__v * 4294967296.0_f64).round() as i64 }} else {{ 0 }} }}"
            )
        }
        (GuestValTy::Fix32, GuestValTy::Fix64) => format!("((({expr}) as i64) << 16)"),
        (GuestValTy::Fix64, GuestValTy::Fix32) => format!("((({expr}) >> 16) as i32)"),
        (_, GuestValTy::Fix32) if from.is_int() => {
            format!("((({expr}) as i64).saturating_mul(65536) as i32)")
        }
        (_, GuestValTy::Fix64) if from.is_int() => {
            format!("((({expr}) as i64).wrapping_shl(32))")
        }
        (GuestValTy::Fix32, _) if to.is_int() => {
            format!("((({expr}) / 65536i32) as {})", to.rust_type(cat))
        }
        (GuestValTy::Fix64, _) if to.is_int() => {
            format!("((({expr}) / 4294967296i64) as {})", to.rust_type(cat))
        }
        _ if (from.is_int() || from.is_float()) && (to.is_int() || to.is_float()) => {
            format!("(({expr}) as {})", to.rust_type(cat))
        }
        (GuestValTy::Array(fe, flen), GuestValTy::Array(te, tlen)) if flen == tlen => {
            format!(
                "({expr}).map(|__ael| {})",
                guest_fast_coerce("__ael", fe, te, cat)
            )
        }
        (GuestValTy::Vec3, GuestValTy::Vec4) => {
            format!("[{expr}[0], {expr}[1], {expr}[2], 0.0_f32]")
        }
        (GuestValTy::Vec4, GuestValTy::Vec3) => format!("[{expr}[0], {expr}[1], {expr}[2]]"),
        (GuestValTy::Vec2, GuestValTy::Vec3) => format!("[{expr}[0], {expr}[1], 0.0_f32]"),
        (GuestValTy::Array(fe, flen), GuestValTy::BitSet(_))
            if matches!(fe.as_ref(), GuestValTy::U32) =>
        {
            let _ = flen;
            expr.to_owned()
        }
        (from_s, GuestValTy::BitSet(bits)) if from_s.is_int() => {
            let words = (*bits).div_ceil(32).max(1);
            let mut elems = Vec::with_capacity(words);
            for w in 0..words {
                if w == 0 {
                    elems.push("(_m as u32)".to_owned());
                } else if w == 1 {
                    elems.push("((_m >> 32) as u32)".to_owned());
                } else {
                    elems.push("0u32".to_owned());
                }
            }
            format!("{{ let _m = ({expr}) as u64; [{}] }}", elems.join(", "))
        }
        _ => expr.to_owned(),
    }
}

pub(super) fn guest_fast_binop(
    op: &str,
    lhs: LocalId,
    rhs: LocalId,
    dst_ty: &GuestValTy,
    fl: &GuestFastLoop,
    cat: &GuestCatalog,
) -> String {
    let l_ty = &fl.val_tys[lhs.0 as usize];
    let r_ty = &fl.val_tys[rhs.0 as usize];
    let le = guest_fast_local_expr(lhs, fl);
    let re = guest_fast_local_expr(rhs, fl);

    if let Some(dims) = l_ty.is_ivec()
        && r_ty.is_ivec() == Some(dims)
    {
        return match op {
            "+" => {
                let parts: Vec<String> = (0..dims)
                    .map(|i| format!("({le}[{i}]).wrapping_add({re}[{i}])"))
                    .collect();
                format!("[{}]", parts.join(", "))
            }
            "-" => {
                let parts: Vec<String> = (0..dims)
                    .map(|i| format!("({le}[{i}]).wrapping_sub({re}[{i}])"))
                    .collect();
                format!("[{}]", parts.join(", "))
            }
            "*" => {
                let parts: Vec<String> = (0..dims)
                    .map(|i| format!("({le}[{i}]).wrapping_mul({re}[{i}])"))
                    .collect();
                format!("[{}]", parts.join(", "))
            }
            "==" => format!("({le} == {re})"),
            "!=" => format!("({le} != {re})"),
            _ => le,
        };
    }
    if let Some(dims) = l_ty.is_vec()
        && r_ty.is_vec() == Some(dims)
    {
        return match op {
            "+" | "-" | "*" | "/" => {
                let parts: Vec<String> = (0..dims)
                    .map(|i| format!("{le}[{i}] {op} {re}[{i}]"))
                    .collect();
                format!("[{}]", parts.join(", "))
            }
            "==" => format!("({le} == {re})"),
            "!=" => format!("({le} != {re})"),
            _ => le,
        };
    }
    if let Some(dims) = l_ty.is_vec()
        && *r_ty == GuestValTy::F32
    {
        return match op {
            "+" | "-" | "*" | "/" => {
                let parts: Vec<String> =
                    (0..dims).map(|i| format!("{le}[{i}] {op} {re}")).collect();
                format!("[{}]", parts.join(", "))
            }
            _ => le,
        };
    }
    if *l_ty == GuestValTy::F32
        && let Some(dims) = r_ty.is_vec()
    {
        return match op {
            "+" | "*" => {
                let parts: Vec<String> =
                    (0..dims).map(|i| format!("{le} {op} {re}[{i}]")).collect();
                format!("[{}]", parts.join(", "))
            }
            _ => re,
        };
    }
    if *l_ty == GuestValTy::Entity && *r_ty == GuestValTy::Entity {
        return match op {
            "==" => format!("({le} == {re})"),
            "!=" => format!("({le} != {re})"),
            _ => "false".to_owned(),
        };
    }
    if *l_ty == GuestValTy::Entity && r_ty.is_int() {
        return match op {
            "==" => format!("{le}.is_null()"),
            "!=" => format!("(!{le}.is_null())"),
            _ => "false".to_owned(),
        };
    }
    if *l_ty == GuestValTy::Bool && *r_ty == GuestValTy::Bool {
        return match op {
            "&&" | "&" => format!("({le} && {re})"),
            "||" | "|" => format!("({le} || {re})"),
            "==" => format!("({le} == {re})"),
            "!=" => format!("({le} != {re})"),
            _ => le,
        };
    }
    if *l_ty == GuestValTy::Fix64 || *r_ty == GuestValTy::Fix64 {
        let la = if *l_ty != GuestValTy::Fix64
            && let Some(&fv) = fl.const_floats.get(&lhs.0)
        {
            format_fix64_i64_lit(scale_float_fix64(fv))
        } else {
            guest_fast_coerce(&le, l_ty, &GuestValTy::Fix64, cat)
        };
        let ra = if *r_ty != GuestValTy::Fix64
            && let Some(&fv) = fl.const_floats.get(&rhs.0)
        {
            format_fix64_i64_lit(scale_float_fix64(fv))
        } else {
            guest_fast_coerce(&re, r_ty, &GuestValTy::Fix64, cat)
        };
        let res = match op {
            "+" => format!("({la}).wrapping_add({ra})"),
            "-" => format!("({la}).wrapping_sub({ra})"),
            "*" => format!("(((({la}) as i128) * (({ra}) as i128) >> 32) as i64)"),
            "/" => format!(
                "{{ let __b = {ra}; if __b != 0 {{ (((({la}) as i128) << 32) / (__b as i128)) as i64 }} else {{ 0i64 }} }}"
            ),
            "%" => format!(
                "{{ let __b = {ra}; if __b != 0 {{ ({la}).wrapping_rem(__b) }} else {{ 0i64 }} }}"
            ),
            "<" | "<=" | ">" | ">=" | "==" | "!=" => format!("({la} {op} {ra})"),
            _ => la,
        };
        return if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=") {
            res
        } else {
            guest_fast_coerce(&res, &GuestValTy::Fix64, dst_ty, cat)
        };
    }
    if *l_ty == GuestValTy::Fix32 || *r_ty == GuestValTy::Fix32 {
        let la = if *l_ty != GuestValTy::Fix32
            && let Some(&fv) = fl.const_floats.get(&lhs.0)
        {
            format_fix32_i32_lit(scale_float_fix32(fv))
        } else {
            guest_fast_coerce(&le, l_ty, &GuestValTy::Fix32, cat)
        };
        let ra = if *r_ty != GuestValTy::Fix32
            && let Some(&fv) = fl.const_floats.get(&rhs.0)
        {
            format_fix32_i32_lit(scale_float_fix32(fv))
        } else {
            guest_fast_coerce(&re, r_ty, &GuestValTy::Fix32, cat)
        };
        let res = match op {
            "+" => format!("({la}).wrapping_add({ra})"),
            "-" => format!("({la}).wrapping_sub({ra})"),
            "*" => format!("(((({la}) as i64) * (({ra}) as i64) >> 16) as i32)"),
            "/" => format!(
                "{{ let __b = {ra}; if __b != 0 {{ (((({la}) as i64) << 16) / (__b as i64)) as i32 }} else {{ 0i32 }} }}"
            ),
            "%" => format!(
                "{{ let __b = {ra}; if __b != 0 {{ ({la}).wrapping_rem(__b) }} else {{ 0i32 }} }}"
            ),
            "<" | "<=" | ">" | ">=" | "==" | "!=" => format!("({la} {op} {ra})"),
            _ => la,
        };
        return if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=") {
            res
        } else {
            guest_fast_coerce(&res, &GuestValTy::Fix32, dst_ty, cat)
        };
    }
    if *l_ty == GuestValTy::F64 || *r_ty == GuestValTy::F64 {
        let la = guest_fast_coerce(&le, l_ty, &GuestValTy::F64, cat);
        let ra = guest_fast_coerce(&re, r_ty, &GuestValTy::F64, cat);
        let res = match op {
            "+" | "-" | "*" | "/" | "%" | "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                format!("({la} {op} {ra})")
            }
            _ => la,
        };
        return if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=") {
            res
        } else {
            guest_fast_coerce(&res, &GuestValTy::F64, dst_ty, cat)
        };
    }
    if *l_ty == GuestValTy::F32 || *r_ty == GuestValTy::F32 {
        let la = guest_fast_coerce(&le, l_ty, &GuestValTy::F32, cat);
        let ra = guest_fast_coerce(&re, r_ty, &GuestValTy::F32, cat);
        let res = match op {
            "+" | "-" | "*" | "/" | "%" | "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                format!("({la} {op} {ra})")
            }
            _ => la,
        };
        return if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=") {
            res
        } else {
            guest_fast_coerce(&res, &GuestValTy::F32, dst_ty, cat)
        };
    }

    let is_nonneg_const = |id: LocalId| fl.const_ints.get(&id.0).is_some_and(|&v| v >= 0);
    let is_unsigned_small = |t: &GuestValTy| matches!(t, GuestValTy::U8 | GuestValTy::U16);
    let op_ty = if *l_ty == GuestValTy::U64 || *r_ty == GuestValTy::U64 {
        GuestValTy::U64
    } else if *l_ty == GuestValTy::I64
        || *r_ty == GuestValTy::I64
        || *l_ty == GuestValTy::Fix64
        || *r_ty == GuestValTy::Fix64
    {
        GuestValTy::I64
    } else if (*l_ty == GuestValTy::U32 && (*r_ty != GuestValTy::I32 || is_nonneg_const(rhs)))
        || (*r_ty == GuestValTy::U32 && (*l_ty != GuestValTy::I32 || is_nonneg_const(lhs)))
        || (is_unsigned_small(l_ty) && (*r_ty == *l_ty || is_nonneg_const(rhs)))
        || (is_unsigned_small(r_ty) && (*l_ty == *r_ty || is_nonneg_const(lhs)))
    {
        GuestValTy::U32
    } else {
        GuestValTy::I32
    };
    let la = guest_fast_coerce(&le, l_ty, &op_ty, cat);
    let ra = guest_fast_coerce(&re, r_ty, &op_ty, cat);
    let res = match op {
        "+" => format!("({la}).wrapping_add({ra})"),
        "-" => format!("({la}).wrapping_sub({ra})"),
        "*" => format!("({la}).wrapping_mul({ra})"),
        "/" => {
            format!("{{ let __b = {ra}; if __b != 0 {{ ({la}).wrapping_div(__b) }} else {{ 0 }} }}")
        }
        "%" => {
            format!("{{ let __b = {ra}; if __b != 0 {{ ({la}).wrapping_rem(__b) }} else {{ 0 }} }}")
        }
        "&" | "|" | "^" | "<" | "<=" | ">" | ">=" | "==" | "!=" => format!("({la} {op} {ra})"),
        "<<" => format!("({la}).wrapping_shl(({ra}) as u32)"),
        ">>" => format!("({la}).wrapping_shr(({ra}) as u32)"),
        "&&" | "||" => {
            let lb = guest_fast_coerce(&le, l_ty, &GuestValTy::Bool, cat);
            let rb = guest_fast_coerce(&re, r_ty, &GuestValTy::Bool, cat);
            format!("({lb} {op} {rb})")
        }
        _ => la,
    };
    if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=" | "&&" | "||") {
        res
    } else {
        guest_fast_coerce(&res, &op_ty, dst_ty, cat)
    }
}

pub(super) fn guest_fast_intrinsic_expr(
    name: &str,
    args: &[LocalId],
    dst_ty: &GuestValTy,
    fl: &GuestFastLoop,
    cat: &GuestCatalog,
) -> String {
    let short = name.rsplit("::").next().unwrap_or(name);
    let a = |i: usize| -> (GuestValTy, String) {
        args.get(i).map_or_else(
            || (GuestValTy::F32, "0.0_f32".to_owned()),
            |&l| {
                (
                    fl.val_tys[l.0 as usize].clone(),
                    guest_fast_local_expr(l, fl),
                )
            },
        )
    };
    let af32 = |i: usize| -> String {
        let (vt, e) = a(i);
        guest_fast_coerce(&e, &vt, &GuestValTy::F32, cat)
    };
    let af64 = |i: usize| -> String {
        let (vt, e) = a(i);
        guest_fast_coerce(&e, &vt, &GuestValTy::F64, cat)
    };
    let use_f64 = *dst_ty == GuestValTy::F64
        || args.iter().any(|l| {
            fl.val_tys
                .get(l.0 as usize)
                .is_some_and(|t| *t == GuestValTy::F64)
        });
    match short {
        "sqrt" | "floor" | "ceil" | "round" | "trunc" | "fract" | "signum" | "sign" | "sin"
        | "cos" | "tan" | "asin" | "acos" | "atan" | "exp" | "ln" | "log" | "log2" | "log10" => {
            let m = match short {
                "sign" => "signum",
                "log" => "ln",
                other => other,
            };
            if use_f64 {
                let raw = format!("({}).{m}()", af64(0));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).{m}()", af32(0));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "abs" => {
            let (vt, e) = a(0);
            if matches!(
                vt,
                GuestValTy::I8
                    | GuestValTy::I16
                    | GuestValTy::I32
                    | GuestValTy::I64
                    | GuestValTy::F32
                    | GuestValTy::F64
            ) {
                let raw = format!("({e}).abs()");
                guest_fast_coerce(&raw, &vt, dst_ty, cat)
            } else if vt.is_fixed() {
                let raw = format!("({e}).wrapping_abs()");
                guest_fast_coerce(&raw, &vt, dst_ty, cat)
            } else if use_f64 {
                let raw = format!("({}).abs()", af64(0));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).abs()", af32(0));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "atan2" => {
            if use_f64 {
                let raw = format!("({}).atan2({})", af64(0), af64(1));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).atan2({})", af32(0), af32(1));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "pow" | "powf" => {
            if use_f64 {
                let raw = format!("({}).powf({})", af64(0), af64(1));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).powf({})", af32(0), af32(1));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "min" | "max" => {
            let (vt0, e0) = a(0);
            let (vt1, e1) = a(1);
            if vt0 == GuestValTy::Vec2 && vt1 == GuestValTy::Vec2 {
                format!("[{e0}[0].{short}({e1}[0]), {e0}[1].{short}({e1}[1])]")
            } else if vt0 == GuestValTy::Vec3 && vt1 == GuestValTy::Vec3 {
                format!(
                    "[{e0}[0].{short}({e1}[0]), {e0}[1].{short}({e1}[1]), {e0}[2].{short}({e1}[2])]"
                )
            } else if vt0 == GuestValTy::Vec4 && vt1 == GuestValTy::Vec4 {
                format!(
                    "[{e0}[0].{short}({e1}[0]), {e0}[1].{short}({e1}[1]), {e0}[2].{short}({e1}[2]), {e0}[3].{short}({e1}[3])]"
                )
            } else if vt0 == vt1 && (vt0.is_int() || vt0.is_fixed()) {
                let raw = format!("({e0}).{short}({e1})");
                guest_fast_coerce(&raw, &vt0, dst_ty, cat)
            } else if use_f64 {
                let raw = format!("({}).{short}({})", af64(0), af64(1));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).{short}({})", af32(0), af32(1));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "clamp" => {
            let (vt0, e0) = a(0);
            let (vt1, e1) = a(1);
            let (vt2, e2) = a(2);
            if vt0 == vt1 && vt0 == vt2 && (vt0.is_int() || vt0.is_fixed()) {
                let raw = format!("({e0}).clamp({e1}, {e2})");
                guest_fast_coerce(&raw, &vt0, dst_ty, cat)
            } else if use_f64 {
                let raw = format!(
                    "{{ let __lo = {lo}; let __hi = {hi}; ({v}).clamp(__lo, __hi.max(__lo)) }}",
                    v = af64(0),
                    lo = af64(1),
                    hi = af64(2)
                );
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!(
                    "{{ let __lo = {lo}; let __hi = {hi}; ({v}).clamp(__lo, __hi.max(__lo)) }}",
                    v = af32(0),
                    lo = af32(1),
                    hi = af32(2)
                );
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "saturate" => {
            if use_f64 {
                let raw = format!("({}).clamp(0.0_f64, 1.0_f64)", af64(0));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).clamp(0.0_f32, 1.0_f32)", af32(0));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "lerp" | "mix" => {
            let (vt0, e0) = a(0);
            let (_, e1) = a(1);
            match vt0 {
                GuestValTy::Vec2 => {
                    let t = af32(2);
                    format!(
                        "[{e0}[0] + ({e1}[0] - {e0}[0]) * {t}, {e0}[1] + ({e1}[1] - {e0}[1]) * {t}]"
                    )
                }
                GuestValTy::Vec3 => {
                    let t = af32(2);
                    format!(
                        "[{e0}[0] + ({e1}[0] - {e0}[0]) * {t}, {e0}[1] + ({e1}[1] - {e0}[1]) * {t}, {e0}[2] + ({e1}[2] - {e0}[2]) * {t}]"
                    )
                }
                GuestValTy::Vec4 => {
                    let t = af32(2);
                    format!(
                        "[{e0}[0] + ({e1}[0] - {e0}[0]) * {t}, {e0}[1] + ({e1}[1] - {e0}[1]) * {t}, {e0}[2] + ({e1}[2] - {e0}[2]) * {t}, {e0}[3] + ({e1}[3] - {e0}[3]) * {t}]"
                    )
                }
                _ if use_f64 => {
                    let x = af64(0);
                    let y = af64(1);
                    let t = af64(2);
                    let raw = format!("({x} + ({y} - {x}) * {t})");
                    guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
                }
                _ => {
                    let x = af32(0);
                    let y = af32(1);
                    let t = af32(2);
                    let raw = format!("({x} + ({y} - {x}) * {t})");
                    guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
                }
            }
        }
        "mul_add" | "fma" => {
            if use_f64 {
                let raw = format!("({}).mul_add({}, {})", af64(0), af64(1), af64(2));
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!("({}).mul_add({}, {})", af32(0), af32(1), af32(2));
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "vec2" => {
            let x = af32(0);
            let y = if args.len() > 1 { af32(1) } else { x.clone() };
            format!("[{x}, {y}]")
        }
        "vec3" => format!("[{}, {}, {}]", af32(0), af32(1), af32(2)),
        "vec4" | "vec3a" | "Vec3a" => {
            let w = if args.len() > 3 {
                af32(3)
            } else {
                "0.0_f32".to_owned()
            };
            format!("[{}, {}, {}, {w}]", af32(0), af32(1), af32(2))
        }
        "ivec2" => {
            let x = {
                let (vt, e) = a(0);
                guest_fast_coerce(&e, &vt, &GuestValTy::I32, cat)
            };
            let y = if args.len() > 1 {
                let (vt, e) = a(1);
                guest_fast_coerce(&e, &vt, &GuestValTy::I32, cat)
            } else {
                x.clone()
            };
            format!("[{x}, {y}]")
        }
        "ivec3" => {
            let x = {
                let (vt, e) = a(0);
                guest_fast_coerce(&e, &vt, &GuestValTy::I32, cat)
            };
            let y = if args.len() > 1 {
                let (vt, e) = a(1);
                guest_fast_coerce(&e, &vt, &GuestValTy::I32, cat)
            } else {
                "0i32".to_owned()
            };
            let z = if args.len() > 2 {
                let (vt, e) = a(2);
                guest_fast_coerce(&e, &vt, &GuestValTy::I32, cat)
            } else {
                "0i32".to_owned()
            };
            format!("[{x}, {y}, {z}]")
        }
        "uvec2" => {
            let x = {
                let (vt, e) = a(0);
                guest_fast_coerce(&e, &vt, &GuestValTy::U32, cat)
            };
            let y = if args.len() > 1 {
                let (vt, e) = a(1);
                guest_fast_coerce(&e, &vt, &GuestValTy::U32, cat)
            } else {
                x.clone()
            };
            format!("[{x}, {y}]")
        }
        "dot" => {
            let (vt0, e0) = a(0);
            let (_, e1) = a(1);
            match vt0 {
                GuestValTy::Vec3 => {
                    format!("({e0}[0] * {e1}[0] + {e0}[1] * {e1}[1] + {e0}[2] * {e1}[2])")
                }
                GuestValTy::Vec4 => format!(
                    "({e0}[0] * {e1}[0] + {e0}[1] * {e1}[1] + {e0}[2] * {e1}[2] + {e0}[3] * {e1}[3])"
                ),
                _ => format!("({e0}[0] * {e1}[0] + {e0}[1] * {e1}[1])"),
            }
        }
        "cross" => {
            let (_, e0) = a(0);
            let (_, e1) = a(1);
            if *dst_ty == GuestValTy::Vec4 {
                format!(
                    "[{e0}[1] * {e1}[2] - {e0}[2] * {e1}[1], {e0}[2] * {e1}[0] - {e0}[0] * {e1}[2], {e0}[0] * {e1}[1] - {e0}[1] * {e1}[0], 0.0_f32]"
                )
            } else {
                format!(
                    "[{e0}[1] * {e1}[2] - {e0}[2] * {e1}[1], {e0}[2] * {e1}[0] - {e0}[0] * {e1}[2], {e0}[0] * {e1}[1] - {e0}[1] * {e1}[0]]"
                )
            }
        }
        "length" | "len" => {
            let (vt0, e0) = a(0);
            match vt0 {
                GuestValTy::Vec3 => {
                    format!("({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2]).sqrt()")
                }
                GuestValTy::Vec4 => format!(
                    "({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2] + {e0}[3] * {e0}[3]).sqrt()"
                ),
                _ => format!("({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1]).sqrt()"),
            }
        }
        "length_sq" | "len_sq" => {
            let (vt0, e0) = a(0);
            match vt0 {
                GuestValTy::Vec3 => {
                    format!("({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2])")
                }
                GuestValTy::Vec4 => format!(
                    "({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2] + {e0}[3] * {e0}[3])"
                ),
                _ => format!("({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1])"),
            }
        }
        "distance" | "dist" => {
            let (vt0, e0) = a(0);
            let (_, e1) = a(1);
            match vt0 {
                GuestValTy::Vec3 => format!(
                    "{{ let __dx = {e0}[0] - {e1}[0]; let __dy = {e0}[1] - {e1}[1]; let __dz = {e0}[2] - {e1}[2]; (__dx * __dx + __dy * __dy + __dz * __dz).sqrt() }}"
                ),
                GuestValTy::Vec4 => format!(
                    "{{ let __dx = {e0}[0] - {e1}[0]; let __dy = {e0}[1] - {e1}[1]; let __dz = {e0}[2] - {e1}[2]; let __dw = {e0}[3] - {e1}[3]; (__dx * __dx + __dy * __dy + __dz * __dz + __dw * __dw).sqrt() }}"
                ),
                _ => format!(
                    "{{ let __dx = {e0}[0] - {e1}[0]; let __dy = {e0}[1] - {e1}[1]; (__dx * __dx + __dy * __dy).sqrt() }}"
                ),
            }
        }
        "normalize" | "norm" => {
            let (vt0, e0) = a(0);
            match vt0 {
                GuestValTy::Vec3 => format!(
                    "{{ let __l = ({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2]).sqrt(); if __l > 1e-6_f32 {{ [{e0}[0] / __l, {e0}[1] / __l, {e0}[2] / __l] }} else {{ [0.0_f32; 3] }} }}"
                ),
                GuestValTy::Vec4 => format!(
                    "{{ let __l = ({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1] + {e0}[2] * {e0}[2] + {e0}[3] * {e0}[3]).sqrt(); if __l > 1e-6_f32 {{ [{e0}[0] / __l, {e0}[1] / __l, {e0}[2] / __l, {e0}[3] / __l] }} else {{ [0.0_f32; 4] }} }}"
                ),
                _ => format!(
                    "{{ let __l = ({e0}[0] * {e0}[0] + {e0}[1] * {e0}[1]).sqrt(); if __l > 1e-6_f32 {{ [{e0}[0] / __l, {e0}[1] / __l] }} else {{ [0.0_f32; 2] }} }}"
                ),
            }
        }
        "step" => {
            if use_f64 {
                let raw = format!(
                    "(if {} < {} {{ 0.0_f64 }} else {{ 1.0_f64 }})",
                    af64(1),
                    af64(0)
                );
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!(
                    "(if {} < {} {{ 0.0_f32 }} else {{ 1.0_f32 }})",
                    af32(1),
                    af32(0)
                );
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "smoothstep" => {
            if use_f64 {
                let raw = format!(
                    "{{ let __d = ({e1} - {e0}).max(1e-6_f64); let __t = (({x} - {e0}) / __d).clamp(0.0_f64, 1.0_f64); __t * __t * (3.0_f64 - 2.0_f64 * __t) }}",
                    e0 = af64(0),
                    e1 = af64(1),
                    x = af64(2)
                );
                guest_fast_coerce(&raw, &GuestValTy::F64, dst_ty, cat)
            } else {
                let raw = format!(
                    "{{ let __d = ({e1} - {e0}).max(1e-6_f32); let __t = (({x} - {e0}) / __d).clamp(0.0_f32, 1.0_f32); __t * __t * (3.0_f32 - 2.0_f32 * __t) }}",
                    e0 = af32(0),
                    e1 = af32(1),
                    x = af32(2)
                );
                guest_fast_coerce(&raw, &GuestValTy::F32, dst_ty, cat)
            }
        }
        "raw" | "to_bits" => {
            let (vt0, e0) = a(0);
            match vt0 {
                GuestValTy::Entity => format!("{e0}.to_bits()"),
                GuestValTy::Bool => format!("u32::from({e0})"),
                _ => guest_fast_coerce(&e0, &vt0, dst_ty, cat),
            }
        }
        "is_null" => format!("{}.is_null()", a(0).1),
        "is_valid" => format!("(!{}.is_null())", a(0).1),
        _ => af32(0),
    }
}

pub(super) fn guest_fast_field_place(
    ptr: LocalId,
    field: &str,
    offset_bytes: u32,
    fl: &GuestFastLoop,
    cat: &GuestCatalog,
) -> Option<(String, Ty)> {
    let pt = fl.ptr_targets.get(&ptr)?;
    match pt {
        GuestPtrTarget::QueryRow {
            query_idx,
            phys_col,
            comp_id,
            optional,
            projected,
            ..
        } => {
            let col_var = if *optional {
                format!("__q{query_idx}_col_{phys_col}.as_ref().unwrap()")
            } else {
                format!("__q{query_idx}_col_{phys_col}")
            };
            if field.is_empty()
                && offset_bytes == 0
                && let Some((fnm, _, sema_ty)) = projected
            {
                let rfield = sanitize_rust_ident(fnm);
                return Some((format!("{col_var}[__row].{rfield}"), sema_ty.clone()));
            }
            let sf = resolve_guest_field(cat, *comp_id, field, offset_bytes)?;
            let rfield = sanitize_rust_ident(&sf.name);
            Some((format!("{col_var}[__row].{rfield}"), sf.ty.clone()))
        }
        GuestPtrTarget::Resource { comp_id, .. } => {
            let sf = resolve_guest_field(cat, *comp_id, field, offset_bytes)?;
            let rfield = sanitize_rust_ident(&sf.name);
            Some((format!("__res_{comp_id}.{rfield}"), sf.ty.clone()))
        }
        GuestPtrTarget::Field { base, field: bf } => {
            let fname = if field.is_empty() { bf.as_str() } else { field };
            match &**base {
                GuestPtrTarget::QueryRow {
                    query_idx,
                    phys_col,
                    comp_id,
                    optional,
                    ..
                } => {
                    let col_var = if *optional {
                        format!("__q{query_idx}_col_{phys_col}.as_ref().unwrap()")
                    } else {
                        format!("__q{query_idx}_col_{phys_col}")
                    };
                    let sf = resolve_guest_field(cat, *comp_id, fname, offset_bytes)?;
                    let rfield = sanitize_rust_ident(&sf.name);
                    Some((format!("{col_var}[__row].{rfield}"), sf.ty.clone()))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub(super) fn guest_fast_field_mut_place(
    ptr: LocalId,
    field: &str,
    offset_bytes: u32,
    fl: &GuestFastLoop,
    cat: &GuestCatalog,
) -> Option<(String, Ty, bool)> {
    let pt = fl.ptr_targets.get(&ptr)?;
    match pt {
        GuestPtrTarget::QueryRow {
            query_idx,
            phys_col,
            comp_id,
            selective,
            optional,
            projected,
            ..
        } => {
            let col_var = if *optional {
                format!("__q{query_idx}_col_{phys_col}.as_deref_mut().unwrap()")
            } else {
                format!("__q{query_idx}_col_{phys_col}")
            };
            if field.is_empty()
                && offset_bytes == 0
                && let Some((fnm, _, sema_ty)) = projected
            {
                let rfield = sanitize_rust_ident(fnm);
                return Some((
                    format!("{col_var}[__row].{rfield}"),
                    sema_ty.clone(),
                    *selective,
                ));
            }
            let sf = resolve_guest_field(cat, *comp_id, field, offset_bytes)?;
            let rfield = sanitize_rust_ident(&sf.name);
            Some((
                format!("{col_var}[__row].{rfield}"),
                sf.ty.clone(),
                *selective,
            ))
        }
        GuestPtrTarget::Field { base, field: bf } => {
            let fname = if field.is_empty() { bf.as_str() } else { field };
            match &**base {
                GuestPtrTarget::QueryRow {
                    query_idx,
                    phys_col,
                    comp_id,
                    selective,
                    optional,
                    ..
                } => {
                    let col_var = if *optional {
                        format!("__q{query_idx}_col_{phys_col}.as_deref_mut().unwrap()")
                    } else {
                        format!("__q{query_idx}_col_{phys_col}")
                    };
                    let sf = resolve_guest_field(cat, *comp_id, fname, offset_bytes)?;
                    let rfield = sanitize_rust_ident(&sf.name);
                    Some((
                        format!("{col_var}[__row].{rfield}"),
                        sf.ty.clone(),
                        *selective,
                    ))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub(super) fn emit_guest_fast_stmt(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    fl: &GuestFastLoop,
    st: &strata_mir::MirStmt,
    indent: &str,
) {
    match &st.inst {
        Inst::ConstInt { value } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                if *dt == GuestValTy::Unit
                    || *dt == GuestValTy::PtrMarker
                    || fl.row_idx_locals.contains(&d)
                {
                    return;
                }
                let expr = match dt {
                    GuestValTy::Entity => {
                        if *value == 0 {
                            "FfiEntity::NULL".to_owned()
                        } else {
                            format!("FfiEntity::from_bits(({value}i64) as u64)")
                        }
                    }
                    GuestValTy::F32 => format!("{}f32", *value as f32),
                    GuestValTy::F64 => format!("{}f64", *value as f64),
                    GuestValTy::Fix32 => format_fix32_i32_lit(scale_int_fix32(*value)),
                    GuestValTy::Fix64 => format_fix64_i64_lit(scale_int_fix64(*value)),
                    GuestValTy::Bool => format!("({value} != 0)"),
                    _ => format!("({value}i64 as {})", dt.rust_type(cat)),
                };
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::ConstFloat { value } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                let expr = match dt {
                    GuestValTy::F64 => fmt_f64(*value),
                    GuestValTy::Fix32 => format_fix32_i32_lit(scale_float_fix32(*value)),
                    GuestValTy::Fix64 => format_fix64_i64_lit(scale_float_fix64(*value)),
                    _ => fmt_f32(*value as f32),
                };
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::ConstBool { value } => {
            if let Some(d) = st.dst
                && fl.val_tys[d.0 as usize] != GuestValTy::Unit
            {
                writeln!(out, "{indent}__loc_{} = {value};", d.0).ok();
            }
        }
        Inst::ConstVec { dims, values } => {
            if let Some(d) = st.dst {
                let expr = match &fl.val_tys[d.0 as usize] {
                    GuestValTy::IVec2 => {
                        format!("[{}i32, {}i32]", values[0] as i32, values[1] as i32)
                    }
                    GuestValTy::IVec3 => format!(
                        "[{}i32, {}i32, {}i32]",
                        values[0] as i32, values[1] as i32, values[2] as i32
                    ),
                    GuestValTy::UVec2 => {
                        format!("[{}u32, {}u32]", values[0] as u32, values[1] as u32)
                    }
                    _ => match dims {
                        2 => format!(
                            "[{}, {}]",
                            fmt_f32(values[0] as f32),
                            fmt_f32(values[1] as f32)
                        ),
                        3 => format!(
                            "[{}, {}, {}]",
                            fmt_f32(values[0] as f32),
                            fmt_f32(values[1] as f32),
                            fmt_f32(values[2] as f32)
                        ),
                        _ => format!(
                            "[{}, {}, {}, {}]",
                            fmt_f32(values[0] as f32),
                            fmt_f32(values[1] as f32),
                            fmt_f32(values[2] as f32),
                            fmt_f32(values[3] as f32)
                        ),
                    },
                };
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::Copy { val } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                if *dt != GuestValTy::Unit && *dt != GuestValTy::PtrMarker {
                    let ve = guest_fast_local_expr(*val, fl);
                    let c = guest_fast_coerce(&ve, &fl.val_tys[val.0 as usize], dt, cat);
                    writeln!(out, "{indent}__loc_{} = {c};", d.0).ok();
                }
            }
        }
        Inst::SlotLoad { slot } => {
            if *slot == fl.row_idx_slot {
                return;
            }
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                if *dt != GuestValTy::Unit && *dt != GuestValTy::PtrMarker {
                    let se = guest_fast_slot_expr(*slot, fl);
                    let st_ty = fl.slot_tys.get(slot).unwrap_or(dt);
                    let c = guest_fast_coerce(&se, st_ty, dt, cat);
                    writeln!(out, "{indent}__loc_{} = {c};", d.0).ok();
                }
            }
        }
        Inst::SlotStore { slot, val } => {
            if *slot == fl.row_idx_slot {
                return;
            }
            let vt = &fl.val_tys[val.0 as usize];
            if *vt == GuestValTy::Unit || *vt == GuestValTy::PtrMarker {
                return;
            }
            let se = guest_fast_slot_expr(*slot, fl);
            let ve = guest_fast_local_expr(*val, fl);
            let st_ty = fl.slot_tys.get(slot).unwrap_or(vt);
            let c = if *st_ty == GuestValTy::Fix64
                && *vt != GuestValTy::Fix64
                && let Some(&fv) = fl.const_floats.get(&val.0)
            {
                format_fix64_i64_lit(scale_float_fix64(fv))
            } else if *st_ty == GuestValTy::Fix32
                && *vt != GuestValTy::Fix32
                && let Some(&fv) = fl.const_floats.get(&val.0)
            {
                format_fix32_i32_lit(scale_float_fix32(fv))
            } else {
                guest_fast_coerce(&ve, vt, st_ty, cat)
            };
            writeln!(out, "{indent}{se} = {c};").ok();
        }
        Inst::BinOp { op, lhs, rhs, .. } => {
            if let Some(d) = st.dst {
                let expr = guest_fast_binop(op, *lhs, *rhs, &fl.val_tys[d.0 as usize], fl, cat);
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::UnOp { op, val } => {
            if let Some(d) = st.dst {
                let vt = &fl.val_tys[val.0 as usize];
                let v = guest_fast_local_expr(*val, fl);
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
                            _ if vt.is_int() || vt.is_fixed() => format!("({v}).wrapping_neg()"),
                            _ => format!("(-{v})"),
                        },
                    },
                    "!" | "~" => format!("(!{v})"),
                    _ => v,
                };
                let c = guest_fast_coerce(&expr, vt, &fl.val_tys[d.0 as usize], cat);
                writeln!(out, "{indent}__loc_{} = {c};", d.0).ok();
            }
        }
        Inst::Cast { val, target_ty } => {
            if let Some(d) = st.dst {
                let from_vt = &fl.val_tys[val.0 as usize];
                let ve = guest_fast_local_expr(*val, fl);
                let to_vt =
                    GuestValTy::from_mir(target_ty, mir, cat).unwrap_or_else(|| from_vt.clone());
                let mid = if to_vt == GuestValTy::Fix64
                    && *from_vt != GuestValTy::Fix64
                    && let Some(&fv) = fl.const_floats.get(&val.0)
                {
                    format_fix64_i64_lit(scale_float_fix64(fv))
                } else if to_vt == GuestValTy::Fix32
                    && *from_vt != GuestValTy::Fix32
                    && let Some(&fv) = fl.const_floats.get(&val.0)
                {
                    format_fix32_i32_lit(scale_float_fix32(fv))
                } else {
                    guest_fast_coerce(&ve, from_vt, &to_vt, cat)
                };
                let fin = guest_fast_coerce(&mid, &to_vt, &fl.val_tys[d.0 as usize], cat);
                writeln!(out, "{indent}__loc_{} = {fin};", d.0).ok();
            }
        }
        Inst::VecExtract { vec, lane } => {
            if let Some(d) = st.dst {
                let ve = guest_fast_local_expr(*vec, fl);
                writeln!(out, "{indent}__loc_{} = {ve}[{lane}];", d.0).ok();
            }
        }
        Inst::VecInsert { vec, lane, val } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                let v_vt = &fl.val_tys[vec.0 as usize];
                let ve = guest_fast_local_expr(*vec, fl);
                let val_vt = &fl.val_tys[val.0 as usize];
                let vle = guest_fast_local_expr(*val, fl);
                let lane_vt = match dt {
                    GuestValTy::IVec2 | GuestValTy::IVec3 => GuestValTy::I32,
                    GuestValTy::UVec2 => GuestValTy::U32,
                    _ => GuestValTy::F32,
                };
                let sc = guest_fast_coerce(&vle, val_vt, &lane_vt, cat);
                let base_v = guest_fast_coerce(&ve, v_vt, dt, cat);
                writeln!(
                    out,
                    "{indent}{{ let mut __tv: {} = {base_v}; __tv[{lane}] = {sc}; __loc_{} = __tv; }}",
                    dt.rust_type(cat),
                    d.0
                )
                .ok();
            }
        }
        Inst::VecSwizzle { vec, lanes } => {
            if let Some(d) = st.dst {
                let ve = guest_fast_local_expr(*vec, fl);
                if lanes.len() == 1 {
                    writeln!(out, "{indent}__loc_{} = {ve}[{}];", d.0, lanes[0]).ok();
                } else {
                    let elems: Vec<String> = lanes.iter().map(|l| format!("{ve}[{l}]")).collect();
                    writeln!(out, "{indent}__loc_{} = [{}];", d.0, elems.join(", ")).ok();
                }
            }
        }
        Inst::IntrinsicMath { name, args, .. } => {
            if let Some(d) = st.dst {
                let expr =
                    guest_fast_intrinsic_expr(name, args, &fl.val_tys[d.0 as usize], fl, cat);
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::EntityAtRow { .. } => {
            if fl.needs_entity
                && let Some(d) = st.dst
            {
                writeln!(
                    out,
                    "{indent}__loc_{} = __q{}_entities[__row];",
                    d.0, fl.query_idx
                )
                .ok();
            }
        }
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
            if let Some(d) = st.dst
                && let Some(GuestPtrTarget::QueryCol {
                    query_idx,
                    phys_col,
                    ..
                }) = fl.ptr_targets.get(slice_ptr)
            {
                writeln!(
                    out,
                    "{indent}__loc_{} = __q{query_idx}_col_{phys_col}.is_some();",
                    d.0
                )
                .ok();
            }
        }
        Inst::FieldLoad {
            base_ptr,
            field,
            offset_bytes,
            ..
        } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                if let Some((place, sema_ty)) =
                    guest_fast_field_place(*base_ptr, field, *offset_bytes, fl, cat)
                {
                    let loaded = match sema_ty {
                        Ty::Bool => format!("{place}.get()"),
                        _ => {
                            let fvt = GuestValTy::from_sema_ty(&sema_ty, mir, cat)
                                .unwrap_or_else(|| dt.clone());
                            guest_fast_coerce(&place, &fvt, dt, cat)
                        }
                    };
                    writeln!(out, "{indent}__loc_{} = {loaded};", d.0).ok();
                } else if let GuestValTy::TableRow(_) = &fl.val_tys[base_ptr.0 as usize] {
                    let be = guest_fast_local_expr(*base_ptr, fl);
                    let rf = sanitize_rust_ident(field);
                    writeln!(out, "{indent}__loc_{} = {be}.{rf};", d.0).ok();
                }
            }
        }
        Inst::FieldStore {
            base_ptr,
            field,
            offset_bytes,
            val,
            ..
        } => {
            if let Some((place, sema_ty, is_sel)) =
                guest_fast_field_mut_place(*base_ptr, field, *offset_bytes, fl, cat)
            {
                let v_vt = &fl.val_tys[val.0 as usize];
                let ve = guest_fast_local_expr(*val, fl);
                let rhs = match sema_ty {
                    Ty::Bool => format!(
                        "FfiBool::from_bool({})",
                        guest_fast_coerce(&ve, v_vt, &GuestValTy::Bool, cat)
                    ),
                    _ => {
                        let dst_vt = GuestValTy::from_sema_ty(&sema_ty, mir, cat)
                            .unwrap_or_else(|| v_vt.clone());
                        if dst_vt == GuestValTy::Fix64
                            && *v_vt != GuestValTy::Fix64
                            && let Some(&fv) = fl.const_floats.get(&val.0)
                        {
                            format_fix64_i64_lit(scale_float_fix64(fv))
                        } else if dst_vt == GuestValTy::Fix32
                            && *v_vt != GuestValTy::Fix32
                            && let Some(&fv) = fl.const_floats.get(&val.0)
                        {
                            format_fix32_i32_lit(scale_float_fix32(fv))
                        } else if dst_vt == GuestValTy::F64
                            && *v_vt != GuestValTy::F64
                            && let Some(&fv) = fl.const_floats.get(&val.0)
                        {
                            fmt_f64(fv)
                        } else {
                            guest_fast_coerce(&ve, v_vt, &dst_vt, cat)
                        }
                    }
                };
                writeln!(out, "{indent}{place} = {rhs};").ok();
                if is_sel && !fl.has_dirty_record_row {
                    writeln!(
                        out,
                        "{indent}let __dr = __row as u32;\n\
                         {indent}if __dlen == 0 {{ __dstart = __dr; __dlen = 1; }}\n\
                         {indent}else if __dstart + __dlen == __dr {{ __dlen += 1; }}\n\
                         {indent}else if __dr + 1 != __dstart + __dlen {{ if __n_runs < 16 {{ __runs[__n_runs] = (__dstart, __dlen); __n_runs += 1; }} else {{ __ovf.push((__dstart, __dlen)); }} __dstart = __dr; __dlen = 1; }}"
                    )
                    .ok();
                }
            }
        }
        Inst::DirtyRunRecordRow { .. } => {
            if fl.selective_col.is_some() {
                writeln!(
                    out,
                    "{indent}let __dr = __row as u32;\n\
                     {indent}if __dlen == 0 {{ __dstart = __dr; __dlen = 1; }}\n\
                     {indent}else if __dstart + __dlen == __dr {{ __dlen += 1; }}\n\
                     {indent}else if __dr + 1 != __dstart + __dlen {{ if __n_runs < 16 {{ __runs[__n_runs] = (__dstart, __dlen); __n_runs += 1; }} else {{ __ovf.push((__dstart, __dlen)); }} __dstart = __dr; __dlen = 1; }}"
                )
                .ok();
            }
        }
        Inst::GraceArm { ptr, duration_sec } => {
            if let Some((place, _, _)) = guest_fast_field_mut_place(*ptr, "", 0, fl, cat) {
                let de = guest_fast_local_expr(*duration_sec, fl);
                writeln!(out, "{indent}{place} = {de};").ok();
            }
        }
        Inst::GraceTick { ptr, dt_sec } => {
            if let Some((place, _, _)) = guest_fast_field_mut_place(*ptr, "", 0, fl, cat) {
                let de = guest_fast_local_expr(*dt_sec, fl);
                writeln!(out, "{indent}{place} = ({place} - {de}).max(0.0_f32);").ok();
            }
        }
        Inst::GraceIsActive { ptr } => {
            if let Some(d) = st.dst
                && let Some((place, _)) = guest_fast_field_place(*ptr, "", 0, fl, cat)
            {
                writeln!(out, "{indent}__loc_{} = {place} > 0.0_f32;", d.0).ok();
            }
        }
        Inst::GraceClear { ptr } => {
            if let Some((place, _, _)) = guest_fast_field_mut_place(*ptr, "", 0, fl, cat) {
                writeln!(out, "{indent}{place} = 0.0_f32;").ok();
            }
        }
        Inst::BitSetSet { ptr, bit, .. } => {
            if let Some((place, _, _)) = guest_fast_field_mut_place(*ptr, "", 0, fl, cat) {
                let be = guest_fast_local_expr(*bit, fl);
                writeln!(
                    out,
                    "{indent}{{ let __b = {be} as usize; if __b / 32 < {place}.len() {{ {place}[__b / 32] |= 1u32 << (__b % 32); }} }}"
                )
                .ok();
            }
        }
        Inst::BitSetClear { ptr, bit, .. } => {
            if let Some((place, _, _)) = guest_fast_field_mut_place(*ptr, "", 0, fl, cat) {
                let be = guest_fast_local_expr(*bit, fl);
                writeln!(
                    out,
                    "{indent}{{ let __b = {be} as usize; if __b / 32 < {place}.len() {{ {place}[__b / 32] &= !(1u32 << (__b % 32)); }} }}"
                )
                .ok();
            }
        }
        Inst::BitSetGet { ptr, bit, .. } => {
            if let Some(d) = st.dst
                && let Some((place, _)) = guest_fast_field_place(*ptr, "", 0, fl, cat)
            {
                let be = guest_fast_local_expr(*bit, fl);
                writeln!(
                    out,
                    "{indent}__loc_{} = {{ let __b = {be} as usize; if __b / 32 < {place}.len() {{ ({place}[__b / 32] & (1u32 << (__b % 32))) != 0 }} else {{ false }} }};",
                    d.0
                )
                .ok();
            }
        }
        Inst::TableLoad {
            table_name,
            key,
            field,
        } => {
            if let Some(d) = st.dst
                && let Some(te) = cat.resolve_table(table_name)
            {
                let ke = guest_fast_local_expr(*key, fl);
                if field.is_empty() {
                    writeln!(
                        out,
                        "{indent}__loc_{} = {}({ke} as i64);",
                        d.0, te.lookup_fn
                    )
                    .ok();
                } else {
                    let rf = sanitize_rust_ident(field);
                    writeln!(
                        out,
                        "{indent}__loc_{} = {}({ke} as i64).{rf};",
                        d.0, te.lookup_fn
                    )
                    .ok();
                }
            }
        }
        Inst::CurveSample { curve_name, x } => {
            if let Some(d) = st.dst {
                let xe = guest_fast_local_expr(*x, fl);
                let ident = sanitize_ident(curve_name);
                let cast = if fl.val_tys[d.0 as usize] == GuestValTy::F64 {
                    ""
                } else {
                    " as f32"
                };
                writeln!(
                    out,
                    "{indent}__loc_{} = strata_curve_sample_{ident}({xe} as f64){cast};",
                    d.0
                )
                .ok();
            }
        }
        Inst::ReduceAccum { acc, op, val } => {
            if let Some(d) = st.dst {
                let dt = &fl.val_tys[d.0 as usize];
                let ae = guest_fast_local_expr(*acc, fl);
                let ve = guest_fast_local_expr(*val, fl);
                let comb = guest_reduce_combine(op, dt, &ae, &ve, cat);
                writeln!(out, "{indent}__loc_{} = {comb};", d.0).ok();
            }
        }
        _ => {}
    }
}

pub(super) fn find_structured_dag_merge(
    func: &MirFunction,
    a: BlockId,
    b: BlockId,
    stop: Option<BlockId>,
    fl: &GuestFastLoop,
) -> Option<BlockId> {
    let reach = |start: BlockId| -> HashSet<BlockId> {
        let mut vis = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(start);
        while let Some(cur) = q.pop_front() {
            if Some(cur) == stop
                || cur == fl.row_hdr_bb
                || cur == fl.row_exit_bb
                || cur == fl.hdr_bb
                || cur == fl.exit_bb
                || fl.row_inc_blocks.contains(&cur)
                || !vis.insert(cur)
            {
                continue;
            }
            for s in guest_term_succs(&func.blocks[cur.0 as usize].terminator) {
                q.push_back(s);
            }
        }
        vis
    };
    let ra = reach(a);
    let rb = reach(b);
    if ra.contains(&b) {
        return Some(b);
    }
    if rb.contains(&a) {
        return Some(a);
    }
    let mut cur = a;
    let mut seen = HashSet::new();
    while seen.insert(cur) {
        if rb.contains(&cur) {
            return Some(cur);
        }
        if Some(cur) == stop
            || cur == fl.row_hdr_bb
            || cur == fl.row_exit_bb
            || cur == fl.hdr_bb
            || cur == fl.exit_bb
            || fl.row_inc_blocks.contains(&cur)
        {
            break;
        }
        cur = match func.blocks[cur.0 as usize].terminator {
            Terminator::Goto(t) => t,
            Terminator::Branch { then_bb, .. } => then_bb,
            _ => break,
        };
    }
    None
}

pub(super) fn is_row_body_acyclic_dag(func: &MirFunction, fl: &GuestFastLoop) -> bool {
    let mut state: HashMap<BlockId, u8> = HashMap::new();
    fn dfs(
        bid: BlockId,
        func: &MirFunction,
        fl: &GuestFastLoop,
        state: &mut HashMap<BlockId, u8>,
    ) -> bool {
        if bid == fl.row_hdr_bb
            || bid == fl.row_exit_bb
            || bid == fl.hdr_bb
            || bid == fl.exit_bb
            || fl.row_inc_blocks.contains(&bid)
        {
            return true;
        }
        if let Some(&st) = state.get(&bid) {
            return st == 2;
        }
        if matches!(
            func.blocks[bid.0 as usize].terminator,
            Terminator::Switch { .. } | Terminator::Return(_)
        ) {
            return false;
        }
        state.insert(bid, 1);
        for succ in guest_term_succs(&func.blocks[bid.0 as usize].terminator) {
            if !dfs(succ, func, fl, state) {
                return false;
            }
        }
        state.insert(bid, 2);
        true
    }
    dfs(fl.row_body_bb, func, fl, &mut state)
}

pub(super) fn emit_structured_row_dag(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    fl: &GuestFastLoop,
    bid: BlockId,
    stop: Option<BlockId>,
    indent: &str,
) -> bool {
    if Some(bid) == stop {
        return true;
    }
    if bid == fl.row_hdr_bb || fl.row_inc_blocks.contains(&bid) {
        if stop.is_some() {
            writeln!(out, "{indent}continue;").ok();
        }
        return true;
    }
    if bid == fl.exit_bb {
        writeln!(out, "{indent}__broke_loop = true;").ok();
        writeln!(out, "{indent}break;").ok();
        return true;
    }
    if bid == fl.row_exit_bb || bid == fl.hdr_bb {
        writeln!(out, "{indent}break;").ok();
        return true;
    }
    let bb = &func.blocks[bid.0 as usize];
    for st in &bb.stmts {
        emit_guest_fast_stmt(out, mir, cat, fl, st, indent);
    }
    match &bb.terminator {
        Terminator::Goto(t) => emit_structured_row_dag(out, mir, cat, func, fl, *t, stop, indent),
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            let merge = find_structured_dag_merge(func, *then_bb, *else_bb, stop, fl);
            let ce = guest_fast_local_expr(*cond, fl);
            if let Some(m) = merge {
                if *then_bb == m {
                    writeln!(out, "{indent}if !({ce}) {{").ok();
                    let sub_indent = format!("{indent}    ");
                    if !emit_structured_row_dag(
                        out,
                        mir,
                        cat,
                        func,
                        fl,
                        *else_bb,
                        Some(m),
                        &sub_indent,
                    ) {
                        return false;
                    }
                    writeln!(out, "{indent}}}").ok();
                } else if *else_bb == m {
                    writeln!(out, "{indent}if {ce} {{").ok();
                    let sub_indent = format!("{indent}    ");
                    if !emit_structured_row_dag(
                        out,
                        mir,
                        cat,
                        func,
                        fl,
                        *then_bb,
                        Some(m),
                        &sub_indent,
                    ) {
                        return false;
                    }
                    writeln!(out, "{indent}}}").ok();
                } else {
                    writeln!(out, "{indent}if {ce} {{").ok();
                    let sub_indent = format!("{indent}    ");
                    if !emit_structured_row_dag(
                        out,
                        mir,
                        cat,
                        func,
                        fl,
                        *then_bb,
                        Some(m),
                        &sub_indent,
                    ) {
                        return false;
                    }
                    writeln!(out, "{indent}}} else {{").ok();
                    if !emit_structured_row_dag(
                        out,
                        mir,
                        cat,
                        func,
                        fl,
                        *else_bb,
                        Some(m),
                        &sub_indent,
                    ) {
                        return false;
                    }
                    writeln!(out, "{indent}}}").ok();
                }
                emit_structured_row_dag(out, mir, cat, func, fl, m, stop, indent)
            } else {
                writeln!(out, "{indent}if {ce} {{").ok();
                let sub_indent = format!("{indent}    ");
                if !emit_structured_row_dag(out, mir, cat, func, fl, *then_bb, stop, &sub_indent) {
                    return false;
                }
                writeln!(out, "{indent}}} else {{").ok();
                if !emit_structured_row_dag(out, mir, cat, func, fl, *else_bb, stop, &sub_indent) {
                    return false;
                }
                writeln!(out, "{indent}}}").ok();
                true
            }
        }
        _ => false,
    }
}

pub(super) fn emit_guest_fast_row_loop(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    fl: &GuestFastLoop,
    indent: &str,
) {
    for &sl in &fl.inner_slots {
        if let Some(vt) = fl.slot_tys.get(&sl) {
            writeln!(
                out,
                "{indent}let mut __slot_{}: {} = {};",
                sl.0,
                vt.rust_type(cat),
                vt.default_expr()
            )
            .ok();
        }
    }
    for &ll in &fl.inner_locals {
        let vt = &fl.val_tys[ll.0 as usize];
        writeln!(
            out,
            "{indent}let mut __loc_{}: {} = {};",
            ll.0,
            vt.rust_type(cat),
            vt.default_expr()
        )
        .ok();
    }

    writeln!(out, "{indent}for __row in 0..__len {{").ok();
    let body_indent = format!("{indent}    ");

    let mut dag_buf = String::new();
    let used_dag = is_row_body_acyclic_dag(func, fl)
        && emit_structured_row_dag(
            &mut dag_buf,
            mir,
            cat,
            func,
            fl,
            fl.row_body_bb,
            None,
            &body_indent,
        );
    if used_dag {
        out.push_str(&dag_buf);
    } else {
        writeln!(
            out,
            "{body_indent}let mut __rbb: u32 = {};",
            fl.row_body_bb.0
        )
        .ok();
        writeln!(out, "{body_indent}loop {{").ok();
        writeln!(out, "{body_indent}    match __rbb {{").ok();
        let mut rblocks: Vec<BlockId> = fl.row_body_blocks.iter().copied().collect();
        rblocks.sort_by_key(|b| b.0);
        let stmt_indent = format!("{body_indent}            ");
        for bid in rblocks {
            writeln!(out, "{body_indent}        {} => {{", bid.0).ok();
            let bb = &func.blocks[bid.0 as usize];
            for st in &bb.stmts {
                emit_guest_fast_stmt(out, mir, cat, fl, st, &stmt_indent);
            }
            let emit_edge = |out: &mut String, target: BlockId, eind: &str| {
                if target == fl.row_hdr_bb || fl.row_inc_blocks.contains(&target) {
                    writeln!(out, "{eind}break;").ok();
                } else if target == fl.exit_bb || target == fl.row_exit_bb || target == fl.hdr_bb {
                    writeln!(out, "{eind}__broke_loop = true; break;").ok();
                } else {
                    writeln!(out, "{eind}__rbb = {};", target.0).ok();
                }
            };
            match &bb.terminator {
                Terminator::Goto(t) => emit_edge(out, *t, &stmt_indent),
                Terminator::Branch {
                    cond,
                    then_bb,
                    else_bb,
                } => {
                    let ce = guest_fast_local_expr(*cond, fl);
                    writeln!(out, "{stmt_indent}if {ce} {{").ok();
                    emit_edge(out, *then_bb, &format!("{stmt_indent}    "));
                    writeln!(out, "{stmt_indent}}} else {{").ok();
                    emit_edge(out, *else_bb, &format!("{stmt_indent}    "));
                    writeln!(out, "{stmt_indent}}}").ok();
                }
                Terminator::Switch {
                    scrutinee,
                    cases,
                    default_bb,
                } => {
                    let se = guest_fast_local_expr(*scrutinee, fl);
                    writeln!(out, "{stmt_indent}match {se} as u32 {{").ok();
                    for (cv, tb) in cases {
                        writeln!(out, "{stmt_indent}    {cv} => {{").ok();
                        emit_edge(out, *tb, &format!("{stmt_indent}        "));
                        writeln!(out, "{stmt_indent}    }}").ok();
                    }
                    writeln!(out, "{stmt_indent}    _ => {{").ok();
                    emit_edge(out, *default_bb, &format!("{stmt_indent}        "));
                    writeln!(out, "{stmt_indent}    }}").ok();
                    writeln!(out, "{stmt_indent}}}").ok();
                }
                Terminator::Return(_) => {
                    writeln!(out, "{stmt_indent}break;").ok();
                }
            }
            writeln!(out, "{body_indent}        }}").ok();
        }
        writeln!(out, "{body_indent}        _ => break,").ok();
        writeln!(out, "{body_indent}    }}").ok();
        writeln!(out, "{body_indent}}}").ok();
        if fl.has_break {
            writeln!(out, "{body_indent}if __broke_loop {{ break; }}").ok();
        }
    }
    writeln!(out, "{indent}}}").ok();
}

pub(super) fn emit_guest_fast_loop(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    query_remap: &[usize],
    fl: &GuestFastLoop,
) {
    let qi = fl.query_idx;
    let eqi = remap_qi(query_remap, qi as usize);
    let pq = &phys_queries[qi as usize];
    let ind = "                    ";

    writeln!(
        out,
        "                if let HostBridge::System(sys_ctx) = bridge {{"
    )
    .ok();

    // 1. Unbox outer locals, outer slots, and snapshot read-only resources BEFORE borrowing `sys_ctx`.
    for &lid in &fl.live_in_locals {
        let vt = &fl.val_tys[lid as usize];
        let ext = vt
            .extract_from_strata_val(&format!("locals[{lid}]"), cat)
            .unwrap_or_else(|| vt.default_expr());
        writeln!(out, "{ind}let __u_{lid}: {} = {ext};", vt.rust_type(cat)).ok();
    }
    for &sid in &fl.live_in_slots {
        let vt = &fl.slot_tys[&LocalId(sid)];
        let ext = vt
            .extract_from_strata_val(&format!("slots[{sid}]"), cat)
            .unwrap_or_else(|| vt.default_expr());
        writeln!(
            out,
            "{ind}let __uslot_{sid}: {} = {ext};",
            vt.rust_type(cat)
        )
        .ok();
    }
    for &sid in &fl.outer_slot_writes {
        let vt = &fl.slot_tys[&LocalId(sid)];
        let ext = vt
            .extract_from_strata_val(&format!("slots[{sid}]"), cat)
            .unwrap_or_else(|| vt.default_expr());
        writeln!(
            out,
            "{ind}let mut __oslot_{sid}: {} = {ext};",
            vt.rust_type(cat)
        )
        .ok();
    }
    for &cid in &fl.read_res_comp_ids {
        let rc = &cat.components[cid];
        let sname = &rc.struct_name;
        let hf = &rc.handle_field;
        writeln!(
            out,
            "{ind}let __res_{cid}: {sname} = if handles.is_host_res_{cid} {{\n\
             {ind}    sys_ctx.res_by_handle::<{sname}>(handles.{hf}).map_or_else({sname}::default, |r| *r)\n\
             {ind}}} else {{\n\
             {ind}    world.lock().map_or_else(|_| {sname}::default(), |w| w.mod_res_{cid})\n\
             {ind}}};"
        )
        .ok();
    }

    if !fl.reduce_info.is_empty() {
        if fl.use_par {
            let init_exprs: Vec<String> = fl
                .reduce_info
                .iter()
                .map(|(sl, _, vt)| {
                    vt.extract_from_strata_val(&format!("slots[{}]", sl.0), cat)
                        .unwrap_or_else(|| vt.default_expr())
                })
                .collect();
            writeln!(
                out,
                "{ind}let __par_red = Arc::new(Mutex::new(({},)));",
                init_exprs.join(", ")
            )
            .ok();
        } else {
            for (sl, _, vt) in &fl.reduce_info {
                let ext = vt
                    .extract_from_strata_val(&format!("slots[{}]", sl.0), cat)
                    .unwrap_or_else(|| vt.default_expr());
                writeln!(
                    out,
                    "{ind}let mut __oslot_{}: {} = {ext};",
                    sl.0,
                    vt.rust_type(cat)
                )
                .ok();
            }
        }
    }

    // 2. Dispatch Path B (`SelectiveWrite`) or Path A (`TypedChunkIter` / `par_chunks_readonly`).
    if let Some(sel_col) = fl.selective_col {
        let sel_sname = &cat.components[pq.terms[sel_col].comp_id].struct_name;
        let other_cols: Vec<(usize, &PhysicalQueryTerm)> = pq
            .terms
            .iter()
            .enumerate()
            .filter(|(i, t)| {
                *i != sel_col && matches!(t.mode, TermAccessMode::Read | TermAccessMode::Write)
            })
            .collect();

        let emit_sel_chunk = |out: &mut String, cind: &str, err_stmt: &str| {
            writeln!(out, "{cind}let __len = __chunk.len();").ok();
            writeln!(out, "{cind}if __len > 0 {{").ok();
            let c2 = format!("{cind}    ");
            if other_cols.is_empty() {
                writeln!(
                    out,
                    "{c2}let mut __dstart: u32 = 0;\n\
                     {c2}let mut __dlen: u32 = 0;\n\
                     {c2}let mut __runs = [(0u32, 0u32); 16];\n\
                     {c2}let mut __n_runs: usize = 0;\n\
                     {c2}let mut __ovf: Vec<(u32, u32)> = Vec::new();\n\
                     {c2}let mut __sm = __chunk.mutable_slice_untracked({sel_col});\n\
                     {c2}let Some(__col_raw) = __sm.as_component_slice_mut::<{sel_sname}>() else {{ {err_stmt} }};\n\
                     {c2}let __q{qi}_col_{sel_col} = &mut __col_raw[..__len];"
                )
                .ok();
                if fl.has_break {
                    writeln!(out, "{c2}let mut __broke_loop = false;").ok();
                }
                emit_guest_fast_row_loop(out, mir, cat, func, fl, &c2);
                writeln!(
                    out,
                    "{c2}drop(__sm);\n\
                     {c2}if __dlen > 0 {{ if __n_runs < 16 {{ __runs[__n_runs] = (__dstart, __dlen); __n_runs += 1; }} else {{ __ovf.push((__dstart, __dlen)); }} }}\n\
                     {c2}for &(rs, rl) in &__runs[..__n_runs] {{ let _ = __chunk.mark_changed_range({sel_col}, rs as usize, rl as usize); }}\n\
                     {c2}for &(rs, rl) in &__ovf {{ let _ = __chunk.mark_changed_range({sel_col}, rs as usize, rl as usize); }}"
                )
                .ok();
                if fl.has_break {
                    writeln!(out, "{c2}if __broke_loop {{ break; }}").ok();
                }
            } else {
                writeln!(
                    out,
                    "{c2}let Some(__sel_src) = __chunk.component::<{sel_sname}>({sel_col}) else {{ {err_stmt} }};\n\
                     {c2}__sel_buf.clear();\n\
                     {c2}__sel_buf.extend_from_slice(__sel_src);\n\
                     {c2}let mut __dstart: u32 = 0;\n\
                     {c2}let mut __dlen: u32 = 0;\n\
                     {c2}let mut __runs = [(0u32, 0u32); 16];\n\
                     {c2}let mut __n_runs: usize = 0;\n\
                     {c2}let mut __ovf: Vec<(u32, u32)> = Vec::new();"
                )
                .ok();
                if fl.has_break {
                    writeln!(out, "{c2}let mut __broke_loop = false;").ok();
                }
                writeln!(out, "{c2}{{").ok();
                let c3 = format!("{c2}    ");
                match other_cols.as_slice() {
                    [(c0, t0)] => {
                        let s0 = &cat.components[t0.comp_id].struct_name;
                        if t0.mode == TermAccessMode::Write {
                            writeln!(
                                out,
                                "{c3}let Some(__raw0) = __chunk.component_mut::<{s0}>({c0}) else {{ {err_stmt} }};\n\
                                 {c3}let __q{qi}_col_{c0} = &mut __raw0[..__len];"
                            )
                            .ok();
                        } else {
                            writeln!(
                                out,
                                "{c3}let Some(__raw0) = __chunk.component::<{s0}>({c0}) else {{ {err_stmt} }};\n\
                                 {c3}let __q{qi}_col_{c0} = &__raw0[..__len];"
                            )
                            .ok();
                        }
                    }
                    [(c0, t0), (c1, t1)] => {
                        let s0 = &cat.components[t0.comp_id].struct_name;
                        let s1 = &cat.components[t1.comp_id].struct_name;
                        match (t0.mode, t1.mode) {
                            (TermAccessMode::Write, TermAccessMode::Write) => {
                                writeln!(
                                    out,
                                    "{c3}let Some((__raw0, __raw1)) = __chunk.component_write_2::<{s0}, {s1}>({c0}, {c1}) else {{ {err_stmt} }};\n\
                                     {c3}let __q{qi}_col_{c0} = &mut __raw0[..__len];\n\
                                     {c3}let __q{qi}_col_{c1} = &mut __raw1[..__len];"
                                )
                                .ok();
                            }
                            (TermAccessMode::Read, TermAccessMode::Write) => {
                                writeln!(
                                    out,
                                    "{c3}let Some((__raw0, __raw1)) = __chunk.component_read_write::<{s0}, {s1}>({c0}, {c1}) else {{ {err_stmt} }};\n\
                                     {c3}let __q{qi}_col_{c0} = &__raw0[..__len];\n\
                                     {c3}let __q{qi}_col_{c1} = &mut __raw1[..__len];"
                                )
                                .ok();
                            }
                            (TermAccessMode::Write, TermAccessMode::Read) => {
                                writeln!(
                                    out,
                                    "{c3}let Some((__raw1, __raw0)) = __chunk.component_read_write::<{s1}, {s0}>({c1}, {c0}) else {{ {err_stmt} }};\n\
                                     {c3}let __q{qi}_col_{c0} = &mut __raw0[..__len];\n\
                                     {c3}let __q{qi}_col_{c1} = &__raw1[..__len];"
                                )
                                .ok();
                            }
                            _ => {
                                writeln!(
                                    out,
                                    "{c3}let (Some(__raw0), Some(__raw1)) = (__chunk.component::<{s0}>({c0}), __chunk.component::<{s1}>({c1})) else {{ {err_stmt} }};\n\
                                     {c3}let __q{qi}_col_{c0} = &__raw0[..__len];\n\
                                     {c3}let __q{qi}_col_{c1} = &__raw1[..__len];"
                                )
                                .ok();
                            }
                        }
                    }
                    _ => {}
                }
                writeln!(
                    out,
                    "{c3}let __q{qi}_col_{sel_col} = &mut __sel_buf[..__len];"
                )
                .ok();
                emit_guest_fast_row_loop(out, mir, cat, func, fl, &c3);
                writeln!(out, "{c2}}}").ok();
                writeln!(
                    out,
                    "{c2}if __dlen > 0 {{ if __n_runs < 16 {{ __runs[__n_runs] = (__dstart, __dlen); __n_runs += 1; }} else {{ __ovf.push((__dstart, __dlen)); }} }}\n\
                     {c2}if __n_runs > 0 || !__ovf.is_empty() {{\n\
                     {c2}    let mut __sm = __chunk.mutable_slice_untracked({sel_col});\n\
                     {c2}    if let Some(__dst) = __sm.as_component_slice_mut::<{sel_sname}>() {{\n\
                     {c2}        for &(rs, rl) in &__runs[..__n_runs] {{ let s = rs as usize; let e = s + rl as usize; __dst[s..e].copy_from_slice(&__sel_buf[s..e]); }}\n\
                     {c2}        for &(rs, rl) in &__ovf {{ let s = rs as usize; let e = s + rl as usize; __dst[s..e].copy_from_slice(&__sel_buf[s..e]); }}\n\
                     {c2}    }}\n\
                     {c2}    drop(__sm);\n\
                     {c2}    for &(rs, rl) in &__runs[..__n_runs] {{ let _ = __chunk.mark_changed_range({sel_col}, rs as usize, rl as usize); }}\n\
                     {c2}    for &(rs, rl) in &__ovf {{ let _ = __chunk.mark_changed_range({sel_col}, rs as usize, rl as usize); }}\n\
                     {c2}}}"
                )
                .ok();
                if fl.has_break {
                    writeln!(out, "{c2}if __broke_loop {{ break; }}").ok();
                }
            }
            writeln!(out, "{cind}}}").ok();
        };

        writeln!(
            out,
            "{ind}if let Some(mut __qit) = sys_ctx.query_mut({qi}) {{"
        )
        .ok();
        let qind = format!("{ind}    ");
        if fl.use_par {
            if !fl.reduce_info.is_empty() {
                writeln!(out, "{qind}let __par_red_cl = Arc::clone(&__par_red);").ok();
            }
            writeln!(
                out,
                "{qind}let __par_st = __qit.par_try_for_each(move |mut __chunk: Chunk<'_, '_>| -> FfiResult {{"
            )
            .ok();
            let pind = format!("{qind}    ");
            if !other_cols.is_empty() {
                writeln!(
                    out,
                    "{pind}let mut __sel_buf: Vec<{sel_sname}> = Vec::new();"
                )
                .ok();
            }
            if !fl.reduce_info.is_empty() {
                for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                    let init_v = guest_reduce_identity(op, vt);
                    writeln!(
                        out,
                        "{pind}let mut __cred_{ri}: {} = {init_v};",
                        vt.rust_type(cat)
                    )
                    .ok();
                }
            }
            emit_sel_chunk(out, &pind, "return FfiResult::TYPE_MISMATCH;");
            if !fl.reduce_info.is_empty() {
                writeln!(out, "{pind}if let Ok(mut __g) = __par_red_cl.lock() {{").ok();
                for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                    let comb = guest_reduce_combine(
                        op,
                        vt,
                        &format!("__g.{ri}"),
                        &format!("__cred_{ri}"),
                        cat,
                    );
                    writeln!(out, "{pind}    __g.{ri} = {comb};").ok();
                }
                writeln!(out, "{pind}}}").ok();
            }
            writeln!(out, "{pind}FfiResult::OK").ok();
            writeln!(out, "{qind}}});").ok();
            writeln!(out, "{qind}if !__par_st.is_ok() {{ return __par_st; }}").ok();
        } else {
            if !other_cols.is_empty() {
                writeln!(
                    out,
                    "{qind}let mut __sel_buf: Vec<{sel_sname}> = Vec::new();"
                )
                .ok();
            }
            writeln!(
                out,
                "{qind}while let Some(mut __chunk) = __qit.next_chunk_view() {{"
            )
            .ok();
            emit_sel_chunk(out, &format!("{qind}    "), "break;");
            writeln!(out, "{qind}}}").ok();
        }
        writeln!(out, "{ind}}}").ok();
    } else {
        // Path A: Non-selective typed slices.
        let use_chunk_ro_reduce = fl.use_par
            && fl.par_is_readonly
            && !fl.reduce_info.is_empty()
            && qi == 0
            && !fl.needs_entity
            && pq.terms.iter().all(|t| t.mode == TermAccessMode::Read);

        if use_chunk_ro_reduce {
            writeln!(out, "{ind}let __par_red_cl = Arc::clone(&__par_red);").ok();
            writeln!(
                out,
                "{ind}let __par_st = sys_ctx.par_chunks_readonly(move |__chunk: &Chunk<'_, '_>| {{"
            )
            .ok();
            let cind = format!("{ind}    ");
            writeln!(out, "{cind}let __len = __chunk.len();").ok();
            writeln!(out, "{cind}if __len == 0 {{ return; }}").ok();
            for (pidx, pt) in pq.terms.iter().enumerate() {
                let sname = &cat.components[pt.comp_id].struct_name;
                writeln!(
                    out,
                    "{cind}let Some(__raw_{pidx}) = __chunk.component::<{sname}>({pidx}) else {{ return; }};\n\
                     {cind}let __q{qi}_col_{pidx} = &__raw_{pidx}[..__len];"
                )
                .ok();
            }
            for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                let init_v = guest_reduce_identity(op, vt);
                writeln!(
                    out,
                    "{cind}let mut __cred_{ri}: {} = {init_v};",
                    vt.rust_type(cat)
                )
                .ok();
            }
            emit_guest_fast_row_loop(out, mir, cat, func, fl, &cind);
            writeln!(out, "{cind}if let Ok(mut __g) = __par_red_cl.lock() {{").ok();
            for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                let comb = guest_reduce_combine(
                    op,
                    vt,
                    &format!("__g.{ri}"),
                    &format!("__cred_{ri}"),
                    cat,
                );
                writeln!(out, "{cind}    __g.{ri} = {comb};").ok();
            }
            writeln!(out, "{cind}}}").ok();
            writeln!(out, "{ind}}});").ok();
            writeln!(out, "{ind}if !__par_st.is_ok() {{ return __par_st; }}").ok();
        } else {
            let q_ty = guest_query_tuple_type(cat, pq, fl.needs_entity);
            let q_pat = guest_query_tuple_pattern(qi, pq, fl.needs_entity);
            let emit_reslice = |out: &mut String, rind: &str| {
                if fl.needs_entity {
                    writeln!(out, "{rind}let __len = __q{qi}_entities.len();").ok();
                    writeln!(
                        out,
                        "{rind}let __q{qi}_entities = &__q{qi}_entities[..__len];"
                    )
                    .ok();
                } else {
                    let first_non_opt = pq
                        .terms
                        .iter()
                        .position(|t| {
                            matches!(t.mode, TermAccessMode::Read | TermAccessMode::Write)
                        })
                        .unwrap_or(0);
                    writeln!(out, "{rind}let __len = __q{qi}_col_{first_non_opt}.len();").ok();
                }
                for (pidx, pt) in pq.terms.iter().enumerate() {
                    match pt.mode {
                        TermAccessMode::Read => {
                            writeln!(
                                out,
                                "{rind}let __q{qi}_col_{pidx} = &__q{qi}_col_{pidx}[..__len];"
                            )
                            .ok();
                        }
                        TermAccessMode::Write => {
                            writeln!(
                                out,
                                "{rind}let __q{qi}_col_{pidx} = &mut __q{qi}_col_{pidx}[..__len];"
                            )
                            .ok();
                        }
                        TermAccessMode::OptionalRead => {
                            writeln!(
                                out,
                                "{rind}let __q{qi}_col_{pidx} = __q{qi}_col_{pidx}.map(|s| &s[..__len]);"
                            )
                            .ok();
                        }
                        TermAccessMode::OptionalWrite => {
                            writeln!(
                                out,
                                "{rind}let mut __q{qi}_col_{pidx} = __q{qi}_col_{pidx}.map(|s| &mut s[..__len]);"
                            )
                            .ok();
                        }
                        _ => {}
                    }
                }
            };

            writeln!(
                out,
                "{ind}if let Some(mut __qt) = sys_ctx.query_typed::<{q_ty}>({eqi}) {{"
            )
            .ok();
            let qind = format!("{ind}    ");
            if fl.use_par {
                let all_ro = pq.terms.iter().all(|t| {
                    matches!(
                        t.mode,
                        TermAccessMode::Read
                            | TermAccessMode::OptionalRead
                            | TermAccessMode::Allow
                            | TermAccessMode::Has
                    )
                });
                let par_method = if fl.par_is_readonly && all_ro {
                    "par_for_each_chunk_readonly"
                } else {
                    "par_for_each"
                };
                if !fl.reduce_info.is_empty() {
                    writeln!(out, "{qind}let __par_red_cl = Arc::clone(&__par_red);").ok();
                }
                writeln!(
                    out,
                    "{qind}let __par_st = __qt.{par_method}(move |{q_pat}| -> FfiResult {{"
                )
                .ok();
                let cind = format!("{qind}    ");
                emit_reslice(out, &cind);
                if !fl.reduce_info.is_empty() {
                    for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                        let init_v = guest_reduce_identity(op, vt);
                        writeln!(
                            out,
                            "{cind}let mut __cred_{ri}: {} = {init_v};",
                            vt.rust_type(cat)
                        )
                        .ok();
                    }
                }
                emit_guest_fast_row_loop(out, mir, cat, func, fl, &cind);
                if !fl.reduce_info.is_empty() {
                    writeln!(out, "{cind}if let Ok(mut __g) = __par_red_cl.lock() {{").ok();
                    for (ri, (_, op, vt)) in fl.reduce_info.iter().enumerate() {
                        let comb = guest_reduce_combine(
                            op,
                            vt,
                            &format!("__g.{ri}"),
                            &format!("__cred_{ri}"),
                            cat,
                        );
                        writeln!(out, "{cind}    __g.{ri} = {comb};").ok();
                    }
                    writeln!(out, "{cind}}}").ok();
                }
                writeln!(out, "{cind}FfiResult::OK").ok();
                writeln!(out, "{qind}}});").ok();
                writeln!(out, "{qind}if !__par_st.is_ok() {{ return __par_st; }}").ok();
            } else if fl.has_break {
                writeln!(out, "{qind}while let Some({q_pat}) = __qt.next_chunk() {{").ok();
                let cind = format!("{qind}    ");
                emit_reslice(out, &cind);
                writeln!(out, "{cind}let mut __broke_loop = false;").ok();
                emit_guest_fast_row_loop(out, mir, cat, func, fl, &cind);
                writeln!(out, "{cind}if __broke_loop {{ break; }}").ok();
                writeln!(out, "{qind}}}").ok();
            } else {
                writeln!(
                    out,
                    "{qind}let __seq_st = __qt.for_each(|{q_pat}| -> FfiResult {{"
                )
                .ok();
                let cind = format!("{qind}    ");
                emit_reslice(out, &cind);
                emit_guest_fast_row_loop(out, mir, cat, func, fl, &cind);
                writeln!(out, "{cind}FfiResult::OK").ok();
                writeln!(out, "{qind}}});").ok();
                writeln!(out, "{qind}if !__seq_st.is_ok() {{ return __seq_st; }}").ok();
            }
            writeln!(out, "{ind}}}").ok();
        }
    }

    // 3. Write back reduction accumulators and sequential outer slot writes.
    if !fl.reduce_info.is_empty() {
        if fl.use_par {
            writeln!(out, "{ind}if let Ok(__g) = __par_red.lock() {{").ok();
            for (ri, (sl, _, vt)) in fl.reduce_info.iter().enumerate() {
                if let Some(sv) = vt.to_strata_val(&format!("__g.{ri}"), cat) {
                    writeln!(out, "{ind}    slots[{}] = {sv};", sl.0).ok();
                }
            }
            writeln!(out, "{ind}}}").ok();
        } else {
            for (sl, _, vt) in &fl.reduce_info {
                if let Some(sv) = vt.to_strata_val(&format!("__oslot_{}", sl.0), cat) {
                    writeln!(out, "{ind}slots[{}] = {sv};", sl.0).ok();
                }
            }
        }
    }
    for &sid in &fl.outer_slot_writes {
        let vt = &fl.slot_tys[&LocalId(sid)];
        if let Some(sv) = vt.to_strata_val(&format!("__oslot_{sid}"), cat) {
            writeln!(out, "{ind}slots[{sid}] = {sv};").ok();
        }
    }

    writeln!(out, "                }}").ok();
}
