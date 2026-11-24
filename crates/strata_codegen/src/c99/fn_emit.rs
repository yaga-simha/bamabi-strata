//! C99 function emission, CFG reachability, and `@par` sub-CFG analysis.

use super::*;

impl<'a> EmitCtx<'a> {
    pub(super) fn emit_functions(&mut self) -> Result<(), CodegenError> {
        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        for f in &fns_snapshot {
            let body = self.emit_mir_function(f)?;
            self.out.push_str(&body);
            self.out.push('\n');
        }
        Ok(())
    }

    pub(super) fn emit_mir_function(&self, f: &MirFunction) -> Result<String, CodegenError> {
        let mut s = String::new();
        let is_helper = matches!(f.kind, MirFnKind::HelperFn);
        let is_void_helper = is_helper && matches!(f.ret_ty, MirType::Unit);
        let is_observer = matches!(f.kind, MirFnKind::Observer { .. });
        let is_migration = matches!(f.kind, MirFnKind::Migration { .. });

        // Pre-scan statements to infer refined pointer provenance, `BAM_RESTRICT` column locals,
        // `SlotAlloc` stack allocations, dirty-run owners, spatial buffers, and coerced local types.
        let mut ptr_meta: HashMap<LocalId, PtrKind> = HashMap::new();
        let mut restrict_cols: HashMap<LocalId, PtrKind> = HashMap::new();
        let mut projected_fields: HashMap<LocalId, String> = HashMap::new();
        let mut nonnull_cols: HashSet<LocalId> = HashSet::new();
        let mut nonnull_ptrs: HashSet<LocalId> = HashSet::new();
        let (reachable, label_targets) = analyze_cfg(&f.blocks);
        let chunk_dom_blocks = c99_chunk_dominated_blocks(&f.blocks, &reachable);
        let pset_groups = self.compute_query_param_set_groups(f);
        let param_set_queries: HashSet<u32> = f
            .query_bindings
            .iter()
            .zip(pset_groups.iter())
            .filter_map(|(qb, &g)| (g != 0).then_some(qb.query_idx))
            .collect();
        let mut query_term_remaps: HashMap<(u32, u32), u32> = HashMap::new();
        let mut query_aliased_terms: HashSet<(u32, u32)> = HashSet::new();
        for qb in &f.query_bindings {
            if let Ok(dq) = self.compute_dedup_query_terms(f, qb, "emit_mir_function") {
                for (raw_ti, eff_ti) in dq.remap {
                    query_term_remaps.insert((qb.query_idx, raw_ti), eff_ti);
                    if dq.aliased_dedup_indices.contains(&eff_ti) {
                        query_aliased_terms.insert((qb.query_idx, raw_ti));
                    }
                }
            }
        }
        let active_checkpoints = compute_active_checkpoints(f);
        let mut def_counts: HashMap<LocalId, usize> = HashMap::new();
        for bb in &f.blocks {
            for stmt in &bb.stmts {
                if let Some(d) = stmt.dst {
                    *def_counts.entry(d).or_insert(0) += 1;
                }
            }
        }
        let mut slot_allocs: Vec<(LocalId, MirType)> = Vec::new();
        let mut spatial_hits_locals: Vec<LocalId> = Vec::new();
        let mut dirty_owners: HashMap<(u32, u32), Vec<(u32, u32)>> = HashMap::new();
        let mut field_ptr_arrays: HashMap<LocalId, (Ty, usize)> = HashMap::new();
        let mut smallvec_ptrs: HashMap<LocalId, (Ty, usize)> = HashMap::new();
        let mut array_index_strides: HashMap<LocalId, usize> = HashMap::new();
        let mut slot_ptr_meta: HashMap<LocalId, PtrKind> = HashMap::new();
        let mut slot_mir_arrays: HashMap<LocalId, (MirType, usize)> = HashMap::new();
        let mut local_types: HashMap<LocalId, MirType> = HashMap::new();
        for l in &f.locals {
            local_types.insert(l.id, l.ty.clone());
        }
        if is_helper {
            let helper_param_tys = self.resolve_helper_param_tys(f);
            for (i, p) in f.params.iter().enumerate() {
                if let Some(ploc) = p.local
                    && let Some(resolved_ty) = helper_param_tys.get(i)
                    && !matches!(resolved_ty, MirType::Ptr | MirType::MutPtr)
                    && matches!(
                        local_types.get(&ploc),
                        Some(MirType::Ptr | MirType::MutPtr) | None
                    )
                {
                    local_types.insert(ploc, resolved_ty.clone());
                }
            }
        }

        for bb in &f.blocks {
            for stmt in &bb.stmts {
                let dst = stmt.dst;
                match &stmt.inst {
                    Inst::InternSymbol { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Sym);
                        }
                    }
                    Inst::IterNextChunk { .. }
                    | Inst::OptionalChunkIsPresent { .. }
                    | Inst::GraceIsActive { .. }
                    | Inst::InputBufConsume { .. }
                    | Inst::InputBufPeek { .. }
                    | Inst::BitSetGet { .. }
                    | Inst::TimelineInWindow { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Bool);
                        }
                    }
                    Inst::IterChunkLen { .. } | Inst::IterCount { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::U32);
                        }
                    }
                    Inst::CmdSpawn { .. } | Inst::TriggerTarget | Inst::EntityAtRow { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::Entity);
                        }
                    }
                    Inst::SpawnBatchBegin { .. } => {
                        if let Some(d) = dst {
                            local_types.insert(d, MirType::U64);
                        }
                    }
                    Inst::SpatialQueryDisc { .. } | Inst::SpatialQuerySegmentAt { .. } => {
                        if let Some(d) = dst {
                            spatial_hits_locals.push(d);
                            ptr_meta.insert(d, PtrKind::EntitySlice);
                        }
                    }
                    Inst::IterUpCascade {
                        query_idx,
                        term_idx,
                        ..
                    } => {
                        if let Some(d) = dst {
                            let comp_layout = f
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx))
                                .and_then(|t| self.find_layout_idx(&t.canonical_component));
                            if let Some(l_idx) = comp_layout {
                                ptr_meta.insert(
                                    d,
                                    PtrKind::LayoutPtr {
                                        layout_idx: l_idx,
                                        is_mut: false,
                                    },
                                );
                            }
                        }
                    }
                    Inst::VecSwizzle { vec, lanes } => {
                        if let Some(d) = dst {
                            let base_ty = local_types.get(vec).cloned().unwrap_or(MirType::Vec4);
                            let vty = match (&base_ty, lanes.len()) {
                                (MirType::IVec2 | MirType::IVec3, 2) => MirType::IVec2,
                                (MirType::IVec2 | MirType::IVec3, 3) => MirType::IVec3,
                                (MirType::UVec2, 2) => MirType::UVec2,
                                (_, 2) => MirType::Vec2,
                                (_, 3) => MirType::Vec3,
                                _ => MirType::Vec4,
                            };
                            local_types.insert(d, vty);
                        }
                    }
                    Inst::SlotAlloc { ty } => {
                        if let Some(d) = dst {
                            if !slot_allocs.iter().any(|(id, _)| *id == d) {
                                slot_allocs.push((d, ty.clone()));
                            }
                            let pk = match ty {
                                MirType::Named(key) => {
                                    if let Some(l_idx) = self.find_layout_idx(key) {
                                        PtrKind::LayoutPtr {
                                            layout_idx: l_idx,
                                            is_mut: true,
                                        }
                                    } else {
                                        PtrKind::ScalarPtr {
                                            c_pointee: self.c_ty(ty),
                                            is_mut: true,
                                        }
                                    }
                                }
                                _ => PtrKind::ScalarPtr {
                                    c_pointee: self.c_ty(ty),
                                    is_mut: true,
                                },
                            };
                            if let MirType::Named(ref key) = *ty
                                && let Some((elem, cap)) = self.parse_smallvec_mir_key(key)
                            {
                                smallvec_ptrs.insert(d, (elem, cap));
                            } else if let MirType::Array { elem, len } = ty {
                                slot_mir_arrays.insert(d, ((**elem).clone(), *len));
                            }
                            ptr_meta.insert(d, pk);
                        }
                    }
                    Inst::IterEntities { .. } => {
                        if let Some(d) = dst {
                            ptr_meta.insert(d, PtrKind::EntitySlice);
                        }
                    }
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            let term_opt = f
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx));
                            let is_sparse = term_opt.is_some_and(|t| t.is_sparse);
                            if is_sparse {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: false });
                            } else {
                                let layout_opt = self
                                    .find_layout_idx(storage_key)
                                    .or_else(|| {
                                        storage_key
                                            .rsplit_once("::")
                                            .and_then(|(c, _)| self.find_layout_idx(c))
                                    })
                                    .or_else(|| {
                                        term_opt.and_then(|t| {
                                            self.find_layout_idx(&t.canonical_component)
                                        })
                                    });
                                if let Some(l_idx) = layout_opt {
                                    let pk = PtrKind::LayoutPtr {
                                        layout_idx: l_idx,
                                        is_mut: false,
                                    };
                                    if !param_set_queries.contains(query_idx)
                                        && !query_aliased_terms.contains(&(*query_idx, *term_idx))
                                    {
                                        restrict_cols.insert(d, pk.clone());
                                    }
                                    ptr_meta.insert(d, pk);
                                    if !is_helper
                                        && def_counts.get(&d) == Some(&1)
                                        && chunk_dom_blocks
                                            .get(query_idx)
                                            .is_some_and(|dom| dom.contains(&bb.id.0))
                                        && term_opt.is_some_and(|t| {
                                            !t.is_sparse
                                                && matches!(
                                                    t.mode,
                                                    TermAccessMode::Read
                                                        | TermAccessMode::Write
                                                        | TermAccessMode::SelectiveWrite
                                                )
                                        })
                                    {
                                        nonnull_cols.insert(d);
                                        nonnull_ptrs.insert(d);
                                    }
                                }
                            }
                            if let Some(fnm) = term_opt.and_then(|t| t.field_name.clone()) {
                                projected_fields.insert(d, fnm);
                            } else if let Some((_, fld)) = storage_key.rsplit_once("::")
                                && self.find_layout_idx(storage_key).is_none()
                            {
                                projected_fields.insert(d, fld.to_string());
                            }
                        }
                    }
                    Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            let term_opt = f
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx));
                            let is_sparse = term_opt.is_some_and(|t| t.is_sparse);
                            if is_sparse {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: true });
                            } else {
                                let layout_opt = self
                                    .find_layout_idx(storage_key)
                                    .or_else(|| {
                                        storage_key
                                            .rsplit_once("::")
                                            .and_then(|(c, _)| self.find_layout_idx(c))
                                    })
                                    .or_else(|| {
                                        term_opt.and_then(|t| {
                                            self.find_layout_idx(&t.canonical_component)
                                        })
                                    });
                                if let Some(l_idx) = layout_opt {
                                    let pk = PtrKind::LayoutPtr {
                                        layout_idx: l_idx,
                                        is_mut: true,
                                    };
                                    if !param_set_queries.contains(query_idx)
                                        && !query_aliased_terms.contains(&(*query_idx, *term_idx))
                                    {
                                        restrict_cols.insert(d, pk.clone());
                                    }
                                    ptr_meta.insert(d, pk);
                                    if !is_helper
                                        && def_counts.get(&d) == Some(&1)
                                        && chunk_dom_blocks
                                            .get(query_idx)
                                            .is_some_and(|dom| dom.contains(&bb.id.0))
                                        && term_opt.is_some_and(|t| {
                                            !t.is_sparse
                                                && matches!(
                                                    t.mode,
                                                    TermAccessMode::Read
                                                        | TermAccessMode::Write
                                                        | TermAccessMode::SelectiveWrite
                                                )
                                        })
                                    {
                                        nonnull_cols.insert(d);
                                        nonnull_ptrs.insert(d);
                                    }
                                }
                            }
                            if let Some(fnm) = term_opt.and_then(|t| t.field_name.clone()) {
                                projected_fields.insert(d, fnm);
                            } else if let Some((_, fld)) = storage_key.rsplit_once("::")
                                && self.find_layout_idx(storage_key).is_none()
                            {
                                projected_fields.insert(d, fld.to_string());
                            }
                        }
                    }
                    Inst::IterColRowsRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            if self.is_query_term_sparse(f, *query_idx, *term_idx, storage_key) {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: false });
                            } else if let Some(l_idx) =
                                self.find_layout_idx(storage_key).or_else(|| {
                                    f.query_bindings
                                        .iter()
                                        .find(|qb| qb.query_idx == *query_idx)
                                        .and_then(|qb| {
                                            qb.terms.iter().find(|t| t.term_idx == *term_idx)
                                        })
                                        .and_then(|t| self.find_layout_idx(&t.canonical_component))
                                })
                            {
                                ptr_meta.insert(
                                    d,
                                    PtrKind::LayoutPtr {
                                        layout_idx: l_idx,
                                        is_mut: false,
                                    },
                                );
                            } else {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: false });
                            }
                        }
                    }
                    Inst::IterColRowsWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    } => {
                        if let Some(d) = dst {
                            if self.is_query_term_sparse(f, *query_idx, *term_idx, storage_key) {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: true });
                            } else if let Some(l_idx) =
                                self.find_layout_idx(storage_key).or_else(|| {
                                    f.query_bindings
                                        .iter()
                                        .find(|qb| qb.query_idx == *query_idx)
                                        .and_then(|qb| {
                                            qb.terms.iter().find(|t| t.term_idx == *term_idx)
                                        })
                                        .and_then(|t| self.find_layout_idx(&t.canonical_component))
                                })
                            {
                                ptr_meta.insert(
                                    d,
                                    PtrKind::LayoutPtr {
                                        layout_idx: l_idx,
                                        is_mut: true,
                                    },
                                );
                            } else {
                                ptr_meta.insert(d, PtrKind::SparseRows { is_mut: true });
                            }
                        }
                    }
                    Inst::EntityGet { storage_key, .. }
                    | Inst::ResRead {
                        resource: storage_key,
                    }
                    | Inst::TriggerPayload { event: storage_key }
                    | Inst::MigrateSrcPtr {
                        layout_key: storage_key,
                    } => {
                        if let Some(d) = dst
                            && let Some(l_idx) = self.find_layout_idx(storage_key)
                        {
                            ptr_meta.insert(
                                d,
                                PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: false,
                                },
                            );
                        }
                    }
                    Inst::EntityGetMut { storage_key, .. }
                    | Inst::ResWrite {
                        resource: storage_key,
                    }
                    | Inst::MigrateDstPtr {
                        layout_key: storage_key,
                    } => {
                        if let Some(d) = dst
                            && let Some(l_idx) = self.find_layout_idx(storage_key)
                        {
                            ptr_meta.insert(
                                d,
                                PtrKind::LayoutPtr {
                                    layout_idx: l_idx,
                                    is_mut: true,
                                },
                            );
                        }
                    }
                    Inst::IterMarkChangedRange {
                        query_idx,
                        term_idx,
                        run_start,
                        run_len,
                    } => {
                        dirty_owners
                            .entry((run_start.0, run_len.0))
                            .or_default()
                            .push((*query_idx, *term_idx));
                    }
                    _ => {}
                }
            }
        }
        // Propagate TableLoad struct types into SlotAlloc / SlotStore / SlotLoad,
        // RowPtr pointee layout, and VecInsert / Copy vector dimensions.
        let mut slot_ty_overrides: HashMap<LocalId, MirType> = HashMap::new();
        for _ in 0..3 {
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    if let Some(d) = stmt.dst {
                        match &stmt.inst {
                            Inst::TableLoad {
                                table_name, field, ..
                            } if field.is_empty() => {
                                local_types.insert(
                                    d,
                                    MirType::Named(format!("__strata_table_{table_name}")),
                                );
                            }
                            Inst::SlotLoad { slot } => {
                                if let Some(ov) = slot_ty_overrides.get(slot) {
                                    local_types.insert(d, ov.clone());
                                }
                                if let Some(pk) = slot_ptr_meta.get(slot) {
                                    ptr_meta.entry(d).or_insert_with(|| pk.clone());
                                }
                            }
                            Inst::RowPtr {
                                col_ptr, is_sparse, ..
                            } => {
                                if let Some(PtrKind::LayoutPtr { layout_idx, is_mut }) =
                                    ptr_meta.get(col_ptr)
                                {
                                    ptr_meta.insert(
                                        d,
                                        PtrKind::LayoutPtr {
                                            layout_idx: *layout_idx,
                                            is_mut: *is_mut,
                                        },
                                    );
                                }
                                if let Some(pf) = projected_fields.get(col_ptr).cloned() {
                                    projected_fields.insert(d, pf);
                                }
                                if !is_sparse
                                    && def_counts.get(&d) == Some(&1)
                                    && nonnull_ptrs.contains(col_ptr)
                                {
                                    nonnull_ptrs.insert(d);
                                }
                            }
                            Inst::FieldPtr {
                                base_ptr,
                                layout_key,
                                field,
                                offset_bytes,
                            } => {
                                if def_counts.get(&d) == Some(&1) && nonnull_ptrs.contains(base_ptr)
                                {
                                    nonnull_ptrs.insert(d);
                                }
                                let effective_key = if !layout_key.is_empty() {
                                    Some(layout_key.clone())
                                } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) =
                                    ptr_meta.get(base_ptr)
                                {
                                    Some(self.layouts[*layout_idx].canonical_name.clone())
                                } else {
                                    None
                                };
                                if layout_key == "SmallVec" && field == "data" {
                                    if let Some((sv_elem, sv_cap)) =
                                        smallvec_ptrs.get(base_ptr).cloned()
                                    {
                                        field_ptr_arrays.insert(d, (sv_elem, sv_cap));
                                    }
                                } else if let Some(lk) = effective_key
                                    && let Some(l_idx) = self.find_layout_idx(&lk)
                                    && let Some(fty) = self.resolve_sema_field_ty(
                                        l_idx,
                                        field,
                                        *offset_bytes as usize,
                                    )
                                {
                                    match fty {
                                        Ty::Array { elem, len } => {
                                            field_ptr_arrays.insert(d, (*elem, len));
                                        }
                                        Ty::SmallVec { elem, cap } => {
                                            smallvec_ptrs.insert(d, (*elem, cap));
                                        }
                                        Ty::Named(ref inner_key) => {
                                            if let Some(inner_li) = self.find_layout_idx(inner_key)
                                                && self.layouts[inner_li].item_kind
                                                    != SchemaItemKind::Enum
                                            {
                                                let is_mut = ptr_meta
                                                    .get(base_ptr)
                                                    .is_none_or(PtrKind::is_mut);
                                                ptr_meta.insert(
                                                    d,
                                                    PtrKind::LayoutPtr {
                                                        layout_idx: inner_li,
                                                        is_mut,
                                                    },
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Inst::ArrayIndex { base, .. } => {
                                if matches!(
                                    local_types.get(&d),
                                    Some(MirType::Ptr | MirType::MutPtr)
                                ) {
                                    let is_mut = ptr_meta.get(base).is_none_or(PtrKind::is_mut);
                                    if let Some((sema_elem, _)) =
                                        field_ptr_arrays.get(base).cloned()
                                    {
                                        let stride = self
                                            .sema_ty_size_align(&sema_elem)
                                            .map(|(es, ea)| es.div_ceil(ea) * ea)
                                            .unwrap_or(4);
                                        array_index_strides.insert(d, stride);
                                        match sema_elem {
                                            Ty::Array {
                                                elem: sub_e,
                                                len: sub_l,
                                            } => {
                                                field_ptr_arrays.insert(d, (*sub_e, sub_l));
                                            }
                                            Ty::SmallVec { elem: sv_e, cap } => {
                                                smallvec_ptrs.insert(d, (*sv_e, cap));
                                            }
                                            Ty::Named(ref inner_key) => {
                                                if let Some(li) = self.find_layout_idx(inner_key)
                                                    && self.layouts[li].item_kind
                                                        != SchemaItemKind::Enum
                                                {
                                                    ptr_meta.insert(
                                                        d,
                                                        PtrKind::LayoutPtr {
                                                            layout_idx: li,
                                                            is_mut,
                                                        },
                                                    );
                                                } else {
                                                    ptr_meta.insert(
                                                        d,
                                                        PtrKind::ScalarPtr {
                                                            c_pointee: self
                                                                .c_ty_from_sema(&sema_elem),
                                                            is_mut,
                                                        },
                                                    );
                                                }
                                            }
                                            other_ty => {
                                                ptr_meta.insert(
                                                    d,
                                                    PtrKind::ScalarPtr {
                                                        c_pointee: self.c_ty_from_sema(&other_ty),
                                                        is_mut,
                                                    },
                                                );
                                            }
                                        }
                                    } else if let Some((mir_elem, _)) =
                                        slot_mir_arrays.get(base).cloned()
                                    {
                                        if let MirType::Array {
                                            elem: sub_e,
                                            len: sub_l,
                                        } = &mir_elem
                                        {
                                            slot_mir_arrays.insert(d, ((**sub_e).clone(), *sub_l));
                                        } else if let MirType::Named(ref key) = mir_elem
                                            && let Some(li) = self.find_layout_idx(key)
                                        {
                                            ptr_meta.insert(
                                                d,
                                                PtrKind::LayoutPtr {
                                                    layout_idx: li,
                                                    is_mut,
                                                },
                                            );
                                        } else {
                                            ptr_meta.insert(
                                                d,
                                                PtrKind::ScalarPtr {
                                                    c_pointee: self.c_ty(&mir_elem),
                                                    is_mut,
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                            Inst::VecInsert { vec, .. } => {
                                if let Some(vty) = local_types.get(vec).cloned() {
                                    local_types.insert(d, vty);
                                }
                            }
                            Inst::BinOp { op, lhs, rhs, .. } => {
                                if op == "quat_mul_vec3" {
                                    local_types.insert(d, MirType::Vec3);
                                } else if op == "quat_mul" {
                                    local_types.insert(d, MirType::Vec4);
                                } else if !matches!(
                                    op.as_str(),
                                    "==" | "!="
                                        | "<"
                                        | "<="
                                        | ">"
                                        | ">="
                                        | "Eq"
                                        | "Ne"
                                        | "Lt"
                                        | "Le"
                                        | "Gt"
                                        | "Ge"
                                        | "&&"
                                        | "||"
                                        | "And"
                                        | "Or"
                                ) {
                                    let vec_ty_opt = local_types
                                        .get(lhs)
                                        .filter(|t| {
                                            matches!(
                                                t,
                                                MirType::Vec2
                                                    | MirType::Vec3
                                                    | MirType::Vec4
                                                    | MirType::IVec2
                                                    | MirType::IVec3
                                                    | MirType::UVec2
                                            )
                                        })
                                        .or_else(|| {
                                            local_types.get(rhs).filter(|t| {
                                                matches!(
                                                    t,
                                                    MirType::Vec2
                                                        | MirType::Vec3
                                                        | MirType::Vec4
                                                        | MirType::IVec2
                                                        | MirType::IVec3
                                                        | MirType::UVec2
                                                )
                                            })
                                        })
                                        .cloned();
                                    if let Some(vt) = vec_ty_opt
                                        && !matches!(
                                            local_types.get(&d),
                                            Some(
                                                MirType::Bool
                                                    | MirType::Vec2
                                                    | MirType::Vec3
                                                    | MirType::Vec4
                                                    | MirType::IVec2
                                                    | MirType::IVec3
                                                    | MirType::UVec2
                                            )
                                        )
                                    {
                                        local_types.insert(d, vt);
                                    }
                                }
                            }
                            Inst::Copy { val } => {
                                if matches!(
                                    local_types.get(&d),
                                    Some(
                                        MirType::Vec2
                                            | MirType::Vec3
                                            | MirType::Vec4
                                            | MirType::IVec2
                                            | MirType::IVec3
                                            | MirType::UVec2
                                    )
                                ) && let Some(vty) = local_types.get(val).cloned()
                                    && matches!(
                                        vty,
                                        MirType::Vec2
                                            | MirType::Vec3
                                            | MirType::Vec4
                                            | MirType::IVec2
                                            | MirType::IVec3
                                            | MirType::UVec2
                                    )
                                {
                                    local_types.insert(d, vty);
                                }
                                if def_counts.get(&d) == Some(&1) && nonnull_ptrs.contains(val) {
                                    nonnull_ptrs.insert(d);
                                }
                                if let Some(arr_meta) = field_ptr_arrays.get(val).cloned() {
                                    field_ptr_arrays.entry(d).or_insert(arr_meta);
                                }
                                if let Some(sv_meta) = smallvec_ptrs.get(val).cloned() {
                                    smallvec_ptrs.entry(d).or_insert(sv_meta);
                                }
                                if let Some(sm_meta) = slot_mir_arrays.get(val).cloned() {
                                    slot_mir_arrays.entry(d).or_insert(sm_meta);
                                }
                                if let Some(st) = array_index_strides.get(val).copied() {
                                    array_index_strides.entry(d).or_insert(st);
                                }
                                if let Some(pk) = ptr_meta.get(val).cloned() {
                                    ptr_meta.entry(d).or_insert(pk);
                                }
                            }
                            _ => {}
                        }
                    } else if let Inst::SlotStore { slot, val } = &stmt.inst {
                        if let Some(vty) = local_types.get(val)
                            && matches!(vty, MirType::Named(k) if k.starts_with("__strata_table_"))
                        {
                            slot_ty_overrides.insert(*slot, vty.clone());
                        }
                        if let Some(PtrKind::LayoutPtr { layout_idx, is_mut }) = ptr_meta.get(val) {
                            slot_ptr_meta.entry(*slot).or_insert(PtrKind::LayoutPtr {
                                layout_idx: *layout_idx,
                                is_mut: *is_mut,
                            });
                        }
                    }
                }
            }
        }
        for (slot_id, st_ty) in &mut slot_allocs {
            if let Some(ov) = slot_ty_overrides.get(slot_id) {
                *st_ty = ov.clone();
                ptr_meta.insert(
                    *slot_id,
                    PtrKind::ScalarPtr {
                        c_pointee: self.c_ty(ov),
                        is_mut: true,
                    },
                );
            }
        }

        let slot_alloc_map: HashMap<LocalId, MirType> = slot_allocs.iter().cloned().collect();
        let mut const_defs: HashMap<LocalId, MirConstVal> = HashMap::new();
        let mut array_inits: HashMap<LocalId, Vec<LocalId>> = HashMap::new();
        for _ in 0..4 {
            let mut changed = false;
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    let Some(d) = stmt.dst else {
                        continue;
                    };
                    if def_counts.get(&d) != Some(&1) {
                        continue;
                    }
                    match &stmt.inst {
                        Inst::ArrayInit { elems } => {
                            array_inits.entry(d).or_insert_with(|| elems.clone());
                            if !const_defs.contains_key(&d)
                                && elems.iter().all(|el| const_defs.contains_key(el))
                            {
                                let vals = elems.iter().map(|el| const_defs[el].clone()).collect();
                                const_defs.insert(d, MirConstVal::Array(vals));
                                changed = true;
                            }
                        }
                        Inst::StructInit { type_name, fields } => {
                            if !const_defs.contains_key(&d)
                                && fields.iter().all(|(_, fv)| const_defs.contains_key(fv))
                            {
                                let fvals = fields
                                    .iter()
                                    .map(|(fnm, fv)| (fnm.clone(), const_defs[fv].clone()))
                                    .collect();
                                const_defs.insert(
                                    d,
                                    MirConstVal::Struct {
                                        name: type_name.clone(),
                                        fields: fvals,
                                    },
                                );
                                changed = true;
                            }
                        }
                        _ if !const_defs.contains_key(&d) => {
                            let val_opt = match &stmt.inst {
                                Inst::ConstInt { value } => Some(MirConstVal::Int(*value)),
                                Inst::ConstFloat { value } => Some(MirConstVal::Float(*value)),
                                Inst::ConstBool { value } => Some(MirConstVal::Bool(*value)),
                                Inst::ConstString { value } => {
                                    Some(MirConstVal::String(value.clone()))
                                }
                                Inst::ConstVec { dims, values } => match dims {
                                    2 => Some(MirConstVal::Vec2([values[0], values[1]])),
                                    3 => Some(MirConstVal::Vec3([values[0], values[1], values[2]])),
                                    _ => Some(MirConstVal::Vec4(*values)),
                                },
                                Inst::UnOp { op, val } => {
                                    match (op.as_str(), const_defs.get(val)) {
                                        ("-" | "Neg", Some(MirConstVal::Int(i))) => {
                                            Some(MirConstVal::Int(i.wrapping_neg()))
                                        }
                                        ("-" | "Neg", Some(MirConstVal::Float(fv))) => {
                                            Some(MirConstVal::Float(-*fv))
                                        }
                                        ("!" | "Not", Some(MirConstVal::Bool(b))) => {
                                            Some(MirConstVal::Bool(!*b))
                                        }
                                        ("~" | "BitNot", Some(MirConstVal::Int(i))) => {
                                            Some(MirConstVal::Int(!*i))
                                        }
                                        _ => None,
                                    }
                                }
                                Inst::Copy { val } => const_defs.get(val).cloned(),
                                _ => None,
                            };
                            if let Some(cv) = val_opt {
                                const_defs.insert(d, cv);
                                changed = true;
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
        let can_outline_par = !is_observer && !is_migration && !is_helper;
        let mut par_tasks: HashMap<u32, C99ParTaskSpec> = HashMap::new();
        let mut par_task_order: Vec<u32> = Vec::new();
        let mut skip_blocks: HashSet<u32> = HashSet::new();
        if can_outline_par {
            let fn_ident = sanitize_ident(&f.name);
            for bb in &f.blocks {
                if !reachable.contains(&bb.id.0) || skip_blocks.contains(&bb.id.0) {
                    continue;
                }
                if let Some((stmt_idx, stmt)) = bb.stmts.iter().enumerate().next_back() {
                    let par_meta = match &stmt.inst {
                        Inst::ParForEachChunk { query_idx, .. } => Some((*query_idx, false, false)),
                        Inst::ParForEachChunkReadonly {
                            query_idx,
                            deterministic_order,
                            ..
                        } => Some((*query_idx, true, *deterministic_order)),
                        _ => None,
                    };
                    if let Some((query_idx, is_readonly, deterministic_order)) = par_meta
                        && let Some(info) = c99_find_par_subcfg(
                            f,
                            bb.id.0,
                            stmt_idx,
                            query_idx,
                            is_readonly,
                            deterministic_order,
                            &ptr_meta,
                            &restrict_cols,
                            &slot_alloc_map,
                            &spatial_hits_locals,
                            &dirty_owners,
                            &local_types,
                            &self.helper_by_name,
                            self.mir_functions(),
                        )
                        && info.sub_blocks.iter().all(|sb| !skip_blocks.contains(sb))
                    {
                        for &sb in &info.sub_blocks {
                            skip_blocks.insert(sb);
                        }
                        let frame_struct =
                            format!("StrataParFrame_{fn_ident}_b{}_q{}", bb.id.0, info.query_idx);
                        let task_fn =
                            format!("strata_par_{fn_ident}_b{}_q{}", bb.id.0, info.query_idx);
                        par_task_order.push(bb.id.0);
                        par_tasks.insert(
                            bb.id.0,
                            C99ParTaskSpec {
                                info,
                                frame_struct,
                                task_fn,
                            },
                        );
                    }
                }
            }
        }

        let by_id: HashMap<u32, usize> = f
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.id.0, i))
            .collect();

        // Emit outlined `@par` frame structs and `BamChunkTaskFn` workers before the parent system.
        for par_bb_id in &par_task_order {
            let spec = &par_tasks[par_bb_id];
            let info = &spec.info;
            let qi = info.query_idx;

            let _ = writeln!(s, "typedef struct {} {{", spec.frame_struct);
            let _ = writeln!(s, "    StrataModState* state;");
            for &lid in &info.live_in_locals {
                let lid_k = LocalId(lid);
                let eff_ty = local_types
                    .get(&lid_k)
                    .unwrap_or(&f.locals[lid as usize].ty);
                let cty = self.c_ty(eff_ty);
                let _ = writeln!(s, "    {cty} f_{lid};");
            }
            for &sid in &info.live_in_slots {
                let st_ty = &slot_alloc_map[&LocalId(sid)];
                let cty = self.c_ty(st_ty);
                let _ = writeln!(s, "    {cty} slot_f_{sid};");
            }
            let _ = writeln!(s, "}} {};\n", spec.frame_struct);

            let _ = writeln!(
                s,
                "static BamResult {}(BamIter* sub_iter, void* raw_user_data) {{",
                spec.task_fn
            );
            let _ = writeln!(
                s,
                "    if (sub_iter == NULL || raw_user_data == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
            );
            let _ = writeln!(
                s,
                "    {}* par_frame = ({}*)raw_user_data;",
                spec.frame_struct, spec.frame_struct
            );
            let _ = writeln!(s, "    StrataModState* state = par_frame->state;");
            let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
            let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
            let _ = writeln!(
                s,
                "    if (state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
            );
            let _ = writeln!(s, "    (void)state; (void)sys_ctx; (void)cmds_cache;");
            let _ = writeln!(s, "    BamIter* iter_{qi} = sub_iter;");
            let _ = writeln!(s, "    size_t iter_{qi}_len = 0u;");
            let _ = writeln!(s, "    const BamEntity* iter_{qi}_ents = NULL;");
            let _ = writeln!(s, "    BamEntity iter_{qi}_cur_ent = BAM_ENTITY_NULL;");
            let _ = writeln!(
                s,
                "    (void)iter_{qi}; (void)iter_{qi}_len; (void)iter_{qi}_ents; (void)iter_{qi}_cur_ent;"
            );

            let live_slot_set: HashSet<u32> = info.live_in_slots.iter().copied().collect();
            for (slot_id, ty) in &slot_allocs {
                let sid = slot_id.0;
                if !info.allocs_inside.contains(&sid) && !live_slot_set.contains(&sid) {
                    continue;
                }
                let slot_cty = self.c_ty(ty);
                if live_slot_set.contains(&sid) {
                    let _ = writeln!(
                        s,
                        "    {slot_cty} slot_buf_{sid} = par_frame->slot_f_{sid};"
                    );
                } else {
                    let _ = writeln!(s, "    {slot_cty} slot_buf_{sid};");
                    let _ = writeln!(s, "    memset(&slot_buf_{sid}, 0, sizeof(slot_buf_{sid}));");
                    if let MirType::Named(key) = ty
                        && let Some(l_idx) = self.find_layout_idx(key)
                        && self.layouts[l_idx].size > 0
                    {
                        let def_fn = format!(
                            "strata_default_{l_idx}_{}",
                            sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                        );
                        let _ = writeln!(s, "    slot_buf_{sid} = {def_fn}();");
                    }
                }
                let _ = writeln!(s, "    (void)slot_buf_{sid};");
            }

            for local in &f.locals {
                let lid = local.id.0;
                if !info.used_or_defined_locals.contains(&lid) {
                    continue;
                }
                if let Some(pk) = restrict_cols.get(&local.id) {
                    let cty = pk.c_type(&self.layout_c_names);
                    let _ = writeln!(s, "    {cty} BAM_RESTRICT col_{lid} = NULL;");
                    let _ = writeln!(s, "    (void)col_{lid};");
                } else if let Some(pk) = ptr_meta.get(&local.id) {
                    let cty = pk.c_type(&self.layout_c_names);
                    if live_slot_set.contains(&lid) {
                        let _ = writeln!(s, "    {cty} v_{lid} = ({cty})&slot_buf_{lid};");
                    } else {
                        let _ = writeln!(s, "    {cty} v_{lid} = NULL;");
                    }
                    let _ = writeln!(s, "    (void)v_{lid};");
                } else {
                    let eff_ty = local_types.get(&local.id).unwrap_or(&local.ty);
                    let cty = self.c_ty(eff_ty);
                    if self.is_aggregate_mir_ty(eff_ty) {
                        let _ = writeln!(s, "    {cty} v_{lid};");
                        let _ = writeln!(s, "    memset(&v_{lid}, 0, sizeof(v_{lid}));");
                    } else {
                        let init = self.c_zero_for_mir(eff_ty);
                        let _ = writeln!(s, "    {cty} v_{lid} = {init};");
                    }
                    let _ = writeln!(s, "    (void)v_{lid};");
                }
            }

            for &lid in &info.live_in_locals {
                let _ = writeln!(s, "    v_{lid} = par_frame->f_{lid};");
            }

            let _ = writeln!(s, "    goto bb_{};", info.chunk_hdr_bb);

            let mut sub_labels: HashSet<u32> = HashSet::new();
            sub_labels.insert(info.chunk_hdr_bb);
            sub_labels.insert(info.chunk_exit_bb);
            for &sb in &info.sub_blocks {
                let bpos = by_id[&sb];
                match &f.blocks[bpos].terminator {
                    Terminator::Goto(t) => {
                        sub_labels.insert(t.0);
                    }
                    Terminator::Branch {
                        then_bb, else_bb, ..
                    } => {
                        sub_labels.insert(then_bb.0);
                        sub_labels.insert(else_bb.0);
                    }
                    Terminator::Switch {
                        cases, default_bb, ..
                    } => {
                        for (_, t) in cases {
                            sub_labels.insert(t.0);
                        }
                        sub_labels.insert(default_bb.0);
                    }
                    Terminator::Return(_) => {}
                }
            }

            let par_fc = FnEmitCtx {
                parent: self,
                func: f,
                sys_idx: None,
                is_observer: false,
                is_migration: false,
                is_void_helper: false,
                is_helper: false,
                ptr_meta: ptr_meta.clone(),
                restrict_cols: restrict_cols.clone(),
                nonnull_cols: nonnull_cols.clone(),
                nonnull_ptrs: nonnull_ptrs.clone(),
                projected_fields: projected_fields.clone(),
                dirty_owners: dirty_owners.clone(),
                local_types: local_types.clone(),
                slot_types: slot_alloc_map.clone(),
                const_defs: const_defs.clone(),
                array_inits: array_inits.clone(),
                field_ptr_arrays: field_ptr_arrays.clone(),
                array_index_strides: array_index_strides.clone(),
                slot_mir_arrays: slot_mir_arrays.clone(),
                query_term_remaps: query_term_remaps.clone(),
                active_checkpoints: active_checkpoints.clone(),
                last_checkpoint: None,
                par_query_idx: Some(qi),
            };

            for &sb in &info.sub_blocks {
                let bb = &f.blocks[by_id[&sb]];
                if sub_labels.contains(&bb.id.0) {
                    let _ = writeln!(s, "bb_{}:;", bb.id.0);
                }
                for (s_idx, stmt) in bb.stmts.iter().enumerate() {
                    par_fc.emit_stmt_at(bb.id.0, s_idx, stmt, &mut s)?;
                }
                par_fc.emit_terminator(&bb.terminator, &mut s)?;
            }
            let _ = writeln!(s, "bb_{}:;", info.chunk_exit_bb);
            let _ = writeln!(s, "    return BAM_RESULT_OK;");
            let _ = writeln!(s, "}}\n");
        }

        match &f.kind {
            MirFnKind::HelperFn => {
                let _ = writeln!(s, "{} {{", self.helper_sig(f));
                let _ = writeln!(s, "    (void)state;");
                let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(s, "    (void)sys_ctx; (void)cmds_cache;");
                for i in 0..f.params.len() {
                    let _ = writeln!(s, "    (void)p_{i};");
                }
            }
            MirFnKind::Observer { .. } => {
                let name = sanitize_ident(&f.name);
                let _ = writeln!(
                    s,
                    "static BamResult strata_obs_{name}(BamEntity entity, const void* event_data, BamSystemCtx* sys_ctx, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(
                    s,
                    "    if (sys_ctx == NULL || state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                let _ = writeln!(
                    s,
                    "    (void)entity; (void)event_data; (void)sys_ctx; (void)cmds_cache;"
                );
            }
            MirFnKind::Migration { dst_layout, .. } => {
                let name = sanitize_ident(&f.name);
                let _ = writeln!(
                    s,
                    "static BamResult strata_mig_{name}(const void* src_row, void* dst_row, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamSystemCtx* sys_ctx = NULL;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(
                    s,
                    "    if (src_row == NULL || dst_row == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                let _ = writeln!(s, "    (void)state; (void)sys_ctx; (void)cmds_cache;");
                if let Some(l_idx) = self.find_layout_idx(dst_layout)
                    && self.layouts[l_idx].size > 0
                {
                    let cty = &self.layout_c_names[l_idx];
                    let def_fn = format!(
                        "strata_default_{l_idx}_{}",
                        sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                    );
                    let _ = writeln!(
                        s,
                        "    {{ {cty} _mig_def = {def_fn}(); memcpy(dst_row, &_mig_def, sizeof(_mig_def)); }}"
                    );
                }
            }
            _ => {
                let name = sanitize_ident(&f.name);
                let c_fn = format!("strata_sys_{name}");
                let _ = writeln!(
                    s,
                    "static BamResult {c_fn}(BamSystemCtx* sys_ctx, void* user_data) {{"
                );
                let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
                let _ = writeln!(s, "    BamCommands* cmds_cache = NULL;");
                let _ = writeln!(
                    s,
                    "    if (sys_ctx == NULL || state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                );
                if let Some(rs) = self.systems.iter().find(|rs| rs.c_fn_name == c_fn)
                    && let Some(ref rif) = rs.run_if_fn
                {
                    let _ = writeln!(
                        s,
                        "    if ({rif}(sys_ctx, user_data) != BAM_RESULT_OK) {{ return BAM_RESULT_OK; }}"
                    );
                }
                let _ = writeln!(s, "    (void)cmds_cache;");
            }
        }

        // Emit function-top C99 declarations (`BamIter*`, `SlotAlloc` buffers, spatial hit buffers, SSA locals).
        for sh_id in &spatial_hits_locals {
            let sid = sh_id.0;
            let _ = writeln!(s, "    StrataSpatialHits spatial_buf_{sid};");
            let _ = writeln!(
                s,
                "    memset(&spatial_buf_{sid}, 0, sizeof(spatial_buf_{sid}));"
            );
            let _ = writeln!(s, "    (void)spatial_buf_{sid};");
        }
        for qb in &f.query_bindings {
            let qi = qb.query_idx;
            let _ = writeln!(s, "    BamIter* iter_{qi} = NULL;");
            let _ = writeln!(s, "    size_t iter_{qi}_len = 0u;");
            let _ = writeln!(s, "    const BamEntity* iter_{qi}_ents = NULL;");
            let _ = writeln!(s, "    BamEntity iter_{qi}_cur_ent = BAM_ENTITY_NULL;");
            let _ = writeln!(
                s,
                "    (void)iter_{qi}; (void)iter_{qi}_len; (void)iter_{qi}_ents; (void)iter_{qi}_cur_ent;"
            );
        }
        for (slot_id, ty) in &slot_allocs {
            let slot_cty = self.c_ty(ty);
            let sid = slot_id.0;
            let _ = writeln!(s, "    {slot_cty} slot_buf_{sid};");
            let _ = writeln!(s, "    memset(&slot_buf_{sid}, 0, sizeof(slot_buf_{sid}));");
            if let MirType::Named(key) = ty
                && let Some(l_idx) = self.find_layout_idx(key)
                && self.layouts[l_idx].size > 0
            {
                let def_fn = format!(
                    "strata_default_{l_idx}_{}",
                    sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                );
                let _ = writeln!(s, "    slot_buf_{sid} = {def_fn}();");
            }
            let _ = writeln!(s, "    (void)slot_buf_{sid};");
        }

        for local in &f.locals {
            let lid = local.id.0;
            if let Some(pk) = restrict_cols.get(&local.id) {
                let cty = pk.c_type(&self.layout_c_names);
                let _ = writeln!(s, "    {cty} BAM_RESTRICT col_{lid} = NULL;");
                let _ = writeln!(s, "    (void)col_{lid};");
            } else if let Some(pk) = ptr_meta.get(&local.id) {
                let cty = pk.c_type(&self.layout_c_names);
                let _ = writeln!(s, "    {cty} v_{lid} = NULL;");
                let _ = writeln!(s, "    (void)v_{lid};");
            } else {
                let eff_ty = local_types.get(&local.id).unwrap_or(&local.ty);
                let cty = self.c_ty(eff_ty);
                if self.is_aggregate_mir_ty(eff_ty) {
                    let _ = writeln!(s, "    {cty} v_{lid};");
                    let _ = writeln!(s, "    memset(&v_{lid}, 0, sizeof(v_{lid}));");
                } else {
                    let init = self.c_zero_for_mir(eff_ty);
                    let _ = writeln!(s, "    {cty} v_{lid} = {init};");
                }
                let _ = writeln!(s, "    (void)v_{lid};");
            }
        }

        if is_helper {
            for (i, p) in f.params.iter().enumerate() {
                if let Some(ploc) = p.local {
                    let lhs = if restrict_cols.contains_key(&ploc) {
                        format!("col_{}", ploc.0)
                    } else {
                        format!("v_{}", ploc.0)
                    };
                    let _ = writeln!(s, "    {lhs} = p_{i};");
                }
            }
        }

        let sys_c_fn = format!("strata_sys_{}", sanitize_ident(&f.name));
        let obs_c_fn = format!("strata_obs_{}", sanitize_ident(&f.name));
        let sys_idx_opt = if !is_helper && !is_migration {
            if is_observer {
                self.observers
                    .iter()
                    .find(|ro| ro.c_fn_name == obs_c_fn)
                    .map(|ro| self.systems.len() + ro.obs_idx)
            } else {
                self.systems
                    .iter()
                    .find(|rs| rs.c_fn_name == sys_c_fn)
                    .map(|rs| rs.idx)
            }
        } else {
            None
        };

        if let Some(s_idx) = sys_idx_opt {
            let comp_n = self.components.len().max(1);
            let mut stream_read_idx = 0usize;
            for p in &f.params {
                if p.kind == HirParamKind::StreamIn
                    && let Some(ploc) = p.local
                {
                    let stream_op = f
                        .stream_ops
                        .iter()
                        .filter(|op| op.kind == MirStreamOpKind::StreamRead)
                        .nth(stream_read_idx);
                    stream_read_idx += 1;
                    if let Some(op) = stream_op
                        && let Some(c_idx) = self
                            .find_comp_idx(&op.canonical_stream)
                            .or_else(|| self.find_comp_idx(&op.stream))
                        && let Some(l_idx) = self.components[c_idx].layout_idx
                    {
                        let lid = ploc.0;
                        let cty = &self.layout_c_names[l_idx];
                        let _ = writeln!(s, "    {cty} stream_buf_{lid};");
                        let _ = writeln!(
                            s,
                            "    memset(&stream_buf_{lid}, 0, sizeof(stream_buf_{lid}));"
                        );
                        let _ = writeln!(s, "    v_{lid} = (const void*)&stream_buf_{lid};");
                        let _ = writeln!(
                            s,
                            "    if (sys_ctx != NULL && state->res_flags[{c_idx}] == 2u && state->sys_msg_q[{s_idx}] != UINT32_MAX && state->sys_msg_ti[{s_idx}u * {comp_n}u + {c_idx}u] != UINT32_MAX && state->api->sys_query != NULL && state->api->msg_read_batch != NULL) {{"
                        );
                        let _ = writeln!(s, "        BamIter* msg_it = NULL;");
                        let _ = writeln!(
                            s,
                            "        if (state->api->sys_query(sys_ctx, state->sys_msg_q[{s_idx}], &msg_it) == BAM_RESULT_OK && msg_it != NULL) {{"
                        );
                        let _ = writeln!(s, "            {cty} msg_batch[16];");
                        let _ = writeln!(s, "            size_t msg_got = 0u;");
                        let _ = writeln!(s, "            do {{");
                        let _ = writeln!(s, "                msg_got = 0u;");
                        let _ = writeln!(
                            s,
                            "                if (state->api->msg_read_batch(msg_it, state->sys_msg_ti[{s_idx}u * {comp_n}u + {c_idx}u], (uint8_t*)msg_batch, 16u, &msg_got) != BAM_RESULT_OK) {{ break; }}"
                        );
                        let _ = writeln!(
                            s,
                            "                if (msg_got > 0u) {{ stream_buf_{lid} = msg_batch[msg_got - 1u]; }}"
                        );
                        let _ = writeln!(s, "            }} while (msg_got == 16u);");
                        let _ = writeln!(s, "        }}");
                        let _ = writeln!(s, "    }}");
                        if self.layouts[l_idx].size > 0 {
                            let _ = writeln!(
                                s,
                                "    else if (state->res_flags[{c_idx}] != 2u && state->mod_stream_has_{c_idx} != 0u) {{\n        stream_buf_{lid} = state->mod_stream_last_{c_idx};\n    }}"
                            );
                        }
                    }
                }
            }
        }

        if f.blocks.is_empty() {
            if is_void_helper {
                let _ = writeln!(s, "    return;");
            } else if is_helper {
                let z = self.c_zero_for_mir(&f.ret_ty);
                let _ = writeln!(s, "    return {z};");
            } else {
                let _ = writeln!(s, "    return BAM_RESULT_OK;");
            }
            let _ = writeln!(s, "}}");
            return Ok(s);
        }

        if label_targets.contains(&0) {
            let _ = writeln!(s, "    goto bb_0;");
        }

        let fc = FnEmitCtx {
            parent: self,
            func: f,
            sys_idx: sys_idx_opt,
            is_observer,
            is_migration,
            is_void_helper,
            is_helper,
            ptr_meta,
            restrict_cols,
            nonnull_cols,
            nonnull_ptrs,
            projected_fields,
            dirty_owners,
            local_types,
            slot_types: slot_alloc_map,
            const_defs,
            array_inits,
            field_ptr_arrays,
            array_index_strides,
            slot_mir_arrays,
            query_term_remaps,
            active_checkpoints,
            last_checkpoint: None,
            par_query_idx: None,
        };

        for bb in &f.blocks {
            if !reachable.contains(&bb.id.0) || skip_blocks.contains(&bb.id.0) {
                continue;
            }
            if label_targets.contains(&bb.id.0) {
                let _ = writeln!(s, "bb_{}:;", bb.id.0);
            }
            if let Some(spec) = par_tasks.get(&bb.id.0) {
                let prefix_len = bb.stmts.len().saturating_sub(1);
                for (s_idx, stmt) in bb.stmts[..prefix_len].iter().enumerate() {
                    fc.emit_stmt_at(bb.id.0, s_idx, stmt, &mut s)?;
                }
                let qi = spec.info.query_idx;
                let par_slot = if spec.info.is_readonly {
                    "par_for_each_chunk_readonly"
                } else {
                    "par_for_each_chunk"
                };
                let _ = writeln!(s, "    {{");
                let _ = writeln!(
                    s,
                    "        if (iter_{qi} == NULL && sys_ctx != NULL && state->api->sys_query != NULL) {{"
                );
                let _ = writeln!(
                    s,
                    "            BamResult q_rc = state->api->sys_query(sys_ctx, {qi}u, &iter_{qi});"
                );
                let _ = writeln!(
                    s,
                    "            if (q_rc != BAM_RESULT_OK) {{ return q_rc; }}"
                );
                let _ = writeln!(s, "        }}");
                let _ = writeln!(s, "        if (iter_{qi} != NULL) {{");
                let _ = writeln!(s, "            {} par_frame;", spec.frame_struct);
                let _ = writeln!(s, "            memset(&par_frame, 0, sizeof(par_frame));");
                let _ = writeln!(s, "            par_frame.state = state;");
                for &lid in &spec.info.live_in_locals {
                    let _ = writeln!(s, "            par_frame.f_{lid} = v_{lid};");
                }
                for &sid in &spec.info.live_in_slots {
                    let _ = writeln!(s, "            par_frame.slot_f_{sid} = slot_buf_{sid};");
                }
                let _ = writeln!(s, "            {{");
                let _ = writeln!(s, "                BamResult par_rc = BAM_RESULT_OK;");
                let _ = writeln!(s, "                if (state->api->{par_slot} != NULL) {{");
                let _ = writeln!(
                    s,
                    "                    par_rc = state->api->{par_slot}(iter_{qi}, {}, &par_frame);",
                    spec.task_fn
                );
                let _ = writeln!(s, "                }} else {{");
                let _ = writeln!(
                    s,
                    "                    par_rc = {}(iter_{qi}, &par_frame);",
                    spec.task_fn
                );
                let _ = writeln!(s, "                }}");
                let _ = writeln!(
                    s,
                    "                if (par_rc != BAM_RESULT_OK) {{ return par_rc; }}"
                );
                let _ = writeln!(s, "            }}");
                let _ = writeln!(s, "        }}");
                let _ = writeln!(s, "        goto bb_{};", spec.info.chunk_exit_bb);
                let _ = writeln!(s, "    }}");
            } else {
                for (s_idx, stmt) in bb.stmts.iter().enumerate() {
                    fc.emit_stmt_at(bb.id.0, s_idx, stmt, &mut s)?;
                }
                fc.emit_terminator(&bb.terminator, &mut s)?;
            }
        }

        let _ = writeln!(s, "}}");
        Ok(s)
    }
}

fn compute_active_checkpoints(f: &MirFunction) -> HashMap<(u32, usize), LocalId> {
    let mut active: HashMap<(u32, usize), LocalId> = HashMap::new();
    if f.blocks.is_empty() {
        return active;
    }
    let by_id: HashMap<u32, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.0, i))
        .collect();
    let mut merge_closes: HashMap<u32, LocalId> = HashMap::new();
    for bb in &f.blocks {
        for stmt in &bb.stmts {
            if matches!(stmt.inst, Inst::CmdCheckpoint)
                && let Some(cp) = stmt.dst
            {
                let mut q: std::collections::VecDeque<(u32, usize)> =
                    std::collections::VecDeque::new();
                let mut seen: HashSet<(u32, usize)> = HashSet::new();
                let push_succs =
                    |b: &BasicBlock,
                     depth: usize,
                     q: &mut std::collections::VecDeque<(u32, usize)>| {
                        match &b.terminator {
                            Terminator::Goto(t) => q.push_back((t.0, depth)),
                            Terminator::Branch {
                                then_bb, else_bb, ..
                            } => {
                                q.push_back((then_bb.0, depth));
                                q.push_back((else_bb.0, depth));
                            }
                            Terminator::Switch {
                                cases, default_bb, ..
                            } => {
                                for (_, t) in cases {
                                    q.push_back((t.0, depth));
                                }
                                q.push_back((default_bb.0, depth));
                            }
                            Terminator::Return(_) => {}
                        }
                    };
                push_succs(bb, 0, &mut q);
                while let Some((bid, mut depth)) = q.pop_front() {
                    if !seen.insert((bid, depth)) {
                        continue;
                    }
                    let Some(&bidx) = by_id.get(&bid) else {
                        continue;
                    };
                    let cur = &f.blocks[bidx];
                    if cur.label == "atomic_merge" && bid != bb.id.0 {
                        if depth == 0 {
                            merge_closes.insert(bid, cp);
                            continue;
                        }
                        depth -= 1;
                    }
                    let ckpts_in_cur = cur
                        .stmts
                        .iter()
                        .filter(|st| matches!(st.inst, Inst::CmdCheckpoint))
                        .count();
                    depth += ckpts_in_cur;
                    push_succs(cur, depth, &mut q);
                }
            }
        }
    }

    let mut visited_entry: HashMap<u32, Vec<LocalId>> = HashMap::new();
    let mut work: std::collections::VecDeque<(u32, Vec<LocalId>)> =
        std::collections::VecDeque::new();
    work.push_back((f.blocks[0].id.0, Vec::new()));
    while let Some((bid, mut stack)) = work.pop_front() {
        if let Some(&closed_cp) = merge_closes.get(&bid)
            && stack.last() == Some(&closed_cp)
        {
            stack.pop();
        }
        if visited_entry.get(&bid) == Some(&stack) {
            continue;
        }
        visited_entry.insert(bid, stack.clone());
        let Some(&bidx) = by_id.get(&bid) else {
            continue;
        };
        let bb = &f.blocks[bidx];
        for (stmt_idx, stmt) in bb.stmts.iter().enumerate() {
            if let Some(&top) = stack.last() {
                active.insert((bid, stmt_idx), top);
            }
            match &stmt.inst {
                Inst::CmdCheckpoint => {
                    if let Some(cp) = stmt.dst {
                        stack.push(cp);
                    }
                }
                Inst::CmdRollback { checkpoint } => {
                    if let Some(pos) = stack.iter().rposition(|c| c == checkpoint) {
                        stack.truncate(pos);
                    }
                }
                _ => {}
            }
        }
        match &bb.terminator {
            Terminator::Goto(t) => work.push_back((t.0, stack)),
            Terminator::Branch {
                then_bb, else_bb, ..
            } => {
                work.push_back((then_bb.0, stack.clone()));
                work.push_back((else_bb.0, stack));
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, t) in cases {
                    work.push_back((t.0, stack.clone()));
                }
                work.push_back((default_bb.0, stack));
            }
            Terminator::Return(_) => {}
        }
    }
    active
}

pub(super) fn analyze_cfg(blocks: &[BasicBlock]) -> (HashSet<u32>, HashSet<u32>) {
    let mut reachable: HashSet<u32> = HashSet::new();
    let mut label_targets: HashSet<u32> = HashSet::new();
    let by_id: HashMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.0, i))
        .collect();
    if let Some(&entry_idx) = by_id.get(&0) {
        let mut q = VecDeque::new();
        reachable.insert(0);
        q.push_back(entry_idx);
        while let Some(bi) = q.pop_front() {
            let bb = &blocks[bi];
            let mut push_t = |tid: BlockId| {
                label_targets.insert(tid.0);
                if reachable.insert(tid.0)
                    && let Some(&next_idx) = by_id.get(&tid.0)
                {
                    q.push_back(next_idx);
                }
            };
            match &bb.terminator {
                Terminator::Goto(t) => push_t(*t),
                Terminator::Branch {
                    then_bb, else_bb, ..
                } => {
                    push_t(*then_bb);
                    push_t(*else_bb);
                }
                Terminator::Switch {
                    cases, default_bb, ..
                } => {
                    for (_, t) in cases {
                        push_t(*t);
                    }
                    push_t(*default_bb);
                }
                Terminator::Return(_) => {}
            }
        }
    }
    (reachable, label_targets)
}

pub(super) fn c99_chunk_dominated_blocks(
    blocks: &[BasicBlock],
    reachable: &HashSet<u32>,
) -> HashMap<u32, HashSet<u32>> {
    let by_id: HashMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.0, i))
        .collect();
    let mut chunk_edges_by_q: HashMap<u32, HashSet<(u32, u32)>> = HashMap::new();
    for bb in blocks {
        if !reachable.contains(&bb.id.0) {
            continue;
        }
        if let Terminator::Branch { cond, then_bb, .. } = bb.terminator
            && then_bb.0 != bb.id.0
        {
            for st in &bb.stmts {
                if let Inst::IterNextChunk { query_idx } = st.inst
                    && st.dst == Some(cond)
                {
                    chunk_edges_by_q
                        .entry(query_idx)
                        .or_default()
                        .insert((bb.id.0, then_bb.0));
                }
            }
        }
    }
    let mut out: HashMap<u32, HashSet<u32>> = HashMap::new();
    let Some(&entry_idx) = by_id.get(&0) else {
        return out;
    };
    for (qi, blocked_edges) in chunk_edges_by_q {
        let mut reach_without: HashSet<u32> = HashSet::new();
        let mut q = VecDeque::new();
        reach_without.insert(0);
        q.push_back(entry_idx);
        while let Some(bi) = q.pop_front() {
            let bb = &blocks[bi];
            let mut push_t = |tid: BlockId| {
                if !blocked_edges.contains(&(bb.id.0, tid.0))
                    && reach_without.insert(tid.0)
                    && let Some(&next_idx) = by_id.get(&tid.0)
                {
                    q.push_back(next_idx);
                }
            };
            match &bb.terminator {
                Terminator::Goto(t) => push_t(*t),
                Terminator::Branch {
                    then_bb, else_bb, ..
                } => {
                    push_t(*then_bb);
                    push_t(*else_bb);
                }
                Terminator::Switch {
                    cases, default_bb, ..
                } => {
                    for (_, t) in cases {
                        push_t(*t);
                    }
                    push_t(*default_bb);
                }
                Terminator::Return(_) => {}
            }
        }
        let dom: HashSet<u32> = reachable
            .iter()
            .copied()
            .filter(|id| !reach_without.contains(id))
            .collect();
        out.insert(qi, dom);
    }
    out
}

pub(super) struct C99ParSubCfgInfo {
    query_idx: u32,
    is_readonly: bool,
    chunk_hdr_bb: u32,
    chunk_exit_bb: u32,
    sub_blocks: Vec<u32>,
    live_in_locals: Vec<u32>,
    live_in_slots: Vec<u32>,
    allocs_inside: HashSet<u32>,
    used_or_defined_locals: HashSet<u32>,
}

pub(super) struct C99ParTaskSpec {
    info: C99ParSubCfgInfo,
    frame_struct: String,
    task_fn: String,
}

pub(super) fn c99_helper_is_par_safe(
    callee: &str,
    helper_by_name: &HashMap<String, usize>,
    mir_functions: &[MirFunction],
    visited: &mut HashSet<String>,
) -> bool {
    if !visited.insert(callee.to_owned()) {
        return true;
    }
    let Some(&h_idx) = helper_by_name.get(callee) else {
        return true;
    };
    let hf = &mir_functions[h_idx];
    for hbb in &hf.blocks {
        for hs in &hbb.stmts {
            match &hs.inst {
                Inst::ResRead { .. }
                | Inst::ResWrite { .. }
                | Inst::CmdSpawn { .. }
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
                | Inst::IterCount { .. }
                | Inst::IterUpCascade { .. }
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
                | Inst::TaskStep { .. } => return false,
                Inst::Call { callee: nested, .. }
                    if !c99_helper_is_par_safe(nested, helper_by_name, mir_functions, visited) =>
                {
                    return false;
                }
                _ => {}
            }
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(super) fn c99_find_par_subcfg(
    func: &MirFunction,
    par_stmt_bb_id: u32,
    par_stmt_idx: usize,
    query_idx: u32,
    is_readonly: bool,
    deterministic_order: bool,
    ptr_meta: &HashMap<LocalId, PtrKind>,
    restrict_cols: &HashMap<LocalId, PtrKind>,
    slot_alloc_map: &HashMap<LocalId, MirType>,
    spatial_hits_locals: &[LocalId],
    dirty_owners: &HashMap<(u32, u32), Vec<(u32, u32)>>,
    local_types: &HashMap<LocalId, MirType>,
    helper_by_name: &HashMap<String, usize>,
    mir_functions: &[MirFunction],
) -> Option<C99ParSubCfgInfo> {
    if is_readonly
        && (deterministic_order
            || func
                .query_bindings
                .iter()
                .find(|qb| qb.query_idx == query_idx)
                .is_some_and(|qb| qb.terms.iter().any(|t| t.mode.is_mutable())))
    {
        return None;
    }
    let by_id: HashMap<u32, usize> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.0, i))
        .collect();
    let par_pos = *by_id.get(&par_stmt_bb_id)?;
    if par_stmt_idx + 1 != func.blocks[par_pos].stmts.len() {
        return None;
    }
    let chunk_hdr_bb = match func.blocks[par_pos].terminator {
        Terminator::Goto(b) => b.0,
        _ => return None,
    };
    let chunk_hdr_pos = *by_id.get(&chunk_hdr_bb)?;
    let hdr_block = &func.blocks[chunk_hdr_pos];
    let has_next_chunk = hdr_block
        .stmts
        .iter()
        .any(|st| matches!(st.inst, Inst::IterNextChunk { query_idx: qi } if qi == query_idx));
    if !has_next_chunk {
        return None;
    }
    let (then_bb, chunk_exit_bb) = match hdr_block.terminator {
        Terminator::Branch {
            then_bb, else_bb, ..
        } => (then_bb.0, else_bb.0),
        _ => return None,
    };
    if then_bb == chunk_hdr_bb || then_bb == chunk_exit_bb || chunk_exit_bb == 0 {
        return None;
    }

    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: Vec<u32> = vec![then_bb];
    let mut sub_blocks: Vec<u32> = Vec::new();
    visited.insert(chunk_hdr_bb);
    while let Some(bid) = queue.pop() {
        if bid == chunk_exit_bb {
            return None;
        }
        if !visited.insert(bid) {
            continue;
        }
        let bpos = *by_id.get(&bid)?;
        sub_blocks.push(bid);
        match &func.blocks[bpos].terminator {
            Terminator::Goto(dst) => queue.push(dst.0),
            Terminator::Branch {
                then_bb: a,
                else_bb: b,
                ..
            } => {
                queue.push(a.0);
                queue.push(b.0);
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, c) in cases {
                    queue.push(c.0);
                }
                queue.push(default_bb.0);
            }
            Terminator::Return(_) => return None,
        }
    }
    sub_blocks.insert(0, chunk_hdr_bb);
    let sub_set: HashSet<u32> = sub_blocks.iter().copied().collect();
    if sub_set.contains(&par_stmt_bb_id) || sub_set.contains(&chunk_exit_bb) {
        return None;
    }

    // Verify no block outside `sub_set` jumps into `sub_set` (other than `par_stmt_bb_id -> chunk_hdr_bb`).
    for bb in &func.blocks {
        if sub_set.contains(&bb.id.0) {
            continue;
        }
        let check_target = |t: BlockId| -> bool {
            if sub_set.contains(&t.0) {
                bb.id.0 == par_stmt_bb_id && t.0 == chunk_hdr_bb
            } else {
                true
            }
        };
        match &bb.terminator {
            Terminator::Goto(t) => {
                if !check_target(*t) {
                    return None;
                }
            }
            Terminator::Branch {
                then_bb, else_bb, ..
            } => {
                if !check_target(*then_bb) || !check_target(*else_bb) {
                    return None;
                }
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, c) in cases {
                    if !check_target(*c) {
                        return None;
                    }
                }
                if !check_target(*default_bb) {
                    return None;
                }
            }
            Terminator::Return(_) => {}
        }
    }

    let mut defined_inside: HashSet<u32> = HashSet::new();
    let mut allocs_inside: HashSet<u32> = HashSet::new();
    let mut dirty_init_inside: HashSet<u32> = HashSet::new();
    for &bid in &sub_blocks {
        let bb = &func.blocks[by_id[&bid]];
        for s in &bb.stmts {
            if let Some(d) = s.dst {
                defined_inside.insert(d.0);
                if matches!(s.inst, Inst::SlotAlloc { .. }) {
                    allocs_inside.insert(d.0);
                }
            }
            if let Inst::DirtyRunInit { run_start, run_len } = &s.inst {
                defined_inside.insert(run_start.0);
                defined_inside.insert(run_len.0);
                dirty_init_inside.insert(run_start.0);
                dirty_init_inside.insert(run_len.0);
            }
        }
    }

    let spatial_set: HashSet<u32> = spatial_hits_locals.iter().map(|l| l.0).collect();

    for &bid in &sub_blocks {
        let bb = &func.blocks[by_id[&bid]];
        for s in &bb.stmts {
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
                | Inst::IterCount { .. }
                | Inst::IterUpCascade { .. }
                | Inst::IterReset { .. }
                | Inst::ResRead { .. }
                | Inst::ResWrite { .. }
                | Inst::ReduceInit { .. }
                | Inst::ReduceAccum { .. }
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
                | Inst::TaskStep { .. } => return None,
                Inst::IterColWrite { .. }
                | Inst::IterColWriteUntracked { .. }
                | Inst::IterColRowsWrite { .. }
                    if is_readonly =>
                {
                    return None;
                }
                Inst::IterNextChunk { query_idx: qi }
                | Inst::IterChunkLen { query_idx: qi }
                | Inst::IterEntities { query_idx: qi }
                | Inst::IterColRead { query_idx: qi, .. }
                | Inst::IterColWrite { query_idx: qi, .. }
                | Inst::IterColWriteUntracked { query_idx: qi, .. }
                | Inst::IterColRowsRead { query_idx: qi, .. }
                | Inst::IterColRowsWrite { query_idx: qi, .. }
                    if *qi != query_idx =>
                {
                    return None;
                }
                Inst::IterMarkChangedRange {
                    query_idx: qi,
                    run_start,
                    run_len,
                    ..
                } => {
                    if *qi != query_idx
                        || !dirty_init_inside.contains(&run_start.0)
                        || !dirty_init_inside.contains(&run_len.0)
                    {
                        return None;
                    }
                }
                Inst::DirtyRunRecordRow {
                    run_start, run_len, ..
                } => {
                    if !dirty_init_inside.contains(&run_start.0)
                        || !dirty_init_inside.contains(&run_len.0)
                    {
                        return None;
                    }
                    if let Some(owners) = dirty_owners.get(&(run_start.0, run_len.0))
                        && owners.iter().any(|&(qi, _)| qi != query_idx)
                    {
                        return None;
                    }
                }
                Inst::SlotStore { slot, .. } if !allocs_inside.contains(&slot.0) => return None,
                Inst::Call { callee, .. } => {
                    let mut visited_helpers = HashSet::new();
                    if !c99_helper_is_par_safe(
                        callee,
                        helper_by_name,
                        mir_functions,
                        &mut visited_helpers,
                    ) {
                        return None;
                    }
                }
                _ => {}
            }
        }
    }

    let mut live_in_locals: Vec<u32> = Vec::new();
    let mut live_in_slots: Vec<u32> = Vec::new();
    let mut live_seen: HashSet<u32> = HashSet::new();
    let mut used_or_defined_locals: HashSet<u32> = defined_inside.clone();

    let slot_only_loaded_inside = |slot_r: u32| -> bool {
        for &bid in &sub_blocks {
            let bb = &func.blocks[by_id[&bid]];
            for s in &bb.stmts {
                let reads = c99_inst_read_locals(&s.inst);
                if reads.contains(&slot_r)
                    && !matches!(s.inst, Inst::SlotLoad { slot } if slot.0 == slot_r)
                {
                    return false;
                }
            }
            if c99_term_read_locals(&bb.terminator).contains(&slot_r) {
                return false;
            }
        }
        true
    };

    let mut record_read = |r: u32| -> bool {
        used_or_defined_locals.insert(r);
        if !defined_inside.contains(&r) && live_seen.insert(r) {
            let lid = LocalId(r);
            if let Some(st_ty) = slot_alloc_map.get(&lid) {
                if matches!(
                    st_ty,
                    MirType::Ptr | MirType::MutPtr | MirType::QueryIter | MirType::Checkpoint
                ) || !slot_only_loaded_inside(r)
                {
                    return false;
                }
                live_in_slots.push(r);
                return true;
            }
            if ptr_meta.contains_key(&lid)
                || restrict_cols.contains_key(&lid)
                || spatial_set.contains(&r)
            {
                return false;
            }
            let eff_ty = local_types
                .get(&lid)
                .unwrap_or_else(|| &func.locals[r as usize].ty);
            if matches!(
                eff_ty,
                MirType::Ptr | MirType::MutPtr | MirType::QueryIter | MirType::Checkpoint
            ) {
                return false;
            }
            live_in_locals.push(r);
        }
        true
    };

    for &bid in &sub_blocks {
        let bb = &func.blocks[by_id[&bid]];
        for s in &bb.stmts {
            for r in c99_inst_read_locals(&s.inst) {
                if !record_read(r) {
                    return None;
                }
            }
        }
        for r in c99_term_read_locals(&bb.terminator) {
            if !record_read(r) {
                return None;
            }
        }
    }

    // Verify no local defined inside `sub_set` is read outside `sub_set`.
    for bb in &func.blocks {
        if sub_set.contains(&bb.id.0) {
            continue;
        }
        for s in &bb.stmts {
            for r in c99_inst_read_locals(&s.inst) {
                if defined_inside.contains(&r) {
                    return None;
                }
            }
        }
        for r in c99_term_read_locals(&bb.terminator) {
            if defined_inside.contains(&r) {
                return None;
            }
        }
    }

    Some(C99ParSubCfgInfo {
        query_idx,
        is_readonly,
        chunk_hdr_bb,
        chunk_exit_bb,
        sub_blocks,
        live_in_locals,
        live_in_slots,
        allocs_inside,
        used_or_defined_locals,
    })
}

pub(super) fn c99_inst_read_locals(inst: &Inst) -> Vec<u32> {
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

pub(super) fn c99_term_read_locals(term: &Terminator) -> Vec<u32> {
    match term {
        Terminator::Return(Some(v)) => vec![v.0],
        Terminator::Branch { cond, .. } => vec![cond.0],
        Terminator::Switch { scrutinee, .. } => vec![scrutinee.0],
        Terminator::Return(None) | Terminator::Goto(_) => Vec::new(),
    }
}

pub(super) fn collect_inst_components(inst: &Inst, out: &mut BTreeSet<String>) {
    match inst {
        Inst::IterColRead { storage_key, .. }
        | Inst::IterColWrite { storage_key, .. }
        | Inst::IterColWriteUntracked { storage_key, .. }
        | Inst::IterColRowsRead { storage_key, .. }
        | Inst::IterColRowsWrite { storage_key, .. }
        | Inst::EntityGet { storage_key, .. }
        | Inst::EntityGetMut { storage_key, .. } => {
            out.insert(storage_key.clone());
        }
        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
            out.insert(resource.clone());
        }
        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
            out.insert(component.clone());
        }
        Inst::CmdSpawn { components, .. }
        | Inst::CmdSpawnBatch { components, .. }
        | Inst::SpawnBatchPush { components, .. } => {
            for (c, _) in components {
                out.insert(c.clone());
            }
        }
        Inst::SpawnBatchBegin { components, .. } => {
            for c in components {
                out.insert(c.clone());
            }
        }
        Inst::CmdDespawnAll { filter } => {
            for tok in filter.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let inner = tok
                    .strip_prefix("Without<")
                    .or_else(|| tok.strip_prefix("With<"))
                    .and_then(|r| r.strip_suffix('>'))
                    .unwrap_or(tok)
                    .trim();
                if !inner.is_empty() {
                    out.insert(inner.to_string());
                }
            }
        }
        Inst::CmdTrigger { event, .. } => {
            out.insert(event.clone());
        }
        Inst::StreamEmit { stream, .. } => {
            out.insert(stream.clone());
        }
        _ => {}
    }
}

pub(super) fn mir_const_is_all_zero(v: &MirConstVal) -> bool {
    match v {
        MirConstVal::Unit => true,
        MirConstVal::Bool(b) => !*b,
        MirConstVal::Int(n) => *n == 0,
        MirConstVal::Float(f) => *f == 0.0 && f.is_sign_positive(),
        MirConstVal::Vec2(arr) => arr.iter().all(|f| *f == 0.0 && f.is_sign_positive()),
        MirConstVal::Vec3(arr) => arr.iter().all(|f| *f == 0.0 && f.is_sign_positive()),
        MirConstVal::Vec4(arr) => arr.iter().all(|f| *f == 0.0 && f.is_sign_positive()),
        MirConstVal::Array(elems) => elems.iter().all(mir_const_is_all_zero),
        MirConstVal::Struct { fields, .. } => {
            fields.iter().all(|(_, fv)| mir_const_is_all_zero(fv))
        }
        MirConstVal::String(_) => false,
    }
}

pub(super) fn mir_const_vals_match(a: &MirConstVal, b: &MirConstVal) -> bool {
    match (a, b) {
        (MirConstVal::Unit, MirConstVal::Unit) => true,
        (MirConstVal::Bool(x), MirConstVal::Bool(y)) => x == y,
        (MirConstVal::Int(x), MirConstVal::Int(y)) => x == y,
        (MirConstVal::Float(x), MirConstVal::Float(y)) => (x - y).abs() <= 1e-12,
        (MirConstVal::Int(i), MirConstVal::Float(f))
        | (MirConstVal::Float(f), MirConstVal::Int(i)) => ((*i as f64) - f).abs() <= 1e-12,
        (MirConstVal::Vec2(x), MirConstVal::Vec2(y)) => x == y,
        (MirConstVal::Vec3(x), MirConstVal::Vec3(y)) => x == y,
        (MirConstVal::Vec4(x), MirConstVal::Vec4(y)) => x == y,
        (MirConstVal::String(x), MirConstVal::String(y)) => x == y,
        (MirConstVal::Array(xs), MirConstVal::Array(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys.iter())
                    .all(|(x, y)| mir_const_vals_match(x, y))
        }
        (MirConstVal::Struct { fields: fx, .. }, MirConstVal::Struct { fields: fy, .. }) => {
            fx.len() == fy.len()
                && fx.iter().all(|(k, vx)| {
                    fy.iter()
                        .any(|(ky, vy)| k == ky && mir_const_vals_match(vx, vy))
                })
        }
        _ => false,
    }
}
