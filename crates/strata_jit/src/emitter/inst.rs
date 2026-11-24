//! MIR statement & instruction lowering (`FnLowerer::lower_stmt` and domain helpers).

use super::*;

impl<'a, 'b, 'f> FnLowerer<'a, 'b, 'f> {
    pub(super) fn lower_stmt(&mut self, stmt: &MirStmt) -> Result<(), JitError> {
        let dst = stmt.dst;
        let ptr_ty = self.ctx.ptr_ty;

        match &stmt.inst {
            Inst::ConstInt { value } => {
                if let Some(d) = dst {
                    self.const_defs.insert(d.0, MirConstVal::Int(*value));
                    let ty = self.expected_cl_ty(d);
                    let mty = self.effective_local_mir_ty(d).clone();
                    let v = match mty {
                        MirType::Bool => self.b.ins().iconst(types::I8, i64::from(*value != 0)),
                        MirType::F32 => self.b.ins().f32const(*value as f32),
                        MirType::F64 => self.b.ins().f64const(*value as f64),
                        MirType::Fix32 => {
                            let q = (*value).saturating_mul(65_536) as i32;
                            self.b.ins().iconst(types::I32, i64::from(q))
                        }
                        MirType::Fix64 => {
                            let q = value.wrapping_shl(32);
                            self.b.ins().iconst(types::I64, q)
                        }
                        _ if ty == types::F32 => self.b.ins().f32const(*value as f32),
                        _ if ty == types::F64 => self.b.ins().f64const(*value as f64),
                        _ => self.b.ins().iconst(ty, *value),
                    };
                    self.def_scalar_typed(d, v);
                }
            }
            Inst::ConstFloat { value } => {
                if let Some(d) = dst {
                    self.const_defs.insert(d.0, MirConstVal::Float(*value));
                    match self.mir_fn.locals[d.0 as usize].ty {
                        MirType::F64 => {
                            let v = self.b.ins().f64const(*value);
                            self.def_scalar_typed(d, v);
                        }
                        MirType::Fix32 => {
                            let q = if value.is_finite() {
                                (*value * 65_536.0).round() as i32
                            } else {
                                0
                            };
                            let v = self.b.ins().iconst(types::I32, i64::from(q));
                            self.def_scalar_typed(d, v);
                        }
                        MirType::Fix64 => {
                            let q = if value.is_finite() {
                                (*value * 4_294_967_296.0).round() as i64
                            } else {
                                0
                            };
                            let v = self.b.ins().iconst(types::I64, q);
                            self.def_scalar_typed(d, v);
                        }
                        _ => {
                            let v = self.b.ins().f32const(*value as f32);
                            self.def_scalar_typed(d, v);
                        }
                    }
                }
            }
            Inst::ConstBool { value } => {
                if let Some(d) = dst {
                    self.const_defs.insert(d.0, MirConstVal::Bool(*value));
                    let v = self.b.ins().iconst(types::I8, i64::from(*value));
                    self.def_scalar_typed(d, v);
                }
            }
            Inst::ConstVec { dims, values } => {
                if let Some(d) = dst {
                    let cv = match *dims {
                        2 => MirConstVal::Vec2([values[0], values[1]]),
                        3 => MirConstVal::Vec3([values[0], values[1], values[2]]),
                        _ => MirConstVal::Vec4(*values),
                    };
                    self.const_defs.insert(d.0, cv);
                    let arr = if is_ivec_mir_ty(self.effective_local_mir_ty(d)) {
                        [
                            self.b.ins().iconst(types::I32, values[0] as i64),
                            self.b.ins().iconst(types::I32, values[1] as i64),
                            self.b.ins().iconst(types::I32, values[2] as i64),
                            self.b.ins().iconst(types::I32, values[3] as i64),
                        ]
                    } else {
                        [
                            self.b.ins().f32const(values[0] as f32),
                            self.b.ins().f32const(values[1] as f32),
                            self.b.ins().f32const(values[2] as f32),
                            self.b.ins().f32const(values[3] as f32),
                        ]
                    };
                    self.def_vec(d, arr);
                }
            }
            Inst::ConstString { value } => {
                if let Some(d) = dst {
                    let cap = value.len().max(16);
                    let blob_id = self.ctx.intern_inline_str_blob(value, cap)?;
                    self.const_string_texts.insert(d.0, value.clone());
                    self.ptr_pointee_tys
                        .insert(d.0, MirType::Named(format!("InlineStr<{cap}>")));
                    let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
                    let addr = self.b.ins().symbol_value(ptr_ty, gv);
                    self.def_scalar_typed(d, addr);
                }
            }
            Inst::Copy { val } => {
                if let Some(d) = dst {
                    self.copy_local(*val, d);
                    if let Some(schema) = self.batch_schemas.get(&val.0).cloned() {
                        self.batch_schemas.insert(d.0, schema);
                    }
                    if let Some(cv) = self.const_defs.get(&val.0).cloned() {
                        self.const_defs.insert(d.0, cv);
                    }
                    if let Some(elems) = self.array_elems.get(&val.0).cloned() {
                        self.array_elems.insert(d.0, elems);
                    }
                    if let Some(len) = self.array_ptr_lens.get(&val.0).copied() {
                        self.array_ptr_lens.insert(d.0, len);
                    }
                    if let Some(et) = self.ptr_elem_tys.get(&val.0).cloned() {
                        self.ptr_elem_tys.insert(d.0, et);
                    }
                    if let Some(pt) = self.ptr_pointee_tys.get(&val.0).cloned() {
                        self.ptr_pointee_tys.insert(d.0, pt);
                    }
                }
            }
            Inst::SlotAlloc { .. } => {
                if let Some(d) = dst
                    && let Some(&slot) = self.agg_slots.get(&d.0)
                {
                    let p = self.b.ins().stack_addr(ptr_ty, slot, 0);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::SlotLoad { slot } => {
                if let Some(d) = dst {
                    self.copy_local(*slot, d);
                    if let Some(schema) = self.batch_schemas.get(&slot.0).cloned() {
                        self.batch_schemas.insert(d.0, schema);
                    }
                    if let Some(len) = self
                        .array_ptr_lens
                        .get(&slot.0)
                        .or_else(|| self.slot_array_lens.get(&slot.0))
                        .copied()
                    {
                        self.array_ptr_lens.insert(d.0, len);
                    }
                    if let Some(et) = self
                        .ptr_elem_tys
                        .get(&slot.0)
                        .or_else(|| self.slot_ptr_elem_tys.get(&slot.0))
                        .cloned()
                    {
                        self.ptr_elem_tys.insert(d.0, et);
                    }
                    if let Some(pt) = self
                        .ptr_pointee_tys
                        .get(&slot.0)
                        .or_else(|| self.slot_ptr_pointee_tys.get(&slot.0))
                        .cloned()
                    {
                        self.ptr_pointee_tys.insert(d.0, pt);
                    }
                }
            }
            Inst::SlotStore { slot, val } => {
                if self.agg_slots.contains_key(&slot.0) {
                    let dst_ptr = self.use_scalar(*slot);
                    let val_mty = self.effective_local_mir_ty(*val).clone();
                    let dst_mty = self
                        .agg_slot_tys
                        .get(&slot.0)
                        .cloned()
                        .unwrap_or_else(|| val_mty.clone());
                    self.store_typed_field_to_mem(*val, &val_mty, &dst_mty, dst_ptr, 0);
                } else {
                    let dst_mty = self.effective_local_mir_ty(*slot).clone();
                    if matches!(dst_mty, MirType::Fix32 | MirType::Fix64 | MirType::F64)
                        && self.effective_local_mir_ty(*val) != &dst_mty
                    {
                        let coerced = self.coerce_val_to_mir_ty(*val, &dst_mty);
                        self.def_scalar_typed(*slot, coerced);
                    } else {
                        self.copy_local(*val, *slot);
                    }
                    if let Some(schema) = self.batch_schemas.get(&val.0).cloned() {
                        self.batch_schemas.insert(slot.0, schema);
                    }
                    if let Some(len) = self.array_ptr_lens.get(&val.0).copied() {
                        self.slot_array_lens.insert(slot.0, len);
                    }
                    if let Some(et) = self.ptr_elem_tys.get(&val.0).cloned() {
                        self.slot_ptr_elem_tys.insert(slot.0, et);
                    }
                    if let Some(pt) = self.ptr_pointee_tys.get(&val.0).cloned() {
                        self.slot_ptr_pointee_tys.insert(slot.0, pt);
                    }
                }
                // Update any strength-reduced row pointers bound to `slot`.
                if let Some(entries) = self.sr_plan.by_slot.get(&slot.0).cloned() {
                    if self.sr_plan.zero_locals.contains(&val.0) {
                        for (base_id, _, pvar) in entries {
                            let base_val = self.use_scalar(LocalId(base_id));
                            self.b.def_var(pvar, base_val);
                        }
                    } else if self.sr_plan.step_inc_map.get(&val.0) == Some(&slot.0) {
                        for (_, stride, pvar) in entries {
                            let cur = self.b.use_var(pvar);
                            let nxt = self.b.ins().iadd_imm_s(cur, i64::from(stride));
                            self.b.def_var(pvar, nxt);
                        }
                    }
                }
            }
            Inst::BinOp {
                op,
                lhs,
                rhs,
                allow_fma,
            } => {
                if let Some(d) = dst {
                    self.lower_binop(d, op, *lhs, *rhs, *allow_fma);
                }
            }
            Inst::UnOp { op, val } => {
                if let Some(d) = dst {
                    self.lower_unop(d, op, *val);
                }
            }
            Inst::Cast { val, target_ty } => {
                if let Some(d) = dst {
                    self.lower_cast(d, *val, target_ty);
                }
            }
            Inst::VecExtract { vec, lane } => {
                if let Some(d) = dst {
                    let vs = self.use_vec(*vec);
                    let l = usize::from((*lane).min(3));
                    self.def_scalar_typed(d, vs[l]);
                }
            }
            Inst::VecInsert { vec, lane, val } => {
                if let Some(d) = dst {
                    let mut vs = self.use_vec(*vec);
                    let l = usize::from((*lane).min(3));
                    let lane_ty = if is_ivec_mir_ty(self.effective_local_mir_ty(d)) {
                        types::I32
                    } else {
                        types::F32
                    };
                    let sv = {
                        let __tmp = self.use_scalar(*val);
                        coerce_cl_val(self.b, __tmp, lane_ty, ptr_ty)
                    };
                    vs[l] = sv;
                    self.def_vec(d, vs);
                }
            }
            Inst::VecSwizzle { vec, lanes } => {
                if let Some(d) = dst {
                    let src = self.use_vec(*vec);
                    let z = if is_ivec_mir_ty(self.effective_local_mir_ty(d)) {
                        self.b.ins().iconst(types::I32, 0)
                    } else {
                        self.b.ins().f32const(0.0)
                    };
                    if lanes.len() <= 1 {
                        let idx = usize::from(lanes.first().copied().unwrap_or(0).min(3));
                        self.def_scalar_typed(d, src[idx]);
                    } else {
                        let mut out = [z; 4];
                        for (i, &l) in lanes.iter().take(4).enumerate() {
                            out[i] = src[usize::from(l.min(3))];
                        }
                        self.def_vec(d, out);
                    }
                }
            }
            Inst::IntrinsicMath {
                name,
                args,
                deterministic,
            } => {
                if let Some(d) = dst {
                    self.lower_intrinsic_math(d, name, args, *deterministic)?;
                }
            }
            Inst::Call { callee, args } => {
                self.lower_helper_call(dst, callee, args)?;
            }
            Inst::StructInit { type_name, fields } => {
                if let Some(d) = dst {
                    self.lower_struct_init(d, type_name, fields);
                }
            }
            Inst::ArrayInit { elems } => {
                if let Some(d) = dst {
                    self.lower_array_init(d, elems);
                }
            }
            Inst::ArrayIndex { base, index } => {
                if let Some(d) = dst {
                    self.lower_array_index(d, *base, *index);
                }
            }
            Inst::ArrayStore {
                base_ptr,
                index,
                val,
                elem_ty,
            } => {
                self.lower_array_store(*base_ptr, *index, *val, elem_ty);
            }
            Inst::FieldPtr {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
            } => {
                if let Some(d) = dst {
                    let (resolved_off, resolved_ty) =
                        self.ctx.resolve_field_offset_and_ty(layout_key, field);
                    let eff_off = if resolved_ty.is_some() {
                        resolved_off
                    } else {
                        *offset_bytes as usize
                    };
                    if let Some(rt) = resolved_ty {
                        self.ptr_pointee_tys.insert(d.0, rt.clone());
                        if let MirType::Array { elem, len } = rt {
                            self.array_ptr_lens.insert(d.0, len);
                            self.ptr_elem_tys.insert(d.0, *elem);
                        }
                    } else if layout_key == "SmallVec" && field == "data" {
                        let sv_mty = self
                            .ptr_pointee_tys
                            .get(&base_ptr.0)
                            .cloned()
                            .unwrap_or_else(|| self.effective_local_mir_ty(*base_ptr).clone());
                        if let MirType::Named(ref sv_name) = sv_mty
                            && let Some((sv_elem, sv_cap)) = parse_smallvec_mir_name(sv_name)
                        {
                            self.array_ptr_lens.insert(d.0, sv_cap);
                            self.ptr_elem_tys.insert(d.0, sv_elem);
                        }
                    }
                    let bp = self.use_scalar(*base_ptr);
                    let zero_p = self.b.ins().iconst(ptr_ty, 0);
                    let is_null = self.b.ins().icmp_imm_s(IntCC::Equal, bp, 0);
                    let added = self.b.ins().iadd_imm_s(bp, eff_off as i64);
                    let res = self.b.ins().select(is_null, zero_p, added);
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::FieldLoad {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                field_ty,
            } => {
                if let Some(d) = dst {
                    self.lower_field_load(d, *base_ptr, layout_key, field, *offset_bytes, field_ty);
                }
            }
            Inst::FieldStore {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                val,
            } => {
                self.lower_field_store(*base_ptr, layout_key, field, *offset_bytes, *val);
            }
            Inst::RowPtr {
                col_ptr,
                row_idx,
                stride_bytes,
                is_sparse,
            } => {
                if let Some(d) = dst {
                    self.lower_row_ptr(d, *col_ptr, *row_idx, *stride_bytes, *is_sparse);
                }
            }
            Inst::IterNextChunk { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                    let len_slot_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
                    let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                    let call_bb = self.b.create_block();
                    let skip_bb = self.b.create_block();
                    let done_bb = self.b.create_block();
                    self.b.append_block_param(done_bb, types::I8);
                    self.b.ins().brif(iter_ok, call_bb, &[], skip_bb, &[]);

                    self.b.switch_to_block(call_bb);
                    self.b.seal_block(call_bb);
                    let has_ch = call_vtable(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_NEXT_CHUNK,
                        &[ptr_ty, ptr_ty],
                        Some(types::I8),
                        ptr_ty,
                        self.ctx.call_conv,
                        &[iter, len_slot_ptr],
                    );
                    let clen_raw =
                        self.b
                            .ins()
                            .load(ptr_ty, MemFlagsData::trusted(), len_slot_ptr, 0);
                    let clen_i32 = coerce_cl_val(self.b, clen_raw, types::I32, ptr_ty);
                    if (*query_idx as usize) < self.chunk_len_vars.len() {
                        self.b
                            .def_var(self.chunk_len_vars[*query_idx as usize], clen_i32);
                    }
                    self.b.ins().jump(done_bb, &[BlockArg::Value(has_ch)]);

                    self.b.switch_to_block(skip_bb);
                    self.b.seal_block(skip_bb);
                    let f_i8 = self.b.ins().iconst(types::I8, 0);
                    if (*query_idx as usize) < self.chunk_len_vars.len() {
                        let z32 = self.b.ins().iconst(types::I32, 0);
                        self.b
                            .def_var(self.chunk_len_vars[*query_idx as usize], z32);
                    }
                    self.b.ins().jump(done_bb, &[BlockArg::Value(f_i8)]);

                    self.b.switch_to_block(done_bb);
                    self.b.seal_block(done_bb);
                    let res = self.b.block_params(done_bb)[0];
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::IterChunkLen { query_idx } => {
                if let Some(d) = dst {
                    let val = if (*query_idx as usize) < self.chunk_len_vars.len() {
                        self.b.use_var(self.chunk_len_vars[*query_idx as usize])
                    } else {
                        self.b.ins().iconst(types::I32, 0)
                    };
                    self.def_scalar_typed(d, val);
                }
            }
            Inst::IterEntities { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let p = call_vtable_guarded(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_ENTITIES,
                        &[ptr_ty],
                        ptr_ty,
                        ptr_ty,
                        self.ctx.call_conv,
                        iter,
                        &[iter],
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityAtRow {
                entities_ptr,
                row_idx,
            } => {
                if let Some(d) = dst {
                    self.lower_entity_at_row(d, *entities_ptr, *row_idx);
                }
            }
            Inst::IterColRead {
                query_idx,
                term_idx,
                storage_key,
            } => {
                if let Some(d) = dst {
                    let slot = if self.is_query_term_sparse(*query_idx, *term_idx, storage_key) {
                        api_slots::ITER_COLUMN_ROWS_READONLY
                    } else {
                        api_slots::ITER_COLUMN_READONLY
                    };
                    let p = self.call_iter_col(*query_idx, *term_idx, slot);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColWrite {
                query_idx,
                term_idx,
                storage_key,
            } => {
                if let Some(d) = dst {
                    let slot = if self.is_query_term_sparse(*query_idx, *term_idx, storage_key) {
                        api_slots::ITER_COLUMN_ROWS_MUTABLE
                    } else {
                        api_slots::ITER_COLUMN_MUTABLE
                    };
                    let p = self.call_iter_col(*query_idx, *term_idx, slot);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColWriteUntracked {
                query_idx,
                term_idx,
                storage_key,
            } => {
                if let Some(d) = dst {
                    let slot = if self.is_query_term_sparse(*query_idx, *term_idx, storage_key) {
                        api_slots::ITER_COLUMN_ROWS_MUTABLE
                    } else {
                        api_slots::ITER_COLUMN_MUTABLE_UNTRACKED
                    };
                    let p = self.call_iter_col(*query_idx, *term_idx, slot);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColRowsRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p = self.call_iter_col(
                        *query_idx,
                        *term_idx,
                        api_slots::ITER_COLUMN_ROWS_READONLY,
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColRowsWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p = self.call_iter_col(
                        *query_idx,
                        *term_idx,
                        api_slots::ITER_COLUMN_ROWS_MUTABLE,
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterMarkChangedRange {
                query_idx,
                term_idx,
                run_start,
                run_len,
            } => {
                let rlen = self.use_scalar(*run_len);
                let rstart = self.use_scalar(*run_start);
                self.emit_flush_changed_range(*query_idx, *term_idx, rstart, rlen);
            }
            Inst::IterCount { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let cnt_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                    let cnt_ptr = self.b.ins().stack_addr(ptr_ty, cnt_slot, 0);
                    let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                    let call_bb = self.b.create_block();
                    let skip_bb = self.b.create_block();
                    self.b.ins().brif(iter_ok, call_bb, &[], skip_bb, &[]);

                    self.b.switch_to_block(call_bb);
                    self.b.seal_block(call_bb);
                    let _rc = call_vtable(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_COUNT,
                        &[ptr_ty, ptr_ty],
                        Some(types::I32),
                        ptr_ty,
                        self.ctx.call_conv,
                        &[iter, cnt_ptr],
                    );
                    self.b.ins().jump(skip_bb, &[]);

                    self.b.switch_to_block(skip_bb);
                    self.b.seal_block(skip_bb);
                    let count = self
                        .b
                        .ins()
                        .load(ptr_ty, MemFlagsData::trusted(), cnt_ptr, 0);
                    self.def_scalar_typed(d, count);
                }
            }
            Inst::IterUpCascade {
                query_idx,
                relation,
                entity,
                term_idx,
            } => {
                if let Some(d) = dst {
                    self.lower_iter_up_cascade(d, *query_idx, relation, *entity, *term_idx);
                }
            }
            Inst::ParForEachChunk { .. } | Inst::ParForEachChunkReadonly { .. } => {
                // Fallback path when not safely outlinable (`has_commands`, reductions, deterministic order):
                // ensure iterator is obtained and proceed into the MIR chunk loop sequentially.
                if let Inst::ParForEachChunk { query_idx, .. }
                | Inst::ParForEachChunkReadonly { query_idx, .. } = stmt.inst
                {
                    let _ = self.ensure_query_iter(query_idx);
                }
            }
            Inst::ReduceInit { identity, .. } => {
                if let Some(d) = dst {
                    self.copy_local(*identity, d);
                }
            }
            Inst::ReduceAccum { acc, op, val } => {
                let d_target = dst.unwrap_or(*acc);
                let eff_op = if op == "sum" || op == "add" || op == "+" || op == "count" {
                    "+"
                } else if op == "prod" || op == "mul" || op == "*" {
                    "*"
                } else if op == "any" {
                    "||"
                } else if op == "all" {
                    "&&"
                } else {
                    op.as_str()
                };
                if eff_op == "||" || eff_op == "&&" {
                    let amty = self.effective_local_mir_ty(*acc).clone();
                    let vmty = self.effective_local_mir_ty(*val).clone();
                    let av = self.use_scalar(*acc);
                    let vv = self.use_scalar(*val);
                    let ab = cast_to_bool(self.b, av, &amty);
                    let vb = cast_to_bool(self.b, vv, &vmty);
                    let res = if eff_op == "||" {
                        self.b.ins().bor(ab, vb)
                    } else {
                        self.b.ins().band(ab, vb)
                    };
                    self.def_scalar_typed(d_target, res);
                } else if eff_op == "min" || eff_op == "max" {
                    let dmty = self.mir_fn.locals[d_target.0 as usize].ty.clone();
                    if let Some(dims) = vec_dims(&dmty) {
                        let av = self.use_vec_dims(*acc, dims);
                        let vv = self.use_vec_dims(*val, dims);
                        let is_int_v = is_ivec_mir_ty(&dmty);
                        let signed_v = !matches!(dmty, MirType::UVec2);
                        let lane_ty = if is_int_v { types::I32 } else { types::F32 };
                        let z = zero_for_cl_type(self.b, lane_ty);
                        let mut out = [z; 4];
                        for i in 0..usize::from(dims) {
                            out[i] = apply_min_max(
                                self.b,
                                lane_ty,
                                eff_op == "min",
                                signed_v,
                                av[i],
                                vv[i],
                            );
                        }
                        self.def_vec(d_target, out);
                    } else {
                        let a = self.coerce_val_to_mir_ty(*acc, &dmty);
                        let v = self.coerce_val_to_mir_ty(*val, &dmty);
                        let ty = self.expected_cl_ty(d_target);
                        let signed = is_signed_int_ty(&dmty);
                        let res = apply_min_max(self.b, ty, eff_op == "min", signed, a, v);
                        self.def_scalar_typed(d_target, res);
                    }
                } else {
                    self.lower_binop(d_target, eff_op, *acc, *val, false);
                }
            }
            Inst::ResRead { resource } => {
                if let Some(d) = dst {
                    let p = self.lower_res_access(resource, false);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::ResWrite { resource } => {
                if let Some(d) = dst {
                    let p = self.lower_res_access(resource, true);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityGet {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let ent = self.use_scalar(*entity);
                    let p = self.call_entity_get(*query_idx, *term_idx, ent, false);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityGetMut {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let ent = self.use_scalar(*entity);
                    let p = self.call_entity_get(*query_idx, *term_idx, ent, true);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::ResolveNamedObject { name } => {
                if let Some(d) = dst {
                    let ent = self.lower_resolve_named_object(name)?;
                    self.def_scalar_typed(d, ent);
                }
            }
            Inst::BindNamedObject { name } => {
                let _ent = self.lower_resolve_named_object(name)?;
            }
            Inst::InternSymbol { symbol } => {
                if let Some(d) = dst {
                    let sym = self.lower_intern_symbol(symbol)?;
                    self.def_scalar_typed(d, sym);
                }
            }
            Inst::TriggerPayload { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .obs_event_data
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::TriggerTarget => {
                if let Some(d) = dst {
                    let e = self
                        .obs_entity
                        .unwrap_or_else(|| self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
                    self.def_scalar_typed(d, e);
                }
            }
            Inst::GraceArm { ptr, duration_sec } => {
                let p = self.use_scalar(*ptr);
                let dur = {
                    let __tmp = self.use_scalar(*duration_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.guarded_store(p, 0, dur);
            }
            Inst::GraceTick { ptr, dt_sec } => {
                let p = self.use_scalar(*ptr);
                let dt = {
                    let __tmp = self.use_scalar(*dt_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_grace_tick(p, dt);
            }
            Inst::GraceIsActive { ptr } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let rem = self.guarded_load(p, 0, types::F32);
                    let zero = self.b.ins().f32const(0.0);
                    let act = self.b.ins().fcmp(FloatCC::GreaterThan, rem, zero);
                    self.def_scalar_typed(d, act);
                }
            }
            Inst::GraceClear { ptr } => {
                let p = self.use_scalar(*ptr);
                let zero = self.b.ins().f32const(0.0);
                self.guarded_store(p, 0, zero);
            }
            Inst::InputBufPush {
                ptr,
                capacity,
                action_id,
                window_sec,
            } => {
                let p = self.use_scalar(*ptr);
                let aid = {
                    let __tmp = self.use_scalar(*action_id);
                    coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                };
                let win = {
                    let __tmp = self.use_scalar(*window_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_input_buf_push(p, *capacity, aid, win);
            }
            Inst::InputBufConsume {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let aid = {
                        let __tmp = self.use_scalar(*action_id);
                        coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                    };
                    let hit = self.lower_input_buf_find(p, *capacity, aid, true);
                    self.def_scalar_typed(d, hit);
                }
            }
            Inst::InputBufPeek {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let aid = {
                        let __tmp = self.use_scalar(*action_id);
                        coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                    };
                    let hit = self.lower_input_buf_find(p, *capacity, aid, false);
                    self.def_scalar_typed(d, hit);
                }
            }
            Inst::InputBufTick {
                ptr,
                capacity,
                dt_sec,
            } => {
                let p = self.use_scalar(*ptr);
                let dt = {
                    let __tmp = self.use_scalar(*dt_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_input_buf_tick(p, *capacity, dt);
            }
            Inst::BitSetSet { ptr, words, bit } => {
                let p = self.use_scalar(*ptr);
                let bit_v = {
                    let __tmp = self.use_scalar(*bit);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                self.lower_bitset_mut(p, *words, bit_v, true);
            }
            Inst::BitSetClear { ptr, words, bit } => {
                let p = self.use_scalar(*ptr);
                let bit_v = {
                    let __tmp = self.use_scalar(*bit);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                self.lower_bitset_mut(p, *words, bit_v, false);
            }
            Inst::BitSetGet { ptr, words, bit } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let bit_v = {
                        let __tmp = self.use_scalar(*bit);
                        coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                    };
                    let res = self.lower_bitset_get(p, *words, bit_v);
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::TimelineInWindow { ptr, window_bit } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let mask = self.guarded_load(p, 4, types::I32);
                    let bit = 1i64 << (*window_bit & 31);
                    let masked = self.b.ins().band_imm_u(mask, bit);
                    let active = self.b.ins().icmp_imm_s(IntCC::NotEqual, masked, 0);
                    self.def_scalar_typed(d, active);
                }
            }
            Inst::TimelineAdvance {
                cursor_ptr,
                rate_hz,
                duration_frames,
                window_masks,
                ..
            } => {
                let p = self.use_scalar(*cursor_ptr);
                self.lower_timeline_advance(p, *rate_hz, *duration_frames, window_masks);
            }
            Inst::CmdSpawn {
                persistent,
                components,
            } => {
                let out_ent = self.lower_cmd_spawn(*persistent, components)?;
                if let Some(d) = dst {
                    self.def_scalar_typed(d, out_ent);
                }
            }
            Inst::CmdSpawnBatch { count, components } => {
                self.lower_cmd_spawn_batch(*count, components)?;
            }
            Inst::SpawnBatchBegin { count, components } => {
                let (hdr_u64, schema) = self.lower_spawn_batch_begin(*count, components)?;
                if let Some(d) = dst {
                    self.def_scalar_typed(d, hdr_u64);
                    self.batch_schemas.insert(d.0, schema);
                }
            }
            Inst::SpawnBatchPush {
                batch,
                index,
                components,
            } => {
                self.lower_spawn_batch_push(*batch, *index, components);
            }
            Inst::SpawnBatchCommit { batch } => {
                self.lower_spawn_batch_commit(*batch)?;
            }
            Inst::CmdDespawn { entity } => {
                let ent = self.use_scalar(*entity);
                let cmds = self.ensure_commands();
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_DESPAWN,
                    &[ptr_ty, types::I64],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, ent],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
            }
            Inst::CmdDespawnAll { filter } => {
                self.lower_cmd_despawn_all(filter)?;
            }
            Inst::CmdInsert {
                entity,
                component,
                data,
                if_new,
            } => {
                let ent = self.use_scalar(*entity);
                self.lower_cmd_insert(ent, component, *data, *if_new)?;
            }
            Inst::CmdRemove { entity, component } => {
                let ent = self.use_scalar(*entity);
                self.lower_cmd_remove(ent, component);
            }
            Inst::CmdTrigger {
                event,
                target,
                payload,
                propagate,
            } => {
                self.lower_cmd_trigger(event, *target, *payload, *propagate);
            }
            Inst::StreamEmit { stream, payload } => {
                self.lower_stream_emit(stream, *payload);
            }
            Inst::CmdCheckpoint => {
                let cmds = self.ensure_commands();
                let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_CHECKPOINT,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, out_ptr],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
                if let Some(d) = dst {
                    let ck = self
                        .b
                        .ins()
                        .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
                    self.def_scalar_typed(d, ck);
                }
            }
            Inst::CmdRollback { checkpoint } => {
                let ck = self.use_scalar(*checkpoint);
                let cmds = self.ensure_commands();
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_ROLLBACK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, ck],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
            }
            Inst::CmdInsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                self.lower_cmd_insert_relation(relation, *entity, *target, *payload);
            }
            Inst::CmdRemoveRelation {
                relation,
                entity,
                target,
            } => {
                self.lower_cmd_remove_relation(relation, *entity, *target);
            }
            Inst::TableLoad {
                table_name,
                key,
                field,
            } => {
                if let Some(d) = dst {
                    self.lower_table_load(d, table_name, *key, field);
                }
            }
            Inst::CurveSample { curve_name, x } => {
                if let Some(d) = dst {
                    self.lower_curve_sample(d, curve_name, *x);
                }
            }
            Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*slice_ptr);
                    let present = self.b.ins().icmp_imm_s(IntCC::NotEqual, p, 0);
                    self.def_scalar_typed(d, present);
                }
            }
            Inst::DirtyRunInit { run_start, run_len } => {
                let z32 = self.b.ins().iconst(types::I32, 0);
                self.def_scalar_typed(*run_start, z32);
                self.def_scalar_typed(*run_len, z32);
            }
            Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx,
            } => {
                self.lower_dirty_run_record_row(*run_start, *run_len, *row_idx);
            }
            Inst::IterReset { query_idx } => {
                self.lower_iter_reset(*query_idx);
            }
            Inst::SpatialCsrBegin { index_name } => {
                self.lower_spatial_csr_begin(index_name);
            }
            Inst::SpatialCsrCount { index_name, pos } => {
                self.lower_spatial_csr_count(index_name, *pos);
            }
            Inst::SpatialCsrPrefixSum { index_name } => {
                self.lower_spatial_csr_prefix_sum(index_name);
            }
            Inst::SpatialCsrScatter {
                index_name,
                entity,
                pos,
            } => {
                self.lower_spatial_csr_scatter(index_name, *entity, *pos);
            }
            Inst::SpatialQueryDisc {
                grid_name,
                center,
                radius,
            } => {
                if let Some(d) = dst {
                    self.lower_spatial_query_disc(d, grid_name, *center, *radius);
                }
            }
            Inst::SpatialQuerySegmentAt {
                history_name,
                start,
                end,
                radius,
                tick_offset,
            } => {
                if let Some(d) = dst {
                    self.lower_spatial_query_segment(
                        d,
                        history_name,
                        *start,
                        *end,
                        *radius,
                        *tick_offset,
                    );
                }
            }
            Inst::SpatialRebuildCsr { .. }
            | Inst::ShadowWrite { .. }
            | Inst::ShadowCommit { .. }
            | Inst::RequireTrue { .. }
            | Inst::FsmDispatch { .. }
            | Inst::TaskStep { .. } => {
                // `SpatialRebuildCsr` is finalized by `SpatialCsrBegin`..`Scatter`.
                // `atomic_tx` / `state_machines` passes already lowered control flow & state steps;
                // `ShadowWrite` must not overwrite `undo_slot` (pre-image saved by `save_bb`).
            }
            Inst::MigrateSrcPtr { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .mig_src
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::MigrateDstPtr { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .mig_dst
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
        }
        Ok(())
    }

    pub(super) fn copy_local(&mut self, src: LocalId, dst: LocalId) {
        if let Some((id, len)) = self.const_strings.get(&src.0).copied() {
            self.const_strings.insert(dst.0, (id, len));
        }
        if let Some(txt) = self.const_string_texts.get(&src.0).cloned() {
            self.const_string_texts.insert(dst.0, txt);
        } else {
            self.const_string_texts.remove(&dst.0);
        }
        if let Some(et) = self.ptr_elem_tys.get(&src.0).cloned() {
            self.ptr_elem_tys.insert(dst.0, et);
        }
        if let Some(pt) = self.ptr_pointee_tys.get(&src.0).cloned() {
            self.ptr_pointee_tys.insert(dst.0, pt);
        }
        match (
            &self.local_reps[src.0 as usize],
            &self.local_reps[dst.0 as usize],
        ) {
            (LocalRep::Vec(_), _) => {
                let vs = self.use_vec(src);
                self.def_vec(dst, vs);
            }
            (_, LocalRep::Vec(_)) => {
                if matches!(
                    self.effective_local_mir_ty(src),
                    MirType::Ptr | MirType::MutPtr
                ) {
                    let vs = self.use_vec(src);
                    self.def_vec(dst, vs);
                } else {
                    let lane_ty = if is_ivec_mir_ty(self.effective_local_mir_ty(dst)) {
                        types::I32
                    } else {
                        types::F32
                    };
                    let s = self.use_scalar(src);
                    let lv = coerce_cl_val(self.b, s, lane_ty, self.ctx.ptr_ty);
                    self.def_vec(dst, [lv; 4]);
                }
            }
            _ => {
                let v = self.use_scalar(src);
                self.def_scalar_typed(dst, v);
            }
        }
    }

    pub(super) fn lower_binop(
        &mut self,
        dst: LocalId,
        op: &str,
        lhs: LocalId,
        rhs: LocalId,
        allow_fma: bool,
    ) {
        let lty_owned = self.effective_local_mir_ty(lhs).clone();
        let rty_owned = self.effective_local_mir_ty(rhs).clone();
        let dst_ty_owned = self.effective_local_mir_ty(dst).clone();
        let lty = &lty_owned;
        let rty = &rty_owned;
        let dst_ty = &dst_ty_owned;
        let ptr_ty = self.ctx.ptr_ty;

        if op == "quat_mul" {
            let l = self.use_vec(lhs);
            let r = self.use_vec(rhs);
            let (lx, ly, lz, lw) = (l[0], l[1], l[2], l[3]);
            let (rx, ry, rz, rw) = (r[0], r[1], r[2], r[3]);
            // Hamilton product for `(x, y, z, w)` quaternions.
            let p0 = self.b.ins().fmul(lw, rx);
            let p1 = self.b.ins().fmul(lx, rw);
            let p2 = self.b.ins().fmul(ly, rz);
            let p3 = self.b.ins().fmul(lz, ry);
            let x0 = self.b.ins().fadd(p0, p1);
            let x1 = self.b.ins().fsub(p2, p3);
            let qx = self.b.ins().fadd(x0, x1);

            let q0 = self.b.ins().fmul(lw, ry);
            let q1 = self.b.ins().fmul(lx, rz);
            let q2 = self.b.ins().fmul(ly, rw);
            let q3 = self.b.ins().fmul(lz, rx);
            let y0 = self.b.ins().fsub(q0, q1);
            let y1 = self.b.ins().fadd(q2, q3);
            let qy = self.b.ins().fadd(y0, y1);

            let r0 = self.b.ins().fmul(lw, rz);
            let r1 = self.b.ins().fmul(lx, ry);
            let r2 = self.b.ins().fmul(ly, rx);
            let r3 = self.b.ins().fmul(lz, rw);
            let z0 = self.b.ins().fadd(r0, r1);
            let z1 = self.b.ins().fsub(r3, r2);
            let qz = self.b.ins().fadd(z0, z1);

            let w0 = self.b.ins().fmul(lw, rw);
            let w1 = self.b.ins().fmul(lx, rx);
            let w2 = self.b.ins().fmul(ly, ry);
            let w3 = self.b.ins().fmul(lz, rz);
            let ww0 = self.b.ins().fsub(w0, w1);
            let ww1 = self.b.ins().fadd(w2, w3);
            let qw = self.b.ins().fsub(ww0, ww1);

            self.def_vec(dst, [qx, qy, qz, qw]);
            return;
        }
        if op == "quat_mul_vec3" {
            let q = self.use_vec(lhs);
            let v = self.use_vec_dims(rhs, 3);
            let (qx, qy, qz, qw) = (q[0], q[1], q[2], q[3]);
            let (vx, vy, vz) = (v[0], v[1], v[2]);
            // v + 2 * cross(q.xyz, cross(q.xyz, v) + q.w * v)
            let cx_a = self.b.ins().fmul(qy, vz);
            let cx_b = self.b.ins().fmul(qz, vy);
            let cx0 = self.b.ins().fsub(cx_a, cx_b);
            let qw_vx = self.b.ins().fmul(qw, vx);
            let c1x = self.b.ins().fadd(cx0, qw_vx);

            let cy_a = self.b.ins().fmul(qz, vx);
            let cy_b = self.b.ins().fmul(qx, vz);
            let cy0 = self.b.ins().fsub(cy_a, cy_b);
            let qw_vy = self.b.ins().fmul(qw, vy);
            let c1y = self.b.ins().fadd(cy0, qw_vy);

            let cz_a = self.b.ins().fmul(qx, vy);
            let cz_b = self.b.ins().fmul(qy, vx);
            let cz0 = self.b.ins().fsub(cz_a, cz_b);
            let qw_vz = self.b.ins().fmul(qw, vz);
            let c1z = self.b.ins().fadd(cz0, qw_vz);

            let c2x = {
                let a = self.b.ins().fmul(qy, c1z);
                let b = self.b.ins().fmul(qz, c1y);
                self.b.ins().fsub(a, b)
            };
            let c2y = {
                let a = self.b.ins().fmul(qz, c1x);
                let b = self.b.ins().fmul(qx, c1z);
                self.b.ins().fsub(a, b)
            };
            let c2z = {
                let a = self.b.ins().fmul(qx, c1y);
                let b = self.b.ins().fmul(qy, c1x);
                self.b.ins().fsub(a, b)
            };
            let two = self.b.ins().f32const(2.0);
            let ox = {
                let t = self.b.ins().fmul(two, c2x);
                self.b.ins().fadd(vx, t)
            };
            let oy = {
                let t = self.b.ins().fmul(two, c2y);
                self.b.ins().fadd(vy, t)
            };
            let oz = {
                let t = self.b.ins().fmul(two, c2z);
                self.b.ins().fadd(vz, t)
            };
            let zf = self.b.ins().f32const(0.0);
            self.def_vec(dst, [ox, oy, oz, zf]);
            return;
        }

        // Handle vector arithmetic (`Vec + Vec`, `Vec * s`, `s * Vec`, `Vec == Vec`, and integer vectors).
        if let (Some(ld), Some(rd)) = (vec_dims(lty), vec_dims(rty)) {
            let lv = self.use_vec(lhs);
            let rv = self.use_vec(rhs);
            let dims = usize::from(ld.max(rd));
            let is_int_vec = is_ivec_mir_ty(lty) || is_ivec_mir_ty(rty);
            if op == "==" || op == "!=" {
                let mut acc = self.b.ins().iconst(types::I8, 1);
                for i in 0..dims {
                    let eq = if is_int_vec {
                        self.b.ins().icmp(IntCC::Equal, lv[i], rv[i])
                    } else {
                        self.b.ins().fcmp(FloatCC::Equal, lv[i], rv[i])
                    };
                    acc = self.b.ins().band(acc, eq);
                }
                let res = if op == "!=" {
                    self.b.ins().icmp_imm_s(IntCC::Equal, acc, 0)
                } else {
                    acc
                };
                self.def_scalar_typed(dst, res);
                return;
            }
            if is_int_vec {
                let signed = !matches!(lty, MirType::UVec2) && !matches!(rty, MirType::UVec2);
                let z = self.b.ins().iconst(types::I32, 0);
                let mut out = [z; 4];
                for i in 0..dims {
                    out[i] = int_binop_or_cmp(self.b, types::I32, signed, op, lv[i], rv[i]);
                }
                self.def_vec(dst, out);
                return;
            }
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..dims {
                out[i] = float_binop(self.b, types::F32, op, lv[i], rv[i]);
            }
            self.def_vec(dst, out);
            return;
        }
        if let Some(ld) = vec_dims(lty) {
            let lv = self.use_vec(lhs);
            if is_ivec_mir_ty(lty) {
                let signed = !matches!(lty, MirType::UVec2);
                let s = {
                    let __tmp = self.use_scalar(rhs);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                let z = self.b.ins().iconst(types::I32, 0);
                let mut out = [z; 4];
                for i in 0..usize::from(ld) {
                    out[i] = int_binop_or_cmp(self.b, types::I32, signed, op, lv[i], s);
                }
                self.def_vec(dst, out);
                return;
            }
            let s = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
            };
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..usize::from(ld) {
                out[i] = float_binop(self.b, types::F32, op, lv[i], s);
            }
            self.def_vec(dst, out);
            return;
        }
        if let Some(rd) = vec_dims(rty) {
            let rv = self.use_vec(rhs);
            if is_ivec_mir_ty(rty) {
                let signed = !matches!(rty, MirType::UVec2);
                let s = {
                    let __tmp = self.use_scalar(lhs);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                let z = self.b.ins().iconst(types::I32, 0);
                let mut out = [z; 4];
                for i in 0..usize::from(rd) {
                    out[i] = int_binop_or_cmp(self.b, types::I32, signed, op, s, rv[i]);
                }
                self.def_vec(dst, out);
                return;
            }
            let s = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
            };
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..usize::from(rd) {
                out[i] = float_binop(self.b, types::F32, op, s, rv[i]);
            }
            self.def_vec(dst, out);
            return;
        }

        // Handle Q16.16 (`Fix32`) and Q32.32 (`Fix64`) deterministic fixed-point arithmetic.
        if matches!(lty, MirType::Fix32) || matches!(rty, MirType::Fix32) {
            let l = self.coerce_val_to_mir_ty(lhs, &MirType::Fix32);
            let r = self.coerce_val_to_mir_ty(rhs, &MirType::Fix32);
            let res = match op {
                "*" => {
                    let l64 = self.b.ins().sextend(types::I64, l);
                    let r64 = self.b.ins().sextend(types::I64, r);
                    let prod = self.b.ins().imul(l64, r64);
                    let sh = self.b.ins().sshr_imm_u(prod, 16);
                    self.b.ins().ireduce(types::I32, sh)
                }
                "/" => {
                    let l64 = self.b.ins().sextend(types::I64, l);
                    let r64 = self.b.ins().sextend(types::I64, r);
                    let shifted = self.b.ins().ishl_imm_u(l64, 16);
                    let q = guarded_sdiv(self.b, types::I64, shifted, r64);
                    self.b.ins().ireduce(types::I32, q)
                }
                _ => int_binop_or_cmp(self.b, types::I32, true, op, l, r),
            };
            self.def_scalar_typed(dst, res);
            return;
        }
        if matches!(lty, MirType::Fix64) || matches!(rty, MirType::Fix64) {
            let l = self.coerce_val_to_mir_ty(lhs, &MirType::Fix64);
            let r = self.coerce_val_to_mir_ty(rhs, &MirType::Fix64);
            let res = match op {
                "*" => {
                    let lo = self.b.ins().imul(l, r);
                    let hi = self.b.ins().smulhi(l, r);
                    let lo_hi = self.b.ins().ushr_imm_u(lo, 32);
                    let hi_lo = self.b.ins().ishl_imm_u(hi, 32);
                    self.b.ins().bor(lo_hi, hi_lo)
                }
                "/" => {
                    let div_ref = self
                        .ctx
                        .obj_mod
                        .declare_func_in_func(self.ctx.fix64_div_fn, self.b.func);
                    let call = self.b.ins().call(div_ref, &[l, r]);
                    self.b.inst_results(call)[0]
                }
                _ => int_binop_or_cmp(self.b, types::I64, true, op, l, r),
            };
            self.def_scalar_typed(dst, res);
            return;
        }

        // Scalar float / int / bool / pointer operation.
        let is_float = matches!(lty, MirType::F32 | MirType::F64)
            || matches!(rty, MirType::F32 | MirType::F64);
        if is_float {
            let fty = if matches!(lty, MirType::F64) || matches!(rty, MirType::F64) {
                types::F64
            } else {
                types::F32
            };
            let lv = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            };
            let rv = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            };
            // Match C99 `-ffp-contract=off` and RustGuest/BevyNative IEEE-754 float semantics so
            // multi-target simulation digests remain bit-identical across backends; explicit `fma`
            // / `mul_add` intrinsics still emit `b.ins().fma(...)` when requested.
            let _ = allow_fma;

            let res = if is_cmp_op(op) {
                float_cmp(self.b, op, lv, rv)
            } else {
                float_binop(self.b, fty, op, lv, rv)
            };
            self.def_scalar_typed(dst, res);
            return;
        }

        let lty_resolved = self.ctx.enum_scalar_mir_ty(lty);
        let rty_resolved = self.ctx.enum_scalar_mir_ty(rty);
        let lty_eff = lty_resolved.as_ref().unwrap_or(lty);
        let rty_eff = rty_resolved.as_ref().unwrap_or(rty);
        let op_ty = common_int_ty(lty_eff, rty_eff, dst_ty, ptr_ty, self.ctx.call_conv);
        let signed = is_signed_int_ty(lty_eff) || is_signed_int_ty(rty_eff);
        let lv = {
            let __tmp = self.use_scalar(lhs);
            coerce_cl_val(self.b, __tmp, op_ty, ptr_ty)
        };
        let rv = {
            let __tmp = self.use_scalar(rhs);
            coerce_cl_val(self.b, __tmp, op_ty, ptr_ty)
        };
        let res = int_binop_or_cmp(self.b, op_ty, signed, op, lv, rv);
        self.def_scalar_typed(dst, res);
    }

    pub(super) fn lower_unop(&mut self, dst: LocalId, op: &str, val: LocalId) {
        if op == "-"
            && let Some(cv) = self.const_defs.get(&val.0).cloned()
        {
            match cv {
                MirConstVal::Int(i) => {
                    self.const_defs
                        .insert(dst.0, MirConstVal::Int(i.wrapping_neg()));
                }
                MirConstVal::Float(f) => {
                    self.const_defs.insert(dst.0, MirConstVal::Float(-f));
                }
                MirConstVal::Vec2(v) => {
                    self.const_defs
                        .insert(dst.0, MirConstVal::Vec2([-v[0], -v[1]]));
                }
                MirConstVal::Vec3(v) => {
                    self.const_defs
                        .insert(dst.0, MirConstVal::Vec3([-v[0], -v[1], -v[2]]));
                }
                MirConstVal::Vec4(v) => {
                    self.const_defs
                        .insert(dst.0, MirConstVal::Vec4([-v[0], -v[1], -v[2], -v[3]]));
                }
                _ => {}
            }
        } else if op == "!"
            && let Some(&MirConstVal::Bool(b)) = self.const_defs.get(&val.0)
        {
            self.const_defs.insert(dst.0, MirConstVal::Bool(!b));
        }
        let vty = self.effective_local_mir_ty(val).clone();
        if let Some(dims) = vec_dims(&vty) {
            let mut vs = self.use_vec(val);
            if op == "-" {
                if is_ivec_mir_ty(&vty) {
                    for v in vs.iter_mut().take(usize::from(dims)) {
                        *v = self.b.ins().ineg(*v);
                    }
                } else {
                    for v in vs.iter_mut().take(usize::from(dims)) {
                        *v = self.b.ins().fneg(*v);
                    }
                }
            }
            self.def_vec(dst, vs);
            return;
        }
        let sv = self.use_scalar(val);
        let res = match op {
            "-" => match vty {
                MirType::F32 | MirType::F64 => self.b.ins().fneg(sv),
                _ => self.b.ins().ineg(sv),
            },
            "!" => self.b.ins().icmp_imm_s(IntCC::Equal, sv, 0),
            "~" => self.b.ins().bnot(sv),
            _ => sv,
        };
        self.def_scalar_typed(dst, res);
    }

    pub(super) fn lower_cast(&mut self, dst: LocalId, val: LocalId, target_ty: &MirType) {
        let src_ty = self.effective_local_mir_ty(val).clone();
        if let Some(dims) = vec_dims(target_ty) {
            let is_ivec = is_ivec_mir_ty(target_ty);
            let mut vs = self.vec_or_broadcast_arg(val, dims, is_ivec);
            let z = if is_ivec {
                self.b.ins().iconst(types::I32, 0)
            } else {
                self.b.ins().f32const(0.0)
            };
            for v in vs.iter_mut().skip(usize::from(dims)) {
                *v = z;
            }
            self.def_vec(dst, vs);
            return;
        }
        if matches!(src_ty, MirType::Fix32 | MirType::Fix64)
            || matches!(target_ty, MirType::Fix32 | MirType::Fix64 | MirType::F64)
        {
            let res = self.coerce_val_to_mir_ty(val, target_ty);
            self.def_scalar_typed(dst, res);
            return;
        }
        if *target_ty == MirType::Bool {
            let sv = self.use_scalar(val);
            let res = cast_to_bool(self.b, sv, &src_ty);
            self.def_scalar_typed(dst, res);
            return;
        }
        let sv = self.use_scalar(val);
        let ptr_ty = self.ctx.ptr_ty;
        let dst_cl = self.ctx.cl_type_for_mir_val(target_ty);
        let src_signed = is_signed_int_ty(&src_ty);
        let dst_signed = is_signed_int_ty(target_ty);
        let res = cast_value(self.b, sv, &src_ty, src_signed, dst_cl, dst_signed, ptr_ty);
        self.def_scalar_typed(dst, res);
    }

    pub(super) fn lower_intrinsic_math(
        &mut self,
        dst: LocalId,
        name: &str,
        args: &[LocalId],
        _deterministic: bool,
    ) -> Result<(), JitError> {
        let short = name.rsplit("::").next().unwrap_or(name);
        let ptr_ty = self.ctx.ptr_ty;
        let zero_f32 = self.b.ins().f32const(0.0);

        match short {
            "vec2" | "Vec2" | "vec3" | "Vec3" | "vec3a" | "Vec3a" | "vec4" | "Vec4" | "quat"
            | "Quat" | "rgba" | "Rgba" => {
                let mut lanes = [zero_f32; 4];
                if args.len() == 1 && self.effective_vec_dims(args[0]).is_some() {
                    lanes = self.use_vec(args[0]);
                } else {
                    for (i, &a) in args.iter().take(4).enumerate() {
                        lanes[i] = {
                            let __tmp = self.use_scalar(a);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                    }
                }
                self.def_vec(dst, lanes);
                return Ok(());
            }
            "ivec2" | "IVec2" | "ivec3" | "IVec3" | "uvec2" | "UVec2" => {
                let zero_i32 = self.b.ins().iconst(types::I32, 0);
                let mut lanes = [zero_i32; 4];
                if args.len() == 1 && self.effective_vec_dims(args[0]).is_some() {
                    lanes = self.use_vec(args[0]);
                } else {
                    for (i, &a) in args.iter().take(4).enumerate() {
                        let raw = self.use_scalar(a);
                        let src_ty = self.effective_local_mir_ty(a).clone();
                        lanes[i] = if matches!(src_ty, MirType::F32 | MirType::F64) {
                            if short.eq_ignore_ascii_case("uvec2") {
                                self.b.ins().fcvt_to_uint_sat(types::I32, raw)
                            } else {
                                self.b.ins().fcvt_to_sint_sat(types::I32, raw)
                            }
                        } else {
                            coerce_cl_val(self.b, raw, types::I32, ptr_ty)
                        };
                    }
                }
                self.def_vec(dst, lanes);
                return Ok(());
            }
            "mat3" | "Mat3" => {
                let slot = alloc_zero_slot(self.b, 36, ptr_ty);
                let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                if args.len() == 3 && self.effective_vec_dims(args[0]).is_some() {
                    for (col, &arg) in args.iter().enumerate() {
                        let v = self.use_vec_dims(arg, 3);
                        for (row, &lane) in v.iter().take(3).enumerate() {
                            self.b.ins().store(
                                MemFlagsData::new(),
                                lane,
                                base_ptr,
                                ((col * 3 + row) * 4) as i32,
                            );
                        }
                    }
                } else if args.len() == 1 {
                    let amty = self.effective_local_mir_ty(args[0]).clone();
                    if matches!(amty, MirType::Named(ref n) if n == "mat3") {
                        let src_ptr = self.use_scalar(args[0]);
                        emit_memcpy(self.b, base_ptr, src_ptr, 36);
                    } else {
                        let s = {
                            let __tmp = self.use_scalar(args[0]);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                        for d in [0i32, 4, 8] {
                            self.b.ins().store(MemFlagsData::new(), s, base_ptr, d * 4);
                        }
                    }
                } else if args.is_empty() {
                    let one = self.b.ins().f32const(1.0);
                    for d in [0i32, 4, 8] {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), one, base_ptr, d * 4);
                    }
                } else {
                    for (i, &arg) in args.iter().take(9).enumerate() {
                        let v = {
                            let __tmp = self.use_scalar(arg);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), v, base_ptr, (i * 4) as i32);
                    }
                }
                self.def_scalar_typed(dst, base_ptr);
                self.ptr_pointee_tys
                    .insert(dst.0, MirType::Named("mat3".to_owned()));
                return Ok(());
            }
            "mat4" | "Mat4" => {
                let slot = alloc_zero_slot(self.b, 64, ptr_ty);
                let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                if args.len() == 4 && self.effective_vec_dims(args[0]).is_some() {
                    for (col, &arg) in args.iter().enumerate() {
                        let v = self.use_vec_dims(arg, 4);
                        for (row, &lane) in v.iter().enumerate() {
                            self.b.ins().store(
                                MemFlagsData::new(),
                                lane,
                                base_ptr,
                                ((col * 4 + row) * 4) as i32,
                            );
                        }
                    }
                } else if args.len() == 1 {
                    let amty = self.effective_local_mir_ty(args[0]).clone();
                    if matches!(amty, MirType::Named(ref n) if n == "mat4") {
                        let src_ptr = self.use_scalar(args[0]);
                        emit_memcpy(self.b, base_ptr, src_ptr, 64);
                    } else {
                        let s = {
                            let __tmp = self.use_scalar(args[0]);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                        for d in [0i32, 5, 10, 15] {
                            self.b.ins().store(MemFlagsData::new(), s, base_ptr, d * 4);
                        }
                    }
                } else if args.is_empty() {
                    let one = self.b.ins().f32const(1.0);
                    for d in [0i32, 5, 10, 15] {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), one, base_ptr, d * 4);
                    }
                } else {
                    for (i, &arg) in args.iter().take(16).enumerate() {
                        let v = {
                            let __tmp = self.use_scalar(arg);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), v, base_ptr, (i * 4) as i32);
                    }
                }
                self.def_scalar_typed(dst, base_ptr);
                self.ptr_pointee_tys
                    .insert(dst.0, MirType::Named("mat4".to_owned()));
                return Ok(());
            }
            "dot" if args.len() >= 2 => {
                let dims = self
                    .effective_vec_dims(args[0])
                    .or_else(|| self.effective_vec_dims(args[1]))
                    .unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let b = self.use_vec_dims(args[1], dims);
                let mut acc = self.b.ins().fmul(a[0], b[0]);
                for i in 1..usize::from(dims) {
                    let p = self.b.ins().fmul(a[i], b[i]);
                    acc = self.b.ins().fadd(acc, p);
                }
                self.def_scalar_typed(dst, acc);
                return Ok(());
            }
            "length" | "len" if !args.is_empty() => {
                let dims = self.effective_vec_dims(args[0]).unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let mut acc = self.b.ins().fmul(a[0], a[0]);
                for &lane in a.iter().take(usize::from(dims)).skip(1) {
                    let p = self.b.ins().fmul(lane, lane);
                    acc = self.b.ins().fadd(acc, p);
                }
                let l = self.b.ins().sqrt(acc);
                self.def_scalar_typed(dst, l);
                return Ok(());
            }
            "length_sq" | "sqr" if !args.is_empty() => {
                if let Some(dims) = self.effective_vec_dims(args[0]) {
                    let a = self.use_vec_dims(args[0], dims);
                    let mut acc = self.b.ins().fmul(a[0], a[0]);
                    for &lane in a.iter().take(usize::from(dims)).skip(1) {
                        let p = self.b.ins().fmul(lane, lane);
                        acc = self.b.ins().fadd(acc, p);
                    }
                    self.def_scalar_typed(dst, acc);
                } else {
                    self.lower_binop(dst, "*", args[0], args[0], false);
                }
                return Ok(());
            }
            "distance" | "distance_sq" if args.len() >= 2 => {
                let dims = self
                    .effective_vec_dims(args[0])
                    .or_else(|| self.effective_vec_dims(args[1]))
                    .unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let b = self.use_vec_dims(args[1], dims);
                let d0 = self.b.ins().fsub(a[0], b[0]);
                let mut acc = self.b.ins().fmul(d0, d0);
                for i in 1..usize::from(dims) {
                    let di = self.b.ins().fsub(a[i], b[i]);
                    let sq = self.b.ins().fmul(di, di);
                    acc = self.b.ins().fadd(acc, sq);
                }
                let out = if short == "distance" {
                    self.b.ins().sqrt(acc)
                } else {
                    acc
                };
                self.def_scalar_typed(dst, out);
                return Ok(());
            }
            "normalize" | "normalize_or_zero" if !args.is_empty() => {
                let dims = self.effective_vec_dims(args[0]).unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let mut acc = self.b.ins().fmul(a[0], a[0]);
                for &lane in a.iter().take(usize::from(dims)).skip(1) {
                    let p = self.b.ins().fmul(lane, lane);
                    acc = self.b.ins().fadd(acc, p);
                }
                let eps = self.b.ins().f32const(1e-12);
                let len = self.b.ins().sqrt(acc);
                let safe_ok = self.b.ins().fcmp(FloatCC::GreaterThan, len, eps);
                let one = self.b.ins().f32const(1.0);
                let inv = self.b.ins().fdiv(one, len);
                let inv_safe = self.b.ins().select(safe_ok, inv, zero_f32);
                let mut out = [zero_f32; 4];
                for i in 0..usize::from(dims) {
                    out[i] = self.b.ins().fmul(a[i], inv_safe);
                }
                self.def_vec(dst, out);
                return Ok(());
            }
            "cross" if args.len() >= 2 => {
                let a = self.use_vec_dims(args[0], 3);
                let b = self.use_vec_dims(args[1], 3);
                let p0 = self.b.ins().fmul(a[1], b[2]);
                let p1 = self.b.ins().fmul(a[2], b[1]);
                let cx = self.b.ins().fsub(p0, p1);
                let q0 = self.b.ins().fmul(a[2], b[0]);
                let q1 = self.b.ins().fmul(a[0], b[2]);
                let cy = self.b.ins().fsub(q0, q1);
                let r0 = self.b.ins().fmul(a[0], b[1]);
                let r1 = self.b.ins().fmul(a[1], b[0]);
                let cz = self.b.ins().fsub(r0, r1);
                self.def_vec(dst, [cx, cy, cz, zero_f32]);
                return Ok(());
            }
            "perp" if !args.is_empty() => {
                let a = self.use_vec(args[0]);
                let nx = self.b.ins().fneg(a[1]);
                self.def_vec(dst, [nx, a[0], zero_f32, zero_f32]);
                return Ok(());
            }
            "lerp" if args.len() >= 3 => {
                let vec_ty_dims = vec_dims(&self.mir_fn.locals[dst.0 as usize].ty)
                    .or_else(|| self.effective_vec_dims(args[0]));
                if let Some(dims) = vec_ty_dims {
                    let a = self.use_vec_dims(args[0], dims);
                    let b = self.vec_or_broadcast_arg(args[1], dims, false);
                    let t = self.vec_or_broadcast_arg(args[2], dims, false);
                    let mut out = [zero_f32; 4];
                    for i in 0..usize::from(dims) {
                        let d = self.b.ins().fsub(b[i], a[i]);
                        let s = self.b.ins().fmul(d, t[i]);
                        out[i] = self.b.ins().fadd(a[i], s);
                    }
                    self.def_vec(dst, out);
                    return Ok(());
                }
                let fty = if matches!(self.mir_fn.locals[dst.0 as usize].ty, MirType::F64) {
                    types::F64
                } else {
                    types::F32
                };
                let a = {
                    let __tmp = self.use_scalar(args[0]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let t = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let d = self.b.ins().fsub(b, a);
                let s = self.b.ins().fmul(d, t);
                let out = self.b.ins().fadd(a, s);
                self.def_scalar_typed(dst, out);
                return Ok(());
            }
            _ => {}
        }

        // Elementwise vector math (`clamp`, `min`, `max`, `abs`, `floor`, `ceil`, `saturate`, `select`, ...).
        let dst_mty = self.mir_fn.locals[dst.0 as usize].ty.clone();
        if let Some(dims) = vec_dims(&dst_mty) {
            let is_ivec = is_ivec_mir_ty(&dst_mty);
            let signed = !matches!(dst_mty, MirType::UVec2);
            let n = usize::from(dims);
            if is_ivec {
                let z = self.b.ins().iconst(types::I32, 0);
                let mut out = [z; 4];
                match short {
                    "abs" if !args.is_empty() => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, true);
                        for i in 0..n {
                            out[i] = if signed {
                                self.b.ins().iabs(a[i])
                            } else {
                                a[i]
                            };
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "min" | "max" if args.len() >= 2 => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, true);
                        let b = self.vec_or_broadcast_arg(args[1], dims, true);
                        for i in 0..n {
                            out[i] = apply_min_max(
                                self.b,
                                types::I32,
                                short == "min",
                                signed,
                                a[i],
                                b[i],
                            );
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "clamp" if args.len() >= 3 => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, true);
                        let lo = self.vec_or_broadcast_arg(args[1], dims, true);
                        let hi = self.vec_or_broadcast_arg(args[2], dims, true);
                        for i in 0..n {
                            let c1 = apply_min_max(self.b, types::I32, false, signed, a[i], lo[i]);
                            out[i] = apply_min_max(self.b, types::I32, true, signed, c1, hi[i]);
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "select" if args.len() >= 3 => {
                        let cond = self.use_scalar(args[0]);
                        let tv = self.vec_or_broadcast_arg(args[1], dims, true);
                        let fv = self.vec_or_broadcast_arg(args[2], dims, true);
                        for i in 0..n {
                            out[i] = self.b.ins().select(cond, tv[i], fv[i]);
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    _ => {}
                }
            } else {
                let mut out = [zero_f32; 4];
                match short {
                    "sqrt" | "abs" | "floor" | "ceil" | "trunc" | "saturate" | "fract" | "sign"
                    | "signum" | "round"
                        if !args.is_empty() =>
                    {
                        let a = self.vec_or_broadcast_arg(args[0], dims, false);
                        let one = self.b.ins().f32const(1.0);
                        let m1 = self.b.ins().f32const(-1.0);
                        let round_fref = if short == "round" {
                            let fid = self.ctx.declare_extern_fn(
                                "roundf",
                                &[types::F32],
                                Some(types::F32),
                            )?;
                            Some(self.ctx.obj_mod.declare_func_in_func(fid, self.b.func))
                        } else {
                            None
                        };
                        for i in 0..n {
                            out[i] = match short {
                                "sqrt" => self.b.ins().sqrt(a[i]),
                                "abs" => self.b.ins().fabs(a[i]),
                                "floor" => self.b.ins().floor(a[i]),
                                "ceil" => self.b.ins().ceil(a[i]),
                                "trunc" => self.b.ins().trunc(a[i]),
                                "round" => {
                                    let rf = round_fref.expect("roundf declared");
                                    let c = self.b.ins().call(rf, &[a[i]]);
                                    self.b.inst_results(c)[0]
                                }
                                "saturate" => {
                                    let c1 = self.b.ins().fmax(a[i], zero_f32);
                                    self.b.ins().fmin(c1, one)
                                }
                                "fract" => {
                                    let fl = self.b.ins().floor(a[i]);
                                    self.b.ins().fsub(a[i], fl)
                                }
                                _ => {
                                    let gt =
                                        self.b.ins().fcmp(FloatCC::GreaterThan, a[i], zero_f32);
                                    let lt = self.b.ins().fcmp(FloatCC::LessThan, a[i], zero_f32);
                                    let s1 = self.b.ins().select(lt, m1, zero_f32);
                                    self.b.ins().select(gt, one, s1)
                                }
                            };
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "min" | "max" if args.len() >= 2 => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, false);
                        let b = self.vec_or_broadcast_arg(args[1], dims, false);
                        for i in 0..n {
                            out[i] = if short == "min" {
                                self.b.ins().fmin(a[i], b[i])
                            } else {
                                self.b.ins().fmax(a[i], b[i])
                            };
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "clamp" if args.len() >= 3 => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, false);
                        let lo = self.vec_or_broadcast_arg(args[1], dims, false);
                        let hi = self.vec_or_broadcast_arg(args[2], dims, false);
                        for i in 0..n {
                            let c1 = self.b.ins().fmax(a[i], lo[i]);
                            out[i] = self.b.ins().fmin(c1, hi[i]);
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "select" if args.len() >= 3 => {
                        let cond = self.use_scalar(args[0]);
                        let tv = self.vec_or_broadcast_arg(args[1], dims, false);
                        let fv = self.vec_or_broadcast_arg(args[2], dims, false);
                        for i in 0..n {
                            out[i] = self.b.ins().select(cond, tv[i], fv[i]);
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    "mul_add" | "fma" if args.len() >= 3 => {
                        let a = self.vec_or_broadcast_arg(args[0], dims, false);
                        let b = self.vec_or_broadcast_arg(args[1], dims, false);
                        let c = self.vec_or_broadcast_arg(args[2], dims, false);
                        for i in 0..n {
                            out[i] = self.b.ins().fma(a[i], b[i], c[i]);
                        }
                        self.def_vec(dst, out);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // Scalar hardware or imported libm math.
        let is_f64 = dst_mty == MirType::F64
            || args
                .first()
                .is_some_and(|a| self.mir_fn.locals[a.0 as usize].ty == MirType::F64);
        let is_int = !is_f64 && dst_mty != MirType::F32 && vec_dims(&dst_mty).is_none();

        if is_int && !args.is_empty() {
            let ity = self.expected_cl_ty(dst);
            let signed = is_signed_int_ty(&dst_mty);
            let a = {
                let __tmp = self.use_scalar(args[0]);
                coerce_cl_val(self.b, __tmp, ity, ptr_ty)
            };
            let out = match short {
                "abs" => {
                    if signed {
                        self.b.ins().iabs(a)
                    } else {
                        a
                    }
                }
                "min" if args.len() >= 2 => {
                    let b = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        self.b.ins().smin(a, b)
                    } else {
                        self.b.ins().umin(a, b)
                    }
                }
                "max" if args.len() >= 2 => {
                    let b = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        self.b.ins().smax(a, b)
                    } else {
                        self.b.ins().umax(a, b)
                    }
                }
                "clamp" if args.len() >= 3 => {
                    let lo = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    let hi = {
                        let __tmp = self.use_scalar(args[2]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        let c1 = self.b.ins().smax(a, lo);
                        self.b.ins().smin(c1, hi)
                    } else {
                        let c1 = self.b.ins().umax(a, lo);
                        self.b.ins().umin(c1, hi)
                    }
                }
                _ => a,
            };
            self.def_scalar_typed(dst, out);
            return Ok(());
        }

        let fty = if is_f64 { types::F64 } else { types::F32 };
        let a = if let Some(&a0) = args.first() {
            {
                let __tmp = self.use_scalar(a0);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            }
        } else {
            zero_f32
        };

        let hardware_val = match short {
            "sqrt" => Some(self.b.ins().sqrt(a)),
            "abs" => Some(self.b.ins().fabs(a)),
            "floor" => Some(self.b.ins().floor(a)),
            "ceil" => Some(self.b.ins().ceil(a)),
            "trunc" => Some(self.b.ins().trunc(a)),
            "min" if args.len() >= 2 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fmin(a, b))
            }
            "max" if args.len() >= 2 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fmax(a, b))
            }
            "clamp" if args.len() >= 3 => {
                let lo = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let hi = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let c1 = self.b.ins().fmax(a, lo);
                Some(self.b.ins().fmin(c1, hi))
            }
            "saturate" => {
                let z = if is_f64 {
                    self.b.ins().f64const(0.0)
                } else {
                    zero_f32
                };
                let o = if is_f64 {
                    self.b.ins().f64const(1.0)
                } else {
                    self.b.ins().f32const(1.0)
                };
                let c1 = self.b.ins().fmax(a, z);
                Some(self.b.ins().fmin(c1, o))
            }
            "fract" => {
                let fl = self.b.ins().floor(a);
                Some(self.b.ins().fsub(a, fl))
            }
            "sign" | "signum" => {
                let z = if is_f64 {
                    self.b.ins().f64const(0.0)
                } else {
                    zero_f32
                };
                let p1 = if is_f64 {
                    self.b.ins().f64const(1.0)
                } else {
                    self.b.ins().f32const(1.0)
                };
                let m1 = if is_f64 {
                    self.b.ins().f64const(-1.0)
                } else {
                    self.b.ins().f32const(-1.0)
                };
                let gt = self.b.ins().fcmp(FloatCC::GreaterThan, a, z);
                let lt = self.b.ins().fcmp(FloatCC::LessThan, a, z);
                let s1 = self.b.ins().select(lt, m1, z);
                Some(self.b.ins().select(gt, p1, s1))
            }
            "select" if args.len() >= 3 => {
                let cond = self.use_scalar(args[0]);
                let tv = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let fv = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().select(cond, tv, fv))
            }
            "mul_add" | "fma" if args.len() >= 3 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let c = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fma(a, b, c))
            }
            _ => None,
        };
        if let Some(v) = hardware_val {
            self.def_scalar_typed(dst, v);
            return Ok(());
        }

        // Imported libm calls (`sinf`, `cosf`, `tanf`, `atan2f`, `powf`, `expf`, `logf`, `roundf`, ...).
        let (sym_name, arity): (&str, usize) = match (short, is_f64) {
            ("sin", false) => ("sinf", 1),
            ("sin", true) => ("sin", 1),
            ("cos", false) => ("cosf", 1),
            ("cos", true) => ("cos", 1),
            ("tan", false) => ("tanf", 1),
            ("tan", true) => ("tan", 1),
            ("asin", false) => ("asinf", 1),
            ("asin", true) => ("asin", 1),
            ("acos", false) => ("acosf", 1),
            ("acos", true) => ("acos", 1),
            ("atan", false) => ("atanf", 1),
            ("atan", true) => ("atan", 1),
            ("atan2", false) => ("atan2f", 2),
            ("atan2", true) => ("atan2", 2),
            ("pow" | "powf", false) => ("powf", 2),
            ("pow" | "powf", true) => ("pow", 2),
            ("exp", false) => ("expf", 1),
            ("exp", true) => ("exp", 1),
            ("log" | "ln", false) => ("logf", 1),
            ("log" | "ln", true) => ("log", 1),
            ("log2", false) => ("log2f", 1),
            ("log2", true) => ("log2", 1),
            ("log10", false) => ("log10f", 1),
            ("log10", true) => ("log10", 1),
            ("round", false) => ("roundf", 1),
            ("round", true) => ("round", 1),
            ("fmod", false) => ("fmodf", 2),
            ("fmod", true) => ("fmod", 2),
            ("copysign", false) => ("copysignf", 2),
            ("copysign", true) => ("copysign", 2),
            ("hypot", false) => ("hypotf", 2),
            ("hypot", true) => ("hypot", 2),
            _ => {
                self.def_scalar_typed(dst, a);
                return Ok(());
            }
        };

        let mut arg_vals = vec![a];
        if arity == 2 {
            let b_val = if let Some(&a1) = args.get(1) {
                {
                    let __tmp = self.use_scalar(a1);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                }
            } else {
                a
            };
            arg_vals.push(b_val);
        }
        let param_tys = vec![fty; arity];
        let fid = self
            .ctx
            .declare_extern_fn(sym_name, &param_tys, Some(fty))?;
        let fref = self.ctx.obj_mod.declare_func_in_func(fid, self.b.func);
        let call = self.b.ins().call(fref, &arg_vals);
        let res = self.b.inst_results(call)[0];
        self.def_scalar_typed(dst, res);
        Ok(())
    }

    pub(super) fn lower_helper_call(
        &mut self,
        dst: Option<LocalId>,
        callee: &str,
        args: &[LocalId],
    ) -> Result<(), JitError> {
        let short = callee.rsplit("::").next().unwrap_or(callee);
        let Some(&(fid, hidx)) = self
            .ctx
            .helper_funcs
            .get(callee)
            .or_else(|| self.ctx.helper_funcs.get(short))
        else {
            if let Some(item_name) = callee.strip_suffix("::start")
                && let Some(d) = dst
            {
                let ptr_ty = self.ctx.ptr_ty;
                if let Some(tl) = self
                    .ctx
                    .mir
                    .timelines
                    .iter()
                    .find(|t| t.name == item_name || t.canonical_name == item_name)
                    .cloned()
                {
                    let lidx = lookup_name_in_map(&self.ctx.layout_map, &tl.canonical_name)
                        .or_else(|| lookup_name_in_map(&self.ctx.layout_map, item_name));
                    let sz = lidx.map_or(16, |i| self.ctx.layouts[i].size).max(8);
                    let slot = alloc_zero_slot(self.b, sz, ptr_ty);
                    let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                    let (off, resolved_ty) = self
                        .ctx
                        .resolve_field_offset_and_ty(&tl.canonical_name, "flags");
                    if let Some(mty) = resolved_ty {
                        let one = self.b.ins().iconst(self.ctx.cl_type_for_mir_val(&mty), 1);
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), one, base_ptr, off as i32);
                    }
                    self.def_scalar_typed(d, base_ptr);
                    return Ok(());
                }
                if let Some(tk) = self
                    .ctx
                    .mir
                    .tasks
                    .iter()
                    .find(|t| t.name == item_name || t.state_layout.canonical_name == item_name)
                    .cloned()
                {
                    let lidx =
                        lookup_name_in_map(&self.ctx.layout_map, &tk.state_layout.canonical_name)
                            .or_else(|| lookup_name_in_map(&self.ctx.layout_map, item_name));
                    let sz = lidx
                        .map_or(tk.state_layout.size, |i| self.ctx.layouts[i].size)
                        .max(8);
                    let slot = alloc_zero_slot(self.b, sz, ptr_ty);
                    let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                    if let Some(i) = lidx
                        && let Some(blob_id) = self.ctx.layouts[i].default_blob_id
                    {
                        let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
                        let def_ptr = self.b.ins().symbol_value(ptr_ty, gv);
                        emit_memcpy(self.b, base_ptr, def_ptr, self.ctx.layouts[i].size);
                    }
                    for (pi, tp) in tk.typed_params.iter().enumerate() {
                        if let Some(&arg_l) = args.get(pi) {
                            let (off, resolved_ty) = self.ctx.resolve_field_offset_and_ty(
                                &tk.state_layout.canonical_name,
                                &tp.name,
                            );
                            let local_ty = self.effective_local_mir_ty(arg_l).clone();
                            let dst_mty = resolved_ty.unwrap_or_else(|| local_ty.clone());
                            self.store_typed_field_to_mem(
                                arg_l, &local_ty, &dst_mty, base_ptr, off as i32,
                            );
                        }
                    }
                    self.def_scalar_typed(d, base_ptr);
                    return Ok(());
                }
                if let Some(fsm) = self
                    .ctx
                    .mir
                    .fsms
                    .iter()
                    .find(|f| f.name == item_name || f.state_layout.canonical_name == item_name)
                    .cloned()
                {
                    let lidx =
                        lookup_name_in_map(&self.ctx.layout_map, &fsm.state_layout.canonical_name)
                            .or_else(|| lookup_name_in_map(&self.ctx.layout_map, item_name));
                    let sz = lidx
                        .map_or(fsm.state_layout.size, |i| self.ctx.layouts[i].size)
                        .max(8);
                    let slot = alloc_zero_slot(self.b, sz, ptr_ty);
                    let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                    if let Some(i) = lidx
                        && let Some(blob_id) = self.ctx.layouts[i].default_blob_id
                    {
                        let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
                        let def_ptr = self.b.ins().symbol_value(ptr_ty, gv);
                        emit_memcpy(self.b, base_ptr, def_ptr, self.ctx.layouts[i].size);
                    }
                    let init_idx = fsm
                        .states
                        .iter()
                        .position(|s| s == &fsm.initial_state)
                        .unwrap_or(0) as i64;
                    if init_idx != 0 {
                        let (off, resolved_ty) = self.ctx.resolve_field_offset_and_ty(
                            &fsm.state_layout.canonical_name,
                            "__state",
                        );
                        let cl_ty = resolved_ty
                            .as_ref()
                            .map_or(types::I16, |mty| self.ctx.cl_type_for_mir_val(mty));
                        let init_val = self.b.ins().iconst(cl_ty, init_idx);
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), init_val, base_ptr, off as i32);
                    }
                    self.def_scalar_typed(d, base_ptr);
                    return Ok(());
                }
            }
            // Fallback for unqualified math intrinsics emitted as `Call`.
            if let Some(d) = dst {
                return self.lower_intrinsic_math(d, callee, args, false);
            }
            return Ok(());
        };
        let ptr_ty = self.ctx.ptr_ty;
        let hfn = self.ctx.mir.fns[hidx].clone();
        let use_out_ptr = helper_uses_out_ptr(&hfn.ret_ty);
        let mut call_args = vec![self.state_ptr, self.sys_ctx];
        let out_ptr = if use_out_ptr {
            let out_slot = alloc_zero_slot(self.b, 16, ptr_ty);
            let p = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
            call_args.push(p);
            Some(p)
        } else {
            None
        };
        for (i, &arg) in args.iter().enumerate() {
            let expected_ty = hfn.params.get(i).map_or_else(
                || self.mir_fn.locals[arg.0 as usize].ty.clone(),
                |p| p.ty.clone(),
            );
            match expected_ty {
                MirType::Unit => {}
                MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => {
                    let vs = self.use_vec(arg);
                    call_args.push(vs[0]);
                    call_args.push(vs[1]);
                }
                MirType::Vec3 | MirType::IVec3 => {
                    let vs = self.use_vec(arg);
                    call_args.push(vs[0]);
                    call_args.push(vs[1]);
                    call_args.push(vs[2]);
                }
                MirType::Vec4 => {
                    let vs = self.use_vec(arg);
                    call_args.extend_from_slice(&vs);
                }
                other => {
                    if matches!(other, MirType::Ptr | MirType::MutPtr)
                        || self.ctx.is_agg_mir_ty(&other)
                    {
                        let tmp = self.use_scalar(arg);
                        call_args.push(coerce_cl_val(self.b, tmp, ptr_ty, ptr_ty));
                    } else {
                        call_args.push(self.coerce_val_to_mir_ty(arg, &other));
                    }
                }
            }
        }
        let fref = self.ctx.obj_mod.declare_func_in_func(fid, self.b.func);
        let call = self.b.ins().call(fref, &call_args);
        let results = self.b.inst_results(call).to_vec();
        if let Some(d) = dst {
            let dty = self.mir_fn.locals[d.0 as usize].ty.clone();
            if let Some(p) = out_ptr {
                let lane_ty = if is_ivec_mir_ty(&hfn.ret_ty) {
                    types::I32
                } else {
                    types::F32
                };
                let lanes = if hfn.ret_ty == MirType::Vec4 { 4 } else { 3 };
                let mut loaded = Vec::with_capacity(lanes);
                for i in 0..lanes {
                    loaded.push(
                        self.b
                            .ins()
                            .load(lane_ty, MemFlagsData::new(), p, (i * 4) as i32),
                    );
                }
                self.bind_param_val(d, &loaded, &dty);
            } else {
                self.bind_param_val(d, &results, &dty);
            }
        }
        Ok(())
    }

    pub(super) fn lower_struct_init(
        &mut self,
        dst: LocalId,
        type_name: &str,
        fields: &[(String, LocalId)],
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        if type_name == "tuple" {
            let tuple_tys = match &self.mir_fn.locals[dst.0 as usize].ty {
                MirType::Tuple(ts) => ts.clone(),
                _ => Vec::new(),
            };
            let sz = fields
                .iter()
                .enumerate()
                .map(|(i, (_, fval))| {
                    let dst_t = tuple_tys
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| self.effective_local_mir_ty(*fval).clone());
                    i * 8 + self.ctx.layout_size_of_mir_ty(&dst_t)
                })
                .max()
                .unwrap_or(16)
                .max(16);
            let slot = alloc_zero_slot(self.b, sz, ptr_ty);
            let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
            for (i, (_, fval)) in fields.iter().enumerate() {
                let local_ty = self.effective_local_mir_ty(*fval).clone();
                let dst_mty = tuple_tys
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| local_ty.clone());
                self.store_typed_field_to_mem(*fval, &local_ty, &dst_mty, base_ptr, (i * 8) as i32);
            }
            self.def_scalar_typed(dst, base_ptr);
            return;
        }
        let lidx = lookup_name_in_map(&self.ctx.layout_map, type_name);
        let sz = lidx.map_or(16, |i| self.ctx.layouts[i].size).max(8);
        let slot = alloc_zero_slot(self.b, sz, ptr_ty);
        let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);

        let mut has_default_blob = false;
        let mut struct_const_fields = Vec::with_capacity(fields.len());
        let mut all_fields_const = true;

        if let Some(i) = lidx
            && let Some(blob_id) = self.ctx.layouts[i].default_blob_id
        {
            let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
            let def_ptr = self.b.ins().symbol_value(ptr_ty, gv);
            emit_memcpy(self.b, base_ptr, def_ptr, self.ctx.layouts[i].size);
            has_default_blob = true;
        }

        let layout_defaults = lidx.and_then(|i| {
            let cname = &self.ctx.mir_layouts_sorted[i].canonical_name;
            self.ctx.mir.field_defaults.get(cname).or_else(|| {
                cname
                    .rsplit("::")
                    .next()
                    .and_then(|s| self.ctx.mir.field_defaults.get(s))
            })
        });

        for (fname, fval) in fields {
            if let Some(cv) = self.const_defs.get(&fval.0) {
                struct_const_fields.push((fname.clone(), cv.clone()));
                if has_default_blob
                    && let Some(defs) = layout_defaults
                    && let Some(dval) = defs.get(fname)
                    && mir_const_vals_match(cv, dval)
                {
                    continue;
                }
            } else {
                all_fields_const = false;
            }
            let (off, resolved_ty) = self.ctx.resolve_field_offset_and_ty(type_name, fname);
            let local_ty = self.effective_local_mir_ty(*fval).clone();
            let dst_mty = resolved_ty.unwrap_or_else(|| local_ty.clone());
            self.store_typed_field_to_mem(*fval, &local_ty, &dst_mty, base_ptr, off as i32);
        }
        if all_fields_const {
            self.const_defs.insert(
                dst.0,
                MirConstVal::Struct {
                    name: type_name.to_owned(),
                    fields: struct_const_fields,
                },
            );
        }
        self.def_scalar_typed(dst, base_ptr);
    }

    pub(super) fn lower_array_init(&mut self, dst: LocalId, elems: &[LocalId]) {
        self.array_elems.insert(dst.0, elems.to_vec());
        self.array_ptr_lens.insert(dst.0, elems.len());
        let mut arr_const = Vec::with_capacity(elems.len());
        let mut all_const = true;
        for &el in elems {
            if let Some(cv) = self.const_defs.get(&el.0) {
                arr_const.push(cv.clone());
            } else {
                all_const = false;
                break;
            }
        }
        if all_const {
            self.const_defs.insert(dst.0, MirConstVal::Array(arr_const));
        }
        let ptr_ty = self.ctx.ptr_ty;
        let dst_mty = self.effective_local_mir_ty(dst).clone();
        let dst_elem_ty = match &dst_mty {
            MirType::Array { elem, .. } => (**elem).clone(),
            _ => elems
                .first()
                .map(|e| self.effective_local_mir_ty(*e).clone())
                .unwrap_or(MirType::I32),
        };
        self.ptr_elem_tys.insert(dst.0, dst_elem_ty.clone());
        self.ptr_pointee_tys.insert(dst.0, dst_mty);
        let elem_stride = align_up(
            self.ctx.layout_size_of_mir_ty(&dst_elem_ty),
            self.ctx.mir_ty_align_of(&dst_elem_ty).max(1),
        )
        .max(1);
        let total = (elems.len().max(1) * elem_stride).max(8);
        let slot = alloc_zero_slot(self.b, total, ptr_ty);
        let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        for (i, &el) in elems.iter().enumerate() {
            let ety = self.effective_local_mir_ty(el).clone();
            self.store_typed_field_to_mem(
                el,
                &ety,
                &dst_elem_ty,
                base_ptr,
                (i * elem_stride) as i32,
            );
        }
        self.def_scalar_typed(dst, base_ptr);
    }

    pub(super) fn lower_array_index(&mut self, dst: LocalId, base: LocalId, index: LocalId) {
        let ptr_ty = self.ctx.ptr_ty;
        let bp = self.use_scalar(base);
        let idx = {
            let __tmp = self.use_scalar(index);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let base_mty = self.effective_local_mir_ty(base).clone();
        let dty = self.effective_local_mir_ty(dst).clone();
        let elem_ty_opt = self.ptr_elem_tys.get(&base.0).cloned().or_else(|| {
            if let MirType::Array { elem, .. } = &base_mty {
                Some((**elem).clone())
            } else if let Some(MirType::Array { elem, .. }) = self.ptr_pointee_tys.get(&base.0) {
                Some((**elem).clone())
            } else {
                None
            }
        });
        let stride = if matches!(base_mty, MirType::QueryIter) {
            8
        } else if let Some(ref et) = elem_ty_opt {
            align_up(
                self.ctx.layout_size_of_mir_ty(et),
                self.ctx.mir_ty_align_of(et).max(1),
            )
            .max(1)
        } else {
            align_up(
                self.ctx.layout_size_of_mir_ty(&dty),
                self.ctx.mir_ty_align_of(&dty).max(1),
            )
            .max(1)
        };
        let off = self.b.ins().imul_imm_s(idx, stride as i64);
        let raw_addr = self.b.ins().iadd(bp, off);
        let is_null = self.b.ins().icmp_imm_s(IntCC::Equal, bp, 0);
        let zero_p = self.b.ins().iconst(ptr_ty, 0);
        let addr = self.b.ins().select(is_null, zero_p, raw_addr);

        if matches!(dty, MirType::Ptr | MirType::MutPtr) {
            self.def_scalar_typed(dst, addr);
            if let Some(et) = elem_ty_opt {
                self.ptr_pointee_tys.insert(dst.0, et.clone());
                if let MirType::Array { elem, len } = et {
                    self.ptr_elem_tys.insert(dst.0, *elem);
                    self.array_ptr_lens.insert(dst.0, len);
                }
            }
            return;
        }
        if let Some(scalar_mty) = self.ctx.enum_scalar_mir_ty(&dty) {
            let load_bb = self.b.create_block();
            let null_bb = self.b.create_block();
            let merge_bb = self.b.create_block();
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
            self.b.ins().brif(ok, load_bb, &[], null_bb, &[]);
            self.b.switch_to_block(load_bb);
            self.b.seal_block(load_bb);
            self.load_local_from_mem(dst, &scalar_mty, addr, 0);
            self.b.ins().jump(merge_bb, &[]);
            self.b.switch_to_block(null_bb);
            self.b.seal_block(null_bb);
            self.def_zero_for_local(dst);
            self.b.ins().jump(merge_bb, &[]);
            self.b.switch_to_block(merge_bb);
            self.b.seal_block(merge_bb);
        } else if self.ctx.is_agg_mir_ty(&dty) {
            self.def_scalar_typed(dst, addr);
            self.ptr_pointee_tys.insert(dst.0, dty.clone());
            if let MirType::Array { elem, len } = dty {
                self.ptr_elem_tys.insert(dst.0, *elem);
                self.array_ptr_lens.insert(dst.0, len);
            }
        } else {
            let load_bb = self.b.create_block();
            let null_bb = self.b.create_block();
            let merge_bb = self.b.create_block();
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
            self.b.ins().brif(ok, load_bb, &[], null_bb, &[]);
            self.b.switch_to_block(load_bb);
            self.b.seal_block(load_bb);
            self.load_local_from_mem(dst, &dty, addr, 0);
            self.b.ins().jump(merge_bb, &[]);
            self.b.switch_to_block(null_bb);
            self.b.seal_block(null_bb);
            self.def_zero_for_local(dst);
            self.b.ins().jump(merge_bb, &[]);
            self.b.switch_to_block(merge_bb);
            self.b.seal_block(merge_bb);
        }
    }

    pub(super) fn lower_array_store(
        &mut self,
        base_ptr: LocalId,
        index: LocalId,
        val: LocalId,
        elem_ty: &MirType,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let bp = self.use_scalar(base_ptr);
        let idx_i64 = {
            let tmp = self.use_scalar(index);
            coerce_cl_val(self.b, tmp, types::I64, ptr_ty)
        };
        let len_opt = self.array_ptr_lens.get(&base_ptr.0).copied().or_else(|| {
            match self.effective_local_mir_ty(base_ptr) {
                MirType::Array { len, .. } => Some(*len),
                _ => None,
            }
        });
        let bp_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
        let idx_ge0 = self
            .b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThanOrEqual, idx_i64, 0);
        let in_bounds = match len_opt {
            Some(len) => {
                let lt_len = self
                    .b
                    .ins()
                    .icmp_imm_s(IntCC::SignedLessThan, idx_i64, len as i64);
                let idx_ok = self.b.ins().band(idx_ge0, lt_len);
                self.b.ins().band(bp_nz, idx_ok)
            }
            None => self.b.ins().band(bp_nz, idx_ge0),
        };
        let store_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(in_bounds, store_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(store_bb);
        self.b.seal_block(store_bb);
        let raw_eff_elem = self
            .ptr_elem_tys
            .get(&base_ptr.0)
            .cloned()
            .unwrap_or_else(|| elem_ty.clone());
        let eff_elem_ty = self
            .ctx
            .enum_scalar_mir_ty(&raw_eff_elem)
            .unwrap_or(raw_eff_elem);
        let stride = align_up(
            self.ctx.layout_size_of_mir_ty(&eff_elem_ty),
            self.ctx.mir_ty_align_of(&eff_elem_ty).max(1),
        )
        .max(1);
        let idx_ptr = coerce_cl_val(self.b, idx_i64, ptr_ty, ptr_ty);
        let off = self.b.ins().imul_imm_s(idx_ptr, stride as i64);
        let addr = self.b.ins().iadd(bp, off);
        let val_mty = self.effective_local_mir_ty(val).clone();
        self.store_typed_field_to_mem(val, &val_mty, &eff_elem_ty, addr, 0);
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
    }

    fn vec_or_broadcast_arg(&mut self, arg: LocalId, dims: u8, is_ivec: bool) -> [Value; 4] {
        if self.effective_vec_dims(arg).is_some() {
            return self.use_vec_dims(arg, dims);
        }
        let lane_ty = if is_ivec { types::I32 } else { types::F32 };
        let s = self.use_scalar(arg);
        let coerced = coerce_cl_val(self.b, s, lane_ty, self.ctx.ptr_ty);
        [coerced; 4]
    }

    pub(super) fn lower_field_load(
        &mut self,
        dst: LocalId,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        field_ty: &MirType,
    ) {
        let base_mty = self.effective_local_mir_ty(base_ptr).clone();
        if vec_dims(&base_mty).is_some()
            && let Some(lanes) = parse_swizzle_lanes(field)
        {
            let src = self.use_vec(base_ptr);
            let is_ivec = is_ivec_mir_ty(&base_mty);
            if lanes.len() == 1 {
                self.def_scalar_typed(dst, src[usize::from(lanes[0])]);
            } else {
                let z = if is_ivec {
                    self.b.ins().iconst(types::I32, 0)
                } else {
                    self.b.ins().f32const(0.0)
                };
                let mut out = [z; 4];
                for (i, &l) in lanes.iter().take(4).enumerate() {
                    out[i] = src[usize::from(l)];
                }
                self.def_vec(dst, out);
            }
            return;
        }
        if let Some((parent_field, swiz)) = field.rsplit_once('.')
            && let Some(lanes) = parse_swizzle_lanes(swiz)
            && let (parent_off, Some(parent_ty)) = self
                .ctx
                .resolve_field_offset_and_ty(layout_key, parent_field)
            && vec_dims(&parent_ty).is_some()
        {
            let bp = self.use_scalar(base_ptr);
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
            let load_bb = self.b.create_block();
            let null_bb = self.b.create_block();
            let merge_bb = self.b.create_block();
            self.b.ins().brif(ok, load_bb, &[], null_bb, &[]);

            self.b.switch_to_block(load_bb);
            self.b.seal_block(load_bb);
            let is_ivec = is_ivec_mir_ty(&parent_ty);
            let lane_cl = if is_ivec { types::I32 } else { types::F32 };
            let z = zero_for_cl_type(self.b, lane_cl);
            let mut vals = [z; 4];
            for (i, &l) in lanes.iter().take(4).enumerate() {
                vals[i] = self.b.ins().load(
                    lane_cl,
                    MemFlagsData::new(),
                    bp,
                    parent_off as i32 + i32::from(l) * 4,
                );
            }
            if lanes.len() == 1 {
                self.def_scalar_typed(dst, vals[0]);
            } else {
                self.def_vec(dst, vals);
            }
            self.b.ins().jump(merge_bb, &[]);

            self.b.switch_to_block(null_bb);
            self.b.seal_block(null_bb);
            self.def_zero_for_local(dst);
            self.b.ins().jump(merge_bb, &[]);

            self.b.switch_to_block(merge_bb);
            self.b.seal_block(merge_bb);
            return;
        }
        let (resolved_off, resolved_ty) = self.ctx.resolve_field_offset_and_ty(layout_key, field);
        let eff_off = if resolved_ty.is_some() {
            resolved_off
        } else {
            offset_bytes as usize
        };
        let eff_field_ty = resolved_ty.unwrap_or_else(|| field_ty.clone());

        let bp = self.use_scalar(base_ptr);
        let ptr_ty = self.ctx.ptr_ty;
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
        let load_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.ins().brif(ok, load_bb, &[], null_bb, &[]);

        self.b.switch_to_block(load_bb);
        self.b.seal_block(load_bb);
        if let Some(scalar_mty) = self.ctx.enum_scalar_mir_ty(&eff_field_ty) {
            self.load_local_from_mem(dst, &scalar_mty, bp, eff_off as i32);
        } else if self.ctx.is_agg_mir_ty(&eff_field_ty) {
            let addr = self.b.ins().iadd_imm_s(bp, eff_off as i64);
            self.def_scalar_typed(dst, addr);
            self.ptr_pointee_tys.insert(dst.0, eff_field_ty.clone());
            if let MirType::Array { elem, len } = eff_field_ty {
                self.array_ptr_lens.insert(dst.0, len);
                self.ptr_elem_tys.insert(dst.0, *elem);
            }
        } else {
            self.load_local_from_mem(dst, &eff_field_ty, bp, eff_off as i32);
        }
        self.b.ins().jump(merge_bb, &[]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        self.def_zero_for_local(dst);
        self.b.ins().jump(merge_bb, &[]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        let _ = ptr_ty;
    }

    fn emit_memzero(&mut self, dst: Value, size: usize) {
        let mut off = 0usize;
        if size >= 8 {
            let z64 = self.b.ins().iconst(types::I64, 0);
            while off + 8 <= size {
                self.b
                    .ins()
                    .store(MemFlagsData::new(), z64, dst, off as i32);
                off += 8;
            }
        }
        if off + 4 <= size {
            let z32 = self.b.ins().iconst(types::I32, 0);
            while off + 4 <= size {
                self.b
                    .ins()
                    .store(MemFlagsData::new(), z32, dst, off as i32);
                off += 4;
            }
        }
        if off < size {
            let z8 = self.b.ins().iconst(types::I8, 0);
            while off < size {
                self.b.ins().store(MemFlagsData::new(), z8, dst, off as i32);
                off += 1;
            }
        }
    }

    fn emit_copy_inline_str(&mut self, dst_addr: Value, dst_cap: usize, src_ptr: Value) {
        let total = 4 + dst_cap.div_ceil(4) * 4;
        self.emit_memzero(dst_addr, total);
        let ptr_ty = self.ctx.ptr_ty;
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, src_ptr, 0);
        let copy_bb = self.b.create_block();
        let utf8_hdr_bb = self.b.create_block();
        let utf8_chk_bb = self.b.create_block();
        let write_len_bb = self.b.create_block();
        let cp_hdr_bb = self.b.create_block();
        let cp_body_bb = self.b.create_block();
        let done_bb = self.b.create_block();

        self.b.append_block_param(utf8_hdr_bb, types::I32);
        self.b.append_block_param(write_len_bb, types::I32);
        self.b.append_block_param(cp_hdr_bb, types::I32);

        self.b.ins().brif(ok, copy_bb, &[], done_bb, &[]);

        self.b.switch_to_block(copy_bb);
        self.b.seal_block(copy_bb);
        let raw_len = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::new(), src_ptr, 0);
        let cap_i32 = self.b.ins().iconst(types::I32, dst_cap as i64);
        let needs_trunc = self
            .b
            .ins()
            .icmp(IntCC::UnsignedGreaterThan, raw_len, cap_i32);
        self.b.ins().brif(
            needs_trunc,
            utf8_hdr_bb,
            &[BlockArg::Value(cap_i32)],
            write_len_bb,
            &[BlockArg::Value(raw_len)],
        );

        self.b.switch_to_block(utf8_hdr_bb);
        let cur_len = self.b.block_params(utf8_hdr_bb)[0];
        let gt0 = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedGreaterThan, cur_len, 0);
        self.b.ins().brif(
            gt0,
            utf8_chk_bb,
            &[],
            write_len_bb,
            &[BlockArg::Value(cur_len)],
        );

        self.b.switch_to_block(utf8_chk_bb);
        self.b.seal_block(utf8_chk_bb);
        let cur_p = coerce_cl_val(self.b, cur_len, ptr_ty, ptr_ty);
        let src_payload = self.b.ins().iadd_imm_s(src_ptr, 4);
        let chk_addr = self.b.ins().iadd(src_payload, cur_p);
        let ch_u8 = self
            .b
            .ins()
            .load(types::I8, MemFlagsData::new(), chk_addr, 0);
        let ch_i32 = self.b.ins().uextend(types::I32, ch_u8);
        let masked = self.b.ins().band_imm_u(ch_i32, 0xC0);
        let is_cont = self.b.ins().icmp_imm_s(IntCC::Equal, masked, 0x80);
        let dec = self.b.ins().iadd_imm_s(cur_len, -1);
        self.b.ins().brif(
            is_cont,
            utf8_hdr_bb,
            &[BlockArg::Value(dec)],
            write_len_bb,
            &[BlockArg::Value(cur_len)],
        );
        self.b.seal_block(utf8_hdr_bb);

        self.b.switch_to_block(write_len_bb);
        self.b.seal_block(write_len_bb);
        let final_len = self.b.block_params(write_len_bb)[0];
        self.b
            .ins()
            .store(MemFlagsData::new(), final_len, dst_addr, 0);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.ins().jump(cp_hdr_bb, &[BlockArg::Value(z32)]);

        self.b.switch_to_block(cp_hdr_bb);
        let idx = self.b.block_params(cp_hdr_bb)[0];
        let more = self.b.ins().icmp(IntCC::UnsignedLessThan, idx, final_len);
        self.b.ins().brif(more, cp_body_bb, &[], done_bb, &[]);

        self.b.switch_to_block(cp_body_bb);
        self.b.seal_block(cp_body_bb);
        let idx_p = coerce_cl_val(self.b, idx, ptr_ty, ptr_ty);
        let sa = self.b.ins().iadd(src_ptr, idx_p);
        let da = self.b.ins().iadd(dst_addr, idx_p);
        let byte = self.b.ins().load(types::I8, MemFlagsData::new(), sa, 4);
        self.b.ins().store(MemFlagsData::new(), byte, da, 4);
        let nxt = self.b.ins().iadd_imm_s(idx, 1);
        self.b.ins().jump(cp_hdr_bb, &[BlockArg::Value(nxt)]);
        self.b.seal_block(cp_hdr_bb);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn copy_coerced_array_to_mem(
        &mut self,
        src_ptr: Value,
        src_elem_ty: &MirType,
        src_len: usize,
        dst_ptr: Value,
        dst_elem_ty: &MirType,
        dst_len: usize,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let src_stride = align_up(
            self.ctx.layout_size_of_mir_ty(src_elem_ty),
            self.ctx.mir_ty_align_of(src_elem_ty).max(1),
        )
        .max(1);
        let dst_stride = align_up(
            self.ctx.layout_size_of_mir_ty(dst_elem_ty),
            self.ctx.mir_ty_align_of(dst_elem_ty).max(1),
        )
        .max(1);
        let copy_len = dst_len.min(src_len);
        if src_len < dst_len {
            let total_dst = dst_len * dst_stride;
            self.emit_memzero(dst_ptr, total_dst);
        }
        if let MirType::Named(dst_n) = dst_elem_ty
            && let Some(dst_cap) = inline_str_cap_from_name(dst_n)
        {
            for i in 0..copy_len {
                let s_off = self.b.ins().iadd_imm_s(src_ptr, (i * src_stride) as i64);
                let d_off = self.b.ins().iadd_imm_s(dst_ptr, (i * dst_stride) as i64);
                self.emit_copy_inline_str(d_off, dst_cap, s_off);
            }
            return;
        }
        if let Some(dst_bs_bytes) = bitset_bytes_from_mir_ty(dst_elem_ty) {
            let src_bs_bytes = bitset_bytes_from_mir_ty(src_elem_ty);
            for i in 0..copy_len {
                let s_off = self.b.ins().iadd_imm_s(src_ptr, (i * src_stride) as i64);
                let d_off = self.b.ins().iadd_imm_s(dst_ptr, (i * dst_stride) as i64);
                self.emit_memzero(d_off, dst_bs_bytes);
                if let Some(sb) = src_bs_bytes {
                    emit_memcpy(self.b, d_off, s_off, sb.min(dst_bs_bytes));
                } else {
                    let src_cl = self.ctx.cl_type_for_mir_val(src_elem_ty);
                    let raw = self.b.ins().load(src_cl, MemFlagsData::new(), s_off, 0);
                    let store_cl = if dst_bs_bytes == 4 {
                        types::I32
                    } else {
                        types::I64
                    };
                    let val = coerce_cl_val(self.b, raw, store_cl, ptr_ty);
                    self.b.ins().store(MemFlagsData::new(), val, d_off, 0);
                }
            }
            return;
        }
        if let (
            MirType::Array {
                elem: inner_src,
                len: inner_src_len,
            },
            MirType::Array {
                elem: inner_dst,
                len: inner_dst_len,
            },
        ) = (src_elem_ty, dst_elem_ty)
        {
            for i in 0..copy_len {
                let s_off = self.b.ins().iadd_imm_s(src_ptr, (i * src_stride) as i64);
                let d_off = self.b.ins().iadd_imm_s(dst_ptr, (i * dst_stride) as i64);
                self.copy_coerced_array_to_mem(
                    s_off,
                    inner_src,
                    *inner_src_len,
                    d_off,
                    inner_dst,
                    *inner_dst_len,
                );
            }
            return;
        }
        if !self.ctx.is_agg_mir_ty(src_elem_ty)
            && !self.ctx.is_agg_mir_ty(dst_elem_ty)
            && vec_dims(src_elem_ty).is_none()
            && vec_dims(dst_elem_ty).is_none()
        {
            let src_cl = self.ctx.cl_type_for_mir_val(src_elem_ty);
            let dst_cl = self.ctx.cl_type_for_mir_val(dst_elem_ty);
            for i in 0..copy_len {
                let raw = self.b.ins().load(
                    src_cl,
                    MemFlagsData::new(),
                    src_ptr,
                    (i * src_stride) as i32,
                );
                let coerced = self.coerce_raw_val_to_mir_ty(raw, src_elem_ty, None, dst_elem_ty);
                let final_val = coerce_cl_val(self.b, coerced, dst_cl, ptr_ty);
                self.b.ins().store(
                    MemFlagsData::new(),
                    final_val,
                    dst_ptr,
                    (i * dst_stride) as i32,
                );
            }
            return;
        }
        let sz = copy_len * dst_stride.min(src_stride);
        emit_memcpy(self.b, dst_ptr, src_ptr, sz);
    }

    pub(super) fn store_typed_field_to_mem(
        &mut self,
        val: LocalId,
        val_mty: &MirType,
        dst_mty: &MirType,
        dst_base: Value,
        offset: i32,
    ) {
        if let MirType::Named(dst_name) = dst_mty
            && let Some(dst_cap) = inline_str_cap_from_name(dst_name)
        {
            let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
            let src_ptr = self.use_scalar(val);
            self.emit_copy_inline_str(dst_addr, dst_cap, src_ptr);
            return;
        }
        if let MirType::Named(dst_name) = dst_mty
            && let Some((sv_elem_mty, sv_cap)) = parse_smallvec_mir_name(dst_name)
        {
            let es = self.ctx.layout_size_of_mir_ty(&sv_elem_mty);
            let ea = self.ctx.mir_ty_align_of(&sv_elem_mty).max(1);
            let elem_stride = align_up(es, ea).max(1);
            let total_sv_bytes = 8 + elem_stride * sv_cap;
            let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
            self.emit_memzero(dst_addr, total_sv_bytes);
            if let Some(elems) = self.array_elems.get(&val.0).cloned() {
                let len_u32 = elems.len().min(sv_cap) as i64;
                let len_v = self.b.ins().iconst(types::I32, len_u32);
                self.b.ins().store(MemFlagsData::new(), len_v, dst_addr, 0);
                for (i, &el) in elems.iter().take(sv_cap).enumerate() {
                    let el_mty = self.effective_local_mir_ty(el).clone();
                    self.store_typed_field_to_mem(
                        el,
                        &el_mty,
                        &sv_elem_mty,
                        dst_base,
                        offset + 8 + (i * elem_stride) as i32,
                    );
                }
                return;
            }
            if let MirType::Array {
                elem: src_elem_ty,
                len: src_len,
            } = val_mty
            {
                let src_ptr = self.use_scalar(val);
                let len_v = self
                    .b
                    .ins()
                    .iconst(types::I32, (*src_len).min(sv_cap) as i64);
                self.b.ins().store(MemFlagsData::new(), len_v, dst_addr, 0);
                let data_dst = self.b.ins().iadd_imm_s(dst_addr, 8);
                self.copy_coerced_array_to_mem(
                    src_ptr,
                    src_elem_ty,
                    *src_len,
                    data_dst,
                    &sv_elem_mty,
                    sv_cap,
                );
                return;
            }
            let src_ptr = self.use_scalar(val);
            let src_pointee = self
                .ptr_pointee_tys
                .get(&val.0)
                .cloned()
                .unwrap_or_else(|| val_mty.clone());
            let src_cap = match &src_pointee {
                MirType::Named(sn) => parse_smallvec_mir_name(sn)
                    .map(|(_, c)| c)
                    .unwrap_or(sv_cap),
                _ => sv_cap,
            };
            let copy_cap = src_cap.min(sv_cap);
            emit_memcpy(self.b, dst_addr, src_ptr, 8 + copy_cap * elem_stride);
            let raw_len = self
                .b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, 0);
            let cap_v = self.b.ins().iconst(types::I32, sv_cap as i64);
            let over = self
                .b
                .ins()
                .icmp(IntCC::UnsignedGreaterThan, raw_len, cap_v);
            let clamped = self.b.ins().select(over, cap_v, raw_len);
            self.b
                .ins()
                .store(MemFlagsData::new(), clamped, dst_addr, 0);
            return;
        }
        if let Some(dst_bs_bytes) = bitset_bytes_from_mir_ty(dst_mty) {
            let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
            self.emit_memzero(dst_addr, dst_bs_bytes);
            let val_is_agg_ptr = matches!(val_mty, MirType::Ptr | MirType::MutPtr)
                || self.ctx.is_agg_mir_ty(val_mty)
                || self.ptr_pointee_tys.contains_key(&val.0);
            if val_is_agg_ptr {
                let src_ptr = self.use_scalar(val);
                let src_bs_bytes = bitset_bytes_from_mir_ty(val_mty).or_else(|| {
                    self.ptr_pointee_tys
                        .get(&val.0)
                        .and_then(bitset_bytes_from_mir_ty)
                });
                let copy_sz = src_bs_bytes.unwrap_or(dst_bs_bytes).min(dst_bs_bytes);
                emit_memcpy(self.b, dst_addr, src_ptr, copy_sz);
            } else {
                let raw = self.use_scalar(val);
                let store_cl = if dst_bs_bytes == 4 {
                    types::I32
                } else {
                    types::I64
                };
                let coerced = coerce_cl_val(self.b, raw, store_cl, self.ctx.ptr_ty);
                self.b
                    .ins()
                    .store(MemFlagsData::new(), coerced, dst_addr, 0);
            }
            return;
        }
        if let MirType::Array {
            elem: dst_elem_ty,
            len: dst_len,
        } = dst_mty
        {
            let elem_stride = align_up(
                self.ctx.layout_size_of_mir_ty(dst_elem_ty),
                self.ctx.mir_ty_align_of(dst_elem_ty).max(1),
            )
            .max(1);
            if let Some(elems) = self.array_elems.get(&val.0).cloned() {
                if elems.len() < *dst_len {
                    let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
                    self.emit_memzero(dst_addr, (*dst_len) * elem_stride);
                }
                for (i, &el) in elems.iter().take(*dst_len).enumerate() {
                    let el_mty = self.effective_local_mir_ty(el).clone();
                    self.store_typed_field_to_mem(
                        el,
                        &el_mty,
                        dst_elem_ty,
                        dst_base,
                        offset + (i * elem_stride) as i32,
                    );
                }
                return;
            }
            if let MirType::Array {
                elem: src_elem_ty,
                len: src_len,
            } = val_mty
                && (src_elem_ty != dst_elem_ty || *src_len != *dst_len)
            {
                let src_ptr = self.use_scalar(val);
                let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
                self.copy_coerced_array_to_mem(
                    src_ptr,
                    src_elem_ty,
                    *src_len,
                    dst_addr,
                    dst_elem_ty,
                    *dst_len,
                );
                return;
            }
        }
        let val_is_agg_ptr = matches!(val_mty, MirType::Ptr | MirType::MutPtr)
            || self.ctx.is_agg_mir_ty(val_mty)
            || self.ptr_pointee_tys.contains_key(&val.0);
        if self.ctx.is_agg_mir_ty(dst_mty) && val_is_agg_ptr {
            let src_ptr = self.use_scalar(val);
            let sz = self.ctx.layout_size_of_mir_ty(dst_mty);
            let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
            emit_memcpy(self.b, dst_addr, src_ptr, sz);
        } else {
            let store_mty = if self.ctx.is_agg_mir_ty(dst_mty) {
                val_mty
            } else {
                dst_mty
            };
            self.store_local_to_mem(val, store_mty, dst_base, offset);
        }
    }

    pub(super) fn lower_field_store(
        &mut self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        val: LocalId,
    ) {
        let base_mty = self.effective_local_mir_ty(base_ptr).clone();
        if let Some(base_dims) = vec_dims(&base_mty)
            && let Some(lanes) = parse_swizzle_lanes(field)
        {
            let is_ivec = is_ivec_mir_ty(&base_mty);
            let rhs = self.vec_or_broadcast_arg(val, lanes.len().min(4) as u8, is_ivec);
            let lane_cl = if is_ivec { types::I32 } else { types::F32 };
            match self.local_reps[base_ptr.0 as usize] {
                LocalRep::Vec(_) => {
                    let mut cur = self.use_vec_dims(base_ptr, base_dims);
                    for (i, &l) in lanes.iter().enumerate() {
                        cur[usize::from(l)] =
                            coerce_cl_val(self.b, rhs[i], lane_cl, self.ctx.ptr_ty);
                    }
                    self.def_vec(base_ptr, cur);
                }
                LocalRep::AggVar(v) => {
                    let ptr = self.b.use_var(v);
                    for (i, &l) in lanes.iter().enumerate() {
                        let rv = coerce_cl_val(self.b, rhs[i], lane_cl, self.ctx.ptr_ty);
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), rv, ptr, i32::from(l) * 4);
                    }
                }
                LocalRep::Scalar(v) => {
                    let ptr = self.b.use_var(v);
                    if matches!(base_mty, MirType::Ptr | MirType::MutPtr) {
                        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
                        let store_bb = self.b.create_block();
                        let skip_bb = self.b.create_block();
                        self.b.ins().brif(ok, store_bb, &[], skip_bb, &[]);
                        self.b.switch_to_block(store_bb);
                        self.b.seal_block(store_bb);
                        for (i, &l) in lanes.iter().enumerate() {
                            let rv = coerce_cl_val(self.b, rhs[i], lane_cl, self.ctx.ptr_ty);
                            self.b
                                .ins()
                                .store(MemFlagsData::new(), rv, ptr, i32::from(l) * 4);
                        }
                        self.b.ins().jump(skip_bb, &[]);
                        self.b.switch_to_block(skip_bb);
                        self.b.seal_block(skip_bb);
                    }
                }
            }
            return;
        }
        if let Some((parent_field, swiz)) = field.rsplit_once('.')
            && let Some(lanes) = parse_swizzle_lanes(swiz)
            && let (parent_off, Some(parent_ty)) = self
                .ctx
                .resolve_field_offset_and_ty(layout_key, parent_field)
            && vec_dims(&parent_ty).is_some()
        {
            let bp = self.use_scalar(base_ptr);
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
            let store_bb = self.b.create_block();
            let skip_bb = self.b.create_block();
            self.b.ins().brif(ok, store_bb, &[], skip_bb, &[]);
            self.b.switch_to_block(store_bb);
            self.b.seal_block(store_bb);
            let is_ivec = is_ivec_mir_ty(&parent_ty);
            let rhs = self.vec_or_broadcast_arg(val, lanes.len().min(4) as u8, is_ivec);
            let lane_cl = if is_ivec { types::I32 } else { types::F32 };
            for (i, &l) in lanes.iter().enumerate() {
                let rv = coerce_cl_val(self.b, rhs[i], lane_cl, self.ctx.ptr_ty);
                self.b.ins().store(
                    MemFlagsData::new(),
                    rv,
                    bp,
                    parent_off as i32 + i32::from(l) * 4,
                );
            }
            self.b.ins().jump(skip_bb, &[]);
            self.b.switch_to_block(skip_bb);
            self.b.seal_block(skip_bb);
            return;
        }
        let bp = self.use_scalar(base_ptr);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
        let store_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(ok, store_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(store_bb);
        self.b.seal_block(store_bb);
        let val_mty = self.effective_local_mir_ty(val).clone();
        let (_, resolved_field_ty) = self.ctx.resolve_field_offset_and_ty(layout_key, field);
        let dst_mty = resolved_field_ty.unwrap_or_else(|| val_mty.clone());
        self.store_typed_field_to_mem(val, &val_mty, &dst_mty, bp, offset_bytes as i32);
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
    }

    pub(super) fn def_zero_for_local(&mut self, lid: LocalId) {
        let zero_f32 = self.b.ins().f32const(0.0);
        match self.effective_local_mir_ty(lid) {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                self.def_vec(lid, [zero_f32; 4]);
            }
            MirType::IVec2 | MirType::IVec3 | MirType::UVec2 => {
                let zero_i32 = self.b.ins().iconst(types::I32, 0);
                self.def_vec(lid, [zero_i32; 4]);
            }
            MirType::F32 => self.def_scalar_typed(lid, zero_f32),
            MirType::F64 => {
                let z = self.b.ins().f64const(0.0);
                self.def_scalar_typed(lid, z);
            }
            _ => {
                let ty = self.expected_cl_ty(lid);
                let z = zero_for_cl_type(self.b, ty);
                self.def_scalar_typed(lid, z);
            }
        }
    }

    pub(super) fn lower_row_ptr(
        &mut self,
        dst: LocalId,
        col_ptr: LocalId,
        row_idx: LocalId,
        stride_bytes: u32,
        is_sparse: bool,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        if !is_sparse {
            // Check strength reduction plan (`iadd_imm_s` inside row loop, ZERO `imul`!).
            for ((slot_id, base_id), &(stride, ptr_var, is_ent)) in &self.sr_plan.reduced {
                let _ = slot_id;
                if !is_ent && *base_id == col_ptr.0 && stride == stride_bytes {
                    let p = self.b.use_var(ptr_var);
                    self.def_scalar_typed(dst, p);
                    return;
                }
            }
            let base = self.use_scalar(col_ptr);
            let zero_p = self.b.ins().iconst(ptr_ty, 0);
            let is_null = self.b.ins().icmp_imm_s(IntCC::Equal, base, 0);
            let idx = {
                let __tmp = self.use_scalar(row_idx);
                coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
            };
            let off = self.b.ins().imul_imm_s(idx, i64::from(stride_bytes));
            let added = self.b.ins().iadd(base, off);
            let res = self.b.ins().select(is_null, zero_p, added);
            self.def_scalar_typed(dst, res);
            return;
        }

        // Batched `@sparse` indirection: `col_ptr` points to `*const *const u8` (`row_ptrs[row_idx]`).
        let base = self.use_scalar(col_ptr);
        let zero_p = self.b.ins().iconst(ptr_ty, 0);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, base, 0);
        let ld_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.append_block_param(merge_bb, ptr_ty);
        self.b.ins().brif(ok, ld_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(ld_bb);
        self.b.seal_block(ld_bb);
        let idx = {
            let __tmp = self.use_scalar(row_idx);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let off = self.b.ins().imul_imm_s(idx, self.ctx.ptr_bytes as i64);
        let slot_addr = self.b.ins().iadd(base, off);
        let loaded = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), slot_addr, 0);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(loaded)]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(zero_p)]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        let res = self.b.block_params(merge_bb)[0];
        self.def_scalar_typed(dst, res);
    }

    pub(super) fn lower_entity_at_row(
        &mut self,
        dst: LocalId,
        entities_ptr: LocalId,
        row_idx: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        for ((_, base_id), &(_, ptr_var, is_ent)) in &self.sr_plan.reduced {
            if is_ent && *base_id == entities_ptr.0 {
                let ep = self.b.use_var(ptr_var);
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ep, 0);
                let ld_bb = self.b.create_block();
                let null_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.append_block_param(done_bb, types::I64);
                self.b.ins().brif(ok, ld_bb, &[], null_bb, &[]);

                self.b.switch_to_block(ld_bb);
                self.b.seal_block(ld_bb);
                let ent = self
                    .b
                    .ins()
                    .load(types::I64, MemFlagsData::trusted(), ep, 0);
                self.b.ins().jump(done_bb, &[BlockArg::Value(ent)]);

                self.b.switch_to_block(null_bb);
                self.b.seal_block(null_bb);
                let z = self.b.ins().iconst(types::I64, 0);
                self.b.ins().jump(done_bb, &[BlockArg::Value(z)]);

                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
                let res = self.b.block_params(done_bb)[0];
                self.def_scalar_typed(dst, res);
                return;
            }
        }

        let ep = self.use_scalar(entities_ptr);
        let idx = {
            let __tmp = self.use_scalar(row_idx);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ep, 0);
        let ld_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I64);
        self.b.ins().brif(ok, ld_bb, &[], null_bb, &[]);

        self.b.switch_to_block(ld_bb);
        self.b.seal_block(ld_bb);
        let off = self.b.ins().imul_imm_s(idx, 8);
        let addr = self.b.ins().iadd(ep, off);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), addr, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(ent)]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        let z = self.b.ins().iconst(types::I64, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(z)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let res = self.b.block_params(done_bb)[0];
        self.def_scalar_typed(dst, res);
    }

    pub(super) fn call_iter_col(
        &mut self,
        query_idx: u32,
        term_idx: u32,
        slot_offset: usize,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        call_vtable_guarded(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            slot_offset,
            &[ptr_ty, ptr_ty],
            ptr_ty,
            ptr_ty,
            self.ctx.call_conv,
            iter,
            &[iter, tv],
        )
    }

    pub(super) fn lower_iter_reset(&mut self, query_idx: u32) {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        if (query_idx as usize) < self.chunk_len_vars.len() {
            let z32 = self.b.ins().iconst(types::I32, 0);
            self.b.def_var(self.chunk_len_vars[query_idx as usize], z32);
        }
        let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
        let call_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(iter_ok, call_bb, &[], done_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_RESET,
            &[ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_iter_up_cascade(
        &mut self,
        dst: LocalId,
        query_idx: u32,
        relation: &str,
        entity: LocalId,
        term_idx: u32,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let ent = {
            let tmp = self.use_scalar(entity);
            coerce_cl_val(self.b, tmp, types::I64, ptr_ty)
        };
        let rel_v = if is_child_of_rel(relation) {
            self.b
                .ins()
                .iconst(types::I32, i64::from(BAM_COMPONENT_INVALID))
        } else if let Some(parent_lidx) = self.custom_rel_parent_layout_idx(relation) {
            self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(parent_lidx) as i32,
            )
        } else {
            let rel_idx = self.ctx.relation_map.get(relation).copied().or_else(|| {
                relation
                    .rsplit("::")
                    .next()
                    .and_then(|s| self.ctx.relation_map.get(s).copied())
            });
            if let Some(ri) = rel_idx {
                self.b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    self.state_ptr,
                    self.ctx.state_layout.rel_slot_offset(ri) as i32,
                )
            } else {
                self.b
                    .ins()
                    .iconst(types::I32, i64::from(BAM_COMPONENT_INVALID))
            }
        };

        let zero_p = self.b.ins().iconst(ptr_ty, 0);
        let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
        let ent_ok = self
            .b
            .ins()
            .icmp_imm_s(IntCC::NotEqual, ent, FFI_ENTITY_NULL as i64);
        let go = self.b.ins().band(iter_ok, ent_ok);

        let call_bb = self.b.create_block();
        let fail_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, ptr_ty);
        self.b.ins().brif(go, call_bb, &[], fail_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let out_ptr_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr_addr = self.b.ins().stack_addr(ptr_ty, out_ptr_slot, 0);
        let out_owner_slot = alloc_zero_slot(self.b, 8, ptr_ty);
        let out_owner_addr = self.b.ins().stack_addr(ptr_ty, out_owner_slot, 0);
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        let rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_UP_CASCADE,
            &[ptr_ty, types::I32, types::I64, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, rel_v, ent, tv, out_ptr_addr, out_owner_addr],
        );
        let rc_ok = self.b.ins().icmp_imm_s(IntCC::Equal, rc, i64::from(FFI_OK));
        let loaded = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr_addr, 0);
        let ptr_res = self.b.ins().select(rc_ok, loaded, zero_p);
        self.b.ins().jump(done_bb, &[BlockArg::Value(ptr_res)]);

        self.b.switch_to_block(fail_bb);
        self.b.seal_block(fail_bb);
        self.b.ins().jump(done_bb, &[BlockArg::Value(zero_p)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let final_ptr = self.b.block_params(done_bb)[0];
        self.def_scalar_typed(dst, final_ptr);
    }

    pub(super) fn emit_flush_changed_range(
        &mut self,
        query_idx: u32,
        term_idx: u32,
        run_start: Value,
        run_len: Value,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let rlen_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, run_len, 0);
        let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
        let go = self.b.ins().band(rlen_nz, iter_ok);
        let call_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(go, call_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        let rs = coerce_cl_val(self.b, run_start, ptr_ty, ptr_ty);
        let rl = coerce_cl_val(self.b, run_len, ptr_ty, ptr_ty);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_MARK_CHANGED_RANGE,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, tv, rs, rl],
        );
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
    }

    pub(super) fn lower_dirty_run_record_row(
        &mut self,
        run_start: LocalId,
        run_len: LocalId,
        row_idx: LocalId,
    ) {
        let cur_start_raw = self.use_scalar(run_start);
        let cur_start = coerce_cl_val(self.b, cur_start_raw, types::I32, self.ctx.ptr_ty);
        let cur_len_raw = self.use_scalar(run_len);
        let cur_len = coerce_cl_val(self.b, cur_len_raw, types::I32, self.ctx.ptr_ty);
        let r_raw = self.use_scalar(row_idx);
        let r = coerce_cl_val(self.b, r_raw, types::I32, self.ctx.ptr_ty);

        let is_empty = self.b.ins().icmp_imm_s(IntCC::Equal, cur_len, 0);
        let expected_next = self.b.ins().iadd(cur_start, cur_len);
        let is_contig = self.b.ins().icmp(IntCC::Equal, r, expected_next);
        let is_dup = self.b.ins().icmp(IntCC::Equal, r, cur_start);

        let start_bb = self.b.create_block();
        let non_empty_bb = self.b.create_block();
        let contig_bb = self.b.create_block();
        let gap_bb = self.b.create_block();
        let done_bb = self.b.create_block();

        self.b
            .ins()
            .brif(is_empty, start_bb, &[], non_empty_bb, &[]);

        self.b.switch_to_block(start_bb);
        self.b.seal_block(start_bb);
        let one = self.b.ins().iconst(types::I32, 1);
        self.def_scalar_typed(run_start, r);
        self.def_scalar_typed(run_len, one);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(non_empty_bb);
        self.b.seal_block(non_empty_bb);
        let keep_bb = done_bb;
        let check_contig_bb = self.b.create_block();
        self.b
            .ins()
            .brif(is_dup, keep_bb, &[], check_contig_bb, &[]);

        self.b.switch_to_block(check_contig_bb);
        self.b.seal_block(check_contig_bb);
        self.b.ins().brif(is_contig, contig_bb, &[], gap_bb, &[]);

        self.b.switch_to_block(contig_bb);
        self.b.seal_block(contig_bb);
        let inc_len = self.b.ins().iadd_imm_s(cur_len, 1);
        self.def_scalar_typed(run_len, inc_len);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(gap_bb);
        self.b.seal_block(gap_bb);
        if let Some(&(qi, ti)) = self.dirty_targets.get(&(run_start.0, run_len.0)) {
            self.emit_flush_changed_range(qi, ti, cur_start, cur_len);
        }
        let one2 = self.b.ins().iconst(types::I32, 1);
        self.def_scalar_typed(run_start, r);
        self.def_scalar_typed(run_len, one2);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_res_access(&mut self, resource: &str, mutable: bool) -> Value {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, resource) else {
            return self.b.ins().iconst(self.ctx.ptr_ty, 0);
        };
        emit_res_ptr_lookup(
            self.ctx,
            self.b,
            self.api_ptr,
            self.sys_ctx,
            self.state_ptr,
            lidx,
            mutable,
        )
    }

    pub(super) fn call_entity_get(
        &mut self,
        query_idx: u32,
        term_idx: u32,
        entity: Value,
        mutable: bool,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let qv = self.b.ins().iconst(ptr_ty, i64::from(query_idx));
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        let slot = if mutable {
            api_slots::SYS_ENTITY_GET_MUT
        } else {
            api_slots::SYS_ENTITY_GET
        };
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let ok = self.b.ins().band(ent_ok, ctx_ok);
        let call_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.append_block_param(merge_bb, ptr_ty);
        self.b.ins().brif(ok, call_bb, &[], null_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let p = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            slot,
            &[ptr_ty, ptr_ty, types::I64, ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, qv, entity, tv],
        );
        self.b.ins().jump(merge_bb, &[BlockArg::Value(p)]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        let zp = self.b.ins().iconst(ptr_ty, 0);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(zp)]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        self.b.block_params(merge_bb)[0]
    }

    pub(super) fn lower_resolve_named_object(&mut self, name: &str) -> Result<Value, JitError> {
        let Some(obj_idx) = self.ctx.mir.objects.iter().position(|o| o.name == name) else {
            return Ok(self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
        };
        let ptr_ty = self.ctx.ptr_ty;
        let off = self.ctx.state_layout.obj_slot_offset(obj_idx) as i32;
        let cached = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), self.state_ptr, off);

        let is_zero = self.b.ins().icmp_imm_s(IntCC::Equal, cached, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let need_lazy = self.b.ins().band(is_zero, ctx_ok);

        let lazy_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I64);
        self.b
            .ins()
            .brif(need_lazy, lazy_bb, &[], done_bb, &[BlockArg::Value(cached)]);

        self.b.switch_to_block(lazy_bb);
        self.b.seal_block(lazy_bb);

        let lookup_qi = self
            .sys_entry
            .and_then(|e| {
                e.extra_obj_queries
                    .iter()
                    .find(|x| x.obj_idx == obj_idx)
                    .map(|x| x.wire_query_idx)
            })
            .or_else(|| find_reusable_obj_query(self.ctx, self.mir_fn, obj_idx));

        let mut resolved = cached;
        if let Some(qi) = lookup_qi {
            let iter_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
            let iter_ptr_out = self.b.ins().stack_addr(ptr_ty, iter_slot, 0);
            let qv = self.b.ins().iconst(ptr_ty, qi as i64);
            let rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::SYS_QUERY,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[self.sys_ctx, qv, iter_ptr_out],
            );
            let iter = self
                .b
                .ins()
                .load(ptr_ty, MemFlagsData::trusted(), iter_ptr_out, 0);
            let rc_ok = self.b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let iter_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
            let ok_iter = self.b.ins().band(rc_ok, iter_nz);

            let chunk_bb = self.b.create_block();
            let after_q_bb = self.b.create_block();
            self.b.append_block_param(after_q_bb, types::I64);
            self.b.ins().brif(
                ok_iter,
                chunk_bb,
                &[],
                after_q_bb,
                &[BlockArg::Value(cached)],
            );

            self.b.switch_to_block(chunk_bb);
            self.b.seal_block(chunk_bb);
            let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
            let len_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
            let has = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_NEXT_CHUNK,
                &[ptr_ty, ptr_ty],
                Some(types::I8),
                ptr_ty,
                self.ctx.call_conv,
                &[iter, len_ptr],
            );
            let clen = self
                .b
                .ins()
                .load(ptr_ty, MemFlagsData::trusted(), len_ptr, 0);
            let has_b = self.b.ins().icmp_imm_s(IntCC::NotEqual, has, 0);
            let len_pos = self.b.ins().icmp_imm_s(IntCC::SignedGreaterThan, clen, 0);
            let got = self.b.ins().band(has_b, len_pos);

            let take_bb = self.b.create_block();
            self.b
                .ins()
                .brif(got, take_bb, &[], after_q_bb, &[BlockArg::Value(cached)]);

            self.b.switch_to_block(take_bb);
            self.b.seal_block(take_bb);
            let ents = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_ENTITIES,
                &[ptr_ty],
                Some(ptr_ty),
                ptr_ty,
                self.ctx.call_conv,
                &[iter],
            );
            let e0 = self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), ents, 0);
            self.b
                .ins()
                .store(MemFlagsData::trusted(), e0, self.state_ptr, off);

            // Reset iterator if `qi` came from one of the system's own ECS queries so normal iteration still sees chunk 0!
            let _rst = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_RESET,
                &[ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[iter],
            );

            // Also call `bind_named_object(host_ctx, name_strview, e0)` (`Slot 56`).
            let (str_id, str_len) = self.ctx.intern_bytes(name)?;
            let gv = self.ctx.obj_mod.declare_data_in_func(str_id, self.b.func);
            let s_ptr = self.b.ins().symbol_value(ptr_ty, gv);
            let s_len = self.b.ins().iconst(ptr_ty, str_len as i64);
            let _bind_rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::BIND_NAMED_OBJECT,
                &[ptr_ty, ptr_ty, ptr_ty, types::I64],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[self.host_ctx, s_ptr, s_len, e0],
            );
            self.b.ins().jump(after_q_bb, &[BlockArg::Value(e0)]);

            self.b.switch_to_block(after_q_bb);
            self.b.seal_block(after_q_bb);
            resolved = self.b.block_params(after_q_bb)[0];
        }
        self.b.ins().jump(done_bb, &[BlockArg::Value(resolved)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(self.b.block_params(done_bb)[0])
    }

    pub(super) fn lower_intern_symbol(&mut self, symbol: &str) -> Result<Value, JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let (sid, slen) = self.ctx.intern_bytes(symbol)?;
        let gv = self.ctx.obj_mod.declare_data_in_func(sid, self.b.func);
        let sptr = self.b.ins().symbol_value(ptr_ty, gv);
        let len_v = self.b.ins().iconst(ptr_ty, slen as i64);
        let out_slot = alloc_zero_slot(self.b, structs::BAM_SYMBOL_SIZE, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::INTERN_SYMBOL,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.host_ctx, sptr, len_v, out_ptr],
        );
        Ok(self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), out_ptr, 0))
    }

    pub(super) fn guarded_load(&mut self, ptr: Value, offset: i32, ty: Type) -> Value {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let l_bb = self.b.create_block();
        let n_bb = self.b.create_block();
        let m_bb = self.b.create_block();
        self.b.append_block_param(m_bb, ty);
        self.b.ins().brif(ok, l_bb, &[], n_bb, &[]);
        self.b.switch_to_block(l_bb);
        self.b.seal_block(l_bb);
        let v = self.b.ins().load(ty, MemFlagsData::new(), ptr, offset);
        self.b.ins().jump(m_bb, &[BlockArg::Value(v)]);
        self.b.switch_to_block(n_bb);
        self.b.seal_block(n_bb);
        let z = zero_for_cl_type(self.b, ty);
        self.b.ins().jump(m_bb, &[BlockArg::Value(z)]);
        self.b.switch_to_block(m_bb);
        self.b.seal_block(m_bb);
        self.b.block_params(m_bb)[0]
    }

    pub(super) fn guarded_store(&mut self, ptr: Value, offset: i32, val: Value) {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let s_bb = self.b.create_block();
        let d_bb = self.b.create_block();
        self.b.ins().brif(ok, s_bb, &[], d_bb, &[]);
        self.b.switch_to_block(s_bb);
        self.b.seal_block(s_bb);
        self.b.ins().store(MemFlagsData::new(), val, ptr, offset);
        self.b.ins().jump(d_bb, &[]);
        self.b.switch_to_block(d_bb);
        self.b.seal_block(d_bb);
    }

    pub(super) fn lower_grace_tick(&mut self, ptr: Value, dt_sec: Value) {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let rem = self.b.ins().load(types::F32, MemFlagsData::new(), ptr, 0);
        let sub = self.b.ins().fsub(rem, dt_sec);
        let zero = self.b.ins().f32const(0.0);
        let clamped = self.b.ins().fmax(sub, zero);
        self.b.ins().store(MemFlagsData::new(), clamped, ptr, 0);
        self.b.ins().jump(done_bb, &[]);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_input_buf_push(
        &mut self,
        ptr: Value,
        capacity: u32,
        action_id: Value,
        window_sec: Value,
    ) {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);

        let idx_var = self.b.declare_var(types::I32);
        let best_idx_var = self.b.declare_var(types::I32);
        let best_rem_var = self.b.declare_var(types::F32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        let huge = self.b.ins().f32const(1e30);
        self.b.def_var(idx_var, z32);
        self.b.def_var(best_idx_var, z32);
        self.b.def_var(best_rem_var, huge);

        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let write_best_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_bounds = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b
            .ins()
            .brif(in_bounds, body_bb, &[], write_best_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let byte_off = self.b.ins().imul_imm_s(i_ptr, 8);
        let entry_ptr = self.b.ins().iadd(ptr, byte_off);
        let cur_aid = self
            .b
            .ins()
            .load(types::I16, MemFlagsData::new(), entry_ptr, 0);
        let cur_rem = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::new(), entry_ptr, 4);

        let same_aid = self.b.ins().icmp(IntCC::Equal, cur_aid, action_id);
        let zero_f = self.b.ins().f32const(0.0);
        let cur_active = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);
        let match_active = self.b.ins().band(same_aid, cur_active);

        let overwrite_here_bb = self.b.create_block();
        let check_empty_bb = self.b.create_block();
        self.b
            .ins()
            .brif(match_active, overwrite_here_bb, &[], check_empty_bb, &[]);

        self.b.switch_to_block(overwrite_here_bb);
        self.b.seal_block(overwrite_here_bb);
        let z16 = self.b.ins().iconst(types::I16, 0);
        self.b
            .ins()
            .store(MemFlagsData::new(), action_id, entry_ptr, 0);
        self.b.ins().store(MemFlagsData::new(), z16, entry_ptr, 2);
        self.b
            .ins()
            .store(MemFlagsData::new(), window_sec, entry_ptr, 4);
        self.b.ins().jump(exit_bb, &[]);

        self.b.switch_to_block(check_empty_bb);
        self.b.seal_block(check_empty_bb);
        let cur_best_rem = self.b.use_var(best_rem_var);
        let cur_best_idx = self.b.use_var(best_idx_var);
        let is_empty_sentinel = self.b.ins().icmp_imm_s(IntCC::Equal, cur_aid, -1);
        let is_expired = self.b.ins().fcmp(FloatCC::LessThanOrEqual, cur_rem, zero_f);
        let slot_free = self.b.ins().bor(is_empty_sentinel, is_expired);
        let smaller_rem = self.b.ins().fcmp(FloatCC::LessThan, cur_rem, cur_best_rem);
        let take_best = self.b.ins().bor(slot_free, smaller_rem);
        let eff_rem = self.b.ins().select(slot_free, zero_f, cur_rem);
        let next_best_rem = self.b.ins().select(take_best, eff_rem, cur_best_rem);
        let next_best_idx = self.b.ins().select(take_best, i, cur_best_idx);
        self.b.def_var(best_rem_var, next_best_rem);
        self.b.def_var(best_idx_var, next_best_idx);
        let next_i = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, next_i);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(write_best_bb);
        self.b.seal_block(write_best_bb);
        let best_idx_raw = self.b.use_var(best_idx_var);
        let bi = coerce_cl_val(self.b, best_idx_raw, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let boff = self.b.ins().imul_imm_s(bi, 8);
        let bptr = self.b.ins().iadd(ptr, boff);
        let z16_2 = self.b.ins().iconst(types::I16, 0);
        self.b.ins().store(MemFlagsData::new(), action_id, bptr, 0);
        self.b.ins().store(MemFlagsData::new(), z16_2, bptr, 2);
        self.b.ins().store(MemFlagsData::new(), window_sec, bptr, 4);
        self.b.ins().jump(exit_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    pub(super) fn lower_input_buf_find(
        &mut self,
        ptr: Value,
        capacity: u32,
        action_id: Value,
        consume: bool,
    ) -> Value {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let fail_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.append_block_param(exit_bb, types::I8);
        self.b.ins().brif(ok, do_bb, &[], fail_bb, &[]);

        self.b.switch_to_block(fail_bb);
        self.b.seal_block(fail_bb);
        let f_i8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(f_i8)]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let idx_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(idx_var, z32);
        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let miss_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_b = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b.ins().brif(in_b, body_bb, &[], miss_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(i_ptr, 8);
        let eptr = self.b.ins().iadd(ptr, off);
        let cur_aid = self.b.ins().load(types::I16, MemFlagsData::new(), eptr, 0);
        let cur_rem = self.b.ins().load(types::F32, MemFlagsData::new(), eptr, 4);
        let zero_f = self.b.ins().f32const(0.0);
        let eq = self.b.ins().icmp(IntCC::Equal, cur_aid, action_id);
        let act = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);
        let hit = self.b.ins().band(eq, act);

        let hit_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(hit, hit_bb, &[], step_bb, &[]);

        self.b.switch_to_block(hit_bb);
        self.b.seal_block(hit_bb);
        if consume {
            let empty_aid = self.b.ins().iconst(types::I16, 0xFFFF);
            self.b.ins().store(MemFlagsData::new(), empty_aid, eptr, 0);
            self.b.ins().store(MemFlagsData::new(), zero_f, eptr, 4);
        }
        let t_i8 = self.b.ins().iconst(types::I8, 1);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(t_i8)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, ni);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(miss_bb);
        self.b.seal_block(miss_bb);
        let miss_i8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(miss_i8)]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
        self.b.block_params(exit_bb)[0]
    }

    pub(super) fn lower_input_buf_tick(&mut self, ptr: Value, capacity: u32, dt_sec: Value) {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let idx_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(idx_var, z32);
        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_b = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b.ins().brif(in_b, body_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(i_ptr, 8);
        let eptr = self.b.ins().iadd(ptr, off);
        let cur_rem = self.b.ins().load(types::F32, MemFlagsData::new(), eptr, 4);
        let zero_f = self.b.ins().f32const(0.0);
        let pos = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);

        let dec_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(pos, dec_bb, &[], step_bb, &[]);

        self.b.switch_to_block(dec_bb);
        self.b.seal_block(dec_bb);
        let rem_next = self.b.ins().fsub(cur_rem, dt_sec);
        let expired = self
            .b
            .ins()
            .fcmp(FloatCC::LessThanOrEqual, rem_next, zero_f);
        let clamped = self.b.ins().fmax(rem_next, zero_f);
        self.b.ins().store(MemFlagsData::new(), clamped, eptr, 4);
        let cur_aid = self.b.ins().load(types::I16, MemFlagsData::new(), eptr, 0);
        let empty_aid = self.b.ins().iconst(types::I16, 0xFFFF);
        let next_aid = self.b.ins().select(expired, empty_aid, cur_aid);
        self.b.ins().store(MemFlagsData::new(), next_aid, eptr, 0);
        self.b.ins().jump(step_bb, &[]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, ni);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    pub(super) fn lower_bitset_mut(&mut self, ptr: Value, words: u32, bit: Value, set_bit: bool) {
        let word_idx = self.b.ins().ushr_imm_u(bit, 5);
        let bit_idx = self.b.ins().band_imm_u(bit, 31);
        let ok_ptr = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let ok_bounds =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, word_idx, i64::from(words));
        let ok = self.b.ins().band(ok_ptr, ok_bounds);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let wi_ptr = coerce_cl_val(self.b, word_idx, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(wi_ptr, 4);
        let addr = self.b.ins().iadd(ptr, off);
        let cur = self.b.ins().load(types::I32, MemFlagsData::new(), addr, 0);
        let one = self.b.ins().iconst(types::I32, 1);
        let mask = self.b.ins().ishl(one, bit_idx);
        let next = if set_bit {
            self.b.ins().bor(cur, mask)
        } else {
            let inv = self.b.ins().bnot(mask);
            self.b.ins().band(cur, inv)
        };
        self.b.ins().store(MemFlagsData::new(), next, addr, 0);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_bitset_get(&mut self, ptr: Value, words: u32, bit: Value) -> Value {
        let word_idx = self.b.ins().ushr_imm_u(bit, 5);
        let bit_idx = self.b.ins().band_imm_u(bit, 31);
        let ok_ptr = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let ok_bounds =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, word_idx, i64::from(words));
        let ok = self.b.ins().band(ok_ptr, ok_bounds);

        let do_bb = self.b.create_block();
        let zero_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I8);
        self.b.ins().brif(ok, do_bb, &[], zero_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let wi_ptr = coerce_cl_val(self.b, word_idx, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(wi_ptr, 4);
        let addr = self.b.ins().iadd(ptr, off);
        let cur = self.b.ins().load(types::I32, MemFlagsData::new(), addr, 0);
        let shifted = self.b.ins().ushr(cur, bit_idx);
        let bit_val = self.b.ins().band_imm_u(shifted, 1);
        let res = self.b.ins().icmp_imm_s(IntCC::NotEqual, bit_val, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(res)]);

        self.b.switch_to_block(zero_bb);
        self.b.seal_block(zero_bb);
        let z8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(z8)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        self.b.block_params(done_bb)[0]
    }

    pub(super) fn lower_timeline_advance(
        &mut self,
        ptr: Value,
        rate_hz: u32,
        duration_frames: u32,
        window_masks: &[(String, u32, u32, u32)],
    ) {
        // Layout: cur_frame: u16 @ 0, flags: u16 @ 2, active_mask: u32 @ 4, accum_sec: f32 @ 8.
        // Note: `state_machines` pass ALREADY incremented `accum_sec` by `dt_sec` at offset 8 right
        // before emitting `TimelineAdvance`.
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let frame_dt = self.b.ins().f32const(1.0 / (rate_hz.max(1) as f32));
        let cur_f16 = self.b.ins().load(types::I16, MemFlagsData::new(), ptr, 0);
        let cur_f32 = self.b.ins().uextend(types::I32, cur_f16);
        let cur_acc = self.b.ins().load(types::F32, MemFlagsData::new(), ptr, 8);

        let f_var = self.b.declare_var(types::I32);
        let acc_var = self.b.declare_var(types::F32);
        self.b.def_var(f_var, cur_f32);
        self.b.def_var(acc_var, cur_acc);

        let loop_hdr = self.b.create_block();
        let loop_body = self.b.create_block();
        let after_loop = self.b.create_block();
        self.b.ins().jump(loop_hdr, &[]);

        self.b.switch_to_block(loop_hdr);
        let fv = self.b.use_var(f_var);
        let av = self.b.use_var(acc_var);
        let can_step = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, av, frame_dt);
        let not_done =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, fv, i64::from(duration_frames));
        let cond = self.b.ins().band(can_step, not_done);
        self.b.ins().brif(cond, loop_body, &[], after_loop, &[]);

        self.b.switch_to_block(loop_body);
        self.b.seal_block(loop_body);
        let av2 = self.b.ins().fsub(av, frame_dt);
        let fv2 = self.b.ins().iadd_imm_s(fv, 1);
        self.b.def_var(acc_var, av2);
        self.b.def_var(f_var, fv2);
        self.b.ins().jump(loop_hdr, &[]);

        self.b.seal_block(loop_hdr);
        self.b.switch_to_block(after_loop);
        self.b.seal_block(after_loop);
        let final_f = self.b.use_var(f_var);
        let final_acc = self.b.use_var(acc_var);
        let final_f16 = self.b.ins().ireduce(types::I16, final_f);
        self.b.ins().store(MemFlagsData::new(), final_f16, ptr, 0);
        self.b.ins().store(MemFlagsData::new(), final_acc, ptr, 8);

        let mut mask_val = self.b.ins().iconst(types::I32, 0);
        for &(_, start_f, end_f, bit_mask) in window_masks {
            let ge = self.b.ins().icmp_imm_s(
                IntCC::UnsignedGreaterThanOrEqual,
                final_f,
                i64::from(start_f),
            );
            let lt = self
                .b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, final_f, i64::from(end_f));
            let in_w = self.b.ins().band(ge, lt);
            let with_bit = self.b.ins().bor_imm_u(mask_val, i64::from(bit_mask));
            mask_val = self.b.ins().select(in_w, with_bit, mask_val);
        }
        self.b.ins().store(MemFlagsData::new(), mask_val, ptr, 4);

        let finished = self.b.ins().icmp_imm_s(
            IntCC::UnsignedGreaterThanOrEqual,
            final_f,
            i64::from(duration_frames),
        );
        let cur_flags = self.b.ins().load(types::I16, MemFlagsData::new(), ptr, 2);
        let cleared_flags = self.b.ins().band_imm_s(cur_flags, !1);
        let set_flags = self.b.ins().bor_imm_u(cur_flags, 1);
        let next_flags = self.b.ins().select(finished, cleared_flags, set_flags);
        self.b.ins().store(MemFlagsData::new(), next_flags, ptr, 2);
        self.b.ins().jump(exit_bb, &[]);

        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    pub(super) fn lower_cmd_spawn(
        &mut self,
        persistent: bool,
        components: &[(String, LocalId)],
    ) -> Result<Value, JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let count = components.len();
        let out_slot = alloc_zero_slot(self.b, structs::FFI_ENTITY_SIZE, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        if count == 0 {
            let cmds = self.ensure_commands();
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
            let call_bb = self.b.create_block();
            let skip_bb = self.b.create_block();
            self.b.ins().brif(ok, call_bb, &[], skip_bb, &[]);
            self.b.switch_to_block(call_bb);
            self.b.seal_block(call_bb);
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_SPAWN_EMPTY,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, out_ptr],
            );
            self.b.ins().jump(skip_bb, &[]);
            self.b.switch_to_block(skip_bb);
            self.b.seal_block(skip_bb);
            return Ok(self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), out_ptr, 0));
        }

        let comp_slot = alloc_zero_slot(self.b, count * structs::BAM_COMPONENT_SIZE, ptr_ty);
        let comp_arr = self.b.ins().stack_addr(ptr_ty, comp_slot, 0);
        let ptrs_slot = alloc_zero_slot(self.b, count * self.ctx.ptr_bytes, ptr_ty);
        let ptrs_arr = self.b.ins().stack_addr(ptr_ty, ptrs_slot, 0);

        for (i, (cname, val_lid)) in components.iter().enumerate() {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comp_arr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let data_ptr = if self.ctx.layouts[lidx].size == 0 {
                self.b.ins().iconst(ptr_ty, 0)
            } else {
                self.use_scalar(*val_lid)
            };
            self.b.ins().store(
                MemFlagsData::trusted(),
                data_ptr,
                ptrs_arr,
                (i * self.ctx.ptr_bytes) as i32,
            );
        }

        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let call_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(ok, call_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let cnt_v = self.b.ins().iconst(ptr_ty, count as i64);
        let vtable_slot = if persistent {
            api_slots::CMD_SPAWN_PERSISTENT
        } else {
            api_slots::CMD_SPAWN
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comp_arr, ptrs_arr, cnt_v, out_ptr],
        );
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
        Ok(self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), out_ptr, 0))
    }

    pub(super) fn lower_cmd_spawn_batch(
        &mut self,
        count: LocalId,
        components: &[(String, LocalId)],
    ) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let ent_cnt = {
            let __tmp = self.use_scalar(count);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let cmds = self.ensure_commands();
        let cnt_pos = self
            .b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThan, ent_cnt, 0);
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let go = self.b.ins().band(cnt_pos, cmds_ok);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(go, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);

        let n = components.len();
        let comp_slot = alloc_zero_slot(self.b, (n * structs::BAM_COMPONENT_SIZE).max(8), ptr_ty);
        let comp_arr = self.b.ins().stack_addr(ptr_ty, comp_slot, 0);
        let ptrs_slot = alloc_zero_slot(self.b, (n * self.ctx.ptr_bytes).max(8), ptr_ty);
        let ptrs_arr = self.b.ins().stack_addr(ptr_ty, ptrs_slot, 0);
        let calloc_fid = self
            .ctx
            .declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;
        let free_fid = self.ctx.declare_extern_fn("free", &[ptr_ty], None)?;
        let calloc_ref = self
            .ctx
            .obj_mod
            .declare_func_in_func(calloc_fid, self.b.func);
        let free_ref = self.ctx.obj_mod.declare_func_in_func(free_fid, self.b.func);

        let mut temp_bufs = Vec::new();
        for (i, (cname, val_lid)) in components.iter().enumerate() {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comp_arr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let sz = self.ctx.layouts[lidx].size;
            if sz == 0 {
                let z = self.b.ins().iconst(ptr_ty, 0);
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    z,
                    ptrs_arr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
            } else {
                let sz_v = self.b.ins().iconst(ptr_ty, sz as i64);
                let call = self.b.ins().call(calloc_ref, &[ent_cnt, sz_v]);
                let buf = self.b.inst_results(call)[0];
                let tmpl_ptr = self.use_scalar(*val_lid);
                self.emit_replicate_template(buf, tmpl_ptr, ent_cnt, sz);
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    buf,
                    ptrs_arr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
                temp_bufs.push(buf);
            }
        }

        let comp_cnt_v = self.b.ins().iconst(ptr_ty, n as i64);
        let null_out = self.b.ins().iconst(ptr_ty, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_SPAWN_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comp_arr, ptrs_arr, comp_cnt_v, ent_cnt, null_out],
        );

        for buf in temp_bufs {
            self.b.ins().call(free_ref, &[buf]);
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    pub(super) fn lower_spawn_batch_begin(
        &mut self,
        count: LocalId,
        components: &[String],
    ) -> Result<(Value, Vec<usize>), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let resolved_lidxs: Vec<usize> = components
            .iter()
            .filter_map(|c| lookup_name_in_map(&self.ctx.layout_map, c))
            .collect();
        let k = resolved_lidxs.len();
        let comps_off = 32usize;
        let ptrs_off = comps_off + align_up(k * structs::BAM_COMPONENT_SIZE, 8);
        let hdr_bytes = (ptrs_off + k * self.ctx.ptr_bytes).max(32);

        let raw_cnt = self.use_scalar(count);
        let cnt_u64 = coerce_cl_val(self.b, raw_cnt, types::I64, ptr_ty);
        let cnt_ptr = coerce_cl_val(self.b, raw_cnt, ptr_ty, ptr_ty);

        let calloc_fid = self
            .ctx
            .declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;
        let calloc_ref = self
            .ctx
            .obj_mod
            .declare_func_in_func(calloc_fid, self.b.func);

        let one = self.b.ins().iconst(ptr_ty, 1);
        let hsz = self.b.ins().iconst(ptr_ty, hdr_bytes as i64);
        let hcall = self.b.ins().call(calloc_ref, &[one, hsz]);
        let hdr = self.b.inst_results(hcall)[0];

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let init_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, init_bb, &[], done_bb, &[]);

        self.b.switch_to_block(init_bb);
        self.b.seal_block(init_bb);

        let k_u64 = self.b.ins().iconst(types::I64, k as i64);
        let comps_ptr = self.b.ins().iadd_imm_s(hdr, comps_off as i64);
        let ptrs_ptr = self.b.ins().iadd_imm_s(hdr, ptrs_off as i64);
        self.b.ins().store(MemFlagsData::trusted(), cnt_u64, hdr, 0);
        self.b.ins().store(MemFlagsData::trusted(), k_u64, hdr, 8);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), comps_ptr, hdr, 16);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ptrs_ptr, hdr, 24);

        let cnt_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, cnt_u64, 0);
        for (i, &lidx) in resolved_lidxs.iter().enumerate() {
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comps_ptr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let sz = self.ctx.layouts[lidx].size;
            if sz > 0 {
                let alloc_bb = self.b.create_block();
                let next_c_bb = self.b.create_block();
                self.b.ins().brif(cnt_pos, alloc_bb, &[], next_c_bb, &[]);

                self.b.switch_to_block(alloc_bb);
                self.b.seal_block(alloc_bb);
                let sz_v = self.b.ins().iconst(ptr_ty, sz as i64);
                let ccall = self.b.ins().call(calloc_ref, &[cnt_ptr, sz_v]);
                let col_buf = self.b.inst_results(ccall)[0];
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    col_buf,
                    ptrs_ptr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
                self.b.ins().jump(next_c_bb, &[]);

                self.b.switch_to_block(next_c_bb);
                self.b.seal_block(next_c_bb);
            }
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let hdr_u64 = coerce_cl_val(self.b, hdr, types::I64, ptr_ty);
        Ok((hdr_u64, resolved_lidxs))
    }

    pub(super) fn lookup_batch_col_buf_by_handle(
        &mut self,
        comps_ptr: Value,
        ptrs_ptr: Value,
        comp_cnt_ptr: Value,
        lidx: usize,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let target_h = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let k_var = self.b.declare_var(ptr_ty);
        let z_ptr = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(k_var, z_ptr);

        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let hit_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, ptr_ty);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let k = self.b.use_var(k_var);
        let in_b = self.b.ins().icmp(IntCC::UnsignedLessThan, k, comp_cnt_ptr);
        self.b
            .ins()
            .brif(in_b, body_bb, &[], done_bb, &[BlockArg::Value(z_ptr)]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let coff = self
            .b
            .ins()
            .imul_imm_s(k, structs::BAM_COMPONENT_SIZE as i64);
        let caddr = self.b.ins().iadd(comps_ptr, coff);
        let h = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), caddr, 0);
        let eq = self.b.ins().icmp(IntCC::Equal, h, target_h);
        self.b.ins().brif(eq, hit_bb, &[], step_bb, &[]);

        self.b.switch_to_block(hit_bb);
        self.b.seal_block(hit_bb);
        let poff = self.b.ins().imul_imm_s(k, self.ctx.ptr_bytes as i64);
        let paddr = self.b.ins().iadd(ptrs_ptr, poff);
        let buf = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), paddr, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(buf)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        self.b.block_params(done_bb)[0]
    }

    pub(super) fn lower_spawn_batch_push(
        &mut self,
        batch: LocalId,
        index: LocalId,
        components: &[(String, LocalId)],
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let hdr_raw = self.use_scalar(batch);
        let hdr = coerce_cl_val(self.b, hdr_raw, ptr_ty, ptr_ty);
        let idx_raw = self.use_scalar(index);
        let idx_u64 = coerce_cl_val(self.b, idx_raw, types::I64, ptr_ty);

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let chk_bb = self.b.create_block();
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, chk_bb, &[], done_bb, &[]);

        self.b.switch_to_block(chk_bb);
        self.b.seal_block(chk_bb);
        let cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 0);
        let in_bounds = self.b.ins().icmp(IntCC::UnsignedLessThan, idx_u64, cnt_u64);
        self.b.ins().brif(in_bounds, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp_cnt = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 8);
        let comp_cnt_ptr = coerce_cl_val(self.b, comp_cnt, ptr_ty, ptr_ty);
        let comps_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 16);
        let ptrs_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 24);
        let idx_ptr = coerce_cl_val(self.b, idx_u64, ptr_ty, ptr_ty);
        let schema = self.batch_schemas.get(&batch.0).cloned();

        for (cname, val_lid) in components {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let sz = self.ctx.layouts[lidx].size;
            if sz == 0 {
                continue;
            }
            let col_buf = if let Some(k) = schema
                .as_ref()
                .and_then(|s| s.iter().position(|&x| x == lidx))
            {
                self.b.ins().load(
                    ptr_ty,
                    MemFlagsData::trusted(),
                    ptrs_ptr,
                    (k * self.ctx.ptr_bytes) as i32,
                )
            } else {
                self.lookup_batch_col_buf_by_handle(comps_ptr, ptrs_ptr, comp_cnt_ptr, lidx)
            };

            let buf_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, col_buf, 0);
            let wr_bb = self.b.create_block();
            let next_c_bb = self.b.create_block();
            self.b.ins().brif(buf_ok, wr_bb, &[], next_c_bb, &[]);

            self.b.switch_to_block(wr_bb);
            self.b.seal_block(wr_bb);
            let off = self.b.ins().imul_imm_s(idx_ptr, sz as i64);
            let dst_ptr = self.b.ins().iadd(col_buf, off);
            let mty = self.mir_fn.locals[val_lid.0 as usize].ty.clone();
            if matches!(mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(&mty) {
                let src_ptr = self.use_scalar(*val_lid);
                let src_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, src_ptr, 0);
                let cp_bb = self.b.create_block();
                self.b.ins().brif(src_ok, cp_bb, &[], next_c_bb, &[]);

                self.b.switch_to_block(cp_bb);
                self.b.seal_block(cp_bb);
                emit_memcpy(self.b, dst_ptr, src_ptr, sz);
                self.b.ins().jump(next_c_bb, &[]);
            } else {
                self.store_local_to_mem(*val_lid, &mty, dst_ptr, 0);
                self.b.ins().jump(next_c_bb, &[]);
            }

            self.b.switch_to_block(next_c_bb);
            self.b.seal_block(next_c_bb);
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_spawn_batch_commit(&mut self, batch: LocalId) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let hdr_raw = self.use_scalar(batch);
        let hdr = coerce_cl_val(self.b, hdr_raw, ptr_ty, ptr_ty);
        let cmds = self.ensure_commands();

        let free_fid = self.ctx.declare_extern_fn("free", &[ptr_ty], None)?;
        let free_ref = self.ctx.obj_mod.declare_func_in_func(free_fid, self.b.func);

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 0);
        let comp_cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 8);
        let comps_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 16);
        let ptrs_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 24);
        let cnt_ptr = coerce_cl_val(self.b, cnt_u64, ptr_ty, ptr_ty);
        let comp_cnt_ptr = coerce_cl_val(self.b, comp_cnt_u64, ptr_ty, ptr_ty);

        let cnt_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, cnt_u64, 0);
        let comp_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, comp_cnt_u64, 0);
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let pos_both = self.b.ins().band(cnt_pos, comp_pos);
        let can_spawn = self.b.ins().band(pos_both, cmds_ok);

        let spawn_bb = self.b.create_block();
        let free_loop_init_bb = self.b.create_block();
        self.b
            .ins()
            .brif(can_spawn, spawn_bb, &[], free_loop_init_bb, &[]);

        self.b.switch_to_block(spawn_bb);
        self.b.seal_block(spawn_bb);
        let null_out = self.b.ins().iconst(ptr_ty, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_SPAWN_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comps_ptr, ptrs_ptr, comp_cnt_ptr, cnt_ptr, null_out],
        );
        self.b.ins().jump(free_loop_init_bb, &[]);

        self.b.switch_to_block(free_loop_init_bb);
        self.b.seal_block(free_loop_init_bb);
        let k_var = self.b.declare_var(ptr_ty);
        let z_ptr = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(k_var, z_ptr);
        let free_hdr_bb = self.b.create_block();
        let free_body_bb = self.b.create_block();
        let free_col_bb = self.b.create_block();
        let free_step_bb = self.b.create_block();
        let free_self_bb = self.b.create_block();
        self.b.ins().jump(free_hdr_bb, &[]);

        self.b.switch_to_block(free_hdr_bb);
        let k = self.b.use_var(k_var);
        let more = self.b.ins().icmp(IntCC::UnsignedLessThan, k, comp_cnt_ptr);
        self.b
            .ins()
            .brif(more, free_body_bb, &[], free_self_bb, &[]);

        self.b.switch_to_block(free_body_bb);
        self.b.seal_block(free_body_bb);
        let poff = self.b.ins().imul_imm_s(k, self.ctx.ptr_bytes as i64);
        let paddr = self.b.ins().iadd(ptrs_ptr, poff);
        let col_buf = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), paddr, 0);
        let col_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, col_buf, 0);
        self.b
            .ins()
            .brif(col_nz, free_col_bb, &[], free_step_bb, &[]);

        self.b.switch_to_block(free_col_bb);
        self.b.seal_block(free_col_bb);
        self.b.ins().call(free_ref, &[col_buf]);
        self.b.ins().jump(free_step_bb, &[]);

        self.b.switch_to_block(free_step_bb);
        self.b.seal_block(free_step_bb);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(free_hdr_bb, &[]);

        self.b.seal_block(free_hdr_bb);
        self.b.switch_to_block(free_self_bb);
        self.b.seal_block(free_self_bb);
        self.b.ins().call(free_ref, &[hdr]);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    pub(super) fn emit_replicate_template(
        &mut self,
        dst_buf: Value,
        tmpl_ptr: Value,
        count: Value,
        elem_sz: usize,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let idx_v = self.b.declare_var(ptr_ty);
        let z = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(idx_v, z);
        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let i = self.b.use_var(idx_v);
        let cond = self.b.ins().icmp(IntCC::UnsignedLessThan, i, count);
        self.b.ins().brif(cond, body, &[], exit, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let off = self.b.ins().imul_imm_s(i, elem_sz as i64);
        let dst = self.b.ins().iadd(dst_buf, off);
        emit_memcpy(self.b, dst, tmpl_ptr, elem_sz);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_v, ni);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
    }

    pub(super) fn lower_cmd_despawn_all(&mut self, filter: &str) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let mut filter_terms: Vec<(usize, u32, u16)> = Vec::new();
        for tok in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (clean, mode_u, flags_u) = if let Some(inner) = tok
                .strip_prefix("Without<")
                .and_then(|s| s.strip_suffix('>'))
            {
                (inner.trim(), AccessMode::WITHOUT.0, 0u16)
            } else if let Some(inner) = tok.strip_prefix("With<").and_then(|s| s.strip_suffix('>'))
            {
                (inner.trim(), AccessMode::FILTER_ONLY.0, 0u16)
            } else if let Some(inner) = tok.strip_prefix("Added<").and_then(|s| s.strip_suffix('>'))
            {
                (
                    inner.trim(),
                    AccessMode::FILTER_ONLY.0,
                    bamabi_sys::BAM_TERM_FLAG_ADDED,
                )
            } else if let Some(inner) = tok
                .strip_prefix("Changed<")
                .and_then(|s| s.strip_suffix('>'))
            {
                (inner.trim(), ACCESS_MODE_CHANGED, 0u16)
            } else {
                (tok.trim(), AccessMode::FILTER_ONLY.0, 0u16)
            };
            if let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, clean) {
                filter_terms.push((lidx, mode_u, flags_u));
            }
        }
        if filter_terms.is_empty() {
            return Ok(());
        }
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let terms_slot =
            alloc_zero_slot(self.b, filter_terms.len() * structs::TERM_DESC_SIZE, ptr_ty);
        let terms_ptr = self.b.ins().stack_addr(ptr_ty, terms_slot, 0);
        for (i, (lidx, mode_u, flags_u)) in filter_terms.iter().enumerate() {
            let base = (i * structs::TERM_DESC_SIZE) as i32;
            let comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(*lidx) as i32,
            );
            let mode_v = self.b.ins().iconst(types::I32, i64::from(*mode_u));
            let flags_v = self.b.ins().iconst(types::I16, i64::from(*flags_u));
            self.b.ins().store(
                MemFlagsData::trusted(),
                comp,
                terms_ptr,
                base + structs::TERM_COMPONENT as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                mode_v,
                terms_ptr,
                base + structs::TERM_MODE as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                flags_v,
                terms_ptr,
                base + structs::TERM_FLAGS as i32,
            );
        }
        let tc = self.b.ins().iconst(ptr_ty, filter_terms.len() as i64);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_DESPAWN_ALL,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, terms_ptr, tc],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    pub(super) fn lower_cmd_insert(
        &mut self,
        entity: Value,
        component: &str,
        data: Option<LocalId>,
        if_new: bool,
    ) -> Result<(), JitError> {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, component) else {
            return Ok(());
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ok = self.b.ins().band(cmds_ok, ent_ok);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else if let Some(dl) = data {
            let mty = &self.mir_fn.locals[dl.0 as usize].ty;
            if matches!(mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(mty) {
                self.use_scalar(dl)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(dl, &cloned, sp, 0);
                sp
            }
        } else if let Some(blob_id) = self.ctx.layouts[lidx].default_blob_id {
            let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
            self.b.ins().symbol_value(ptr_ty, gv)
        } else {
            let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
            self.b.ins().stack_addr(ptr_ty, s, 0)
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);
        let vtable_slot = if if_new {
            api_slots::CMD_INSERT_IF_NEW
        } else {
            api_slots::CMD_INSERT
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, types::I64, types::I32, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, entity, comp, dptr, dlen],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    pub(super) fn lower_cmd_remove(&mut self, entity: Value, component: &str) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, component) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ok = self.b.ins().band(cmds_ok, ent_ok);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_REMOVE,
            &[ptr_ty, types::I64, types::I32],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, entity, comp],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_cmd_trigger(
        &mut self,
        event: &str,
        target: Option<LocalId>,
        payload: Option<LocalId>,
        propagate: bool,
    ) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, event) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let ev_comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let tgt_ent = target
            .map(|t| self.use_scalar(t))
            .unwrap_or_else(|| self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else if let Some(pl) = payload {
            let mty = &self.mir_fn.locals[pl.0 as usize].ty;
            if matches!(mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(mty) {
                self.use_scalar(pl)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(pl, &cloned, sp, 0);
                sp
            }
        } else {
            let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
            self.b.ins().stack_addr(ptr_ty, s, 0)
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);

        if propagate {
            let tslot = alloc_zero_slot(self.b, structs::TRIGGER_DESC_SIZE, ptr_ty);
            let tptr = self.b.ins().stack_addr(ptr_ty, tslot, 0);
            let tsz = self
                .b
                .ins()
                .iconst(types::I32, structs::TRIGGER_DESC_SIZE as i64);
            let tflags = self
                .b
                .ins()
                .iconst(types::I32, i64::from(TRIGGER_FLAG_PROPAGATE));
            let ekind = self
                .b
                .ins()
                .iconst(types::I32, i64::from(BAM_EVENT_KIND_CUSTOM));
            let elo = self.b.ins().ireduce(types::I32, tgt_ent);
            let shifted = self.b.ins().ushr_imm_u(tgt_ent, 32);
            let ehi = self.b.ins().ireduce(types::I32, shifted);
            let inv_rel = self
                .b
                .ins()
                .iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            self.b
                .ins()
                .stack_store(ptr_ty, tsz, tslot, structs::TRG_STRUCT_SIZE as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, tflags, tslot, structs::TRG_FLAGS as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ev_comp, tslot, structs::TRG_EVENT as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ekind, tslot, structs::TRG_EVENT_KIND as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, elo, tslot, structs::TRG_ENTITY_LO as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ehi, tslot, structs::TRG_ENTITY_HI as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, dptr, tslot, structs::TRG_DATA_PTR as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, dlen, tslot, structs::TRG_DATA_LEN as i32);
            self.b.ins().stack_store(
                ptr_ty,
                inv_rel,
                tslot,
                structs::TRG_PROPAGATE_RELATIONSHIP as i32,
            );
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_TRIGGER_EX,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, tptr],
            );
        } else {
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_TRIGGER,
                &[ptr_ty, types::I32, types::I64, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ev_comp, tgt_ent, dptr, dlen],
            );
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn ensure_stream_query_iter(&mut self, stream_layout_idx: usize) -> Option<Value> {
        let entry = self.sys_entry?;
        let pos = entry
            .stream_queries
            .iter()
            .position(|s| s.stream_layout_idx == stream_layout_idx)?;
        let ptr_ty = self.ctx.ptr_ty;
        let non_empty_wire = entry
            .wire_queries
            .iter()
            .filter(|wq| {
                !wq.terms.is_empty()
                    || !wq.with_filters.is_empty()
                    || !wq.without_filters.is_empty()
                    || !wq.extra_changed_filters.is_empty()
                    || !wq.extra_added_filters.is_empty()
            })
            .count();
        let base_q = non_empty_wire + entry.extra_obj_queries.len();
        let mut q_idx_val = self.b.ins().iconst(ptr_ty, base_q as i64);
        for prior in entry.stream_queries.iter().take(pos) {
            let pflag = self.b.ins().load(
                types::I8,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx
                    .state_layout
                    .res_flag_offset(prior.stream_layout_idx) as i32,
            );
            let is_msg = self.b.ins().icmp_imm_s(IntCC::Equal, pflag, 2);
            let inc = self.b.ins().uextend(ptr_ty, is_msg);
            q_idx_val = self.b.ins().iadd(q_idx_val, inc);
        }
        let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let fetch_bb = self.b.create_block();
        let cont_bb = self.b.create_block();
        self.b.ins().brif(ctx_ok, fetch_bb, &[], cont_bb, &[]);

        self.b.switch_to_block(fetch_bb);
        self.b.seal_block(fetch_bb);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::SYS_QUERY,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, q_idx_val, out_ptr],
        );
        self.b.ins().jump(cont_bb, &[]);

        self.b.switch_to_block(cont_bb);
        self.b.seal_block(cont_bb);
        let fetched = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
        Some(fetched)
    }

    pub(super) fn bind_stream_in_params(&mut self) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let stream_params: Vec<(LocalId, usize)> = {
            let mut out = Vec::new();
            let mut stream_read_idx = 0usize;
            for p in &self.mir_fn.params {
                if p.kind == HirParamKind::StreamIn
                    && let Some(pl) = p.local
                {
                    let op_opt = self
                        .mir_fn
                        .stream_ops
                        .iter()
                        .filter(|op| op.kind == MirStreamOpKind::StreamRead)
                        .nth(stream_read_idx);
                    stream_read_idx += 1;
                    let lidx_opt = op_opt
                        .and_then(|op| {
                            lookup_name_in_map(&self.ctx.layout_map, &op.canonical_stream)
                                .or_else(|| lookup_name_in_map(&self.ctx.layout_map, &op.stream))
                        })
                        .or_else(|| match &p.ty {
                            MirType::Named(n) => lookup_name_in_map(&self.ctx.layout_map, n),
                            _ => None,
                        });
                    if let Some(lidx) = lidx_opt {
                        out.push((pl, lidx));
                    }
                }
            }
            out
        };

        for (pl, lidx) in stream_params {
            let sz = self.ctx.layouts[lidx].size;
            let buf_slot = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
            let buf_ptr = self.b.ins().stack_addr(ptr_ty, buf_slot, 0);
            self.def_scalar_typed(pl, buf_ptr);

            let flag = self.b.ins().load(
                types::I8,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.res_flag_offset(lidx) as i32,
            );
            let is_msg = self.b.ins().icmp_imm_s(IntCC::Equal, flag, 2);
            let read_bb = self.b.create_block();
            let done_bb = self.b.create_block();
            self.b.ins().brif(is_msg, read_bb, &[], done_bb, &[]);

            self.b.switch_to_block(read_bb);
            self.b.seal_block(read_bb);
            if let Some(msg_it) = self.ensure_stream_query_iter(lidx) {
                let it_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, msg_it, 0);
                let loop_pre_bb = self.b.create_block();
                self.b.ins().brif(it_ok, loop_pre_bb, &[], done_bb, &[]);

                self.b.switch_to_block(loop_pre_bb);
                self.b.seal_block(loop_pre_bb);
                let elem_sz = sz.max(1);
                let batch_cap = 16usize;
                let batch_slot = alloc_zero_slot(self.b, batch_cap * elem_sz, ptr_ty);
                let batch_ptr = self.b.ins().stack_addr(ptr_ty, batch_slot, 0);
                let got_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                let got_ptr = self.b.ins().stack_addr(ptr_ty, got_slot, 0);
                let z_term = self.b.ins().iconst(ptr_ty, 0);
                let cap_v = self.b.ins().iconst(ptr_ty, batch_cap as i64);
                let z_ptr = self.b.ins().iconst(ptr_ty, 0);

                let loop_hdr = self.b.create_block();
                let copy_bb = self.b.create_block();
                let check_more_bb = self.b.create_block();
                self.b.ins().jump(loop_hdr, &[]);

                self.b.switch_to_block(loop_hdr);
                self.b
                    .ins()
                    .store(MemFlagsData::trusted(), z_ptr, got_ptr, 0);
                let rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::MSG_READ_BATCH,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[msg_it, z_term, batch_ptr, cap_v, got_ptr],
                );
                let rc_ok = self.b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
                let got = self
                    .b
                    .ins()
                    .load(ptr_ty, MemFlagsData::trusted(), got_ptr, 0);
                let got_pos = self.b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, got, 0);
                let has_msg = self.b.ins().band(rc_ok, got_pos);
                self.b.ins().brif(has_msg, copy_bb, &[], done_bb, &[]);

                self.b.switch_to_block(copy_bb);
                self.b.seal_block(copy_bb);
                if sz > 0 {
                    let last_idx = self.b.ins().iadd_imm_s(got, -1);
                    let off = self.b.ins().imul_imm_s(last_idx, sz as i64);
                    let src_ptr = self.b.ins().iadd(batch_ptr, off);
                    emit_memcpy(self.b, buf_ptr, src_ptr, sz);
                }
                self.b.ins().jump(check_more_bb, &[]);

                self.b.switch_to_block(check_more_bb);
                self.b.seal_block(check_more_bb);
                let full_batch = self.b.ins().icmp_imm_s(IntCC::Equal, got, batch_cap as i64);
                self.b.ins().brif(full_batch, loop_hdr, &[], done_bb, &[]);
                self.b.seal_block(loop_hdr);
            } else {
                self.b.ins().jump(done_bb, &[]);
            }

            self.b.switch_to_block(done_bb);
            self.b.seal_block(done_bb);
        }
        Ok(())
    }

    pub(super) fn lower_stream_emit(&mut self, stream: &str, payload: LocalId) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, stream) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else {
            let mty = &self.mir_fn.locals[payload.0 as usize].ty;
            if matches!(mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(mty) {
                self.use_scalar(payload)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(payload, &cloned, sp, 0);
                sp
            }
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);

        // If host registered `stream` as `BAM_STORAGE_FLAG_MESSAGE`, emit via `msg_send(iter, 0, ...)`.
        if let Some(sq) = self
            .sys_entry
            .and_then(|e| {
                e.stream_queries
                    .iter()
                    .find(|s| s.stream_layout_idx == lidx)
            })
            .cloned()
        {
            let flag = self.b.ins().load(
                types::I8,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.res_flag_offset(lidx) as i32,
            );
            let is_host_msg = self.b.ins().icmp_imm_s(IntCC::Equal, flag, 2);
            let msg_bb = self.b.create_block();
            let trig_bb = self.b.create_block();
            let done_bb = self.b.create_block();
            self.b.ins().brif(is_host_msg, msg_bb, &[], trig_bb, &[]);

            self.b.switch_to_block(msg_bb);
            self.b.seal_block(msg_bb);
            let iter = self
                .ensure_stream_query_iter(sq.stream_layout_idx)
                .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
            let z_term = self.b.ins().iconst(ptr_ty, 0);
            let _rc = call_vtable_guarded(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::MSG_SEND,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                types::I32,
                ptr_ty,
                self.ctx.call_conv,
                iter,
                &[iter, z_term, dptr, dlen],
            );
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(trig_bb);
            self.b.seal_block(trig_bb);
            self.lower_cmd_trigger(stream, None, Some(payload), false);
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(done_bb);
            self.b.seal_block(done_bb);
            return;
        }

        self.lower_cmd_trigger(stream, None, Some(payload), false);
    }

    pub(super) fn lower_cmd_insert_relation(
        &mut self,
        relation: &str,
        entity: LocalId,
        target: LocalId,
        payload: Option<LocalId>,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let ent = self.use_scalar(entity);
        let tgt = {
            let tmp = self.use_scalar(target);
            coerce_cl_val(self.b, tmp, types::I64, ptr_ty)
        };
        if is_child_of_rel(relation) {
            let cmds = self.ensure_commands();
            let comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.child_of_comp_off as i32,
            );
            let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
            let comp_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, comp, 0);
            let comp_valid =
                self.b
                    .ins()
                    .icmp_imm_s(IntCC::NotEqual, comp, i64::from(BAM_COMPONENT_INVALID));
            let c0 = self.b.ins().band(cmds_ok, comp_nz);
            let ok = self.b.ins().band(c0, comp_valid);
            let do_bb = self.b.create_block();
            let done_bb = self.b.create_block();
            self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

            self.b.switch_to_block(do_bb);
            self.b.seal_block(do_bb);
            let slot = alloc_zero_slot(self.b, 8, ptr_ty);
            let dptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
            self.b.ins().store(MemFlagsData::trusted(), tgt, dptr, 0);
            let dlen = self.b.ins().iconst(ptr_ty, 8);
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_INSERT,
                &[ptr_ty, types::I64, types::I32, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, comp, dptr, dlen],
            );
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(done_bb);
            self.b.seal_block(done_bb);
            return;
        }
        let rel_idx = self.ctx.relation_map.get(relation).copied().or_else(|| {
            relation
                .rsplit("::")
                .next()
                .and_then(|s| self.ctx.relation_map.get(s).copied())
        });
        let parent_lidx = self.custom_rel_parent_layout_idx(relation);
        if rel_idx.is_none() && parent_lidx.is_none() {
            return;
        }
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        if let Some(ri) = rel_idx {
            let rel_comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.rel_slot_offset(ri) as i32,
            );
            let sz = self.ctx.relations[ri].payload_size;
            let dptr = if sz == 0 {
                self.b.ins().iconst(ptr_ty, 0)
            } else if let Some(pl) = payload {
                let mty = self.effective_local_mir_ty(pl).clone();
                if matches!(mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(&mty) {
                    self.use_scalar(pl)
                } else {
                    let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                    let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                    self.store_local_to_mem(pl, &mty, sp, 0);
                    sp
                }
            } else {
                self.b.ins().iconst(ptr_ty, 0)
            };
            let dlen = self.b.ins().iconst(ptr_ty, sz as i64);
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_INSERT_RELATION,
                &[ptr_ty, types::I64, types::I32, types::I64, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, rel_comp, tgt, dptr, dlen],
            );
        }
        if let Some(plidx) = parent_lidx {
            let pcomp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(plidx) as i32,
            );
            let slot = alloc_zero_slot(self.b, 8, ptr_ty);
            let dptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
            self.b.ins().store(MemFlagsData::trusted(), tgt, dptr, 0);
            let dlen = self.b.ins().iconst(ptr_ty, 8);
            let _prc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_INSERT,
                &[ptr_ty, types::I64, types::I32, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, pcomp, dptr, dlen],
            );
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_cmd_remove_relation(
        &mut self,
        relation: &str,
        entity: LocalId,
        target: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let ent = self.use_scalar(entity);
        let tgt = self.use_scalar(target);
        if is_child_of_rel(relation) {
            let cmds = self.ensure_commands();
            let comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.child_of_comp_off as i32,
            );
            let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
            let comp_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, comp, 0);
            let comp_valid =
                self.b
                    .ins()
                    .icmp_imm_s(IntCC::NotEqual, comp, i64::from(BAM_COMPONENT_INVALID));
            let c0 = self.b.ins().band(cmds_ok, comp_nz);
            let ok = self.b.ins().band(c0, comp_valid);
            let do_bb = self.b.create_block();
            let done_bb = self.b.create_block();
            self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

            self.b.switch_to_block(do_bb);
            self.b.seal_block(do_bb);
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_REMOVE,
                &[ptr_ty, types::I64, types::I32],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, comp],
            );
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(done_bb);
            self.b.seal_block(done_bb);
            return;
        }
        let rel_idx = self.ctx.relation_map.get(relation).copied().or_else(|| {
            relation
                .rsplit("::")
                .next()
                .and_then(|s| self.ctx.relation_map.get(s).copied())
        });
        let parent_lidx = self.custom_rel_parent_layout_idx(relation);
        if rel_idx.is_none() && parent_lidx.is_none() {
            return;
        }
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        if let Some(ri) = rel_idx {
            let rel_comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.rel_slot_offset(ri) as i32,
            );
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_REMOVE_RELATION,
                &[ptr_ty, types::I64, types::I32, types::I64],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, rel_comp, tgt],
            );
        }
        if let Some(plidx) = parent_lidx {
            let pcomp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(plidx) as i32,
            );
            let _prc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_REMOVE,
                &[ptr_ty, types::I64, types::I32],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ent, pcomp],
            );
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn custom_rel_parent_layout_idx(&self, relation: &str) -> Option<usize> {
        let short_r = relation.rsplit("::").next().unwrap_or(relation);
        let comp_short = format!("__strata_rel_parent_{short_r}");
        lookup_name_in_map(&self.ctx.layout_map, &comp_short)
    }

    pub(super) fn lower_table_load(
        &mut self,
        dst: LocalId,
        table_name: &str,
        key: LocalId,
        field: &str,
    ) {
        let Some(tbl) = self.ctx.resolve_table_by_key(table_name).cloned() else {
            self.def_zero_for_local(dst);
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let raw_k_orig = self.use_scalar(key);
        let raw_k_cl = self.b.func.dfg.value_type(raw_k_orig);
        let key_mty = self.effective_local_mir_ty(key).clone();
        let key_signed = tbl.key_is_signed
            || is_signed_int_ty(&key_mty)
            || self
                .ctx
                .enum_scalar_mir_ty(&key_mty)
                .is_some_and(|st| is_signed_int_ty(&st));
        let key_i64 = if raw_k_cl == types::I64 {
            raw_k_orig
        } else if raw_k_cl.bits() < 64 {
            if key_signed {
                self.b.ins().sextend(types::I64, raw_k_orig)
            } else {
                self.b.ins().uextend(types::I64, raw_k_orig)
            }
        } else {
            coerce_cl_val(self.b, raw_k_orig, types::I64, ptr_ty)
        };

        let safe_idx_ptr = if let Some(keys_id) = tbl.keys_data_id {
            let kgv = self.ctx.obj_mod.declare_data_in_func(keys_id, self.b.func);
            let kptr = self.b.ins().symbol_value(ptr_ty, kgv);
            let z64 = self.b.ins().iconst(types::I64, 0);
            let n64 = self.b.ins().iconst(types::I64, tbl.row_count as i64);

            let bs_hdr = self.b.create_block();
            let bs_body = self.b.create_block();
            let bs_done = self.b.create_block();
            self.b.append_block_param(bs_hdr, types::I64);
            self.b.append_block_param(bs_hdr, types::I64);
            self.b
                .ins()
                .jump(bs_hdr, &[BlockArg::Value(z64), BlockArg::Value(n64)]);

            self.b.switch_to_block(bs_hdr);
            let lo = self.b.block_params(bs_hdr)[0];
            let hi = self.b.block_params(bs_hdr)[1];
            let cont = self.b.ins().icmp(IntCC::UnsignedLessThan, lo, hi);
            self.b.ins().brif(cont, bs_body, &[], bs_done, &[]);

            self.b.switch_to_block(bs_body);
            self.b.seal_block(bs_body);
            let sum = self.b.ins().iadd(lo, hi);
            let mid = self.b.ins().ushr_imm_u(sum, 1);
            let mid_p = coerce_cl_val(self.b, mid, ptr_ty, ptr_ty);
            let m_off = self.b.ins().imul_imm_s(mid_p, 8);
            let m_addr = self.b.ins().iadd(kptr, m_off);
            let k_mid = self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), m_addr, 0);
            let is_lt = self.b.ins().icmp(IntCC::SignedLessThan, k_mid, key_i64);
            let mid_p1 = self.b.ins().iadd_imm_s(mid, 1);
            let next_lo = self.b.ins().select(is_lt, mid_p1, lo);
            let next_hi = self.b.ins().select(is_lt, hi, mid);
            self.b.ins().jump(
                bs_hdr,
                &[BlockArg::Value(next_lo), BlockArg::Value(next_hi)],
            );
            self.b.seal_block(bs_hdr);

            self.b.switch_to_block(bs_done);
            self.b.seal_block(bs_done);
            let lo_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, lo, n64);
            let chk_bb = self.b.create_block();
            let miss_bb = self.b.create_block();
            let resolved_bb = self.b.create_block();
            self.b.append_block_param(resolved_bb, ptr_ty);
            self.b.ins().brif(lo_ok, chk_bb, &[], miss_bb, &[]);

            self.b.switch_to_block(chk_bb);
            self.b.seal_block(chk_bb);
            let lo_p = coerce_cl_val(self.b, lo, ptr_ty, ptr_ty);
            let l_off = self.b.ins().imul_imm_s(lo_p, 8);
            let l_addr = self.b.ins().iadd(kptr, l_off);
            let k_at_lo = self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), l_addr, 0);
            let eq = self.b.ins().icmp(IntCC::Equal, k_at_lo, key_i64);
            let zp = self.b.ins().iconst(ptr_ty, 0);
            let idx_p = self.b.ins().select(eq, lo_p, zp);
            self.b.ins().jump(resolved_bb, &[BlockArg::Value(idx_p)]);

            self.b.switch_to_block(miss_bb);
            self.b.seal_block(miss_bb);
            let zp2 = self.b.ins().iconst(ptr_ty, 0);
            self.b.ins().jump(resolved_bb, &[BlockArg::Value(zp2)]);

            self.b.switch_to_block(resolved_bb);
            self.b.seal_block(resolved_bb);
            self.b.block_params(resolved_bb)[0]
        } else {
            let raw_k_ptr = coerce_cl_val(self.b, key_i64, ptr_ty, ptr_ty);
            let in_range =
                self.b
                    .ins()
                    .icmp_imm_s(IntCC::UnsignedLessThan, key_i64, tbl.row_count as i64);
            let z = self.b.ins().iconst(ptr_ty, 0);
            self.b.ins().select(in_range, raw_k_ptr, z)
        };

        let gv = self
            .ctx
            .obj_mod
            .declare_data_in_func(tbl.data_id, self.b.func);
        let tbl_ptr = self.b.ins().symbol_value(ptr_ty, gv);
        let row_off = self.b.ins().imul_imm_s(safe_idx_ptr, tbl.row_stride as i64);
        let row_ptr = self.b.ins().iadd(tbl_ptr, row_off);

        if field.is_empty() {
            let dst_mty = self.effective_local_mir_ty(dst).clone();
            if matches!(dst_mty, MirType::Ptr | MirType::MutPtr) || self.ctx.is_agg_mir_ty(&dst_mty)
            {
                self.def_scalar_typed(dst, row_ptr);
                self.ptr_pointee_tys.insert(dst.0, dst_mty);
            } else {
                self.load_local_from_mem(dst, &dst_mty, row_ptr, 0);
            }
            return;
        }
        let (foff, fmty_opt) = if let Some((off, mty)) = tbl.fields.get(field) {
            (*off, Some(mty.clone()))
        } else {
            self.ctx.resolve_field_offset_and_ty(table_name, field)
        };
        let Some(fmty) = fmty_opt else {
            self.def_zero_for_local(dst);
            return;
        };
        if let Some(scalar_mty) = self.ctx.enum_scalar_mir_ty(&fmty) {
            self.load_local_from_mem(dst, &scalar_mty, row_ptr, foff as i32);
        } else if self.ctx.is_agg_mir_ty(&fmty) {
            let fptr = self.b.ins().iadd_imm_s(row_ptr, foff as i64);
            self.def_scalar_typed(dst, fptr);
            self.ptr_pointee_tys.insert(dst.0, fmty.clone());
            if let MirType::Array { elem, len } = fmty {
                self.array_ptr_lens.insert(dst.0, len);
                self.ptr_elem_tys.insert(dst.0, *elem);
            }
        } else {
            self.load_local_from_mem(dst, &fmty, row_ptr, foff as i32);
        }
    }

    pub(super) fn lower_curve_sample(&mut self, dst: LocalId, curve_name: &str, x: LocalId) {
        let Some(crv) = self.ctx.curves.get(curve_name).cloned() else {
            self.def_zero_for_local(dst);
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let xv = {
            let __tmp = self.use_scalar(x);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let gv = self
            .ctx
            .obj_mod
            .declare_data_in_func(crv.data_id, self.b.func);
        let ptr = self.b.ins().symbol_value(ptr_ty, gv);

        if crv.points_len == 0 {
            let z = self.b.ins().f32const(0.0);
            self.def_scalar_typed(dst, z);
            return;
        }
        if crv.points_len == 1 {
            let y0 = self
                .b
                .ins()
                .load(types::F32, MemFlagsData::trusted(), ptr, 4);
            self.def_scalar_typed(dst, y0);
            return;
        }

        let x0 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, 0);
        let y0 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, 4);
        let last_off = ((crv.points_len - 1) * 8) as i32;
        let xn = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, last_off);
        let yn = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, last_off + 4);

        let le_first = self.b.ins().fcmp(FloatCC::LessThanOrEqual, xv, x0);
        let ge_last = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, xv, xn);

        let ret_first_bb = self.b.create_block();
        let check_last_bb = self.b.create_block();
        let ret_last_bb = self.b.create_block();
        let scan_init_bb = self.b.create_block();
        let scan_hdr_bb = self.b.create_block();
        let scan_body_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::F32);

        self.b
            .ins()
            .brif(le_first, ret_first_bb, &[], check_last_bb, &[]);

        self.b.switch_to_block(ret_first_bb);
        self.b.seal_block(ret_first_bb);
        self.b.ins().jump(done_bb, &[BlockArg::Value(y0)]);

        self.b.switch_to_block(check_last_bb);
        self.b.seal_block(check_last_bb);
        self.b
            .ins()
            .brif(ge_last, ret_last_bb, &[], scan_init_bb, &[]);

        self.b.switch_to_block(ret_last_bb);
        self.b.ins().jump(done_bb, &[BlockArg::Value(yn)]);

        self.b.switch_to_block(scan_init_bb);
        self.b.seal_block(scan_init_bb);
        let iv = self.b.declare_var(ptr_ty);
        let z = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(iv, z);
        self.b.ins().jump(scan_hdr_bb, &[]);

        self.b.switch_to_block(scan_hdr_bb);
        let i = self.b.use_var(iv);
        let ok = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, (crv.points_len - 1) as i64);
        self.b.ins().brif(ok, scan_body_bb, &[], ret_last_bb, &[]);
        self.b.seal_block(ret_last_bb);

        self.b.switch_to_block(scan_body_bb);
        self.b.seal_block(scan_body_bb);
        let off = self.b.ins().imul_imm_s(i, 8);
        let seg_ptr = self.b.ins().iadd(ptr, off);
        let x1 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 8);
        let in_seg = self.b.ins().fcmp(FloatCC::LessThanOrEqual, xv, x1);

        let interp_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(in_seg, interp_bb, &[], step_bb, &[]);

        self.b.switch_to_block(interp_bb);
        self.b.seal_block(interp_bb);
        let xa = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 0);
        let ya = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 4);
        let yb = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 12);
        let dx = self.b.ins().fsub(x1, xa);
        let eps = self.b.ins().f32const(1e-12);
        let dx_pos = self.b.ins().fcmp(FloatCC::GreaterThan, dx, eps);
        let num = self.b.ins().fsub(xv, xa);
        let ratio = self.b.ins().fdiv(num, dx);
        let zf = self.b.ins().f32const(0.0);
        let t = self.b.ins().select(dx_pos, ratio, zf);
        let dy = self.b.ins().fsub(yb, ya);
        let delta = self.b.ins().fmul(dy, t);
        let out_y = self.b.ins().fadd(ya, delta);
        self.b.ins().jump(done_bb, &[BlockArg::Value(out_y)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(iv, ni);
        self.b.ins().jump(scan_hdr_bb, &[]);

        self.b.seal_block(scan_hdr_bb);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let final_y = self.b.block_params(done_bb)[0];
        self.def_scalar_typed(dst, final_y);
    }
}

fn parse_swizzle_lanes(field: &str) -> Option<Vec<u8>> {
    if field.is_empty() || field.len() > 4 {
        return None;
    }
    let mut lanes = Vec::with_capacity(field.len());
    for c in field.chars() {
        let l = match c {
            'x' | 'r' => 0,
            'y' | 'g' => 1,
            'z' | 'b' => 2,
            'w' | 'a' => 3,
            _ => return None,
        };
        lanes.push(l);
    }
    Some(lanes)
}
