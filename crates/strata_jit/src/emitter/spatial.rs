//! Spatial index 2-pass CSR rebuild and cell-bucketed disc/segment broadphase lowering.

use super::*;

fn find_spatial_meta_by_key(ctx: &ModuleContext<'_>, key: &str) -> Option<SpatialIndexMeta> {
    let short = key.rsplit("::").next().unwrap_or(key);
    ctx.spatial_metas
        .iter()
        .find(|m| {
            m.name == key
                || m.name == short
                || m.name.rsplit("::").next() == Some(short)
                || m.canonical_name == key
                || m.canonical_name.rsplit("::").next() == Some(short)
        })
        .cloned()
}

fn resolve_spatial_meta(
    ctx: &ModuleContext<'_>,
    func: &MirFunction,
    index_name: &str,
) -> Option<SpatialIndexMeta> {
    if let Some(rb) = func.resources.iter().find(|rb| rb.param_name == index_name)
        && let Some(meta) = find_spatial_meta_by_key(ctx, &rb.resource_name)
            .or_else(|| find_spatial_meta_by_key(ctx, &rb.canonical_name))
    {
        return Some(meta);
    }
    if let Some(meta) = find_spatial_meta_by_key(ctx, index_name) {
        return Some(meta);
    }
    for rb in &func.resources {
        if (rb.resource_name == index_name || rb.canonical_name == index_name)
            && let Some(meta) = find_spatial_meta_by_key(ctx, &rb.resource_name)
                .or_else(|| find_spatial_meta_by_key(ctx, &rb.canonical_name))
        {
            return Some(meta);
        }
    }
    None
}

fn axis_val(coords: [Value; 3], ax: u8) -> Value {
    match ax {
        0 => coords[0],
        1 => coords[1],
        _ => coords[2],
    }
}

fn emit_spatial_clamp_cell_coord(
    b: &mut FunctionBuilder<'_>,
    coord: Value,
    bmin: f32,
    inv_cs: f32,
    dim: usize,
) -> Value {
    let bmin_v = b.ins().f32const(bmin);
    let inv_v = b.ins().f32const(inv_cs);
    let diff = b.ins().fsub(coord, bmin_v);
    let scaled = b.ins().fmul(diff, inv_v);
    let floored = b.ins().floor(scaled);
    let zero_f = b.ins().f32const(0.0);
    let zero_i = b.ins().iconst(types::I32, 0);
    let max_c = dim.saturating_sub(1) as i64;
    let max_ci = b.ins().iconst(types::I32, max_c);
    let max_cf = b.ins().f32const(max_c as f32);
    let gt_zero = b.ins().fcmp(FloatCC::GreaterThan, floored, zero_f);
    let lt_max = b.ins().fcmp(FloatCC::LessThan, floored, max_cf);
    let raw_i = b.ins().fcvt_to_sint_sat(types::I32, floored);
    let clamped_hi = b.ins().select(lt_max, raw_i, max_ci);
    b.ins().select(gt_zero, clamped_hi, zero_i)
}

fn emit_spatial_quantize_cell(
    b: &mut FunctionBuilder<'_>,
    coords: [Value; 3],
    meta: &SpatialIndexMeta,
) -> Value {
    let cx = emit_spatial_clamp_cell_coord(
        b,
        axis_val(coords, meta.plane_axes[0]),
        meta.bounds_min[0],
        meta.inv_cell_size,
        meta.cols,
    );
    let cy = emit_spatial_clamp_cell_coord(
        b,
        axis_val(coords, meta.plane_axes[1]),
        meta.bounds_min[1],
        meta.inv_cell_size,
        meta.rows,
    );
    let row_off = b.ins().imul_imm_s(cy, meta.cols as i64);
    b.ins().iadd(row_off, cx)
}

fn emit_spatial_frame_ptr(
    b: &mut FunctionBuilder<'_>,
    state_ptr: Value,
    frame_idx: Value,
    meta: &SpatialIndexMeta,
    ptr_ty: Type,
) -> Value {
    let fp = coerce_cl_val(b, frame_idx, ptr_ty, ptr_ty);
    let soff = b.ins().imul_imm_s(fp, meta.slot_bytes as i64);
    let ring_base = b.ins().iadd_imm_s(state_ptr, meta.ring_offset as i64);
    b.ins().iadd(ring_base, soff)
}

impl<'a, 'b, 'f> FnLowerer<'a, 'b, 'f> {
    pub(super) fn lower_spatial_csr_begin(&mut self, index_name: &str) {
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, index_name) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cur_tick = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let z32 = self.b.ins().iconst(types::I32, 0);
        let next_frame = if meta.frames > 1 {
            let inc = self.b.ins().iadd_imm_s(cur_tick, 1);
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            self.b.ins().urem(inc, fv)
        } else {
            z32
        };
        self.b.ins().store(
            MemFlagsData::trusted(),
            next_frame,
            self.state_ptr,
            meta.cursor_offset as i32,
        );

        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, next_frame, &meta, ptr_ty);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), z32, frame_ptr, 0);

        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let stride = (meta.cell_count + 1) as i64;
        let idx_var = self.b.declare_var(types::I32);
        self.b.def_var(idx_var, z32);
        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let done = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let c = self.b.use_var(idx_var);
        let c_ok = self.b.ins().icmp_imm_s(IntCC::UnsignedLessThan, c, stride);
        self.b.ins().brif(c_ok, body, &[], done, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let cp = coerce_cl_val(self.b, c, ptr_ty, ptr_ty);
        let coff = self.b.ins().imul_imm_s(cp, 4);
        let addr = self.b.ins().iadd(off_base, coff);
        self.b.ins().store(MemFlagsData::trusted(), z32, addr, 0);
        let nc = self.b.ins().iadd_imm_s(c, 1);
        self.b.def_var(idx_var, nc);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(done);
        self.b.seal_block(done);
    }

    pub(super) fn lower_spatial_csr_count(&mut self, index_name: &str, pos: LocalId) {
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, index_name) else {
            return;
        };
        if meta.cell_count == 0 {
            return;
        }
        let ptr_ty = self.ctx.ptr_ty;
        let pvec = self.use_vec(pos);
        let coords = [pvec[0], pvec[1], pvec[2]];

        let cur_frame = if meta.frames > 1 {
            let raw = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                meta.cursor_offset as i32,
            );
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            self.b.ins().urem(raw, fv)
        } else {
            self.b.ins().iconst(types::I32, 0)
        };
        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, cur_frame, &meta, ptr_ty);
        let cur_cnt = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame_ptr, 0);
        let cap_ok =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cur_cnt, meta.capacity as i64);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(cap_ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let ncnt = self.b.ins().iadd_imm_s(cur_cnt, 1);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ncnt, frame_ptr, 0);
        let cell = emit_spatial_quantize_cell(self.b, coords, &meta);
        let cell_ok =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cell, meta.cell_count as i64);
        let inc_bb = self.b.create_block();
        self.b.ins().brif(cell_ok, inc_bb, &[], done_bb, &[]);

        self.b.switch_to_block(inc_bb);
        self.b.seal_block(inc_bb);
        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let cell_p1 = self.b.ins().iadd_imm_s(cell, 1);
        let cell_p1_ptr = coerce_cl_val(self.b, cell_p1, ptr_ty, ptr_ty);
        let boff = self.b.ins().imul_imm_s(cell_p1_ptr, 4);
        let addr = self.b.ins().iadd(off_base, boff);
        let prev = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), addr, 0);
        let next = self.b.ins().iadd_imm_s(prev, 1);
        self.b.ins().store(MemFlagsData::trusted(), next, addr, 0);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_spatial_csr_prefix_sum(&mut self, index_name: &str) {
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, index_name) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let z32 = self.b.ins().iconst(types::I32, 0);
        let cur_frame = if meta.frames > 1 {
            let raw = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                meta.cursor_offset as i32,
            );
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            self.b.ins().urem(raw, fv)
        } else {
            z32
        };
        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, cur_frame, &meta, ptr_ty);
        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let wc_base = self
            .b
            .ins()
            .iadd_imm_s(self.state_ptr, meta.write_cursors_offset as i64);

        let c_var = self.b.declare_var(types::I32);
        let run_var = self.b.declare_var(types::I32);
        self.b.def_var(c_var, z32);
        self.b.def_var(run_var, z32);

        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let done = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let c = self.b.use_var(c_var);
        let c_ok = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, c, meta.cell_count as i64);
        self.b.ins().brif(c_ok, body, &[], done, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let run = self.b.use_var(run_var);
        let cp = coerce_cl_val(self.b, c, ptr_ty, ptr_ty);
        let coff = self.b.ins().imul_imm_s(cp, 4);
        let off_c_addr = self.b.ins().iadd(off_base, coff);
        let wc_c_addr = self.b.ins().iadd(wc_base, coff);
        let cnt = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), off_c_addr, 4);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), run, off_c_addr, 0);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), run, wc_c_addr, 0);
        let next_run = self.b.ins().iadd(run, cnt);
        self.b.def_var(run_var, next_run);
        let nc = self.b.ins().iadd_imm_s(c, 1);
        self.b.def_var(c_var, nc);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(done);
        self.b.seal_block(done);
        let total_run = self.b.use_var(run_var);
        self.b.ins().store(
            MemFlagsData::trusted(),
            total_run,
            off_base,
            (meta.cell_count * 4) as i32,
        );
    }

    pub(super) fn lower_spatial_csr_scatter(
        &mut self,
        index_name: &str,
        entity: LocalId,
        pos: LocalId,
    ) {
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, index_name) else {
            return;
        };
        if meta.cell_count == 0 {
            return;
        }
        let ptr_ty = self.ctx.ptr_ty;
        let ent = {
            let tmp = self.use_scalar(entity);
            coerce_cl_val(self.b, tmp, types::I64, ptr_ty)
        };
        let pvec = self.use_vec(pos);
        let coords = [pvec[0], pvec[1], pvec[2]];
        let zf = self.b.ins().f32const(0.0);

        let cur_frame = if meta.frames > 1 {
            let raw = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                meta.cursor_offset as i32,
            );
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            self.b.ins().urem(raw, fv)
        } else {
            self.b.ins().iconst(types::I32, 0)
        };
        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, cur_frame, &meta, ptr_ty);
        let cell = emit_spatial_quantize_cell(self.b, coords, &meta);
        let cell_ok =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cell, meta.cell_count as i64);
        let check_slot_bb = self.b.create_block();
        let write_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(cell_ok, check_slot_bb, &[], done_bb, &[]);

        self.b.switch_to_block(check_slot_bb);
        self.b.seal_block(check_slot_bb);
        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let wc_base = self
            .b
            .ins()
            .iadd_imm_s(self.state_ptr, meta.write_cursors_offset as i64);
        let cell_p = coerce_cl_val(self.b, cell, ptr_ty, ptr_ty);
        let coff = self.b.ins().imul_imm_s(cell_p, 4);
        let wc_addr = self.b.ins().iadd(wc_base, coff);
        let off_addr = self.b.ins().iadd(off_base, coff);
        let slot = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), wc_addr, 0);
        let cell_end = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), off_addr, 4);
        let lt_end = self.b.ins().icmp(IntCC::UnsignedLessThan, slot, cell_end);
        let lt_cap = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, slot, meta.capacity as i64);
        let slot_ok = self.b.ins().band(lt_end, lt_cap);
        self.b.ins().brif(slot_ok, write_bb, &[], done_bb, &[]);

        self.b.switch_to_block(write_bb);
        self.b.seal_block(write_bb);
        let next_slot = self.b.ins().iadd_imm_s(slot, 1);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), next_slot, wc_addr, 0);
        let slot_p = coerce_cl_val(self.b, slot, ptr_ty, ptr_ty);
        let ents_base = self.b.ins().iadd_imm_s(frame_ptr, meta.entities_off as i64);
        let eoff = self.b.ins().imul_imm_s(slot_p, 8);
        let edst = self.b.ins().iadd(ents_base, eoff);
        self.b.ins().store(MemFlagsData::trusted(), ent, edst, 0);

        let pos_base = self
            .b
            .ins()
            .iadd_imm_s(frame_ptr, meta.positions_off as i64);
        let poff = self.b.ins().imul_imm_s(slot_p, 16);
        let pdst = self.b.ins().iadd(pos_base, poff);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), coords[0], pdst, 0);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), coords[1], pdst, 4);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), coords[2], pdst, 8);
        self.b.ins().store(MemFlagsData::trusted(), zf, pdst, 12);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    pub(super) fn lower_spatial_query_disc(
        &mut self,
        dst: LocalId,
        grid_name: &str,
        center: LocalId,
        radius: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let out_slot = alloc_zero_slot(self.b, MAX_SPATIAL_CANDIDATES * 8, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, grid_name) else {
            self.def_scalar_typed(dst, out_ptr);
            return;
        };
        if meta.cols == 0 || meta.rows == 0 || meta.cell_count == 0 {
            self.def_scalar_typed(dst, out_ptr);
            return;
        }

        let cvec = self.use_vec(center);
        let rad_raw = {
            let __tmp = self.use_scalar(radius);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let zf = self.b.ins().f32const(0.0);
        let rad_pos = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, rad_raw, zf);
        let rad = self.b.ins().select(rad_pos, rad_raw, zf);
        let r2 = self.b.ins().fmul(rad, rad);

        let cur_frame = if meta.frames > 1 {
            let raw = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                meta.cursor_offset as i32,
            );
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            self.b.ins().urem(raw, fv)
        } else {
            self.b.ins().iconst(types::I32, 0)
        };
        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, cur_frame, &meta, ptr_ty);
        let raw_total = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame_ptr, 0);
        let cap_v = self.b.ins().iconst(types::I32, meta.capacity as i64);
        let total_lt_cap = self.b.ins().icmp(IntCC::UnsignedLessThan, raw_total, cap_v);
        let total = self.b.ins().select(total_lt_cap, raw_total, cap_v);

        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let ents_base = self.b.ins().iadd_imm_s(frame_ptr, meta.entities_off as i64);
        let pos_base = self
            .b
            .ins()
            .iadd_imm_s(frame_ptr, meta.positions_off as i64);

        let c_coords = [cvec[0], cvec[1], cvec[2]];
        let cx_coord = axis_val(c_coords, meta.plane_axes[0]);
        let cy_coord = axis_val(c_coords, meta.plane_axes[1]);
        let min_x = self.b.ins().fsub(cx_coord, rad);
        let max_x = self.b.ins().fadd(cx_coord, rad);
        let min_y = self.b.ins().fsub(cy_coord, rad);
        let max_y = self.b.ins().fadd(cy_coord, rad);

        let min_cx = emit_spatial_clamp_cell_coord(
            self.b,
            min_x,
            meta.bounds_min[0],
            meta.inv_cell_size,
            meta.cols,
        );
        let max_cx = emit_spatial_clamp_cell_coord(
            self.b,
            max_x,
            meta.bounds_min[0],
            meta.inv_cell_size,
            meta.cols,
        );
        let min_cy = emit_spatial_clamp_cell_coord(
            self.b,
            min_y,
            meta.bounds_min[1],
            meta.inv_cell_size,
            meta.rows,
        );
        let max_cy = emit_spatial_clamp_cell_coord(
            self.b,
            max_y,
            meta.bounds_min[1],
            meta.inv_cell_size,
            meta.rows,
        );

        let cy_var = self.b.declare_var(types::I32);
        let cx_var = self.b.declare_var(types::I32);
        let k_var = self.b.declare_var(types::I32);
        let w_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(cy_var, min_cy);
        self.b.def_var(w_var, z32);

        let cy_hdr = self.b.create_block();
        let cy_body = self.b.create_block();
        let cx_hdr = self.b.create_block();
        let cx_body = self.b.create_block();
        let k_hdr = self.b.create_block();
        let k_body = self.b.create_block();
        let add_bb = self.b.create_block();
        let k_step = self.b.create_block();
        let cx_step = self.b.create_block();
        let cy_step = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(cy_hdr, &[]);

        self.b.switch_to_block(cy_hdr);
        let cy = self.b.use_var(cy_var);
        let w_cy = self.b.use_var(w_var);
        let cy_ok = self.b.ins().icmp(IntCC::SignedLessThanOrEqual, cy, max_cy);
        let w_ok_cy = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_cy,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let cy_go = self.b.ins().band(cy_ok, w_ok_cy);
        self.b.ins().brif(cy_go, cy_body, &[], exit, &[]);

        self.b.switch_to_block(cy_body);
        self.b.seal_block(cy_body);
        self.b.def_var(cx_var, min_cx);
        self.b.ins().jump(cx_hdr, &[]);

        self.b.switch_to_block(cx_hdr);
        let cx = self.b.use_var(cx_var);
        let w_cx = self.b.use_var(w_var);
        let cx_ok = self.b.ins().icmp(IntCC::SignedLessThanOrEqual, cx, max_cx);
        let w_ok_cx = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_cx,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let cx_go = self.b.ins().band(cx_ok, w_ok_cx);
        self.b.ins().brif(cx_go, cx_body, &[], cy_step, &[]);

        self.b.switch_to_block(cx_body);
        self.b.seal_block(cx_body);
        let row_off = self.b.ins().imul_imm_s(cy, meta.cols as i64);
        let cell = self.b.ins().iadd(row_off, cx);
        let cell_in =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cell, meta.cell_count as i64);
        let cell_p = coerce_cl_val(self.b, cell, ptr_ty, ptr_ty);
        let coff = self.b.ins().imul_imm_s(cell_p, 4);
        let oaddr = self.b.ins().iadd(off_base, coff);
        let range_check_bb = self.b.create_block();
        self.b
            .ins()
            .brif(cell_in, range_check_bb, &[], cx_step, &[]);

        self.b.switch_to_block(range_check_bb);
        self.b.seal_block(range_check_bb);
        let start = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), oaddr, 0);
        let end = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), oaddr, 4);
        let s_le_e = self
            .b
            .ins()
            .icmp(IntCC::UnsignedLessThanOrEqual, start, end);
        let e_le_tot = self
            .b
            .ins()
            .icmp(IntCC::UnsignedLessThanOrEqual, end, total);
        let valid_rng = self.b.ins().band(s_le_e, e_le_tot);
        self.b.def_var(k_var, start);
        self.b.ins().brif(valid_rng, k_hdr, &[], cx_step, &[]);

        self.b.switch_to_block(k_hdr);
        let k = self.b.use_var(k_var);
        let w_k = self.b.use_var(w_var);
        let k_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, k, end);
        let w_ok_k = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_k,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let k_go = self.b.ins().band(k_ok, w_ok_k);
        self.b.ins().brif(k_go, k_body, &[], cx_step, &[]);

        self.b.switch_to_block(k_body);
        self.b.seal_block(k_body);
        let kp = coerce_cl_val(self.b, k, ptr_ty, ptr_ty);
        let poff = self.b.ins().imul_imm_s(kp, 16);
        let pptr = self.b.ins().iadd(pos_base, poff);
        let px = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 0);
        let py = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 4);
        let pz = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 8);
        let dx = self.b.ins().fsub(px, cvec[0]);
        let dy = self.b.ins().fsub(py, cvec[1]);
        let dz = self.b.ins().fsub(pz, cvec[2]);
        let dx2 = self.b.ins().fmul(dx, dx);
        let dy2 = self.b.ins().fmul(dy, dy);
        let dz2 = self.b.ins().fmul(dz, dz);
        let dxy2 = self.b.ins().fadd(dx2, dy2);
        let d2 = self.b.ins().fadd(dxy2, dz2);
        let hit = self.b.ins().fcmp(FloatCC::LessThanOrEqual, d2, r2);
        self.b.ins().brif(hit, add_bb, &[], k_step, &[]);

        self.b.switch_to_block(add_bb);
        self.b.seal_block(add_bb);
        let eoff = self.b.ins().imul_imm_s(kp, 8);
        let eptr = self.b.ins().iadd(ents_base, eoff);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), eptr, 0);
        let wp = coerce_cl_val(self.b, w_k, ptr_ty, ptr_ty);
        let woff = self.b.ins().imul_imm_s(wp, 8);
        let dst_addr = self.b.ins().iadd(out_ptr, woff);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ent, dst_addr, 0);
        let nw = self.b.ins().iadd_imm_s(w_k, 1);
        self.b.def_var(w_var, nw);
        self.b.ins().jump(k_step, &[]);

        self.b.switch_to_block(k_step);
        self.b.seal_block(k_step);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(k_hdr, &[]);

        self.b.seal_block(k_hdr);
        self.b.switch_to_block(cx_step);
        self.b.seal_block(cx_step);
        let ncx = self.b.ins().iadd_imm_s(cx, 1);
        self.b.def_var(cx_var, ncx);
        self.b.ins().jump(cx_hdr, &[]);

        self.b.seal_block(cx_hdr);
        self.b.switch_to_block(cy_step);
        self.b.seal_block(cy_step);
        let ncy = self.b.ins().iadd_imm_s(cy, 1);
        self.b.def_var(cy_var, ncy);
        self.b.ins().jump(cy_hdr, &[]);

        self.b.seal_block(cy_hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
        self.def_scalar_typed(dst, out_ptr);
    }

    pub(super) fn lower_spatial_query_segment(
        &mut self,
        dst: LocalId,
        history_name: &str,
        start: LocalId,
        end: LocalId,
        radius: LocalId,
        tick_offset: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let out_slot = alloc_zero_slot(self.b, MAX_SPATIAL_CANDIDATES * 8, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let Some(meta) = resolve_spatial_meta(self.ctx, self.mir_fn, history_name) else {
            self.def_scalar_typed(dst, out_ptr);
            return;
        };
        if meta.cols == 0 || meta.rows == 0 || meta.cell_count == 0 {
            self.def_scalar_typed(dst, out_ptr);
            return;
        }

        let svec = self.use_vec(start);
        let evec = self.use_vec(end);
        let rad_raw = {
            let __tmp = self.use_scalar(radius);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let zf = self.b.ins().f32const(0.0);
        let rad_pos = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, rad_raw, zf);
        let rad = self.b.ins().select(rad_pos, rad_raw, zf);
        let r2 = self.b.ins().fmul(rad, rad);

        let toff_raw = {
            let __tmp = self.use_scalar(tick_offset);
            coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
        };
        let z32 = self.b.ins().iconst(types::I32, 0);
        let toff_ge0 = self
            .b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThan, toff_raw, 0);
        let toff = self.b.ins().select(toff_ge0, toff_raw, z32);

        let cur_tick = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let target_frame = if meta.frames > 1 {
            let fv = self.b.ins().iconst(types::I32, meta.frames as i64);
            let toff_mod = self.b.ins().urem(toff, fv);
            let cur_mod = self.b.ins().urem(cur_tick, fv);
            let added = self.b.ins().iadd(cur_mod, fv);
            let diff = self.b.ins().isub(added, toff_mod);
            self.b.ins().urem(diff, fv)
        } else {
            z32
        };

        let frame_ptr = emit_spatial_frame_ptr(self.b, self.state_ptr, target_frame, &meta, ptr_ty);
        let raw_total = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame_ptr, 0);
        let cap_v = self.b.ins().iconst(types::I32, meta.capacity as i64);
        let total_lt_cap = self.b.ins().icmp(IntCC::UnsignedLessThan, raw_total, cap_v);
        let total = self.b.ins().select(total_lt_cap, raw_total, cap_v);

        let off_base = self.b.ins().iadd_imm_s(frame_ptr, meta.offsets_off as i64);
        let ents_base = self.b.ins().iadd_imm_s(frame_ptr, meta.entities_off as i64);
        let pos_base = self
            .b
            .ins()
            .iadd_imm_s(frame_ptr, meta.positions_off as i64);

        let s_coords = [svec[0], svec[1], svec[2]];
        let e_coords = [evec[0], evec[1], evec[2]];
        let a0 = axis_val(s_coords, meta.plane_axes[0]);
        let b0 = axis_val(e_coords, meta.plane_axes[0]);
        let a1 = axis_val(s_coords, meta.plane_axes[1]);
        let b1 = axis_val(e_coords, meta.plane_axes[1]);

        let x_lo = self.b.ins().fmin(a0, b0);
        let x_hi = self.b.ins().fmax(a0, b0);
        let y_lo = self.b.ins().fmin(a1, b1);
        let y_hi = self.b.ins().fmax(a1, b1);
        let min_x = self.b.ins().fsub(x_lo, rad);
        let max_x = self.b.ins().fadd(x_hi, rad);
        let min_y = self.b.ins().fsub(y_lo, rad);
        let max_y = self.b.ins().fadd(y_hi, rad);

        let min_cx = emit_spatial_clamp_cell_coord(
            self.b,
            min_x,
            meta.bounds_min[0],
            meta.inv_cell_size,
            meta.cols,
        );
        let max_cx = emit_spatial_clamp_cell_coord(
            self.b,
            max_x,
            meta.bounds_min[0],
            meta.inv_cell_size,
            meta.cols,
        );
        let min_cy = emit_spatial_clamp_cell_coord(
            self.b,
            min_y,
            meta.bounds_min[1],
            meta.inv_cell_size,
            meta.rows,
        );
        let max_cy = emit_spatial_clamp_cell_coord(
            self.b,
            max_y,
            meta.bounds_min[1],
            meta.inv_cell_size,
            meta.rows,
        );

        let abx = self.b.ins().fsub(evec[0], svec[0]);
        let aby = self.b.ins().fsub(evec[1], svec[1]);
        let abz = self.b.ins().fsub(evec[2], svec[2]);
        let abx2 = self.b.ins().fmul(abx, abx);
        let aby2 = self.b.ins().fmul(aby, aby);
        let abz2 = self.b.ins().fmul(abz, abz);
        let ab_xy2 = self.b.ins().fadd(abx2, aby2);
        let ab_len2 = self.b.ins().fadd(ab_xy2, abz2);
        let eps = self.b.ins().f32const(1e-12);
        let ab_ok = self.b.ins().fcmp(FloatCC::GreaterThan, ab_len2, eps);
        let onef = self.b.ins().f32const(1.0);

        let cy_var = self.b.declare_var(types::I32);
        let cx_var = self.b.declare_var(types::I32);
        let k_var = self.b.declare_var(types::I32);
        let w_var = self.b.declare_var(types::I32);
        self.b.def_var(cy_var, min_cy);
        self.b.def_var(w_var, z32);

        let cy_hdr = self.b.create_block();
        let cy_body = self.b.create_block();
        let cx_hdr = self.b.create_block();
        let cx_body = self.b.create_block();
        let k_hdr = self.b.create_block();
        let k_body = self.b.create_block();
        let add_bb = self.b.create_block();
        let k_step = self.b.create_block();
        let cx_step = self.b.create_block();
        let cy_step = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(cy_hdr, &[]);

        self.b.switch_to_block(cy_hdr);
        let cy = self.b.use_var(cy_var);
        let w_cy = self.b.use_var(w_var);
        let cy_ok = self.b.ins().icmp(IntCC::SignedLessThanOrEqual, cy, max_cy);
        let w_ok_cy = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_cy,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let cy_go = self.b.ins().band(cy_ok, w_ok_cy);
        self.b.ins().brif(cy_go, cy_body, &[], exit, &[]);

        self.b.switch_to_block(cy_body);
        self.b.seal_block(cy_body);
        self.b.def_var(cx_var, min_cx);
        self.b.ins().jump(cx_hdr, &[]);

        self.b.switch_to_block(cx_hdr);
        let cx = self.b.use_var(cx_var);
        let w_cx = self.b.use_var(w_var);
        let cx_ok = self.b.ins().icmp(IntCC::SignedLessThanOrEqual, cx, max_cx);
        let w_ok_cx = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_cx,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let cx_go = self.b.ins().band(cx_ok, w_ok_cx);
        self.b.ins().brif(cx_go, cx_body, &[], cy_step, &[]);

        self.b.switch_to_block(cx_body);
        self.b.seal_block(cx_body);
        let row_off = self.b.ins().imul_imm_s(cy, meta.cols as i64);
        let cell = self.b.ins().iadd(row_off, cx);
        let cell_in =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cell, meta.cell_count as i64);
        let cell_p = coerce_cl_val(self.b, cell, ptr_ty, ptr_ty);
        let coff = self.b.ins().imul_imm_s(cell_p, 4);
        let oaddr = self.b.ins().iadd(off_base, coff);
        let range_check_bb = self.b.create_block();
        self.b
            .ins()
            .brif(cell_in, range_check_bb, &[], cx_step, &[]);

        self.b.switch_to_block(range_check_bb);
        self.b.seal_block(range_check_bb);
        let start_idx = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), oaddr, 0);
        let end_idx = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), oaddr, 4);
        let s_le_e = self
            .b
            .ins()
            .icmp(IntCC::UnsignedLessThanOrEqual, start_idx, end_idx);
        let e_le_tot = self
            .b
            .ins()
            .icmp(IntCC::UnsignedLessThanOrEqual, end_idx, total);
        let valid_rng = self.b.ins().band(s_le_e, e_le_tot);
        self.b.def_var(k_var, start_idx);
        self.b.ins().brif(valid_rng, k_hdr, &[], cx_step, &[]);

        self.b.switch_to_block(k_hdr);
        let k = self.b.use_var(k_var);
        let w_k = self.b.use_var(w_var);
        let k_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, k, end_idx);
        let w_ok_k = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w_k,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let k_go = self.b.ins().band(k_ok, w_ok_k);
        self.b.ins().brif(k_go, k_body, &[], cx_step, &[]);

        self.b.switch_to_block(k_body);
        self.b.seal_block(k_body);
        let kp = coerce_cl_val(self.b, k, ptr_ty, ptr_ty);
        let poff = self.b.ins().imul_imm_s(kp, 16);
        let pptr = self.b.ins().iadd(pos_base, poff);
        let px = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 0);
        let py = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 4);
        let pz = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), pptr, 8);

        let apx = self.b.ins().fsub(px, svec[0]);
        let apy = self.b.ins().fsub(py, svec[1]);
        let apz = self.b.ins().fsub(pz, svec[2]);
        let dot_x = self.b.ins().fmul(apx, abx);
        let dot_y = self.b.ins().fmul(apy, aby);
        let dot_z = self.b.ins().fmul(apz, abz);
        let dot_xy = self.b.ins().fadd(dot_x, dot_y);
        let dot = self.b.ins().fadd(dot_xy, dot_z);
        let raw_t = self.b.ins().fdiv(dot, ab_len2);
        let t_safe = self.b.ins().select(ab_ok, raw_t, zf);
        let t_min = self.b.ins().fmax(t_safe, zf);
        let t_clamped = self.b.ins().fmin(t_min, onef);

        let sx_step = self.b.ins().fmul(abx, t_clamped);
        let sy_step = self.b.ins().fmul(aby, t_clamped);
        let sz_step = self.b.ins().fmul(abz, t_clamped);
        let clx = self.b.ins().fadd(svec[0], sx_step);
        let cly = self.b.ins().fadd(svec[1], sy_step);
        let clz = self.b.ins().fadd(svec[2], sz_step);
        let dx = self.b.ins().fsub(px, clx);
        let dy = self.b.ins().fsub(py, cly);
        let dz = self.b.ins().fsub(pz, clz);
        let dx2 = self.b.ins().fmul(dx, dx);
        let dy2 = self.b.ins().fmul(dy, dy);
        let dz2 = self.b.ins().fmul(dz, dz);
        let dxy2 = self.b.ins().fadd(dx2, dy2);
        let d2 = self.b.ins().fadd(dxy2, dz2);
        let hit = self.b.ins().fcmp(FloatCC::LessThanOrEqual, d2, r2);
        self.b.ins().brif(hit, add_bb, &[], k_step, &[]);

        self.b.switch_to_block(add_bb);
        self.b.seal_block(add_bb);
        let eoff = self.b.ins().imul_imm_s(kp, 8);
        let eptr = self.b.ins().iadd(ents_base, eoff);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), eptr, 0);
        let wp = coerce_cl_val(self.b, w_k, ptr_ty, ptr_ty);
        let woff = self.b.ins().imul_imm_s(wp, 8);
        let dst_addr = self.b.ins().iadd(out_ptr, woff);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ent, dst_addr, 0);
        let nw = self.b.ins().iadd_imm_s(w_k, 1);
        self.b.def_var(w_var, nw);
        self.b.ins().jump(k_step, &[]);

        self.b.switch_to_block(k_step);
        self.b.seal_block(k_step);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(k_hdr, &[]);

        self.b.seal_block(k_hdr);
        self.b.switch_to_block(cx_step);
        self.b.seal_block(cx_step);
        let ncx = self.b.ins().iadd_imm_s(cx, 1);
        self.b.def_var(cx_var, ncx);
        self.b.ins().jump(cx_hdr, &[]);

        self.b.seal_block(cx_hdr);
        self.b.switch_to_block(cy_step);
        self.b.seal_block(cy_step);
        let ncy = self.b.ins().iadd_imm_s(cy, 1);
        self.b.def_var(cy_var, ncy);
        self.b.ins().jump(cy_hdr, &[]);

        self.b.seal_block(cy_hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
        self.def_scalar_typed(dst, out_ptr);
    }
}
